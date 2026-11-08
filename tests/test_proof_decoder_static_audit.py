import re
from math import prod
from pathlib import Path


PROOF_HARNESS_SRC = Path(__file__).resolve().parents[1] / "archive" / "candidate-a" / "proof_harness" / "src"
BOUNDED_CALL = re.compile(r"crate::bounded_postcard::from_proof_bytes\s*\(")
DIRECT_POSTCARD_CALL = re.compile(r"postcard::from_bytes\s*(?:::<[^;]+?>)?\s*\(")


def test_all_proof_envelopes_use_bounded_decode_and_canonical_reencoding():
    rust_sources = sorted(PROOF_HARNESS_SRC.glob("*.rs"))
    assert rust_sources

    bounded_call_count = 0
    for path in rust_sources:
        source = path.read_text(encoding="utf-8")
        calls = len(BOUNDED_CALL.findall(source))
        bounded_call_count += calls

        if calls:
            assert source.count("canonical.matches_exactly()") >= calls, path.name
            assert "bytes.len() !=" in source, path.name

        # Proof decoders must not bypass the adapter with postcard's raw entrypoint.
        assert not DIRECT_POSTCARD_CALL.search(source), path.name

        # Keep explicitly typed proof values routed through the budgeted helper.
        for match in re.finditer(r"\bProof\s*<\s*Stark\s*>\s*=", source):
            statement_end = source.find(";", match.end())
            assert statement_end >= 0, path.name
            statement = source[match.start() : statement_end]
            assert "from_proof_bytes" in statement, path.name

    assert bounded_call_count == 9


def test_shared_proof_decoder_checks_profile_size_before_deserialization():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    decoder = _rust_function_body(source, "fn decode_proof(payload: &[u8])")

    guard = "if payload.is_empty() || payload.len() > MAX_PROOF_BYTES"
    assert guard in decoder
    assert decoder.index(guard) < decoder.index("from_proof_bytes(payload)")


def _rust_function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unclosed Rust function body: {signature}")


def _rust_product_constant(source: str, name: str) -> int:
    match = re.search(rf"const {name}: u64 = ([0-9 *]+);", source)
    assert match is not None, name
    factors = [int(part.strip()) for part in match.group(1).split("*")]
    return prod(factors)


def _rust_pinned_u64(source: str, field: str) -> int:
    """Read a `assert_eq!(report.<field>, N);` pin so Python and Rust agree."""
    match = re.search(rf"assert_eq!\(report\.{re.escape(field)}, ([0-9_]+)\);", source)
    assert match is not None, field
    return int(match.group(1).replace("_", ""))


def test_rdxl_overlap_estimate_exceeds_declared_device_budgets():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    dimensions = re.search(
        r"assert_eq!\(\(report\.trace_rows, report\.trace_width\), \((\d[\d_]*), (\d[\d_]*)\)\);",
        source,
    )
    blowup = re.search(r"const PCS_LOG_BLOWUP: usize = (\d+);", source)
    random_codewords = re.search(
        r"const PCS_ZK_RANDOM_CODEWORDS: usize = (\d+);", source
    )
    assert dimensions is not None and blowup is not None and random_codewords is not None
    assert "const RDXL_TRACE_ROWS: usize = TRACE_ROWS * 2;" in source
    assert (
        "const RDXL_TRACE_WIDTH: usize = OUTPUT_KDF_SECRET_BITS_OFFSET + OUTPUT_KDF_SECRET_BYTES * 8;"
        in source
    )
    trace_rows, trace_width = (int(value.replace("_", "")) for value in dimensions.groups())
    randomized_rows = trace_rows * 2
    randomized_width = trace_width + int(random_codewords.group(1))
    randomized_bytes = randomized_rows * randomized_width * 4  # BabyBear field element
    lde_rows = randomized_rows * (1 << int(blowup.group(1)))
    lde_bytes = lde_rows * randomized_width * 4
    estimated_overlap = randomized_bytes + lde_bytes

    desktop_budget = _rust_product_constant(source, "DESKTOP_PROCESS_BUDGET_BYTES")
    mobile_budget = _rust_product_constant(source, "MOBILE_PROCESS_BUDGET_BYTES")

    # The Rust resource report pins the same numbers; compare against those pins
    # instead of duplicating literals here, so the layout cannot drift silently.
    assert trace_rows * trace_width * 4 == _rust_pinned_u64(source, "trace_payload_bytes")
    assert randomized_bytes == _rust_pinned_u64(source, "randomized_payload_bytes")
    assert lde_bytes == _rust_pinned_u64(source, "lde_payload_bytes")
    assert estimated_overlap == _rust_pinned_u64(
        source, "randomized_plus_lde_payload_bytes"
    )
    assert estimated_overlap > desktop_budget == 4_294_967_296
    assert estimated_overlap > mobile_budget == 1_073_741_824


def test_rdxl_resource_report_overflow_fails_closed():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    report = _rust_function_body(source, "fn rdxl_resource_report()")
    guard = _rust_function_body(source, "fn ensure_rdxl_process_budget()")

    assert "trace_rows.checked_mul(trace_width)?.checked_mul(field_bytes)?" in re.sub(
        r"\s+", "", report
    )
    assert "trace_rows.checked_mul(2)?" in re.sub(r"\s+", "", report)
    assert "trace_width.checked_add(PCS_ZK_RANDOM_CODEWORDS)?" in re.sub(r"\s+", "", report)
    assert "randomized_rows.checked_mul(1usize.checked_shl(PCS_LOG_BLOWUPasu32)?)?" in re.sub(
        r"\s+", "", report
    )
    assert "randomized_payload_bytes.checked_add(lde_payload_bytes)?" in re.sub(
        r"\s+", "", report
    )
    assert "rdxl_resource_report().ok_or(Depth64PathProofError::ResourceBudgetExceeded" in re.sub(
        r"\s+", "", guard
    )
    assert "estimated_workspace_bytes:u64::MAX" in re.sub(r"\s+", "", guard)
    assert "u64::try_from(report.randomized_plus_lde_payload_bytes).unwrap_or(u64::MAX)" in re.sub(
        r"\s+", "", guard
    )


def test_rdxl_prover_has_preallocation_process_budget_guard():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    guard = _rust_function_body(source, "fn ensure_rdxl_process_budget()")
    prover = _rust_function_body(
        source,
        "pub fn prove_source_key_note_nullifier_output_balance_depth64_path_with_output_secret(",
    )

    assert "rdxl_resource_report()" in guard
    assert "randomized_plus_lde_payload_bytes" in guard
    assert "desktop_process_budget_bytes" in guard
    assert "Depth64PathProofError::ResourceBudgetExceeded" in guard
    assert "ensure_rdxl_process_budget()?;" in prover
    guard_offset = prover.index("ensure_rdxl_process_budget()?;")
    for allocation_marker in (
        "note_commitment_opening::build_trace(",
        "build_source_key_note_nullifier_trace_with_width(",
        "build_source_key_note_nullifier_output_trace_with_secret(",
        "prove(&config, &air, trace, &values)",
    ):
        assert allocation_marker in prover
        assert guard_offset < prover.index(allocation_marker)


def test_rdxl_fixed_156_output_profile_rejects_other_statement_lengths_early():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    statement_source = (PROOF_HARNESS_SRC / "transaction_statement.rs").read_text(
        encoding="utf-8"
    )
    prover = _rust_function_body(
        source,
        "pub fn prove_source_key_note_nullifier_output_balance_depth64_path_with_output_secret(",
    )
    public_values = _rust_function_body(source, "fn rdxl_statement_public_values(")

    assert "const OUTPUT_CIPHERTEXT_BYTES: usize = 156;" in source
    assert "fn rdxl_public_values_reject_other_codec_valid_ciphertext_lengths()" in source
    assert "if !(156..=668).contains(&self.output.ciphertext.len())" in statement_source
    profile_check = "if statement.output.ciphertext.len() != OUTPUT_CIPHERTEXT_BYTES"
    assert profile_check in prover and profile_check in public_values
    assert prover.index(profile_check) < prover.index("checked_source_leaf_blocks(source)?")
    assert prover.index(profile_check) < prover.index("ensure_rdxl_process_budget()?;")
    assert public_values.index(profile_check) < public_values.index("output_leaf_frame(")


def test_expected_public_binding_is_checked_before_proof_deserialization():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")

    legacy_decode = _rust_function_body(source, "fn decode(")
    assert legacy_decode.index("if len == 0") < legacy_decode.index("if &root != expected_root")
    assert legacy_decode.index("if &root != expected_root") < legacy_decode.index("decode_proof(payload)?")
    legacy_verifier = _rust_function_body(source, "pub fn verify_depth64_path(")
    assert "decode(bytes, expected_root)?" in legacy_verifier

    statement_verifiers = (
        "pub fn verify_statement_bound_depth64_path(",
        "pub fn verify_source_bound_depth64_path(",
        "pub fn verify_source_note_depth64_path(",
        "pub fn verify_source_key_note_depth64_path(",
        "pub fn verify_source_key_note_nullifier_depth64_path(",
        "pub fn verify_source_key_note_nullifier_output_balance_depth64_path(",
    )
    for signature in statement_verifiers:
        body = _rust_function_body(source, signature)
        split = body.index("split_statement_bound_with_magic(")
        compare = body.index("if statement_bytes != expected_statement_bytes")
        deserialize = body.index("decode_proof(proof_payload)?")
        assert split < compare < deserialize, signature


def test_merkle_path_digest_bits_and_direction_remain_boolean():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    air = _rust_function_body(source, "fn eval(&self, builder: &mut AB)")
    air_compact = re.sub(r"\s+", "", air)

    assert "forbits_offsetin[CURRENT_BITS,SIBLING_BITS]" in air_compact
    assert "forindexin0..DIGEST_BYTES" in air_compact
    assert "letb:AB::Expr=row[bits_offset+index*8+bit].into()" in air_compact
    assert "builder.assert_zero(b.clone()*(b-one.clone()))" in air_compact
    assert "builder.assert_zero(direction.clone()*(direction.clone()-one.clone()))" in air_compact
    assert "forbitin&level" in air_compact
    assert "builder.assert_zero(bit.clone()*(bit.clone()-one.clone()))" in air_compact


def test_rdxl_statement_and_output_leaf_public_values_are_canonical_and_bound():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    public_values = _rust_function_body(source, "fn rdxl_statement_public_values(")
    generic_values = _rust_function_body(source, "fn statement_public_values(")
    root_values = _rust_function_body(source, "fn public_values(root: &ValArray)")
    verifier = _rust_function_body(
        source,
        "pub fn verify_source_key_note_nullifier_output_balance_depth64_path(",
    )
    public_values_compact = re.sub(r"\s+", "", public_values)
    generic_values_compact = re.sub(r"\s+", "", generic_values)

    # The public vector begins with root bytes, then appends every statement byte.
    assert "root.iter()" in root_values
    assert "Val::from_u32(u32::from(*byte))" in root_values
    assert generic_values.index("let mut values = public_values(root);") < generic_values.index("values.extend(")

    # Re-encode and compare the complete statement, then bind every canonical
    # byte as a public value (the verifier's public vector length binds its size).
    assert "letcanonical_statement_bytes=statement.serialize()" in public_values_compact
    assert "canonical_statement_bytes.as_slice()!=statement_bytes" in public_values_compact
    assert "statement_public_values(&statement.root_out,statement_bytes)" in public_values_compact
    assert public_values_compact.index(
        "canonical_statement_bytes.as_slice()!=statement_bytes"
    ) < public_values_compact.index(
        "statement_public_values(&statement.root_out,statement_bytes)"
    )
    assert "statement_bytes.iter()" in generic_values_compact
    assert "Val::from_u32(u32::from(*byte))" in generic_values_compact

    # The output leaf absorption blocks are derived from the parsed statement,
    # and the verifier requires the envelope's exact bytes before proof decoding.
    assert public_values.index("output_leaf_frame(") < public_values.index("output_leaf_absorb_blocks_from_frame(")
    assert public_values.index("blocks.len() != (frame.len() + 1).div_ceil(SHAKE_RATE_BYTES)") < public_values.index("Ok(values)")
    assert "TransactionStatementV1::parse(expected_statement_bytes)" in verifier
    assert "public_value_count: values.len()" in verifier
    compare = verifier.index("if statement_bytes != expected_statement_bytes")
    decode = verifier.index("decode_proof(proof_payload)?")
    bind = verifier.index("rdxl_statement_public_values(statement_bytes, &statement)?")
    assert compare < decode < bind
    assert "verify(&config, &air, &proof, &values)" in verifier


def test_output_leaf_block_stream_starts_at_zero_and_ends_at_public_count():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    air = _rust_function_body(source, "fn eval(&self, builder: &mut AB)")
    output_leaf = _rust_function_body(source, "fn eval_output_leaf_constraints<")
    air_compact = re.sub(r"\s+", "", air)
    leaf_compact = re.sub(r"\s+", "", output_leaf)

    # Output-leaf index limbs are zero outside the active stage; transition
    # equations therefore initialize the first active block at slot zero.
    assert "builder.assert_zero((one.clone()-output_leaf_stage.clone())*value);" in air_compact
    assert "letmutcarry=nonfinal_block_end.clone();" in leaf_compact
    assert "letupdated=current_expr.clone()+carry.clone()-current_expr*carry*AB::Expr::from_u32(2);" in leaf_compact
    assert "builder.when(transition.clone()*(one.clone()-leaf_end.clone())).assert_zero(next_expr.clone()-updated);" in leaf_compact
    assert "builder.when(transition.clone()*leaf_end.clone()).assert_zero(next_expr);" in leaf_compact

    # Public metadata determines a valid 10..14 block count and exactly one
    # active block selector supplies each absorb block to the output-leaf hash.
    assert "block_count.clone()-public_last_index.clone()-one.clone()" in leaf_compact
    assert "forcountin10..=14" in leaf_compact
    assert "output_leaf_stage.clone()*(selector_sum-one.clone())" in leaf_compact
    assert "letfirst_block_start:AB::Expr=output_leaf_stage.clone()*first_step*output_leaf_slot_selector::<AB>(row,0);" in leaf_compact


def test_merkle_root_binds_only_the_terminal_level_63_hash():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    air = _rust_function_body(source, "fn eval(&self, builder: &mut AB)")
    compact = re.sub(r"\s+", "", air)

    assert "lethash_end=path_active.clone()*final_step.clone()*phase.clone();" in compact
    assert "letmutroot_selector=hash_end*(one.clone()-level[6].clone());" in compact
    assert "forbitin0..6{root_selector=root_selector*level[bit].clone();}" in compact
    assert (
        "builder.when(root_selector.clone()).assert_zero(actual-(lo+hi*AB::Expr::from_u32(256)));"
        in compact
    )
    assert "builder.public_values()[limb*2]" in compact
    assert "builder.public_values()[limb*2+1]" in compact


def test_path_active_state_terminates_only_after_level_63_hash():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    air = _rust_function_body(source, "fn eval(&self, builder: &mut AB)")
    compact = re.sub(r"\s+", "", air)

    assert "builder.assert_zero(path_active.clone()*level[6].clone());" in compact
    assert "when(inactive.clone()).assert_zero(level[6].clone()-one.clone());" in compact
    assert "when(inactive.clone()).assert_zero(level[bit].clone());" in compact
    assert "when_first_row().assert_zero(active.clone()-one.clone());" in compact
    assert "letincrement=path_active.clone()*final_step.clone()*phase.clone();" in compact
    assert "letmutlevel63=one.clone()-level[6].clone();" in compact
    assert "forbitin0..6{level63=level63*level[bit].clone();}" in compact
    assert "letend_path=path_active.clone()*final_step.clone()*phase.clone()*level63;" in compact
    assert "next_active-(active.clone()-end_path)" in compact


def test_path_hash_inputs_and_phase_persist_between_node_boundaries():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    air = _rust_function_body(source, "fn eval(&self, builder: &mut AB)")
    compact = re.sub(r"\s+", "", air)

    assert "lethash_end=path_active.clone()*final_step.clone()*phase.clone();" in compact
    assert "letstay=transition.clone()*path_active.clone()*(one.clone()-hash_end.clone());" in compact
    assert "builder.when(stay.clone()).assert_zero(next_current_bit-current_bit);" in compact
    assert "builder.when(stay.clone()).assert_zero(next_sibling_bit-sibling_bit);" in compact
    assert "builder.when(stay.clone()).assert_zero(next_direction-direction);" in compact
    assert "letboundary=transition.clone()*hash_end.clone();" in compact
    assert "builder.when(boundary.clone()).assert_zero(actual-(lo+hi*AB::Expr::from_u32(256)));" in compact

    # Pin the per-bit level increment and Boolean phase toggle at transitions.
    assert "letincrement=path_active.clone()*final_step.clone()*phase.clone();" in compact
    assert "forlowerin0..bit{carry=carry*level[lower].clone();}" in compact
    assert "level[bit].clone()+carry.clone()-level[bit].clone()*carry*AB::Expr::from_u32(2)" in compact
    assert "builder.when(transition.clone()*(one.clone()-source_stage.clone())*(one.clone()-note_stage.clone()),).assert_zero(next_bit-updated);" in compact
    assert "builder.assert_zero(phase.clone()*(phase.clone()-one.clone()));" in compact
    assert "letround_end=(path_active.clone()+note_stage.clone()+nullifier_stage.clone()+output_note_stage.clone())*final_step.clone();" in compact
    assert "letphase_updated=phase.clone()+round_end.clone()-phase.clone()*round_end*AB::Expr::from_u32(2);" in compact
    assert "builder.when(transition.clone()).assert_zero(next_phase-phase_updated);" in compact
    assert "when_last_row().assert_zero(phase.clone());" in compact
    assert "when(inactive.clone()*(one.clone()-output_note_stage.clone())).assert_zero(phase.clone());" in compact

    # Root comparison, path termination, and deactivation share level == 63.
    assert "letmutroot_selector=hash_end*(one.clone()-level[6].clone());" in compact
    assert "root_selector=root_selector*level[bit].clone();" in compact
    assert "letend_path=path_active.clone()*final_step.clone()*phase.clone()*level63;" in compact
    assert "next_active-(active.clone()-end_path)" in compact


def test_merkle_direction_selects_consistent_left_and_right_hash_inputs():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    byte_frame = _rust_function_body(source, "fn frame_byte64<")
    bit_frame = _rust_function_body(source, "fn frame_bit64<")
    byte_compact = re.sub(r"\s+", "", byte_frame)
    bit_compact = re.sub(r"\s+", "", bit_frame)

    for frame in (byte_compact, bit_compact):
        assert "37..=100=>" in frame
        assert "105..=168=>" in frame
        assert "letdir:AB::Expr=row[DIRECTION].into();" in frame
        assert "cur.clone()+dir*(sib-cur)" in frame
        assert "sib.clone()+dir*(cur-sib)" in frame
    assert "letindex=offset-37;" in byte_compact
    assert "letindex=offset-105;" in byte_compact
    assert "letindex=offset-37;" in bit_compact
    assert "letindex=offset-105;" in bit_compact


def test_note_value_and_fee_balance_relations_remain_in_the_air():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    note = _rust_function_body(source, "fn eval_note_commitment_constraints<")
    balance = _rust_function_body(source, "fn eval_output_value_balance_constraints<")
    air = _rust_function_body(source, "fn eval(&self, builder: &mut AB)")

    assert "for bit in 0..64" in note
    assert "value_bits * inverse - one.clone()" in note
    assert "NOTE_PRIVATE_BITS_OFFSET + bit" in air
    assert "current_bit.clone() * (current_bit.clone() - one.clone())" in air
    # Input amount bits must be boolean and copied from the private input note;
    # otherwise a field-valued witness could evade the intended U64 relation.
    assert "let input_note_start" in air
    assert "saved.clone() * (saved.clone() - one.clone())" in air
    assert "assert_zero(saved - note_bit)" in air
    assert "note_stage.clone() * value.clone() * (value - one.clone())" in air
    air_compact = re.sub(r"\s+", "", air)
    assert "next_saved-saved.clone()" in air_compact
    assert "row[NOTE_PRIVATE_BITS_OFFSET+64*8+bit]" in air_compact
    assert "forbitin0..(200*8)" in air_compact
    assert (
        "output_note_private_live.clone()*current.clone()*(current.clone()-one.clone())"
        in air_compact
    )
    balance_compact = re.sub(r"\s+", "", balance)
    assert "row[NOTE_PRIVATE_BITS_OFFSET+64*8+limb*16+bit]" in balance_compact
    assert "STATEMENT_FEE_BYTES_OFFSET" in balance
    assert "for carry in 0..3" in balance
    assert "let carry_out = if limb == 3" in balance
    assert "let output_start = output_note_stage.clone() * first_step;" in balance
    assert "output_note_stage.clone()*value.clone()*(value-AB::Expr::ONE)" in balance_compact
    assert "let carry_in = if limb == 0" in balance
    assert (
        "letcarry_in=iflimb==0{AB::Expr::ZERO}else{row[BALANCE_CARRY_BITS_OFFSET+limb-1].into()};"
        in balance_compact
    )
    assert (
        "letcarry_out=iflimb==3{AB::Expr::ZERO}else{row[BALANCE_CARRY_BITS_OFFSET+limb].into()};"
        in balance_compact
    )
    assert "letfee=fee_low+fee_high*AB::Expr::from_u32(256);" in balance_compact
    assert "output + fee + carry_in - input - carry_out * AB::Expr::from_u32(1 << 16)" in balance


def test_rdxl_output_kdf_and_ctr_relations_remain_bound_to_public_fields():
    source = (PROOF_HARNESS_SRC / "depth64_path_opening.rs").read_text(encoding="utf-8")
    air = _rust_function_body(source, "fn eval(&self, builder: &mut AB)")
    kdf = _rust_function_body(source, "fn eval_input_kdf_constraints<")
    kdf_frame = _rust_function_body(source, "fn output_kdf_frame_byte<")
    ctr = _rust_function_body(source, "fn eval_aes256_ctr_plaintext_constraints<")
    air_compact = re.sub(r"\s+", "", air)
    kdf_compact = re.sub(r"\s+", "", kdf)
    frame_compact = re.sub(r"\s+", "", kdf_frame)
    ctr_compact = re.sub(r"\s+", "", ctr)

    # The output shared secret is private but byte-constrained and persistent;
    # the mode-selected Candidate-A KDF includes the public KEM ciphertext and
    # commitment, and its result feeds the AES key schedule.
    assert "forbytein0..OUTPUT_KDF_SECRET_BYTES" in air_compact
    assert "OUTPUT_KDF_SECRET_BITS_OFFSET+byte*8+bit" in air_compact
    assert "builder.assert_zero(value-reconstructed)" in air_compact
    assert "builder.when(transition.clone()).assert_zero(following-current)" in air_compact
    assert "output_frame*output_mode.clone()" in kdf_compact
    assert "witnessed-expected" in kdf_compact
    assert "kdf_end_transition.clone()).assert_zero(key-byte_bits)" in kdf_compact
    assert "output_kdf_secret_byte::<AB>(row,offset-31)" in frame_compact
    assert "OUTPUT_KEM_CIPHERTEXT_PUBLIC_OFFSET+offset-67" in frame_compact
    assert "OUTPUT_COMMITMENT_PUBLIC_OFFSET+offset-1159" in frame_compact

    # The output-mode AES-CTR relation must consume the statement ciphertext
    # and equate decrypted bytes to the exact private output-note plaintext.
    assert "OUTPUT_CIPHERTEXT_PUBLIC_OFFSET+plaintext_index" in ctr_compact
    assert "output_note_plaintext_byte::<AB>(row,plaintext_index)" in ctr_compact
    assert "plaintext_byte-expected_plaintext" in ctr_compact
    assert "aes_xor::<AB>(cipher_bit,stream_bit)-plaintext_bit" in ctr_compact
