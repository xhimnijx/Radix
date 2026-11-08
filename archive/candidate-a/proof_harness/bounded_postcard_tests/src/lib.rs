// Exercise the production adapter without compiling the proof system.
#[cfg(test)]
#[path = "../../src/bounded_postcard.rs"]
mod bounded_postcard;

#[cfg(test)]
mod tests;
