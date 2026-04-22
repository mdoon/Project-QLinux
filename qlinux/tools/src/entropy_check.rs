use anyhow::Result;
use qhal::{drivers::thermal_rng::ThermalRng, QuantumHardwareAbstraction};

fn main() -> Result<()> {
    let rng = ThermalRng::new()?;
    match rng.check_entropy_quality() {
        Ok(())  => println!("✓ エントロピー品質: OK"),
        Err(e)  => eprintln!("✗ エントロピー品質チェック失敗: {}", e),
    }
    Ok(())
}
