use std::sync::Arc;
use stark::field::Field;

fn main() {
    let f = Arc::new(Field::main());
    println!("Field p: {}", f.p);
    
    let generator = f.generator();
    println!("Generator: {}", generator);
    
    let root = f.primitive_nth_root(2);
    println!("2nd root of unity: {}", root);
}
