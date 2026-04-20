use std::sync::Arc;

use stark::field::Field;

pub fn field() -> Arc<Field> {
    Arc::new(Field::main())
}
