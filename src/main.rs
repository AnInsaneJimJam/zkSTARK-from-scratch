fn main() {
    // fn xgcd( x: u32, y: u32) ->(u32,u32,u32){
    //     let (mut old_r,mut r) = (x,y);
    //     let (mut old_s,mut s) = (1,0);
    //     let (mut old_t,mut t) = (0,1);
    //     while r != 0 {
    //         let quotient = old_r/r;
    //         (old_r,r) = (r,old_r - quotient*r);
    //         (old_s,s) = (s,old_s - quotient*s);
    //         (old_t,t) = (r,old_t - quotient*t);
    //     }   
    //     return (old_s,old_t,old_r ) 

    // }

    struct FieldElement{
        value: u32,
        field: u32
    }

    // Have to look that field should be same 

    impl FieldElement {
        fn new(value: u32, field: u32) -> Self{
            FieldElement { value: value%field, field }
        }
        
        fn add(&self,other: &FieldElement) -> Self{
            let sum = (self.value+other.value)%self.field;
            let field = self.field;
            FieldElement{value: sum,field}
        }

        fn mul(&self,other: &FieldElement) -> Self{
            let product = (self.value+other.value)%self.field;
            let field = self.field;
            FieldElement{value: product,field}
        }

    }

}
