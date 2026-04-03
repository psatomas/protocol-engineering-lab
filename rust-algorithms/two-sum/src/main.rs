use std::collections::HashMap;

fn two_sum(nums: Vec<i32>, target: i32) -> (usize, usize) {
    let mut map = HashMap::new();

    for (i, num) in nums.iter().enumerate() {
        let complement = target - num;

        if let Some(&idx) = map.get(&complement) {
            return (idx, i);
        }

        map.insert(*num, i);
    }

    panic!("No solution found");
}

fn main() {
    let nums = vec![2, 7, 11, 15];
    let result = two_sum(nums, 9);

    println!("{:?}", result);
}
