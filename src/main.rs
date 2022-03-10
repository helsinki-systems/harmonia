mod nixstore;

fn main() {
    println!("{}", nixstore::get_store_dir());
    println!("{}", nixstore::get_bin_dir());
}
