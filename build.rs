extern crate gcc;

fn main() {
    gcc::Config::new()
        .file("box-stream-c/src/box-stream.c")
        .include("box-stream-c/src")
        .compile("libbox-stream.a");
}
