extern crate cc;

fn main() {
    cc::Build::new()
        .file("box-stream-c/src/box-stream.c")
        .include("box-stream-c/src")
        .compile("libbox-stream.a");
}
