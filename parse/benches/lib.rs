#![feature(test)]

extern crate test;

#[cfg(test)]
mod bench {
    use test::Bencher;

    #[bench]
    fn bench_uri_parse(b: &mut Bencher) {
        let uri = test::black_box(b"https://example.com/aa/bb/cc?q=5&d=1#test");

        b.iter(|| parse::Uri::parse(uri))
    }

    #[bench]
    fn bench_url_crate_parse(b: &mut Bencher) {
        let uri = test::black_box("https://example.com/aa/bb/cc?q=5&d=1#test");

        b.iter(|| url::Url::parse(uri));
    }
}
