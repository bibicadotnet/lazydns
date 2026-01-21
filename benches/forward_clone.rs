use lazydns::dns::Message;
use std::sync::Arc;
use std::time::Instant;

fn bench_forward_clone(iter: usize, inner: usize) {
    let mut msg = Message::new();
    msg.add_question(lazydns::dns::Question::new(
        "example.com",
        lazydns::dns::types::RecordType::A,
        lazydns::dns::types::RecordClass::IN,
    ));
    #[allow(dead_code)]
    #[derive(Clone, Debug)]
    struct CoreSim {
        upstreams: Vec<String>,
    }

    let core = CoreSim {
        upstreams: vec!["1.1.1.1:53".to_string(); 10],
    };

    // deep clone loop
    let start = Instant::now();
    for _ in 0..iter {
        for _ in 0..inner {
            let _r = msg.clone();
            let _c = core.clone();
        }
    }
    let dur_clone = start.elapsed();

    // arc clone loop
    let req_arc = Arc::new(msg.clone());
    let core_arc = Arc::new(core.clone());
    let start = Instant::now();
    for _ in 0..iter {
        for _ in 0..inner {
            let _r = Arc::clone(&req_arc);
            let _c = Arc::clone(&core_arc);
        }
    }
    let dur_arc = start.elapsed();

    println!(
        "forward: iter={} inner={} clone={:?} arc={:?}",
        iter, inner, dur_clone, dur_arc
    );
}

fn bench_cache_clone(iter: usize, inner: usize) {
    let mut msg = Message::new();
    msg.add_question(lazydns::dns::Question::new(
        "example.com",
        lazydns::dns::types::RecordType::A,
        lazydns::dns::types::RecordClass::IN,
    ));

    // message.clone
    let start = Instant::now();
    for _ in 0..iter {
        for _ in 0..inner {
            let _m2 = msg.clone();
        }
    }
    let dur_clone = start.elapsed();

    // arc.clone
    let m_arc = Arc::new(msg.clone());
    let start = Instant::now();
    for _ in 0..iter {
        for _ in 0..inner {
            let _m2 = Arc::clone(&m_arc);
        }
    }
    let dur_arc = start.elapsed();

    println!(
        "cache: iter={} inner={} clone={:?} arc={:?}",
        iter, inner, dur_clone, dur_arc
    );
}

fn main() {
    // warmup
    bench_forward_clone(10, 100);
    bench_cache_clone(10, 100);

    // measured
    bench_forward_clone(1000, 1000);
    bench_cache_clone(1000, 1000);
}
