import rfc5649 from '../src/rfc5649';
import test from 'tape';

// tests from https://tools.ietf.org/html/rfc5649#section-6

test.only('16B key', t => {
    let kek = new Buffer('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8', 'hex');
    let wrap = new Buffer('afbeb0f07dfbf5419200f2ccb50bb24f', 'hex');
    let key = new Buffer('466f7250617369', 'hex');
  
    t.ok(assertUnwrap({kek, key, wrap}), 'unwrapped matches key');
    t.ok(assertWrap({kek, key, wrap}), 'wrapped matches wrap');
    t.end();
});

test('>16B key', t => {
    let kek = new Buffer('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8', 'hex');
    let wrap = new Buffer('138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a', 'hex');
    let key = new Buffer('c37b7e6492584340bed12207808941155068f738', 'hex');
    
    t.ok(validate({kek, key, wrap}), 'unwrapped matches key');
    t.end();
});

function assertUnwrap({kek, key, wrap}) {
  let unwrapped;

  try {
    unwrapped = rfc5649.unwrap(wrap, kek);
  } catch (e) {
    return false;
  }

  return unwrapped.equals(key);
}

function assertWrap({kek, key, wrap}) {
  let wrapped;

  try {
    wrapped = rfc5649.wrap(key, kek);
  } catch (e) {
    return false;
  }

  return wrapped.equals(wrap);
}
