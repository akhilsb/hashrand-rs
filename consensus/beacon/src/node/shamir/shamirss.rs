/**
 * Cloned from https://github.com/bitrocks/verifiable-secret-sharing
 * Author: bitrocks: https://github.com/bitrocks
 */

pub use num_bigint;
use num_bigint::{BigUint, RandBigInt, BigInt};
use num_traits::{One, Zero};
use rand;
/// The `ShamirSecretSharing` stores threshold, share_amount and the prime of finite field.
#[derive(Clone, Debug)]
pub struct ShamirSecretSharing {
    /// the threshold of shares to recover the secret.
    pub threshold: usize,
    /// the total number of shares to generate from the secret.
    pub share_amount: usize,
    /// the characteristic of finite field.
    pub prime: BigUint,
}
/**
 * Shamir secret sharing and Lagrange Interpolation for reconstruction. 
 */
impl ShamirSecretSharing {
    /// Split a secret according to the config.
    pub fn split(&self, secret: BigUint) -> Vec<(usize, BigUint)> {
        assert!(self.threshold < self.share_amount);
        let polynomial = self.sample_polynomial(secret);
        // println!("polynomial: {:?}", polynomial);
        self.evaluate_polynomial(polynomial)
    }

    fn sample_polynomial(&self, secret: BigUint) -> Vec<BigUint> {
        let mut coefficients: Vec<BigUint> = vec![secret];
        let mut rng = rand::thread_rng();
        let low = BigUint::from(0u32);
        let high = &self.prime - BigUint::from(1u32);
        let random_coefficients: Vec<BigUint> = (0..(self.threshold - 1))
            .map(|_| rng.gen_biguint_range(&low, &high))
            .collect();
        coefficients.extend(random_coefficients);
        coefficients
    }

    fn evaluate_polynomial(&self, polynomial: Vec<BigUint>) -> Vec<(usize, BigUint)> {
        (1..=self.share_amount)
            .map(|x| (x, self.mod_evaluate_at(&polynomial, x)))
            .collect()
    }

    fn mod_evaluate_at(&self, polynomial: &[BigUint], x: usize) -> BigUint {
        let x_big_uint = BigUint::from(x);
        polynomial.iter().rev().fold(Zero::zero(), |sum, item| {
            (&x_big_uint * sum + item) % &self.prime
        })
    }

    /// Recover the secret by the shares.
    pub fn recover(&self, shares: &[(usize, BigUint)]) -> BigUint {
        assert!(shares.len() == self.threshold, "wrong shares number");
        let (xs, ys): (Vec<usize>, Vec<BigUint>) = shares.iter().cloned().unzip();
        let result = self.lagrange_interpolation(BigInt::from(0i8), xs, ys);
        if result < Zero::zero() {
            let mu = result + BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone());
            mu.to_biguint().unwrap()
        } else {
            result.to_biguint().unwrap()
        }
    }

    fn lagrange_interpolation(&self, x: BigInt, xs: Vec<usize>, ys: Vec<BigUint>) -> BigInt {
        let ys_bi:Vec<BigInt> = ys.into_iter().map(|x| BigInt::from_biguint(num_bigint::Sign::Plus, x)).collect();
        let len = xs.len();
        // println!("x: {}, xs: {:?}, ys: {:?}", x, xs, ys);
        let xs_big_uint: Vec<BigInt> = xs.iter().map(|x| BigInt::from(*x as i64)).collect();
        // println!("sx_BigUint: {:?}", xs_BigUint);
        (0..len).fold(BigInt::from(0i8), |sum:BigInt, item:usize| {
            let numerator = (0..len).fold(One::one(), |product: BigInt, i| {
                if i == item {
                    product
                } else {
                    product * (&x - &xs_big_uint[i]) % BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone())
                }
            });
            let denominator = (0..len).fold(One::one(), |product: BigInt, i| {
                if i == item {
                    product
                } else {
                    product * (&xs_big_uint[item] - &xs_big_uint[i]) % BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone())
                }
            });
            // println!(
            // "numerator: {}, donominator: {}, y: {}",
            // numerator, denominator, &ys[item]
            // );
            (sum + numerator * self.mod_reverse(denominator) * &ys_bi[item]) % BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone())
        })
    }

    fn mod_reverse(&self, num: BigInt) -> BigInt {
        let num1 = if num < Zero::zero() {
            num + BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone())
        } else {
            num
        };
        let (_gcd, _, inv) = self.extend_euclid_algo(num1);
        // println!("inv:{}", inv);
        inv
    }

    /**
     * https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
     *
     * a*s + b*t = gcd(a,b) a > b
     * r_0 = a*s_0 + b*t_0    s_0 = 1    t_0 = 0
     * r_1 = a*s_1 + b*t_1    s_1 = 0    t_1 = 1
     * r_2 = r_0 - r_1*q_1
     *     = a(s_0 - s_1*q_1) + b(t_0 - t_1*q_1)   s_2 = s_0 - s_1*q_1     t_2 = t_0 - t_1*q_1
     * ...
     * stop when r_k = 0
     */
    fn extend_euclid_algo(&self, num: BigInt) -> (BigInt, BigInt, BigInt) {
        let (mut r, mut next_r, mut s, mut next_s, mut t, mut next_t) = (
            BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone()),
            num.clone(),
            BigInt::from(1u32),
            BigInt::from(0u32),
            BigInt::from(0u32),
            BigInt::from(1u32),
        );
        let mut quotient;
        let mut tmp;
        while next_r > Zero::zero() {
            quotient = r.clone() / next_r.clone();
            tmp = next_r.clone();
            next_r = r.clone() - next_r.clone() * quotient.clone();
            r = tmp.clone();
            tmp = next_s.clone();
            next_s = s - next_s.clone() * quotient.clone();
            s = tmp;
            tmp = next_t.clone();
            next_t = t - next_t * quotient;
            t = tmp;
        }
        // println!(
        // "{} * {} + {} * {} = {} mod {}",
        // num, t, &self.prime, s, r, &self.prime
        // );
        (r, s, t)
    }
}