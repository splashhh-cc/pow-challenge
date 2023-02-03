
export async function deriveKey(password: string, salt: string, iterations: number, keyLength: number): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const pwArray = encoder.encode(password);
    const saltArray = encoder.encode(salt);

    const pbkdf2Algorithm: Pbkdf2Params = {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: saltArray,
        iterations: iterations
    };

    const derivedKey = await crypto.subtle.importKey(
        'raw',
        pwArray,
        {name: 'PBKDF2'},
        false,
        ['deriveBits']
    );

    const key = await crypto.subtle.deriveBits(
        pbkdf2Algorithm,
        derivedKey,
        keyLength * 8
    );

    return new Uint8Array(key);
}

function normalize(num_array: Uint8Array): number {
    // convert derived key to a number between 0 and 1 when 1 is the max value
    // that can be represented by the number of bytes in the derived key
    const max = Math.pow(2, num_array.length * 8);
    const num = num_array.reduce((acc, byte) => acc * 256 + byte, 0);
    return num / max;
}

interface ChallengeSolution {
    solution: string;
    guess_count: number;
    time_taken_ms: number;
}

// the function should return the solution to the challenge
// difficulty is the expected number of guesses
async function solve_challenge(challenge: string, difficulty: number): Promise<ChallengeSolution> {
    let guess = 'as good as any';
    const normalized_difficulty: number = 1 / difficulty;

    const iterations = 100;
    const keyLength = 32;

    let guess_count = 0;
    let startTime = performance.now()

    while (true) {
        const derivedKey = await deriveKey(challenge, guess, iterations, keyLength);
        guess_count++;
        const normalized = normalize(derivedKey);

        if (normalized < normalized_difficulty) {
            const time_taken_ms = performance.now() - startTime;
            return {solution: guess, guess_count, time_taken_ms};
        }
        // generate a random string of the same length as the guess
        guess = Array.from({length: guess.length}, () => Math.random().toString(36)[2]).join('');
    }

}

interface BenchResults {
    avg_guess_count: number;
    avg_time_taken_ms: number;
}

//
export async function benchmark_solver(difficulty: number) :Promise<BenchResults> {
    const runtimes = 50;
    let {avg_guess_count, avg_time_taken_ms} = {avg_guess_count: 0, avg_time_taken_ms: 0};

    for (let i = 0; i < runtimes; i++) {
        let {guess_count, time_taken_ms} = await solve_challenge('hard_challange', difficulty);
        avg_guess_count += guess_count;
        avg_time_taken_ms += time_taken_ms;
    }

    avg_guess_count = avg_guess_count / runtimes;
    avg_time_taken_ms = avg_time_taken_ms / runtimes;

    console.log('avg Guess Count: ' + avg_guess_count);
    console.log('avg Time Taken (ms): ' + avg_time_taken_ms);

    return {avg_guess_count, avg_time_taken_ms};
}

export async function run_kdf() {

    let { solution, guess_count, time_taken_ms } = await solve_challenge('hard_challenge', 1000);
    console.log('Solution: ' + solution);
    console.log('Guess Count: ' + guess_count);
    console.log('Time Taken (ms): ' + time_taken_ms);


    // await benchmark_solver();


}

// python code to verify:
// # the function should normalize a bytes array to a number between 0 and 1
// # output 1 will represent the maximum value of the input array
// def normalize_key(num: bytes) -> float:
//     max_value = 2 ** (8 * len(num))
// return int.from_bytes(num, 'big') / max_value
//
//
// def verify_solution(challenge: str, solution: str, difficulty: int) -> bool:
//     iterations = 100
// key_length = 32
//
// challenge_bytes = challenge.encode('utf-8')
// solution_bytes = solution.encode('utf-8')
//
// res = pbkdf2_hmac('sha256', challenge_bytes, solution_bytes, iterations, key_length)
// normalized_res = normalize_key(res)
// print('normalized_res', normalized_res)
// normalized_difficulty = 1 / difficulty
//
// return normalized_res < normalized_difficulty