use bincode;
use std::{fs, thread};
use std::env;
use std::fs::File;
use glob::glob;
use std::io::BufRead;
use std::io::{BufReader, Cursor, Write};
use std::ops::Deref;
use std::time::{Duration, Instant};
use rayon::prelude::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use tfhe::integer::{RadixCiphertext};
use tfhe::prelude::*;
use tfhe::prelude::{FheDecrypt, FheEncrypt, FheTrivialEncrypt};
use tfhe::{set_server_key, ClientKey, FheUint, FheUint16, FheUint16Id, FheUint8, FheUint8Id, ServerKey, FheUint32Id, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mut k = 26 ;
    let mut modulo =  179u16;
    let final_state:Vec<u16> = vec![2];
    let mut string_size = vec![];
    string_size.push(args[1].parse::<u8>().expect("Not a valid u8"));//args[1].parse::<u8>().expect("Not a valid u8");;
    //let string_number = args[2].parse::<usize>().expect("Not a valid usize");
    let mut coef: Vec<u16> = vec![124, 156, 173, 85, 170, 113, 31, 86, 62, 111, 4, 176, 40, 116, 2, 144, 168, 145, 120, 71, 6, 63, 43, 94, 104, 149, 11, 94, 107, 95, 90, 115, 133, 60, 45, 18, 51, 39, 132, 14, 166, 17, 141, 37, 111, 66, 121, 134, 11, 164, 142, 61, 144, 159, 146, 8, 27, 2, 158, 65, 40, 59, 55, 114, 97, 74, 176, 14, 96, 157, 129, 12, 66, 132, 123, 154, 0, 96, 144, 139, 113, 20, 166, 140, 31, 78, 48, 92, 88, 63, 105, 145, 175, 161, 164, 29, 77, 142, 135, 169, 22, 111, 150, 80, 118, 72, 49, 33, 158, 134, 3, 105, 141, 8, 101, 6, 154, 126, 32, 92, 25, 17, 45, 109, 9, 162, 15, 140, 66, 118, 18, 152, 72, 87, 126, 156, 22, 99, 109, 86, 21, 162, 47, 112, 15, 38, 85, 130, 173, 129, 8, 171, 22, 130, 114, 3];
    let encoding: Vec<u8> = (b'a'..=b'z').collect();
    let dir_path = "/home/henry/fhe-worker";
    let mut idx_start_str = 0;

    let mut file = fs::read("server_key.bin")?;
    let sk = deserialize_sk(file.as_slice())?;

    rayon::broadcast(|_| set_server_key(sk.clone()));
    set_server_key(sk);
    let args: Vec<String> = env::args().collect();
    //println!("DEBUG: deserializing client key...");
    let mut byte_vec = fs::read("client_key.bin")?;
    let ck = deserialize_ck(&byte_vec.into_boxed_slice().deref())?;

    /*
    println!("deserializing encrypted_str.bin...");
    let file = fs::read("encrypted_str.bin")?;
    let enc_str = deserialize_str(&file, string_size)?;
    */
    //println!("deserializing encrypted slice_string_i.bin...");

    let mut entries: Vec<_> = fs::read_dir(dir_path)?
        .filter_map(Result::ok) // 過濾掉失敗的結果
        .filter(|entry| {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            file_name.starts_with("slice_string_") && file_name.ends_with(".bin") // 篩選符合條件的檔案
        })
        .collect();

    // 按檔案名稱中的數字部分排序
    entries.sort_by_key(|entry| {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        extract_number(&file_name) // 提取數字部分
    });

    let mut enc_string_arr = vec![];
    let mut enc_string_arr_ascii = vec![];

    let mut count = 0;

    for entry in entries {
        println!("reading file {:?}", entry);
        let path = entry.path();
        let file = fs::read(&path)?;
        enc_string_arr.push(deserialize_str(&file, string_size[count])?);
        count+=1;

    }
    enc_string_arr_ascii = enc_string_arr.clone();

    for i in 0..enc_string_arr.len(){
        let s = decryptStr(enc_string_arr[i].clone(), &ck);
        println!("[debug] the fetch slice string is {:?}", s);
    }

    let mut idx_str = 0;
    for mut enc_str in enc_string_arr{

        println!("encoding...");
        let mut enc_zero =FheUint16::encrypt_trivial(0u8);
        let mut enc_one = FheUint16::encrypt_trivial(1u8);
        let encoding_bytes: Vec<u8> = encoding.iter().map(|&c| c as u8).collect();
        //let mut enc_chars = vec![];

        let mut enc_encoding =vec![];
        for i in encoding_bytes.clone(){
            enc_encoding.push(FheUint16::encrypt_trivial(i));
        }
        let mut enc_code = vec![];
        for i in 1..27{
            enc_code.push(FheUint16::encrypt_trivial(i as u8));
        }


        for (i,ascii_val) in enc_str.clone().iter().enumerate(){
            for (j,chars_val) in enc_encoding.clone().iter().enumerate() {

                let enc_cmp = ascii_val.eq(chars_val);
                enc_str[i] = enc_cmp.if_then_else(&enc_code[j], &enc_str[i]);

            }
        }

        let mut encoding_clear:Vec<u8> = vec![];
        for i in enc_str.clone(){
            encoding_clear.push(i.decrypt(&ck));
        }
        println!("[debug] the encoding is {:?}", encoding_clear);

        let mut len_coef = coef.len();
        println!("poly degree: {}", len_coef);
        let mut enc_coef = vec![];
        for i in coef.clone() {
            enc_coef.push(FheUint16::encrypt_trivial(i));
        }


        let mut enc_final_state = vec![];

        for i in final_state.clone(){
            enc_final_state.push(FheUint16::encrypt_trivial(i));
        }


        println!("calculating poly...");
        //let mut state_debug = vec![];
        //let mut curr_m_debug = vec![];
        let mut v_states = vec![];
        let mut curr_state = FheUint16::encrypt_trivial(0u8);

        let measurements = 1;
        let mut elapsed_times: Vec<Duration> = Vec::new();
        for _ in 0..measurements {

            curr_state = FheUint16::encrypt_trivial(0u8);
            let start = Instant::now();

            for enc_x in &enc_str {

                let mut curr_m = enc_x + &curr_state * k;
                let mut x = vec![];
                x.push(curr_m.clone());
                //curr_m_debug.push(curr_m.clone());

                //1+coef*x
                let mut sum = enc_coef[0].clone();;
                let mut temp = &x[0] * coef[1];
                sum = &sum + &temp;

                // x = [x,x^2...]
                for i in 2..len_coef {
                    let mut temp_x = x[i - 2].clone();
                    x.push(&temp_x * &curr_m % modulo);

                }
                /*
                let mut v_terms = vec![];
                for i in 2..len_coef {
                    v_terms.push(&x[i - 1] * coef[i]);
                }
    */
                println!("start multi-threading");
                let mut v_terms: Vec<_> = (2..len_coef)
                    .into_par_iter()
                    .map(|i| &x[i - 1] * coef[i] % modulo)
                    .collect();
                //println!("done");

                for i in 2..len_coef {
                    sum = &sum + &v_terms[i-2] ;
                }

                let start_mod = Instant::now();
                println!("final modulo...");
                curr_state = &sum % modulo;
                let duration_mod = start_mod.elapsed();
                println!("the mod duration is {:?}", duration_mod);
                let debug_state:u8 = curr_state.decrypt(&ck);
                println!("debug curr state {:?}", debug_state);

                //state_debug.push(curr_state.clone());
                v_states.push(curr_state.clone());
            }

            let elapsed = start.elapsed();
            elapsed_times.push(elapsed);

            println!("Elapsed time: {:?}", elapsed);
        }



        let total_elapsed: Duration = elapsed_times.iter().sum();
        let average_elapsed = total_elapsed / (measurements as u32);

        println!("Average poly elapsed time: {:?}", average_elapsed);

        println!("checking final state...");
        let mut matching_count:FheUint16 = enc_zero.clone();
        for i in enc_final_state.clone(){
            matching_count = matching_count + FheUint16::cast_from(curr_state.eq(i));
        }
        let matching_res: FheUint16 = FheUint16::cast_from(matching_count.eq(enc_zero.clone()));
        /* 1: not matching; 0: matching */

        println!("sanitization...");

        let measurements = 30;
        let mut elapsed_times: Vec<Duration> = Vec::new();

        let mut sanitized_v = vec![];
        for enc_x in &enc_string_arr_ascii[idx_str] {
            sanitized_v.push(&matching_res * enc_x);
        }


        for _ in 0..measurements {

            let start = Instant::now();

            for enc_x in &enc_string_arr_ascii[idx_str] {
                let a = &matching_res * enc_x;
            }

            let elapsed = start.elapsed();
            elapsed_times.push(elapsed);

            println!("sanitization Elapsed time: {:?}", elapsed);

        }

        // 計算平均經過時間
        //let total_elapsed: Duration = elapsed_times.iter().sum();
        //let average_elapsed = total_elapsed / (measurements as u32);

        println!("Average sanitization elapsed time: {:?}", average_elapsed);


        println!("serialization for single string...");
        let mut serialized_enc_str = Vec::new();
        for i in &sanitized_v {
            bincode::serialize_into(&mut serialized_enc_str, &i)?;
        }
        let file_name = format!("sanitized_string_{}.bin", idx_start_str);
        let mut file_str = File::create(&file_name)?;
        file_str.write(serialized_enc_str.as_slice())?;
        println!("done");

        idx_start_str+=1;
        idx_str+=1;


        println!("decrypt sanitized result");
        let s = decryptStr(sanitized_v, &ck);
        println!("the sanitized res is {:?}", s);

    }

    Ok(())




}

fn extract_number(file_name: &str) -> u32 {
    file_name
        .split('_')
        .last() // 取得最後一部分，例如 "0.bin"
        .and_then(|s| s.strip_suffix(".bin")) // 去除後綴
        .and_then(|s| s.parse::<u32>().ok()) // 轉換成數字
        .unwrap_or(0) // 預設為 0
}

pub fn decryptStr(content: Vec<FheUint<FheUint16Id>>, ck: &ClientKey) -> String {
    let mut v = vec![];

    for byte in &content {
        v.push(byte.decrypt(&ck));
    }

    let measurements = 100;
    let mut elapsed_times: Vec<Duration> = Vec::new();

    for _ in 0..measurements {
        let start = Instant::now();
        for byte in &content {
            let temp: u8 = byte.decrypt(&ck);
        }
        let elapsed = start.elapsed();
        elapsed_times.push(elapsed);
        //println!("Elapsed time: {:?}", elapsed);
    }

    // 計算平均經過時間
    let total_elapsed: Duration = elapsed_times.iter().sum();
    let average_elapsed = total_elapsed / (measurements as u32);

   // println!("Average decryption elapsed time: {:?}", average_elapsed);

    //println!("{:?}", v);
    String::from_utf8(v).unwrap()

}
fn deserialize_sk(serialized_data: &[u8]) -> Result<ServerKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let sk: ServerKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(sk)
}

fn deserialize_ck(serialized_data: &[u8]) -> Result<ClientKey, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let ck: ClientKey = bincode::deserialize_from(&mut to_des_data)?;
    Ok(ck)
}

fn deserialize_str(
    serialized_data: &[u8],
    content_size: u8
) -> Result<Vec<FheUint<FheUint16Id>>, Box<dyn std::error::Error>> {
    let mut to_des_data = Cursor::new(serialized_data);
    let mut v: Vec<FheUint<FheUint16Id>> = vec![];
    for _ in 0..content_size{
        // length of received string
        v.push(bincode::deserialize_from(&mut to_des_data)?);
    }
    Ok(v)
}


