use serde::Deserialize;
use serde_json::json;
use std::{collections::HashMap, fs, io::{self, Write}, time::{SystemTime, UNIX_EPOCH}};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
use reqwest::blocking::Client;
use anyhow::{Result, bail};

#[derive(Deserialize)]
struct Wallet {
    #[serde(rename = "priv")]
    priv_: String,
    addr: String,
    rpc: String,
}

#[derive(Deserialize)]
struct Method {
    name: String,
    label: String,
    params: Vec<Param>,
    #[serde(rename = "type")]
    method_type: String,
}

#[derive(Deserialize)]
struct Param {
    name: String,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    param_type: String,
    example: Option<String>,
    max: Option<u64>,
}

#[derive(Deserialize)]
struct Interface {
    contract: String,
    methods: Vec<Method>,
}

#[derive(Deserialize)]
struct BalanceResponse {
    balance_raw: String,
    nonce: u64,
}

fn api_call<T: for<'de> Deserialize<'de>>(
    client: &Client,
    method: &str,
    url: &str,
    data: Option<serde_json::Value>
) -> Result<T> {
    let response = match method {
        "GET" => client.get(url).send()?,
        "POST" => client.post(url).json(&data).send()?,
        _ => bail!("unsupported method"),
    };
    
    if response.status().as_u16() >= 400 {
        bail!("api error: {}", response.text()?);
    }
    
    Ok(response.json()?)
}

fn sign_tx(sk: &Ed25519SigningKey, tx: &HashMap<&str, String>) -> String {
    let blob = format!(
        r#"{{"from":"{}","to_":"{}","amount":"{}","nonce":{},"ou":"{}","timestamp":{}}}"#,
        tx["from"], tx["to_"], tx["amount"], tx["nonce"], tx["ou"], tx["timestamp"]
    );
    
    let signature = sk.sign(blob.as_bytes());
    general_purpose::STANDARD.encode(signature.to_bytes())
}

fn get_balance(client: &Client, api_url: &str, addr: &str) -> Result<(f64, u64)> {
    let balance: BalanceResponse = api_call(
        client,
        "GET",
        &format!("{}/balance/{}", api_url, addr),
        None
    )?;
    
    Ok((balance.balance_raw.parse::<f64>()? / 1_000_000.0, balance.nonce))
}

fn view_call(
    client: &Client,
    api_url: &str,
    contract: &str,
    method: &str,
    params: &[String],
    caller: &str
) -> Result<Option<String>> {
    let response: serde_json::Value = api_call(
        client,
        "POST",
        &format!("{}/contract/call-view", api_url),
        Some(json!({
            "contract": contract,
            "method": method,
            "params": params,
            "caller": caller
        }))
    )?;
    
    Ok(if response["status"] == "success" {
        // Handle different types of results
        match &response["result"] {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            serde_json::Value::Null => Some("null".to_string()),
            _ => Some(response["result"].to_string())
        }
    } else {
        None
    })
}

fn call_contract(
    client: &Client,
    api_url: &str,
    sk: &Ed25519SigningKey,
    from_addr: &str,
    contract: &str,
    method: &str,
    params: &[String]
) -> Result<String> {
    let (_, nonce) = get_balance(client, api_url, from_addr)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
    
    let mut tx = HashMap::new();
    tx.insert("from", from_addr.to_string());
    tx.insert("to_", contract.to_string());
    tx.insert("amount", "0".to_string());
    tx.insert("nonce", (nonce + 1).to_string());
    tx.insert("ou", "1".to_string());
    tx.insert("timestamp", timestamp.to_string());
    
    let signature = sign_tx(sk, &tx);
    let public_key = general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
    
    let response: serde_json::Value = api_call(
        client,
        "POST",
        &format!("{}/call-contract", api_url),
        Some(json!({
            "contract": contract,
            "method": method,
            "params": params,
            "caller": from_addr,
            "nonce": nonce + 1,
            "timestamp": timestamp,
            "signature": signature,
            "public_key": public_key
        }))
    )?;
    
    Ok(response["tx_hash"].as_str().unwrap_or("").to_string())
}

fn wait_tx(client: &Client, api_url: &str, tx_hash: &str, timeout: u64) -> Result<bool> {
    let start = SystemTime::now();
    
    loop {
        let elapsed = SystemTime::now().duration_since(start)?.as_secs();
        if elapsed > timeout {
            return Ok(false);
        }
        
        let tx: serde_json::Value = api_call(
            client,
            "GET",
            &format!("{}/tx/{}", api_url, tx_hash),
            None
        )?;
        
        if tx["status"] == "confirmed" {
            return Ok(true);
        }
        
        print!(".");
        io::stdout().flush()?;
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn parse_params(params: &[Param]) -> Vec<String> {
    params.iter().map(|p| {
        let mut prompt = format!("{}", p.name);
        if let Some(example) = &p.example {
            prompt.push_str(&format!(" (e.g. {})", example));
        }
        if let Some(max) = p.max {
            prompt.push_str(&format!(" (max: {})", max));
        }
        prompt.push_str(": ");
        read_input(&prompt)
    }).collect()
}

fn main() -> Result<()> {
    let wallet: Wallet = serde_json::from_str(&fs::read_to_string("wallet.json")?)?;
    let interface: Interface = serde_json::from_str(&fs::read_to_string("exec_interface.json")?)?;
    
    let sk_bytes = general_purpose::STANDARD.decode(&wallet.priv_)?;
    let sk = Ed25519SigningKey::from_bytes(&sk_bytes.try_into().unwrap());
    
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(100))
        .build()?;
    
    loop {
        println!("\n--- ocs01 test client ---");
        println!("contract: {}", interface.contract);
        
        let (balance, nonce) = get_balance(&client, &wallet.rpc, &wallet.addr)?;
        println!("your balance: {:.6} oct (nonce: {})", balance, nonce);
        println!("\nselect method:");
        
        for (i, method) in interface.methods.iter().enumerate() {
            println!("{}. {}", i + 1, method.label);
        }
        println!("0. exit");
        
        let choice = read_input("\nchoice: ");
        if choice == "0" {
            break;
        }
        
        if let Ok(idx) = choice.parse::<usize>() {
            if idx > 0 && idx <= interface.methods.len() {
                let method = &interface.methods[idx - 1];
                println!("\n--- {} ---", method.name);
                
                let params = parse_params(&method.params);
                
                match method.method_type.as_str() {
                    "view" => {
                        match view_call(&client, &wallet.rpc, &interface.contract, &method.name, &params, &wallet.addr) {
                            Ok(result) => println!("\nresult: {}", result.unwrap_or_else(|| "none".to_string())),
                            Err(e) => println!("error: {}", e),
                        }
                    }
                    "call" => {
                        match call_contract(&client, &wallet.rpc, &sk, &wallet.addr, &interface.contract, &method.name, &params) {
                            Ok(tx_hash) => {
                                println!("\ntx: {}", tx_hash);
                                if read_input("wait for confirmation? y/n: ").to_lowercase() == "y" {
                                    print!("waiting");
                                    io::stdout().flush()?;
                                    match wait_tx(&client, &wallet.rpc, &tx_hash, 100) {
                                        Ok(true) => println!("\nconfirmed"),
                                        Ok(false) => println!("\ntimeout"),
                                        Err(e) => println!("\nerror: {}", e),
                                    }
                                }
                            }
                            Err(e) => println!("error: {}", e),
                        }
                    }
                    _ => println!("unknown method type"),
                }
            }
        }
        
        read_input("\npress enter to continue...");
    }
    
    println!("\nbye");
    Ok(())
}
