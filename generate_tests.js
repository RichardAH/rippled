
const states = {
    'L': 'Non-existent Account',
    'M': 'Sponsored LiteAcc < 2 Reserve',
    'N': 'Unsponsored Lite Account',
    'O': 'Full Account',
    'P': 'Sponsored LiteAcc >= 2 Reserve'
}

const transitions = {
    '0': 'Payment to Account From Sponsor with tfSponsor Flag',
    '1': 'Remove Sponsor from Account (Upgrade 1)',
    '2': 'Become Full Account (Upgrade 2)',
    '3': 'Forced Delete of Account by Sponsor',
    '4': 'Forced Upgrade of Account by Sponsor',
    '5': 'Downgrade Account by Account',
    '6': 'Delete Account by Account',
    '7': 'Normal Payment To Account From Sponsor',
    '8': 'Normal Payment To Sponsor From Account',
    '9': 'Normal Payment To Non-Sponsor account From Account',
    'A': 'Normal Payment To Account from Non-Sponsor'
}


const normal_payment_min = 10;
const normal_payment_max = 50000;

var fees = {
    "ReserveBase":200000000,                                                                                            
    "ReserveIncrement":50000000
}
/*
accountReserve(0, false) = 200000000
accountReserve(0, true) = 50000000
*/

const transition_amounts = {
    '0': ()=>{return Math.ceil((fees["ReserveIncrement"]/5) * 1.5)},
    '1': ()=>{return Math.ceil(fees["ReserveIncrement"]/5)},
    '4': ()=>{return Math.ceil(fees["ReserveIncrement"]/5)},
    '7': ()=>{return Math.ceil(2.5 * fees["ReserveBase"] + Math.floor(Math.random() * normal_payment_min + normal_payment_max))},
    '8': ()=>{return Math.floor(Math.random() * normal_payment_min + normal_payment_max)},
    '9': ()=>{return Math.floor(Math.random() * normal_payment_min + normal_payment_max)},
    'A': ()=>{return Math.ceil(2.5 * fees["ReserveBase"] + Math.floor(Math.random() * normal_payment_min + normal_payment_max))}
}

const  transition = {
    'L': {'0': 'M', '7': 'O'},
    'M': {'3': 'L', '7': 'P', '8': 'M', '9': 'M', 'A': 'P'},
    'N': {'2': 'O', '6': 'L', '7': 'N', '8': 'N', '9': 'M', 'A': 'N'},
    'O': {'5': 'N', '6': 'L', '7': 'O', '8': 'O', '9': 'M', 'A': 'O'},
    'P': {'4': 'N', '1': 'N', '3': 'L', '7': 'P', '8': 'P', '9': 'P', 'A': 'P'}
}

const lsfSponsor = 0x00080000;
const asfSponsored = 11;
const asfLiteAccount = 10;
const ledgers_before_force = 3;
var global_error_counter = 10000;

const transition_action = {
    '0': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Payment with tfSponsor flag from sponsor to account
        return generate_payment(indent_level, s, positive_test, resolve, reject, current_state,
            sponsor_seed, sponsor, amount, account, lsfSponsor,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '1': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed,third_account, third_account_seed, amount) => {
        // Remove sponsor (Upgrade 1)
        return generate_accountset(indent_level, s, positive_test, resolve, reject, current_state,
            account_seed, account, null, asfSponsored, 
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '2': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Become Full (Upgrade 2)
        return generate_accountset(indent_level, s, positive_test, resolve, reject, current_state,
            account_seed, account, null, asfLiteAccount, 
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '3': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Forced Delete by Sponsor
        let out = ''
//        let out = spacer.repeat(indent_level) + 'ledger_accept(' + ledgers_before_force + ').then( ()=> {\n';
//        indent_level++
            out += generate_accountdelete(indent_level, s, positive_test, resolve, reject, current_state,
                    sponsor_seed, account, sponsor, false,
                    sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
//        indent_level--;
//        out += spacer.repeat(indent_level) + "}).catch(e=>{" + reject + "([e," + (global_error_counter++) + "]);});\n";
        return out
    },
    '4': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Forced Upgrade 1 by Sponsor
//        let out = spacer.repeat(indent_level) + 'ledger_accept(' + ledgers_before_force + ').then( ()=> {\n';
//        indent_level++
        let out = ''
        out +=    generate_accountset(indent_level, s, positive_test, resolve, reject, current_state,
                  sponsor_seed, account, null, asfSponsored, 
                    sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
//        indent_level--;
//        out += spacer.repeat(indent_level) + "}).catch(e=>{" + reject + "([e," + (global_error_counter++) + "]);});\n";
        return out
    },
    '5': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Downgrade by accoount
        return generate_accountset(indent_level, s, positive_test, resolve, reject, current_state,
            account_seed, account, asfLiteAccount, null, 
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '6': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Delete by Accoount
        return generate_accountdelete(indent_level, s, positive_test, resolve, reject, current_state,
            account_seed, account, sponsor, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
    },
    '7': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Sponsor
        return generate_payment(indent_level, s, positive_test, resolve, reject, current_state,
            sponsor_seed, sponsor, amount, account, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '8': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Account
        return generate_payment(indent_level, s, positive_test, resolve, reject, current_state,
            account_seed, account, amount, sponsor, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    '9': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Account to third account
        return generate_payment(indent_level, s, positive_test, resolve, reject, current_state,
            account_seed, account, amount, third_account, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    },
    'A': (indent_level, s, positive_test, resolve, reject, current_state,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount) => {
        // Normal Payment from Non-Sponsor
        return generate_payment(indent_level, s, positive_test, resolve, reject, current_state,
            third_account_seed, third_account, amount, account, false,
            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed);
    }
}

function generate_code(indent_level, s, positive_test, resolve, reject,
                        sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = ""

    if (s == "")
        return out + spacer.repeat(indent_level) + resolve + '(); // t1\n';

    c = s.slice(0,1)
    // todo check current state c

    t = s.slice(1,2)

    if (t == "")
        return out + spacer.repeat(indent_level) + resolve + '(); // t2\n';

    out += spacer.repeat(indent_level) + 'account_info(' + account + ').then(ai => {\n'
    indent_level++


    // assert the state 
/*
    'L': 'Non-existent Account',
    'M': 'Sponsored LiteAcc < 2 Reserve',
    'N': 'Unsponsored Lite Account',
    'O': 'Full Account',
    'P': 'Sponsored LiteAcc >= 2 Reserve'
    lsfLiteAccount = 0x02000000,    // True, this account is a lite account                                            
    lsfSponsored   = 0x04000000,    // True, this account is a sponsored lite account        
 */
//    out += spacer.repeat(indent_level) + 'console.log(ai)\n';
    if (c == 'L') // unfunded account
        out += spacer.repeat(indent_level) + 'if (ai.error != "actNotFound")\n' + 
            spacer.repeat(indent_level + 1) + 
            'reject(["account exists when it should not", ' + (global_error_counter++) + '])\n';
    else if (c != 'L')
    {
        out += spacer.repeat(indent_level) + 'if (typeof(ai.error) != "undefined")\n' + 
            spacer.repeat(indent_level + 1) + 
            'reject(["account does not exist when it should", ' + (global_error_counter++) + '])\n';
   
        // lite account states
        if (c == 'M' || c == 'N' || c == 'P')
            out += spacer.repeat(indent_level) + 'if (ai.result.Flags & lsfLiteAccount == 0)\n' + 
                spacer.repeat(indent_level + 1) + 
                    'reject(["account is not lite when it should be", ' + (global_error_counter++) + '])\n';
        else
        {
            out += spacer.repeat(indent_level) + 'if (ai.result.Flags & lsfLiteAccount != 0)\n' + 
                spacer.repeat(indent_level + 1) + 
                'reject(["account is sponsored when it should not be", ' + (global_error_counter++) + '])\n';
        }

        // sponsored states
        if (c == 'M' || c == 'P')
        {
            out += spacer.repeat(indent_level) + 'if (ai.result.Flags & lsfSponsored == 0)\n' + 
                spacer.repeat(indent_level + 1) + 
                'reject(["account is not sponsored when it should be", ' + (global_error_counter++) + '])\n';
            out += spacer.repeat(indent_level) + 'if (ai.result.account_data.Sponsor == undefined)\n' + 
                spacer.repeat(indent_level + 1) + 
                'reject(["account is missing sfSponsor field", ' + (global_error_counter++) + '])\n';
        }
        else
        {
            out += spacer.repeat(indent_level) + 'if (ai.result.Flags & lsfSponsored != 0)\n' + 
                spacer.repeat(indent_level + 1) + 
                'reject(["account is sponsored when it should not be", ' + (global_error_counter++) + '])\n';
        }
    }

    amount = null
    if (t in transition_amounts)
        amount = transition_amounts[t]()
    out += spacer.repeat(indent_level) + 'ledger_accept('+(t == '3' || t == '4' ? '256' : '1')+').then( () =>  {\n';
    indent_level++;
    out += spacer.repeat(indent_level) + '/* ' + transitions[t] + ' [' + t + '] */\n' +
                transition_action[t](indent_level, s.slice(2), positive_test, resolve, reject, c,
                    sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed, amount);
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e=>{' + reject + '([e,' + (global_error_counter++) + ']);});\n';
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e=>{' + reject + '([e,' + (global_error_counter++) + ']);});\n';
    return out
}


const spacer = '    ';
function human_readable(indent_level, s, quote_after_indent)
{
    let out = "";
    let level = 1;
        
    for (let x = 0; x < s.length-1; ++x)
    {
        let c = s[x];
        let n = (x + 1 < s.length ? s[x+1] : '')
        n = (n in states ? "(" + states[n] + ")" : "(INVALID)")

        if (c in transitions)
            out += " + " +
                transitions[c] + "" + (n != '' ? " = " + n : "") + (x == s.length-2 ? "" : "\n")
        else if (c in states)
            out += spacer.repeat(indent_level + level) + "(" + states[c] + ")" 
        else if (c == 'X')
            out += spacer.repeat(indent_level + level) + "(INVALID)" 
        else
        {
            console.log('s', s)
            throw("invalid char in`" + s + '`:`' + c + '`')
        }
    }

    if (quote_after_indent)
    {
        lines = out.split('\n')
        out = ""
        let front = new RegExp('^' + spacer.repeat(indent_level), 'img')
        for (x in lines)
        {
            out += lines[x].replace(front, spacer.repeat(indent_level) + '`') + '\\n` + \n'
        }
        out = out.slice(0,-3)
    }
    return out

}

function generate_payment(indent_level, s, positive_test, resolve, reject,  current_state,
                            seed, from, amount, dest, flags, 
                            sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = "";
    out += spacer.repeat(indent_level) + 'api.prepareTransaction({\n';
    indent_level++;
//        out += spacer.repeat(indent_level) + 'LastLedgerSequence: max_ledger,\n';
        out += spacer.repeat(indent_level) + 'Account: ' + from + ',\n';
        out += spacer.repeat(indent_level) + 'TransactionType: "Payment",\n';
        out += spacer.repeat(indent_level) + 'Amount: "' + amount + '",\n';
        out += spacer.repeat(indent_level) + 'Destination: ' + dest + ',\n';
        if (flags)
            out += spacer.repeat(indent_level) + 'Flags: ' + flags + ',\n';
        out += spacer.repeat(indent_level) + 'Fee: "10000"\n';
    indent_level--;
    out += spacer.repeat(indent_level) + '}).then(unsigned_txn => {\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'console.log("submitting txn", unsigned_txn.txJSON);\n';
        out += spacer.repeat(indent_level) + 'let signed_txn = api.sign(unsigned_txn.txJSON, ' + seed + ')\n';
        out += spacer.repeat(indent_level) + 'api.submit(signed_txn.signedTransaction).then(response => {\n';
        indent_level++;
        if (s.length > 1)
        {
            out += spacer.repeat(indent_level) + 'console.log(response);\n'
            out += spacer.repeat(indent_level) + 'if (response.resultCode != "tesSUCCESS") return ' + reject + 
                '([response.resultCode,' + global_error_counter++ + ']);\n';
            out += generate_code(indent_level, s, positive_test, resolve, reject,
                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed
            );
        }
        else
            out += spacer.repeat(indent_level) + resolve + '([response.resultCode ' +
                (positive_test ? '=' : '!') + '= "tesSUCCESS", response.resultCode]);\n';
        indent_level--;
        out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    return out;
}

function generate_accountdelete(indent_level, s, positive_test, resolve, reject,  current_state,
                                seed, from, dest, flags,
                                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = "";
    out += spacer.repeat(indent_level) + 'let accdel = {\n';
    indent_level++;
//        out += spacer.repeat(indent_level) + 'LastLedgerSequence: max_ledger,\n';
        out += spacer.repeat(indent_level) + 'Account: ' + from + ',\n';
        out += spacer.repeat(indent_level) + 'TransactionType: "AccountDelete",\n';
        out += spacer.repeat(indent_level) + 'Destination: ' + dest + ',\n';
        if (flags)
            out += spacer.repeat(indent_level) + 'Flags: ' + flags + ',\n';
        out += spacer.repeat(indent_level) + 'Fee: "' + 
            (current_state == 'O' ? Math.ceil(fees["ReserveBase"]/4) : Math.ceil(fees["ReserveIncrement"]/5)) + '"\n'; // delete full/lite acccount fee
    indent_level--;
    out += spacer.repeat(indent_level) + '}\n';
    out += spacer.repeat(indent_level) + 'console.log("accdel", accdel);\n';
    out += spacer.repeat(indent_level) + 'api.prepareTransaction(accdel).then(unsigned_txn => {\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'console.log("submitting txn", unsigned_txn.txJSON);\n';
        out += spacer.repeat(indent_level) + 'let signed_txn = api.sign(unsigned_txn.txJSON, ' + seed + ')\n';
        out += spacer.repeat(indent_level) + 'api.submit(signed_txn.signedTransaction).then(response => {\n';
        indent_level++;
        if (s.length > 1)
        {
            out += spacer.repeat(indent_level) + 'console.log(response);\n'
            out += spacer.repeat(indent_level) + 'if (response.resultCode != "tesSUCCESS") return ' + reject + 
                '([response.resultCode,' + global_error_counter++ + ']);\n';
            out += generate_code(indent_level, s, positive_test, resolve, reject,
                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed
            );
        }
        else
            out += spacer.repeat(indent_level) + resolve + '([response.resultCode ' +
                (positive_test ? '=' : '!') + '= "tesSUCCESS", response.resultCode]);\n';
        indent_level--;
        out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    return out;
}

function generate_accountset(indent_level, s, positive_test, resolve, reject, current_state,
                                seed, from, setflag, clearflag,
                                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed)
{
    let out = "";
    out += spacer.repeat(indent_level) + 'api.prepareTransaction({\n';
    indent_level++;
//        out += spacer.repeat(indent_level) + 'LastLedgerSequence: max_ledger,\n';
        out += spacer.repeat(indent_level) + 'Account: ' + from + ',\n';
        out += spacer.repeat(indent_level) + 'TransactionType: "AccountSet",\n';
        if (setflag !== undefined && setflag !== null)
            out += spacer.repeat(indent_level) + "SetFlag: " + setflag + ",\n";
        else
            out += spacer.repeat(indent_level) + "ClearFlag: " + clearflag + ",\n";
        out += spacer.repeat(indent_level) + 'Fee: "10000"\n';
    indent_level--;
    out += spacer.repeat(indent_level) + '}).then(unsigned_txn => {\n';
    indent_level++;
        out += spacer.repeat(indent_level) + 'console.log("submitting txn", unsigned_txn.txJSON);\n';
        out += spacer.repeat(indent_level) + 'let signed_txn = api.sign(unsigned_txn.txJSON, ' + seed + ')\n';
        out += spacer.repeat(indent_level) + 'api.submit(signed_txn.signedTransaction).then(response => {\n';
        indent_level++;
        if (s.length > 1)
        {
            out += spacer.repeat(indent_level) + 'console.log(response);\n'
            out += spacer.repeat(indent_level) + 'if (response.resultCode != "tesSUCCESS") return ' + reject + 
                '([response.resultCode,' + global_error_counter++ + ']);\n';
            out += generate_code(indent_level, s, positive_test, resolve, reject,
                sponsor, sponsor_seed, account, account_seed, third_account, third_account_seed
            );
        }
        else
            out += spacer.repeat(indent_level) + resolve + '([response.resultCode ' +
                (positive_test ? '=' : '!') + '= "tesSUCCESS", response.resultCode]);\n';
        indent_level--;
        out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    indent_level--;
    out += spacer.repeat(indent_level) + '}).catch(e => {' + reject + '([e, ' + global_error_counter++ + ']);});\n'
    return out;
}




function positive(state, stack, positive_cases)
{

    if (positive_cases === undefined)
        positive_cases = [];

    if (stack == undefined) stack = "";

    if (stack.match(state))
    {
        positive_cases.push(stack + state);
        return;
    }

    stack += state;

    for (let x in transition[state])
        positive(transition[state][x], stack + x, positive_cases);

    return positive_cases;
}

function negative(state, stack, negative_cases)
{
    if (negative_cases === undefined)
        negative_cases = [];

    if (stack == undefined) stack = "";

    if (stack.match(state))
    {
        return;
    }

    stack += state;

    let allowed_transitions = transition[state];

    for (let t in transitions)
        if (!(t in transition[state]))
            negative_cases.push(stack + t + 'X');
        else
            negative(transition[state][t], stack + t, negative_cases);

    return negative_cases;
}


let positive_cases = positive('L').sort();
let negative_cases = negative('L').sort();
let counter = 1;

// print header
console.log(`
const keypairs = require("ripple-keypairs")
const api_factory = require('ripple-lib').RippleAPI
const make_api = ()=>{
    return new api_factory({server: 'ws://localhost:6005', maxFeeXRP:"1000"});
};

var api = make_api();
const wsf = require('ws')

const lsfLiteAccount = 0x02000000
const lsfSponsored   = 0x04000000

function account_info(account) 
{
    return new Promise((resolve, reject) => {
        const after_disconnect = (e)=> {

            if (e)
                console.log("api.disconnect:", e)

            const ws = new wsf('ws://localhost:6005')
            
            ws.on('message', retry = m=>{
                api = make_api();
                api.connect().then(() => {
                    try {
                        i = JSON.parse(m)
                        console.log(i)
                        resolve(i)
                    } catch (e) {
                        reject(m)
                    }
                }).catch((e)=>{
                    //reject(e);
                    retry()
                })
            })

            
            ws.on('open', ()=>{
               ws.send('{"command":"account_info", "account":"' + account + '"}') 
            })
        }
        after_disconnect();
//        api.disconnect().then(after_disconnect).catch(after_disconnect);
    })
}

function ledger_accept(n) 
{
    return new Promise((resolve, reject) => {
        const after_disconnect = (e)=> {

            if (e)
                console.log("api.disconnect:", e)

            const ws = new wsf('ws://localhost:6005')
            ws.on('open', ()=>{
                //max_ledger += n;
                if (n == undefined)
                    n = 1;
                for (let i = 0; i < n; ++i)
                {
                    if (i % 64 == 0)
                        console.log("ledger_accept ... ", i)
                    ws.send('{"command":"ledger_accept"}');
                }
                ws.close();

/*
> {"command": "ledger_entry",  "index": "4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651",  "ledger_index": "validated"}
< {"result":{
"index":"4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651",
"ledger_hash":"26E0C6882676307E3B3C6B6C55B69C280C72AF9E9AD6A6ED762EF78FF3563714",
"ledger_index":292,
"node":{
    "BaseFee":"a",
    "Flags":0,
    "LedgerEntryType":"FeeSettings",
    "ReferenceFeeUnits":10,
    "ReserveBase":20000000,
    "ReserveIncrement":5000000,
    "index":"4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651"},
    "validated":true
},"status":"success","type":"response"}

< {"error":"entryNotFound","ledger_hash":"E395D322D748D4C792BE4E345DCAB83A86B636D5FAAE9A68C81C9AB0DF756CBA","ledger_index":2,"request":{"command":"ledger_entry","index":"4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651","ledger_index":"validated"},"status":"error","type":"response","validated":true}
*/


                let seconds = n/128 + 1;
                setTimeout(retry = ()=>{
                    ws2 = new wsf('ws://localhost:6005')
                    ws2.on('open', ()=>{
                        ws2.send('{"command": "ledger_entry",  "index": "4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651",  "ledger_index": "validated"}');
                        ws2.on('message', m => {
                            let f = JSON.parse(m)
                            if (f.result && f.result.node)
                                fees = f.result.node

                            ws2.close()
                            api = make_api();
                            api.connect().then(() => {
                                resolve();
                            }).catch((e)=>{
                                retry();
                            })
                        })
                    });
                }, seconds * 1000);

            });
        };
        after_disconnect();
        //api.disconnect().then(after_disconnect).catch(after_disconnect);
    });
};

function random_address()
{
    let s = keypairs.generateSeed()
    let k = keypairs.deriveKeypair(s)
    let r = keypairs.deriveAddress(k.publicKey)
    return {seed: s, address: r, key: k}
}

const genesis = {seed: 'snoPBrXtMeMyMHUVTgbuqAfg1SUTb', address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'};
const sponsor = random_address();
const third = random_address();

    api.connect().then(() => {
        (new Promise((resolve, reject)=>{
`);
console.log(generate_payment(3, '', true, 'resolve','reject', 'L',
    'genesis.seed', 'genesis.address', '100000000000', 'sponsor.address', ''));
console.log(`
        })).then(setup_result=>{
            console.log("setup result:", setup_result);
            tests = {};
            tests_description = {};
            const tests_updated = (testid)=>{
                console.log(tests_description[testid])
                console.log("===> " + (tests[testid][0] === true ? 'PASS' :  'FAIL' ) + ' - ' + 
                    (typeof(tests[testid]) == 'string' ? tests[testid] :  tests[testid][1]))
                testid++
                let prom = tests_functions(testid);
                if (prom)
                    prom.then(
                        result => {
                            tests[testid] = result;
                            ledger_accept(1).then(()=>{
                                tests_updated(testid);
                            }).catch(e => {
                                console.log(e)
                                process.exit(1);
                            })
                        }
                    ).catch(e => {tests[testid] = "ERROR: " + JSON.stringify(e) + "; " + e; tests_updated(testid);});
                else
                {
                    console.log("finished")
                    process.exit(0)
                }
            }
            function tests_functions(testid)
            {
`);


function produce_cases(indent_level, cases, namespace, counter = 0, should_succeed = true)
{
    for (let x in cases)
    for (let i = 0; i < 2; ++i)
    {
        console.log(spacer.repeat(indent_level) + '/* ' + namespace + ' test ' + counter + ' [' + cases[x] + ']')
        console.log(human_readable(indent_level, cases[x]) + ' run=' + (i+1) + '/ */')
        console.log(spacer.repeat(indent_level) +
            'if (testid == ' + counter + ') return new Promise((resolve, reject)=>{');
        console.log(spacer.repeat(indent_level + 1) + 'const account = random_address();');
        console.log(spacer.repeat(indent_level + 1) + "tests_description[" + counter + "] = \n" + 
            spacer.repeat(indent_level + 1) + '`' + namespace + " test " + counter + " [" + cases[x] + "]:\\n` +\n" + 
            human_readable(indent_level + 1, cases[x], true) + ";")
        console.log(generate_code(indent_level + 1, cases[x], should_succeed, 'resolve', 'reject',
            'sponsor.address', 'sponsor.seed', 'account.address', 'account.seed', 'third.address', 'third.seed'));
        console.log(spacer.repeat(indent_level) + '});')
/*        console.log(spacer.repeat(indent_level) + 'test' + counter + '.then(' +
            'result => {tests[' + counter + 
            '] = result; tests_updated('+counter+');}).catch(\n' + 
            spacer.repeat(indent_level + 1) + 'e => {tests[' + counter + 
            ']="ERROR: " + JSON.stringify(e) + "; " + e; tests_updated(' + counter + ');})');
*/
        counter++;
    }
    return counter
}


counter = produce_cases(4, [positive_cases[0]], "positive", 0, true);
//produce_cases(negative_cases, "negative", counter, false);
console.log(spacer.repeat(4) + 'return false;')
console.log(spacer.repeat(3) + '}')
console.log(spacer.repeat(3) + 'tests_functions(0).then(result => {tests[0] = result; tests_updated(0);}).catch(\n' +
   spacer.repeat(3) + 'e => {tests[0]="ERROR: " + JSON.stringify(e) + "; " + e; tests_updated(0);})');
console.log('       }).catch(e=>{throw(e);});');
console.log('   }).catch(console.error);');

