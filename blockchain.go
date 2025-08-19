package main

// 导入标准库：fmt 用于打印；time 用于时间戳；crypto/sha256 用于哈希；
// encoding/hex 把字节转成十六进制字符串；strings 处理字符串前缀匹配；
// bytes 用于连接字节片；strconv 把数字转字符串，保证拼接时稳定。
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Transaction 表示一笔极简交易（只包含 from、to、amount 三个字段）。
type Transaction struct {
	From   string // 付款方地址或标识（演示用，未做校验）
	To     string // 收款方地址或标识
	Amount int    // 转账数量，演示用 int 即可
}

// Block 表示一个区块，包括索引、高度、时间戳、前一区块哈希、
// 当前区块哈希、工作量证明用的 nonce，以及打包的交易列表。
type Block struct {
	Index        int           // 区块高度，从 0 开始
	Timestamp    int64         // 区块生产的 Unix 时间戳（秒）
	PrevHash     string        // 前一个区块的哈希（创世区块为空串或固定值）
	Hash         string        // 当前区块的哈希（满足难度目标）
	Nonce        int64         // 挖矿过程中尝试的计数器
	Transactions []Transaction // 该区块包含的交易
}

// Blockchain 是链的容器，持有所有区块与全局难度设置。
type Blockchain struct {
	Blocks     []Block // 区块按顺序存放，Blocks[0] 是创世区块
	Difficulty int     // 难度：要求哈希前缀有多少个 '0'（十六进制字符串）
}

// newGenesisBlock 创建创世区块（链的第一个区块）。
func newGenesisBlock(difficulty int) Block {
	// 创世区块的基础字段：索引为 0，时间戳为当前时间，PrevHash 设为固定值
	b := Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		PrevHash:     "",
		Transactions: []Transaction{}, // 创世区块可为空交易
	}
	// 通过挖矿（PoW）求解一个满足难度的哈希
	b.Hash, b.Nonce = mine(b, difficulty)
	return b
}

// newBlock 基于上一块创建新区块（未挖矿前先填充必要元数据）。
func newBlock(prev Block, txs []Transaction) Block {
	// 填写索引递增、时间戳、前哈希和交易等元数据
	return Block{
		Index:        prev.Index + 1,
		Timestamp:    time.Now().Unix(),
		PrevHash:     prev.Hash,
		Transactions: txs,
	}
}

// serializeTransactions 把交易列表稳定地序列化为字节流，确保哈希可复现。
func serializeTransactions(txs []Transaction) []byte {
	// 使用 bytes.Buffer 高效拼接字节
	var buf bytes.Buffer
	for _, tx := range txs {
		// 每笔交易按固定顺序与分隔符拼接，避免哈希不稳定
		buf.WriteString(tx.From)
		buf.WriteByte('|')
		buf.WriteString(tx.To)
		buf.WriteByte('|')
		buf.WriteString(strconv.Itoa(tx.Amount))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// calculateHash 计算一个区块（当前 nonce 下）对应的哈希。
func calculateHash(b Block) string {
	// 将区块关键字段按固定顺序拼接成字节，确保同一内容哈希一致
	var buf bytes.Buffer
	buf.WriteString(strconv.Itoa(b.Index))
	buf.WriteByte('|')
	buf.WriteString(strconv.FormatInt(b.Timestamp, 10))
	buf.WriteByte('|')
	buf.WriteString(b.PrevHash)
	buf.WriteByte('|')
	buf.Write(serializeTransactions(b.Transactions))
	buf.WriteByte('|')
	buf.WriteString(strconv.FormatInt(b.Nonce, 10))

	// 对拼接后的字节做一次 SHA-256，得到 32 字节摘要
	sum := sha256.Sum256(buf.Bytes())
	// 把摘要转为十六进制字符串，便于展示与比较前缀
	return hex.EncodeToString(sum[:])
}

// mine 执行工作量证明：不断尝试 nonce，直到哈希满足难度前缀。
func mine(b Block, difficulty int) (hash string, nonce int64) {
	// 目标前缀由 difficulty 个 '0' 组成（十六进制字符），例如难度 4 => "0000"
	targetPrefix := strings.Repeat("0", difficulty)
	// 从 0 开始尝试 nonce 递增
	for {
		b.Nonce = nonce
		h := calculateHash(b)
		// 判断哈希是否以足够数量的 '0' 开头
		if strings.HasPrefix(h, targetPrefix) {
			return h, nonce // 满足条件，返回哈希与对应 nonce
		}
		nonce++ // 不满足则继续尝试
	}
}

// AddBlock 把一组交易打包成区块、挖矿并加入链尾。
func (bc *Blockchain) AddBlock(txs []Transaction) Block {
	// 取当前链的最后一个区块作为父块
	prev := bc.Blocks[len(bc.Blocks)-1]
	// 先构造未挖矿的新块（包含元数据与交易）
	b := newBlock(prev, txs)
	// 进行 PoW，得到满足难度的哈希与 nonce
	h, n := mine(b, bc.Difficulty)
	b.Hash = h
	b.Nonce = n
	// 将新块追加到链上
	bc.Blocks = append(bc.Blocks, b)
	return b
}

// IsValid 校验整条链的一致性与工作量证明是否成立。
func (bc *Blockchain) IsValid() bool {
	// 从第 1 个区块开始（跳过创世块），逐一检查
	for i := 1; i < len(bc.Blocks); i++ {
		cur := bc.Blocks[i]
		prev := bc.Blocks[i-1]
		// 1) 前哈希要匹配
		if cur.PrevHash != prev.Hash {
			return false
		}
		// 2) 重新计算当前块哈希，必须等于记录值
		if calculateHash(cur) != cur.Hash {
			return false
		}
		// 3) 哈希需满足难度前缀
		if !strings.HasPrefix(cur.Hash, strings.Repeat("0", bc.Difficulty)) {
			return false
		}
	}
	return true // 所有检查通过，链有效
}

// NewBlockchain 创建一条带有创世区块的新链，并设置全局难度。
func NewBlockchain(difficulty int) *Blockchain {
	// 先生成创世区块
	genesis := newGenesisBlock(difficulty)
	// 初始化链结构体并返回指针
	return &Blockchain{
		Blocks:     []Block{genesis},
		Difficulty: difficulty,
	}
}

// printBlock 辅助函数：友好地打印一个区块的关键字段。
func printBlock(b Block) {
	fmt.Println("---------------- block ----------------")
	fmt.Println("Index:", b.Index)
	fmt.Println("Timestamp:", b.Timestamp)
	fmt.Println("PrevHash:", b.PrevHash)
	fmt.Println("Hash:", b.Hash)
	fmt.Println("Nonce:", b.Nonce)
	fmt.Println("Txs:")
	for i, tx := range b.Transactions {
		fmt.Printf("  #%d %s -> %s : %d\n", i, tx.From, tx.To, tx.Amount)
	}
}

// main 是程序入口：创建链、添加区块、校验并打印结果。
func main() {
	// 设定一个适中的难度（本地演示建议 4~5；数字越大越慢）
	difficulty := 4
	// 创建一条新区块链（自动带创世区块）
	bc := NewBlockchain(difficulty)
	// 打印创世区块
	printBlock(bc.Blocks[0])

	// 组装第一批交易并打包成区块
	txs1 := []Transaction{
		{From: "alice", To: "bob", Amount: 10},
		{From: "carol", To: "dave", Amount: 5},
	}
	b1 := bc.AddBlock(txs1)
	printBlock(b1)

	// 再组装第二批交易，继续出块
	txs2 := []Transaction{
		{From: "bob", To: "alice", Amount: 3},
		{From: "dave", To: "carol", Amount: 2},
	}
	b2 := bc.AddBlock(txs2)
	printBlock(b2)

	// 最后校验一下整条链是否有效
	fmt.Println("chain valid:", bc.IsValid())
}
