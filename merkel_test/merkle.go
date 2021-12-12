package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
)

func main() {

	files, err := os.ReadDir("./to_export")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		fmt.Println(file.Name())
	}

	empty := make([]byte, 0)
	name := []byte("to_export")
	empty2 := make([]*Node, 0)

	racine, err := NewDirectory(&empty, nil, &empty2, name)
	if err != nil {
		log.Printf("Error : %v\n", err)
	}
	newMerkleTree(&racine, ".")

	fmt.Printf("root hash:%v \n", racine.content)
	test := append(append(racine.son[0].checksum, racine.son[1].checksum...), racine.son[2].checksum...)
	fmt.Printf("\nverif : %v\n\n", test)

	for _, n := range racine.son {
		fmt.Printf("Name : %v\n", string(n.name))
	}
	fmt.Printf("README : %v\n", string(racine.son[2].content))

}

//===================================================================================================
//									Merkle s tree
//===================================================================================================

type Node struct {
	content   []byte
	checksum  []byte
	chunk     bool
	directory bool
	root      *Node
	son       []*Node
	name      []byte
}

func NewNode(cont *[]byte, chu bool, dir bool, roo *Node, son *[]*Node, name []byte) (Node, error) {
	var err error
	err = nil
	checksum := make([]byte, 32)
	if len(*cont) > 128 && !dir {
		err = errors.New("content is more than 1024 bits")
	}
	if len(*son) > 32 && !dir {
		err = errors.New("parent of too many nodes")
	}
	if chu {
		checks := sha256.Sum256(*cont)
		checksum = checks[:]
	}

	nod := Node{*cont, checksum, chu, dir, roo, *son, name}
	return nod, err
}

func NewDirectory(cont *[]byte, roo *Node, son *[]*Node, name []byte) (Node, error) {
	return NewNode(cont, false, true, roo, son, name)
}

func NewBigFile(cont *[]byte, roo *Node, son *[]*Node, name []byte) (Node, error) {
	return NewNode(cont, false, false, roo, son, name)
}

func NewFile(cont *[]byte, roo *Node, name []byte) (Node, error) {
	emptyTabNode := make([]*Node, 0)
	return NewNode(cont, true, false, roo, &emptyTabNode, name)
}

func log_32(x int) (int, int) {
	if x == 0 {
		return 0, 0
	}
	log_32 := 0
	for (x >> (5 * log_32)) > 0 {
		log_32++
	}
	log_32--
	coef := x >> (5 * log_32)
	return coef, log_32
}

func addSon(dady *Node, child *Node) {
	tmp := make([]*Node, 1)
	tmp[0] = child
	dady.son = append(dady.son, tmp...)
}

func addHashToFatherContent(dady *Node, hash []byte) {
	dady.content = append(dady.content, hash...)
}

func fillBigFile(node *Node, data *[][]byte) error {
	length := len(*data)
	emptyData := make([]byte, 0)
	emptySon := make([]*Node, 0)
	noName := make([]byte, 0)
	if length > 32 {
		nbBigFileNeeded, log_len := log_32(length)
		cmptr := 0
		for cmptr <= nbBigFileNeeded { //Il faut nbNeeded + 1 pour le reste qui n'est pas plein
			bigF, err := NewBigFile(&emptyData, node, &emptySon, noName)
			if err != nil {
				log.Printf("Error new bigFile : %v\n", err)
				return err
			}
			//Ajout aux fils du père
			addSon(node, &bigF)

			limit := (1 << (5 * log_len))
			//Test pour ne pas ajouter des 0 inutiles dans le dernier bigFile qui ne sera pas complet
			l := len(*data)
			if limit > l {
				limit = l
			}
			newdata := (*data)[:limit]
			fillBigFile(&bigF, &newdata)
			//ajout du hash au contenu du père
			addHashToFatherContent(node, bigF.checksum)
			datatmp := (*data)[limit:]
			data = &datatmp
			cmptr++
		}
		//On a fini de rempli le bigFile node, on peut calculer son hash
		hash := sha256.Sum256(node.content)
		node.checksum = hash[:]
	} else { //si len < 32
		bigF, err := NewBigFile(&emptyData, node, &emptySon, noName)
		if err != nil {
			log.Printf("Error new bigFile : %v\n", err)
			return err
		}
		//ajout aux fils du père
		addSon(node, &bigF)
		cmptr := 0
		for cmptr < length {
			file, err := NewFile(&((*data)[cmptr]), &bigF, noName)
			if err != nil {
				log.Printf("Error new File : %v\n", err)
				return err
			}
			//ajout aux fils du père
			addSon(&bigF, &file)
			hash := sha256.Sum256((*data)[cmptr])
			file.checksum = hash[:]
			//Ajout du hash au contenu du père
			addHashToFatherContent(&bigF, hash[:])
			cmptr++

		}
		//On a fini de remplir le bigFile bigF, on peut calculer son hash
		hash := sha256.Sum256(bigF.content)
		bigF.checksum = hash[:]
	}
	return nil
}

func FileParser(filepath string) [][]byte {
	//subdivise un fichier en chunks de 1024 bits recursivement
	var tamp []byte
	buf, err := os.ReadFile(filepath)
	if err != nil {
		log.Panic(err)
	}
	ret := make([][]byte, 0, len(buf)/128+1)
	for len(buf) >= 128 {
		tamp, buf = buf[:128], buf[128:]
		ret = append(ret, tamp)
	}
	if len(buf) > 0 {
		ret = append(ret, buf)
	}
	return ret
}

func newMerkleTree(topDir *Node, fileParentPath string) {
	contTmp := make([]byte, 0)
	nodTmp := make([]*Node, 0)
	fmt.Printf("%v \n", fileParentPath+"/"+string(topDir.name))
	files, err := os.ReadDir(fileParentPath + "/" + string(topDir.name))
	if err != nil {
		log.Fatal(err)
	}
	if len(files) > 16 {
		log.Fatalf("Too much elements in directory\n")
	}
	for _, file := range files {
		if file.IsDir() {
			//création du Dir file.name()
			childDir, err := NewDirectory(&contTmp, topDir, &nodTmp, []byte(file.Name()))
			if err != nil {
				log.Printf("Error new Node : %v\n", err)
			}
			//Ajout du noeud dans les enfants de topDir
			tmp := make([]*Node, 1)
			tmp[0] = &childDir
			topDir.son = append(topDir.son, tmp...)
			newMerkleTree(&childDir, fileParentPath+"/"+string(topDir.name))
			//ajout du hash de childDir à son père
			addHashToFatherContent(topDir, childDir.checksum)

		} else {
			//On est au niveau d'un fichier
			data := FileParser(fileParentPath + "/" + string(topDir.name) + "/" + file.Name())
			if len(data) > 1 { //Le fichier contient plus d'un chunk
				//New bigfile
				bigFile, err := NewBigFile(&contTmp, topDir, &nodTmp, []byte(file.Name()))
				if err != nil {
					log.Printf("Error new Node : %v\n", err)
				}
				//Ajout dans les enfants de node
				tmp := make([]*Node, 1)
				tmp[0] = &bigFile
				topDir.son = append(topDir.son, tmp...)
				//appel de la fonction qui fera le bigFile
				fillBigFile(&bigFile, &data)
				//Une fois le bigFile rempli, on ajoute son hash au contenu de son père
				addHashToFatherContent(topDir, bigFile.checksum)

			} else { //Le fichier est réduit à un chunk
				//New file
				file, err := NewFile(&data[0], topDir, []byte(file.Name()))
				if err != nil {
					log.Printf("Error new Node : %v\n", err)
				}
				// On met le hash dans le champ checksum
				hash := sha256.Sum256(data[0])
				file.checksum = hash[:]
				//Ajout dans les enfants de node
				tmp := make([]*Node, 1)
				tmp[0] = &file
				topDir.son = append(topDir.son, tmp...)
				//Une fois le file rempli, on ajoute son hash au contenu de son père
				addHashToFatherContent(topDir, file.checksum)
			}
		}
	}
	//On a fini de tout remplir, on peut calculer le hash racine
	hash := sha256.Sum256(topDir.content)
	topDir.checksum = hash[:]
}
