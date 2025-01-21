package poseidon

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/v2/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPoseidonHash(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)
	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	b5 := big.NewInt(5)
	b6 := big.NewInt(6)
	b7 := big.NewInt(7)
	b8 := big.NewInt(8)
	b9 := big.NewInt(9)
	b10 := big.NewInt(10)
	b11 := big.NewInt(11)
	b12 := big.NewInt(12)
	b13 := big.NewInt(13)
	b14 := big.NewInt(14)
	b15 := big.NewInt(15)
	b16 := big.NewInt(16)

	h, err := Hash([]*big.Int{b1})
	assert.Nil(t, err)
	assert.Equal(t,
		"18586133768512220936620570745912940619677854269274689475585506675881198879027",
		h.String())

	h, err = Hash([]*big.Int{b1, b2})
	assert.Nil(t, err)
	assert.Equal(t,
		"7853200120776062878684798364095072458815029376092732009249414926327459813530",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"1018317224307729531995786483840663576608797660851238720571059489595066344487",
		h.String())
	h, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"15336558801450556532856248569924170992202208561737609669134139141992924267169",
		h.String())

	h, err = Hash([]*big.Int{b3, b4, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"5811595552068139067952687508729883632420015185677766880877743348592482390548",
		h.String())
	h, err = Hash([]*big.Int{b3, b4, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"12263118664590987767234828103155242843640892839966517009184493198782366909018",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b3, b4, b5, b6})
	assert.Nil(t, err)
	assert.Equal(t,
		"20400040500897583745843009878988256314335038853985262692600694741116813247201",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14})
	assert.Nil(t, err)
	assert.Equal(t,
		"8354478399926161176778659061636406690034081872658507739535256090879947077494",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"5540388656744764564518487011617040650780060800286365721923524861648744699539",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"11882816200654282475720830292386643970958445617880627439994635298904836126497",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16})
	assert.Nil(t, err)
	assert.Equal(t,
		"9989051620750914585850546081941653841776809718687451684622678807385399211877",
		h.String())
}

func TestPoseidonHashEx(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)
	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	b5 := big.NewInt(5)
	b6 := big.NewInt(6)
	b7 := big.NewInt(7)
	b8 := big.NewInt(8)
	b9 := big.NewInt(9)
	b10 := big.NewInt(10)
	b11 := big.NewInt(11)
	b12 := big.NewInt(12)
	b13 := big.NewInt(13)
	b14 := big.NewInt(14)
	b15 := big.NewInt(15)
	b16 := big.NewInt(16)

	h, err := HashEx([]*big.Int{b1}, 1)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(h))
	assert.Equal(t,
		"18586133768512220936620570745912940619677854269274689475585506675881198879027",
		h[0].String())

	h, err = HashEx([]*big.Int{b1, b2}, 2)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(h))
	assert.Equal(t,
		"7853200120776062878684798364095072458815029376092732009249414926327459813530",
		h[0].String())
	assert.Equal(t,
		"7142104613055408817911962100316808866448378443474503659992478482890339429929",
		h[1].String())

	h, err = HashEx([]*big.Int{b1, b2, b0, b0, b0}, 3)
	assert.Nil(t, err)
	assert.Equal(t,
		"1018317224307729531995786483840663576608797660851238720571059489595066344487",
		h[0].String())
	assert.Equal(t, 3, len(h))

	h, err = HashEx([]*big.Int{b1, b2, b0, b0, b0, b0}, 4)
	assert.Nil(t, err)
	assert.Equal(t,
		"15336558801450556532856248569924170992202208561737609669134139141992924267169",
		h[0].String())
	assert.Equal(t, 4, len(h))

	h, err = HashEx([]*big.Int{b3, b4, b0, b0, b0}, 5)
	assert.Nil(t, err)
	assert.Equal(t,
		"5811595552068139067952687508729883632420015185677766880877743348592482390548",
		h[0].String())
	assert.Equal(t, 5, len(h))

	h, err = HashEx([]*big.Int{b3, b4, b0, b0, b0, b0}, 6)
	assert.Nil(t, err)
	assert.Equal(t,
		"12263118664590987767234828103155242843640892839966517009184493198782366909018",
		h[0].String())
	assert.Equal(t, 6, len(h))

	h, err = HashEx([]*big.Int{b1, b2, b3, b4, b5, b6}, 7)
	assert.Nil(t, err)
	assert.Equal(t,
		"20400040500897583745843009878988256314335038853985262692600694741116813247201",
		h[0].String())
	assert.Equal(t, 7, len(h))

	h, err = HashEx([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14}, 8)
	assert.Nil(t, err)
	assert.Equal(t,
		"8354478399926161176778659061636406690034081872658507739535256090879947077494",
		h[0].String())
	assert.Equal(t, 8, len(h))

	h, err = HashEx([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0}, 9)
	assert.Nil(t, err)
	assert.Equal(t,
		"5540388656744764564518487011617040650780060800286365721923524861648744699539",
		h[0].String())
	assert.Equal(t, 9, len(h))

	h, err = HashEx([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b0, b0, b0, b0, b0, b0, b0}, 10)
	assert.Nil(t, err)
	assert.Equal(t,
		"11882816200654282475720830292386643970958445617880627439994635298904836126497",
		h[0].String())
	assert.Equal(t, 10, len(h))

	h, err = HashEx([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16}, 11)
	assert.Nil(t, err)
	assert.Equal(t, 11, len(h))
	assert.Equal(t,
		"9989051620750914585850546081941653841776809718687451684622678807385399211877",
		h[0].String())
	assert.Equal(t,
		"8319791455060392555425392842391403897548969645190976863995973180967774875286",
		h[1].String())
	assert.Equal(t,
		"21636406227810893698117978732800647815305553312233448361627674958309476058692",
		h[2].String())
	assert.Equal(t,
		"5858261170370825589990804751061473291946977191299454947182890419569833191564",
		h[3].String())
	assert.Equal(t,
		"9379453522659079974536893534601645512603628658741037060370899250203068088821",
		h[4].String())
	assert.Equal(t,
		"473570682425071423656832074606161521036781375454126861176650950315985887926",
		h[5].String())
	assert.Equal(t,
		"6579803930273263668667567320853266118141819373699554146671374489258288008348",
		h[6].String())
	assert.Equal(t,
		"19782381913414087710766737863494215505205430771941455097533197858199467016164",
		h[7].String())
	assert.Equal(t,
		"16057750626779488870446366989248320873718232843994532204040561017822304578116",
		h[8].String())
	assert.Equal(t,
		"18984357576272539606133217260692170661113104846539835604742079547853774113837",
		h[9].String())
	assert.Equal(t,
		"6999414602732066348339779277600222355871064730107676749892229157577448591106",
		h[10].String())
}

func TestErrorInputs(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)

	var err error

	_, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0})
	require.Nil(t, err)

	_, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0})
	require.NotNil(t, err)
	assert.Equal(t, "invalid inputs length 17, max 16", err.Error())

	_, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0})
	require.NotNil(t, err)
	assert.Equal(t, "invalid inputs length 18, max 16", err.Error())

	_, err = HashEx([]*big.Int{b1, b2}, 0)
	assert.EqualError(t, err, "invalid nOuts 0, min 1, max 3")

	_, err = HashEx([]*big.Int{b1, b2}, 4)
	assert.EqualError(t, err, "invalid nOuts 4, min 1, max 3")
}

func TestInputsNotInField(t *testing.T) {
	var err error

	// Very big number, should just return error and not go into endless loop
	b1, _ := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061999999999999999999999999999999999999999999999999999999999")
	_, err = Hash([]*big.Int{b1})
	require.Error(t, err, "inputs values not inside Finite Field")

	// Finite Field const Q, should return error
	b2, _ := utils.NewIntFromString("21888242871839275222246405745257275088548364400416034343698204186575808495617")
	_, err = Hash([]*big.Int{b2})
	require.Error(t, err, "inputs values not inside Finite Field")
}

func TestHashWithState(t *testing.T) {
	initState0 := big.NewInt(0)
	initState1 := big.NewInt(7)

	b1 := big.NewInt(1)
	b2 := big.NewInt(2)
	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	b5 := big.NewInt(5)
	b6 := big.NewInt(6)
	b7 := big.NewInt(7)
	b8 := big.NewInt(8)
	b9 := big.NewInt(9)
	b10 := big.NewInt(10)
	b11 := big.NewInt(11)
	b12 := big.NewInt(12)
	b13 := big.NewInt(13)
	b14 := big.NewInt(14)
	b15 := big.NewInt(15)
	b16 := big.NewInt(16)
	b17 := big.NewInt(17)

	h, err := HashWithState([]*big.Int{b1, b2, b3, b4, b5, b6}, initState0)
	assert.Nil(t, err)
	assert.Equal(t,
		"20400040500897583745843009878988256314335038853985262692600694741116813247201",
		h.String())

	h, err = HashWithState([]*big.Int{b1, b2, b3, b4}, initState1)
	assert.Nil(t, err)
	assert.Equal(t,
		"1569211601569591254857354699102545060324851338714426496554851741114291465006",
		h.String())

	h, err = HashWithState([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16}, b17)
	assert.Nil(t, err)
	assert.Equal(t,
		"7865037705064445207187340054656830232157001572238023180016026650118519857086",
		h.String())
}

func TestHashWithStateEx(t *testing.T) {
	initState0 := big.NewInt(0)
	initState1 := big.NewInt(7)

	b1 := big.NewInt(1)
	b2 := big.NewInt(2)
	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	b5 := big.NewInt(5)
	b6 := big.NewInt(6)
	b7 := big.NewInt(7)
	b8 := big.NewInt(8)
	b9 := big.NewInt(9)
	b10 := big.NewInt(10)
	b11 := big.NewInt(11)
	b12 := big.NewInt(12)
	b13 := big.NewInt(13)
	b14 := big.NewInt(14)
	b15 := big.NewInt(15)
	b16 := big.NewInt(16)
	b17 := big.NewInt(17)

	h, err := HashWithStateEx([]*big.Int{b1, b2, b3, b4, b5, b6}, initState0, 6)
	assert.Nil(t, err)
	assert.Equal(t, 6, len(h))
	assert.Equal(t,
		"20400040500897583745843009878988256314335038853985262692600694741116813247201",
		h[0].String())

	h, err = HashWithStateEx([]*big.Int{b1, b2, b3, b4}, initState1, 4)
	assert.Nil(t, err)
	assert.Equal(t, 4, len(h))
	assert.Equal(t,
		"1569211601569591254857354699102545060324851338714426496554851741114291465006",
		h[0].String())

	h, err = HashWithStateEx([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16}, b17, 16)
	assert.Nil(t, err)
	assert.Equal(t, 16, len(h))
	assert.Equal(t,
		"7865037705064445207187340054656830232157001572238023180016026650118519857086",
		h[0].String())
	assert.Equal(t,
		"9292383997006336854008325030029058442489692927472584277596649832441082093099",
		h[1].String())
	assert.Equal(t,
		"21700625464938935909463291795162623951575229166945244593449711331894544619498",
		h[2].String())
	assert.Equal(t,
		"1749964961100464837642084889776091157070407086051097880220367435814831060919",
		h[3].String())
	assert.Equal(t,
		"14926884742736943105557530036865339747160219875259470496706517357951967126770",
		h[4].String())
	assert.Equal(t,
		"2039691552066237153485547245250552033884196017621501609319319339955236135906",
		h[5].String())
	assert.Equal(t,
		"15632370980418377873678240526508190824831030254352022226082241110936555130543",
		h[6].String())
	assert.Equal(t,
		"12415717486933552680955550946925876656737401305417786097937904386023163034597",
		h[7].String())
	assert.Equal(t,
		"19518791782429957526810500613963817986723905805167983704284231822835104039583",
		h[8].String())
	assert.Equal(t,
		"3946357499058599914103088366834769377007694643795968939540941315474973940815",
		h[9].String())
	assert.Equal(t,
		"5618081863604788554613937982328324792980580854673130938690864738082655170455",
		h[10].String())
	assert.Equal(t,
		"9119013501536010391475078939286676645280972023937320238963975266387024327421",
		h[11].String())
	assert.Equal(t,
		"8377736769906336164136520530350338558030826788688113957410934156526990238336",
		h[12].String())
	assert.Equal(t,
		"15295058061474937220002017533551270394267030149562824985607747654793981405060",
		h[13].String())
	assert.Equal(t,
		"3767094797637425204201844274463024412131937665868967358407323347727519975724",
		h[14].String())
	assert.Equal(t,
		"11046361685833871233801453306150294246339755171874771935347992312124050338976",
		h[15].String())
}

func TestInitStateNotInField(t *testing.T) {
	var err error

	b0 := big.NewInt(0)
	b1 := big.NewInt(1)

	// Very big number, should just return error and not go into endless loop
	initState, err := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061999999999999999999999999999999999999999999999999999999999")
	require.NoError(t, err)
	_, err = HashWithState([]*big.Int{b0, b1}, initState)
	require.Error(t, err, "initState values not inside Finite Field")

	// Finite Field const Q, should return error
	initState, err = utils.NewIntFromString("21888242871839275222246405745257275088548364400416034343698204186575808495617")
	require.NoError(t, err)
	_, err = HashWithState([]*big.Int{b0, b1}, initState)
	require.Error(t, err, "initState values not inside Finite Field")
}

func BenchmarkPoseidonHash6Inputs(b *testing.B) {
	b0 := big.NewInt(0)
	b1, _ := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061")
	b2, _ := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061")

	bigArray6 := []*big.Int{b1, b2, b0, b0, b0, b0}

	for i := 0; i < b.N; i++ {
		_, _ = Hash(bigArray6)
	}
}

func BenchmarkPoseidonHash8Inputs(b *testing.B) {
	bigArray8 := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
		big.NewInt(6),
		big.NewInt(7),
		big.NewInt(8),
	}

	for i := 0; i < b.N; i++ {
		_, _ = Hash(bigArray8)
	}
}
func BenchmarkPoseidonHash12Inputs(b *testing.B) {
	bigArray12 := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
		big.NewInt(6),
		big.NewInt(7),
		big.NewInt(8),
		big.NewInt(9),
		big.NewInt(10),
		big.NewInt(11),
		big.NewInt(12),
	}

	for i := 0; i < b.N; i++ {
		_, _ = Hash(bigArray12)
	}
}

func BenchmarkPoseidonHash16Inputs(b *testing.B) {
	bigArray16 := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
		big.NewInt(6),
		big.NewInt(7),
		big.NewInt(8),
		big.NewInt(9),
		big.NewInt(10),
		big.NewInt(11),
		big.NewInt(12),
		big.NewInt(13),
		big.NewInt(14),
		big.NewInt(15),
		big.NewInt(16),
	}

	for i := 0; i < b.N; i++ {
		_, _ = Hash(bigArray16)
	}
}
