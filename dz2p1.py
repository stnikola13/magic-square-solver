from copy import deepcopy


class Stack:                                                                # Klasa steka realizovana preko liste.
    def __init__(self):
        self.stack = []

    def push(self, node):                                                   # Operacija push podrazumeva da se element
        self.stack.append(node)                                             # doda na kraj liste.

    def pop(self):                                                          # Operacija pop prvo proverava da li je
        if len(self.stack) == 0:                                            # stek prazan, i ukoliko jeste vraca None,
            return None                                                     # a ukoliko nije vraca poslednji element
        else:                                                               # liste.
            node = self.stack.pop()
            return node

    def stack_empty(self):                                                  # Funkcija stack_empty proverava da li je
        if len(self.stack) == 0:                                            # lista koja predstavlja stek prazna i ako
            return True                                                     # jeste vraca True, u suprotnom vraca False.
        else:
            return False


class Queue:                                                                # Klasa reda realizovana preko liste.
    def __init__(self):
        self.queue = []

    def insert(self, node):                                                 # Operacija insert podrazumeva da se element
        self.queue.append(node)                                             # ubacuje na kraj liste.

    def remove(self):                                                       # Operacija remove prvo proverava da li je
        if len(self.queue) == 0:                                            # red prazan, i ako jeste vraca None, a
            return None                                                     # ukoliko nije vraca prvi element liste.
        else:
            node = self.queue.pop(0)
            return node

    def queue_empty(self):                                                  # Operacija queue_empty proverava da li je
        if len(self.queue) == 0:                                            # red prazan, i ukoliko jeste vraca True, a
            return True                                                     # u suprotnom vraca False.
        else:
            return False


class Node:                                                                 # Klasa cvora stabla, sa osobinama state,
    def __init__(self, state, input_values, level=None):                    # koje predstavlja listu listi (matricu)
        self.state = state                                                  # trenutnog stanja cvora; input_values
        self.values = input_values                                          # je lista brojeva koja ce se unositi u
        self.level = level                                                  # u cvor; level je nivo na kom se cvor u
        self.children = []                                                  # u stablu nalazi i children je lista dece.

    def add_child(self, node):                                              # F-ja add_child dodaje prosledjeni cvor
        self.children.append(node)                                          # u listu dece datog cvora.

    def get_state(self):                                                    # F-ja get_state vraca trenutno stanje
        return self.state                                                   # cvora.

    def get_values(self):                                                   # F-ja get_values vraca listu vrednosti
        return self.values                                                  # cvora.

    def get_children(self):                                                 # F-ja get_children vraca listu dece cvora.
        return self.children


class Tree:
    def __init__(self, state):                                              # Klasa korena stabla, sa istim osobinama
        self.state = state                                                  # kao i cvor sem nepostojanja liste values.
        self.level = 0
        self.children = []

    def add_child(self, node):                                              # Funkcije add_child, get_state, i get_
        self.children.append(node)                                          # children rade isto kao kod klase cvora.

    def get_state(self):
        return self.state

    def get_children(self):
        return self.children


def fill_missing_value(matrix, value):
    """ Funkcija fill_missing_value kojoj se prosledjuje matrica i neka vrednost pronalazi
    prvo slobodno mesto (prvu nulu u matrici) i unosi prosledjenu vrednost na to mesto. """

    for i in range(len(matrix)):
        for j in range(len(matrix[i])):                                     # Vrte se dva ciklusa (prvi za vrste)
            if matrix[i][j] == 0:                                           # (drugi za kolone) i unosi se vrednost
                matrix[i][j] = value                                        # na prvu nulu na koju se naidje i vraca
                return matrix                                               # matrica kao povratna vrednosti ili None
    return None                                                             # ukoliko nije bilo slobodnih mesta.


def remove_value(values, i):
    """ Funkcija remove_value kojoj se prosledjuje lista vrednosti i jedna odredjena
    vrednost pravi kopiju prosledjene liste, brise odgovarajuci element iz kopije
    i kao povratnu vrednost vraca kopiranu i izmenjenu listu. """

    new_values = values.copy()
    new_values.remove(i)                                                    # Brise se element sa vrednosti i iz liste.
    return new_values


def is_natural_series(array):
    """ Funkcija is_natural_series proverava da li je prosledjena lista aritmeticki
    niz. Pronalazi razliku i proverava da li je u sortiranoj listi razlika svaka
    dva elementa jednaka toj razlici. """

    if len(array) == 1:
        return True                                                         # Ukoliko je duzina liste 1, svakako je
    else:                                                                   # aritmeticki niz. Ukoliko to nije slucaj,
        diff = array[1] - array[0]                                          # razlika prva dva elementa se uzima kao
        for i in range(len(array) - 1):                                     # konstanta razlika, i u ciklusu se svaka
            if (array[i + 1] - array[i]) != diff:                           # dva susedna elementa proveravaju. Vraca se
                return False                                                # False ukoliko se naidje na par koji se
        return True                                                         # razlikuje, a True ukoliko sve prodje.


def magic_sum_calculator(matrix, values):
    """ Funkcija magic_sum_calculator (koja za argumente prima matricu i listu vrednosti
    koja se unosi u nju) prvo proverava da li elementi u matrici i listi vrednosti jesu
    aritmeticka progresija. A ukoliko nisu prolazi kroz sve vrste, kolone, dijagonale
    kako bi pronasla pun niz preko koga moze da izracuna magicnu sumu. """

    magic_sum = 0
    n = len(matrix)

    # Provera da li ce biti niz 1..n^2
    numbers = []                                                            # Prvo se prolazi kroz celu matricu i svi
    for i in range(len(matrix)):                                            # elementi matrice razliciti od 0 se
        for j in range(len(matrix[i])):                                     # stavljaju u pomonu listu numbers. Nakon
            if matrix[i][j] != 0:                                           # toga se i svi elementi liste values
                numbers.append(matrix[i][j])                                # stavljaju u ovu listu.
    for i in range(len(values)):                                            # Nakon toga se lista sortira i proverava
        numbers.append(values[i])                                           # se da li brojevi cine niz 1..n^2, tako sto
    numbers.sort()                                                          # proverava da li su brojevi aritmeticki niz
    if is_natural_series(numbers) and max(numbers) == n ** 2:               # i da li je maksimalni element n^2, ako su
        magic_sum = int((n * (n ** 2 + 1)) / 2)                             # uslovi ispunjeni, magicnu sumu racuna
        return magic_sum                                                    # pomocu date formule.

    # Prolazak po vrstama
    for i in range(n):                                                      # Ukoliko nije ispunjen prvi blok, prelazi
        temp = 0                                                            # se na obilazak redova. Koristi se pomocna
        for j in range(n):                                                  # prom. temp koja je suma jednog reda. Ako
            if matrix[i][j] == 0:                                           # postoji 0 u redu vrednost temp ce biti 0
                temp = 0                                                    # i izlazi se iz tekuce iteracije.
                break                                                       # Za sumu svakog reda se proverava da li je
            else:                                                           # razlicita od 0, tj. da li su svi elementi
                temp += matrix[i][j]                                        # bili postojeci (bez 0) i ukoliko postoji
        if temp != 0:                                                       # takav red, suma tog reda ce biti magicna
            magic_sum = temp                                                # suma, sto se i vraca kao povratna vrednost
            return magic_sum                                                # funkcije.

    # Prolazak po kolonama
    for j in range(n):                                                      # Ukoliko drugi blok nije ispunjen, prelazi
        temp = 0                                                            # se na obilazak vrsta. Po istom principu
        for i in range(n):                                                  # kao i za obilazak redova, racuna se suma
            if matrix[i][j] == 0:                                           # svake kolone, i ako se naidje na kolonu
                temp = 0                                                    # koja nije imala nule, suma te kolone
                break                                                       # se vraca kao magicna suma.
            else:
                temp += matrix[i][j]
        if temp != 0:
            magic_sum = temp
            return magic_sum

    # Prolazak po glavnoj dijagonali
    temp = 0                                                                # Dalje se prelazi na obilazak glavne
    for i in range(n):                                                      # dijagonale. Opet se proverava da li su
        if matrix[i][i] == 0:                                               # svi elementi na glavnoj dijagonali
            temp = 0                                                        # razliciti od 0, i ukoliko to jeste
            break                                                           # slucaj, kao povratna vrednost funkcije
        else:                                                               # se vraca suma elemenata glavne dijagonale.
            temp += matrix[i][i]
    if temp != 0:
        magic_sum = temp
        return magic_sum

    # Prolazak po sporednoj dijagonali
    temp = 0
    for i in range(n):                                                      # Dalje se prelazi na obilazak sporedne
        if matrix[i][n - i - 1] == 0:                                       # dijagonale. Opet se proverava da li su
            temp = 0                                                        # svi elementi na sporednoj dijagonali
            break                                                           # razliciti od 0, i ukoliko to jeste
        else:                                                               # slucaj, kao povratna vrednost funkcije
            temp += matrix[i][n - i - 1]                                    # se vraca suma elemenata na sporednoj
    if temp != 0:                                                           # dijagonali. Ciklus krece od desne strane
        magic_sum = temp                                                    # matrice i krece se na levo.
        return magic_sum

    # Preostali slucaj
    temp = 0
    values_copy = values.copy()                                             # Ukoliko nista od prethodnih blokova nije
    for j in range(n):                                                      # vratilo magicnu sumu, popunjava se prva
        if matrix[0][j] != 0:                                               # vrsta matrice elementima iz liste values
            temp += matrix[0][j]                                            # tj. njene kopije, i racuna se suma
        else:                                                               # prve vrste i to vraca kao magicna suma.
            temp += values[0]
            values_copy.pop(0)
    magic_sum = temp
    return magic_sum


def check_incomplete_square(matrix, values):
    """ Funkcija check_incomplete_square kojoj se prosledjuje matrica i lista vrednosti
     uzima magicnu sumu od funkcije magic_sum_calculator i proverava da li svaka puna kolona/
     vrsta/dijagonala odgovara magicnoj sumi. Potom se proverava da li neka nepuna kolona/vrsta
     /dijagonala u zbiru elemenata ima veci zbir od magicne sume i vraca True ili False kao povratnu vrednost. """

    n = len(matrix)
    magic_sum = magic_sum_calculator(matrix, values)

    # Prolazak po vrstama
    for i in range(n):                                                      # Prvo se prolazi po vrstama i racuna se
        temp = 0                                                            # suma elemenata u toj vrsti (bice 0 ako
        for j in range(n):                                                  # postoji element koji je 0). Za svaki red
            if matrix[i][j] == 0:                                           # se proverava da li u sumi daje 0 (ako nije
                temp = 0                                                    # bio popunjen) ili magicnu sumu (ako je bio
                break                                                       # pun). Ukoliko je to slucaj nastavlja se
            else:                                                           # dalje, a ako je suma razlicita od 0 i
                temp += matrix[i][j]                                        # magicne sume znaci da taj red nije jednak
        if not (temp == 0 or temp == magic_sum):                            # magicnoj sumi i funkcija odmah vraca
            return False                                                    # vrednost False.

    # Prolazak po kolonama
    for j in range(n):                                                      # Potom se vrsi obilazak svih kolona i
        temp = 0                                                            # sprovodi se isti postupak kao kod
        for i in range(n):                                                  # obilaska vrsta. Ukoliko postoji kolona
            if matrix[i][j] == 0:                                           # koja u sumi daje nesto razlicito od 0
                temp = 0                                                    # ili magicne sume, odmah se vraca vrednost
                break                                                       # False kao povratna vrednost funkcije.
            else:
                temp += matrix[i][j]
        if not (temp == 0 or temp == magic_sum):
            return False

    # Prolazak po glavnoj dijagonali
    temp = 0
    for i in range(n):                                                      # Potom se vrsi obilazak glavne dijagonale i
        if matrix[i][i] == 0:                                               # sprovodi se isti postupak kao kod
            temp = 0                                                        # obilaska vrsta. Ukoliko glavna dijagonala
            break                                                           # u sumi daje nesto razlicito od 0
        else:                                                               # ili magicne sume, odmah se vraca vrednost
            temp += matrix[i][i]                                            # False kao povratna vrednost funkcije.
    if not (temp == 0 or temp == magic_sum):
        return False

    # Prolazak po sporednoj dijagonali
    temp = 0
    for i in range(n):
        if matrix[i][n - i - 1] == 0:                                       # Potom se vrsi obilazak sporedne dijagonale
            temp = 0                                                        # i sprovodi se isti postupak kao kod
            break                                                           # obilaska vrsta. Ukoliko sporedna
        else:                                                               # dijagonala u sumi daje nesto razlicito od
            temp += matrix[i][n - i - 1]                                    # 0 ili magicne sume, vraca se vrednost
    if not (temp == 0 or temp == magic_sum):                                # False kao povratna vrednost funkcije.
        return False

    # Provera stanja - drugi deo (vece od magicne sume)
    for i in range(n):
        temp1 = 0                                                           # Nakon obilaska svih vrsta/kolona/
        temp2 = 0                                                           # dijagonala, vrsi se provera da li neka
        for j in range(n):                                                  # nepopunjena vrsta/kolona/dijagonala u
            temp1 += matrix[i][j]                                           # sumi daje vrednost koja je veca od magicne
            temp2 += matrix[j][i]                                           # sume. Ukoliko je to slucaj, magicni
        if temp1 > magic_sum or temp2 > magic_sum:                          # kvadrat se sigurno ne moze formirati
            return False                                                    # jer sta god da se stavi u preostala mesta
    temp1 = 0                                                               # ta kolona/vrsta/dijagonala u sumi nece
    for i in range(n):                                                      # dati magicnu sumu.
        temp1 += matrix[i][i]
    if temp1 > magic_sum:                                                   # Prvo se vrsi provera za vrste i kolone
        return False                                                        # zajedno, potom za glavnu i za sporednu
    temp1 = 0                                                               # dijagonalu, i ako se naidje na takvu
    for i in range(n):                                                      # kolonu/vrstu/dijagonalu vraca se False.
        temp += matrix[i][n - i - 1]
    if temp1 > magic_sum:
        return False

    # Ukoliko je svaki slucaj prosao                                        # Ukoliko je svaki od prethodnih slucajeva
    return True                                                             # prosao, kvadrat moze da bude magicni.


def check_complete_square(matrix):
    """ Funkcija check_complete_square samo poziva funkciju
    check_incomplete_square, pri cemu za argument prosledjuje praznu
    listu values i na taj nacin proverava da li je pun kvadrat kandidat za magican."""

    return check_incomplete_square(matrix, [])


def is_complete_square(matrix):
    """ Funkcija is_complete_square proverava da li je prosledjena matrica
    u potpunosti popunjena (nema vrednosti 0 u njoj). """

    for i in range(len(matrix)):
        for j in range(len(matrix[i])):                                     # Prolazi se svaki element matrice i ako
            if matrix[i][j] == 0:                                           # se naidje na bilo koji da je jednak nuli
                return False                                                # vraca se vrednost False, a u suprotnom
    return True                                                             # ako nema nula, vraca se True.


def check_perfect_square(matrix):
    """ Funkcija check_perfect_square proverava da li je prosledjena
    matrica savrsen kvadrat. """

    if not (is_complete_square(matrix)):                                    # Funkcija prvo proverava da li je matrica
        return False                                                        # koja je prosledjena popunjena i da li
    if not (check_complete_square(matrix)):                                 # je magicna, ukoliko nije automatski ona ne
        return False                                                        # moze da bude savrsen kvadrat pa se vraca
    magic_sum = magic_sum_calculator(matrix, [])                            # False.

    matrix_len = len(matrix)
    for i in range(matrix_len):                                             # Funkcija ce prvo da u svaku vrstu doda
        for j in range(matrix_len):                                         # te iste elemente [1,2,3] -> [1,2,3,1,2,3].
            matrix[i].append(matrix[i][j])

    diagonals = []                                                          # Funkcija potom od svake dijagonale pravi
    for count in range(matrix_len):                                         # podlistu elemenata koja se stavlja u listu
        diagonal = []                                                       # diagonals. Za glavnu dijagonalu se krece
        for i in range(matrix_len):                                         # od prve kolone, pri cemu za svaku
            diagonal.append(matrix[i][i + count])                           # iteraciju dijagonale (kojih ima n = dim)
        diagonals.append(diagonal)                                          # se kolona pomera u desno u odnosu na vrstu

    for count in range(matrix_len):                                         # za onoliko dijagonala koliko je vec
        diagonal = []                                                       # izbrojano. Isti postupak se vrsi i za
        for i in range(matrix_len):                                         # sporedne dijagonale s tim sto se krece
            diagonal.append(matrix[i][2 * matrix_len - 1 - (i + count)])    # od poslednje kolone matrice.
        diagonals.append(diagonal)

    for diagonal in diagonals:                                              # Potom se za svaku formiranu dijagonalu
        if sum(diagonal) != magic_sum:                                      # proverava da li u sumi daje magicnu sumu
            return False                                                    # i ako postoji neka koja ne daje, vraca se
    return True                                                             # False, a ako sve prodju, vraca se True.


def print_matrix(matrix, level):
    """ Funkcija print_matrix ispisuje prosledjenu matricu formatiranu na standardnom
     izlazu. Kao argument f-je se takodje i prosledjuje i nivo na kome se data matrica nalazi. """
    new_matrix = deepcopy(matrix)
    for row in new_matrix:
        for i in range(len(row)):                                           # Pravi se kopija matrice koja je argument
            if row[i] <= 9:                                                 # i obezbedjuje se dva mesta za svaki elem.
                row[i] = " " + str(row[i])                                  # za jednocif. (0 + razmak), za dvocifrene
            else:                                                           # dva mesta. Svaki red se ispisuje tako da
                row[i] = str(row[i])                                        # kompletna matrica bude uvucena za nivo *
            if row[i] == " 0":                                              # dimenzija matrice tabova, kako bi se
                row[i] = " _"                                               # obezbedilo ugnezdavanje i da se matrice
        print(level * n * "\t","|"," ".join(row),"|")                       # ne preklapaju.


# Glavni program

matrix = []                                                                 # Inicijalizuju se lista matrice i vrednosti
values = []                                                                 # tako da budu prazne na pocetku.

# Meni
''' Ispisuje se meni samo jednom na pocetku programa, i unosom odgovarajuceg rednog broja zeljene opcije
    se izvrava jedan od delova glavnog programa.'''

print("\n------------- Magicni kvadrati - stablo odlucivanja -------------\n")
print("1. Formiranje stabla")
print("2. Ispis strukture stabla")
print("3. Ispis magicnih kvadrata")
print("4. Izlazak iz programa")

while True:
    unos = input("\nUnesite broj zeljene opcije: ")                         # Ulazi se u beskonacnu petlju menija
    try:                                                                    # dokle god se ne izabere opcija za
        unos = int(unos)                                                    # izlazak iz programa.
    except Exception:
        print("Unesite ceo prirodan broj.")                                 # Proverava se korektnost unetog rednog
        continue                                                            # broja i ukoliko nije korektno unet,
    if not 1 <= unos <= 4:                                                  # ponavlja se unos prelaskom u sledecu
        print("Neispravno unet redni broj.")                                # iteraciju ciklusa.
        continue

    # Opcija 1 - Unos dimenzija i pocetnog stanja kvadrata

    if unos == 1:

        matrix = []                                                         # Prilikom svake nove inicijalizacije stabla
        values = []                                                         # se matrica i vrednost reinicijalizuju.
        n = input("Unesite dimenzije magicnog kvadrata: ")
        try:                                                                # Unos i provera korektnosti dimenzija
            n = int(n)                                                      # kvadrata koji se unosi.
        except Exception:
            print("Unesite ceo prirodan broj.")

        if n < 1:
            print("Neispravno unete dimenzije.")

        print("\n--------------------- Unos pocetnog stanja ---------------------\n!!"
              " Za elemente koje ne zelite da unesete, unesite vrednost 0. !!\n")

        i = 0
        while i < n:
            row = input("Unesite elemente {}. vrste: ".format(i + 1)).split()           # Unos i provera korektnosi
            if len(row) != n:                                                           # elemenata matrice.
                print("Nije unet tacan broj elemenata. Pokusajte ponovo.")
                continue
            try:
                row = [int(j) for j in row]
            except Exception:
                print("Unesite pozitivne brojeve kao clanove kvadrata. Pokusajte ponovo.")
                continue
            t = True
            for j in range(n):
                if row[j] < 0:
                    t = False
            if not t:
                print("Unesite pozitivne brojeve kao clanove kvadrata. Pokusajte ponovo.")
                continue
            i += 1
            matrix.append(row)

        # Prebrojavanje nedefinisanih vrednosti

        undef_values = 0                                                        # Prebrojava se broj nula u matrici,
        for i in range(n):                                                      # kako bi se obezbedio poznat broj
            for j in range(n):                                                  # elemenata koji treba da se nalazi
                if matrix[i][j] == 0:                                           # u listi vrednosti values.
                    undef_values += 1

        # Unos vrednosti i provera njihove korektnosti

        while True:
            values = input("Unesite skup vrednosti od kojih ce se formirati kvadrat: ").split()
            if len(values) != undef_values:
                print("Nije unet tacan broj elemenata. Pokusajte ponovo.")
                continue
            try:
                values = [int(i) for i in values]
            except Exception:
                print("Unesite pozitivne brojeve kao clanove kvadrata. Pokusajte ponovo.")
                continue
            t = True
            if not (len(values)):
                t = True
                break
            else:
                for i in range(len(values)):
                    if values[i] <= 0:
                        t = False
                if not t:
                    print("Unesite pozitivne brojeve kao clanove kvadrata. Pokusajte ponovo.")
                    continue
                break

        print("Stablo uspesno formirano!")

        # Formiranje stabla

        queue = Queue()                                                             # Incijalizuje se red.

        root = Tree(matrix)                                                         # Kao koren stabla se stavlja samo
        for value in values:                                                        # pocetno stanje kvadrata. Za svaku
            new_state = fill_missing_value(deepcopy(matrix), value)                 # vrednost iz liste vrednosti se
            new_values = remove_value(values, value)                                # popunjava prvo slobodno mesto tom
            node = Node(new_state, new_values)                                      # vrednoscu i pravi novi cvor. Ako
            if check_incomplete_square(node.state, node.values):                    # je novi cvor potencijalan magican
                root.add_child(node)                                                # kvadrat, postavlja se kao sin
                queue.insert(node)                                                  # korena i dodaje se u red.

        while not queue.queue_empty():                                              # Vrsi se ciklus dohvatanja elem. iz
            current_node = queue.remove()                                           # reda i obavljanje njihove obrade.
            state = current_node.state                                              # Dohvata se element i cita se
            values = current_node.values                                            # njegovo stanje i skup vrednosti.

            for value in values:                                                    # Potom za svaku vrednost iz njegove
                new_state = fill_missing_value(deepcopy(state), value)              # liste vrednosti se formira novi
                new_values = remove_value(values, value)                            # novi cvor. Ukoliko je novi cvor
                node = Node(new_state, new_values)                                  # kandidat za magican kvadrat, on
                if check_incomplete_square(node.state, node.values):                # postaje sin tekuceg cvora i
                    current_node.add_child(node)                                    # stavlja se u red. Ciklus se
                    queue.insert(node)                                              # ponavlja dok se red ne isprazni.

    # Opcija 2 - Ispis strukture stabla

    elif unos == 2:
        if len(matrix) == 0:                                                        # Prvo se proverava da li je stablo
            print("Prvo je potrebno formirati stablo!")                             # inicijalizovano, i ako nije
            continue                                                                # prelazi se u sledecu iteraciju.
        else:

            # Popunjavanje informacije u nivou

            curr_node = root                                                        # Popunjava se info u nivou za
            queue = Queue()                                                         # svaki cvor tako sto koren ima nivo
            queue.insert(curr_node)                                                 # 0, njegova deca 1, i tako svaki
            while not queue.queue_empty():                                          # cvor ima nivo za jedan veci od
                curr_node = queue.remove()                                          # svog oca. Obilazak se vrsi pomocu
                children = curr_node.get_children()                                 # strukture reda, dok se red ne
                for child in children:                                              # isprazni i nivoi svih cvorova ne
                    child.level = curr_node.level + 1                               # budu zabelezeni.
                    queue.insert(child)

            # Printovanje stabla preko preorder obilaska

            print("\n----------------------- Struktura stabla -----------------------")
            stack = Stack()
            print(" Nivo {}".format(root.level))                                    # Pomocu preordera se vrsi obilazak
            print_matrix(root.state, root.level)                                    # i ispis svake matrice. Prvo se to
            curr_node = root                                                        # vrsi za koren. Nakon ispisa korena
            while not (len(curr_node.get_children()) == 0):                         # dokle god ne dodjemo do najlevljeg
                children = curr_node.get_children()                                 # lista, se dohvataju deca, ispisuje
                print(children[0].level * n * "\t", "Nivo {}".format(children[0].level))    # prvo dete (najlevlje) i
                print_matrix(children[0].state, children[0].level)                  # prelazi se na njegovu decu, ako
                if len(children) == 1:                                              # ima samo jedno dete, prelazi se
                    curr_node = children[0]                                         # na njega, a ako ih ima vise
                else:                                                               # svi desni sinovi se stavljaju na
                    for child in range(len(children) - 1, 0, -1):                   # stek. Ciklus se ponavlja dok ne
                        stack.push(children[child])                                 # naidjemo na poslenji (najlevlji)
                    curr_node = children[0]                                         # list.

            while not stack.stack_empty():                                          # Kada dodjemo do najlevljeg lista
                curr_node = stack.pop()                                             # jedan po jedan element skidamo sa
                print(curr_node.level * n * "\t", "Nivo {}".format(curr_node.level))  # sa steka i ispisujemo ga.
                print_matrix(curr_node.state, curr_node.level)                      # Dohvataju se njegova deca i
                children = curr_node.get_children()                                 # ukoliko ima decu njegova deca se
                if len(children) == 1:                                              # stavljaju na stek u poretku od
                    stack.push(children[0])                                         # najdesnjeg do najlevljeg sina
                elif len(children) > 1:                                             # kako bi se obezbedilo da se pri
                    for child in range(len(children) - 1, 0, -1):                   # skidanju sa steka prvo skine
                        stack.push(children[child])                                 # najlevlji sin. Ciklus se ponavlja
                    stack.push(children[0])                                         # dok se stek ne isprazni.

    # Opcija 3 - Ispis resenja i provera savrsenih kvadrata

    elif unos == 3:
        if len(matrix) == 0:
            print("Prvo je potrebno formirati stablo!")
            continue
        else:

            # Kolekcija rezultata po postorderu

            stack1 = Stack()                                                        # Obilazak se vrsi po postorderu
            stack2 = Stack()                                                        # pomocu dva steka. Koristi se
            magic_squares = []                                                      # pomocna lista u koju ce da se
            curr_node = root                                                        # skupljaju svi savrseni kvadati
            stack1.push(root)                                                       # prilikom obilaska.
            while not stack1.stack_empty():                                         # Koren se stavlja na stek1, i ulazi
                curr_node = stack1.pop()                                            # se u ciklus dok se stek1 ne
                stack2.push(curr_node)                                              # isprazni - dohvata se element sa
                children = curr_node.get_children()                                 # steka1, njegova deca se stavljaju
                for child in children:                                              # na stek 1, a on se stavlja na stek
                    stack1.push(child)                                              # 2. Ovim se obezbedjuje da se svaki
            while not stack2.stack_empty():                                         # element dva puta obidje pre ispisa
                curr_node = stack2.pop()                                            # i potom kada se isprazni stek1, se
                if curr_node.level == 0 and is_complete_square(curr_node.state):    # skidaju jedan po jedan element
                    if check_complete_square(curr_node.state):                      # sa steka2 (koji su rasporedjeni po
                        magic_squares.append(curr_node.state)                       # postorderu) i za svaku matricu
                elif is_complete_square(curr_node.state):                           # koja jeste magicni kvadrat se
                    if check_complete_square(curr_node.state):                      # dodaje u listu magicnih kvadrata.
                        magic_squares.append(curr_node.state)

            # Ispis resenja i provera savrsenih kvadrata

            print("\n----------- Magicni kvadrati -----------\n")                       # Ukoliko je lista magicnih
            if len(magic_squares) == 0:                                                 # kvadrata prazna, ispisuje se
                print("Nije pronadjen nijedan magican kvadrat!")                        # poruka da nema magicnih
            else:                                                                       # kvadrata. U suprotnom se
                print("Broj magicnih kvadrata je {}.\n".format(len(magic_squares)))     # ispisuje broj magicnih kvadr.
                for i in range(len(magic_squares)):                                     # Potom se u ciklusu prolazi
                    if check_perfect_square(deepcopy(magic_squares[i])):                # kroz svaki kvadrat i pomocu
                        print("Magicni kvadrat {} je savrseni kvadrat:".format(i + 1))  # funkcije za ispis se ona
                    else:                                                               # ispisuje. Usput se proverava
                        print("Magicni kvadrat {} nije savrseni kvadrat:".format(i + 1))  # da li je i savrseni kvadrat
                    print_matrix(magic_squares[i], 0)                                   # i ta info. se takodje pise.

    # Opcija 4 - Izlazak iz programa

    elif unos == 4:
        print("Zdravo!")                                                            # Ispisuje se poruka i napusta se
        break                                                                       # beskonacna petlja.
