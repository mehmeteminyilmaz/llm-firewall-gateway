from typing import Dict


class StreamUnmasker:
    """
    Akış (SSE) sırasında yer tutucuları ([TC_KIMLIK_1] vb.) canlı olarak gerçek veriyle değiştirir.

    LLM bir yer tutucuyu parçalara bölerek gönderebilir ("[TC_KI" + "MLIK_1]").
    Bu nedenle '[' ile başlayıp henüz ']' ile kapanmamış kuyruk, en fazla
    MAX_PLACEHOLDER_LEN karaktere kadar tamponda tutulur; yer tutucu tamamlanınca
    çözülür, yer tutucu olmadığı anlaşılırsa olduğu gibi serbest bırakılır.

    Not: Geri yazılan orijinal değerler tekrar taranmaz (içlerinde '[' olsa bile güvenli).
    """

    MAX_PLACEHOLDER_LEN = 48

    def __init__(self, mapping: Dict[str, str]):
        self._mapping = mapping
        self._buf = ""

    def feed(self, chunk: str) -> str:
        """Yeni parçayı ekler ve istemciye güvenle gönderilebilecek metni döner."""
        self._buf += chunk
        return self._drain(final=False)

    def flush(self) -> str:
        """Akış bittiğinde tamponda kalan her şeyi serbest bırakır."""
        return self._drain(final=True)

    def _drain(self, final: bool) -> str:
        out = []
        buf = self._buf
        pos = 0
        while True:
            i = buf.find("[", pos)
            if i == -1:
                out.append(buf[pos:])
                pos = len(buf)
                break

            out.append(buf[pos:i])
            j = buf.find("]", i + 1)

            if j == -1:
                tail = buf[i:]
                if not final and len(tail) <= self.MAX_PLACEHOLDER_LEN:
                    pos = i  # yer tutucunun devamı bekleniyor: tamponda tut
                    break
                out.append("[")
                pos = i + 1
                continue

            candidate = buf[i:j + 1]
            if candidate in self._mapping:
                out.append(self._mapping[candidate])
                pos = j + 1
            else:
                out.append("[")
                pos = i + 1

        self._buf = buf[pos:]
        return "".join(out)

