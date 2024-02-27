NAME=`basename "$(pwd)"`
if [[ -z $1 ]]
then
    CNAME=$NAME
else
    CNAME=$1
fi
touch "$NAME.py"
echo "# Name: $NAME.py" > "$NAME.py"
echo "" >> "$NAME.py"
echo "from pwn import *" >> "$NAME.py"
echo "" >> "$NAME.py"
echo "def slog(name,addr): success(f'{name}: {hex(addr)}')" >> "$NAME.py"
echo "" >> "$NAME.py"
echo "HOST = 'host3.dreamhack.games'" >> "$NAME.py"
echo "PORT = 0" >> "$NAME.py"
echo "" >> "$NAME.py"
echo "p = remote(HOST,PORT)" >> "$NAME.py"
echo "" >> "$NAME.py"
echo "#ifndef __Custom_Functions_For_Convenience_" >> "$NAME.py"
echo "#define __Custom_Functions_For_Convenience_" >> "$NAME.py"
echo "#endif /* __Custom_Functions_For_Convenience_ */" >> "$NAME.py"
echo "" >> "$NAME.py"
echo "#ifndef __Custom_Global_Variables_For_Convenience_" >> "$NAME.py"
echo "#define __Custom_Global_Variables_For_Convenience_" >> "$NAME.py"
echo "dummy = b'A'" >> "$NAME.py"
echo "#endif /* __Custom_Global_Variables_For_Convenience_ */" >> "$NAME.py"

touch "$NAME.md"
echo '```c' > "$NAME.md"
cat "$CNAME.c" >> "$NAME.md"
echo '```' >> "$NAME.md"
echo "" >> "$NAME.md"
echo '```bash' >> "$NAME.md"
echo "\$ checksec ./$CNAME" >> "$NAME.md"
`checksec "./$CNAME"`
echo '```' >> "$NAME.md"
echo "" >> "$NAME.md"
echo "# 코드 분석" >> "$NAME.md"
echo "" >> "$NAME.md"
echo "# 공격" >> "$NAME.md"