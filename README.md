# cmd2shellcode

> 用于将cmd命令转化为shellcode形式运行，可结合shellcode加载方式用于杀软规避。

例子：正常添加用户和cmd2shellcode添加用户和CS添加用户。

都是被拦截，但是正常添加用户和CS执行命令添加用户的父进程都是cmd.exe（即使CS是通过反射性dll加载），而cmd2shellcode可无cmd执行命令，"即使没有cmd.exe"，所以父进程无cmd.exe

* 正常添加用户
![image](https://user-images.githubusercontent.com/42691451/117047166-23817480-ad44-11eb-9173-03d82e0d624d.png)

* cmd2shellcode添加用户
![image](https://user-images.githubusercontent.com/42691451/117047309-4ca20500-ad44-11eb-8ac6-c768ed7891d7.png)

* CS添加用户
![image](https://user-images.githubusercontent.com/42691451/117047620-ad314200-ad44-11eb-8aaf-d71307973e33.png)
