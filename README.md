### 32位进程函数监控
  
#### 开发环境：
Win10  VisualStudio 2019  多字节集编码  x86
#### 介绍：
选择进程后，隐藏模块注入DLL，控制端利用命名管道与注入的DLL进行通信，使用IAT HOOK监控导入表中存在的API的调用情况。对于导入表中不存在的函数，可以手动输入函数地址进行Inline HOOK，实现自定义监控。还可以对被注入进程中的函数进行远程调用。

#### 演示：

##### 隐藏模块注入：
![进程监控-注入成功](https://i.loli.net/2021/05/12/wZWh3Uzv8ASrKfC.png)
##### IAT HOOK实现监控：
![进程监控-IAT HOOK实现监控](https://i.loli.net/2021/05/12/mobCtQJjdOZSuFH.png)
##### Inline HOOK实现自定义监控：
![进程监控-Inline HOOK实现自定义监控](https://i.loli.net/2021/05/12/bFvoxDAXRUeHyg9.png)
##### 远程调用：
![进程监控-远程调用](https://i.loli.net/2021/05/12/jrepETW3qzK4Mn7.png)
