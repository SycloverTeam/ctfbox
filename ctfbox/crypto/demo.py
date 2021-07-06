import myrandom
myrandom.android_random(1) #必须指定种子
myrandom.windows_srand(1) #必须指定种子
myrandom.linux_srand(1) #必须指定种子
for i in range(50):
    print(myrandom.android_nextInt()) #生成随机数
    print(myrandom.android_nextInt_bound(10)) #生成[0,10)随机数
    print(myrandom.windows_rand())
    print(myrandom.linux_rand())
