Return-Path: <kasan-dev+bncBCRKFI7J2AJRB44T66GAMGQEXTOPGMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 75E5645B3C4
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 06:13:25 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id i8-20020a056e021d0800b0029e81787af1sf831163ila.20
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 21:13:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637730804; cv=pass;
        d=google.com; s=arc-20160816;
        b=PTBt8DgKrN8wAtci4bn8uns3ZADCmAgh/4BTFeXPinBDU15Nff4x2zJvp0dQdKVk3U
         QtH90W07YIWfPfeZ/j8LlTSYduDapQC3QR0Cwobr52TU0ZSdSwVTtHz4N04QnCFKWESs
         quIp7hcieLbe6HB3wOJDY68UlBchGw5dliORjR9Jk06tVu6J3JE1JQyyKamqGSz61GDk
         vKM9rSAzpUhYTa4csjY6/0XHXz86D0WWU2WzpG+n6tDzoU4XqgCJVGnLKd5l005AXQrc
         f9cRDFeHpSSN90X5Wzfai322S5dazEzXdt33fOG4d2gSGeAGzCarPNrAmRHhTo+VWZ0B
         Q48Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=PWzmoNRIVOtQU88tI9pBzqSJ/mKJjwCw2H5YQq3XSHg=;
        b=mdzE1vfN0B6GBxlP9Av+8bmKrAQGsLCT4dHu9BfQjX76lYZHtKLFEqLNiDJFG68Pab
         nI9bu5hLuIcMrrKendVb+drSJHcajWUmGc+a+4RhMvKfxeL2ytzhyVMCcUHsIPI7FEAX
         MzteLvvot4wyI8BgRDGfaGgcgzNIDvFYL8JYSVbbm899ORzaJRau39AKBKPALIrg4w6U
         skk8VIuoW/cFqL+cspW/BVPdxtFfzgD9THxAG8IQnS3AH0iwddXYQ5k+XmIto++i2emF
         Viq/Ii1Q64ExvgH0OGwaRUxVpdHpOpzpUMfrZ6sEKcT9N+gBgoLMopanBbLVugNI1ueq
         4qyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PWzmoNRIVOtQU88tI9pBzqSJ/mKJjwCw2H5YQq3XSHg=;
        b=PLxTeEJveQeMDYQQY0unlSnvUDmV2305lpNjT8mXVpKKWEQSIz/P2oprHapZ8Tl1AP
         18BTy0GDFnXlohGdk537n4iEU+csIKwzwsy4iN1TFh4FBkuOEfy6NxPdmwEESCj1QAvy
         RKeRe0FRjNX8xQS49+g8JHnpuizNL7g0RsqUctnEXiaFQjYq5WtY/RTYfUyD0JUavuTi
         RvQI1S6huS4LnLxosdpDPZ9sC645CUlv/8vLJyoRpzhyq+qnuQzJQ7vsSnVNrJE+iuW3
         ZfCUEQ+CrqqnB6zHIZXZrhZ1fWLhkT7gFxrEQqHQ2LeWCYO5hKuHOBrsZ4Y+ZuOrYdNy
         9zAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PWzmoNRIVOtQU88tI9pBzqSJ/mKJjwCw2H5YQq3XSHg=;
        b=zTB2doInP2m4brA15SA6f8KufOlIxXm+MRoVtnco+98TzQ9AShdu1s23/nt7fg3H7g
         Xhx5sPr3uWW7T1y0BESyy+l3U6Ra2jsC9AiBLx8E/77mPvwpI7WYwKe4MLEOJcpQjdRq
         KeYKOIYxbMpDpfCFOdcCDkAlo86jbQcreS44TV9ct8WIScykK4ieV8pAlaPQUHNnanGa
         p8M3wQAKq50hhZrJSKeT7oMVY1h4LeJgvEQD5qZbKBHyqM0JSQVMa2l/tUGj83b0HeiR
         N/ZyMtozBh6h4dfC20T33yzVzw24dAvY3rwxOwb5LMdeLRdPXr5tU08Ng8Ivkz3u23rj
         DeaQ==
X-Gm-Message-State: AOAM530uZYDNIJbBAkQG46ZJsAIIxZsMWMPMfNA05O+YepmMQbtYHBZx
	6TIy/rObzxH3TfdB17c71aE=
X-Google-Smtp-Source: ABdhPJxh7l6LcZnocsZk/gQYMJoM+soSMbQLfCOMWhtsaZ8gujRkV8QSOFpb+rqD0hwuOiJsLD5tZg==
X-Received: by 2002:a05:6602:4c:: with SMTP id z12mr11053360ioz.117.1637730803975;
        Tue, 23 Nov 2021 21:13:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:cf13:: with SMTP id o19ls189359ioa.1.gmail; Tue, 23 Nov
 2021 21:13:23 -0800 (PST)
X-Received: by 2002:a5d:994f:: with SMTP id v15mr11654917ios.88.1637730803594;
        Tue, 23 Nov 2021 21:13:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637730803; cv=none;
        d=google.com; s=arc-20160816;
        b=EdezvzKcVrVp4oZVYfjS8AhxbmgWkEh1BU+77cYZGOT87DvN/h0cJZXVCCZ+o9FP9F
         ZFmGPvNY3M4mPSej0lXbamCVtHoRVLfCZ6B0Vj8eNuOvv97Wo0WL49/+VaankaWEV9uK
         caBPrCG5+VYCzLcskvk5di48dUQKPd965SC6dVcg7nmJGTjwRwKhqfKt8hG0n12IMqfJ
         WDLAuSEmZ3OGcTPMyD0XYFMceolYyr4ldnEm9K5GHWWuBAAbxMpyc2ICoqdDawuBESdK
         1agPnj7/9Yyd51kmMZGZ+YsH37sXvODUNGjT2Nwi3Bm8g4U0arBTbxNFf9+Hn9gWMWij
         /Vdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=SoLP5TllbXecThxp4ptc55sJSwJzG25X2hwf/06ifHk=;
        b=kBH2uLJn5KQksXEZYMlC7F5Kie1gxOyc39Aml6UvhCqHy5hZnGLF4gzGPCDO184tn8
         BhOy1meIYSNKBpqNKKUcdldmHSrqcd4h9epGj3wqrOL4Y0yu0vlrVeqZLPbpMp5xlVFx
         MVhC07NT7Wep2N8CjZRBmsPIXzwEzV0LC7HAtpCrstixwfM6H/ggbQp068QaWnkZn7vP
         dkWsjbiaFGkl23FdsuIy2vypRqMwIoQ+mq1uCB4a3Egmx1WlBhGzMpBEppy2lGAIKmZv
         Y6ikieH7X4vbLNaQ0wZ1OsZ+IpM54i/hci1bi4T1SFCCkTlnM6pr/icTVBi5BGYXPqBU
         /SiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id o6si164677ilu.4.2021.11.23.21.13.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Nov 2021 21:13:23 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm500022.china.huawei.com (unknown [172.30.72.54])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4HzTcN0v8kz8vYr;
	Wed, 24 Nov 2021 13:11:00 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500022.china.huawei.com (7.185.36.162) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Wed, 24 Nov 2021 13:12:50 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.20; Wed, 24 Nov 2021 13:12:50 +0800
Message-ID: <9f25b098-0253-4721-3b91-b7d3a79776c6@huawei.com>
Date: Wed, 24 Nov 2021 13:12:49 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH v2] mm: Delay kmemleak object creation of module_alloc()
Content-Language: en-US
To: Catalin Marinas <catalin.marinas@arm.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-s390@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Will Deacon <will@kernel.org>, Heiko Carstens
	<hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, Christian Borntraeger
	<borntraeger@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	Alexander Potapenko <glider@google.com>, Yongqiang Liu
	<liuyongqiang13@huawei.com>
References: <20211123143220.134361-1-wangkefeng.wang@huawei.com>
 <YZ1Eo2m3VKZTfthA@arm.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <YZ1Eo2m3VKZTfthA@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme701-chm.china.huawei.com (10.1.199.97) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>


On 2021/11/24 3:44, Catalin Marinas wrote:
> On Tue, Nov 23, 2021 at 10:32:20PM +0800, Kefeng Wang wrote:
>> Yongqiang reports a kmemleak panic when module insmod/rmmod with KASAN
>> enabled on x86[1].
>>
>> When the module allocates memory, it's kmemleak_object is created succes=
sfully,
>> but the KASAN shadow memory of module allocation is not ready, so when k=
memleak
>> scan the module's pointer, it will panic due to no shadow memory with KA=
SAN.
>>
>> module_alloc
>>    __vmalloc_node_range
>>      kmemleak_vmalloc
>> 				kmemleak_scan
>> 				  update_checksum
>>    kasan_module_alloc
>>      kmemleak_ignore
> Can you share the .config and the stack trace you get on arm64?

My gcc could not support CC_HAS_KASAN_SW_TAGS, so no repoduced on ARM64

>
> I have a suspicion there is no problem if KASAN_VMALLOC is enabled.

Yes,=C2=A0 if KASAN_VMALLOC enabled, the memory of vmalloc shadow has been=
=20
populated in arch's kasan_init(),

there is no issue. but x86/arm64/s390 support dynamic allocation of=20
module area per module load by

kasan_module_alloc(), and this leads the above concurrent issue.

>> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
>> index 4a4929b29a23..2ade2f484562 100644
>> --- a/mm/kasan/shadow.c
>> +++ b/mm/kasan/shadow.c
>> @@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsi=
gned long end,
>>  =20
>>   #else /* CONFIG_KASAN_VMALLOC */
>>  =20
>> -int kasan_module_alloc(void *addr, size_t size)
>> +int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
>>   {
>>   	void *ret;
>>   	size_t scaled_size;
>> @@ -520,9 +520,14 @@ int kasan_module_alloc(void *addr, size_t size)
>>   			__builtin_return_address(0));
>>  =20
>>   	if (ret) {
>> +		struct vm_struct *vm =3D find_vm_area(addr);
>>   		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
>> -		find_vm_area(addr)->flags |=3D VM_KASAN;
>> +		vm->flags |=3D VM_KASAN;
>>   		kmemleak_ignore(ret);
>> +
>> +		if (vm->flags & VM_DELAY_KMEMLEAK)
>> +			kmemleak_vmalloc(vm, size, gfp_mask);
>> +
>>   		return 0;
>>   	}
> This function only exists if CONFIG_KASAN_VMALLOC=3Dn.
yes.
>
>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>> index d2a00ad4e1dd..23c595b15839 100644
>> --- a/mm/vmalloc.c
>> +++ b/mm/vmalloc.c
>> @@ -3074,7 +3074,8 @@ void *__vmalloc_node_range(unsigned long size, uns=
igned long align,
>>   	clear_vm_uninitialized_flag(area);
>>  =20
>>   	size =3D PAGE_ALIGN(size);
>> -	kmemleak_vmalloc(area, size, gfp_mask);
>> +	if (!(vm_flags & VM_DELAY_KMEMLEAK))
>> +		kmemleak_vmalloc(area, size, gfp_mask);
> So with KASAN_VMALLOC enabled, we'll miss the kmemleak allocation.

See the definination, if KASAN_VMALLOC enabled, VM_DELAY_KMEMLEAK=C2=A0 is =
0,=20
so kmemleak allocation

still works.

 =20
+#if defined(CONFIG_KASAN) && (defined(CONFIG_KASAN_GENERIC) || \
+	defined(CONFIG_KASAN_SW_TAGS)) && !defined(CONFIG_KASAN_VMALLOC)
+#define VM_DELAY_KMEMLEAK	0x00000800	/* delay kmemleak object create */
+#else
+#define VM_DELAY_KMEMLEAK	0
+#endif
+

>
> You could add an IS_ENABLED(CONFIG_KASAN_VMALLOC) check but I'm not
> particularly fond of the delay approach (also think DEFER is probably a
> better name).
Will use DEFER instead.
>
> A quick fix would be to make KMEMLEAK depend on !KASAN || KASAN_VMALLOC.
> We'll miss KASAN_SW_TAGS with kmemleak but I think vmalloc support could
> be enabled for this as well.
>
> What does KASAN do with other vmalloc() allocations when !KASAN_VMALLOC?
> Can we not have a similar approach. I don't fully understand why the
> module vmalloc() is a special case.

Only the shadow of module area is dynamic allocation , this exists on=20
ARM64 too.

if no KASAN_VMALLOC, no shadow area for vmalloc,=C2=A0 other vmalloc=20
allocation is

no problem. Correct me if I'm wrong.

Thanks.

>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9f25b098-0253-4721-3b91-b7d3a79776c6%40huawei.com.
