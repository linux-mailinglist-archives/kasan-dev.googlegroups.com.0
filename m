Return-Path: <kasan-dev+bncBCRKFI7J2AJRB75RXCGQMGQEHY6WCNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A3F8F4697F4
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 15:06:56 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id h10-20020a056e021b8a00b002a3f246adeasf4629191ili.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 06:06:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638799615; cv=pass;
        d=google.com; s=arc-20160816;
        b=iFfZz/BAJVwraSkECi3eHtYpEvcA4HvhpQ5JsMLVWg1ARjaaDawoXKd3MLvqAtcsju
         2AtiWDoMqffaZBxq53ax1dZDPHtSwEu8wkeaMldWg1pg4ME/C0dBUslrjeTYTpcntgub
         dovYNiNGDcq174Eyi8TFoeoh1etSESUNLbL2Hmjol1D2C2OWTo+EuNxBnO3cs3lHumlu
         zCvlsa6/dPJqUbkR37jH9xqgMhZEXaXlGcsn+dnKtufJBMaVbs0iWLkg3J0h51RxA1jG
         YFUWce0geYgH4hBNVIqSg88g0YvlAtOMSea7Np8z7/7dj1+aiHdLCVF2H2ehxfeuP7E/
         qRXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=9kLcp75pqOiooND0Ys3pWZaNd7OgLfG6xrOa5ekKHyo=;
        b=d5MYYxAfiSF2x7nCS4d2KZRKrdeXHGrAxh+7YdOFagc4RLn+kdh2wIFl4Sf3stAeus
         aBxjForObW5f/bT/thB+6jTtpDxqS/I+7SrIHZ6hz9BCBCr4nwNFtfplgyo6KghfY2kM
         5q8ZWaKp7Cz6zEadp+PAWLHWc6IB4NhdESQ6y38fkSdNGE2n5r8bKqdEZWDbUnOJvIAm
         tmyqJm5TLZQkHzLWGGSyC/H8z049ShluomLJ4aFBb136MURp5J/WC7AnWZSolQmGfOin
         KbnhZWbFjGmRaJ3Jh9nBY0VlYOitsQfzqJdu5qLxBdSTMqLWG9j6I79xIXF6inQxI0Fv
         KvYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9kLcp75pqOiooND0Ys3pWZaNd7OgLfG6xrOa5ekKHyo=;
        b=ccjP9ZIxCq4ppSrXoK5OQoKP8CTiRKND4XItapxO/rCF3x+uLEZfimRtyJ03uYcDAV
         b3fAKerxQWDoGK2ZbTp0dgPpEZ9fkHHHonZ1aM4ojP8hywsyLRODEWDvUUybzFZfJva2
         575jAULOTaMZxREw54gLpT4G95I4uYxirWyb8XyO1FOwQE5cgEmslyv679w4tMA4gPdB
         vkIuYXNy1G1ujOwjYv4AxeL1UG+CNJVYEldyDl7Zs+EcfcHQstLJZ63yMwChiPc2SOR+
         OWE1iV+g5n0Y8dTeyh/YkOAN9Jz7dlZomMHecUpLhTybfNLkucawsCTBm42zUt864ygs
         kNJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9kLcp75pqOiooND0Ys3pWZaNd7OgLfG6xrOa5ekKHyo=;
        b=Nk8i/nYcbaiBnYWeOAqBaQOUgBXVUnx8c84aobIr1lvfQOJRAdawMAXNXT6nHoQWk6
         saHIuT0zVbMzoQ/LLuW7zWY5njsbdqrD72vaOUj8Cm3/ZOI+gdJsrgcpBFNWkAGKxXiw
         etIjQ8pPWd0Ljxcm2lLKJLYWAcmh6bh40XHCMpcZsEB9HtJnFbOo/kxsuSer0ZxlyUb+
         rfOP14m6tz4OjFAlmfNSzIJgHoF+H7blIlleH4Y1K8STR5OCgW1xGS2uCaM64fb8yul3
         d+PnW8v4wL8PSCw5qsyY9iafB96bR9DLsoBsuEA8+p2jWfUL06CbJA7gLtzK7nyClJ20
         ittg==
X-Gm-Message-State: AOAM531W6x8ZwzpON1LIRXNffKOnbJ+6osnzsGxe0udC4kt+rCyyoAUH
	TvPKiPCjoWT22dVT0dvMmZY=
X-Google-Smtp-Source: ABdhPJwhm0nKgrV9NqeSARPcefv8xFEZ7SF8jbBhb1uoMX43pVbINAs/38/t7XyklVafwq6Am/Ql0g==
X-Received: by 2002:a05:6e02:1c2e:: with SMTP id m14mr34880948ilh.172.1638799615464;
        Mon, 06 Dec 2021 06:06:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:cf81:: with SMTP id w1ls1856184jar.9.gmail; Mon, 06 Dec
 2021 06:06:55 -0800 (PST)
X-Received: by 2002:a02:ab8f:: with SMTP id t15mr43833578jan.147.1638799615051;
        Mon, 06 Dec 2021 06:06:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638799615; cv=none;
        d=google.com; s=arc-20160816;
        b=zEKOLsGAvcMy2YSFgzZNFlwe37zwaEj5+JDAriKMc2D7DadO+FPtIkFwFOVJnT1EKV
         BMdCCavbRqdGJNFjndchsL9MlPIjgSa5QzZcM/vYuOr5Q3imnii0DtQ2jnQ19vKwM70z
         nX3Gjy08bwqgUj0uCYgwcFnbdyYYr4u1laUrKDQLjV6/K75cOFK8qJe2d5NkD2YfCJLE
         9CnxrawhF3BFBRJy3vOzggVavxcp+rOrFFx3V8WYeJQj/1GK/8/uM2zmByVszqDA0zXK
         Hp/xdzXvHQA+/BQN83fjwR5IS6eKDKhqTI8ut48yF0Yay3c7m2I/8M5XgAGvzb6XufNj
         cBbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=l/Sy8gnKSEJG1QN1xeA2xReXFtdF3iOy7s8pjcmmi+E=;
        b=TFqwraoamYlM0bO2WEU5my1JeIUJeY2gor3eziTVlmhB/goF8IKuJ4myaK+08tviDy
         ClKvAdCtGPhcXQTYYjK8CbKx4UTotv/TmAdEjou/Z6G2pXNimWHXXWSW9/6UQM+B6cV9
         kqMJMNPjJnHKtQ68zNpnLM7GSHmBoyz00cA/giRlvZjqE37OSV6BUc+NZoG6docRr78z
         phtqo3dXthdB0ishTUBiPitDzljphWVrIDlK7X/eS3op3zFzmQsVgL+KORiEipNSn7nE
         d58mwjUZbvd6ZAZOFtGF2vK/knAmCN7omBVV7r7ERZ+d3uT7g4VoBRPjQ3873J78dOoy
         940w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id d4si595699iob.2.2021.12.06.06.06.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Dec 2021 06:06:55 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm500024.china.huawei.com (unknown [172.30.72.55])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4J74sw35xcz1DJxB;
	Mon,  6 Dec 2021 22:04:04 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500024.china.huawei.com (7.185.36.203) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Mon, 6 Dec 2021 22:06:52 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.20; Mon, 6 Dec 2021 22:06:51 +0800
Message-ID: <71c69735-6064-6b28-eab3-67c36f88e51d@huawei.com>
Date: Mon, 6 Dec 2021 22:06:51 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH -next] kfence: fix memory leak when cat kfence objects
Content-Language: en-US
To: Marco Elver <elver@google.com>, Baokun Li <libaokun1@huawei.com>
CC: <glider@google.com>, <dvyukov@google.com>, <akpm@linux-foundation.org>,
	<viro@zeniv.linux.org.uk>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>, <yukuai3@huawei.com>,
	Hulk Robot <hulkci@huawei.com>
References: <20211206133628.2822545-1-libaokun1@huawei.com>
 <CANpmjNOrtcu16zKEjiZbBZJPDKWa6-PM_hw1yNZhXvpZupYgng@mail.gmail.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNOrtcu16zKEjiZbBZJPDKWa6-PM_hw1yNZhXvpZupYgng@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme705-chm.china.huawei.com (10.1.199.101) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
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


On 2021/12/6 21:29, Marco Elver wrote:
> On Mon, 6 Dec 2021 at 14:24, Baokun Li <libaokun1@huawei.com> wrote:
>> Hulk robot reported a kmemleak problem:
>> -----------------------------------------------------------------------
>> unreferenced object 0xffff93d1d8cc02e8 (size 248):
>>    comm "cat", pid 23327, jiffies 4624670141 (age 495992.217s)
>>    hex dump (first 32 bytes):
>>      00 40 85 19 d4 93 ff ff 00 10 00 00 00 00 00 00  .@..............
>>      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
>>    backtrace:
>>      [<00000000db5610b3>] seq_open+0x2a/0x80
>>      [<00000000d66ac99d>] full_proxy_open+0x167/0x1e0
>>      [<00000000d58ef917>] do_dentry_open+0x1e1/0x3a0
>>      [<0000000016c91867>] path_openat+0x961/0xa20
>>      [<00000000909c9564>] do_filp_open+0xae/0x120
>>      [<0000000059c761e6>] do_sys_openat2+0x216/0x2f0
>>      [<00000000b7a7b239>] do_sys_open+0x57/0x80
>>      [<00000000e559d671>] do_syscall_64+0x33/0x40
>>      [<000000000ea1fbfd>] entry_SYSCALL_64_after_hwframe+0x44/0xa9
>> unreferenced object 0xffff93d419854000 (size 4096):
>>    comm "cat", pid 23327, jiffies 4624670141 (age 495992.217s)
>>    hex dump (first 32 bytes):
>>      6b 66 65 6e 63 65 2d 23 32 35 30 3a 20 30 78 30  kfence-#250: 0x0
>>      30 30 30 30 30 30 30 37 35 34 62 64 61 31 32 2d  0000000754bda12-
>>    backtrace:
>>      [<000000008162c6f2>] seq_read_iter+0x313/0x440
>>      [<0000000020b1b3e3>] seq_read+0x14b/0x1a0
>>      [<00000000af248fbc>] full_proxy_read+0x56/0x80
>>      [<00000000f97679d1>] vfs_read+0xa5/0x1b0
>>      [<000000000ed8a36f>] ksys_read+0xa0/0xf0
>>      [<00000000e559d671>] do_syscall_64+0x33/0x40
>>      [<000000000ea1fbfd>] entry_SYSCALL_64_after_hwframe+0x44/0xa9
>> -----------------------------------------------------------------------
>>
>> I find that we can easily reproduce this problem with the following
>> commands:
>>          `cat /sys/kernel/debug/kfence/objects`
>>          `echo scan > /sys/kernel/debug/kmemleak`
>>          `cat /sys/kernel/debug/kmemleak`
>>
>> The leaked memory is allocated in the stack below:
>> ----------------------------------
>> do_syscall_64
>>    do_sys_open
>>      do_dentry_open
>>        full_proxy_open
>>          seq_open            ---> alloc seq_file
>>    vfs_read
>>      full_proxy_read
>>        seq_read
>>          seq_read_iter
>>            traverse          ---> alloc seq_buf
>> ----------------------------------
>>
>> And it should have been released in the following process:
>> ----------------------------------
>> do_syscall_64
>>    syscall_exit_to_user_mode
>>      exit_to_user_mode_prepare
>>        task_work_run
>>          ____fput
>>            __fput
>>              full_proxy_release  ---> free here
>> ----------------------------------
>>
>> However, the release function corresponding to file_operations is not
>> implemented in kfence. As a result, a memory leak occurs. Therefore,
>> the solution to this problem is to implement the corresponding
>> release function.
>>
>> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
>> Reported-by: Hulk Robot <hulkci@huawei.com>
>> Signed-off-by: Baokun Li <libaokun1@huawei.com>
Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71c69735-6064-6b28-eab3-67c36f88e51d%40huawei.com.
