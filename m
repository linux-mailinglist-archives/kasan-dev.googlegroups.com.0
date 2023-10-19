Return-Path: <kasan-dev+bncBCRKFI7J2AJRBJ7WYOUQMGQEHLXIGBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id F30987CF454
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 11:47:20 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-35278d347bbsf58491195ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 02:47:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697708839; cv=pass;
        d=google.com; s=arc-20160816;
        b=n18CfdrU8F1donQSpMcbU4puahm1PiR/tC+JVcHYIv+hi4bRxC9YSR8X9VGuOY6HaL
         9OeajrhR8WdPULNg19gzXq+855n8H6uQkk8tAFCbZBMLOaSWSbZkEINxRyecn+CQWwwO
         o4aAuygcjzTlreDTC8csgKZkxP/p177pTkzN5pMJ5PhmVgJ7HtM60oC6O4tzOWjkkNCH
         Q/c8/hFnXza7/fabHI7oX1TxNOIfPaXOKEaWHqSmS9AkSUzrzWtHnZuNTVK5VFjlnMWk
         B3Z7pZtE47W6pNLIfa/j3aBLtzH20ZAPoidTEOmEOHrg2qufM6jRUDPo3ygT60QsWdwC
         vHdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=NS6bynwRfeJxxTD8tPwoCHOpHddmFGaFHs/pd/9gNhY=;
        fh=fhypw1/r/HG+aNTeYBk1rNVXIP/3EDL4naufRsDyMCM=;
        b=YsV+WBZkxcMYZoqbNgjZlXCuHkNlstHWraXburN1InBgyqrF3CLitc/rLiBYWY0zbq
         VMV2x1b7dfxS3yNt5vMNpuNf/FneIKWgg8svUXHTcS1YPfYtKH9fpwqcDqZlnkxdaSrA
         c2Z58ORDAHEFfoc8ZlT0rYH/yfy0KaBxpEFYo8ZzoHH6IcEEeXWv7ryS/aLmIpm2suvh
         y9z5/I7Lh7PyMhP2GvYdGEvSgmHYAwSmULKF8Dw25pHByIc+prYFfpXeu/vIWu3y5Sdt
         iR0Bqunjioz1Phx6wyDvc8dpf+mj2qZchfkE3VMzF6uauzUUsGOctQruvEaD47krtrlJ
         L05g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697708839; x=1698313639; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NS6bynwRfeJxxTD8tPwoCHOpHddmFGaFHs/pd/9gNhY=;
        b=GuZ94D/rwTQvoOAO44BUzDahQ/BQWJUPZz8QAHoeCyLKKSDqzmLiqZATVquJNfu+xH
         TXyG/VHIGI+8ROmruyzUfCIgS77D1cyOxZP/FTfAdEL+m+jHTRDpSqh2S6V3b0W8D3Kz
         WCy6BgSflBpIXcaGAbmaJc7RgXDNqAWGNtSa38L7E8zCvOe0MVnutqZPeDELs7wZnBzl
         W+sNbSut5vs2Azn8hqSOd5uZxQy66loCVDZVY7Ar93p9wX+8Axcnnoh3cHtvAhmYMc8p
         0fWf4ng5kwmup85za0b3Is2n3ZhKqQobHp7LG6K8WCsDFqYDAEsnvedvodk8AKZRo4ET
         h8Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697708839; x=1698313639;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NS6bynwRfeJxxTD8tPwoCHOpHddmFGaFHs/pd/9gNhY=;
        b=axTj2tZHvBwFghmt9doxkgXI36FHmPoVwUKwvIi0xA4U26ZVhZ3GGVR9mX2BS1sZRX
         NyRyowsLl0DLNEOk7LbhhBmUvt624RTV5+SgBgg4HwQdxH2R2+J335SP/4TbZda4rpHC
         1jwojGT/yVBkcuSQuGP8eFJKdsLV0R4llwdeYTPZ1uzsHZQPtE2e43EaIoVZK7T3OsbL
         axsnDhCYNXB5PGAze880Oai9k/+LOkjiQyiyXYq5BTelMVW4sdjXn1rzxV2A/KwQrvjj
         UhVoQxf7TqbXtqoYp69ndz6AYlZzJzF58dqgf16MPoiL4IlVbl6OzB5x2r0Ss7Tx0ijr
         RkCQ==
X-Gm-Message-State: AOJu0YxmSyuzJX947vwp2GKdzflOfHua9Gg8COoGA9SbV8BRsgAsILD1
	UfL1JibdaD4XDQ+RBswN1C0=
X-Google-Smtp-Source: AGHT+IFI6F8YwlcPoznD2JNyo+4VMpx6t5Oapo+ZZPOUGUr8g8BI4akPW5K3iEbBorx3/gg1NUAOeg==
X-Received: by 2002:a05:6e02:1d8a:b0:357:9eb5:15d6 with SMTP id h10-20020a056e021d8a00b003579eb515d6mr2261160ila.12.1697708839513;
        Thu, 19 Oct 2023 02:47:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ce43:0:b0:357:af8c:6704 with SMTP id a3-20020a92ce43000000b00357af8c6704ls173452ilr.2.-pod-prod-02-us;
 Thu, 19 Oct 2023 02:47:18 -0700 (PDT)
X-Received: by 2002:a05:6602:13cc:b0:786:7100:72de with SMTP id o12-20020a05660213cc00b00786710072demr1877920iov.16.1697708838758;
        Thu, 19 Oct 2023 02:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697708838; cv=none;
        d=google.com; s=arc-20160816;
        b=Ifdm5niipSSkY/3/RPuqdJB/aQH2FAPWtNisuH4B7ljNT7cH0Oz4N9a1i2hJTcg7VY
         0AAtLV5JXSiREZc6Y7IHjPWqFM1vRpvjodn7bl52d011e5liju0dHiMyMd9XB7kaGfZ5
         +Ja9fJtlqRqDH7NvXaCxbkdXySHkR3aJlRbxjXUHdyUQEJ1skWbYqs1qqyqQZbTBZNAp
         lRhETHJhYIB6rRmp3B1tA1C2JOByM3lSKwOZFdyBNwcBt3pUAXdUqSuPRb6BNzi/N9MF
         YytlNhTzmKa+UqoczxrrFgZo5AIeApK30URu6iyslUdmg5ozo0z0mn2vNpeGb4rPoKhl
         YvqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=F/guqm0bAnd8erKXwEu4rIXqDeeFo2MIuBKs9kIGWUY=;
        fh=fhypw1/r/HG+aNTeYBk1rNVXIP/3EDL4naufRsDyMCM=;
        b=RBVDrTdZEgVmbOEPO0ryAcZyM5KHr+kSRPsPpKYZpj7TXGmGiD2zf2vTqvCvx7xt61
         uO18P108/9pD4Dm12cbFiDum5bbEew2JSoxsgyV7AWp3sfBJynTsSq+lSxb+6fpBFaPD
         qGw3eW6rLMAORp7byk7qnL2QbdMs0Si56gt7TpsyS9RqlaZ7NjZ9N0vb4u/69rk6AKd3
         14Rg0Z4M6BAYxHZeXyU6cxqJjbPq8sjn5gxTxbpGC6/GabMNuXhNA1FO1Pd1mMn0TIj+
         JTGP1W6XXgZDXGWNaK2S0B0KH/KH7kOJKiZGo6LgTPk5GwUrxojFG40N/jFx08U1/tma
         Yysg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id l10-20020a6b7f0a000000b0079d5fe48bd9si173888ioq.0.2023.10.19.02.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Oct 2023 02:47:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4SB2pC11q5zNnyQ;
	Thu, 19 Oct 2023 17:43:15 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Thu, 19 Oct 2023 17:47:14 +0800
Message-ID: <146508e9-db36-4c84-8ac6-1b3173b94194@huawei.com>
Date: Thu, 19 Oct 2023 17:47:13 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or
 depopulate pte
Content-Language: en-US
To: Uladzislau Rezki <urezki@gmail.com>
CC: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@infradead.org>, Lorenzo Stoakes <lstoakes@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
 <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com>
 <dd39cb3e-b184-407d-b74f-5b90a7983c99@huawei.com>
 <CANpmjNPY5NgvnfDcu1GFP-K0rCgiB4_+TqL4-p_ER-bLYvw26A@mail.gmail.com>
 <5b33515b-5fd2-4dc7-9778-e321484d2427@huawei.com> <ZTDJ8t9ug3Q6E8GG@pc636>
 <7ab8839b-8f88-406e-b6e1-2c69c8967d4e@huawei.com> <ZTDunPbSDg29l8so@pc636>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZTDunPbSDg29l8so@pc636>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm100001.china.huawei.com (7.185.36.93)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
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



On 2023/10/19 16:53, Uladzislau Rezki wrote:
> On Thu, Oct 19, 2023 at 03:26:48PM +0800, Kefeng Wang wrote:
>>
>>
>> On 2023/10/19 14:17, Uladzislau Rezki wrote:
>>> On Thu, Oct 19, 2023 at 09:40:10AM +0800, Kefeng Wang wrote:
>>>>
>>>>
>>>> On 2023/10/19 0:37, Marco Elver wrote:
>>>>> On Wed, 18 Oct 2023 at 16:16, 'Kefeng Wang' via kasan-dev
>>>>> <kasan-dev@googlegroups.com> wrote:
>>>>>>
>>>>>> The issue is easy to reproduced with large vmalloc, kindly ping...
>>>>>>
>>>>>> On 2023/9/15 8:58, Kefeng Wang wrote:
>>>>>>> Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.
>>>>>>>
>>>>>>> On 2023/9/6 20:42, Kefeng Wang wrote:
>>>>>>>> This is a RFC, even patch3 is a hack to fix the softlock issue whe=
n
>>>>>>>> populate or depopulate pte with large region, looking forward to y=
our
>>>>>>>> reply and advise, thanks.
>>>>>>>
>>>>>>> Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C
>>>>>>>
>>>>>>> [    C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [insmod:=
458]
>>>>>>> [    C3] Modules linked in: test(OE+)
>>>>>>> [    C3] irq event stamp: 320776
>>>>>>> [    C3] hardirqs last  enabled at (320775): [<ffff8000815a0c98>]
>>>>>>> _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>>>> [    C3] hardirqs last disabled at (320776): [<ffff8000815816e0>]
>>>>>>> el1_interrupt+0x38/0xa8
>>>>>>> [    C3] softirqs last  enabled at (318174): [<ffff800080040ba8>]
>>>>>>> __do_softirq+0x658/0x7ac
>>>>>>> [    C3] softirqs last disabled at (318169): [<ffff800080047fd8>]
>>>>>>> ____do_softirq+0x18/0x30
>>>>>>> [    C3] CPU: 3 PID: 458 Comm: insmod Tainted: G           OE 6.5.0=
+ #595
>>>>>>> [    C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06=
/2015
>>>>>>> [    C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYP=
E=3D--)
>>>>>>> [    C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>>>> [    C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>>>> [    C3] sp : ffff800093386d70
>>>>>>> [    C3] x29: ffff800093386d70 x28: 0000000000000801 x27: ffff0007f=
fffa9c0
>>>>>>> [    C3] x26: 0000000000000000 x25: 000000000000003f x24: fffffc000=
4353708
>>>>>>> [    C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: 000000000=
0000000
>>>>>>> [    C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 000000000=
0000000
>>>>>>> [    C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: ffff80008=
024ec60
>>>>>>> [    C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: ffff6000f=
ffff5f9
>>>>>>> [    C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000f=
ffff5f8
>>>>>>> [    C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff80000=
0000000
>>>>>>> [    C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff70001=
2670d70
>>>>>>> [    C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : 000000000=
004e507
>>>>>>> [    C3] Call trace:
>>>>>>> [    C3]  _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>>>> [    C3]  rmqueue_bulk+0x434/0x6b8
>>>>>>> [    C3]  get_page_from_freelist+0xdd4/0x1680
>>>>>>> [    C3]  __alloc_pages+0x244/0x508
>>>>>>> [    C3]  alloc_pages+0xf0/0x218
>>>>>>> [    C3]  __get_free_pages+0x1c/0x50
>>>>>>> [    C3]  kasan_populate_vmalloc_pte+0x30/0x188
>>>>>>> [    C3]  __apply_to_page_range+0x3ec/0x650
>>>>>>> [    C3]  apply_to_page_range+0x1c/0x30
>>>>>>> [    C3]  kasan_populate_vmalloc+0x60/0x70
>>>>>>> [    C3]  alloc_vmap_area.part.67+0x328/0xe50
>>>>>>> [    C3]  alloc_vmap_area+0x4c/0x78
>>>>>>> [    C3]  __get_vm_area_node.constprop.76+0x130/0x240
>>>>>>> [    C3]  __vmalloc_node_range+0x12c/0x340
>>>>>>> [    C3]  __vmalloc_node+0x8c/0xb0
>>>>>>> [    C3]  vmalloc+0x2c/0x40
>>>>>>> [    C3]  show_mem_init+0x1c/0xff8 [test]
>>>>>>> [    C3]  do_one_initcall+0xe4/0x500
>>>>>>> [    C3]  do_init_module+0x100/0x358
>>>>>>> [    C3]  load_module+0x2e64/0x2fc8
>>>>>>> [    C3]  init_module_from_file+0xec/0x148
>>>>>>> [    C3]  idempotent_init_module+0x278/0x380
>>>>>>> [    C3]  __arm64_sys_finit_module+0x88/0xf8
>>>>>>> [    C3]  invoke_syscall+0x64/0x188
>>>>>>> [    C3]  el0_svc_common.constprop.1+0xec/0x198
>>>>>>> [    C3]  do_el0_svc+0x48/0xc8
>>>>>>> [    C3]  el0_svc+0x3c/0xe8
>>>>>>> [    C3]  el0t_64_sync_handler+0xa0/0xc8
>>>>>>> [    C3]  el0t_64_sync+0x188/0x190
>>>>>>>
> This trace is stuck in the rmqueue_bulk() because you request a
> huge alloc size. It has nothing to do with free_vmap_area_lock,
> it is about bulk allocator. It gets stuck to accomplish such
> demand.

Yes, this is not about spinlock issue, it runs too much time in
kasan_populate_vmalloc() as the __apply_to_page_range() with a
large range, and this issue could be fixed by adding a cond_resched()
in kasan_populate_vmalloc(), see patch1.



>=20
>=20
>>>>>>> and for depopuldate pte=EF=BC=8C
>>>>>>>
>>>>>>> [    C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kworker=
/6:1:59]
>>>>>>> [    C6] Modules linked in: test(OE+)
>>>>>>> [    C6] irq event stamp: 39458
>>>>>>> [    C6] hardirqs last  enabled at (39457): [<ffff8000815a0c98>]
>>>>>>> _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>>>> [    C6] hardirqs last disabled at (39458): [<ffff8000815816e0>]
>>>>>>> el1_interrupt+0x38/0xa8
>>>>>>> [    C6] softirqs last  enabled at (39420): [<ffff800080040ba8>]
>>>>>>> __do_softirq+0x658/0x7ac
>>>>>>> [    C6] softirqs last disabled at (39415): [<ffff800080047fd8>]
>>>>>>> ____do_softirq+0x18/0x30
>>>>>>> [    C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G           OEL
>>>>>>> 6.5.0+ #595
>>>>>>> [    C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06=
/2015
>>>>>>> [    C6] Workqueue: events drain_vmap_area_work
>>>>>>> [    C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYP=
E=3D--)
>>>>>>> [    C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>>>> [    C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>>>> [    C6] sp : ffff80008fe676b0
>>>>>>> [    C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: ffff000ed=
f5dfa80
>>>>>>> [    C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: 000000000=
0000006
>>>>>>> [    C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: 000000000=
0000006
>>>>>>> [    C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 000000000=
0000000
>>>>>>> [    C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: ffff80008=
05c11b0
>>>>>>> [    C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: ffff6000f=
ffff5f9
>>>>>>> [    C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000f=
ffff5f8
>>>>>>> [    C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff80000=
0000000
>>>>>>> [    C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff70001=
1fcce98
>>>>>>> [    C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : 000000000=
0009a21
>>>>>>> [    C6] Call trace:
>>>>>>> [    C6]  _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>>>> [    C6]  free_pcppages_bulk+0x2bc/0x3e0
>>>>>>> [    C6]  free_unref_page_commit+0x1fc/0x290
>>>>>>> [    C6]  free_unref_page+0x184/0x250
>>>>>>> [    C6]  __free_pages+0x154/0x1a0
>>>>>>> [    C6]  free_pages+0x88/0xb0
>>>>>>> [    C6]  kasan_depopulate_vmalloc_pte+0x58/0x80
>>>>>>> [    C6]  __apply_to_page_range+0x3ec/0x650
>>>>>>> [    C6]  apply_to_existing_page_range+0x1c/0x30
>>>>>>> [    C6]  kasan_release_vmalloc+0xa4/0x118
>>>>>>> [    C6]  __purge_vmap_area_lazy+0x4f4/0xe30
>>>>>>> [    C6]  drain_vmap_area_work+0x60/0xc0
>>>>>>> [    C6]  process_one_work+0x4cc/0xa38
>>>>>>> [    C6]  worker_thread+0x240/0x638
>>>>>>> [    C6]  kthread+0x1c8/0x1e0
>>>>>>> [    C6]  ret_from_fork+0x10/0x20
>>>>>>>
>>
>> See Call Trace of softlock, when map/unmap the vmalloc buf, the kasan wi=
ll
>> populate and depopulate vmalloc pte, those will spend more time than
>> no-kasan kernel, for unmap, and there is already a cond_resched_lock() i=
n
>> __purge_vmap_area_lazy(), but with more time consumed under
>> spinlock(free_vmap_area_lock), and we couldn't add cond_resched_lock in
>> kasan_depopulate_vmalloc_pte(), so if spin lock converted to mutex lock,=
 we
>> could add a cond_resched into kasan depopulate, this is why make such
>> conversion if kasan enabled, but this
>> conversion maybe not correct, any better solution?
>>
> I have at least below thoughts:
>=20
> a) Add a max allowed threshold that user can request over vmalloc() call.
>    I do not think ~40G is a correct request.

I don't know, but maybe some driver could map large range , but we do
meet this issue in qemu, though it is very low probability.

>=20
> b) This can fix unmap path:
>=20
> <snip>
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index ef8599d394fd..988735da5c5c 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -1723,7 +1723,6 @@ static void purge_fragmented_blocks_allcpus(void);
>    */
>   static bool __purge_vmap_area_lazy(unsigned long start, unsigned long e=
nd)
>   {
> -	unsigned long resched_threshold;
>   	unsigned int num_purged_areas =3D 0;
>   	struct list_head local_purge_list;
>   	struct vmap_area *va, *n_va;
> @@ -1747,36 +1746,32 @@ static bool __purge_vmap_area_lazy(unsigned long =
start, unsigned long end)
>   			struct vmap_area, list)->va_end);
>  =20
>   	flush_tlb_kernel_range(start, end);
> -	resched_threshold =3D lazy_max_pages() << 1;
>  =20
> -	spin_lock(&free_vmap_area_lock);
>   	list_for_each_entry_safe(va, n_va, &local_purge_list, list) {
>   		unsigned long nr =3D (va->va_end - va->va_start) >> PAGE_SHIFT;
>   		unsigned long orig_start =3D va->va_start;
>   		unsigned long orig_end =3D va->va_end;
>  =20
> +		if (is_vmalloc_or_module_addr((void *)orig_start))
> +			kasan_release_vmalloc(orig_start, orig_end,
> +					      va->va_start, va->va_end);


> +
>   		/*
>   		 * Finally insert or merge lazily-freed area. It is
>   		 * detached and there is no need to "unlink" it from
>   		 * anything.
>   		 */
> +		spin_lock(&free_vmap_area_lock);
>   		va =3D merge_or_add_vmap_area_augment(va, &free_vmap_area_root,
>   				&free_vmap_area_list);
> +		spin_unlock(&free_vmap_area_lock);
>  =20
>   		if (!va)
>   			continue;
>  =20
> -		if (is_vmalloc_or_module_addr((void *)orig_start))
> -			kasan_release_vmalloc(orig_start, orig_end,
> -					      va->va_start, va->va_end);
> -
>   		atomic_long_sub(nr, &vmap_lazy_nr);
>   		num_purged_areas++;
> -
> -		if (atomic_long_read(&vmap_lazy_nr) < resched_threshold)
> -			cond_resched_lock(&free_vmap_area_lock);
>   	}
> -	spin_unlock(&free_vmap_area_lock);
>  =20
>   out:
>   	trace_purge_vmap_area_lazy(start, end, num_purged_areas);
> <snip>

Thanks for you suggestion. but check kasan_release_vmalloc(), it seems
that kasan_release_vmalloc() need free_vmap_area_lock from comment[1],

Marco and all kasan maintainers, please help to check the above way.

[1] https://elixir.bootlin.com/linux/v6.6-rc6/source/mm/kasan/shadow.c#L491

>=20
> c) bulk-path i have not checked, but on a high level kasan_populate_vmall=
oc()
> should take a breath between requests.
>=20
> --
> Uladzislau Rezki
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/146508e9-db36-4c84-8ac6-1b3173b94194%40huawei.com.
