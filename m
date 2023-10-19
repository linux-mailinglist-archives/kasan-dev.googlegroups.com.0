Return-Path: <kasan-dev+bncBCRKFI7J2AJRB74RYKUQMGQEHPRVU6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 256487CEDA1
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 03:40:17 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-65af758fa1esf86987276d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 18:40:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697679616; cv=pass;
        d=google.com; s=arc-20160816;
        b=BBa/aYiEc0DMXTUHq6bQrY+axuLaiPIZGxdXHtH9LPT0VQtsfc1xinLc9d5NYW1oOi
         elXJklZ5HGzKKqoTDc7CZxEAF6lMH6Z3RK4NRUrUqpzOha4Cn5npMIaUio5q+YP8JOL1
         9rywgwN56cUDo3hWl2xI2Lal8lss9TiXg/w35Tw0BISTr3bcd3HxVSltDwONvc2QfC7R
         qYz3xBuMGk7iVLlB1lmXenVo48NX3CB8XfCnRNhWzg/bDxsRL/mUYaJdZSLALP+K4jer
         jzOJUpattWzzqWtmKAOWoIzWdx/w0ofLx/lEzgPk2TZqC6VE8HvZzHuI5EKJxqzIKIZj
         psuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=RNx+EE5WXsLGgxf5KYMSE8BPYh/95dfqbZN1Aey7liE=;
        fh=9+AsJiaRYtdUCzlsBVxllfOqK6vK5sRdJvmuQsAf5RE=;
        b=lF+f9jlG//H78FKHplUSz4/2LezzW7QK3+DASNk21lVMAS3F7RVSzOzkeQyit9lAln
         iwz0uXfknpzPOtSbbtbpHNtsf14/UfkXfV2EqDiwUFfjznuKE1Kls+giPycoGTAV8jPZ
         v6eYGR6l0Q+tHaoUUQz1qzuAjipf8KAEC5/RQanTnqCXNFFuY/AxSxff/OOZVT/373sy
         beUcrFBn5HONARNx0NFfVPWAmO6kFb+s4UU4dZfO669IWeJId/F2hfKgPZR4Yr8hglHK
         tJFey1B0TG8RmG5hMZD3oP6B9+rGZtv6G/ZSCxg8ExdYOrEXzf9Tshu6abbz5NVYwXQe
         di2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697679616; x=1698284416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RNx+EE5WXsLGgxf5KYMSE8BPYh/95dfqbZN1Aey7liE=;
        b=SEhlCSRHgTXSTCKOabH3lX+PPhyALkWHJuRs3bVEevRDUYwNhoJc5W0hB0uGb/rpCG
         3dYorZVFcstOxBYFfFrlAo9vNAlMBjDr3iv+QwoACMNxq7bII20ZkM+YhIxbH3KyaNiy
         O4Zj4reN3kefMJZKO5Ky71y2RIKfte/P6mDslY8PbGcO/Q6mvQ1uEIxkj0qYgTVZ2gGP
         S78D4qhZ/Fr+KWCRF/nw1/de3k+Xo1Ltdb6j4c5pmm1C3zOsNPTpgUFViJoDBuGek6jo
         XcrREWVgkW6gtxlGTGgcvTP8Q5BFEqBBuxDNLzHtkEY1+K9I1yLTCf4YbtVdD0vfWolg
         TJ0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697679616; x=1698284416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RNx+EE5WXsLGgxf5KYMSE8BPYh/95dfqbZN1Aey7liE=;
        b=i9dqKs+qhvMPfN74FFY9tbMWKKYARdglhFKH7Rzke5dA+wKdyrSTEg+C9fsMzovCZP
         4a7E2dwGe4dhn8R+P9o76vPVVykQvHbTa/Nn5wMpFYen9aDf/uWx7MaN5H27lyj/fBpG
         aS3EK3FdydUYiul+0tliaYu8XeOC8RHie1FglSD4h7bHLsvWjdshRvmO7oX/dDftk5Lv
         YL9AZ84wSwqQJcU8CLjJ4q9W9hKHNhGB25TOtK4WJ8X1WTnKUTwF5KkcdnsptmDZN4v4
         4qncwnvySdH1bG4gBQHg8Km4B0stAmxCSHIm2CeNp4v7WRNc35WjpzIfgJ+iTRY/+52r
         dCcw==
X-Gm-Message-State: AOJu0YwM6l/E/yIlaRBDspquAbfm7wVcEi0aBcnfR67bX7NB++/KBBo9
	i4boZImYwc7z9rhcVs6Iuws=
X-Google-Smtp-Source: AGHT+IHW70fsrlNgaz4g3VoSFSvJsFIHCLaS9Pssf1VJvClmTmzC2QMwgJIsr8c52LiH6ZoT5jpHNQ==
X-Received: by 2002:ad4:5c8b:0:b0:66d:11fd:c9c0 with SMTP id o11-20020ad45c8b000000b0066d11fdc9c0mr1162782qvh.58.1697679615840;
        Wed, 18 Oct 2023 18:40:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:19e6:b0:66d:869b:3a7c with SMTP id
 q6-20020a05621419e600b0066d869b3a7cls488985qvc.1.-pod-prod-05-us; Wed, 18 Oct
 2023 18:40:15 -0700 (PDT)
X-Received: by 2002:a05:6214:2029:b0:66d:1174:3b46 with SMTP id 9-20020a056214202900b0066d11743b46mr1303540qvf.50.1697679614948;
        Wed, 18 Oct 2023 18:40:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697679614; cv=none;
        d=google.com; s=arc-20160816;
        b=mlNi+iwanpsaChWmsjyBZeAkNijCK/zSW2jTjtoDJrk7okzFC22VarG/DM6HUF2xJk
         HviupuYcvPywht5NbttYvLNlAy36KQIX+tJ0I3KDgNcvL03NE+5H38sSMiEbAaf9Mmc7
         y8gmiuSlfEwiha2evW4gBaE2ia4evIj9xV0aJSOWeA4c1KJP2dg8q/JjV2ixFMlEr/X6
         zgUAcKUqE/Vf5bSfyURN2qSd097pPNnXUGzRPzesaUhxXuccqBwP5lFEaPEahHXWdI5C
         1CV+1tLw3QsQkts++WC7jGM5RdbZ8ysxt6X0J3X0uMDznu3mMHaZJ4m2U+fUGGT1r3A8
         T43Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=iEXz9BhdkkB38Au8NZ9ZEeDEU1ofYbOxdh7uiBM6aZA=;
        fh=9+AsJiaRYtdUCzlsBVxllfOqK6vK5sRdJvmuQsAf5RE=;
        b=bXLbCJULIccrLYvLmSboljRkihNjzXGHAVHAepwZ+RimhniHIZr0auPaWTJtvwjCZV
         FA7MFsuQ50mXBn9gzaJ2yU6OVqo4TbungVu8S+RJkLL52RmzMT8dAZgD322w+KL6oVim
         j84/XNYOSTtTEcv08F+14btArNf9KTVFk7anmA1OA9okc3NcRvdR9AbpPEJva8rPZ3EQ
         J/LqL2/SwXa/iVAVOphWiprKo6z1mkKDHxOeLBaYSnGfda2lih+5hjHskG35LdLhkTZu
         eOAayHN0L+Lzv4rpWAElAlRKJdELKdwcs7qYafhZUTMtMTluDaTxDz3HDezzEnypiXsl
         AUkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id c22-20020a05620a135600b0076989bfc79fsi92691qkl.1.2023.10.18.18.40.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Oct 2023 18:40:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4S9r0C5YcQzNp33;
	Thu, 19 Oct 2023 09:36:11 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Thu, 19 Oct 2023 09:40:10 +0800
Message-ID: <5b33515b-5fd2-4dc7-9778-e321484d2427@huawei.com>
Date: Thu, 19 Oct 2023 09:40:10 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or
 depopulate pte
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>, Lorenzo Stoakes <lstoakes@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
 <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com>
 <dd39cb3e-b184-407d-b74f-5b90a7983c99@huawei.com>
 <CANpmjNPY5NgvnfDcu1GFP-K0rCgiB4_+TqL4-p_ER-bLYvw26A@mail.gmail.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNPY5NgvnfDcu1GFP-K0rCgiB4_+TqL4-p_ER-bLYvw26A@mail.gmail.com>
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



On 2023/10/19 0:37, Marco Elver wrote:
> On Wed, 18 Oct 2023 at 16:16, 'Kefeng Wang' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>
>> The issue is easy to reproduced with large vmalloc, kindly ping...
>>
>> On 2023/9/15 8:58, Kefeng Wang wrote:
>>> Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.
>>>
>>> On 2023/9/6 20:42, Kefeng Wang wrote:
>>>> This is a RFC, even patch3 is a hack to fix the softlock issue when
>>>> populate or depopulate pte with large region, looking forward to your
>>>> reply and advise, thanks.
>>>
>>> Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C
>>>
>>> [    C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [insmod:458]
>>> [    C3] Modules linked in: test(OE+)
>>> [    C3] irq event stamp: 320776
>>> [    C3] hardirqs last  enabled at (320775): [<ffff8000815a0c98>]
>>> _raw_spin_unlock_irqrestore+0x98/0xb8
>>> [    C3] hardirqs last disabled at (320776): [<ffff8000815816e0>]
>>> el1_interrupt+0x38/0xa8
>>> [    C3] softirqs last  enabled at (318174): [<ffff800080040ba8>]
>>> __do_softirq+0x658/0x7ac
>>> [    C3] softirqs last disabled at (318169): [<ffff800080047fd8>]
>>> ____do_softirq+0x18/0x30
>>> [    C3] CPU: 3 PID: 458 Comm: insmod Tainted: G           OE 6.5.0+ #5=
95
>>> [    C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/201=
5
>>> [    C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=3D=
--)
>>> [    C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
>>> [    C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
>>> [    C3] sp : ffff800093386d70
>>> [    C3] x29: ffff800093386d70 x28: 0000000000000801 x27: ffff0007ffffa=
9c0
>>> [    C3] x26: 0000000000000000 x25: 000000000000003f x24: fffffc0004353=
708
>>> [    C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: 0000000000000=
000
>>> [    C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 0000000000000=
000
>>> [    C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: ffff80008024e=
c60
>>> [    C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: ffff6000fffff=
5f9
>>> [    C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fffff=
5f8
>>> [    C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff800000000=
000
>>> [    C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff700012670=
d70
>>> [    C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : 000000000004e=
507
>>> [    C3] Call trace:
>>> [    C3]  _raw_spin_unlock_irqrestore+0x50/0xb8
>>> [    C3]  rmqueue_bulk+0x434/0x6b8
>>> [    C3]  get_page_from_freelist+0xdd4/0x1680
>>> [    C3]  __alloc_pages+0x244/0x508
>>> [    C3]  alloc_pages+0xf0/0x218
>>> [    C3]  __get_free_pages+0x1c/0x50
>>> [    C3]  kasan_populate_vmalloc_pte+0x30/0x188
>>> [    C3]  __apply_to_page_range+0x3ec/0x650
>>> [    C3]  apply_to_page_range+0x1c/0x30
>>> [    C3]  kasan_populate_vmalloc+0x60/0x70
>>> [    C3]  alloc_vmap_area.part.67+0x328/0xe50
>>> [    C3]  alloc_vmap_area+0x4c/0x78
>>> [    C3]  __get_vm_area_node.constprop.76+0x130/0x240
>>> [    C3]  __vmalloc_node_range+0x12c/0x340
>>> [    C3]  __vmalloc_node+0x8c/0xb0
>>> [    C3]  vmalloc+0x2c/0x40
>>> [    C3]  show_mem_init+0x1c/0xff8 [test]
>>> [    C3]  do_one_initcall+0xe4/0x500
>>> [    C3]  do_init_module+0x100/0x358
>>> [    C3]  load_module+0x2e64/0x2fc8
>>> [    C3]  init_module_from_file+0xec/0x148
>>> [    C3]  idempotent_init_module+0x278/0x380
>>> [    C3]  __arm64_sys_finit_module+0x88/0xf8
>>> [    C3]  invoke_syscall+0x64/0x188
>>> [    C3]  el0_svc_common.constprop.1+0xec/0x198
>>> [    C3]  do_el0_svc+0x48/0xc8
>>> [    C3]  el0_svc+0x3c/0xe8
>>> [    C3]  el0t_64_sync_handler+0xa0/0xc8
>>> [    C3]  el0t_64_sync+0x188/0x190
>>>
>>> and for depopuldate pte=EF=BC=8C
>>>
>>> [    C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kworker/6:1=
:59]
>>> [    C6] Modules linked in: test(OE+)
>>> [    C6] irq event stamp: 39458
>>> [    C6] hardirqs last  enabled at (39457): [<ffff8000815a0c98>]
>>> _raw_spin_unlock_irqrestore+0x98/0xb8
>>> [    C6] hardirqs last disabled at (39458): [<ffff8000815816e0>]
>>> el1_interrupt+0x38/0xa8
>>> [    C6] softirqs last  enabled at (39420): [<ffff800080040ba8>]
>>> __do_softirq+0x658/0x7ac
>>> [    C6] softirqs last disabled at (39415): [<ffff800080047fd8>]
>>> ____do_softirq+0x18/0x30
>>> [    C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G           OEL
>>> 6.5.0+ #595
>>> [    C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/201=
5
>>> [    C6] Workqueue: events drain_vmap_area_work
>>> [    C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=3D=
--)
>>> [    C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
>>> [    C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
>>> [    C6] sp : ffff80008fe676b0
>>> [    C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: ffff000edf5df=
a80
>>> [    C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: 0000000000000=
006
>>> [    C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: 0000000000000=
006
>>> [    C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 0000000000000=
000
>>> [    C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: ffff8000805c1=
1b0
>>> [    C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: ffff6000fffff=
5f9
>>> [    C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fffff=
5f8
>>> [    C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff800000000=
000
>>> [    C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff700011fcc=
e98
>>> [    C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : 0000000000009=
a21
>>> [    C6] Call trace:
>>> [    C6]  _raw_spin_unlock_irqrestore+0x50/0xb8
>>> [    C6]  free_pcppages_bulk+0x2bc/0x3e0
>>> [    C6]  free_unref_page_commit+0x1fc/0x290
>>> [    C6]  free_unref_page+0x184/0x250
>>> [    C6]  __free_pages+0x154/0x1a0
>>> [    C6]  free_pages+0x88/0xb0
>>> [    C6]  kasan_depopulate_vmalloc_pte+0x58/0x80
>>> [    C6]  __apply_to_page_range+0x3ec/0x650
>>> [    C6]  apply_to_existing_page_range+0x1c/0x30
>>> [    C6]  kasan_release_vmalloc+0xa4/0x118
>>> [    C6]  __purge_vmap_area_lazy+0x4f4/0xe30
>>> [    C6]  drain_vmap_area_work+0x60/0xc0
>>> [    C6]  process_one_work+0x4cc/0xa38
>>> [    C6]  worker_thread+0x240/0x638
>>> [    C6]  kthread+0x1c8/0x1e0
>>> [    C6]  ret_from_fork+0x10/0x20
>>>
>>>
>>>
>>>>
>>>> Kefeng Wang (3):
>>>>     mm: kasan: shadow: add cond_resched() in kasan_populate_vmalloc_pt=
e()
>>>>     mm: kasan: shadow: move free_page() out of page table lock
>>>>     mm: kasan: shadow: HACK add cond_resched_lock() in
>>>>       kasan_depopulate_vmalloc_pte()
>=20
> The first 2 patches look ok, but yeah, the last is a hack. I also
> don't have any better suggestions, only more questions.

Thanks Marco, maybe we could convert free_vmap_area_lock from spinlock=20
to mutex lock only if KASAN enabled?

>=20
> Does this only happen on arm64?

Our test case run on arm64 qemu(host is x86), so it run much more slower=20
than real board.
> Do you have a minimal reproducer you can share?
Here is the code in test driver,

void *buf =3D vmalloc(40UL << 30);
vfree(buf);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5b33515b-5fd2-4dc7-9778-e321484d2427%40huawei.com.
