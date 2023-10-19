Return-Path: <kasan-dev+bncBCRKFI7J2AJRBPNUYOUQMGQEZ6SGNCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 052FE7CF130
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 09:26:55 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1e9b6561650sf9410496fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 00:26:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697700413; cv=pass;
        d=google.com; s=arc-20160816;
        b=04P/GTiDuCpJfqlEVIbijgnXy5Ncz+32khm0WDBR5o+Bk+CkSiQYsm/v4u4QwREGWn
         E6enJZLzJC+mUljoJe8/8dcgz7avWikZsbT5ziWkDCd/LQSb33+SNmn2qTdaAaFXUCs1
         Y/+R5O8njC60unu59vVtYacPMsvduNQ/+oVVXexsb/EbET57yGcVTx/KX5aYaQEqSem6
         OAVvx0PejZPH2XWiJbzwYTPCGYrpqcTummnfX28OZ+qIiDJH/EMqOX+MZPsGRZGnsKnq
         y/aEleWVUgwIdngBjNSsfjEWinrSJb7+d8xGfzmhTfR7NO9j79jbjPTQ8ZGZOmwfSPoW
         h5IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Ra9m1WM+9kxSXd/XNzt2vGNUvV4aiGnNAdcCVy1xiW0=;
        fh=fhypw1/r/HG+aNTeYBk1rNVXIP/3EDL4naufRsDyMCM=;
        b=UQR4oswkhlrmDvFno8dSuzHWLfYkuaQnN4CG/fLQFdaoyTuE9GLcVxsKQ77jh6ykZL
         wbnVA3l0dRUhpCmLmTZkwLBeb7kFvH+Nd9oKfvwLdhz1s1PoHegt/cJUjPFDUIgc5GoD
         VpD6dkKWvkdbJOsl9qq37xBOXv1OekBC/VTvHgAfNxoUmBfWrmbFKIslbNN3VOGAt6yL
         q7r7YQD4YVIDtstP0d7/iZ/cO1A/R56k/02SH5oS2VRVoWNXt/PFqSrWazkuuNWQz1HM
         97gtOJjcSlgTvVBDFIoV3krzVL3f60u9Y8nHnCRI9K+iW0lHFljlYdMGHUfecHiiZhhl
         Qrqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697700413; x=1698305213; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ra9m1WM+9kxSXd/XNzt2vGNUvV4aiGnNAdcCVy1xiW0=;
        b=D5w7jdOeBCRKhhGTVjViwiIMsnea1FHxo/AJthY3tu2EWTjEO4NOLFGmBgkIiZv/hX
         9PVm6AEX04+pIl8cxNDZUjuvKdAcBjw9vGZY9hFBTTli2PZbIGSICLhkKT3wDOX1hjT+
         k5vlrx3WNgeV7IsO6EfVYYs+4B6Mv9Wh8w6QfdXbBHTWFlkoBrOXkeEEFADmbGk8ImX3
         bhSSvS9gmJ84OnE/I439IBEef7Im+aGlmtb9JM+pGQSpG4xFw2cSZMiE15jTyiAvBY0E
         4VvhVQT9ZzXOEo4JvlAHrQJABszd4SJ/c7YejKVdFZxeOjpb0ooRWu5DtVzBuMEwNuM5
         3j5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697700413; x=1698305213;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ra9m1WM+9kxSXd/XNzt2vGNUvV4aiGnNAdcCVy1xiW0=;
        b=LLBf4ww8sdOmnrzeG3zKGq9sx1PLT2Dis83U/UU7zzWvsCJPMYLBJmi4ahFDaNtGds
         TGH2Gsk4f+m9PS7FPfVeeYbUAiM4YBqKuzmRYtGB3jfpQSbx+opoLAKuMXTtQeYG6Gtj
         UnJHwziFxiDex7hGLJmq89ZAAvp85jED5worEMZ5f/POGorXx+xK9pGI6gUom1HXo8Ha
         IrMi3TB+PwpHsVOIBglD9cXZj/JYtXisksLy3yujNStrVvvVBjnNLKbfJPqGYkLtxtSw
         pTfBcjSYZtlUDwlv5NoWWwE9PSR1MeTFbZrzKCqg2koMEqfq9X0FlYOEViTIkZLC8T2i
         1NMg==
X-Gm-Message-State: AOJu0YyUdVCXtUsbBR1ZEMrt+EfBEKh18xngpavQSd9RKwb1qhHKMefY
	LcxwRBv59PMAosGhqxvgUxk=
X-Google-Smtp-Source: AGHT+IGzmYyWYC6LBburQxvcw0wZ/ws29qVFGaqXt4ZZFUkIpaM9Z/esinp2NALoljLzjiaoWKMJ/w==
X-Received: by 2002:a05:6870:7810:b0:1e9:b811:da13 with SMTP id hb16-20020a056870781000b001e9b811da13mr1975877oab.49.1697700413560;
        Thu, 19 Oct 2023 00:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:be8f:b0:1e9:8d46:4019 with SMTP id
 nx15-20020a056870be8f00b001e98d464019ls290944oab.2.-pod-prod-07-us; Thu, 19
 Oct 2023 00:26:52 -0700 (PDT)
X-Received: by 2002:a9d:6ac4:0:b0:6be:ffdd:efb9 with SMTP id m4-20020a9d6ac4000000b006beffddefb9mr1451583otq.32.1697700412645;
        Thu, 19 Oct 2023 00:26:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697700412; cv=none;
        d=google.com; s=arc-20160816;
        b=DhDVBdbuyyMQyQy8kpnTuLqjWceM9ZNJ0dWN+sKdTRHZJyulV+RptaH6XTNhrufe+K
         eVlqwnT4rpjPXy0F9ioTYcXh+uTt0hFH+JpX5LCJmfWu0+gfvQzoQtHIMto2Rd0mLm83
         2zbdFEy5WVyl7pUTNkxCwN1UzZDCLWiepMdF70CWd9eDG6EUNcsJEYcHXShut1D9IqU2
         3faBazR95Anevw71KipFtzmxBooBvEd2ODdKMHgvsaL9p4qRBJ+hg7NT87mBMrVWRCMT
         EiTxOPWxfbmMyh8DX1a0LDMZC88h6NO2K7380nxRLsvRxmai17TzRgBVDGVwddiTTvtq
         aV2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=i/xmajoZJ1tMSwShrYaGj6OyDi4UdsTn43+MHwZAZ4E=;
        fh=fhypw1/r/HG+aNTeYBk1rNVXIP/3EDL4naufRsDyMCM=;
        b=tqJwGkivVMERFO1ancokM/slfM+0CGvOym49N2+XH2b+wK13Fzd6zX6SbLfFvc62P/
         owc48EkeSKV8uz6KxdsKdBWfXEYNEarcnPvZxX+txW5ho08Oyx0ZmIAHTMjgnVc+Khlj
         XzByoDwct5XgP1ISYwSKSsV/d+XA8Ljl1WaR6iRz+MRuteB/4czMmJTqP2Gw2gGKuk8F
         neLKFxPTyM422bzkwHLlkRvZQKP43SeKm6CjK/iHo50TFcKcxELLX3d+DTK2hII2ib05
         m0N+gnn/0eBaKEWCtOB33e6YV2mn7OhZxZxcqqUtOEVFxxeIuEgtsXCMV2nBzBuKVmNr
         ELNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id bh10-20020a056830380a00b006c64ecd75f8si353049otb.5.2023.10.19.00.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Oct 2023 00:26:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4S9zjd6DXRz15NYZ;
	Thu, 19 Oct 2023 15:24:05 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Thu, 19 Oct 2023 15:26:49 +0800
Message-ID: <7ab8839b-8f88-406e-b6e1-2c69c8967d4e@huawei.com>
Date: Thu, 19 Oct 2023 15:26:48 +0800
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
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <ZTDJ8t9ug3Q6E8GG@pc636>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm100001.china.huawei.com (7.185.36.93)
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



On 2023/10/19 14:17, Uladzislau Rezki wrote:
> On Thu, Oct 19, 2023 at 09:40:10AM +0800, Kefeng Wang wrote:
>>
>>
>> On 2023/10/19 0:37, Marco Elver wrote:
>>> On Wed, 18 Oct 2023 at 16:16, 'Kefeng Wang' via kasan-dev
>>> <kasan-dev@googlegroups.com> wrote:
>>>>
>>>> The issue is easy to reproduced with large vmalloc, kindly ping...
>>>>
>>>> On 2023/9/15 8:58, Kefeng Wang wrote:
>>>>> Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.
>>>>>
>>>>> On 2023/9/6 20:42, Kefeng Wang wrote:
>>>>>> This is a RFC, even patch3 is a hack to fix the softlock issue when
>>>>>> populate or depopulate pte with large region, looking forward to you=
r
>>>>>> reply and advise, thanks.
>>>>>
>>>>> Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C
>>>>>
>>>>> [    C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [insmod:45=
8]
>>>>> [    C3] Modules linked in: test(OE+)
>>>>> [    C3] irq event stamp: 320776
>>>>> [    C3] hardirqs last  enabled at (320775): [<ffff8000815a0c98>]
>>>>> _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>> [    C3] hardirqs last disabled at (320776): [<ffff8000815816e0>]
>>>>> el1_interrupt+0x38/0xa8
>>>>> [    C3] softirqs last  enabled at (318174): [<ffff800080040ba8>]
>>>>> __do_softirq+0x658/0x7ac
>>>>> [    C3] softirqs last disabled at (318169): [<ffff800080047fd8>]
>>>>> ____do_softirq+0x18/0x30
>>>>> [    C3] CPU: 3 PID: 458 Comm: insmod Tainted: G           OE 6.5.0+ =
#595
>>>>> [    C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/2=
015
>>>>> [    C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=
=3D--)
>>>>> [    C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>> [    C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>> [    C3] sp : ffff800093386d70
>>>>> [    C3] x29: ffff800093386d70 x28: 0000000000000801 x27: ffff0007fff=
fa9c0
>>>>> [    C3] x26: 0000000000000000 x25: 000000000000003f x24: fffffc00043=
53708
>>>>> [    C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: 00000000000=
00000
>>>>> [    C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 00000000000=
00000
>>>>> [    C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: ffff8000802=
4ec60
>>>>> [    C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: ffff6000fff=
ff5f9
>>>>> [    C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fff=
ff5f8
>>>>> [    C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff8000000=
00000
>>>>> [    C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff7000126=
70d70
>>>>> [    C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : 00000000000=
4e507
>>>>> [    C3] Call trace:
>>>>> [    C3]  _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>> [    C3]  rmqueue_bulk+0x434/0x6b8
>>>>> [    C3]  get_page_from_freelist+0xdd4/0x1680
>>>>> [    C3]  __alloc_pages+0x244/0x508
>>>>> [    C3]  alloc_pages+0xf0/0x218
>>>>> [    C3]  __get_free_pages+0x1c/0x50
>>>>> [    C3]  kasan_populate_vmalloc_pte+0x30/0x188
>>>>> [    C3]  __apply_to_page_range+0x3ec/0x650
>>>>> [    C3]  apply_to_page_range+0x1c/0x30
>>>>> [    C3]  kasan_populate_vmalloc+0x60/0x70
>>>>> [    C3]  alloc_vmap_area.part.67+0x328/0xe50
>>>>> [    C3]  alloc_vmap_area+0x4c/0x78
>>>>> [    C3]  __get_vm_area_node.constprop.76+0x130/0x240
>>>>> [    C3]  __vmalloc_node_range+0x12c/0x340
>>>>> [    C3]  __vmalloc_node+0x8c/0xb0
>>>>> [    C3]  vmalloc+0x2c/0x40
>>>>> [    C3]  show_mem_init+0x1c/0xff8 [test]
>>>>> [    C3]  do_one_initcall+0xe4/0x500
>>>>> [    C3]  do_init_module+0x100/0x358
>>>>> [    C3]  load_module+0x2e64/0x2fc8
>>>>> [    C3]  init_module_from_file+0xec/0x148
>>>>> [    C3]  idempotent_init_module+0x278/0x380
>>>>> [    C3]  __arm64_sys_finit_module+0x88/0xf8
>>>>> [    C3]  invoke_syscall+0x64/0x188
>>>>> [    C3]  el0_svc_common.constprop.1+0xec/0x198
>>>>> [    C3]  do_el0_svc+0x48/0xc8
>>>>> [    C3]  el0_svc+0x3c/0xe8
>>>>> [    C3]  el0t_64_sync_handler+0xa0/0xc8
>>>>> [    C3]  el0t_64_sync+0x188/0x190
>>>>>
>>>>> and for depopuldate pte=EF=BC=8C
>>>>>
>>>>> [    C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kworker/6=
:1:59]
>>>>> [    C6] Modules linked in: test(OE+)
>>>>> [    C6] irq event stamp: 39458
>>>>> [    C6] hardirqs last  enabled at (39457): [<ffff8000815a0c98>]
>>>>> _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>> [    C6] hardirqs last disabled at (39458): [<ffff8000815816e0>]
>>>>> el1_interrupt+0x38/0xa8
>>>>> [    C6] softirqs last  enabled at (39420): [<ffff800080040ba8>]
>>>>> __do_softirq+0x658/0x7ac
>>>>> [    C6] softirqs last disabled at (39415): [<ffff800080047fd8>]
>>>>> ____do_softirq+0x18/0x30
>>>>> [    C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G           OEL
>>>>> 6.5.0+ #595
>>>>> [    C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/2=
015
>>>>> [    C6] Workqueue: events drain_vmap_area_work
>>>>> [    C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=
=3D--)
>>>>> [    C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>> [    C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
>>>>> [    C6] sp : ffff80008fe676b0
>>>>> [    C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: ffff000edf5=
dfa80
>>>>> [    C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: 00000000000=
00006
>>>>> [    C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: 00000000000=
00006
>>>>> [    C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 00000000000=
00000
>>>>> [    C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: ffff8000805=
c11b0
>>>>> [    C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: ffff6000fff=
ff5f9
>>>>> [    C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fff=
ff5f8
>>>>> [    C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff8000000=
00000
>>>>> [    C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff700011f=
cce98
>>>>> [    C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : 00000000000=
09a21
>>>>> [    C6] Call trace:
>>>>> [    C6]  _raw_spin_unlock_irqrestore+0x50/0xb8
>>>>> [    C6]  free_pcppages_bulk+0x2bc/0x3e0
>>>>> [    C6]  free_unref_page_commit+0x1fc/0x290
>>>>> [    C6]  free_unref_page+0x184/0x250
>>>>> [    C6]  __free_pages+0x154/0x1a0
>>>>> [    C6]  free_pages+0x88/0xb0
>>>>> [    C6]  kasan_depopulate_vmalloc_pte+0x58/0x80
>>>>> [    C6]  __apply_to_page_range+0x3ec/0x650
>>>>> [    C6]  apply_to_existing_page_range+0x1c/0x30
>>>>> [    C6]  kasan_release_vmalloc+0xa4/0x118
>>>>> [    C6]  __purge_vmap_area_lazy+0x4f4/0xe30
>>>>> [    C6]  drain_vmap_area_work+0x60/0xc0
>>>>> [    C6]  process_one_work+0x4cc/0xa38
>>>>> [    C6]  worker_thread+0x240/0x638
>>>>> [    C6]  kthread+0x1c8/0x1e0
>>>>> [    C6]  ret_from_fork+0x10/0x20
>>>>>
>>>>>
>>>>>
>>>>>>
>>>>>> Kefeng Wang (3):
>>>>>>      mm: kasan: shadow: add cond_resched() in kasan_populate_vmalloc=
_pte()
>>>>>>      mm: kasan: shadow: move free_page() out of page table lock
>>>>>>      mm: kasan: shadow: HACK add cond_resched_lock() in
>>>>>>        kasan_depopulate_vmalloc_pte()
>>>
>>> The first 2 patches look ok, but yeah, the last is a hack. I also
>>> don't have any better suggestions, only more questions.
>>
>> Thanks Marco, maybe we could convert free_vmap_area_lock from spinlock t=
o
>> mutex lock only if KASAN enabled?
>>
> I do not think it is a good suggestion. Could you please clarify the
> reason of such conversion?

See Call Trace of softlock, when map/unmap the vmalloc buf, the kasan=20
will populate and depopulate vmalloc pte, those will spend more time=20
than no-kasan kernel, for unmap, and there is already a=20
cond_resched_lock() in __purge_vmap_area_lazy(), but with more time=20
consumed under spinlock(free_vmap_area_lock), and we couldn't add=20
cond_resched_lock in kasan_depopulate_vmalloc_pte(), so if spin lock=20
converted to mutex lock, we could add a cond_resched into kasan=20
depopulate, this is why make such conversion if kasan enabled, but this
conversion maybe not correct, any better solution?

>=20
>>>
>>> Does this only happen on arm64?
>>
>> Our test case run on arm64 qemu(host is x86), so it run much more slower
>> than real board.
>>> Do you have a minimal reproducer you can share?
>> Here is the code in test driver,
>>
>> void *buf =3D vmalloc(40UL << 30);
>> vfree(buf);
>>
> What is a test driver? Why do you need 42G of memmory, for which purpose?

This is just to accelerate reproduction of above issue, the main reason=20
of the issue is too much time spent during kasan_populate_vmalloc() and
kasan_release_vmalloc().

Thanks.

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
kasan-dev/7ab8839b-8f88-406e-b6e1-2c69c8967d4e%40huawei.com.
