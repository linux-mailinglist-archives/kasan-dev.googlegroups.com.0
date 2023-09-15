Return-Path: <kasan-dev+bncBCRKFI7J2AJRBLOYR2UAMGQEQ3M3BUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CD3F7A12A4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 02:58:22 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-770538a2946sf205763385a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 17:58:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694739501; cv=pass;
        d=google.com; s=arc-20160816;
        b=knTd0oqAtAYb44ohaoBLxtHfj4LP1agMZjcVrQxWyMfkjoMyybU1sTSpdTTkIZRyHJ
         xGuhzPQkmHHgCUXxAwXPoiXbYtFBUylD9D75osSlOtoDBXcV40JZJOvBM0/JMSWU5OcL
         f8CeMb6VZph13cq8/X3MOzS8zRdYWjlVt93lNZ17kmVRgRSh4PEYpirYFxiQSC5PDV+F
         /4zJfe6iDXP7hp1P+f+M3veHkOU9iV1Wpf5MkmyTfusntUFIwiz5bwiFoVTe8V+xTN52
         JKDVeZxEkkll8uaR1w/I9M1eAXEzgl5CjoRuH2WfxEc+xc9qLqCe5y5nV/7/mBnohrdH
         GxIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:to:content-language:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=LrmWlQ4HuzJY3kIHXRY5bYLKak40V6JE8S484PYmEUI=;
        fh=IgWjnRjx/pelTxM5QYMkMq87TSCzEaYU6LtbrTlFROI=;
        b=cl1oYU/Jl9ISHEKmpYBZzS3Ihdxo3dl+37nNTr7y6BzPuIVRg3AF1pLcBZR2KqX/K/
         r0p0Vt+z1qvJSWM0fLmSTRpu1gjZQ8rOERObVLmcsX1NAjJ1d1PbIzFF5BUJcF/qmA9j
         JtBNwvdxJBL89fEqKf6wI9SkPal7aMHL/SiL77aK5egd0JhIPmr+PT6VjpiDYxz4Fn49
         El7f43b/YaVh5C0Kxbr95ObBmCardSs48sGZgGjd5xZJqYN4H/R5knS11KFJtNuJ2Kzc
         2dwSuQxOI+OtSs32E9ezVCU2qmfLrGyLM/newqwMQ9Hhfpft7CNYoMJ1Z3k4YerXu0h9
         SS4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694739501; x=1695344301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LrmWlQ4HuzJY3kIHXRY5bYLKak40V6JE8S484PYmEUI=;
        b=dI4faR8QMi2GWZGXCqW3b3e7wAU6pSCX1WYbURs3Ip1PI94jfP/NO6IMAyzOALKsg8
         zbxj17TZO2LzQM14euo/NnVktNGLRfL3yjEyKoYGo+R8ufK6TA1GAgNTKcoIb+UnLNOB
         R1I5hgwstLqadh3EW/rXN5MEKBwPMLInMktzz4GNDdkM+0iqpRgVwjxv3kTimhEFoB7v
         AEtVBSoOoISgcwnJ1jP+72M9XIwYYAJGYJ4aV7panG7qBZnIo0abaizPd1pBvyJSom+d
         QTIB9cSdNMl3l3aKEVieaUC5vGQXcF6imA5vLWDBjqTHNYkHXohYLPUC2G9GVJi2e+L2
         tDpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694739501; x=1695344301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LrmWlQ4HuzJY3kIHXRY5bYLKak40V6JE8S484PYmEUI=;
        b=w/MDioZLv+ds1qjl6kPOB1rzl2lF2eRGB8+12x9awmtfbq10beafP+jW8e9Pp5r00P
         TEiCYYZyJUj6H2ho1yDtZai0WRTYrQtq9sLy1meKZ0SkbbKEC9+UD+0K1eX3slU5puT9
         G/h1XmLX7+nrFZ1asTTx8e7NzsK9ZFS2Eh8UH3oL/uwzzYzAVCOa47ZWzWY8+nMMI6ut
         Bwd0Tq/RDxEwY9ROfp5ieTlOPvSugGJ1IA2o0c9rLN3UtDQgZteR7xKQUTaJtQnXI76Y
         SD4n29/V1mc2GLXNRACJIZdbxtWZ6WzTKNOUShnkXKtBY0HjIdZqVeTlrZAeCh97LL2+
         +DYA==
X-Gm-Message-State: AOJu0YyTLd0/XWKtggziYu+xkJ3Q4RQE5BikdMEn/6iFOVKJ2Ej2+kNK
	aTLaOUqVOmmcvk6EOiOxTBA=
X-Google-Smtp-Source: AGHT+IGxhdEkqbaLxv3qHmMpTUSFPWY7lF0ZJS3hWDkyQ0LUlWzcSQYphIDY4kFgSPV3ePMUuGlJtg==
X-Received: by 2002:a05:620a:1a8c:b0:773:2757:ea9f with SMTP id bl12-20020a05620a1a8c00b007732757ea9fmr118090qkb.53.1694739501197;
        Thu, 14 Sep 2023 17:58:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7299:0:b0:412:c44:e465 with SMTP id v25-20020ac87299000000b004120c44e465ls1495591qto.0.-pod-prod-01-us;
 Thu, 14 Sep 2023 17:58:20 -0700 (PDT)
X-Received: by 2002:a1f:cd03:0:b0:495:ceb6:2df8 with SMTP id d3-20020a1fcd03000000b00495ceb62df8mr427554vkg.0.1694739500560;
        Thu, 14 Sep 2023 17:58:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694739500; cv=none;
        d=google.com; s=arc-20160816;
        b=S/5QbunPLror16owSsFSpe1zqPDq88q0rwMY0mvr9zqT/ZtgxipIVDvpZDwaYgvGSQ
         KMWmVRC52RaNt+xSdRP4afDRurV4a8SudMo40gvF00/C24ZwLNOoXepguIhOQIAdAkM8
         GvZ2kiZZmfkT0Zr6tg/U6GiJMyHDPq69uhq0FSQMpPSqH30Ykrg3dUu65z01BUJUPKwR
         isRrfdylfvWThgDUs07Cj+ySDbsziingnUwF/IvOagDlr1p+TlE3IYtWYztRMFKBnD7A
         fhW6NWmt+hbLwWHEa+bax49tEV9QiEZGaon/YN9RMyx8B+7DcDS7Q4oEqHanAargfNvY
         BL+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=A6amhPw/ShqMQ4jyKXEiLcD47a1tFUZBnB70blhG43Q=;
        fh=IgWjnRjx/pelTxM5QYMkMq87TSCzEaYU6LtbrTlFROI=;
        b=Key8gLNp2EOVd/YJWJrEjmG7S/rXGqYbBVygrSSqaWg0oC6YNMMqq4MTJHpRTs8ktm
         qrDX0MqCTOZMOwEJb6f49Ib3I/2PjP9Xg4LScBwxj1s6X7p1YHUOjWLRCJwj28Refqqc
         2DozLSnx4KrtqE3o5eKnuLIzs2zHOsVmaG73pRTLliJKc5ch1RctydLNgdRevIEuxB8Q
         /Ad59e8L85rw6r3jpfK57S4kDeiL7Q+XjtPBRGXaM8b2dMAFGACifeZPySfi6uvj2BNU
         6oBNrEtx2i/yJ/fP70oweknmY/ub7QV5Skn0ndX5CMW5C4N5P7Bzwv2PDlkWNcSgyPoh
         nmKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id i7-20020a056122208700b0049362af6c50si252686vkd.5.2023.09.14.17.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Sep 2023 17:58:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.57])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4Rmwh81V7xzMlZw;
	Fri, 15 Sep 2023 08:54:48 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Fri, 15 Sep 2023 08:58:16 +0800
Message-ID: <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com>
Date: Fri, 15 Sep 2023 08:58:16 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or
 depopulate pte
Content-Language: en-US
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>, Lorenzo Stoakes <lstoakes@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm100001.china.huawei.com (7.185.36.93)
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

Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.

On 2023/9/6 20:42, Kefeng Wang wrote:
> This is a RFC, even patch3 is a hack to fix the softlock issue when
> populate or depopulate pte with large region, looking forward to your
> reply and advise, thanks.

Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C

[    C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [insmod:458]
[    C3] Modules linked in: test(OE+)
[    C3] irq event stamp: 320776
[    C3] hardirqs last  enabled at (320775): [<ffff8000815a0c98>]=20
_raw_spin_unlock_irqrestore+0x98/0xb8
[    C3] hardirqs last disabled at (320776): [<ffff8000815816e0>]=20
el1_interrupt+0x38/0xa8
[    C3] softirqs last  enabled at (318174): [<ffff800080040ba8>]=20
__do_softirq+0x658/0x7ac
[    C3] softirqs last disabled at (318169): [<ffff800080047fd8>]=20
____do_softirq+0x18/0x30
[    C3] CPU: 3 PID: 458 Comm: insmod Tainted: G           OE=20
6.5.0+ #595
[    C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/2015
[    C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=3D--)
[    C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
[    C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
[    C3] sp : ffff800093386d70
[    C3] x29: ffff800093386d70 x28: 0000000000000801 x27: ffff0007ffffa9c0
[    C3] x26: 0000000000000000 x25: 000000000000003f x24: fffffc0004353708
[    C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: 0000000000000000
[    C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 0000000000000000
[    C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: ffff80008024ec60
[    C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: ffff6000fffff5f9
[    C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fffff5f8
[    C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff800000000000
[    C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff700012670d70
[    C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : 000000000004e507
[    C3] Call trace:
[    C3]  _raw_spin_unlock_irqrestore+0x50/0xb8
[    C3]  rmqueue_bulk+0x434/0x6b8
[    C3]  get_page_from_freelist+0xdd4/0x1680
[    C3]  __alloc_pages+0x244/0x508
[    C3]  alloc_pages+0xf0/0x218
[    C3]  __get_free_pages+0x1c/0x50
[    C3]  kasan_populate_vmalloc_pte+0x30/0x188
[    C3]  __apply_to_page_range+0x3ec/0x650
[    C3]  apply_to_page_range+0x1c/0x30
[    C3]  kasan_populate_vmalloc+0x60/0x70
[    C3]  alloc_vmap_area.part.67+0x328/0xe50
[    C3]  alloc_vmap_area+0x4c/0x78
[    C3]  __get_vm_area_node.constprop.76+0x130/0x240
[    C3]  __vmalloc_node_range+0x12c/0x340
[    C3]  __vmalloc_node+0x8c/0xb0
[    C3]  vmalloc+0x2c/0x40
[    C3]  show_mem_init+0x1c/0xff8 [test]
[    C3]  do_one_initcall+0xe4/0x500
[    C3]  do_init_module+0x100/0x358
[    C3]  load_module+0x2e64/0x2fc8
[    C3]  init_module_from_file+0xec/0x148
[    C3]  idempotent_init_module+0x278/0x380
[    C3]  __arm64_sys_finit_module+0x88/0xf8
[    C3]  invoke_syscall+0x64/0x188
[    C3]  el0_svc_common.constprop.1+0xec/0x198
[    C3]  do_el0_svc+0x48/0xc8
[    C3]  el0_svc+0x3c/0xe8
[    C3]  el0t_64_sync_handler+0xa0/0xc8
[    C3]  el0t_64_sync+0x188/0x190

and for depopuldate pte=EF=BC=8C

[    C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kworker/6:1:59]
[    C6] Modules linked in: test(OE+)
[    C6] irq event stamp: 39458
[    C6] hardirqs last  enabled at (39457): [<ffff8000815a0c98>]=20
_raw_spin_unlock_irqrestore+0x98/0xb8
[    C6] hardirqs last disabled at (39458): [<ffff8000815816e0>]=20
el1_interrupt+0x38/0xa8
[    C6] softirqs last  enabled at (39420): [<ffff800080040ba8>]=20
__do_softirq+0x658/0x7ac
[    C6] softirqs last disabled at (39415): [<ffff800080047fd8>]=20
____do_softirq+0x18/0x30
[    C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G           OEL=20
6.5.0+ #595
[    C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/2015
[    C6] Workqueue: events drain_vmap_area_work
[    C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=3D--)
[    C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
[    C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
[    C6] sp : ffff80008fe676b0
[    C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: ffff000edf5dfa80
[    C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: 0000000000000006
[    C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: 0000000000000006
[    C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 0000000000000000
[    C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: ffff8000805c11b0
[    C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: ffff6000fffff5f9
[    C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fffff5f8
[    C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff800000000000
[    C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff700011fcce98
[    C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : 0000000000009a21
[    C6] Call trace:
[    C6]  _raw_spin_unlock_irqrestore+0x50/0xb8
[    C6]  free_pcppages_bulk+0x2bc/0x3e0
[    C6]  free_unref_page_commit+0x1fc/0x290
[    C6]  free_unref_page+0x184/0x250
[    C6]  __free_pages+0x154/0x1a0
[    C6]  free_pages+0x88/0xb0
[    C6]  kasan_depopulate_vmalloc_pte+0x58/0x80
[    C6]  __apply_to_page_range+0x3ec/0x650
[    C6]  apply_to_existing_page_range+0x1c/0x30
[    C6]  kasan_release_vmalloc+0xa4/0x118
[    C6]  __purge_vmap_area_lazy+0x4f4/0xe30
[    C6]  drain_vmap_area_work+0x60/0xc0
[    C6]  process_one_work+0x4cc/0xa38
[    C6]  worker_thread+0x240/0x638
[    C6]  kthread+0x1c8/0x1e0
[    C6]  ret_from_fork+0x10/0x20



>=20
> Kefeng Wang (3):
>    mm: kasan: shadow: add cond_resched() in kasan_populate_vmalloc_pte()
>    mm: kasan: shadow: move free_page() out of page table lock
>    mm: kasan: shadow: HACK add cond_resched_lock() in
>      kasan_depopulate_vmalloc_pte()
>=20
>   include/linux/kasan.h |  9 ++++++---
>   mm/kasan/shadow.c     | 20 +++++++++++++-------
>   mm/vmalloc.c          |  7 ++++---
>   3 files changed, 23 insertions(+), 13 deletions(-)
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4e2e075f-b74c-4daf-bf1a-f83fced742c4%40huawei.com.
