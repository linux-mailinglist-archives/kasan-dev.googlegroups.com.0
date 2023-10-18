Return-Path: <kasan-dev+bncBCRKFI7J2AJRBSGRX6UQMGQEJG2C2OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 743BC7CDF15
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 16:16:42 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-35760da0842sf28685535ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 07:16:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697638601; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHrovIRj/oeFF43Gk3kAz2V98MY6yDx/Fr5ZLsQSJiLgvFcyafuFoXPajv36BMdJ8u
         AztgPlyhoXF9bnfdP4njxms3rqMMavPcbg7U//xOL4shU2X8fow6XflI2IOama9C9Nsm
         iNnYpUwGoplB/Rrebhb2Xfa5Y/3T09vFf4ne3Hy1fVXB+xjWnTf+cPxPWbe50rCrMMwB
         hu6iz0Qh6WmzjFjWcBBqOLe8OO+tlw6hp+7/iYcyejNqmYS9x8JfeG/I63jeXgTBSD9L
         zhDH3I2OPBOwlHcLG0xCwPu+JVbDV80KGRey6XUvgY/uNr4vAOHuoPOn0CI9TSVRUtxn
         Gm1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:references:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=A7wruSdijyS2GwkyS4GOv3W6fRVVqKP+6DFB+cdyUdI=;
        fh=IgWjnRjx/pelTxM5QYMkMq87TSCzEaYU6LtbrTlFROI=;
        b=cBUw1ltFZMesLoz3Gz7ijTrIcPMLjrMA++MipU0b66ImjqPwHFZnlK3BM4LHTgUyeo
         hA3SpVbIWo6Y0KXsHh1ock6osvmKF3pzbMD666m45h83dn4Ctvp64RWgNP9ldeCAVsTy
         SkVz2F5smzN/nWOUwPVSG0VP5ppi9E3j+JGaX15RbEeE0c9qqmf/0piJ9LO04yg9Bu3p
         qi6kCSp3aKs2UANRHl/8x0ZatQQky1QdtsfKj3zH2fzinUTXOyJ4N/A5MJ9q+20prWVG
         qU+z4aMUBMtuWXrHFXxiv5ncsoTdIVmvDdyBM4m5bw7xN8DpfwaCBBWtYJDS/loJBSBI
         z9Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697638601; x=1698243401; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A7wruSdijyS2GwkyS4GOv3W6fRVVqKP+6DFB+cdyUdI=;
        b=A1BGGBmCL9QkGNAAmLeNwBM5a4SqVBUT82tLmokKbBPs4OFjD1Pecer/mF1fzvAqeE
         79S54L/FHzu//GMdrzUU/I0GzjWPj1QzCeZq3MbHtGFLK5cmiDGY8HSnNY7BaqjBx9dP
         r+blajn9BsBa54/nwm5bWv3T5BlvELEeOuhtgheTYS/3o8YK8LQn7mH3MI0k4JGHYBBM
         INt7lBhIfd9dG85f0dRBAJhPzr/y0vP8l8eQ6CL6iL0NAVmG5YuMrzcUK9x2Ou6c1u9l
         XrVDqqQ4Ndw81aikYQQmwWg3/iBVfw5qJJankOteTgeAR1DfLX2q7wx18qmaAtd0GSsX
         m/tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697638601; x=1698243401;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:references:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A7wruSdijyS2GwkyS4GOv3W6fRVVqKP+6DFB+cdyUdI=;
        b=IKDb63bGk6DsH8ZwbVIUg+f0cTyYir92TTe/PaCRX2kOXMn+lQIds/znSFO6PBD92V
         Toort1QXNVEwisB8o1cdJuOuj9HnuY7+A2BSPLbRqJJOlzhZid0SsFLWlQ8bAoGXpYS7
         0Wt/KnprUl13AYS+TD/32USmRHOTe3AE4NkD9RVxQHGFfbFyqQYTnm2kNY/mqpaQGFmD
         cxZDT60jqLUi0T58neHGhHk1n52o7vf9pUe73n1/HxMSAa9XwD4pyldZILWZEOZjtpTG
         v9da/eSuN47laV4jIQ/EEK6SN0XqeU9V3S2PoPg2OnlAOBhOvr27wll0mYpvGEmJ9iPw
         LzHw==
X-Gm-Message-State: AOJu0YwlxvV1fOu4a4H+6qsnQ18Edhsjwafe3HxT2W8uPBNRpMdINmPj
	JdnfV7Jc8rNubI6BPVzQAUk=
X-Google-Smtp-Source: AGHT+IEeSyAMPyg9t4linnGAlxl0qwlhysF13UqvDMkxW8y1tUjU2uI8qQIbrz+C1ElIOXo6fUjKSQ==
X-Received: by 2002:a05:6e02:145:b0:351:3546:dabe with SMTP id j5-20020a056e02014500b003513546dabemr4723995ilr.0.1697638601051;
        Wed, 18 Oct 2023 07:16:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ef3:b0:357:a588:bfde with SMTP id
 j19-20020a056e020ef300b00357a588bfdels225805ilk.1.-pod-prod-00-us; Wed, 18
 Oct 2023 07:16:40 -0700 (PDT)
X-Received: by 2002:a05:6e02:1aad:b0:357:a853:dbd with SMTP id l13-20020a056e021aad00b00357a8530dbdmr1014106ilv.13.1697638600330;
        Wed, 18 Oct 2023 07:16:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697638600; cv=none;
        d=google.com; s=arc-20160816;
        b=fmlO6lxeiQ/1+7FLRJHLqM96pag3JBxmuhNleIM0EsS9HxS2p7TNED4ESpl4hElCfO
         F/cJyHjGefiZYf6/+CfZ4kgmqtAOdp3vyvx1hVhB+SvquCbZilrR3m++bL7yZZeRkHAe
         VoMmPeDXo4Rcdjx4DA9NpUOvsMNnC0CPrKNrF+jvQ8tb4Vx4ps1XkEF7MJrTaKaVlGOx
         1JFUWDJCe8UnOa+XdVebmuVZ0NCDepgCUwkge6NEu9bXyfBfeeHdRsLbBy2Cy+pmtBn+
         9EKemkCkL3byYk8GJLlKzZaZOVXqtsVMPyKMBLRZdlP+mMGQPFrTZBnV6hHip06lgRyR
         KVRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:to:from
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=ydIkvbS+/6F0j1VegN2jh0ivkiZtXhAF4G/oPjr5WG0=;
        fh=IgWjnRjx/pelTxM5QYMkMq87TSCzEaYU6LtbrTlFROI=;
        b=zLaUSu3YWTokuevevLR/pJNQiFkxF+hY5aTjs5Q1EjTSpoHCrz/BsZEn4PP0MZaQon
         TVCLSljNofmm0U02JrgOYHLAatlU7SyMxU4G6hL3wRPJcZVRg7qzK/qWB2Y0xeuEaZbO
         6RNKONRIeVXlhJC7qUi4b9UWuqDQtQ8Pa3nbQO0RSUcZRa53KFUpJ/d0WNmTS5JThgdS
         mku23S7J21EYASstc4yjXOTeLrbrYhBciqWbarMpMoUs+uQy9VSJNRn8h3itmVZLgFIS
         AK0dCUhosz55HFZLKC/VlA7WghechsWJWaKNbrCjzSTctEuWqjRxmiSlpCBwj95QSuNA
         3xzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id a8-20020a926608000000b003512778fb27si363934ilc.2.2023.10.18.07.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Oct 2023 07:16:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.57])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4S9Xpk2JxnzLp5f;
	Wed, 18 Oct 2023 22:11:58 +0800 (CST)
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Wed, 18 Oct 2023 22:16:03 +0800
Message-ID: <dd39cb3e-b184-407d-b74f-5b90a7983c99@huawei.com>
Date: Wed, 18 Oct 2023 22:16:02 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or
 depopulate pte
Content-Language: en-US
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>, Lorenzo Stoakes <lstoakes@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
 <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com>
In-Reply-To: <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
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

The issue is easy to reproduced with large vmalloc, kindly ping...

On 2023/9/15 8:58, Kefeng Wang wrote:
> Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.
>=20
> On 2023/9/6 20:42, Kefeng Wang wrote:
>> This is a RFC, even patch3 is a hack to fix the softlock issue when
>> populate or depopulate pte with large region, looking forward to your
>> reply and advise, thanks.
>=20
> Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C
>=20
> [=C2=A0=C2=A0=C2=A0 C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s!=
 [insmod:458]
> [=C2=A0=C2=A0=C2=A0 C3] Modules linked in: test(OE+)
> [=C2=A0=C2=A0=C2=A0 C3] irq event stamp: 320776
> [=C2=A0=C2=A0=C2=A0 C3] hardirqs last=C2=A0 enabled at (320775): [<ffff80=
00815a0c98>]=20
> _raw_spin_unlock_irqrestore+0x98/0xb8
> [=C2=A0=C2=A0=C2=A0 C3] hardirqs last disabled at (320776): [<ffff8000815=
816e0>]=20
> el1_interrupt+0x38/0xa8
> [=C2=A0=C2=A0=C2=A0 C3] softirqs last=C2=A0 enabled at (318174): [<ffff80=
0080040ba8>]=20
> __do_softirq+0x658/0x7ac
> [=C2=A0=C2=A0=C2=A0 C3] softirqs last disabled at (318169): [<ffff8000800=
47fd8>]=20
> ____do_softirq+0x18/0x30
> [=C2=A0=C2=A0=C2=A0 C3] CPU: 3 PID: 458 Comm: insmod Tainted: G=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 OE 6.5.0+ #595
> [=C2=A0=C2=A0=C2=A0 C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.=
0.0 02/06/2015
> [=C2=A0=C2=A0=C2=A0 C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -=
SSBS BTYPE=3D--)
> [=C2=A0=C2=A0=C2=A0 C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> [=C2=A0=C2=A0=C2=A0 C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> [=C2=A0=C2=A0=C2=A0 C3] sp : ffff800093386d70
> [=C2=A0=C2=A0=C2=A0 C3] x29: ffff800093386d70 x28: 0000000000000801 x27: =
ffff0007ffffa9c0
> [=C2=A0=C2=A0=C2=A0 C3] x26: 0000000000000000 x25: 000000000000003f x24: =
fffffc0004353708
> [=C2=A0=C2=A0=C2=A0 C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: =
0000000000000000
> [=C2=A0=C2=A0=C2=A0 C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: =
0000000000000000
> [=C2=A0=C2=A0=C2=A0 C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: =
ffff80008024ec60
> [=C2=A0=C2=A0=C2=A0 C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: =
ffff6000fffff5f9
> [=C2=A0=C2=A0=C2=A0 C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : =
1fffe000fffff5f8
> [=C2=A0=C2=A0=C2=A0 C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : =
dfff800000000000
> [=C2=A0=C2=A0=C2=A0 C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : =
ffff700012670d70
> [=C2=A0=C2=A0=C2=A0 C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : =
000000000004e507
> [=C2=A0=C2=A0=C2=A0 C3] Call trace:
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 _raw_spin_unlock_irqrestore+0x50/0xb8
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 rmqueue_bulk+0x434/0x6b8
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 get_page_from_freelist+0xdd4/0x1680
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 __alloc_pages+0x244/0x508
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 alloc_pages+0xf0/0x218
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 __get_free_pages+0x1c/0x50
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 kasan_populate_vmalloc_pte+0x30/0x188
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 __apply_to_page_range+0x3ec/0x650
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 apply_to_page_range+0x1c/0x30
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 kasan_populate_vmalloc+0x60/0x70
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 alloc_vmap_area.part.67+0x328/0xe50
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 alloc_vmap_area+0x4c/0x78
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 __get_vm_area_node.constprop.76+0x130/0x240
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 __vmalloc_node_range+0x12c/0x340
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 __vmalloc_node+0x8c/0xb0
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 vmalloc+0x2c/0x40
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 show_mem_init+0x1c/0xff8 [test]
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 do_one_initcall+0xe4/0x500
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 do_init_module+0x100/0x358
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 load_module+0x2e64/0x2fc8
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 init_module_from_file+0xec/0x148
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 idempotent_init_module+0x278/0x380
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 __arm64_sys_finit_module+0x88/0xf8
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 invoke_syscall+0x64/0x188
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 el0_svc_common.constprop.1+0xec/0x198
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 do_el0_svc+0x48/0xc8
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 el0_svc+0x3c/0xe8
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 el0t_64_sync_handler+0xa0/0xc8
> [=C2=A0=C2=A0=C2=A0 C3]=C2=A0 el0t_64_sync+0x188/0x190
>=20
> and for depopuldate pte=EF=BC=8C
>=20
> [=C2=A0=C2=A0=C2=A0 C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s!=
 [kworker/6:1:59]
> [=C2=A0=C2=A0=C2=A0 C6] Modules linked in: test(OE+)
> [=C2=A0=C2=A0=C2=A0 C6] irq event stamp: 39458
> [=C2=A0=C2=A0=C2=A0 C6] hardirqs last=C2=A0 enabled at (39457): [<ffff800=
0815a0c98>]=20
> _raw_spin_unlock_irqrestore+0x98/0xb8
> [=C2=A0=C2=A0=C2=A0 C6] hardirqs last disabled at (39458): [<ffff80008158=
16e0>]=20
> el1_interrupt+0x38/0xa8
> [=C2=A0=C2=A0=C2=A0 C6] softirqs last=C2=A0 enabled at (39420): [<ffff800=
080040ba8>]=20
> __do_softirq+0x658/0x7ac
> [=C2=A0=C2=A0=C2=A0 C6] softirqs last disabled at (39415): [<ffff80008004=
7fd8>]=20
> ____do_softirq+0x18/0x30
> [=C2=A0=C2=A0=C2=A0 C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 OEL=20
> 6.5.0+ #595
> [=C2=A0=C2=A0=C2=A0 C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.=
0.0 02/06/2015
> [=C2=A0=C2=A0=C2=A0 C6] Workqueue: events drain_vmap_area_work
> [=C2=A0=C2=A0=C2=A0 C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -=
SSBS BTYPE=3D--)
> [=C2=A0=C2=A0=C2=A0 C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> [=C2=A0=C2=A0=C2=A0 C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> [=C2=A0=C2=A0=C2=A0 C6] sp : ffff80008fe676b0
> [=C2=A0=C2=A0=C2=A0 C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: =
ffff000edf5dfa80
> [=C2=A0=C2=A0=C2=A0 C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: =
0000000000000006
> [=C2=A0=C2=A0=C2=A0 C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: =
0000000000000006
> [=C2=A0=C2=A0=C2=A0 C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: =
0000000000000000
> [=C2=A0=C2=A0=C2=A0 C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: =
ffff8000805c11b0
> [=C2=A0=C2=A0=C2=A0 C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: =
ffff6000fffff5f9
> [=C2=A0=C2=A0=C2=A0 C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : =
1fffe000fffff5f8
> [=C2=A0=C2=A0=C2=A0 C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : =
dfff800000000000
> [=C2=A0=C2=A0=C2=A0 C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : =
ffff700011fcce98
> [=C2=A0=C2=A0=C2=A0 C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : =
0000000000009a21
> [=C2=A0=C2=A0=C2=A0 C6] Call trace:
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 _raw_spin_unlock_irqrestore+0x50/0xb8
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 free_pcppages_bulk+0x2bc/0x3e0
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 free_unref_page_commit+0x1fc/0x290
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 free_unref_page+0x184/0x250
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 __free_pages+0x154/0x1a0
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 free_pages+0x88/0xb0
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 kasan_depopulate_vmalloc_pte+0x58/0x80
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 __apply_to_page_range+0x3ec/0x650
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 apply_to_existing_page_range+0x1c/0x30
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 kasan_release_vmalloc+0xa4/0x118
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 __purge_vmap_area_lazy+0x4f4/0xe30
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 drain_vmap_area_work+0x60/0xc0
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 process_one_work+0x4cc/0xa38
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 worker_thread+0x240/0x638
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 kthread+0x1c8/0x1e0
> [=C2=A0=C2=A0=C2=A0 C6]=C2=A0 ret_from_fork+0x10/0x20
>=20
>=20
>=20
>>
>> Kefeng Wang (3):
>> =C2=A0=C2=A0 mm: kasan: shadow: add cond_resched() in kasan_populate_vma=
lloc_pte()
>> =C2=A0=C2=A0 mm: kasan: shadow: move free_page() out of page table lock
>> =C2=A0=C2=A0 mm: kasan: shadow: HACK add cond_resched_lock() in
>> =C2=A0=C2=A0=C2=A0=C2=A0 kasan_depopulate_vmalloc_pte()
>>
>> =C2=A0 include/linux/kasan.h |=C2=A0 9 ++++++---
>> =C2=A0 mm/kasan/shadow.c=C2=A0=C2=A0=C2=A0=C2=A0 | 20 +++++++++++++-----=
--
>> =C2=A0 mm/vmalloc.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 7 ++++---
>> =C2=A0 3 files changed, 23 insertions(+), 13 deletions(-)
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/dd39cb3e-b184-407d-b74f-5b90a7983c99%40huawei.com.
