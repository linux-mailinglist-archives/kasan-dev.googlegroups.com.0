Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4TYCUQMGQEL2SNNUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id D7A637CE2F0
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 18:37:40 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-d9a3954f6dcsf8672602276.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 09:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697647059; cv=pass;
        d=google.com; s=arc-20160816;
        b=BZ+01EWIr+o8aKO7CL+iiN19CSetfQb39IfHIMxPjXtFjdkdxly02FZI26DbXYjOKP
         ozequS7LcT71V38mjsoxwvGzxYxZanUDAo9lRDcforKiBQrro9PcSX9kP7qyYNeGFXb7
         3GdQCXhdcDDHDu8ymeUPIS7HTARxmIaARVvjY8RGsZEzjWiTTOsgiDezQXTI+tx72kb0
         ZeX9zZPJ2Gjmvot7PHzjb0gNjQz6FehRQSXVnyLJj5Z/blXl9aOtLnPGS+g9qCtAhbih
         jD1Y0FJINq8vX7Lh0vDF1j+zgi49q1pbMWIXVOSX4J9Lgv4NtC2i35fnY5WC+cr31Oif
         sHxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LFbp7niKiVIjeouFiRkljZSGII+QOlDG4vyZ9/SFK1A=;
        fh=a5CaafEcuGCUm2FQOos4D2mQrQJkqPLjeO1T2Z5pAgY=;
        b=WUT/6SiMP+Iw7k0OR7884CajrX7pNKpI6tGJs/04r4adoEyFTsgtBpWZ0tazDu4neW
         PYU1kS8WnBHxjLV4lfbF3et7tULvmljeAii9IV0okOX2Oa+BiByDk460NjDt2QLxowwS
         7k3Ng/nPBBpuI7JwMc0Ufh6yJk6N56pkaMy6jiWv0d5jGGTt87eW/HSvsUf9u/fxb+/Z
         8SpTbZP/gzPakMDMI9d1QlNKfaPWTMinvKKyxyYM95bf6lS4H98PW0e6mdwibwHgn28E
         OGLLrzRJpT6BJKe+7660TbgYDsSqxcOpNVhmM2WEUb+yCMOoUmeMT4aQ5zPurxllBR8Z
         Geww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MYYqcl8o;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697647059; x=1698251859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LFbp7niKiVIjeouFiRkljZSGII+QOlDG4vyZ9/SFK1A=;
        b=Zy5IXs6b6f9RWPxbLGKSzcDhDf1jJggv57uICCsKSDYEIpENtL8iohZId8UYHZ8sLU
         N3e14KOVXhsKuRWCs5kkiiAfjhqhwrLosgPIj1MGcuHBRoE4SvYne4ZRxaWIZZdP/PKz
         IsE8Ds7hELrEGZ6nfY6VdcU7gofzsj5GGIUG73J4DX0q0f2v/b18NevbQ5LVrKLKdgmt
         03HLtHCVswNK0X1DMLexzZyaCxH7W483jkrlfpNiQtqMk4XE8uMzTxtaishoi/Fz2LSA
         lJf5JCtD656eKHPcATo45SdkphECrr0BK8KpE62hUnG4NO8NtkNuURmzd23mx5ke/OVc
         LmCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697647059; x=1698251859;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LFbp7niKiVIjeouFiRkljZSGII+QOlDG4vyZ9/SFK1A=;
        b=IzmdpK3VDhXJecpedCAP7KdAIRzgEoNUVgBHbc8TXTAh2xW5BBS3gGD6EXad4xFK+C
         sOtAGOAJpATUvktRD/zr9O/8t8qAcp2cWLNXHmVsouHgokwxsz5IR66uap2D6wJBRoQB
         3iW+3Vi18O5XMQ31ppV8/cywIHrABK2HoLBtHUt5az2miG7JCLC5SEuLShjMzU8CYBPZ
         ZHgI4MXPAfQQQKjyQ735dPkQA2VBuJEC9s9gIHdgSFT3h0nFXEYPfvXzzCgsKV+gY0zB
         GnafEwJcU5/7iDZyL/Vn3gE6QRMYDoVtC4+06PphQAFTCg1hPi0x/yvFDpZFuKawG9pa
         rohg==
X-Gm-Message-State: AOJu0Ywk+1zRQS/kaQbwQrehX6g5o3PBwgPrcpPbzsEF3O/TbxR9URw1
	zVoXpS55za1BCbX5FO/rQS0=
X-Google-Smtp-Source: AGHT+IEe5ForAFOg542KQM8D21BNTQ1lHQK3HzW75j8arvK35alazsMi20xAQE+ZFFsF0NIf93eWQA==
X-Received: by 2002:a25:bfca:0:b0:d9a:42a4:eaf3 with SMTP id q10-20020a25bfca000000b00d9a42a4eaf3mr5507736ybm.11.1697647059570;
        Wed, 18 Oct 2023 09:37:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:410:0:b0:d9b:df64:a21d with SMTP id 16-20020a250410000000b00d9bdf64a21dls525813ybe.0.-pod-prod-06-us;
 Wed, 18 Oct 2023 09:37:38 -0700 (PDT)
X-Received: by 2002:a25:8481:0:b0:d9a:c946:c18a with SMTP id v1-20020a258481000000b00d9ac946c18amr5571636ybk.28.1697647058496;
        Wed, 18 Oct 2023 09:37:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697647058; cv=none;
        d=google.com; s=arc-20160816;
        b=br/S4en5bPiUpnXAXOBCe0wPMBOyL72t9La4lxQxgpzEWY6Z7HxHgu0FrMlxEZV9oD
         n1T8YsGgKSaMrutKTjyqvYvZNlGaRY2Au3pBNDAYLMrew20WO49bUpBn0SRytMBdZVud
         5X6wBOJTvsCqMcd4KXBpBl0Ma+6anEWxQ1Nnxc6UIHqYcpsLgLRAJ5jOGDQsyOPX5aRZ
         826EcLxKRDW8pss2p9ij7zSCjveqk3dv9ZdfwHscwamzznhXxoiEUGxQz8XVHUWSyVDH
         oRbBbUAvFJZl0b0HKUl8HZ0If4KFjLMW8UPSK6DotB2P448FhmJft46txC6yntne7BUq
         tA6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZS6/4vqnqCgfA+WMNFGqFV+FgCO5fKsjIazP0J73rTA=;
        fh=a5CaafEcuGCUm2FQOos4D2mQrQJkqPLjeO1T2Z5pAgY=;
        b=pOIILcexC57ZZV1SWwF7HUIFHP7xfWHKbqisMb3B2aH+biZoq6JqGJK2BMizB+RlzK
         6NR7lDnDUYV4SVbCQAEPWSvgndAwPnEQQenEiVABYw98d/ByE9Ok7yto7UdWgU/wfVWO
         NT5TqedxmlAXDe9o7cH2+YXQJlM7lrpzb/tkLo4MUYNs6FYe08aW2gDJ+TEN8vpxffut
         Zu0H/jRBH69OW9qUW8s0YZRti/6JrIOh7gY8whmAoZuM+LlJumGYaARxyhh6tYJZcz8R
         ottVLKmfgZsoHw/q2ikTAmGRwgxKdJCtu/a5g2sL7Md1kbufjnObC+wsEBS1+OO8msrB
         hZqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MYYqcl8o;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id l15-20020a25250f000000b00d866d666ad6si345832ybl.0.2023.10.18.09.37.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Oct 2023 09:37:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id a1e0cc1a2514c-7b08ac3ce7fso2964452241.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Oct 2023 09:37:38 -0700 (PDT)
X-Received: by 2002:a67:c39a:0:b0:458:19fc:e1e5 with SMTP id
 s26-20020a67c39a000000b0045819fce1e5mr6396948vsj.6.1697647057877; Wed, 18 Oct
 2023 09:37:37 -0700 (PDT)
MIME-Version: 1.0
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
 <4e2e075f-b74c-4daf-bf1a-f83fced742c4@huawei.com> <dd39cb3e-b184-407d-b74f-5b90a7983c99@huawei.com>
In-Reply-To: <dd39cb3e-b184-407d-b74f-5b90a7983c99@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Oct 2023 18:37:01 +0200
Message-ID: <CANpmjNPY5NgvnfDcu1GFP-K0rCgiB4_+TqL4-p_ER-bLYvw26A@mail.gmail.com>
Subject: Re: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or
 depopulate pte
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>, 
	Lorenzo Stoakes <lstoakes@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MYYqcl8o;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 18 Oct 2023 at 16:16, 'Kefeng Wang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> The issue is easy to reproduced with large vmalloc, kindly ping...
>
> On 2023/9/15 8:58, Kefeng Wang wrote:
> > Hi All=EF=BC=8C any suggest or comments=EF=BC=8Cmany thanks.
> >
> > On 2023/9/6 20:42, Kefeng Wang wrote:
> >> This is a RFC, even patch3 is a hack to fix the softlock issue when
> >> populate or depopulate pte with large region, looking forward to your
> >> reply and advise, thanks.
> >
> > Here is full stack=EF=BC=8Cfor populate pte=EF=BC=8C
> >
> > [    C3] watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [insmod:458]
> > [    C3] Modules linked in: test(OE+)
> > [    C3] irq event stamp: 320776
> > [    C3] hardirqs last  enabled at (320775): [<ffff8000815a0c98>]
> > _raw_spin_unlock_irqrestore+0x98/0xb8
> > [    C3] hardirqs last disabled at (320776): [<ffff8000815816e0>]
> > el1_interrupt+0x38/0xa8
> > [    C3] softirqs last  enabled at (318174): [<ffff800080040ba8>]
> > __do_softirq+0x658/0x7ac
> > [    C3] softirqs last disabled at (318169): [<ffff800080047fd8>]
> > ____do_softirq+0x18/0x30
> > [    C3] CPU: 3 PID: 458 Comm: insmod Tainted: G           OE 6.5.0+ #5=
95
> > [    C3] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/201=
5
> > [    C3] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=3D=
--)
> > [    C3] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> > [    C3] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> > [    C3] sp : ffff800093386d70
> > [    C3] x29: ffff800093386d70 x28: 0000000000000801 x27: ffff0007ffffa=
9c0
> > [    C3] x26: 0000000000000000 x25: 000000000000003f x24: fffffc0004353=
708
> > [    C3] x23: ffff0006d476bad8 x22: fffffc0004353748 x21: 0000000000000=
000
> > [    C3] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 0000000000000=
000
> > [    C3] x17: ffff80008024e7fc x16: ffff80008055a8f0 x15: ffff80008024e=
c60
> > [    C3] x14: ffff80008024ead0 x13: ffff80008024e7fc x12: ffff6000fffff=
5f9
> > [    C3] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fffff=
5f8
> > [    C3] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff800000000=
000
> > [    C3] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff700012670=
d70
> > [    C3] x2 : 0000000000000001 x1 : c9a5dbfae610fa24 x0 : 000000000004e=
507
> > [    C3] Call trace:
> > [    C3]  _raw_spin_unlock_irqrestore+0x50/0xb8
> > [    C3]  rmqueue_bulk+0x434/0x6b8
> > [    C3]  get_page_from_freelist+0xdd4/0x1680
> > [    C3]  __alloc_pages+0x244/0x508
> > [    C3]  alloc_pages+0xf0/0x218
> > [    C3]  __get_free_pages+0x1c/0x50
> > [    C3]  kasan_populate_vmalloc_pte+0x30/0x188
> > [    C3]  __apply_to_page_range+0x3ec/0x650
> > [    C3]  apply_to_page_range+0x1c/0x30
> > [    C3]  kasan_populate_vmalloc+0x60/0x70
> > [    C3]  alloc_vmap_area.part.67+0x328/0xe50
> > [    C3]  alloc_vmap_area+0x4c/0x78
> > [    C3]  __get_vm_area_node.constprop.76+0x130/0x240
> > [    C3]  __vmalloc_node_range+0x12c/0x340
> > [    C3]  __vmalloc_node+0x8c/0xb0
> > [    C3]  vmalloc+0x2c/0x40
> > [    C3]  show_mem_init+0x1c/0xff8 [test]
> > [    C3]  do_one_initcall+0xe4/0x500
> > [    C3]  do_init_module+0x100/0x358
> > [    C3]  load_module+0x2e64/0x2fc8
> > [    C3]  init_module_from_file+0xec/0x148
> > [    C3]  idempotent_init_module+0x278/0x380
> > [    C3]  __arm64_sys_finit_module+0x88/0xf8
> > [    C3]  invoke_syscall+0x64/0x188
> > [    C3]  el0_svc_common.constprop.1+0xec/0x198
> > [    C3]  do_el0_svc+0x48/0xc8
> > [    C3]  el0_svc+0x3c/0xe8
> > [    C3]  el0t_64_sync_handler+0xa0/0xc8
> > [    C3]  el0t_64_sync+0x188/0x190
> >
> > and for depopuldate pte=EF=BC=8C
> >
> > [    C6] watchdog: BUG: soft lockup - CPU#6 stuck for 48s! [kworker/6:1=
:59]
> > [    C6] Modules linked in: test(OE+)
> > [    C6] irq event stamp: 39458
> > [    C6] hardirqs last  enabled at (39457): [<ffff8000815a0c98>]
> > _raw_spin_unlock_irqrestore+0x98/0xb8
> > [    C6] hardirqs last disabled at (39458): [<ffff8000815816e0>]
> > el1_interrupt+0x38/0xa8
> > [    C6] softirqs last  enabled at (39420): [<ffff800080040ba8>]
> > __do_softirq+0x658/0x7ac
> > [    C6] softirqs last disabled at (39415): [<ffff800080047fd8>]
> > ____do_softirq+0x18/0x30
> > [    C6] CPU: 6 PID: 59 Comm: kworker/6:1 Tainted: G           OEL
> > 6.5.0+ #595
> > [    C6] Hardware name: QEMU QEMU Virtual Machine, BIOS 0.0.0 02/06/201=
5
> > [    C6] Workqueue: events drain_vmap_area_work
> > [    C6] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=3D=
--)
> > [    C6] pc : _raw_spin_unlock_irqrestore+0x50/0xb8
> > [    C6] lr : _raw_spin_unlock_irqrestore+0x98/0xb8
> > [    C6] sp : ffff80008fe676b0
> > [    C6] x29: ffff80008fe676b0 x28: fffffc000601d310 x27: ffff000edf5df=
a80
> > [    C6] x26: ffff000edf5dfad8 x25: 0000000000000000 x24: 0000000000000=
006
> > [    C6] x23: ffff000edf5dfad4 x22: 0000000000000000 x21: 0000000000000=
006
> > [    C6] x20: ffff0007ffffafc0 x19: 0000000000000000 x18: 0000000000000=
000
> > [    C6] x17: ffff8000805544b8 x16: ffff800080553d94 x15: ffff8000805c1=
1b0
> > [    C6] x14: ffff8000805baeb0 x13: ffff800080047e10 x12: ffff6000fffff=
5f9
> > [    C6] x11: 1fffe000fffff5f8 x10: ffff6000fffff5f8 x9 : 1fffe000fffff=
5f8
> > [    C6] x8 : dfff800000000000 x7 : 00000000f2000000 x6 : dfff800000000=
000
> > [    C6] x5 : 00000000f2f2f200 x4 : dfff800000000000 x3 : ffff700011fcc=
e98
> > [    C6] x2 : 0000000000000001 x1 : cf09d5450e2b4f7f x0 : 0000000000009=
a21
> > [    C6] Call trace:
> > [    C6]  _raw_spin_unlock_irqrestore+0x50/0xb8
> > [    C6]  free_pcppages_bulk+0x2bc/0x3e0
> > [    C6]  free_unref_page_commit+0x1fc/0x290
> > [    C6]  free_unref_page+0x184/0x250
> > [    C6]  __free_pages+0x154/0x1a0
> > [    C6]  free_pages+0x88/0xb0
> > [    C6]  kasan_depopulate_vmalloc_pte+0x58/0x80
> > [    C6]  __apply_to_page_range+0x3ec/0x650
> > [    C6]  apply_to_existing_page_range+0x1c/0x30
> > [    C6]  kasan_release_vmalloc+0xa4/0x118
> > [    C6]  __purge_vmap_area_lazy+0x4f4/0xe30
> > [    C6]  drain_vmap_area_work+0x60/0xc0
> > [    C6]  process_one_work+0x4cc/0xa38
> > [    C6]  worker_thread+0x240/0x638
> > [    C6]  kthread+0x1c8/0x1e0
> > [    C6]  ret_from_fork+0x10/0x20
> >
> >
> >
> >>
> >> Kefeng Wang (3):
> >>    mm: kasan: shadow: add cond_resched() in kasan_populate_vmalloc_pte=
()
> >>    mm: kasan: shadow: move free_page() out of page table lock
> >>    mm: kasan: shadow: HACK add cond_resched_lock() in
> >>      kasan_depopulate_vmalloc_pte()

The first 2 patches look ok, but yeah, the last is a hack. I also
don't have any better suggestions, only more questions.

Does this only happen on arm64?
Do you have a minimal reproducer you can share?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPY5NgvnfDcu1GFP-K0rCgiB4_%2BTqL4-p_ER-bLYvw26A%40mail.gmai=
l.com.
