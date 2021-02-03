Return-Path: <kasan-dev+bncBCMIZB7QWENRBHPW5OAAMGQEIRRHFDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D54E730E356
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 20:35:58 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id 76sf352355oty.23
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 11:35:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612380957; cv=pass;
        d=google.com; s=arc-20160816;
        b=LR6WpBT8C/bF/F7TIy6wCVGF0uf6mDN+rk/sfKDIqxzegbD2gyOOmUw8Ws58IpgONz
         6wT7X5LDe8BegYFvVMw1g/lyLY+wSr0skUrhMw0Nzq6VH30zwhEgRVP7W37ZUTNoyHv8
         jarwj/akgxU6IZS8Sxgsxx/RHwHMR6hwo+nDhuHk66PhaqW/BLHweL8W+yalPIgx5xPV
         xKFQeiWBLt0zPGV3mHcelYkMWqfUhfll/x7Cj5+WTe5i0p052ccJc3VUvQ+HEbJHvncT
         q71vgcWNTXFrWQoT4l8zk/vY8txK3LdPP+8wpubo7r89AN17QZraqnCGlDxLEQVkP1pN
         zctw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yJfOPIGKzwkls39HXGh9NSDXwiFr8iTvDHZsLPhB30k=;
        b=kIgMK4RBwLLy9/y08Q+ov/ILynJlHquWs8w96HM+sG7vqYhQXjS+HPGRKICXP1Az2Z
         Bib3Aq3TbHZEJUmhrLcclOiUgZ07Jp1t9PWhdqq5/OLPNwMcWMb6Z+ssOG449V4C4Z2v
         VeRlyHwLY3Oh3kFKCMe0WGtFLRsjP7/ls35m1EoTyLGX8/kKVMQH6vWhDC4NhTAvJ768
         oz5PeQ8zC1FR7MR9MCfqW/G2FituQL1SprjDm9TzSJO+D7ZHPklR/HZ5mjEvgc/4ElRe
         2sS55i/W72iL2RSnNSy9qyF5XEnQhV7EcZe+oZkluoF9RW00krRdI/dpyVEn2pxpN+26
         HXfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N3RNBnr1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yJfOPIGKzwkls39HXGh9NSDXwiFr8iTvDHZsLPhB30k=;
        b=C/WvmRe5ZKVkJ/tynq3lnhwkul7qKmDESoh97/lCKe5ukcw2TosHTcFnTjNCi6mUGj
         k+3doxcdr1M4KsNpFID567UTtHZMrAdYbC2VC9E1OwAb0dyUidwGyr935UjviCGdvkYV
         6Hz39BKv4FA4K7Bc83q90DitHP0ixyPFcnKilwCgnWtxA1iN5kIjPAsLNjKW/Gm/lawL
         C4PH2/AcAI1fQa2oKRgNpuARt5qhv8Y3HOiHjhHTLD35fC7pBgepk86N5fvjzquG0TLK
         CH3TJ873hOn0Md4kspcPg3WdOxjzIWam20SrSUGDBqpaDcXRJ8yiJht9E6KWX3vmq2cM
         fPyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yJfOPIGKzwkls39HXGh9NSDXwiFr8iTvDHZsLPhB30k=;
        b=ujbN1ZPQjc5edD1LcNeoOSiB7XGqStgLhNPjOmK1d/8CAnatfgNQ+64rSKZXvQh+/T
         cw4wzLxT+kqJ2xYCALowTm+ElUVR5YS/L5C6SntbaQr/Dkg6el8kNYvBQuuD8hLcGLjU
         9Jw502a6S1YZClBzoTUr7Ld3N+qLkarxQEegObM4Nxi9gCxvTvuatTS5jpsotAcWk155
         sKoBGrFYyXYRoEk01dRTKM3qEdV+KtW4ViUb8YxEWh1we1M8OoVT1FqmU/MY9kabfSDr
         /YD5TWPjAgqj7+3eJYW4tLF49VA5X9wdwNP8ihS1pbHE6ETIfaT8VOC9SfBC3LugMpGu
         Iznw==
X-Gm-Message-State: AOAM5321EzztowEIra3DXi/ZK2EcdrkAcryUuscc4oK89j2NlMuHj58u
	P3rvgW5GU5Rjl0+ZRRV4arw=
X-Google-Smtp-Source: ABdhPJxF8DhsdBR2Wi9m+AlVtV1A93MLQU/oKWv4ZvgtknVDXSFgA9qDpUi7hpnYoNE5E0/C41RUqQ==
X-Received: by 2002:a9d:4c8b:: with SMTP id m11mr3161122otf.319.1612380957842;
        Wed, 03 Feb 2021 11:35:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1105:: with SMTP id 5ls802992oir.7.gmail; Wed, 03 Feb
 2021 11:35:57 -0800 (PST)
X-Received: by 2002:aca:4454:: with SMTP id r81mr2969354oia.129.1612380957414;
        Wed, 03 Feb 2021 11:35:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612380957; cv=none;
        d=google.com; s=arc-20160816;
        b=FAmO8S3+Zsbz4Oo/AXDW8x8pC9N7YRp0kmF5sF5him0g2+G5YvSQpgnajKbNSxmE2i
         GN7MCU31umhsiwAsZBS2/YhJvmjUW2ZSTqwSwuUsB0Jfu2TLFMDVCX0T2/ikRLPkx4Cz
         UUqoP5dqfBHGM7GGtyr0J94THlQ65TlgxUAhzVrn1Z4D0Y0g+T7Or7PDe2n7lQwJ/b7S
         mgvn0OrFchg/5aBZ2najRZncF9yJXtAL1FP8ubCasiHKx1WdfcDdFu4A/sSSOX8U3tLf
         +orEGRZhK+iQsf7L/rLWRSra3Cq9cJ39+eStsx9QASoDH8ESQW3sRqsauy2FOdraTeyC
         1OzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lygUOItVONTyhsU88Z4pU+ueswAcSicxheoODoB+RTQ=;
        b=vEedspbevTHeUXqQuXGR79MvDpdXcCzdV7ryzqDTPLxJGVXXijpQHYBPSbsvwe1S7J
         CMNpW+FTocB/bJp9PsvnmU3xVJVx9AWc4/vLBV7TV5nN3QBuQXP7IED1osiZ2IAZCmSq
         WIxqchV6JJRTNumjH8lqWIQXS9OCLzWwlW0BXw4XKdhW0SWQsufGGjrhBwFc8iPoONaq
         cVSydIM4W+zlBoxEieXPN8OUmBSgAF45Mzolp1q4GQgEYJ3vkPRS4V9hPQ7RVgpyZDOp
         B719CcfRVBMzD7B/rapXdWQkFP6dcMr9BSQy+qCyaLsUWyo7fe3lxHtnqcmTCBhvTGEF
         vdiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N3RNBnr1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id r27si225515oth.2.2021.02.03.11.35.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 11:35:57 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id z22so592143qto.7
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 11:35:57 -0800 (PST)
X-Received: by 2002:ac8:7c82:: with SMTP id y2mr3906877qtv.67.1612380956634;
 Wed, 03 Feb 2021 11:35:56 -0800 (PST)
MIME-Version: 1.0
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
 <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local> <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
 <cc712c9c-7786-bb26-7082-04e564df98aa@oracle.com> <CACT4Y+bPDvmwk38DrKfGV8cbtS_abAMDCqr9OigcPfep0uk5AQ@mail.gmail.com>
 <20210203192856.GA324708@fedora>
In-Reply-To: <20210203192856.GA324708@fedora>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Feb 2021 20:35:44 +0100
Message-ID: <CACT4Y+bscZGpMK-UXXzeFDeJtGYt-royR_=iTzTmBrwe3wOmTw@mail.gmail.com>
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in ibft_init()
To: Konrad Rzeszutek Wilk <konrad@darnok.org>
Cc: "Rafael J. Wysocki" <rjw@rjwysocki.net>, George Kennedy <george.kennedy@oracle.com>, 
	Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com, 
	konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N3RNBnr1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Feb 3, 2021 at 8:29 PM Konrad Rzeszutek Wilk <konrad@darnok.org> wrote:
>
> Hey Dmitry, Rafael, George, please see below..
>
> On Wed, Jan 27, 2021 at 10:10:07PM +0100, Dmitry Vyukov wrote:
> > On Wed, Jan 27, 2021 at 9:01 PM George Kennedy
> > <george.kennedy@oracle.com> wrote:
> > >
> > > Hi Dmitry,
> > >
> > > On 1/27/2021 1:48 PM, Dmitry Vyukov wrote:
> > >
> > > On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
> > > <konrad.wilk@oracle.com> wrote:
> > >
> > > On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
> > >
> > > During boot of kernel with CONFIG_KASAN the following KASAN false
> > > positive failure will occur when ibft_init() reads the
> > > ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
> > >
> > > The ACPI iBFT table is not allocated, and the iscsi driver uses
> > > a pointer to it to calculate checksum, etc. KASAN complains
> > > about this pointer with use-after-free, which this is not.
> > >
> > > Andrey, Alexander, Dmitry,
> > >
> > > I think this is the right way for this, but was wondering if you have
> > > other suggestions?
> > >
> > > Thanks!
> > >
> > > Hi George, Konrad,
> > >
> > > Please provide a sample KASAN report and kernel version to match line numbers.
> > >
> > > 5.4.17-2102.200.0.0.20210106_0000
> > >
> > > [   24.413536] iBFT detected.
> > > [   24.414074]
> > > ==================================================================
> > > [   24.407342] BUG: KASAN: use-after-free in ibft_init+0x134/0xb8b
> > > [   24.407342] Read of size 4 at addr ffff8880be452004 by task swapper/0/1
> > > [   24.407342]
> > > [   24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.4.17-2102.200.0.0.20210106_0000.syzk #1
> > > [   24.407342] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
> > > [   24.407342] Call Trace:
> > > [   24.407342]  dump_stack+0xd4/0x119
> > > [   24.407342]  ? ibft_init+0x134/0xb8b
> > > [   24.407342]  print_address_description.constprop.6+0x20/0x220
> > > [   24.407342]  ? ibft_init+0x134/0xb8b
> > > [   24.407342]  ? ibft_init+0x134/0xb8b
> > > [   24.407342]  __kasan_report.cold.9+0x37/0x77
> > > [   24.407342]  ? ibft_init+0x134/0xb8b
> > > [   24.407342]  kasan_report+0x14/0x1b
> > > [   24.407342]  __asan_report_load_n_noabort+0xf/0x11
> > > [   24.407342]  ibft_init+0x134/0xb8b
> > > [   24.407342]  ? dmi_sysfs_init+0x1a5/0x1a5
> > > [   24.407342]  ? dmi_walk+0x72/0x89
> > > [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
> > > [   24.407342]  ? rvt_init_port+0x110/0x101
> > > [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
> > > [   24.407342]  do_one_initcall+0xc3/0x44d
> > > [   24.407342]  ? perf_trace_initcall_level+0x410/0x405
> > > [   24.407342]  kernel_init_freeable+0x551/0x673
> > > [   24.407342]  ? start_kernel+0x94b/0x94b
> > > [   24.407342]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
> > > [   24.407342]  ? __kasan_check_write+0x14/0x16
> > > [   24.407342]  ? rest_init+0xe6/0xe6
> > > [   24.407342]  kernel_init+0x16/0x1bd
> > > [   24.407342]  ? rest_init+0xe6/0xe6
> > > [   24.407342]  ret_from_fork+0x2b/0x36
> > > [   24.407342]
> > > [   24.407342] The buggy address belongs to the page:
> > > [   24.407342] page:ffffea0002f91480 refcount:0 mapcount:0 mapping:0000000000000000 index:0x1
> > > [   24.407342] flags: 0xfffffc0000000()
> > > [   24.407342] raw: 000fffffc0000000 ffffea0002fca588 ffffea0002fb1a88 0000000000000000
> > > [   24.407342] raw: 0000000000000001 0000000000000000 00000000ffffffff 0000000000000000
> > > [   24.407342] page dumped because: kasan: bad access detected
> > > [   24.407342]
> > > [   24.407342] Memory state around the buggy address:
> > > [   24.407342]  ffff8880be451f00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > > [   24.407342]  ffff8880be451f80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > > [   24.407342] >ffff8880be452000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > > [   24.407342]                    ^
> > > [   24.407342]  ffff8880be452080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > > [   24.407342]  ffff8880be452100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> > > [   24.407342]
> > > ==================================================================
> > > [   24.407342] Disabling lock debugging due to kernel taint
> > > [   24.451021] Kernel panic - not syncing: panic_on_warn set ...
> > > [   24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G    B 5.4.17-2102.200.0.0.20210106_0000.syzk #1
> > > [   24.452002] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 0.0.0 02/06/2015
> > > [   24.452002] Call Trace:
> > > [   24.452002]  dump_stack+0xd4/0x119
> > > [   24.452002]  ? ibft_init+0x102/0xb8b
> > > [   24.452002]  panic+0x28f/0x6e0
> > > [   24.452002]  ? __warn_printk+0xe0/0xe0
> > > [   24.452002]  ? ibft_init+0x134/0xb8b
> > > [   24.452002]  ? add_taint+0x68/0xb3
> > > [   24.452002]  ? add_taint+0x68/0xb3
> > > [   24.452002]  ? ibft_init+0x134/0xb8b
> > > [   24.452002]  ? ibft_init+0x134/0xb8b
> > > [   24.452002]  end_report+0x4c/0x54
> > > [   24.452002]  __kasan_report.cold.9+0x55/0x77
> > > [   24.452002]  ? ibft_init+0x134/0xb8b
> > > [   24.452002]  kasan_report+0x14/0x1b
> > > [   24.452002]  __asan_report_load_n_noabort+0xf/0x11
> > > [   24.452002]  ibft_init+0x134/0xb8b
> > > [   24.452002]  ? dmi_sysfs_init+0x1a5/0x1a5
> > > [   24.452002]  ? dmi_walk+0x72/0x89
> > > [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
> > > [   24.452002]  ? rvt_init_port+0x110/0x101
> > > [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
> > > [   24.452002]  do_one_initcall+0xc3/0x44d
> > > [   24.452002]  ? perf_trace_initcall_level+0x410/0x405
> > > [   24.452002]  kernel_init_freeable+0x551/0x673
> > > [   24.452002]  ? start_kernel+0x94b/0x94b
> > > [   24.452002]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
> > > [   24.452002]  ? __kasan_check_write+0x14/0x16
> > > [   24.452002]  ? rest_init+0xe6/0xe6
> > > [   24.452002]  kernel_init+0x16/0x1bd
> > > [   24.452002]  ? rest_init+0xe6/0xe6
> > > [   24.452002]  ret_from_fork+0x2b/0x36
> > > [   24.452002] Dumping ftrace buffer:
> > > [   24.452002] ---------------------------------
> > > [   24.452002] swapper/-1         1.... 24564337us : rdmaip_init: 2924: rdmaip_init: Active Bonding is DISABLED
> > > [   24.452002] ---------------------------------
> > > [   24.452002] Kernel Offset: disabled
> > > [   24.452002] Rebooting in 1 seconds..
> > >
> > > Why does KASAN think the address is freed? For that to happen that
> > > memory should have been freed. I don't remember any similar false
> > > positives from KASAN, so this looks a bit suspicious.
> > >
> > > I'm not sure why KASAN thinks the address is freed. There are other modules where KASAN/KCOV is disabled on boot.
> > > Could this be for a similar reason?
> >
> > Most of these files are disabled because they cause recursion in
> > instrumentation, or execute too early in bootstrap process (before
> > kasan_init).
> >
> > Somehow the table pointer in ibft_init points to a freed page. I
> > tracked it down to here:
> > https://elixir.bootlin.com/linux/v5.4.17/source/drivers/acpi/acpica/tbutils.c#L399
> > but I can't find where this table_desc->pointer comes from. Perhaps it
>
> It is what the BIOS generated. It usually points to some memory
> location in right under 4GB and the BIOS stashes the DSDT, iBFT, and
> other tables in there.
>
> > uses some allocation method that's not supported by KASAN? However,
> > it's the only such case that I've seen, so it's a bit weird. Could it
> > use something like memblock_alloc? Or maybe that page was in fact
> > freed?... Too bad KASAN does not print free stack for pages, maybe
> > it's not too hard to do if CONFIG_PAGE_OWNER is enabled...
>
> Hm, there is a comment in the acpi_get_table speaking about the
> requirement of having a acpi_put_table and:
>
>
>  * DESCRIPTION: Finds and verifies an ACPI table. Table must be in the
>  *              RSDT/XSDT.
>  *              Note that an early stage acpi_get_table() call must be paired
>  *              with an early stage acpi_put_table() call. otherwise the table
>  *              pointer mapped by the early stage mapping implementation may be
>  *              erroneously unmapped by the late stage unmapping implementation
>  *              in an acpi_put_table() invoked during the late stage.
>  *
>
> Which would imply that I should use acpi_put_table in the error path
> (see below a patch), but also copy the structure instead of depending
> on ACPI keeping it mapped for me. I think.

Hi Konrad,

Thanks for looking into this.
If ACPI unmaps this page, that would perfectly explain the KASAN report.

George, does this patch eliminate the KASAN report for you?


> CC-ing Rafeal.
>
>
> From c37da50fdfc62cd4f7b23562b55661478c90a17d Mon Sep 17 00:00:00 2001
> From: Konrad Rzeszutek Wilk <konrad@darnok.org>
> Date: Tue, 2 Feb 2021 17:28:28 +0000
> Subject: [PATCH] ibft: Put ibft_addr back
>
> Signed-off-by: Konrad Rzeszutek Wilk <konrad@darnok.org>
> ---
>  drivers/firmware/iscsi_ibft.c | 19 +++++++++++++------
>  1 file changed, 13 insertions(+), 6 deletions(-)
>
> diff --git a/drivers/firmware/iscsi_ibft.c b/drivers/firmware/iscsi_ibft.c
> index 7127a04..2a1a033 100644
> --- a/drivers/firmware/iscsi_ibft.c
> +++ b/drivers/firmware/iscsi_ibft.c
> @@ -811,6 +811,10 @@ static void ibft_cleanup(void)
>                 ibft_unregister();
>                 iscsi_boot_destroy_kset(boot_kset);
>         }
> +       if (ibft_addr) {
> +               acpi_put_table((struct acpi_table_header *)ibft_addr);
> +               ibft_addr = NULL;
> +       }
>  }
>
>  static void __exit ibft_exit(void)
> @@ -835,13 +839,15 @@ static void __init acpi_find_ibft_region(void)
>  {
>         int i;
>         struct acpi_table_header *table = NULL;
> +       acpi_status status;
>
>         if (acpi_disabled)
>                 return;
>
>         for (i = 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
> -               acpi_get_table(ibft_signs[i].sign, 0, &table);
> -               ibft_addr = (struct acpi_table_ibft *)table;
> +               status = acpi_get_table(ibft_signs[i].sign, 0, &table);
> +               if (ACPI_SUCCESS(status))
> +                       ibft_addr = (struct acpi_table_ibft *)table;
>         }
>  }
>  #else
> @@ -870,12 +876,13 @@ static int __init ibft_init(void)
>
>                 rc = ibft_check_device();
>                 if (rc)
> -                       return rc;
> +                       goto out_free;
>
>                 boot_kset = iscsi_boot_create_kset("ibft");
> -               if (!boot_kset)
> -                       return -ENOMEM;
> -
> +               if (!boot_kset) {
> +                       rc = -ENOMEM;
> +                       goto out_free;
> +               }
>                 /* Scan the IBFT for data and register the kobjects. */
>                 rc = ibft_register_kobjects(ibft_addr);
>                 if (rc)
> --
> 1.8.3.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbscZGpMK-UXXzeFDeJtGYt-royR_%3DiTzTmBrwe3wOmTw%40mail.gmail.com.
