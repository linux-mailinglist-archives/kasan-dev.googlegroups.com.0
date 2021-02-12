Return-Path: <kasan-dev+bncBCMIZB7QWENRBCUQTKAQMGQE72NXYZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F3DF31A011
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 14:52:11 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id 124sf7284542qkg.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 05:52:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613137930; cv=pass;
        d=google.com; s=arc-20160816;
        b=EeCHdbZuC6Hb5NdR4PIaYG69d9skNqa5Xi+l5EUWJWu6lElOec3J/iutJQ+s8ATQYt
         2vo08jYFj2eKsmjF2xiFQ0NPzsP1PGd5w6RQDhcYyurO7e4YMlbDEJAvVe1PA0HarpuR
         +SL7tP8HY053czDCxDoMEqQB7T1ASRZomKodTqnnGNwhkkrqXdJ6UKYu+yrlTtbt1l7u
         VivlDqkQyE2MU+g8kHegSRCKGkTGaYX+vK3IupMHGTp6bpefBrMBfABhs1yJmrCO4GTf
         tlW3cIP3DERLIHfLEuqlb2HcZcmeUXF0iFU2z6ivscs3jhh4HwGadm2SwD8nHS6rdAMJ
         uHOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rJBCW6qvycMA9oFFYDjtE23ClYZNjNzfqH3DC5HUAck=;
        b=FK5LWm5AR21i8bKauLu+IIu6UExzwpUvUHr5iaVekEM2wF2gtAvgi/ni0FVf9Ozoz6
         V4eTEEUL6q3rf90EQmZqe12mzL3Ge4UyhVpAxuLgy61o08dhCl1Gjznt5I/D2KI7r7kN
         9pBoRQodY0ZfPAqItPH8vBGKAoix6kID7tDQw6yuMM39tSW3FBUGvbfb6vYVXRycZa4H
         ut0/sA4w+vdH+q/WaIHwxb9NxbL4NNSxGA5FbOiTqLj/UUX2Imietq1hsz2GZkZkHY4F
         ORmIwFFiFzrDIglp0BEgNDnvCxCuSBvfiZ+xJvPf5iM/B71GHSy6sg5lkURYEPfb3vYy
         rswQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b3nHoiQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rJBCW6qvycMA9oFFYDjtE23ClYZNjNzfqH3DC5HUAck=;
        b=A0Mma7layG94A5CYi67hmIIHbJ7wBBZSTlwgb5GgjbYIBbvvhMko9Xo9kenL5rCxJV
         M4xxPI9PkU68vi7L91nD1beXn459LzDFJF3360dTURRiCxUFo5MAGJQ+fyooNodYf0Op
         0dhAaWN4BJIrVt35RYtLzg9+aa3eVRl2BR3I3C+gJmFCtLGc7TE3F4LtRGQvL5BKQUFc
         oCWVLq8uCZdphWy3iQ3AKgZrhuTUTGKOQr02JRsTsMCZJ9OMcdHO0c/0Tlh/EjSp8jMI
         /XEwbGCNnIRJ1BHC+lzMs4H5rgarOO7UxbE0ba3YTbHCDumYMJporDbCC1P05PohTgYS
         RS+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rJBCW6qvycMA9oFFYDjtE23ClYZNjNzfqH3DC5HUAck=;
        b=g7y/4czfDp9USfqa+xd3Jh+xz29keGXfuJGyQMdT1TywCyFlFtm29n9NLLyOOVNy49
         MDAKw5qSJeVZzToohzz7Pt5tnu5trIV0cga8INOiaXlj5W9kRy5l84aRX4SgsGpr5NOJ
         iapGtX9talP66MgwqORGKboKcXCXRq1s8EecKKK+kbm7dF8SX2OgYRAib0yEvVEvuLlS
         VBpxgcwR6KI/SJ60fus+4tZMZkXBSlRhjqOYD8JUHuKMBneqI/NKnsFVhhi3FbJlrfWS
         i79B9dz76JW4LUXrKMkDdAonsRukkDcyFvDx3l/j7SxGhnd+oKF66sUOT7KPGStvW6h+
         kIHA==
X-Gm-Message-State: AOAM5333/reDmjtKk9lWYYItD6+ekkplDRvLoLDHHmTBuGepRsMo6ohX
	2Xh6EDLsFklZ6BLRHy5/JwY=
X-Google-Smtp-Source: ABdhPJxmA/OKtjXbI4O1x0mOXmjVgQkv64b114rh7KLyjRtLLOQC7PLci8qRYgfkcUMEZGNHtJkWBQ==
X-Received: by 2002:a05:620a:145:: with SMTP id e5mr2644078qkn.293.1613137930738;
        Fri, 12 Feb 2021 05:52:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:38b:: with SMTP id 133ls4604723qkd.3.gmail; Fri, 12 Feb
 2021 05:52:10 -0800 (PST)
X-Received: by 2002:a37:542:: with SMTP id 63mr2748658qkf.8.1613137930361;
        Fri, 12 Feb 2021 05:52:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613137930; cv=none;
        d=google.com; s=arc-20160816;
        b=eKwm0BEjfZXuQPsBdoNDhZWk8F+phA4qz9ry0KF1OWgzjig6ec4q7FG+TUvSE+VXh0
         UaHiL5n6gHvrvewf/V66OWAVV16dd0ruUge49Ff88AfMSl0TRX/XQnHFCXxwqt0ZneSh
         61HuHh99SRnNPAwrpTeh8PGlctKlX4uJtfcBNpi34N1ePxWrOAUKOcQzN+5ssly2s5cR
         Xkwr3Z8A12r/9h9NKgQfMirsOGyyaRxrPfqLqix65um5FFgnNlcCSO67RVwYGboHXm6D
         z2wAtgkyxdgbtVWSWieMN74/k2TZD41zCne7wNk3XLwsJMvTmA9BwD4kMkfzKeS153+3
         P9HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UeM02MGUTBn2j1+WvhmPUGZ8QOsdJKfd/Mm53IHcq24=;
        b=TThjZqWlxb/rAIQbCBonSNj3neJEl0JFda+YeBmbjx/cLp4QposSlTCVC644TranhA
         ebpAOk/WvSyB86vxNr6AD1Vm9ZiFBnriG98A8fN/4X/2ClUeh3p+YZVgqQvuot7HdHmG
         QJ23+VtYEwd2RqCWxMCzOWHC2h2lCe3nEt2WCGXUjHlucP4MS/vlLAzWQq4dseBL0N43
         Q874cxi9NXtp9IZ3H7EOg9yvAQTkT3WQmFeBrN86+Nhsl1NdUsDxf7Wip2pLnpJoEAGo
         isAwa17OrOkCUfOpdSQuwXVdGAu+6OQB9G2GE/fZ0xR/cXoYCARY5sm87y1qqVdx+zoe
         //Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b3nHoiQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id q24si394017qtp.5.2021.02.12.05.52.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 05:52:10 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id f18so4173774qvm.9
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 05:52:10 -0800 (PST)
X-Received: by 2002:a0c:8304:: with SMTP id j4mr2626882qva.18.1613137929540;
 Fri, 12 Feb 2021 05:52:09 -0800 (PST)
MIME-Version: 1.0
References: <1611684201-16262-1-git-send-email-george.kennedy@oracle.com>
 <YBG0glwiK1wyJTeN@Konrads-MacBook-Pro.local> <CACT4Y+a48smtXc6qJy9Wthwuqjk2gh6o7BK1tfWW46g7D_r-Lg@mail.gmail.com>
 <cc712c9c-7786-bb26-7082-04e564df98aa@oracle.com> <CACT4Y+bPDvmwk38DrKfGV8cbtS_abAMDCqr9OigcPfep0uk5AQ@mail.gmail.com>
 <20210203192856.GA324708@fedora> <CACT4Y+bscZGpMK-UXXzeFDeJtGYt-royR_=iTzTmBrwe3wOmTw@mail.gmail.com>
 <14124734-326e-87b3-a04a-b7190f1e1282@oracle.com> <bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com>
In-Reply-To: <bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 14:51:58 +0100
Message-ID: <CACT4Y+Ze3J5L7vBt7hmqbMrxhRg=k1hZkPTJpCG83Gc=Wr-Fsg@mail.gmail.com>
Subject: Re: [PATCH 1/1] iscsi_ibft: KASAN false positive failure occurs in ibft_init()
To: George Kennedy <george.kennedy@oracle.com>
Cc: Konrad Rzeszutek Wilk <konrad@darnok.org>, "Rafael J. Wysocki" <rjw@rjwysocki.net>, 
	Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, pjones@redhat.com, 
	konrad@kernel.org, LKML <linux-kernel@vger.kernel.org>, 
	Dan Carpenter <dan.carpenter@oracle.com>, Dhaval Giani <dhaval.giani@oracle.com>, 
	David Hildenbrand <david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b3nHoiQb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c
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

On Fri, Feb 12, 2021 at 2:31 PM George Kennedy
<george.kennedy@oracle.com> wrote:
> On 2/10/2021 4:51 PM, George Kennedy wrote:
> > On 2/3/2021 2:35 PM, Dmitry Vyukov wrote:
> >> On Wed, Feb 3, 2021 at 8:29 PM Konrad Rzeszutek Wilk
> >> <konrad@darnok.org> wrote:
> >>> Hey Dmitry, Rafael, George, please see below..
> >>>
> >>> On Wed, Jan 27, 2021 at 10:10:07PM +0100, Dmitry Vyukov wrote:
> >>>> On Wed, Jan 27, 2021 at 9:01 PM George Kennedy
> >>>> <george.kennedy@oracle.com> wrote:
> >>>>> Hi Dmitry,
> >>>>>
> >>>>> On 1/27/2021 1:48 PM, Dmitry Vyukov wrote:
> >>>>>
> >>>>> On Wed, Jan 27, 2021 at 7:44 PM Konrad Rzeszutek Wilk
> >>>>> <konrad.wilk@oracle.com> wrote:
> >>>>>
> >>>>> On Tue, Jan 26, 2021 at 01:03:21PM -0500, George Kennedy wrote:
> >>>>>
> >>>>> During boot of kernel with CONFIG_KASAN the following KASAN false
> >>>>> positive failure will occur when ibft_init() reads the
> >>>>> ACPI iBFT table: BUG: KASAN: use-after-free in ibft_init
> >>>>>
> >>>>> The ACPI iBFT table is not allocated, and the iscsi driver uses
> >>>>> a pointer to it to calculate checksum, etc. KASAN complains
> >>>>> about this pointer with use-after-free, which this is not.
> >>>>>
> >>>>> Andrey, Alexander, Dmitry,
> >>>>>
> >>>>> I think this is the right way for this, but was wondering if you have
> >>>>> other suggestions?
> >>>>>
> >>>>> Thanks!
> >>>>>
> >>>>> Hi George, Konrad,
> >>>>>
> >>>>> Please provide a sample KASAN report and kernel version to match
> >>>>> line numbers.
> >>>>>
> >>>>> 5.4.17-2102.200.0.0.20210106_0000
> >>>>>
> >>>>> [   24.413536] iBFT detected.
> >>>>> [   24.414074]
> >>>>> ==================================================================
> >>>>> [   24.407342] BUG: KASAN: use-after-free in ibft_init+0x134/0xb8b
> >>>>> [   24.407342] Read of size 4 at addr ffff8880be452004 by task
> >>>>> swapper/0/1
> >>>>> [   24.407342]
> >>>>> [   24.407342] CPU: 1 PID: 1 Comm: swapper/0 Not tainted
> >>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
> >>>>> [   24.407342] Hardware name: QEMU Standard PC (i440FX + PIIX,
> >>>>> 1996), BIOS 0.0.0 02/06/2015
> >>>>> [   24.407342] Call Trace:
> >>>>> [   24.407342]  dump_stack+0xd4/0x119
> >>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.407342] print_address_description.constprop.6+0x20/0x220
> >>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.407342]  __kasan_report.cold.9+0x37/0x77
> >>>>> [   24.407342]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.407342]  kasan_report+0x14/0x1b
> >>>>> [   24.407342]  __asan_report_load_n_noabort+0xf/0x11
> >>>>> [   24.407342]  ibft_init+0x134/0xb8b
> >>>>> [   24.407342]  ? dmi_sysfs_init+0x1a5/0x1a5
> >>>>> [   24.407342]  ? dmi_walk+0x72/0x89
> >>>>> [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
> >>>>> [   24.407342]  ? rvt_init_port+0x110/0x101
> >>>>> [   24.407342]  ? ibft_check_initiator_for+0x159/0x159
> >>>>> [   24.407342]  do_one_initcall+0xc3/0x44d
> >>>>> [   24.407342]  ? perf_trace_initcall_level+0x410/0x405
> >>>>> [   24.407342]  kernel_init_freeable+0x551/0x673
> >>>>> [   24.407342]  ? start_kernel+0x94b/0x94b
> >>>>> [   24.407342]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
> >>>>> [   24.407342]  ? __kasan_check_write+0x14/0x16
> >>>>> [   24.407342]  ? rest_init+0xe6/0xe6
> >>>>> [   24.407342]  kernel_init+0x16/0x1bd
> >>>>> [   24.407342]  ? rest_init+0xe6/0xe6
> >>>>> [   24.407342]  ret_from_fork+0x2b/0x36
> >>>>> [   24.407342]
> >>>>> [   24.407342] The buggy address belongs to the page:
> >>>>> [   24.407342] page:ffffea0002f91480 refcount:0 mapcount:0
> >>>>> mapping:0000000000000000 index:0x1
> >>>>> [   24.407342] flags: 0xfffffc0000000()
> >>>>> [   24.407342] raw: 000fffffc0000000 ffffea0002fca588
> >>>>> ffffea0002fb1a88 0000000000000000
> >>>>> [   24.407342] raw: 0000000000000001 0000000000000000
> >>>>> 00000000ffffffff 0000000000000000
> >>>>> [   24.407342] page dumped because: kasan: bad access detected
> >>>>> [   24.407342]
> >>>>> [   24.407342] Memory state around the buggy address:
> >>>>> [   24.407342]  ffff8880be451f00: ff ff ff ff ff ff ff ff ff ff ff
> >>>>> ff ff ff ff ff
> >>>>> [   24.407342]  ffff8880be451f80: ff ff ff ff ff ff ff ff ff ff ff
> >>>>> ff ff ff ff ff
> >>>>> [   24.407342] >ffff8880be452000: ff ff ff ff ff ff ff ff ff ff ff
> >>>>> ff ff ff ff ff
> >>>>> [   24.407342]                    ^
> >>>>> [   24.407342]  ffff8880be452080: ff ff ff ff ff ff ff ff ff ff ff
> >>>>> ff ff ff ff ff
> >>>>> [   24.407342]  ffff8880be452100: ff ff ff ff ff ff ff ff ff ff ff
> >>>>> ff ff ff ff ff
> >>>>> [   24.407342]
> >>>>> ==================================================================
> >>>>> [   24.407342] Disabling lock debugging due to kernel taint
> >>>>> [   24.451021] Kernel panic - not syncing: panic_on_warn set ...
> >>>>> [   24.452002] CPU: 1 PID: 1 Comm: swapper/0 Tainted: G B
> >>>>> 5.4.17-2102.200.0.0.20210106_0000.syzk #1
> >>>>> [   24.452002] Hardware name: QEMU Standard PC (i440FX + PIIX,
> >>>>> 1996), BIOS 0.0.0 02/06/2015
> >>>>> [   24.452002] Call Trace:
> >>>>> [   24.452002]  dump_stack+0xd4/0x119
> >>>>> [   24.452002]  ? ibft_init+0x102/0xb8b
> >>>>> [   24.452002]  panic+0x28f/0x6e0
> >>>>> [   24.452002]  ? __warn_printk+0xe0/0xe0
> >>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.452002]  ? add_taint+0x68/0xb3
> >>>>> [   24.452002]  ? add_taint+0x68/0xb3
> >>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.452002]  end_report+0x4c/0x54
> >>>>> [   24.452002]  __kasan_report.cold.9+0x55/0x77
> >>>>> [   24.452002]  ? ibft_init+0x134/0xb8b
> >>>>> [   24.452002]  kasan_report+0x14/0x1b
> >>>>> [   24.452002]  __asan_report_load_n_noabort+0xf/0x11
> >>>>> [   24.452002]  ibft_init+0x134/0xb8b
> >>>>> [   24.452002]  ? dmi_sysfs_init+0x1a5/0x1a5
> >>>>> [   24.452002]  ? dmi_walk+0x72/0x89
> >>>>> [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
> >>>>> [   24.452002]  ? rvt_init_port+0x110/0x101
> >>>>> [   24.452002]  ? ibft_check_initiator_for+0x159/0x159
> >>>>> [   24.452002]  do_one_initcall+0xc3/0x44d
> >>>>> [   24.452002]  ? perf_trace_initcall_level+0x410/0x405
> >>>>> [   24.452002]  kernel_init_freeable+0x551/0x673
> >>>>> [   24.452002]  ? start_kernel+0x94b/0x94b
> >>>>> [   24.452002]  ? __sanitizer_cov_trace_const_cmp1+0x1a/0x1c
> >>>>> [   24.452002]  ? __kasan_check_write+0x14/0x16
> >>>>> [   24.452002]  ? rest_init+0xe6/0xe6
> >>>>> [   24.452002]  kernel_init+0x16/0x1bd
> >>>>> [   24.452002]  ? rest_init+0xe6/0xe6
> >>>>> [   24.452002]  ret_from_fork+0x2b/0x36
> >>>>> [   24.452002] Dumping ftrace buffer:
> >>>>> [   24.452002] ---------------------------------
> >>>>> [   24.452002] swapper/-1         1.... 24564337us : rdmaip_init:
> >>>>> 2924: rdmaip_init: Active Bonding is DISABLED
> >>>>> [   24.452002] ---------------------------------
> >>>>> [   24.452002] Kernel Offset: disabled
> >>>>> [   24.452002] Rebooting in 1 seconds..
> >>>>>
> >>>>> Why does KASAN think the address is freed? For that to happen that
> >>>>> memory should have been freed. I don't remember any similar false
> >>>>> positives from KASAN, so this looks a bit suspicious.
> >>>>>
> >>>>> I'm not sure why KASAN thinks the address is freed. There are
> >>>>> other modules where KASAN/KCOV is disabled on boot.
> >>>>> Could this be for a similar reason?
> >>>> Most of these files are disabled because they cause recursion in
> >>>> instrumentation, or execute too early in bootstrap process (before
> >>>> kasan_init).
> >>>>
> >>>> Somehow the table pointer in ibft_init points to a freed page. I
> >>>> tracked it down to here:
> >>>> https://elixir.bootlin.com/linux/v5.4.17/source/drivers/acpi/acpica/tbutils.c#L399
> >>>>
> >>>> but I can't find where this table_desc->pointer comes from. Perhaps it
> >>> It is what the BIOS generated. It usually points to some memory
> >>> location in right under 4GB and the BIOS stashes the DSDT, iBFT, and
> >>> other tables in there.
> >>>
> >>>> uses some allocation method that's not supported by KASAN? However,
> >>>> it's the only such case that I've seen, so it's a bit weird. Could it
> >>>> use something like memblock_alloc? Or maybe that page was in fact
> >>>> freed?... Too bad KASAN does not print free stack for pages, maybe
> >>>> it's not too hard to do if CONFIG_PAGE_OWNER is enabled...
> >>> Hm, there is a comment in the acpi_get_table speaking about the
> >>> requirement of having a acpi_put_table and:
> >>>
> >>>
> >>>   * DESCRIPTION: Finds and verifies an ACPI table. Table must be in the
> >>>   *              RSDT/XSDT.
> >>>   *              Note that an early stage acpi_get_table() call must
> >>> be paired
> >>>   *              with an early stage acpi_put_table() call.
> >>> otherwise the table
> >>>   *              pointer mapped by the early stage mapping
> >>> implementation may be
> >>>   *              erroneously unmapped by the late stage unmapping
> >>> implementation
> >>>   *              in an acpi_put_table() invoked during the late stage.
> >>>   *
> >>>
> >>> Which would imply that I should use acpi_put_table in the error path
> >>> (see below a patch), but also copy the structure instead of depending
> >>> on ACPI keeping it mapped for me. I think.
> >> Hi Konrad,
> >>
> >> Thanks for looking into this.
> >> If ACPI unmaps this page, that would perfectly explain the KASAN report.
> >>
> >> George, does this patch eliminate the KASAN report for you?
> >
> > Hi Dmitry,
> >
> > No luck with the patch. Tried high level bisect instead. Here are the
> > results:
> >
> > BUG: KASAN: use-after-free in ibft_init+0x134/0xc49
> >
> > Bisect status:
> > v5.11-rc6 Sun Jan 31 13:50:09 2021 -0800     Failed
> > v5.11-rc1 Sun Dec 27 15:30:22 2020 -0800    Failed
> > v5.10 Sun Dec 13 14:41:30 2020 -0800           Failed
> > v5.10-rc6 Sun Nov 29 15:50:50 2020 -0800    Failed
> > v5.10-rc5 Sun Nov 22 15:36:08 2020 -0800    Failed
> > v5.10-rc4 Sun Nov 15 16:44:31 2020 -0800    Failed
> > v5.10-rc3 Sun Nov 8 16:10:16 2020 -0800      Failed
> > v5.10-rc2 Sun Nov 1 14:43:52 2020 -0800      Failed
> > v5.10-rc1 Sun Oct 25 15:14:11 2020 -0700     Failed
> > v5.9 Sun Oct 11 14:15:50 2020 -0700              OK - 10 reboots so
> > far w/o kasan failure
> >
> > So, will look at what changed between v5.9 and v5.10-rc1
>
> git bisect has identified the following as the offending commit:
>
> 2020-10-16 torvalds@linux-foundation.org - 7fef431 2020-10-15 David
> Hildenbrand mm/page_alloc: place pages to tail in __free_pages_core()

I think this suggests that this is a real use-after-free and the
page_alloc change just exposed a latent bug.

> Here's the commit that follows the above:
>
> 2020-10-16 torvalds@linux-foundation.org - 293ffa5 2020-10-15 David
> Hildenbrand mm/page_alloc: move pages to tail in move_to_free_list()
>
> With HEAD=7fef431 the KASAN crash occurs.
> With HEAD=293ffa5 no crash.
>
> With latest upstream (HEAD=dcc0b49) now getting this:
>
> [    1.759763] BUG: unable to handle page fault for address:
> ffff8880be453000
> [    1.761100] #PF: supervisor read access in kernel mode
> [    1.762106] #PF: error_code(0x0000) - not-present page
> [    1.763114] PGD 28c01067 P4D 28c01067 PUD 13fb01067 PMD 13f90e067 PTE
> 800fffff41bac060
> [    1.764672] Oops: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN PTI
> [    1.765731] CPU: 0 PID: 0 Comm: swapper/0 Not tainted
> 5.11.0-rc7-dcc0b49 #39
> [    1.767103] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
> BIOS 0.0.0 02/06/2015
> [    1.768665] RIP: 0010:acpi_tb_verify_checksum
> (drivers/acpi/acpica/tbprint.c:161)
> [    1.773301] RSP: 0000:ffffffff8fe07c78 EFLAGS: 00010246
> [    1.774330] RAX: 0000000000000003 RBX: ffff8880be453000 RCX:
> ffffffff839ab92c
> [    1.775718] RDX: 1ffff11017c8a600 RSI: ffffffff8fe3dec0 RDI:
> 0000000000000002
> [    1.777099] RBP: ffffffff8fe07c90 R08: 0000000000000000 R09:
> fffffbfff212ebfd
> [    1.778479] R10: ffffffff90975fe7 R11: fffffbfff212ebfc R12:
> 0000000000000800
> [    1.779864] R13: 0000000000000800 R14: dffffc0000000000 R15:
> 0000000000000000
> [    1.781245] FS:  0000000000000000(0000) GS:ffff88810a400000(0000)
> knlGS:0000000000000000
> [    1.782819] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    1.783941] CR2: ffff8880be453000 CR3: 0000000024e30000 CR4:
> 00000000000006b0
> [    1.785325] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
> 0000000000000000
> [    1.786709] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
> 0000000000000400
> [    1.788094] Call Trace:
> [    1.788595] acpi_tb_verify_temp_table (drivers/acpi/acpica/tbdata.c:499)
> [    1.789546] ? acpi_tb_validate_temp_table
> (drivers/acpi/acpica/tbdata.c:469)
> [    1.790536] ? __sanitizer_cov_trace_pc (kernel/kcov.c:197)
> [    1.791474] ? write_comp_data (kernel/kcov.c:218)
> [    1.792263] ? write_comp_data (kernel/kcov.c:218)
> [    1.793049] ? __sanitizer_cov_trace_pc (kernel/kcov.c:197)
> [    1.793983] ? write_comp_data (kernel/kcov.c:218)
> [    1.794766] acpi_reallocate_root_table
> (drivers/acpi/acpica/tbxface.c:182)
> [    1.795736] ? acpi_tb_parse_root_table
> (drivers/acpi/acpica/tbxface.c:134)
> [    1.796706] ? write_comp_data (kernel/kcov.c:218)
> [    1.797488] ? __sanitizer_cov_trace_pc (kernel/kcov.c:197)
> [    1.798422] acpi_early_init (drivers/acpi/bus.c:1050)
> [    1.799211] start_kernel (init/main.c:1023)
> [    1.799955] x86_64_start_reservations (arch/x86/kernel/head64.c:526)
> [    1.800875] x86_64_start_kernel (arch/x86/kernel/head64.c:507)
> [    1.801699] secondary_startup_64_no_verify
> (arch/x86/kernel/head_64.S:283)
> [    1.802709] Modules linked in:
> [    1.803324] Dumping ftrace buffer:
> [    1.804003]    (ftrace buffer empty)
> [    1.804707] CR2: ffff8880be453000
> [    1.805369] ---[ end trace fab88542288c30b6 ]---
> [    1.806272] RIP: 0010:acpi_tb_verify_checksum
> (drivers/acpi/acpica/tbprint.c:161)
> [ 1.807325] Code: da b8 ff ff 37 00 48 c1 e0 2a 48 c1 ea 03 8a 14 02 48
> 89 d8 83 e0 07 83 c0 03 38 d0 7c 0c 84 d2 74 08 48 89 df e8 c6 f8 1e fe
> <44> 8b 23 bf 53 33 50 54 44 89 e6 e8 f6 84 db fd 41 81 fc 53 33 50
> [    1.810904] RSP: 0000:ffffffff8fe07c78 EFLAGS: 00010246
> [    1.811930] RAX: 0000000000000003 RBX: ffff8880be453000 RCX:
> ffffffff839ab92c
> [    1.813312] RDX: 1ffff11017c8a600 RSI: ffffffff8fe3dec0 RDI:
> 0000000000000002
> [    1.814701] RBP: ffffffff8fe07c90 R08: 0000000000000000 R09:
> fffffbfff212ebfd
> [    1.816078] R10: ffffffff90975fe7 R11: fffffbfff212ebfc R12:
> 0000000000000800
> [    1.817458] R13: 0000000000000800 R14: dffffc0000000000 R15:
> 0000000000000000
> [    1.818841] FS:  0000000000000000(0000) GS:ffff88810a400000(0000)
> knlGS:0000000000000000
> [    1.820406] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [    1.821529] CR2: ffff8880be453000 CR3: 0000000024e30000 CR4:
> 00000000000006b0
> [    1.822918] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
> 0000000000000000
> [    1.824299] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
> 0000000000000400
> [    1.825680] Kernel panic - not syncing: Fatal exception
> [    1.827454] Dumping ftrace buffer:
> [    1.828122]    (ftrace buffer empty)
> [    1.828821] Rebooting in 1 seconds..
>
> Thank you,
> George
>
> >
> > Failure is intermittent, so takes a lot of retries.
> >
> > Thank you,
> > George
> >
> >>
> >>
> >>> CC-ing Rafeal.
> >>>
> >>>
> >>>  From c37da50fdfc62cd4f7b23562b55661478c90a17d Mon Sep 17 00:00:00 2001
> >>> From: Konrad Rzeszutek Wilk <konrad@darnok.org>
> >>> Date: Tue, 2 Feb 2021 17:28:28 +0000
> >>> Subject: [PATCH] ibft: Put ibft_addr back
> >>>
> >>> Signed-off-by: Konrad Rzeszutek Wilk <konrad@darnok.org>
> >>> ---
> >>>   drivers/firmware/iscsi_ibft.c | 19 +++++++++++++------
> >>>   1 file changed, 13 insertions(+), 6 deletions(-)
> >>>
> >>> diff --git a/drivers/firmware/iscsi_ibft.c
> >>> b/drivers/firmware/iscsi_ibft.c
> >>> index 7127a04..2a1a033 100644
> >>> --- a/drivers/firmware/iscsi_ibft.c
> >>> +++ b/drivers/firmware/iscsi_ibft.c
> >>> @@ -811,6 +811,10 @@ static void ibft_cleanup(void)
> >>>                  ibft_unregister();
> >>>                  iscsi_boot_destroy_kset(boot_kset);
> >>>          }
> >>> +       if (ibft_addr) {
> >>> +               acpi_put_table((struct acpi_table_header *)ibft_addr);
> >>> +               ibft_addr = NULL;
> >>> +       }
> >>>   }
> >>>
> >>>   static void __exit ibft_exit(void)
> >>> @@ -835,13 +839,15 @@ static void __init acpi_find_ibft_region(void)
> >>>   {
> >>>          int i;
> >>>          struct acpi_table_header *table = NULL;
> >>> +       acpi_status status;
> >>>
> >>>          if (acpi_disabled)
> >>>                  return;
> >>>
> >>>          for (i = 0; i < ARRAY_SIZE(ibft_signs) && !ibft_addr; i++) {
> >>> -               acpi_get_table(ibft_signs[i].sign, 0, &table);
> >>> -               ibft_addr = (struct acpi_table_ibft *)table;
> >>> +               status = acpi_get_table(ibft_signs[i].sign, 0, &table);
> >>> +               if (ACPI_SUCCESS(status))
> >>> +                       ibft_addr = (struct acpi_table_ibft *)table;
> >>>          }
> >>>   }
> >>>   #else
> >>> @@ -870,12 +876,13 @@ static int __init ibft_init(void)
> >>>
> >>>                  rc = ibft_check_device();
> >>>                  if (rc)
> >>> -                       return rc;
> >>> +                       goto out_free;
> >>>
> >>>                  boot_kset = iscsi_boot_create_kset("ibft");
> >>> -               if (!boot_kset)
> >>> -                       return -ENOMEM;
> >>> -
> >>> +               if (!boot_kset) {
> >>> +                       rc = -ENOMEM;
> >>> +                       goto out_free;
> >>> +               }
> >>>                  /* Scan the IBFT for data and register the
> >>> kobjects. */
> >>>                  rc = ibft_register_kobjects(ibft_addr);
> >>>                  if (rc)
> >>> --
> >>> 1.8.3.1
> >>>
> >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZe3J5L7vBt7hmqbMrxhRg%3Dk1hZkPTJpCG83Gc%3DWr-Fsg%40mail.gmail.com.
