Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBFX3XGIAMGQEJ7F3VIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 469F44BA672
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Feb 2022 17:53:43 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id u14-20020a05600c210e00b0037bddd0562esf1930341wml.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Feb 2022 08:53:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645116823; cv=pass;
        d=google.com; s=arc-20160816;
        b=xNuHpVligJjenAL+ZiCW+nfqmPMaD/zC0X92NVVgnPFlvXs/hlf+Ku4R5rSzV9a0H/
         yv779YFT6q+DyaUun7IZ00bAuvaBIRzYEtxIQNhXiUjKLVNshcaDKDjQ5VSeGPocpXgq
         /J4Pru0I+qKPTw85WT9E8sFchkDBgLivHM3VzJDMacLR3t0cGtmsBmVCd52vUbAkTsgB
         7KsKzqXW7h6I3uaTeEfd/P6MaNKeLo1sJrHgmgJX2B9w0JISWI7v1iU+H3R5IKig5bqW
         OtFkUfV3Et62bAxkZSX7ZvLNlSoRtQlv0MIFomyMpnq/vetkPbqFTUfH6yTlTscXdS3S
         2FkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=s+7/B0ZYMo+OMwJ7RLbE5B2XlPX4nF5+HQnEYnuHsNs=;
        b=kDJQB8UNo5gR28bOU2n1kD2yxU5wu88f5srvnS0ubsixxAMNqiTd+YF0keWa8apjSg
         3cSODrtgVMah3kAUAEDipNusje+FQ6aU3qisnZkpqVQWOgSLxWwXEWeNb9QKAQlzrb+q
         86XozLH3dHOmDW8ZH//cmJOjauGaePFnxjX307DwE4NxuPvv38CemykymOEKkpEjNaQv
         MNtiwB+48QoCEHo+AH2W2EdMzn6LV9KbJtNHuNezXcLXYhNqTiidOtlhsDjxSD+8MuAE
         IgiEW+iP1pKUJE93JZ3NF5keC0UmbHnPMP8rLHwoNBbq585WEn/D04Xh/A78srJ+DSRd
         xS6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=YelvD+8r;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s+7/B0ZYMo+OMwJ7RLbE5B2XlPX4nF5+HQnEYnuHsNs=;
        b=RBKFO6oMwxmqOBMN7izKYkbwjA8QIk4Sl9Xgbf4J7H11maUZiYRp+936de3jzNDpfA
         AxPkFQZcMrwNGnB5jrb8lrnVeCB8RbWunMovWmulskzixvJW83h0sgsvH0xOUAObRooU
         61LwuZj23fBbR1IamdfJH7PaSrP8JkTMoIYJQJy5sGt1Lem2IZHkAhC+bAbZbPofXIT+
         jpp3Bc1OE5x8SzsUg5zUonwDZUS3tQk5pF+0hIVwyW6eV35CfYZjAqRcmMeASedQ1uSD
         I8C7REfHFN/8UMZmZSbBYEuscIyu8C6pVpu55suocN1J6NdjHOiJ7Wgkavycj3tG9hKr
         ugLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s+7/B0ZYMo+OMwJ7RLbE5B2XlPX4nF5+HQnEYnuHsNs=;
        b=FQAe5uGbSTJtu15mVLN1ppsLEYULnfoKn5RSRDD6wTQ/u0jVkQlrL38gtzVWOH0cFV
         JHYLv1rXSazofEJ+gQZIRRrfpR1IX2WMZhtLAzGVf7ldOK6idt/WquX/3wScbGGnoKOs
         0fBYrmk3QUHM7rlewoQ6BqKV/jhT5/4q4UMh62Z8CeVlpItbbILqu65YwQPDtw5T+tV0
         Xf7YDsJ02r4YLHgopS86OAHa/MxYhPQs2tdV3CpWYtGJWh2Vu07ilCSVFng+g//UeqGl
         N63e2v9pEdK7HNwXTc4fotfkzG/EyEyiB6WNnevagLNXfB6elHpFQfXYSXyO6vqBIU0M
         HXKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Z/1JB72TJRs0II+nx3/Gb8vIWdmS8CoHNsWeT015wyn9J08Pc
	LsvwrKPIRPFIx47epqEa0Ow=
X-Google-Smtp-Source: ABdhPJzG6wzVfZEeiyvQQqZu5K/H8tdDAj8C/kUX+EL1cKafKQ/PwqIFIY8yxGbBvJSaVvT38phSHQ==
X-Received: by 2002:a05:600c:4ed1:b0:37b:bb72:9ecd with SMTP id g17-20020a05600c4ed100b0037bbb729ecdmr3416279wmq.177.1645116822881;
        Thu, 17 Feb 2022 08:53:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d9a:b0:37b:f94b:3486 with SMTP id
 bi26-20020a05600c3d9a00b0037bf94b3486ls78781wmb.0.experimental-gmail; Thu, 17
 Feb 2022 08:53:41 -0800 (PST)
X-Received: by 2002:a05:600c:4f03:b0:37c:b58:9c35 with SMTP id l3-20020a05600c4f0300b0037c0b589c35mr6731653wmq.118.1645116821833;
        Thu, 17 Feb 2022 08:53:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645116821; cv=none;
        d=google.com; s=arc-20160816;
        b=w9tc4iAxnvNUx96flwIEYvy4R6AxHxqC4tV1qASAHFtPpOhtLQDFA3p4EbZgSua7Q4
         oSEcvNDkqk3TGIi1n/3Vk1JxzIUC3qC/L4Ap3eLK+1KgEEHEO1+0emfuqCENUAqdgDQw
         caOlLxCGeAYQk5nnGApBCZBT5ItQkfzoh+Xk/za51HtJmVwHUSHn4lkMBfltDiXIWjhF
         QDA4s52wtq/++smoYW6Nfhnpnb9KoFEsFzy9Lt3do6PUXOdJcc+W/xSgE9ykWXlsVDgo
         WeQo59nzyJtduEJN3j+NCrIEbdr2GbMajUbg9uuI3WlzO43Ag14KwcW70FrgN27f3C10
         7CTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Whof+L8GAE6TRZ8kVWtcGS7H+uijkpwIOjnhSmI6YY=;
        b=pfXyKL0NMjdGjZ6T5/tr/03yYU4eU3ndJxgc75MM+yzUv1wPmu/M36nYSMZcnYoQtj
         pj1I/2tFNKVAMuynSVn866ReNP/5mmCUdwPl5M4HUdOIC3DEw2fuDPW65nprcyRJ6MSa
         rXCw+6G9pqWkzpL24Fc1/jLotbBspuygP3TzjNlWTXGfVUHrnLcD+a6dT0z2iySOyY+6
         V1z808ZRYzF80ee5vSpOaIs174lFAQ64Kdy5w8mpvZpDA4qSICkKOQc9PLXN804QMWNS
         si+IPUwwSyRcDONopNpe6LeGUsOhHq9XAJTtpfNUuTLzm9GBIgtM/p6fz1/WptpYRWP/
         /NkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=YelvD+8r;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id y17si106634wmi.2.2022.02.17.08.53.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Feb 2022 08:53:41 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 800F740338
	for <kasan-dev@googlegroups.com>; Thu, 17 Feb 2022 16:53:41 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id m11-20020a056402430b00b00410678d119eso3854471edc.21
        for <kasan-dev@googlegroups.com>; Thu, 17 Feb 2022 08:53:41 -0800 (PST)
X-Received: by 2002:a05:6402:5110:b0:403:dbc0:2a47 with SMTP id m16-20020a056402511000b00403dbc02a47mr3685313edd.197.1645116820118;
        Thu, 17 Feb 2022 08:53:40 -0800 (PST)
X-Received: by 2002:a05:6402:5110:b0:403:dbc0:2a47 with SMTP id
 m16-20020a056402511000b00403dbc02a47mr3685291edd.197.1645116819915; Thu, 17
 Feb 2022 08:53:39 -0800 (PST)
MIME-Version: 1.0
References: <00000000000038779505d5d8b372@google.com> <CANp29Y7WjwXwgxPrNq0XXjXPu+wGFqTreh9gry=O6aE7+cKpLQ@mail.gmail.com>
 <CA+zEjCvu76yW7zfM+qJUe+t5y23oPdzR4KDV1mOdqH8bB4GmTw@mail.gmail.com>
 <CACT4Y+arufrRgwmN66wUU+_FGxMy-sTkjMQnRN8U2H2tQuhB7A@mail.gmail.com>
 <a0769218-c84a-a1d3-71e7-aefd40bf54fe@ghiti.fr> <CANp29Y4WMhsE_-VWvNbwq18+qvb1Qc-ES80h_j_G-N_hcAnRAw@mail.gmail.com>
 <CANp29Y4ujmz901aE9oiBDx9dYWHti4-Jw=6Ewtotm6ck6MN9FQ@mail.gmail.com>
 <CACT4Y+ZvStiHLYBOcPDoAJnk8hquXwm9BgjQTv=APwh7AvgEUQ@mail.gmail.com>
 <CANp29Y56Or0V1AG7rzBfV_ZTph2Crg4JKKHiuw1kcGFFxeWqiQ@mail.gmail.com>
 <CANp29Y5+MuhKAzVxzEDb_k9voXmKWrUFx8k4wnW5=2+5enVFVA@mail.gmail.com> <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com>
In-Reply-To: <CA+zEjCtvaT0YsxxUgnEGM+V4b5sWuCAs3=3J+Xocf580uT3t1g@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 17 Feb 2022 17:53:28 +0100
Message-ID: <CA+zEjCs1FEUTcM+pgV+_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg@mail.gmail.com>
Subject: Re: [syzbot] riscv/fixes boot error: can't ssh into the instance
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	syzbot <syzbot+330a558d94b58f7601be@syzkaller.appspotmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=YelvD+8r;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

Aleksandr,

On Wed, Feb 16, 2022 at 5:58 PM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> First, thank you for working on this.
>
> On Wed, Feb 16, 2022 at 5:17 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > If I use just defconfig + DEBUG_VIRTUAL, without any KASAN, it begins
> > to boot, but overwhelms me with tons of `virt_to_phys used for
> > non-linear address:` errors.
> >
> > Like that
> >
> > [    2.701271] virt_to_phys used for non-linear address:
> > 00000000b59e31b6 (0xffffffff806c2000)
> > [    2.701727] WARNING: CPU: 0 PID: 1 at arch/riscv/mm/physaddr.c:16
> > __virt_to_phys+0x7e/0x86
> > [    2.702207] Modules linked in:
> > [    2.702393] CPU: 0 PID: 1 Comm: swapper/0 Tainted: G        W
> >   5.17.0-rc1 #1
> > [    2.702806] Hardware name: riscv-virtio,qemu (DT)
> > [    2.703051] epc : __virt_to_phys+0x7e/0x86
> > [    2.703298]  ra : __virt_to_phys+0x7e/0x86
> > [    2.703547] epc : ffffffff80008448 ra : ffffffff80008448 sp :
> > ffff8f800021bde0
> > [    2.703977]  gp : ffffffff80ed9b30 tp : ffffaf8001230000 t0 :
> > ffffffff80eea56f
> > [    2.704704]  t1 : ffffffff80eea560 t2 : 0000000000000000 s0 :
> > ffff8f800021be00
> > [    2.705153]  s1 : ffffffff806c2000 a0 : 000000000000004f a1 :
> > ffffffff80e723d8
> > [    2.705555]  a2 : 0000000000000010 a3 : fffffffffffffffe a4 :
> > 0000000000000000
> > [    2.706027]  a5 : 0000000000000000 a6 : 0000000000000005 a7 :
> > ffffffffffffffff
> > [    2.706474]  s2 : ffffffff80b80b08 s3 : 00000000000000c2 s4 :
> > ffffffff806c2000
> > [    2.706891]  s5 : ffffffff80edba10 s6 : ffffffff80edb960 s7 :
> > 0000000000000001
> > [    2.707290]  s8 : 00000000000000ff s9 : ffffffff80b80b40 s10:
> > 00000000000000cc
> > [    2.707689]  s11: ffffaf807e1fcf00 t3 : 0000000000000076 t4 :
> > ffffffffffffffff
> > [    2.708092]  t5 : 00000000000001f2 t6 : ffff8f800021bb48
> > [    2.708433] status: 0000000000000120 badaddr: 0000000000000000
> > cause: 0000000000000003
> > [    2.708919] [<ffffffff8011416a>] free_reserved_area+0x72/0x19a
> > [    2.709296] [<ffffffff80003a5a>] free_initmem+0x6c/0x7c
> > [    2.709648] [<ffffffff805f60c8>] kernel_init+0x3a/0x10a
> > [    2.709993] [<ffffffff80002fda>] ret_from_exception+0x0/0xc
> > [    2.710310] ---[ end trace 0000000000000000 ]---
> >
>
> I was able to reproduce this: the first one regarding init_zero_pfn is
> legit but not wrong, I have to check when it was introduced and how to
> fix this.
> Regarding the huge batch that follows, at first sight, I would say
> this is linked to my sv48 patchset but that does not seem important as
> the address is a kernel mapping address so the use of virt_to_phys is
> right.
>
> > On Wed, Feb 16, 2022 at 5:09 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > >
> > > On Wed, Feb 16, 2022 at 12:56 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > >
> > > > On Wed, 16 Feb 2022 at 12:47, Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > >
> > > > > On Wed, Feb 16, 2022 at 11:37 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > >
> > > > > > Hi Alex,
> > > > > >
> > > > > > On Wed, Feb 16, 2022 at 5:14 AM Alexandre Ghiti <alex@ghiti.fr> wrote:
> > > > > > >
> > > > > > > Hi Dmitry,
> > > > > > >
> > > > > > > On 2/15/22 18:12, Dmitry Vyukov wrote:
> > > > > > > > On Wed, 2 Feb 2022 at 14:18, Alexandre Ghiti
> > > > > > > > <alexandre.ghiti@canonical.com> wrote:
> > > > > > > >> Hi Aleksandr,
> > > > > > > >>
> > > > > > > >> On Wed, Feb 2, 2022 at 12:08 PM Aleksandr Nogikh <nogikh@google.com> wrote:
> > > > > > > >>> Hello,
> > > > > > > >>>
> > > > > > > >>> syzbot has already not been able to fuzz its RISC-V instance for 97
> > > > > > > >> That's a longtime, I'll take a look more regularly.
> > > > > > > >>
> > > > > > > >>> days now because the compiled kernel cannot boot. I bisected the issue
> > > > > > > >>> to the following commit:
> > > > > > > >>>
> > > > > > > >>> commit 54c5639d8f507ebefa814f574cb6f763033a72a5
> > > > > > > >>> Author: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > > > > > >>> Date:   Fri Oct 29 06:59:27 2021 +0200
> > > > > > > >>>
> > > > > > > >>>      riscv: Fix asan-stack clang build
> > > > > > > >>>
> > > > > > > >>> Apparently, the problem appears on GCC-built RISC-V kernels with KASAN
> > > > > > > >>> enabled. In the previous message syzbot mentions
> > > > > > > >>> "riscv64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU
> > > > > > > >>> Binutils for Debian) 2.35.2", but the issue also reproduces finely on
> > > > > > > >>> a newer GCC compiler: "riscv64-linux-gnu-gcc (Debian 11.2.0-10)
> > > > > > > >>> 11.2.0, GNU ld (GNU Binutils for Debian) 2.37".
> > > > > > > >>> For convenience, I also duplicate the .config file from the bot's
> > > > > > > >>> message: https://syzkaller.appspot.com/x/.config?x=522544a2e0ef2a7d
> > > > > > > >>>
> > > > > > > >>> Can someone with KASAN and RISC-V expertise please take a look?
> > > > > > > >> I'll take a look at that today.
> > > > > > > >>
> > > > > > > >> Thanks for reporting the issue,
> > > > > > > >
> > > > > > >
> > > > > > > I took a quick look, not enough to fix it but I know the issue comes
> > > > > > > from the inline instrumentation, I have no problem with the outline
> > > > > > > instrumentation. I need to find some cycles to work on this, my goal is
> > > > > > > to fix this for 5.17.
> > > > > >
> > > > > > Thanks for the update!
> > > > > >
> > > > > > Can you please share the .config with which you tested the outline
> > > > > > instrumentation?
> > > > > > I updated the syzbot config to use KASAN_OUTLINE instead of KASAN_INLINE,
> > > > > > but it still does not boot :(
> > > > > >
> > > > > > Here's what I used:
> > > > > > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > > > >
> > > > > Update: it doesn't boot with that big config, but boots if I generate
> > > > > a simple one with KASAN_OUTLINE:
> > > > >
> > > > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > > ./scripts/config -e KASAN -e KASAN_OUTLINE
> > > > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > > >
> > > > > And it indeed doesn't work if I use KASAN_INLINE.
> > > >
> > > > It may be an issue with code size. Full syzbot config + KASAN + KCOV
> > > > produce hugely massive .text. It may be hitting some limitation in the
> > > > bootloader/kernel bootstrap code.
>
> I took a quick glance and it traps on a KASAN address that is not
> mapped, either because it is too soon or because the mapping failed
> somehow.
>
> I'll definitely dive into that tomorrow, sorry for being slow here and
> thanks again for all your work, that helps a lot.
>
> Thanks,
>
> Alex
>
> > >
> > > I bisected the difference between the config we use on syzbot and the
> > > simple one that was generated like I described above.
> > > Turns out that it's the DEBUG_VIRTUAL config that makes the difference.
> > >
> > > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > > ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > >
> > > And the resulting kernel does not boot.
> > > My env: the `riscv/fixes` branch, commit
> > > 6df2a016c0c8a3d0933ef33dd192ea6606b115e3, qemu 6.2.0.

I fixed a few things today: KASAN + SPARSE_VMEMMAP, DEBUG_VIRTUAL and
maybe KASAN  + KCOV.

With those small fixes, I was able to boot your large dotconfig with
KASAN_OUTLINE, the inline version still fails, this is my next target
:)
I'll push that tomorrow!

Thanks again,

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCs1FEUTcM%2BpgV%2B_MZnixSO5c2hexZFxGxuCQWc2ZMQiRg%40mail.gmail.com.
