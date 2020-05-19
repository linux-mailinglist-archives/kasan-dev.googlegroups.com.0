Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6ODR73AKGQEWM3OS7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B1661D9802
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 15:41:15 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id v87sf13152444ill.23
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 06:41:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589895673; cv=pass;
        d=google.com; s=arc-20160816;
        b=JbW8QGsLYh9Polu9kJX4bhFVcLDmDJuoWaFssBIIniVmoYBxRtf/G9amfIVkNZmX55
         Cw3jLvFI9Ihyt3If8Yle7KiFQPg8hvGk0qiVc+QdTVAwTVzctbvKxaNi9PB/gqaBdT+y
         5ko2kHWS/BZcjR6miAglnayzUfbcET7zGoMPJKwFgKaALp4LYFJ0bvRSSGekxIDP401F
         EyM3jUruPHeLj7Ha3L46kCLpp9yZF6LiAyz8MmqQGezVSaMabQcQkej/05aLXvd3zoRP
         HvT7gzv/2992KrGlM5CAP3Daq4GReOmkAcH750mwzDnZajCpugoI81JBCZQcoNZ0VHlr
         WmJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+noN1a56kN1NbpEwUEjUFaZbbY2qIkJKwGwPgwGjXwQ=;
        b=yf4OIZJgkHpry0uO22kTm39xf0Gv1tSbc1l6UwaAa67pHjNwmQRIJxBmQG4zEKQ6Uf
         7RzIYlI0LesgZgran5nCGKYJbYV0gsBzFXB/+UsW/FKOYB4hrYt9ixdBCipyZQGAc9+F
         ueg30VibuD589K2/l3aKNMQdo1GnY1r8fKNnTVSRd9oiej+F/34oiq2JOVSaGEy4/oGw
         hNHDGT5ny7fQhZwiF6jS5nlwhvT53JLKJ1HVkikheB/3lEb3P9Ux4r4Jzffhzi/B1ZSJ
         c7tthup0wSmovYEFX5fwjHHJ1A6fyZZ7Wl72qoICgUNLxDsEFsUgtlRue/Wp6SutUkX5
         Cs/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nrtXpzxk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+noN1a56kN1NbpEwUEjUFaZbbY2qIkJKwGwPgwGjXwQ=;
        b=WQ1NaqiUrLi1BgD3Ubkk/fIveawGAI2IQQrsklwG7gkEYuMKzJZGpxrBaYrfS8XHf8
         ZQZAJCr4S+whuRFbcHJuEmuqX2BsWq78/OpfUJsbca+ujzphyXwiAR7Uq7cFzEYh4QYT
         s8FubWcFemJV9OQuKltvk9LDLZrIfEck6DQSjja+o3mauxdc9M2USi748unre/DvTD+K
         mOZyuOJUbBfDEyJjR/eBRukcTnFxDnyRwhLD9e0B0Zio6zHdOxmGmgDd0bSBQEi3AL5V
         pZ9LD8A9shOeYN7nzXrVar+UTGDJSPjzGv6tN4pLJzHHjuPHiFV3m8iuCurj/s6uPDjF
         9dxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+noN1a56kN1NbpEwUEjUFaZbbY2qIkJKwGwPgwGjXwQ=;
        b=l5GKm5n3B8JtPSkS7GowmelATCI4Cw305zHFX/DXK/MgUi1joKbgW3oG+i6ZrXVGrp
         FV2aCW6/FEWcG7q9qjht7lS2kVyrLbEUTxaYzun/LxueNWi7iTKP9dinP6d9JRcCBaWJ
         wEJJqFkulaGc8u4m0DX6DvCz3K5Bh4DfXX+ZkAX2sBkM4IbWYDtLGLh8Btnc635SX5U2
         aOgrGkXL4IBt+c2E9QI8I8EnEHEgG18G6t2ji7DOKEthSumR4Gox/n9ddSPohcJoHdm4
         I+MuK8ZwOopvFl5xN0uV6p4nNbRLK57sRsXLgBFcutJ8waaVvfJeNafHegl/JmcgAoiN
         1IXg==
X-Gm-Message-State: AOAM532Lj4p63mFd6CUDwVqFQR1zFJgxlYiMa42Oyb8xdAHarikZr9dS
	cF72To+m9VBogFz56h3zjKM=
X-Google-Smtp-Source: ABdhPJx82aNYYHBT2XQN925oe62MR3EUzEiKN9PAXMu/tbftj5tGMa9WmxEUioaB4s8G2GiR7atXFg==
X-Received: by 2002:a05:6638:5a2:: with SMTP id b2mr21127221jar.59.1589895673632;
        Tue, 19 May 2020 06:41:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:da05:: with SMTP id z5ls3420710ilm.10.gmail; Tue, 19 May
 2020 06:41:13 -0700 (PDT)
X-Received: by 2002:a92:1b0d:: with SMTP id b13mr22234784ilb.232.1589895673050;
        Tue, 19 May 2020 06:41:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589895673; cv=none;
        d=google.com; s=arc-20160816;
        b=s4/U5fy1StjpY1XQtzZVVbjPc4oIJiG1BJ7Chimmenl5Xso7Xhk1Ugf8ANNV1XaN/6
         XxCWr5tjKAognuJSInr2AYgfY5LrCqyVCGqw8Hi2P9DAE6vpoMB6spUUqp29v94EhVdO
         pOglnRG/fJgaXwRnHfAdiTcT9JkGI6vThlsALuJ49D0B+gtFg6g2sE4C761GLgwplVHS
         LzBgj4phQltBijxkyg7yb0W5lFYzpUzPPrDoq7LLziTh+BL51t+FmVsLPllF/qyQsrFp
         G5uvMo7x3XsvRWzKCreKU36MXWGQByYUJlD6cthu4hXyY79m03dBvsFeW2l0txTYwoDt
         sQGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OJ0/X+KDsYJg8CyaNbUZIzyGPtenDDvVDD3jODmVGao=;
        b=GV6hacXbGzVvEJJ9qQ/GOrkdt85Jn3ZTDbj6VImues0QSejt1DuGl/z/Qun60EX3P9
         HZpkCs+GfgK4aggV/OhGpJH6GopeQq4c+KnPGbpduS3h6iyem39sI/KWwhA246/GxmvQ
         UpilcwhZEB/CSIsxFcdTeXaqBwv0Sb8zwXBwbuE1z/Cgzlpt9m8lF+1PY2b2oxA0OHCq
         xOKP+tmWIlYC1mdq9f6PWCrybkm5+pa8DQ5KnBfWtAXP51LTheEnIFbiihHJ916q7Qky
         2eVtTSNIpAjbT/vRQUZQY/tBmK5Wz6j9lNF1erw/z4y3pe9MmNHHLzlMS5XMUYmLSjG3
         TW+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nrtXpzxk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id n1si630028ilm.1.2020.05.19.06.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 06:41:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id v128so12306878oia.7
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 06:41:13 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr3278271oih.70.1589895672315;
 Tue, 19 May 2020 06:41:12 -0700 (PDT)
MIME-Version: 1.0
References: <20200517011732.GE24705@shao2-debian> <20200517034739.GO2869@paulmck-ThinkPad-P72>
 <CANpmjNNj37=mgrZpzX7joAwnYk-GsuiE8oOm13r48FYAK0gSQw@mail.gmail.com>
 <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com>
 <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
 <CAKwvOd=Gi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w@mail.gmail.com>
 <20200518180513.GA114619@google.com> <CANpmjNMTRO0TxxTQxFt8EaRLggcPXKLJL2+G2WFL+vakgd2OUg@mail.gmail.com>
In-Reply-To: <CANpmjNMTRO0TxxTQxFt8EaRLggcPXKLJL2+G2WFL+vakgd2OUg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 May 2020 15:40:59 +0200
Message-ID: <CANpmjNO0kDVW4uaLcOF95L3FKc8WjawJqXKQtYbCad+W2r=75g@mail.gmail.com>
Subject: Re: [rcu] 2f08469563: BUG:kernel_reboot-without-warning_in_boot_stage
To: Nick Desaulniers <ndesaulniers@google.com>, george.burgess.iv@gmail.com
Cc: Kan Liang <kan.liang@linux.intel.com>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel test robot <rong.a.chen@intel.com>, Peter Zijlstra <peterz@infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, LKP <lkp@lists.01.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nrtXpzxk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Tue, 19 May 2020 at 12:16, Marco Elver <elver@google.com> wrote:
>
> On Mon, 18 May 2020 at 20:05, Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 18 May 2020, 'Nick Desaulniers' via kasan-dev wrote:
> >
> > > On Mon, May 18, 2020 at 7:34 AM Marco Elver <elver@google.com> wrote:
> > > >
> > > > On Mon, 18 May 2020 at 14:44, Marco Elver <elver@google.com> wrote:
> > > > >
> > > > > [+Cc clang-built-linux FYI]
> > > > >
> > > > > On Mon, 18 May 2020 at 12:11, Marco Elver <elver@google.com> wrote:
> > > > > >
> > > > > > On Sun, 17 May 2020 at 05:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > > >
> > > > > > > On Sun, May 17, 2020 at 09:17:32AM +0800, kernel test robot wrote:
> > > > > > > > Greeting,
> > > > > > > >
> > > > > > > > FYI, we noticed the following commit (built with clang-11):
> > > > > > > >
> > > > > > > > commit: 2f08469563550d15cb08a60898d3549720600eee ("rcu: Mark rcu_state.ncpus to detect concurrent writes")
> > > > > > > > https://git.kernel.org/cgit/linux/kernel/git/paulmck/linux-rcu.git dev.2020.05.14c
> > > > > > > >
> > > > > > > > in testcase: boot
> > > > > > > >
> > > > > > > > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 8G
> > > > > > > >
> > > > > > > > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > > > > > > >
> > > > > > > >
> > > > > > > >
> > > > > > > >
> > > > > > > > If you fix the issue, kindly add following tag
> > > > > > > > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > > > > > > >
> > > > > > > >
> > > > > > > > [    0.054943] BRK [0x05204000, 0x05204fff] PGTABLE
> > > > > > > > [    0.061181] BRK [0x05205000, 0x05205fff] PGTABLE
> > > > > > > > [    0.062403] BRK [0x05206000, 0x05206fff] PGTABLE
> > > > > > > > [    0.065200] RAMDISK: [mem 0x7a247000-0x7fffffff]
> > > > > > > > [    0.067344] ACPI: Early table checksum verification disabled
> > > > > > > > BUG: kernel reboot-without-warning in boot stage
> > > > > > >
> > > > > > > I am having some difficulty believing that this commit is at fault given
> > > > > > > that the .config does not list CONFIG_KCSAN=y, but CCing Marco Elver
> > > > > > > for his thoughts.  Especially given that I have never built with clang-11.
> > > > > > >
> > > > > > > But this does invoke ASSERT_EXCLUSIVE_WRITER() in early boot from
> > > > > > > rcu_init().  Might clang-11 have objections to early use of this macro?
> > > > > >
> > > > > > The macro is a noop without KCSAN. I think the bisection went wrong.
> > > > > >
> > > > > > I am able to reproduce a reboot-without-warning when building with
> > > > > > Clang 11 and the provided config. I did a bisect, starting with v5.6
> > > > > > (good), and found this:
> > > > > > - Since v5.6, first bad commit is
> > > > > > 20e2aa812620439d010a3f78ba4e05bc0b3e2861 (Merge tag
> > > > > > 'perf-urgent-2020-04-12' of
> > > > > > git://git.kernel.org/pub/scm/linux/kernel//git/tip/tip)
> > > > > > - The actual commit that introduced the problem is
> > > > > > 2b3b76b5ec67568da4bb475d3ce8a92ef494b5de (perf/x86/intel/uncore: Add
> > > > > > Ice Lake server uncore support) -- reverting it fixes the problem.
> > > >
> > > > Some more clues:
> > > >
> > > > 1. I should have noticed that this uses CONFIG_KASAN=y.
> > >
> > > Thanks for the report, testing, and bisection.  I don't see any
> > > smoking gun in the code.
> > > https://godbolt.org/z/qbK26r
> >
> > My guess is data layout and maybe some interaction with KASAN. I also
> > played around with leaving icx_mmio_uncores empty, meaning none of the
> > data it refers to end up in the data section (presumably because
> > optimized out), which resulted in making the bug disappear as well.
> >
> > > >
> > > > 2. Something about function icx_uncore_mmio_init(). Making it a noop
> > > > also makes the issue go away.
> > > >
> > > > 3. Leaving icx_uncore_mmio_init() a noop but removing the 'static'
> > > > from icx_mmio_uncores also presents the issue. So this seems to be
> > > > something about how/where icx_mmio_uncores is allocated.
> > >
> > > Can you share the disassembly of icx_uncore_mmio_init() in the given
> > > configuration?
> >
> > ffffffff8102c097 <icx_uncore_mmio_init>:
> > ffffffff8102c097:       e8 b4 52 bd 01          callq  ffffffff82c01350 <__fentry__>
> > ffffffff8102c09c:       48 c7 c7 e0 55 c3 83    mov    $0xffffffff83c355e0,%rdi
> > ffffffff8102c0a3:       e8 69 9a 3b 00          callq  ffffffff813e5b11 <__asan_store8>
> > ffffffff8102c0a8:       48 c7 05 2d 95 c0 02    movq   $0xffffffff83c388e0,0x2c0952d(%rip)        # ffffffff83c355e0 <uncore_mmio_uncores>
> > ffffffff8102c0af:       e0 88 c3 83
> > ffffffff8102c0b3:       c3                      retq
> >
> > The problem still happens if we add a __no_sanitize_address (or even
> > KASAN_SANITIZE := n) here. I think this function is a red herring: you
> > can make this function be empty, but as long as icx_mmio_uncores and its
> > dependencies are added to the data section somewhere, does the bug
> > appear.
>
> I also tried to bisect Clang/LLVM, and found that
> https://reviews.llvm.org/D78162 introduced the breaking change to
> Clang/LLVM. Reverting that change results in a bootable kernel *with*
> "perf/x86/intel/uncore: Add Ice Lake server uncore support" still
> applied.

I found that with Clang/LLVM change D78162, a bunch of memcpys are
optimized into just a bunch of loads/stores. It may turn out that this
is again a red herring, because the result is that more code is
generated, affecting layout. So in the end, the Clang/LLVM bisection
might just point at the first change that causes data layout to change
in a way that triggers the bug.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0kDVW4uaLcOF95L3FKc8WjawJqXKQtYbCad%2BW2r%3D75g%40mail.gmail.com.
