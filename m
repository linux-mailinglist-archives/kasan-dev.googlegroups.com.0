Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVWMSD3AKGQEYVKPQTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 677591D9F89
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 20:32:55 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id x26sf616676qvd.20
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 11:32:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589913174; cv=pass;
        d=google.com; s=arc-20160816;
        b=vzGtVAFo7JZ0uDPlHrUR5vqNg5Bp54/gKfNb1pOMyItDOG2LsbDgVEABr8oJGY9rae
         MCr70R60vOLTVrYPAiQboxPjEwux/61+8i5Z3uFunNwYQmVNFEoPdz3kcLTSoCYdDs8J
         ymMCcutNebqD/FcsdIIr4OrhmHjZx2Rtyf1TwbcLsTn14oQrbLRt5/Po6amVcfmR62qH
         y0WZbDTEcue/9kFabNjkKOxSIDHUmKe3lvqhsQ9/7P/N/Xsy39JmBToz3U7BJmg0OTJM
         80bK5tBkpk76sH6yKWYClZ+CKjq00ieoxUhKSHe4qwKIUu16cq3nDiReF/hi4V2XzIwP
         q5Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jTZ4Zyop1nU+pMD4vREy65Ac/TlnTU7vH7w//K9Wwhk=;
        b=bE2I5+lGfSTwW5Iu05xQOVsRPgzSoDL73INnYmTsJSRRu4MusvIR4n1YYhEHndKeAY
         /oq4yXORhWAK30/GXVVDbEc0/xOb0E0ge21AwZswhDuEj6ySZedVEXqe8GNGZHFVPbHb
         XtTnq1oQ6WvsuZhLVmh5Lfz6u4aoREfV5BxBWIMh9GZB0FpuzcNjEiVXWHwHVLvz7mSu
         dQqmxPeYy3t1vszM+p5JfLWH+PFPP5jlwLywE4SdlApNjC6RyhMU4ymmvK5G0X+bOJiC
         MsPPBBhu8S51blCyBeg9W7ayPhf9qFZuvL7kG9z1UXytDmh1BNvHF8HIT11wKitjfPOR
         4Amg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vJXKeOCN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jTZ4Zyop1nU+pMD4vREy65Ac/TlnTU7vH7w//K9Wwhk=;
        b=tF8P+bGXNVbkW/dRdjKuLs55Mcb68SJHI6St858EUL1Vfk5ebYKt2RRiBbRDmz3+r5
         QeyWAWIcW3q+8AVDogGM2gkU/TRxZuUZUcWpdL+ZAZ05RqYewUglwebeASGogP2q4C3x
         veAhZMV/skfHf80Tf23I5EqbKicnQJl9S3PwutFMEBFee7GNNDrCP9L4sWtrqPlflW4Z
         mdv0FnpJ3B/oE70jeIyHczCjxvSZcpJ/wpll4LaG5ZO6nSDVq/H7ANW+xoIYzolDh+Fo
         qLgsOc6NtdvUwrd25FU2Aad+720PaRrHFHg8LL8HC07nkxh8EZZ9YDuszECiDbcPPX5A
         yYxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jTZ4Zyop1nU+pMD4vREy65Ac/TlnTU7vH7w//K9Wwhk=;
        b=sK9pUNqgIazb858JGnylc+AlGPRRLo5VCMyaPrUmIOQNfoDs52MUGNLebEiPBJjUye
         Xu48k6wN3WV1yGrt0gppFuoxvonFC2nHswLcxZl0HdRYP7QAK8gw76qBUgvmUWzn7C6H
         DGaA/KRpbqm3MpcCmpT0bHmqqXfpvKE+v/ugeUx/jTstCWyEUuAAp5eMJpmx2ZorX6Yy
         iOIpc1F14DB5e3EwpmI7Am90BXOkc0RHT9vuXtKTcOmo3VEI2v5EepsDHzab0clxfNWp
         95U6TJiPkAZKT7Q/UDQ43yflnvrCQBLMvYmXVLavlww8Kf9vT852whdCPWHB7CSETiJW
         8b1w==
X-Gm-Message-State: AOAM531Y4c8RDn8oLF53WnovomvWtwXKVvddRWNS6tGl6qtlGQESC6nT
	O38Va3CH4+devO9KgZC1QpU=
X-Google-Smtp-Source: ABdhPJyc5cuV1vArk4Trf07PcqRq8xjk0amh1k64KyZ53gp1v68cU16RoUMD56P+Z4YxGQMHCUY3wQ==
X-Received: by 2002:a0c:a5c5:: with SMTP id z63mr1049805qvz.50.1589913174334;
        Tue, 19 May 2020 11:32:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:27c5:: with SMTP id m5ls315973qtg.4.gmail; Tue, 19 May
 2020 11:32:53 -0700 (PDT)
X-Received: by 2002:aed:2ac5:: with SMTP id t63mr1241469qtd.245.1589913173491;
        Tue, 19 May 2020 11:32:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589913173; cv=none;
        d=google.com; s=arc-20160816;
        b=x1wRQGVe18WI/6EmJtZWIPSKlBRpNX3+dwoc391hbN9cfPPZHXI5Jt01adSaG3fv0k
         pnDy6aWxcqVhTvAdCVJbQ4brjTEWXGAXvwKOpGmsM7Gg9j9IHquLMeeaaX1UmtSNKGbN
         tH8gewlj2gr+dedQO95wXf6eYplN0O5YbYHjN6OQ6+2uoG52wT0T1doShe5qp9+DKnAG
         oYeu4oq4Tz+cp7w6eARDGI6MWUgHPppO3SECmdZa1dg/abnXv3Q3wy70pApextNOpX4v
         iLYYzEXgnDa/OHcX5Rqa7pu+sU/gHb0t3w1thFfrCRusahgMthy4UdrexsRhRrTveWrw
         KQPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zUMaWPm9SlcfCzjrHwM0IpeNPj7KBePW3ACEor5djhA=;
        b=dNtAoOt6OXtoYukpql6Nkfzif9MZIDea/NDZDa1vvLW5PZaJfQH+4u8E8FEAHKwHEb
         /RLAZTG5z77rcnxJ4Cixyv/tq62FgrgHzMhEl77xbTRcOuKtzDVO2CtYhd71Lf9NWxTF
         3HToid5VtcKN0uuTSDplH7Slq/OMeY1NdqF4wWDVn+aPb1YkjgZWdUoDMdFg1b2HL28c
         YOGE30fn/LnMarAAVMDNeWCIZ1QUg8wH7xu/ygnMyDb8mL0WCpUnhS8a1DUKprBGEAZH
         rTtQN4NnYu9g6iqMnW48hkJxhDG+KR8p2u+EOyy+VAb7ovQdDGxQBz2pVuvB+lrfpCZV
         Wgbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vJXKeOCN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id m128si53660qke.3.2020.05.19.11.32.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 11:32:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id v128so612138oia.7
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 11:32:53 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr591152oih.70.1589913172739;
 Tue, 19 May 2020 11:32:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200517011732.GE24705@shao2-debian> <20200517034739.GO2869@paulmck-ThinkPad-P72>
 <CANpmjNNj37=mgrZpzX7joAwnYk-GsuiE8oOm13r48FYAK0gSQw@mail.gmail.com>
 <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com>
 <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
 <CAKwvOd=Gi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w@mail.gmail.com>
 <20200518180513.GA114619@google.com> <CANpmjNMTRO0TxxTQxFt8EaRLggcPXKLJL2+G2WFL+vakgd2OUg@mail.gmail.com>
 <CANpmjNO0kDVW4uaLcOF95L3FKc8WjawJqXKQtYbCad+W2r=75g@mail.gmail.com>
In-Reply-To: <CANpmjNO0kDVW4uaLcOF95L3FKc8WjawJqXKQtYbCad+W2r=75g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 May 2020 20:32:39 +0200
Message-ID: <CANpmjNOeXmD5E3O50Z3MjkiuCYaYOPyi+1rq=GZvEKwBvLR0Ug@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=vJXKeOCN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Tue, 19 May 2020 at 15:40, Marco Elver <elver@google.com> wrote:
>
> On Tue, 19 May 2020 at 12:16, Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 18 May 2020 at 20:05, Marco Elver <elver@google.com> wrote:
> > >
> > > On Mon, 18 May 2020, 'Nick Desaulniers' via kasan-dev wrote:
> > >
> > > > On Mon, May 18, 2020 at 7:34 AM Marco Elver <elver@google.com> wrote:
> > > > >
> > > > > On Mon, 18 May 2020 at 14:44, Marco Elver <elver@google.com> wrote:
> > > > > >
> > > > > > [+Cc clang-built-linux FYI]
> > > > > >
> > > > > > On Mon, 18 May 2020 at 12:11, Marco Elver <elver@google.com> wrote:
> > > > > > >
> > > > > > > On Sun, 17 May 2020 at 05:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > > > >
> > > > > > > > On Sun, May 17, 2020 at 09:17:32AM +0800, kernel test robot wrote:
> > > > > > > > > Greeting,
> > > > > > > > >
> > > > > > > > > FYI, we noticed the following commit (built with clang-11):
> > > > > > > > >
> > > > > > > > > commit: 2f08469563550d15cb08a60898d3549720600eee ("rcu: Mark rcu_state.ncpus to detect concurrent writes")
> > > > > > > > > https://git.kernel.org/cgit/linux/kernel/git/paulmck/linux-rcu.git dev.2020.05.14c
> > > > > > > > >
> > > > > > > > > in testcase: boot
> > > > > > > > >
> > > > > > > > > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 8G
> > > > > > > > >
> > > > > > > > > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > > > > > > > >
> > > > > > > > >
> > > > > > > > >
> > > > > > > > >
> > > > > > > > > If you fix the issue, kindly add following tag
> > > > > > > > > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > > > > > > > >
> > > > > > > > >
> > > > > > > > > [    0.054943] BRK [0x05204000, 0x05204fff] PGTABLE
> > > > > > > > > [    0.061181] BRK [0x05205000, 0x05205fff] PGTABLE
> > > > > > > > > [    0.062403] BRK [0x05206000, 0x05206fff] PGTABLE
> > > > > > > > > [    0.065200] RAMDISK: [mem 0x7a247000-0x7fffffff]
> > > > > > > > > [    0.067344] ACPI: Early table checksum verification disabled
> > > > > > > > > BUG: kernel reboot-without-warning in boot stage
> > > > > > > >
> > > > > > > > I am having some difficulty believing that this commit is at fault given
> > > > > > > > that the .config does not list CONFIG_KCSAN=y, but CCing Marco Elver
> > > > > > > > for his thoughts.  Especially given that I have never built with clang-11.
> > > > > > > >
> > > > > > > > But this does invoke ASSERT_EXCLUSIVE_WRITER() in early boot from
> > > > > > > > rcu_init().  Might clang-11 have objections to early use of this macro?
> > > > > > >
> > > > > > > The macro is a noop without KCSAN. I think the bisection went wrong.
> > > > > > >
> > > > > > > I am able to reproduce a reboot-without-warning when building with
> > > > > > > Clang 11 and the provided config. I did a bisect, starting with v5.6
> > > > > > > (good), and found this:
> > > > > > > - Since v5.6, first bad commit is
> > > > > > > 20e2aa812620439d010a3f78ba4e05bc0b3e2861 (Merge tag
> > > > > > > 'perf-urgent-2020-04-12' of
> > > > > > > git://git.kernel.org/pub/scm/linux/kernel//git/tip/tip)
> > > > > > > - The actual commit that introduced the problem is
> > > > > > > 2b3b76b5ec67568da4bb475d3ce8a92ef494b5de (perf/x86/intel/uncore: Add
> > > > > > > Ice Lake server uncore support) -- reverting it fixes the problem.
> > > > >
> > > > > Some more clues:
> > > > >
> > > > > 1. I should have noticed that this uses CONFIG_KASAN=y.
> > > >
> > > > Thanks for the report, testing, and bisection.  I don't see any
> > > > smoking gun in the code.
> > > > https://godbolt.org/z/qbK26r
> > >
> > > My guess is data layout and maybe some interaction with KASAN. I also
> > > played around with leaving icx_mmio_uncores empty, meaning none of the
> > > data it refers to end up in the data section (presumably because
> > > optimized out), which resulted in making the bug disappear as well.
> > >
> > > > >
> > > > > 2. Something about function icx_uncore_mmio_init(). Making it a noop
> > > > > also makes the issue go away.
> > > > >
> > > > > 3. Leaving icx_uncore_mmio_init() a noop but removing the 'static'
> > > > > from icx_mmio_uncores also presents the issue. So this seems to be
> > > > > something about how/where icx_mmio_uncores is allocated.
> > > >
> > > > Can you share the disassembly of icx_uncore_mmio_init() in the given
> > > > configuration?
> > >
> > > ffffffff8102c097 <icx_uncore_mmio_init>:
> > > ffffffff8102c097:       e8 b4 52 bd 01          callq  ffffffff82c01350 <__fentry__>
> > > ffffffff8102c09c:       48 c7 c7 e0 55 c3 83    mov    $0xffffffff83c355e0,%rdi
> > > ffffffff8102c0a3:       e8 69 9a 3b 00          callq  ffffffff813e5b11 <__asan_store8>
> > > ffffffff8102c0a8:       48 c7 05 2d 95 c0 02    movq   $0xffffffff83c388e0,0x2c0952d(%rip)        # ffffffff83c355e0 <uncore_mmio_uncores>
> > > ffffffff8102c0af:       e0 88 c3 83
> > > ffffffff8102c0b3:       c3                      retq
> > >
> > > The problem still happens if we add a __no_sanitize_address (or even
> > > KASAN_SANITIZE := n) here. I think this function is a red herring: you
> > > can make this function be empty, but as long as icx_mmio_uncores and its
> > > dependencies are added to the data section somewhere, does the bug
> > > appear.
> >
> > I also tried to bisect Clang/LLVM, and found that
> > https://reviews.llvm.org/D78162 introduced the breaking change to
> > Clang/LLVM. Reverting that change results in a bootable kernel *with*
> > "perf/x86/intel/uncore: Add Ice Lake server uncore support" still
> > applied.
>
> I found that with Clang/LLVM change D78162, a bunch of memcpys are
> optimized into just a bunch of loads/stores. It may turn out that this
> is again a red herring, because the result is that more code is
> generated, affecting layout. So in the end, the Clang/LLVM bisection
> might just point at the first change that causes data layout to change
> in a way that triggers the bug.

This fixes the problem:
https://lkml.kernel.org/r/20200519182459.87166-1-elver@google.com

I suppose there are several things that happened that caused the above
bisected changes to trigger this. Hard to say how exactly the above
bisected changes caused this to manifest, because during early boot
(while uninitialized) KASAN may just randomly enter kasan_report()
before the branch (annotated with likely(), which is caught by the
branch tracer) prevents it from actually generating a report. However,
if it goes branch tracer -> KASAN -> branch tracers -> KASAN ..., then
we crash. If I had to guess some combination of different code gen,
different stack and/or data usage. So all the above bisected changes
(AFAIK) were red herrings. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOeXmD5E3O50Z3MjkiuCYaYOPyi%2B1rq%3DGZvEKwBvLR0Ug%40mail.gmail.com.
