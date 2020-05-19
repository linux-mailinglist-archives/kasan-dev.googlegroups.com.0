Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4XDR33AKGQEZE74WBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 46D111D9423
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 12:16:20 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id z2sf11381766pfz.13
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 03:16:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589883379; cv=pass;
        d=google.com; s=arc-20160816;
        b=udU0zZmVzZiQ8qZFBSpROHQbgz4iQMGJMEnY2djrW2d+8jUAwqc7AnKZuQSQdxbJGA
         kEV8Kh/qMv0klA3ySQZAKDK4b6JCUtSot7bii+FDM6TVgQYlJjEKVZRiDyOatevj12qK
         tURy6FFlo/O17C6AawyVRtHpI6r48ExKNOiI3V/qhmU4+K9gJqgN2hbXhvhKx6WGu2px
         0tlOvkbJkEOi/ZgeWoHdl3k00KIBhSj8lBbbz+o0Tsw2mtm00BWxVImT8EWKwNN/c3BK
         ZFgh6OqDCejV0DJqwiXWDClqXghpcDqHAGkhxX6jth8ndobr2yc4cCIj0XNLLvoFTKFW
         DicQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=n2cP53ShNL+/H1TQoOQZQhhSnQ99QTEe4+i3qJpbdA8=;
        b=SWMiGo7bsRhiskrJ8/wq5xJOW62nQI9a35lJcElW5gpxIxqDBlQnZ4hFX5OMIyHrtv
         +dxwt2+hjAupJqcRzrWW++ND6GjguMgdIrVNepSfhNL/SDQNx0SEIvmXWKecrrHcQnNR
         90rOG+G57dzphkDt9M3MsJThh4FEfl/cc1VpYlvXm+PqEv5OxBYtXLV+yTpCn30iRGkH
         7yOrvbYZAnu+yVQJFIoVNjG9QaaaEKBiAuRupirLnyo4/AVwL74/yQkktAaNpC/gj6eU
         +C1aErtm4sR8wXx1pqdFFHnJGiO7j/inKsV9LfT0w0i9kwsZItoA0mdDvSLOiZKicoLW
         4sng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qhrBnwjJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n2cP53ShNL+/H1TQoOQZQhhSnQ99QTEe4+i3qJpbdA8=;
        b=PU+cfyl5eUDXLMNK3BAZ09Cn/PMM5SMq4XlgmvH0nbWIqvGr58i2sLXIo4NzzaGLt3
         QpnwspRdFKiBtR1mDMOyKXMIpBlRLai/GteMmG4VWeKbhiDi+sr4zAhx+QHVoY/a+urV
         lcHy+5zqf+fXP1iSogpOzAkrDCi3WnYGV5jc6OvIgX7MWz6v8v9iCufHnT1ZfX6bPuoQ
         kO8eGH9yyHYO8j2v94LVLdGDdgNyuTQFXkwuWtJEbErPG/VeYyDirWq46H+/yiXEVXFy
         PCgEz0KfOACOwLHPLg2QppgRocD3nW0/NPIL6UAg1Yyoghe61Y1gXoRJn6sI7jgA/x1K
         yqqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n2cP53ShNL+/H1TQoOQZQhhSnQ99QTEe4+i3qJpbdA8=;
        b=ErXr/gz2bSs/y5CGc+uh5jCk4mHf3DyrnSKRH3Q4A6xJKUTDRBX5CNV+VyLPx1QQYG
         fSD7f41zLAzRZ040JZCXsDzm9xLsDfYvAVsgDNE685vSh/I5vkJDUJ6s2J93DuMUJHFQ
         Sx8LSDeKLlvSxXCa7JHFHYb0YIET2/KUflkhbw9RljwgTXXNnIPR1W5cYbA+aqVH6lIK
         AiI08JNkt/xbvNlc81XQokVifYRFg+oMqrHfCCC88Ci2FUkgzROLL4yNNvO4lVHxEHiU
         x60Dw6w2SbNqLAu9ojSxkeDA0VgPOQhbjfuZvxzuAXgnSl3Q8PnFWg+vHPTi9q2ivDLA
         niOQ==
X-Gm-Message-State: AOAM531d3iMWJPz75YRKTVTgkn46KbjMPavVpdtseydH6qIix68nRHEy
	4mjXikiW79bB2NjirdiVJcU=
X-Google-Smtp-Source: ABdhPJyIHdonrbgIaxnmPhtrmyPIdslpVvpXNuhE78TUTgP3aBSnpNvCGIOu3SE6XKbpXK1uvPJnZQ==
X-Received: by 2002:a62:3441:: with SMTP id b62mr13191098pfa.225.1589883378652;
        Tue, 19 May 2020 03:16:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5457:: with SMTP id e23ls3669702pgm.4.gmail; Tue, 19 May
 2020 03:16:18 -0700 (PDT)
X-Received: by 2002:a63:d60a:: with SMTP id q10mr19615284pgg.37.1589883378153;
        Tue, 19 May 2020 03:16:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589883378; cv=none;
        d=google.com; s=arc-20160816;
        b=rJSC8Alak7M7K1VG0hTzkSVHV92VyTDwhHV+6wcmvsroRjTPrNiCGSeXJ8xjZJKAaI
         KeI0oo03O6NUij/t7bxxnmCOZvt4Gsfx1KRDSRJnzhirDaoQbSEaSwiXmKvi+mHL3Uhy
         PhxzwNz1yyBTyPEILiPeehh6RptdC/VNGbTeBylUQ/U6I5lDh06x9KDH9sHEFJErFPvB
         wTW/Wk6+lSammd5ejLy+f9dslk9dLND6ByiRoWrSV2PhGNcTgSwWrsYauJywVNi4eH8d
         lTKUZDSYLfWZc8GPLf9Hszn6VtWOPjdSG1VSjBRCKr2bmJY80Hz+2z4KYekdvH4O/Mtl
         4k8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eSUUGwovgEAFUWOh5GaQ33PRSsYhOgKLOqbhYaUm0d4=;
        b=eGcOpiS1bdjTe0F2P+I9Rqt21Tc0lZNxK5oJS99DSlgHdfJiboMoc783BLQdSFN/KO
         /dVIrJoZB8a7/Bbu5yshHn9s4wHYu4QbSN03bCz8WzaFF+VBZ06Y7n24/VS75zrgS6eP
         9FMtKQVYBH3Y3zUpr2vc24KhesXDFRc6Tv8nDp80pxVrdJVswD9kbtM/e7j1KWyUhKUj
         Ux2iyJqw5otefSDUgfb0DdPBaWZ5CG2kRehVpEVIhIwLZn8Ft0omMruUxtkTTkAIVc8+
         15Dbvp7BaLmiObmgMRZYQAHxfk6/xss58TvECyQvIS7PiXbZLg2LK68CUySlFLUCxrVA
         MdfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qhrBnwjJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id b8si199140pjk.2.2020.05.19.03.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 03:16:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id i22so11799175oik.10
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 03:16:18 -0700 (PDT)
X-Received: by 2002:aca:3254:: with SMTP id y81mr2617327oiy.172.1589883377228;
 Tue, 19 May 2020 03:16:17 -0700 (PDT)
MIME-Version: 1.0
References: <20200517011732.GE24705@shao2-debian> <20200517034739.GO2869@paulmck-ThinkPad-P72>
 <CANpmjNNj37=mgrZpzX7joAwnYk-GsuiE8oOm13r48FYAK0gSQw@mail.gmail.com>
 <CANpmjNMx0+=Cac=WvHuzKb2zJvgNVvVxjo_W1wYWztywxDKeCQ@mail.gmail.com>
 <CANpmjNPcOHAE5d=gaD327HqxTBegf75qeN_pjoszahdk6_i5=Q@mail.gmail.com>
 <CAKwvOd=Gi2z_NjRfpTigCCcV5kUWU7Bm7h1eHLeQ6DZCmrsR8w@mail.gmail.com> <20200518180513.GA114619@google.com>
In-Reply-To: <20200518180513.GA114619@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 May 2020 12:16:05 +0200
Message-ID: <CANpmjNMTRO0TxxTQxFt8EaRLggcPXKLJL2+G2WFL+vakgd2OUg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=qhrBnwjJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Mon, 18 May 2020 at 20:05, Marco Elver <elver@google.com> wrote:
>
> On Mon, 18 May 2020, 'Nick Desaulniers' via kasan-dev wrote:
>
> > On Mon, May 18, 2020 at 7:34 AM Marco Elver <elver@google.com> wrote:
> > >
> > > On Mon, 18 May 2020 at 14:44, Marco Elver <elver@google.com> wrote:
> > > >
> > > > [+Cc clang-built-linux FYI]
> > > >
> > > > On Mon, 18 May 2020 at 12:11, Marco Elver <elver@google.com> wrote:
> > > > >
> > > > > On Sun, 17 May 2020 at 05:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > >
> > > > > > On Sun, May 17, 2020 at 09:17:32AM +0800, kernel test robot wrote:
> > > > > > > Greeting,
> > > > > > >
> > > > > > > FYI, we noticed the following commit (built with clang-11):
> > > > > > >
> > > > > > > commit: 2f08469563550d15cb08a60898d3549720600eee ("rcu: Mark rcu_state.ncpus to detect concurrent writes")
> > > > > > > https://git.kernel.org/cgit/linux/kernel/git/paulmck/linux-rcu.git dev.2020.05.14c
> > > > > > >
> > > > > > > in testcase: boot
> > > > > > >
> > > > > > > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 8G
> > > > > > >
> > > > > > > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > > > > > >
> > > > > > >
> > > > > > >
> > > > > > >
> > > > > > > If you fix the issue, kindly add following tag
> > > > > > > Reported-by: kernel test robot <rong.a.chen@intel.com>
> > > > > > >
> > > > > > >
> > > > > > > [    0.054943] BRK [0x05204000, 0x05204fff] PGTABLE
> > > > > > > [    0.061181] BRK [0x05205000, 0x05205fff] PGTABLE
> > > > > > > [    0.062403] BRK [0x05206000, 0x05206fff] PGTABLE
> > > > > > > [    0.065200] RAMDISK: [mem 0x7a247000-0x7fffffff]
> > > > > > > [    0.067344] ACPI: Early table checksum verification disabled
> > > > > > > BUG: kernel reboot-without-warning in boot stage
> > > > > >
> > > > > > I am having some difficulty believing that this commit is at fault given
> > > > > > that the .config does not list CONFIG_KCSAN=y, but CCing Marco Elver
> > > > > > for his thoughts.  Especially given that I have never built with clang-11.
> > > > > >
> > > > > > But this does invoke ASSERT_EXCLUSIVE_WRITER() in early boot from
> > > > > > rcu_init().  Might clang-11 have objections to early use of this macro?
> > > > >
> > > > > The macro is a noop without KCSAN. I think the bisection went wrong.
> > > > >
> > > > > I am able to reproduce a reboot-without-warning when building with
> > > > > Clang 11 and the provided config. I did a bisect, starting with v5.6
> > > > > (good), and found this:
> > > > > - Since v5.6, first bad commit is
> > > > > 20e2aa812620439d010a3f78ba4e05bc0b3e2861 (Merge tag
> > > > > 'perf-urgent-2020-04-12' of
> > > > > git://git.kernel.org/pub/scm/linux/kernel//git/tip/tip)
> > > > > - The actual commit that introduced the problem is
> > > > > 2b3b76b5ec67568da4bb475d3ce8a92ef494b5de (perf/x86/intel/uncore: Add
> > > > > Ice Lake server uncore support) -- reverting it fixes the problem.
> > >
> > > Some more clues:
> > >
> > > 1. I should have noticed that this uses CONFIG_KASAN=y.
> >
> > Thanks for the report, testing, and bisection.  I don't see any
> > smoking gun in the code.
> > https://godbolt.org/z/qbK26r
>
> My guess is data layout and maybe some interaction with KASAN. I also
> played around with leaving icx_mmio_uncores empty, meaning none of the
> data it refers to end up in the data section (presumably because
> optimized out), which resulted in making the bug disappear as well.
>
> > >
> > > 2. Something about function icx_uncore_mmio_init(). Making it a noop
> > > also makes the issue go away.
> > >
> > > 3. Leaving icx_uncore_mmio_init() a noop but removing the 'static'
> > > from icx_mmio_uncores also presents the issue. So this seems to be
> > > something about how/where icx_mmio_uncores is allocated.
> >
> > Can you share the disassembly of icx_uncore_mmio_init() in the given
> > configuration?
>
> ffffffff8102c097 <icx_uncore_mmio_init>:
> ffffffff8102c097:       e8 b4 52 bd 01          callq  ffffffff82c01350 <__fentry__>
> ffffffff8102c09c:       48 c7 c7 e0 55 c3 83    mov    $0xffffffff83c355e0,%rdi
> ffffffff8102c0a3:       e8 69 9a 3b 00          callq  ffffffff813e5b11 <__asan_store8>
> ffffffff8102c0a8:       48 c7 05 2d 95 c0 02    movq   $0xffffffff83c388e0,0x2c0952d(%rip)        # ffffffff83c355e0 <uncore_mmio_uncores>
> ffffffff8102c0af:       e0 88 c3 83
> ffffffff8102c0b3:       c3                      retq
>
> The problem still happens if we add a __no_sanitize_address (or even
> KASAN_SANITIZE := n) here. I think this function is a red herring: you
> can make this function be empty, but as long as icx_mmio_uncores and its
> dependencies are added to the data section somewhere, does the bug
> appear.

I also tried to bisect Clang/LLVM, and found that
https://reviews.llvm.org/D78162 introduced the breaking change to
Clang/LLVM. Reverting that change results in a bootable kernel *with*
"perf/x86/intel/uncore: Add Ice Lake server uncore support" still
applied.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMTRO0TxxTQxFt8EaRLggcPXKLJL2%2BG2WFL%2Bvakgd2OUg%40mail.gmail.com.
