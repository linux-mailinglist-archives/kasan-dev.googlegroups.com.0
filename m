Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75R7WBQMGQE27HX7ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id DDB0536623C
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 00:43:12 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 27-20020a63155b0000b02901fc44c72f4fsf8781418pgv.10
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Apr 2021 15:43:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618958591; cv=pass;
        d=google.com; s=arc-20160816;
        b=BZo6PAZgI4chL1pJ7wRBKxdfAwLH3jdxkCi/DaSycZ0X8lpbgsVfcszoTBtNQLniAv
         HlXBmR8BLOWHF0CtSbGHskXVjEhiwSyMeEvbRZRTg8EkPiSh2no4BmlqdwynzD6bf2QW
         wVE/SvTY3ThYvb7GzR0W6/yqKHF34WBX4EKGObuwJMBqqBXlCiFVHablGmMet/JDAcg9
         ybSoAyhzBNc/R0XcFLpYTFIJg25ZMMuHWu0HWpQGcRLGJIDO0lUAJGvgz6PBiDmkAhM+
         ciCdNylbPnK32a3xPPSGuf+Spa8rNGAIREvHLbjUe7sqhgPj3gBEfoGTPDRuOquH1/qd
         8Z4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jCVJeGBzcpaHo92/MAnNxYVBi9dSkTFWeABwx2TdV2E=;
        b=prVHDzVlJWPs5WwPDjhGTe8Viv6Ugh5WEGs+KWmutYRPoPUKkpt+/pMeDkIlo/63fd
         xqB1gfL4udX805nR62KBUAXOADetGRqS+t2jU0bR4vP8DbJR4SzH07w0J7K0UJBN6Lqc
         5OXpxuta7ZHCSX2ATsU8Fy8prXOvS7+ekbCWX6/KEbLtY5HEfv5MBMKbUhwwEFGuFlzL
         w0s2mLDpHHk/fHrw0Kxe6e1vOR3ya0hLSiqcyN3idRlPwSWro4uXnCnIeEjb3sDl0ikK
         f9kmYHMdrTkYMA3IUrufr3v/hFO9kqH4NbyHPsRo/Pp3lPaBANnQ8RVu6W5vymtoyQ3e
         1UOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="s/ZBszYf";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jCVJeGBzcpaHo92/MAnNxYVBi9dSkTFWeABwx2TdV2E=;
        b=F4GwaZ8iWaC16TAel8Zo4ZLDivERsMG1D9Kchzx4QSdvTBni5uiS9hzi0229QVpgkU
         q4Zx1e2vKr1SeVH425dnKtAxyJScBdl8rO5wdRv/9Lbe6RtpXqoJxe1d8g3cUu7ufsWG
         cPAzUcKQTyrBFEukUTl0aSq7FcnGBAlmc3Hj2sx3ei4ZkXFbCZBKoex1/ITwMIpghUq9
         hSjKlIaq8liK8t6Y/JoSjqDWNXk0fGkzr82DyHDN1wqvmI87sXl3ho6rrwHVjncVd1vu
         1lZyRukHYfO04ZS5mxwz+HvPGVNdwoYNGuIG0eTybM7zjpjwlgRU/4YwpnsCHE+GTdY8
         8IUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jCVJeGBzcpaHo92/MAnNxYVBi9dSkTFWeABwx2TdV2E=;
        b=XT/LWsLDwBZ5VLauKnUfJ++lVk7HbqKzWsUy7T1Tqht+JJUdnZA8Rya0ZbKcBM0UWJ
         Xjys3VUW0BWiXC24rqVdC0jCWAU1st+DoDsblgihsxEKUG165E4FlUx7ueQFT7H2nEZS
         8QMUaJ5jmcQrLkjQVs6xe0hDfYeQU11mbP7YsXLt8VvYjSsIr7QDq64pJIs2ifwl22ed
         7n2AjtJUBqt+4D+RBNkT0ScCQcOqKSggCSWUtI85Y75eZlBuZbiU7fAcj/nWkGlPj7Fr
         lf8WgirJ5565DxLC4vYjCqYrsONE8p4cK5CG/qCYjxPlBICKMPvuurlm/QbcGaI2FGiF
         7Eyg==
X-Gm-Message-State: AOAM532iTj326LvGJVuaozvmuRXXMrYfb12SAvA9Mi4nMaZBu5oC7M/2
	JckGz0EP0pNtL/7vmPGjgd0=
X-Google-Smtp-Source: ABdhPJyJbO7Z5Wdgkjh6d9pUtR7sAuO5LKrkTV++XjamZjAxtW5l2/8Vzm/FvyXqmKmM3MfDjt/9WA==
X-Received: by 2002:a65:6418:: with SMTP id a24mr16517790pgv.57.1618958591398;
        Tue, 20 Apr 2021 15:43:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4ec2:: with SMTP id v2ls174419pjl.2.gmail; Tue, 20
 Apr 2021 15:43:10 -0700 (PDT)
X-Received: by 2002:a17:90a:9a85:: with SMTP id e5mr675080pjp.201.1618958590607;
        Tue, 20 Apr 2021 15:43:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618958590; cv=none;
        d=google.com; s=arc-20160816;
        b=WblNjMHBF1Z4Ff56mzGUW3yMwz1n58u0acAz2b+xdPjxmKEFj6ECGcCn9eX5uO3jse
         vqW6tiOupkhlsehl88hVWyWZ4srQHZ+Rw1oX8zBgHz1zunpdbrTFdJYqp1F66kFk7oAC
         Rw5NRzjYOp7T2SEXBKEIH0Fq9hL1JbdGjqLBnQpG11Pw42iHDZoyfjzcl+EHHEbw/3De
         hpWvwK5FfvKYPJWaFAV6v71Kw7pQSEN55DwuIRhYqWlX9IMw5qjNOuYhrsHqs4kIbwOm
         6H92kxwy+MY+Xi8Vp0f3l8Od9xF5xQjeXcplCYbKoe4tRB+ZGl7tj8sxxnhwwSo9akEF
         BCcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Cqcr/bWRc5duDemxdRvUOo4OnGCAh1SF+Fi9sGC5Wd8=;
        b=KsxAUzsvx2pqvlmr5s0VZXORjLwty8bei8KnRnmuvyOLw3ZT+Py1mWUAkjgwe6C1Q/
         Y5TOoXY3CDBKk8mLdtvRk1DPlQCBecOTJOkjINIXURQdeNI7eh858pmpBKwNdWN4x/mx
         c3yKhJcL2chUrNU2pH09RkIto7KrVPPJ/h+NxzEyppFCSr6D5Ex8ni9hvRHl/tG6HQjW
         j91/IfrpucjZ5YvK6208eoSEbzy5zYSwBuRNgjZHdv5SdOq5TxSly+56GyPY4v25cBcY
         1A+H8WxYD4HOFgU0aAegSHEiQiCvM12IcGzOgEoTGaowGB9/p/tsqdhI2j61RotYKHjt
         6K+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="s/ZBszYf";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id z28si17687pgk.2.2021.04.20.15.43.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Apr 2021 15:43:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id k14-20020a9d7dce0000b02901b866632f29so37296044otn.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Apr 2021 15:43:10 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr16170709otn.233.1618958589742;
 Tue, 20 Apr 2021 15:43:09 -0700 (PDT)
MIME-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com> <CGME20210420212618eucas1p102b427d1af9c682217dfe093f3eac3e8@eucas1p1.samsung.com>
 <20210408103605.1676875-6-elver@google.com> <1fbf3429-42e5-0959-9a5c-91de80f02b6a@samsung.com>
In-Reply-To: <1fbf3429-42e5-0959-9a5c-91de80f02b6a@samsung.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Apr 2021 00:42:58 +0200
Message-ID: <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, Oleg Nesterov <oleg@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="s/ZBszYf";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
>
> Hi Marco,
>
> On 08.04.2021 12:36, Marco Elver wrote:
> > Introduces the TRAP_PERF si_code, and associated siginfo_t field
> > si_perf. These will be used by the perf event subsystem to send signals
> > (if requested) to the task where an event occurred.
> >
> > Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
> > Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
> > Signed-off-by: Marco Elver <elver@google.com>
>
> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
> regression on my test systems (arm 32bit and 64bit). Most systems fails
> to boot in the given time frame. I've observed that there is a timeout
> waiting for udev to populate /dev and then also during the network
> interfaces configuration. Reverting this commit, together with
> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to let it
> compile, on top of next-20210420 fixes the issue.

Thanks, this is weird for sure and nothing in particular stands out.

I have questions:
-- Can you please share your config?
-- Also, can you share how you run this? Can it be reproduced in qemu?
-- How did you derive this patch to be at fault? Why not just
97ba62b27867, given you also need to revert it?

If you are unsure which patch exactly it is, can you try just
reverting 97ba62b27867 and see what happens?

Thanks,
-- Marco

> > ---
> >   arch/m68k/kernel/signal.c          |  3 +++
> >   arch/x86/kernel/signal_compat.c    |  5 ++++-
> >   fs/signalfd.c                      |  4 ++++
> >   include/linux/compat.h             |  2 ++
> >   include/linux/signal.h             |  1 +
> >   include/uapi/asm-generic/siginfo.h |  6 +++++-
> >   include/uapi/linux/signalfd.h      |  4 +++-
> >   kernel/signal.c                    | 11 +++++++++++
> >   8 files changed, 33 insertions(+), 3 deletions(-)
> >
> > diff --git a/arch/m68k/kernel/signal.c b/arch/m68k/kernel/signal.c
> > index 349570f16a78..a4b7ee1df211 100644
> > --- a/arch/m68k/kernel/signal.c
> > +++ b/arch/m68k/kernel/signal.c
> > @@ -622,6 +622,9 @@ static inline void siginfo_build_tests(void)
> >       /* _sigfault._addr_pkey */
> >       BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x12);
> >
> > +     /* _sigfault._perf */
> > +     BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x10);
> > +
> >       /* _sigpoll */
> >       BUILD_BUG_ON(offsetof(siginfo_t, si_band)   != 0x0c);
> >       BUILD_BUG_ON(offsetof(siginfo_t, si_fd)     != 0x10);
> > diff --git a/arch/x86/kernel/signal_compat.c b/arch/x86/kernel/signal_compat.c
> > index a5330ff498f0..0e5d0a7e203b 100644
> > --- a/arch/x86/kernel/signal_compat.c
> > +++ b/arch/x86/kernel/signal_compat.c
> > @@ -29,7 +29,7 @@ static inline void signal_compat_build_tests(void)
> >       BUILD_BUG_ON(NSIGFPE  != 15);
> >       BUILD_BUG_ON(NSIGSEGV != 9);
> >       BUILD_BUG_ON(NSIGBUS  != 5);
> > -     BUILD_BUG_ON(NSIGTRAP != 5);
> > +     BUILD_BUG_ON(NSIGTRAP != 6);
> >       BUILD_BUG_ON(NSIGCHLD != 6);
> >       BUILD_BUG_ON(NSIGSYS  != 2);
> >
> > @@ -138,6 +138,9 @@ static inline void signal_compat_build_tests(void)
> >       BUILD_BUG_ON(offsetof(siginfo_t, si_pkey) != 0x20);
> >       BUILD_BUG_ON(offsetof(compat_siginfo_t, si_pkey) != 0x14);
> >
> > +     BUILD_BUG_ON(offsetof(siginfo_t, si_perf) != 0x18);
> > +     BUILD_BUG_ON(offsetof(compat_siginfo_t, si_perf) != 0x10);
> > +
> >       CHECK_CSI_OFFSET(_sigpoll);
> >       CHECK_CSI_SIZE  (_sigpoll, 2*sizeof(int));
> >       CHECK_SI_SIZE   (_sigpoll, 4*sizeof(int));
> > diff --git a/fs/signalfd.c b/fs/signalfd.c
> > index 456046e15873..040a1142915f 100644
> > --- a/fs/signalfd.c
> > +++ b/fs/signalfd.c
> > @@ -134,6 +134,10 @@ static int signalfd_copyinfo(struct signalfd_siginfo __user *uinfo,
> >   #endif
> >               new.ssi_addr_lsb = (short) kinfo->si_addr_lsb;
> >               break;
> > +     case SIL_PERF_EVENT:
> > +             new.ssi_addr = (long) kinfo->si_addr;
> > +             new.ssi_perf = kinfo->si_perf;
> > +             break;
> >       case SIL_CHLD:
> >               new.ssi_pid    = kinfo->si_pid;
> >               new.ssi_uid    = kinfo->si_uid;
> > diff --git a/include/linux/compat.h b/include/linux/compat.h
> > index 6e65be753603..c8821d966812 100644
> > --- a/include/linux/compat.h
> > +++ b/include/linux/compat.h
> > @@ -236,6 +236,8 @@ typedef struct compat_siginfo {
> >                                       char _dummy_pkey[__COMPAT_ADDR_BND_PKEY_PAD];
> >                                       u32 _pkey;
> >                               } _addr_pkey;
> > +                             /* used when si_code=TRAP_PERF */
> > +                             compat_u64 _perf;
> >                       };
> >               } _sigfault;
> >
> > diff --git a/include/linux/signal.h b/include/linux/signal.h
> > index 205526c4003a..1e98548d7cf6 100644
> > --- a/include/linux/signal.h
> > +++ b/include/linux/signal.h
> > @@ -43,6 +43,7 @@ enum siginfo_layout {
> >       SIL_FAULT_MCEERR,
> >       SIL_FAULT_BNDERR,
> >       SIL_FAULT_PKUERR,
> > +     SIL_PERF_EVENT,
> >       SIL_CHLD,
> >       SIL_RT,
> >       SIL_SYS,
> > diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> > index d2597000407a..d0bb9125c853 100644
> > --- a/include/uapi/asm-generic/siginfo.h
> > +++ b/include/uapi/asm-generic/siginfo.h
> > @@ -91,6 +91,8 @@ union __sifields {
> >                               char _dummy_pkey[__ADDR_BND_PKEY_PAD];
> >                               __u32 _pkey;
> >                       } _addr_pkey;
> > +                     /* used when si_code=TRAP_PERF */
> > +                     __u64 _perf;
> >               };
> >       } _sigfault;
> >
> > @@ -155,6 +157,7 @@ typedef struct siginfo {
> >   #define si_lower    _sifields._sigfault._addr_bnd._lower
> >   #define si_upper    _sifields._sigfault._addr_bnd._upper
> >   #define si_pkey             _sifields._sigfault._addr_pkey._pkey
> > +#define si_perf              _sifields._sigfault._perf
> >   #define si_band             _sifields._sigpoll._band
> >   #define si_fd               _sifields._sigpoll._fd
> >   #define si_call_addr        _sifields._sigsys._call_addr
> > @@ -253,7 +256,8 @@ typedef struct siginfo {
> >   #define TRAP_BRANCH     3   /* process taken branch trap */
> >   #define TRAP_HWBKPT     4   /* hardware breakpoint/watchpoint */
> >   #define TRAP_UNK    5       /* undiagnosed trap */
> > -#define NSIGTRAP     5
> > +#define TRAP_PERF    6       /* perf event with sigtrap=1 */
> > +#define NSIGTRAP     6
> >
> >   /*
> >    * There is an additional set of SIGTRAP si_codes used by ptrace
> > diff --git a/include/uapi/linux/signalfd.h b/include/uapi/linux/signalfd.h
> > index 83429a05b698..7e333042c7e3 100644
> > --- a/include/uapi/linux/signalfd.h
> > +++ b/include/uapi/linux/signalfd.h
> > @@ -39,6 +39,8 @@ struct signalfd_siginfo {
> >       __s32 ssi_syscall;
> >       __u64 ssi_call_addr;
> >       __u32 ssi_arch;
> > +     __u32 __pad3;
> > +     __u64 ssi_perf;
> >
> >       /*
> >        * Pad strcture to 128 bytes. Remember to update the
> > @@ -49,7 +51,7 @@ struct signalfd_siginfo {
> >        * comes out of a read(2) and we really don't want to have
> >        * a compat on read(2).
> >        */
> > -     __u8 __pad[28];
> > +     __u8 __pad[16];
> >   };
> >
> >
> > diff --git a/kernel/signal.c b/kernel/signal.c
> > index f2718350bf4b..7061e4957650 100644
> > --- a/kernel/signal.c
> > +++ b/kernel/signal.c
> > @@ -1199,6 +1199,7 @@ static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
> >       case SIL_FAULT_MCEERR:
> >       case SIL_FAULT_BNDERR:
> >       case SIL_FAULT_PKUERR:
> > +     case SIL_PERF_EVENT:
> >       case SIL_SYS:
> >               ret = false;
> >               break;
> > @@ -2531,6 +2532,7 @@ static void hide_si_addr_tag_bits(struct ksignal *ksig)
> >       case SIL_FAULT_MCEERR:
> >       case SIL_FAULT_BNDERR:
> >       case SIL_FAULT_PKUERR:
> > +     case SIL_PERF_EVENT:
> >               ksig->info.si_addr = arch_untagged_si_addr(
> >                       ksig->info.si_addr, ksig->sig, ksig->info.si_code);
> >               break;
> > @@ -3341,6 +3343,10 @@ void copy_siginfo_to_external32(struct compat_siginfo *to,
> >   #endif
> >               to->si_pkey = from->si_pkey;
> >               break;
> > +     case SIL_PERF_EVENT:
> > +             to->si_addr = ptr_to_compat(from->si_addr);
> > +             to->si_perf = from->si_perf;
> > +             break;
> >       case SIL_CHLD:
> >               to->si_pid = from->si_pid;
> >               to->si_uid = from->si_uid;
> > @@ -3421,6 +3427,10 @@ static int post_copy_siginfo_from_user32(kernel_siginfo_t *to,
> >   #endif
> >               to->si_pkey = from->si_pkey;
> >               break;
> > +     case SIL_PERF_EVENT:
> > +             to->si_addr = compat_ptr(from->si_addr);
> > +             to->si_perf = from->si_perf;
> > +             break;
> >       case SIL_CHLD:
> >               to->si_pid    = from->si_pid;
> >               to->si_uid    = from->si_uid;
> > @@ -4601,6 +4611,7 @@ static inline void siginfo_buildtime_checks(void)
> >       CHECK_OFFSET(si_lower);
> >       CHECK_OFFSET(si_upper);
> >       CHECK_OFFSET(si_pkey);
> > +     CHECK_OFFSET(si_perf);
> >
> >       /* sigpoll */
> >       CHECK_OFFSET(si_band);
>
> Best regards
> --
> Marek Szyprowski, PhD
> Samsung R&D Institute Poland
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM8wEJngK%3DJ8Lt9npkZgrSWoRsqkdajErWEoY_%3DM1GW5A%40mail.gmail.com.
