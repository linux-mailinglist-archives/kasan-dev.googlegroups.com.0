Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFH3YGCAMGQEUY52JGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 16C86372330
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 00:47:50 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id q18-20020a056a000852b02902766388a3c5sf3742510pfk.4
        for <lists+kasan-dev@lfdr.de>; Mon, 03 May 2021 15:47:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620082069; cv=pass;
        d=google.com; s=arc-20160816;
        b=aKcrRltbboWlXty0n2ECwZQxrmNfftZ2UX5e2mOFGH01mXRt+doMEshoqkzs6Myd+F
         IrShKukXlf8hMDXQJXNj5x1vVdp3ipqNs1sb8dmGwU79HCJo1uqTtdQj95BpZdrRZjKM
         QufcO2/hPO+058e6aNw1Z2VMhntBlipuDe/tPe0f4vkPD2MotbtUtTsMsphPJRYjehpD
         VMfF891AC0DxyUsI1utwnPuNm7DnbbzyILJBo2kPyE7kQkHGx4kd1HTrTtUWtHrjfpvw
         +T76i9oRy2uk0YTreGhzdsW5d98iMwGKWytt6eJSI4fB9gqpoic3ciE1pBu8mj/fj6//
         Ibmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wwpH08+2tWttrwWE0ZRdwzv4qEqy3I98/pCes7Hqa0o=;
        b=QFifCsVfYwwnyrBEKCF1ELnA9+ysgB2mNMaZdawXlzo7Ya+eghVRxO4/y5Ms4Xr1Tr
         y74nlysYS7WmhxUvWOyL23q8lFRDfcTH5T3TFpRA/3ARtW7HC6GqKIeRDlK1m2dR3HWb
         QEgNcq9Cw5Dl3Yf9iCVIuAY1AGvtqJWIaU5tL/5JUWqaCy/jHMd5lZjTW1iuwE0zExjR
         It5E0QtcQegEgVjkt+XfH2u2VlYNKBLb+TeFdlWepuvaav3zFnwglO4gO2+YSjo71ukr
         HwsG1/BdYsnzZG2IQYadg8wbA8e4bnHo5Y2cM9F5N2R25yrPsYdIwBS/tq5+qbRhV3u2
         OQsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OveNxb30;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wwpH08+2tWttrwWE0ZRdwzv4qEqy3I98/pCes7Hqa0o=;
        b=Rv2uw0MK8mCsrvrjWHhiYQ2uLfbizw4zhTaIfhW/GV3jOKgpg+zMz3JOInqnphfEQR
         86r7CYKuOPDn165inyreW7VUV6arqFLloEheGZvPjwoh6PYUO4TnBDlcN7hy5hm6Tdl9
         uRDz0elvnRk8fS7Ndj9uyEzVbFWUKk2bk0wnL/H2DFM26uC7zf0fIqeCsNUsuiX7RWv4
         cyY4LBg9tFRf+oiQXV7qZfLm3iQ/Ppdw+LiRUVLpsJY4L05CVG2EP3l/36PW/AJzFRo4
         TY9F5Y542oP+05MsuXo8sw7Jg2dMBVVjHI8BnRzmKBM76DRDCSb2bqpCSk/WVLJbBPW/
         Rx3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wwpH08+2tWttrwWE0ZRdwzv4qEqy3I98/pCes7Hqa0o=;
        b=gfr6O+kwcXxA+Kkskux5y+f4R4nrJWDmBYDLblVamAgy9JtrVqUGHXG2L5oHN/OU8S
         1PtWroIv+RPCiSda/PySh623vbp2jUXYgj4UCjDdJZikRFmYKLhwrPTvoDw05lsdS/+Q
         En0AUUx6017zEmCJOz6vv6B6MCMcpY/AJP6Mx8KOH7uLdoPaLdwd3HMYSA+uAB3dDp75
         fH9j/iGL3wGtZ8haPC5CfcziF/p/b+fcx8b4RusKfht+lIZ/pKig80z17tJ6TNpzPHek
         GbheHXxxfUt1iZmNtj7K/2Dq+3QUxqOuqmrc9nOlWXy999od/0EQivH/WIbKo8JYQIke
         d3KQ==
X-Gm-Message-State: AOAM530t2t8Rkhh10ByW6fmYqojXX26pn3p9YHobrO6or35bsXNpQCMT
	kMWKp433YCAc1As15VMmiJg=
X-Google-Smtp-Source: ABdhPJy8n2D7Ro2lxw17XZZor3PeCQg5r9kYIzXViwQkg0mWDEJfqg5fELpwYgAXlrAcqpAL32c14A==
X-Received: by 2002:a17:902:9898:b029:ee:d673:198f with SMTP id s24-20020a1709029898b02900eed673198fmr7836779plp.19.1620082068733;
        Mon, 03 May 2021 15:47:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7e1c:: with SMTP id z28ls5778693pgc.3.gmail; Mon, 03 May
 2021 15:47:48 -0700 (PDT)
X-Received: by 2002:a63:2226:: with SMTP id i38mr20286958pgi.215.1620082068153;
        Mon, 03 May 2021 15:47:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620082068; cv=none;
        d=google.com; s=arc-20160816;
        b=FxavNbzZQayOqxg191owd3FJHr0ZWDOlga9kVQfabPuc9svgPoznPDwaIR62UyWfld
         Ib4bvH5C8MFy1JkXrGSgxRCLlnAU1qukd7LhZB+CiqgQHXDPe6DHc6uDd6gMYB5InHqi
         lQUXnE634wP1s0/exTxhNI0OEG56++U2ejyvQ3RfEGNmN14wgqMmy3dm9NI4GCJqWr+u
         OL98XUC3o6S/2rVnCaNY6cy35K2pCM4uNNYNhO7oVyEybBsQ8HPR5aPEp8G2pO+CNFwI
         LQyErHqVZGM8bhQVWeRHKYy0Z9h//Yl+E62Bk0J8s6cuadws6dZXWmIWMpBs1Q7+P7XR
         pfGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J3yLB+vbpq5Xc9JhKmZutr67bAiFvkUnDMtUXpplUGA=;
        b=V0WDLAn+CP3obW+HhNHTMq+6PdWdzE2fF5fenNsY6khQGBuMB10pTbBhZ7f0/ydbi/
         B1MLVMNAcwcQnDa9oghTK9G/WX9jU/ahc6YCLc9uCimMBVojx5uCsEgQN8sKu9n/+6tA
         GZQVRQwCoFSvABWL8Fg8TqQfVrROT7pdLs9jzyZ0gMNaEw2ppm+JIwJhhJYn1QpHqlsr
         ddjsJaDJ49lLlrQAxQh50AYcgX/1H6pckZb/gQn7xOe5bLWb1SnauL49V3HXV2b+7U5U
         TRHgBFgiA8yUg84lfWnDwbDPcpr4ZY21YwyqZkgv8L5zSDYhjGMWzHevoOnQ+vISKOTQ
         XDkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OveNxb30;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id e10si72570pfc.0.2021.05.03.15.47.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 May 2021 15:47:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id d25so6971813oij.5
        for <kasan-dev@googlegroups.com>; Mon, 03 May 2021 15:47:48 -0700 (PDT)
X-Received: by 2002:aca:44d6:: with SMTP id r205mr15201349oia.172.1620082067206;
 Mon, 03 May 2021 15:47:47 -0700 (PDT)
MIME-Version: 1.0
References: <m14kfjh8et.fsf_-_@fess.ebiederm.org> <20210503203814.25487-1-ebiederm@xmission.com>
 <20210503203814.25487-10-ebiederm@xmission.com> <m1o8drfs1m.fsf@fess.ebiederm.org>
In-Reply-To: <m1o8drfs1m.fsf@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 May 2021 00:47:35 +0200
Message-ID: <CANpmjNNOK6Mkxkjx5nD-t-yPQ-oYtaW5Xui=hi3kpY_-Y0=2JA@mail.gmail.com>
Subject: Re: [PATCH 10/12] signal: Redefine signinfo so 64bit fields are possible
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OveNxb30;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Mon, 3 May 2021 at 23:04, Eric W. Biederman <ebiederm@xmission.com> wrote:
> "Eric W. Beiderman" <ebiederm@xmission.com> writes:
> > From: "Eric W. Biederman" <ebiederm@xmission.com>
> >
> > The si_perf code really wants to add a u64 field.  This change enables
> > that by reorganizing the definition of siginfo_t, so that a 64bit
> > field can be added without increasing the alignment of other fields.

If you can, it'd be good to have an explanation for this, because it's
not at all obvious -- some future archeologist will wonder how we ever
came up with this definition of siginfo...

(I see the trick here is that before the union would have changed
alignment, introducing padding after the 3 ints -- but now because the
3 ints are inside the union the union's padding no longer adds padding
for these ints.  Perhaps you can explain it better than I can. Also
see below.)

> I decided to include this change because it is not that complicated,
> and it allows si_perf_data to have the definition that was originally
> desired.

Neat, and long-term I think this seems to be worth having. Sooner or
later something else might want __u64, too.

But right now, due to the slight increase in complexity, we need to
take extra care ensuring nothing broke -- at a high-level I see why
this seems to be safe.

> If this looks difficult to make in the userspace definitions,
> or is otherwise a problem I don't mind dropping this change.  I just
> figured since it was not too difficult and we are changing things
> anyway I should try for everything.

Languages that support inheritance might end up with the simpler
definition here (and depending on which fields they want to access,
they'd have to cast the base siginfo into the one they want). What
will become annoying is trying to describe siginfo_t.

I will run some tests in the morning.

Thanks,
-- Marco

[...]
> > diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> > index e663bf117b46..1fcede623a73 100644
> > --- a/include/uapi/asm-generic/siginfo.h
> > +++ b/include/uapi/asm-generic/siginfo.h
> > @@ -29,15 +29,33 @@ typedef union sigval {
> >  #define __ARCH_SI_ATTRIBUTES
> >  #endif
> >
> > +#ifndef __ARCH_HAS_SWAPPED_SIGINFO
> > +#define ___SIGINFO_COMMON    \
> > +     int     si_signo;       \
> > +     int     si_errno;       \
> > +     int     si_code
> > +#else
> > +#define ___SIGINFO_COMMON    \
> > +     int     si_signo;       \
> > +     int     si_code;        \
> > +     int     si_errno
> > +#endif /* __ARCH_HAS_SWAPPED_SIGINFO */
> > +
> > +#define __SIGINFO_COMMON     \
> > +     ___SIGINFO_COMMON;      \
> > +     int     _common_pad[__alignof__(void *) != __alignof(int)]

Just to verify my understanding of _common_pad: this is again a legacy
problem, right? I.e. if siginfo was designed from the start like this,
we wouldn't need the _common_pad.


While this looks quite daunting, this is effectively turning siginfo
from a struct with a giant union, into lots of smaller structs, each
of which share a common header a'la inheritance -- until now the
distinction didn't matter, but it starts to matter as soon as
alignment of one child-struct would affect the offsets of another
child-struct (i.e. the old version). Right?

I was wondering if it would make things look cleaner if the above was
encapsulated in a struct, say __sicommon? Then the outermost union
would use 'struct __sicommon _sicommon' and we need #defines for
si_signo, si_code, and si_errno.

Or would it break alignment somewhere?

I leave it to your judgement -- just an idea.

> >  union __sifields {
> >       /* kill() */
> >       struct {
> > +             __SIGINFO_COMMON;
> >               __kernel_pid_t _pid;    /* sender's pid */
> >               __kernel_uid32_t _uid;  /* sender's uid */
> >       } _kill;
> >
> >       /* POSIX.1b timers */
> >       struct {
> > +             __SIGINFO_COMMON;
> >               __kernel_timer_t _tid;  /* timer id */
> >               int _overrun;           /* overrun count */
> >               sigval_t _sigval;       /* same as below */
> > @@ -46,6 +64,7 @@ union __sifields {
> >
> >       /* POSIX.1b signals */
> >       struct {
> > +             __SIGINFO_COMMON;
> >               __kernel_pid_t _pid;    /* sender's pid */
> >               __kernel_uid32_t _uid;  /* sender's uid */
> >               sigval_t _sigval;
> > @@ -53,6 +72,7 @@ union __sifields {
> >
> >       /* SIGCHLD */
> >       struct {
> > +             __SIGINFO_COMMON;
> >               __kernel_pid_t _pid;    /* which child */
> >               __kernel_uid32_t _uid;  /* sender's uid */
> >               int _status;            /* exit code */
> > @@ -62,6 +82,7 @@ union __sifields {
> >
> >       /* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
> >       struct {
> > +             __SIGINFO_COMMON;
> >               void __user *_addr; /* faulting insn/memory ref. */
> >  #ifdef __ia64__
> >               int _imm;               /* immediate value for "break" */
> > @@ -97,35 +118,28 @@ union __sifields {
> >
> >       /* SIGPOLL */
> >       struct {
> > +             __SIGINFO_COMMON;
> >               __ARCH_SI_BAND_T _band; /* POLL_IN, POLL_OUT, POLL_MSG */
> >               int _fd;
> >       } _sigpoll;
> >
> >       /* SIGSYS */
> >       struct {
> > +             __SIGINFO_COMMON;
> >               void __user *_call_addr; /* calling user insn */
> >               int _syscall;   /* triggering system call number */
> >               unsigned int _arch;     /* AUDIT_ARCH_* of syscall */
> >       } _sigsys;
> >  };
> >
> > -#ifndef __ARCH_HAS_SWAPPED_SIGINFO
> > -#define __SIGINFO                    \
> > -struct {                             \
> > -     int si_signo;                   \
> > -     int si_errno;                   \
> > -     int si_code;                    \
> > -     union __sifields _sifields;     \
> > -}
> > -#else
> > +
> >  #define __SIGINFO                    \
> > -struct {                             \
> > -     int si_signo;                   \
> > -     int si_code;                    \
> > -     int si_errno;                   \
> > +union {                                      \
> > +     struct {                        \
> > +             __SIGINFO_COMMON;       \
> > +     };                              \
> >       union __sifields _sifields;     \
> >  }
> > -#endif /* __ARCH_HAS_SWAPPED_SIGINFO */
> >
> >  typedef struct siginfo {
> >       union {

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNOK6Mkxkjx5nD-t-yPQ-oYtaW5Xui%3Dhi3kpY_-Y0%3D2JA%40mail.gmail.com.
