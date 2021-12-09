Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE62ZGGQMGQEURPBCTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D4D146F545
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 21:54:45 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id p3-20020a170903248300b00143c00a5411sf2979476plw.12
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 12:54:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639083284; cv=pass;
        d=google.com; s=arc-20160816;
        b=Taut30Ryy5mhlUrjsC8Js+j0EVeuxqh9PNLVFect1Z5aA8H/XPPmdxW3OrSc96QSWH
         mrZ3qsQR9qUJZTQTA9Dgr5lKe22N7t9ih80KP2ZfFSggr9Fl44Cnma48Lvdih4PjjjFZ
         8k2ndDRASyTdjloe9msZ8Qm+aj5pz/69dzbIiCKeUmSqiR3V3vR4V+vRuo3pmrGyRKgJ
         ncRPIvd96SW3v722zy4W/4cqB+4krFVprkDTKaBuUVtkEZGwsUAEjVN3XaaWpzo+7sgc
         nz7h5GpbmWac/nj36O0ESNzdG5EYooj+GipYO4A5aMOccjpbLxfXsyeKce6eqm0PBPrY
         d5Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9YIH7Nw+RSs/8v/5z/4qw1MaJJNpqtFZvNnE4aWJ0iY=;
        b=Ygdel7LannJbSb/aNx8xolObdT6EPtdnDbLyZMnYU6C0rYG0kLX5lFGNHnimi9M35K
         EkfE4yKWaepCP8DiXZ2oIn1idBtCShWr2zApVt10DND9JzToRSuPVKMTrxLkYTmiNzc0
         K5Wg3MgC1pFBM0CmZ/XimfM5eyd6HrC8sXjgbBaXssnJuRsPKOcCy19Ka//vbULb1KMq
         kzahVkN0queJh1num++E50GmVXLTwe6okMptWLNV6tjdgSdsviOkLvSlAiYy8QqjixQp
         ejpxk7DnUcn11o7tuzD528V1k7IqQfxmKT4SN1r3mkcpsRDvS+flZ82A02v7/bH5XYsz
         PFrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fr59f5tn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9YIH7Nw+RSs/8v/5z/4qw1MaJJNpqtFZvNnE4aWJ0iY=;
        b=VMS5thEAap16usIqrPbYG1O/ejLINGWZDxuaZy4vr/p7jL38Qwp9nYxA5m4TGKxtiy
         6RNLrPahJe+FFC3l50xAxEGlrjf1THQdKFZnCevY7oWurZifIk7iGw19m0Tf7U2G9P2m
         xivIEKjP8V9vCddK5Hd9XvLHxCkE2vleAuPC/unqg8DXgZOXzeDYVLI6pfJa45xp/xgm
         kdL1nNrtzIZ0B5PXs+44W92VL+lbcVvtywSDoYVlqfxfksApilfqbt74cdAY96aHEeHR
         WO5dPmGs/OOuCJoz+gn8/XOHdpNvLLsJDkXf0GClSXli1LMfKHVNLRpW3KKbDYgQnumX
         YA5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9YIH7Nw+RSs/8v/5z/4qw1MaJJNpqtFZvNnE4aWJ0iY=;
        b=tqbkK1mrr9dS4Mnjk+1feK3mooae61dDDEip5UGnIaMXEgijIOYFCXZP0y7CE8S5rs
         MnrdtuMPJb09XBGsxNHHOjTm7dohsT4lOs5RdTtyGd2pjsrpxBXtJErupxrInEWcFc+u
         Dpu2p2G/2kb0VZCfwMHZIU+bdaNdzITSjeTcYxdVkQ0LQ+ZrJyWGGS52DmCyCkYKg1bs
         beNG1HKGSlHSfsBelZ3kLqu5S5uyDdUc+YKLrQZPqz1Ovjk+m9/mdlIuwTnrUkboqk5c
         p/uA0GvxpBmr7Oq0Aqzak4j1GXvnr1cjd0yS/YQ9S+OMhBgfxNDTVgbJZU5I0Q10V8LH
         uN1w==
X-Gm-Message-State: AOAM5331h/PTV2pDga8d0P7mH0XGR+x1W/LKl0m2FSjHUxlvPoSjp5da
	X1K7zFT/6Ik6bxYw5QExcoY=
X-Google-Smtp-Source: ABdhPJyCDGnjLi0Rlqo4SJ8Px4BOAy+TOzVEKhxSPE1z8Z+TekKnqS1xrZLVgjYt6KIrI25b8RIGVw==
X-Received: by 2002:a17:902:a5c5:b0:143:c3cf:739b with SMTP id t5-20020a170902a5c500b00143c3cf739bmr69689818plq.9.1639083284009;
        Thu, 09 Dec 2021 12:54:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e5d0:: with SMTP id u16ls3684780plf.0.gmail; Thu, 09
 Dec 2021 12:54:43 -0800 (PST)
X-Received: by 2002:a17:902:d4c2:b0:142:2039:e8e5 with SMTP id o2-20020a170902d4c200b001422039e8e5mr70870384plg.18.1639083283355;
        Thu, 09 Dec 2021 12:54:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639083283; cv=none;
        d=google.com; s=arc-20160816;
        b=ezT+UgWI1nFzdC9uulfzF70cA7JHp2RTtPi2COIG5ggk7b4H9/0eLvCh74+F/eVlrP
         4gFt45whwfLLOD20y2TL+uRZCcJpBH85Zu1mc9m0W9f5sz92Ll3yrcSaLydh0HwK1fgx
         Hth4+UzMzr2QYvcceNw+voiu/TNRqYi1AvQBZg5T7gCXjZcVjDWA/ONPA19JVe5chHKF
         ShUiWE4Z/z09xGH53Rj8b0OXOub/qKnfDlGLEMr9ScsBqjvgFd1FFG2BQ/zNGkACICdf
         ILSU/ikk/qXsheUVtKUlgyEWr275geJy4gqDrXBGLzh9a2tiO8wY/mgsbAtjIi9gWjET
         be6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HFSacAT887PNCoxtm3wOxVaKJ2m3E3kQPyuB0zZo9cM=;
        b=EbJ9AUitk+7hp2ukaIe20HKwJhTUEkIHhe7QFVDZ2QLwVjurNPHLOYeqgP6EfJ3hLb
         6uPqV+M6kw9aFFeSYSzLAgf7+l4mJJswvn1T+0lmhkC0AkQZ9kyeLwhDuyyqfxZV6f1r
         GObkw3eJgLxrf+uqrVY9MR2d76VCzUOdE0V7ydYlISo5Rm4HZMeECOdXxbAWU2P44duZ
         KQTWPb4QjGtZATc9M4UcOWClet2q0VsVP2KKKjD8KNnSZ0UjmelSZyV7YU5eTjuOmNE6
         WmhD5cUo2USOVLeDHTg3Zv2oCMkKnxduzICLkBNJTIdyOxJX/kw0n7l+EfcW2zyXdTBE
         u3XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fr59f5tn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id mu12si940183pjb.3.2021.12.09.12.54.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 12:54:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id n17-20020a9d64d1000000b00579cf677301so7531337otl.8
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 12:54:43 -0800 (PST)
X-Received: by 2002:a9d:7548:: with SMTP id b8mr7516429otl.92.1639083282784;
 Thu, 09 Dec 2021 12:54:42 -0800 (PST)
MIME-Version: 1.0
References: <YbHTKUjEejZCLyhX@elver.google.com> <202112091232.51D0DE5535@keescook>
In-Reply-To: <202112091232.51D0DE5535@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Dec 2021 21:54:30 +0100
Message-ID: <CANpmjNPJpbKzO46APQgxeirYV=K5YwCw3yssnkMKXG2SGorUPw@mail.gmail.com>
Subject: Re: randomize_kstack: To init or not to init?
To: Kees Cook <keescook@chromium.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Elena Reshetova <elena.reshetova@intel.com>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Alexander Potapenko <glider@google.com>, Jann Horn <jannh@google.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fr59f5tn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::334 as
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

On Thu, 9 Dec 2021 at 21:48, Kees Cook <keescook@chromium.org> wrote:
>
> On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> > Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> > default since dcb7c0b9461c2, which is why this came on my radar. And
> > Clang also performs auto-init of allocas when auto-init is on
> > (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> > aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> > allocas.
> >
> > add_random_kstack_offset() uses __builtin_alloca() to add a stack
> > offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> > enabled, add_random_kstack_offset() will auto-init that unused portion
> > of the stack used to add an offset.
> >
> > There are several problems with this:
> >
> >       1. These offsets can be as large as 1023 bytes. Performing
> >          memset() on them isn't exactly cheap, and this is done on
> >          every syscall entry.
> >
> >       2. Architectures adding add_random_kstack_offset() to syscall
> >          entry implemented in C require them to be 'noinstr' (e.g. see
> >          x86 and s390). The potential problem here is that a call to
> >          memset may occur, which is not noinstr.
> >
> > A defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> >
> >  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
> >  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
> >  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
> >  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section
> >
> > Switching to INIT_STACK_ALL_NONE resolves the warnings as expected.
> >
> > To figure out what the right solution is, the first thing to figure out
> > is, do we actually want that offset portion of the stack to be
> > auto-init'd?
> >
> > There are several options:
> >
> >       A. Make memset (and probably all other mem-transfer functions)
> >          noinstr compatible, if that is even possible. This only solves
> >          problem #2.
>
> I'd agree: "A" isn't going to work well here.
>
> >
> >       B. A workaround could be using a VLA with
> >          __attribute__((uninitialized)), but requires some restructuring
> >          to make sure the VLA remains in scope and other trickery to
> >          convince the compiler to not give up that stack space.
>
> I was hoping the existing trickery would work for a VLA, but it seems
> not. It'd be nice if it could work with a VLA, which could just gain the
> attribute and we'd be done.
>
> >       C. Introduce a new __builtin_alloca_uninitialized().
>
> Hrm, this means conditional logic between compilers, too. :(

And as Segher just pointed out, I think Clang has a "bug" because
explicit alloca() calls aren't "automatic storage". I think Clang
needs a new -mllvm param.

Because I think making #B work is quite ugly and also brittle. :-/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPJpbKzO46APQgxeirYV%3DK5YwCw3yssnkMKXG2SGorUPw%40mail.gmail.com.
