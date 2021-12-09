Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHXCZGGQMGQEUHEFYDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id ACDD746F5AE
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 22:12:01 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id jo4-20020a056214500400b003a5cb094fb8sf11210242qvb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 13:12:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639084320; cv=pass;
        d=google.com; s=arc-20160816;
        b=NBjYfrExlZoqZHpHDlRPTOwfzDMCUpw4ym4vNYkuKjSqh7hkwE4IxdGAqQSO5qmkAu
         xkDnyHA0g1yhCAhr+vdFRregso40A9pO7A7BMlSP0Vsrq/t/YjrqwMB2umdFdzbPh47P
         o5b6Ek2/UaVEo6RuWrYFAgbWPVZZ8QjRkWnjyBO+t3h+4r63onYACatDtQefcPCiWWNz
         i6x+VCttfSYTa3gij6h8qVQcKD05Wzc/F4b1eZMwOmRhwbBVXjoKJ7ekDvnUFX6fUg2C
         y8f1K8jE9k1Kv7OsFJhvg/ZEBceEQQXaopflwfxgtijs5Uxtjpxi5zOdEneF8Xnu49w6
         e9xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yf0HIvVRU+oRUx+wZndbLKrfwInUyHINx7NUqkFj7zM=;
        b=Hp+HvqkOOaxw+aiWK2vVJ3pnJc0Dcjvz36rB38x3c16Ltvs1IWWGgGbnjKuDA+Blq3
         sKuQnizvQ0lWsmf5hUGkUgBhL90aOUeJtsfyGPuSysqz6bRSo+Y6pNa4jqFqDcM9GeLO
         T93XJiDkhlNS7ZdgSDyCbVHwpV0FhgVo6cmfpMSUzM8Cv2gDGvvBl0JnOT9BQ7nJ/Z6G
         gOObcqeUrN+6PimQGFyg9z5tBqLpKLqsMmJvO3F19gH/uIDgNcUsQqE3vu70a34CQius
         01rAkOPHhFF5FI6QTk+rPaO2bIwivDJH0KooEF2c5x43tBhdNverfWNaEL0CWkHiLvN1
         +UBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HD6w//AO";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Yf0HIvVRU+oRUx+wZndbLKrfwInUyHINx7NUqkFj7zM=;
        b=OicCv8o5pej2I/7jihE9B4WIxA1ll5fjWxaoh38dPHhjyrv4aB+LWpT5LvdAQmDSWG
         3GN9dHGy75tYhc/NVpBD6r9SzgtiC6CWYcncJhVQb8hR5L9bZ40sXyV7NNCrEpLcO3cH
         NvEm7lFdhiJBThtGujWuZJkdTYhJ1qXppMZc5hD9VC7Pp8FEiTA34bzdlSY02ztUHfQF
         Sd6S31zsYrjsXqPq3TBmphhYuoU0QRZysCpZfPV5D+TCU5POOpXRNmp2az4EDCPgZV0v
         5lCVyM7llLy9fDCCviWLOJv1COK/N0C3r0sDkm4vbw1RidjmcimscfO3fbgbVRkg2ITI
         z3gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yf0HIvVRU+oRUx+wZndbLKrfwInUyHINx7NUqkFj7zM=;
        b=fmSkVqzDJFwQUp0tog+8lnceHLsOJZ0I458aWYfOy91C38LG/dgyIifACtIog68hDy
         k2ZkATYQK2krXsyiFDHiJYqigO1gcW9aTbw2ESaj0q3RNVzodR5jx25yx9wPqH2okFhV
         cP67w/xd87+wZTGx1d/BjMfNb8rcLL4HcWK2zi5L0siwywbchgyEL4S4iMLW3DHZ3rea
         B35cuoblTy/71CMGdU88ueQ5AGXc+z+hbyQe79db1NPRLJE8o9xBTLNpLVfkiluMSBBv
         cul4e1yOzNKhabSFJH+iNx/O7fiwtp7wEOLTL05iF5T40IezeUbamkRk86LdU+wi/MiP
         po6g==
X-Gm-Message-State: AOAM5336563fA78rYdqShRVNtM/sz6D2ZrXIEQM9UIzaNQgF+llvzKow
	Mych9zBXNpAAxqKdd++SuqA=
X-Google-Smtp-Source: ABdhPJwWChnqYG8FoWc0M/CuyyQ8L0M74jykCzQ36Tg1SxzF2cOOEKkXFip/4Ay/j4Lua6OtDS3IDw==
X-Received: by 2002:a0c:e5d1:: with SMTP id u17mr19407890qvm.120.1639084318472;
        Thu, 09 Dec 2021 13:11:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:19a2:: with SMTP id bm34ls4544165qkb.5.gmail; Thu,
 09 Dec 2021 13:11:57 -0800 (PST)
X-Received: by 2002:a05:620a:2684:: with SMTP id c4mr16257964qkp.24.1639084317774;
        Thu, 09 Dec 2021 13:11:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639084317; cv=none;
        d=google.com; s=arc-20160816;
        b=yJ5EoblbqmOkXYIf1dww6CleCgHoXwGfK8xRY+wCJuvpnXhKcfOmnP4/h1MDx1qMML
         WukmoOEHDo2RMHfuQWaTV0KEX1U+dsG0OWcnf7wOfB2tXN06Lbm3Un4g44ccmD08A6oY
         DR4cWUCXEL85WBScThoQ485b6JaL47ZiAlXzMbdBC1tSQUf6kdi95B0SJM4wIyv+ztdz
         Vkgx5LvV9MveZ1kg48mP8JcHOTq32WE5xb7DEvEU9+wPD3eEZna/4udaxaQAktJ2fGIj
         jW6+/vIivX+gGurMWhf/Fc3zO+HXiidv3rOUA2m+XdJEbX91U26JQm/pVX9PtV2+h+Nc
         9Geg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=f39DFnoj8lua8eJKcrSxpR3sJ0r+3/YfBmxC1RnRv7o=;
        b=EZKxaeuYOO+SGOq5ahoZLviIEJqLeFaFmiyum07cLv11+J4g4JLP/HtKPqnTk8GfMZ
         2M4uBMNCmfg3Vk5rcLJ9Ae4UQA6uQlxUz4YusvhJz5fYXPNRPW1iXvClTZJkdZoRcH88
         +nb5lY6qNh7ehFF9bdPaM80hnGlENphRqYMGrCjTOC7M8l9z0D8QkR76HVqSAStEdZVq
         W9nDEvsg74JbN8kvU7UDmWKT85wyIwgFhdTYJ2oC4VttkfjnxVIEnCcZj8dO0izy7G2t
         39KiSGKSZJTkRG951E4X7QxnNlSq0lzvCsfRBF1rxFWjnV6Qa0vBqltGxZR8OcjDrWMV
         vHpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="HD6w//AO";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id k10si41428qko.0.2021.12.09.13.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 13:11:57 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id t83so6047929qke.8
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 13:11:57 -0800 (PST)
X-Received: by 2002:a05:620a:2848:: with SMTP id h8mr16571622qkp.610.1639084317071;
 Thu, 09 Dec 2021 13:11:57 -0800 (PST)
MIME-Version: 1.0
References: <YbHTKUjEejZCLyhX@elver.google.com> <202112091232.51D0DE5535@keescook>
 <CANpmjNPJpbKzO46APQgxeirYV=K5YwCw3yssnkMKXG2SGorUPw@mail.gmail.com>
In-Reply-To: <CANpmjNPJpbKzO46APQgxeirYV=K5YwCw3yssnkMKXG2SGorUPw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Dec 2021 22:11:19 +0100
Message-ID: <CAG_fn=WEOb_3_u3CrAG36=j_moeHu0hmFmqM+sXSTepnN8kLjw@mail.gmail.com>
Subject: Re: randomize_kstack: To init or not to init?
To: Marco Elver <elver@google.com>, segher@kernel.crashing.org
Cc: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Jann Horn <jannh@google.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="HD6w//AO";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Dec 9, 2021 at 9:54 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 9 Dec 2021 at 21:48, Kees Cook <keescook@chromium.org> wrote:
> >
> > On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> > > Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> > > default since dcb7c0b9461c2, which is why this came on my radar. And
> > > Clang also performs auto-init of allocas when auto-init is on
> > > (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> > > aware, GCC 12's upcoming -ftrivial-auto-var-init=3D doesn't yet auto-=
init
> > > allocas.
> > >
> > > add_random_kstack_offset() uses __builtin_alloca() to add a stack
> > > offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> > > enabled, add_random_kstack_offset() will auto-init that unused portio=
n
> > > of the stack used to add an offset.
> > >
> > > There are several problems with this:
> > >
> > >       1. These offsets can be as large as 1023 bytes. Performing
> > >          memset() on them isn't exactly cheap, and this is done on
> > >          every syscall entry.
> > >
> > >       2. Architectures adding add_random_kstack_offset() to syscall
> > >          entry implemented in C require them to be 'noinstr' (e.g. se=
e
> > >          x86 and s390). The potential problem here is that a call to
> > >          memset may occur, which is not noinstr.
> > >
> > > A defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> > >
> > >  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset(=
) leaves .noinstr.text section
> > >  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to m=
emset() leaves .noinstr.text section
> > >  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to =
memset() leaves .noinstr.text section
> > >  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset=
() leaves .noinstr.text section
> > >
> > > Switching to INIT_STACK_ALL_NONE resolves the warnings as expected.
> > >
> > > To figure out what the right solution is, the first thing to figure o=
ut
> > > is, do we actually want that offset portion of the stack to be
> > > auto-init'd?
> > >
> > > There are several options:
> > >
> > >       A. Make memset (and probably all other mem-transfer functions)
> > >          noinstr compatible, if that is even possible. This only solv=
es
> > >          problem #2.
> >
> > I'd agree: "A" isn't going to work well here.
> >
> > >
> > >       B. A workaround could be using a VLA with
> > >          __attribute__((uninitialized)), but requires some restructur=
ing
> > >          to make sure the VLA remains in scope and other trickery to
> > >          convince the compiler to not give up that stack space.
> >
> > I was hoping the existing trickery would work for a VLA, but it seems
> > not. It'd be nice if it could work with a VLA, which could just gain th=
e
> > attribute and we'd be done.
> >
> > >       C. Introduce a new __builtin_alloca_uninitialized().
> >
> > Hrm, this means conditional logic between compilers, too. :(
>
> And as Segher just pointed out, I think Clang has a "bug" because
> explicit alloca() calls aren't "automatic storage". I think Clang
> needs a new -mllvm param.

I don't think the original Clang flag was built with just "automatic
storage" in mind.
After all, people do forget to initialize their variables, regardless
of whether they are automatic stack variables, or malloc() or alloca()
allocations.

If __builtin_alloca() wasn't banned in the kernel, we'd probably want
it to return initialized memory, because otherwise people would be
making the same mistakes using it.
Now that there's a single call to __builtin_alloca() that happens to
suffer from initialization, it is hard to justify that initializing
allocas is a good thing to do.
But I believe developers in other projects don't want to worry about
how they allocate their memory when turning stack initialization on -
they just want to be on the safe side.

> Because I think making #B work is quite ugly and also brittle. :-/



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWEOb_3_u3CrAG36%3Dj_moeHu0hmFmqM%2BsXSTepnN8kLjw%40mail.=
gmail.com.
