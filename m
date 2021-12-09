Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ7PZGGQMGQEKH6ZG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 81F0846F61A
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 22:40:56 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 1-20020ad45ba1000000b003bdfcecfe10sf11333129qvq.23
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 13:40:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639086055; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gswp1wPgnuCuPz37nwr+pOEiM8CbsdtTsdueKEv0RxAuwKZ2piKvN4qpH6BCqqhXhb
         lE8hyGJtMybjNS3TsvHqPCxd0leMhqBAZiz3DWBKCczYAjLCNOK/ssowIucuzlivDU3X
         k3PUTkQZuOmcPotajicvh0thFo5MMpH6T/IP/f4r0qAT/kRJgJEjHWNaCyXJ5WK6KJ6c
         NoKI7Uk0JTneuocyHVTaVjY5rplhuK6dsg8ag66yVsdAYKjEljEbr+YPrZaoRdk8bMCt
         x4D1ZMGhYsNxsK1Glql/KN2gRUeXzbyrQrycABNJkSRFQdtXgRMWmVurfH1uCZKkNCwY
         NrQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wJvYDo9lt3pANgcSHs7U5qlM4yK7nhhlSnze5ThgYsY=;
        b=Tgaun5h4ImacSSN4gM1qZeDCccNhaAVoCiCQEFUBBH9Yuh2CNzRi+0CB1EWZZv12Es
         kL6+B9dX5Cf4DN/0W7HAqf2osEc5jrlAf3uecjRt4sCjDYDZYH9oUTr4B1kq7x44a98e
         p+OqkBwjo5Ci7T0jBu0ySxcssforZ8GD6d5jFQiPs86nia+KTJsYUheSxNY8k1P8m9SO
         c1gjxkQw7a7WxfU2Eo60Ca57hhIGY7GOMsAQFVDDBirIDlV4nesNGNoi0nnPhPSDuKnt
         AAQB3ntN2jhXZ+bxguInETlCvAfl8fAPHzvK2n6wJ04qjFnbE047PRdjrXsm3bEkGvDm
         xY2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n+iW5W03;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJvYDo9lt3pANgcSHs7U5qlM4yK7nhhlSnze5ThgYsY=;
        b=bC1H1/9CJDlewOPQNXfEW2EcPEOcyXykJnNZGLVJi2RQ8x3qIeBf2WGviTXHs6+Kvu
         tDuoBiLoIOEnI275R6HltPcTFk/Q+dZZ63TQkQxd5bYiBFsVxmNdjuLII5guxpmOlpEE
         toZywYmpAdwczOkleJLgHqqe/w3wTRkh18ICfriekcmko4vN6TWQtlrLF8IlNkt3JbmM
         acckT059CM2/SozWUAbxcffZQMe9xGPdvms46jW1GbdduGQLGpR/gn0ZbX08soXpmz1e
         pna1cAKlWtfIpyug4SILU+n1yn77ZD3AZZHEYuXIPaQX74RbPfH9taXfAHduFXN7IAK0
         bQEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJvYDo9lt3pANgcSHs7U5qlM4yK7nhhlSnze5ThgYsY=;
        b=ooP71Mn+4Suubi0TMgxz8ykR16+TgSXznNbp/ME5ziyupaCKUUf9a048ymFunrZjfc
         Xuske3LPbx7VaNCy6GPTO+bFDzTbnC2QchxBN1A37zmm4U3LAsqnMDqqXtsU/oyQzf6E
         0kyYrFKNt3i1ebQx8WlQhEroe+ZTGRY0eNarRStM0DneAU/5ilHwyZaUz1V3VRlNf8l7
         idCLN5buzbxPl8pY3Ir0AFAljm78gX+9ALJyQGFRyaEl310MjAPIzSzXiV3tM7ktVHuv
         /8yEgT/cgNv4Qfiu9KGz0tni/erHDT9URVC32NCeBJ4LwfCO5cdJ9MUbSuxet3FQ3Lbq
         XK/w==
X-Gm-Message-State: AOAM530nzPGwgrT95cQwnOqFTrA0r2JW0FRwqFBQXi5u55HRke6j6xzR
	+h+4WIsgI+rCyeiLGxLFP5E=
X-Google-Smtp-Source: ABdhPJwDyCv2Mgjw8HHz19Cg2aGNnj0nf5gtKjZhc+oo2J5oFkEVcfO8JauIG+MXZJT6hVTjSnoskA==
X-Received: by 2002:a05:620a:454b:: with SMTP id u11mr15987433qkp.599.1639086055628;
        Thu, 09 Dec 2021 13:40:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f3cb:: with SMTP id f11ls3739196qvm.4.gmail; Thu, 09 Dec
 2021 13:40:55 -0800 (PST)
X-Received: by 2002:a05:6214:23c9:: with SMTP id hr9mr20830035qvb.83.1639086055109;
        Thu, 09 Dec 2021 13:40:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639086055; cv=none;
        d=google.com; s=arc-20160816;
        b=R/07HC1MekmHfXdATGffjR8FggOoFMQEOrdPV1uUIYi1BXXWTn0r7o8h+HtDdpal5z
         pzxtcn4yqZjePHmHzVmJ+xzMv5L676qKWa+QonRtGSFJFGScHugD6muPSaAkJL4XIMF4
         s+tAIBXMyqvuc23XBXuY2TPjyIwW6Lx4gw9y22ISIg50GIKsZkWQ8ND8xslzIe+gQKJ9
         mp3a+WJx3ca3zYUTXGcCUO4oWMiWKH3r545xFSD5+7zIsXpVLC09sRBUs2jHRb4aDYd6
         x1boZGUk+TZn9v1id+IxbnKIqA4ojA7qD9AiJdm8yG/JrcIHh++FmEx2PhuYCnvsE7yZ
         htHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2j4bcO0qWcjtdm6gaythjKIq7TrKLkjf4762fiQLRQ0=;
        b=v2pOebTrivg80ulUirkAVn8QIAKk4qFn2P/NZUYyxsyQ9Ec5msEpkGsdP69f7X/Xkh
         kGSA7TLDt0pU80hHV2r9PQH5RcHqD3WJOIio7IOSrbJvgL8qY5JRTgCvDoKhiKdNwmZl
         MLpOv5/9kAgxaRyXnHJ/Z2Z2qXot7MD/bFJq5KKkp5A7i4n4wFo2+iJu9we2tz1tVT4c
         esol/8+uitd3q4jM8W1xrS3LptQcYLhWbubW9oYs7kvE2sQYldtwEW0ovD/wrTeO3QFe
         Oj/GClgVbYUm2myQKR7X1RVdCW/QlKKj2F4PlEdKwynanOkKj8iGQYH/gncUlng3k6dO
         PHfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n+iW5W03;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id s4si235764qtc.4.2021.12.09.13.40.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 13:40:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id a23-20020a9d4717000000b0056c15d6d0caso7631410otf.12
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 13:40:55 -0800 (PST)
X-Received: by 2002:a9d:7548:: with SMTP id b8mr7757039otl.92.1639086054434;
 Thu, 09 Dec 2021 13:40:54 -0800 (PST)
MIME-Version: 1.0
References: <YbHTKUjEejZCLyhX@elver.google.com> <CAG48ez0dZwigkLHVWvNS6Cg-7bL4GoCMULyQzWteUv4zZ=OnWQ@mail.gmail.com>
In-Reply-To: <CAG48ez0dZwigkLHVWvNS6Cg-7bL4GoCMULyQzWteUv4zZ=OnWQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Dec 2021 22:40:42 +0100
Message-ID: <CANpmjNOA2BKJfPAFH56etdQ70hsoPFb_VJizipKdJMgEgf3jTg@mail.gmail.com>
Subject: Re: randomize_kstack: To init or not to init?
To: Jann Horn <jannh@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Alexander Potapenko <glider@google.com>, 
	Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=n+iW5W03;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Thu, 9 Dec 2021 at 22:16, Jann Horn <jannh@google.com> wrote:
>
> On Thu, Dec 9, 2021 at 10:58 AM Marco Elver <elver@google.com> wrote:
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
> >         1. These offsets can be as large as 1023 bytes. Performing
> >            memset() on them isn't exactly cheap, and this is done on
> >            every syscall entry.
> >
> >         2. Architectures adding add_random_kstack_offset() to syscall
> >            entry implemented in C require them to be 'noinstr' (e.g. see
> >            x86 and s390). The potential problem here is that a call to
> >            memset may occur, which is not noinstr.
>
> This doesn't just affect alloca(), right? According to godbolt.org
> (https://godbolt.org/z/jYrWEx7o8):
>
> void bar(char *p);
> void foo() {
>   char arr[512];
>   bar(arr);
> }
>
> when compiled with "-ftrivial-auto-var-init=pattern -O2 -mno-sse"
> gives this result:
>
> foo:                                    # @foo
>         push    rbx
>         sub     rsp, 512
>         mov     rbx, rsp
>         mov     edx, 512
>         mov     rdi, rbx
>         mov     esi, 170
>         call    memset@PLT
>         mov     rdi, rbx
>         call    bar
>         add     rsp, 512
>         pop     rbx
>         ret
>
> So I think to fix this properly in a way that doesn't conflict with
> noinstr validation, I think you'll have to add a compiler flag that
> lets you specify a noinstr-safe replacement for memset() that should
> be used here?

Yeah, this story isn't over with __builtin_alloca().

A workaround would be to use __attribute__((uninitialized)). Of course
that implies there are no uninit bugs. ;-)
To initialize in noinstr, __memset can be used explicitly.

Maybe there's some guidance on what is and what isn't ok in noinstr
code so we can actually decide what is the right thing to do. I found
this: https://lore.kernel.org/all/878rx5b7i5.ffs@tglx/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOA2BKJfPAFH56etdQ70hsoPFb_VJizipKdJMgEgf3jTg%40mail.gmail.com.
