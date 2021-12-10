Return-Path: <kasan-dev+bncBD4LX4523YGBBKVTZKGQMGQEJ7R4ZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CCF946F7D8
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Dec 2021 01:05:00 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id k19-20020a05612212f300b002f9b9e6a997sf4922716vkp.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 16:05:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639094699; cv=pass;
        d=google.com; s=arc-20160816;
        b=RWid6am8P77Pak/7Y1QNJsdUDv4x4uNr788JE0VsyBOZvRz53X582tgqmHMRH9keLh
         h3r5OylBT3nSLBt0TcYCpz2NPIGekS9iBfEgWp5a5qYY/eOVq1GQAgZdIXUo7rPwjK9i
         ve9D56lqMmZSYTsdB5cSubp30WKXPRK24nfJrVn4qJWuzEjB5BKnef0w0PKFP+bQ4vF4
         F5PgE03OQTE/PFpF8MuL8KVjF9RNi9TbHP1PYXiug+vxlraAw9OLyvdHJIZ38FLNOAl3
         MJMnphv4Wj5W7sRejdXV2K9IixMt56O3g7AtVT8urhovts3aw3cEcTBseSZkle+8TgSd
         QYUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cJ0j23K12zm8hnHbRepEjmFQw07NNxVC8G2lQDkpubU=;
        b=BhTugtuz43n2uo/IdXvzTDZFJiautUE+xf4ti11fmn1bCrhjpnqIgljrOxQ3xCilEn
         uKlfQT/OubWAe10ru2XZf6tse0idIIx9jWCCv4Yl2CPz6Bl8VJqAsG2rS5evCG4YChV2
         W8N6PKUkkqQ+RaPhqJwwCVciFmyHloIgKhEgGBUiAAnGXYuHct4VeW/n9WL07EBg/0Ak
         9AAyIVIe3VdfD3xIHmuD//YPzziFTs5AKYEJgaL7jY0okz6DrSc6xcWv94Og0cyVfZqW
         aaL8Y55+aS1mJh4QBx2xA+Z5bJa6/WVaS7dNYGe8mPkaznVtnDDT/VkcRbjYaqkNGsOO
         8G1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cJ0j23K12zm8hnHbRepEjmFQw07NNxVC8G2lQDkpubU=;
        b=mm9MjA9NGOGigMCQ9kJRDeXI7vxWbneEc6FU70+FbfGTf7KocRAH53p3S4VNXjTfps
         6K36y1I2bfJ1c3QUA+Mnq4f0xBuFFPxNI2ufV+6CFQ9Uap4xgmyh0+OnWH4UqP9hRjgE
         /8PVK480rAlF+LSRzisVKRbLYExwKfMAIbQKnv+D68x3srsZ21igeGI+wg9SrYLiCFvu
         g/3oVS5SZEkA6ZoKD7uTGaMZ0xpV3XoPLxtFy4aJrmwvycYoCyfGzgiKrGjLXWoWQm5A
         i97V0rrQStvackk9oYg0LKHuDtBoKiNPljtS2EM7F5YP+OkpLahnX5rEOSK2Rn1DMy/t
         SV0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cJ0j23K12zm8hnHbRepEjmFQw07NNxVC8G2lQDkpubU=;
        b=uEWFrQQgetsUUOvqNgSlNekCvu97vxO8dJiPrbRLnfwn78gJP1rOX5XSG4AOJV6BNo
         O5uWklHH3eH7mWKk6KoAt71GzpJhBSKHiEb0q5XKXil/CIgABwRHwwyVTt1Qb1e99RD5
         pUXTyt03wn3ZhDfrG9bWhXTizy/3hSNR+61HKPubC9eyv8PAtirTtXiDvmlPlfy/vXlV
         UEpcEMRUAMP/IOKHES3aTl6mNeHbVyH0sSTByeAZc7MDpnWBl4+UYK9rHhIE/uH2bPgu
         fo7p8VItPhRlFtmTMA+4CQsha+u66vwHTiTazhBMvQITKX1JwKHwlp1GtICnhxnSDqzO
         bV/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZCQV3w3e/u2QwaKl4l7nce3aBPxtS0JCS17eY19OLoLaoGf9p
	yuLpgntssXOSYEXK9vC+v5k=
X-Google-Smtp-Source: ABdhPJxe4B7D3v0DJUIuiFNsZKUBwvLAVM2DJNItsRqyGpjIfI2Etzmyowckn0vEF/KTWdxU4f8jPw==
X-Received: by 2002:ab0:719a:: with SMTP id l26mr23908879uao.88.1639094698131;
        Thu, 09 Dec 2021 16:04:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:339a:: with SMTP id y26ls1212086uap.3.gmail; Thu, 09 Dec
 2021 16:04:57 -0800 (PST)
X-Received: by 2002:ab0:20d4:: with SMTP id z20mr24168982ual.23.1639094697564;
        Thu, 09 Dec 2021 16:04:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639094697; cv=none;
        d=google.com; s=arc-20160816;
        b=XA8QLPyO5Mkxz1RGdVgB629qfIsanIIBvt11MR76H4CJAnjNGfE1VqJSDyrDpFse0T
         86Bh0/W4jdvPNnMiubNCQT5jhKSK9TLhOGCqaZtILu9E17MsEj1qD2pta5qGpqahi3Cb
         a4golMznGKS42FrF8RODiQ/C+OyfSx0k/6SiXSJjdpH/gk5fVzs4r2UoX5KlufmrzoPX
         XwJZ82LkWglKz4c2qf0dYlbDHmgYxxOMbLElrDYMjDk6ZrcXKVP8xJgnx1udXKY39Mnr
         PsBAERQRM3BQtqqCCqYAiPW0eqb04h6cK2BHHqZGpknqOBMS7j1pDon0rWGR7vAcDpDE
         bHww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/jry5C6rCnzu8LHL7KdU7CY+/YQYdhnglt7s7uXcoc8=;
        b=A9LxVhp1GuMY4qho6hPsrdjGud88yEUHdMEFMbbdRZf4qDv+b5um+h4+5I5YxDiT8u
         ZFlan0UN3OE2E9z6DBObvNS/vJ1G2F2abK5FxmLQLem3u0R8NoTqfRuLktOIkOnfknBT
         haU0IXh+SS1gQauVDX20Mc86e7Xb0WL7GT+HqfTnopRkcPU+RNjErBiS63oVDaOg8ALz
         pudiesFE73FhLltyS+48IuzEJwW0fdFo8cUahyRrqXfxdPTxIrbQRdNjk0ToLXM8bX0r
         L//RL5+A6OcPtBZiR8ycY08Ro43EVlYJB+4/Ty8L2VlBtVrkyAEEw2uaL0QimFpOy7Wy
         aqqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id q25si140091vko.0.2021.12.09.16.04.57
        for <kasan-dev@googlegroups.com>;
        Thu, 09 Dec 2021 16:04:57 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 1BA01m5F024581;
	Thu, 9 Dec 2021 18:01:48 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 1BA01ljO024580;
	Thu, 9 Dec 2021 18:01:47 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 9 Dec 2021 18:01:47 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Kees Cook <keescook@chromium.org>,
        Thomas Gleixner <tglx@linutronix.de>,
        Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        Elena Reshetova <elena.reshetova@intel.com>,
        Mark Rutland <mark.rutland@arm.com>,
        Peter Zijlstra <peterz@infradead.org>, Jann Horn <jannh@google.com>,
        Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
        linux-toolchains@vger.kernel.org
Subject: Re: randomize_kstack: To init or not to init?
Message-ID: <20211210000147.GZ614@gate.crashing.org>
References: <YbHTKUjEejZCLyhX@elver.google.com> <202112091232.51D0DE5535@keescook> <CANpmjNPJpbKzO46APQgxeirYV=K5YwCw3yssnkMKXG2SGorUPw@mail.gmail.com> <CAG_fn=WEOb_3_u3CrAG36=j_moeHu0hmFmqM+sXSTepnN8kLjw@mail.gmail.com>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=WEOb_3_u3CrAG36=j_moeHu0hmFmqM+sXSTepnN8kLjw@mail.gmail.com>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Thu, Dec 09, 2021 at 10:11:19PM +0100, Alexander Potapenko wrote:
> On Thu, Dec 9, 2021 at 9:54 PM Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 9 Dec 2021 at 21:48, Kees Cook <keescook@chromium.org> wrote:
> > >
> > > On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> > > > Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> > > > default since dcb7c0b9461c2, which is why this came on my radar. And
> > > > Clang also performs auto-init of allocas when auto-init is on
> > > > (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> > > > aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> > > > allocas.
> > > >
> > > > add_random_kstack_offset() uses __builtin_alloca() to add a stack
> > > > offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> > > > enabled, add_random_kstack_offset() will auto-init that unused portion
> > > > of the stack used to add an offset.
> > > >
> > > > There are several problems with this:
> > > >
> > > >       1. These offsets can be as large as 1023 bytes. Performing
> > > >          memset() on them isn't exactly cheap, and this is done on
> > > >          every syscall entry.
> > > >
> > > >       2. Architectures adding add_random_kstack_offset() to syscall
> > > >          entry implemented in C require them to be 'noinstr' (e.g. see
> > > >          x86 and s390). The potential problem here is that a call to
> > > >          memset may occur, which is not noinstr.
> > > >
> > > > A defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> > > >
> > > >  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
> > > >  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
> > > >  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
> > > >  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section
> > > >
> > > > Switching to INIT_STACK_ALL_NONE resolves the warnings as expected.
> > > >
> > > > To figure out what the right solution is, the first thing to figure out
> > > > is, do we actually want that offset portion of the stack to be
> > > > auto-init'd?
> > > >
> > > > There are several options:
> > > >
> > > >       A. Make memset (and probably all other mem-transfer functions)
> > > >          noinstr compatible, if that is even possible. This only solves
> > > >          problem #2.
> > >
> > > I'd agree: "A" isn't going to work well here.
> > >
> > > >
> > > >       B. A workaround could be using a VLA with
> > > >          __attribute__((uninitialized)), but requires some restructuring
> > > >          to make sure the VLA remains in scope and other trickery to
> > > >          convince the compiler to not give up that stack space.
> > >
> > > I was hoping the existing trickery would work for a VLA, but it seems
> > > not. It'd be nice if it could work with a VLA, which could just gain the
> > > attribute and we'd be done.
> > >
> > > >       C. Introduce a new __builtin_alloca_uninitialized().
> > >
> > > Hrm, this means conditional logic between compilers, too. :(
> >
> > And as Segher just pointed out, I think Clang has a "bug" because
> > explicit alloca() calls aren't "automatic storage". I think Clang
> > needs a new -mllvm param.
> 
> I don't think the original Clang flag was built with just "automatic
> storage" in mind.

My comment was about the GCC -ftrivial-auto-var-init= flag.  It only
influences automatic variables, as the name suggests :-)

What it does is it adds an initialiser for the variable early on, long
before it is generating anything like target code.  Handling alloca has
to be done somewhere different (and probably should have its own flag
anyway).

> Now that there's a single call to __builtin_alloca() that happens to
> suffer from initialization, it is hard to justify that initializing
> allocas is a good thing to do.

The same argument holds for *all* unnecessary initialisations, btw; it
just isn't obvious what it costs for a single simple variable, but it
all adds up.

> But I believe developers in other projects don't want to worry about
> how they allocate their memory when turning stack initialization on -
> they just want to be on the safe side.

Sure.  And the kernel has a tiny stack anyway, so unless that alloca is
in a hot path (or wastefully allocates way more than is actually used),
initialising stuff isn't worse than anywhere else, just more obvious to
spot in your profiles (everything will easily fit in cache after all).


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211210000147.GZ614%40gate.crashing.org.
