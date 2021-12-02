Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEUJUSGQMGQEFDO6JKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 522AF466941
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 18:38:28 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id j9-20020a17090a31c900b001abe663b508sf2438134pjf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 09:38:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638466707; cv=pass;
        d=google.com; s=arc-20160816;
        b=nTH2MVuHVFCIm7XzTOjRA/UrHtb6nGXjmTQS8eKYx+Zj5KpFRtyfS4AaQX0WywcZvc
         Ob/n1N/YeSP/A96pez3UrjC6o9V0fqquA6dhVFtWQpQLdSZfbU6TP88KnjpxHyRCIBvw
         Z2zsOE8CWd3DAT0jh8FJYVPGEHjXgNJu2mEC8qGu+8A9IOLxjzSpR88HMAuZJmh7SVP9
         DVj3fiCrcrPxL61JZ707nWcEvMTg2xSatENtI0k3EX3dtlvbDwDKvHRp3jeI51q0ZlUo
         F9iDxvBHSvHwMHU+dnIpZ4TaxEwMimMRb0JQ213gOG9RmYG8lGsYrw0Uxz3rmO6F30oO
         rD2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8vjwQ8gvCbJSZC/TzO8aN8JWUwe4LNOhzYjQxQGD4LY=;
        b=fhmTetsTwIiQVJxAR8DId7g0kfpsyYHnMVDsgCPY1qU8Ol/ryNBbr5oaJZMuenUXEI
         IvKZtM0LmsAZDuFA1cY/RZBAJS+D0e5uRBVwU3baqUuepQS9gXH2vnW54ZibIuamdqHT
         DCGW2hGYO5xp7XRRClr8lv0qFRAuXDZbc5XCFkSIJUcd6oaKXEc9uQLfQAwzqK8cUjn5
         zNFD7r9U0R/lRZgLtgYLvRUv/B4d4Vz4kAvaiAcd8mqEOYELKOiYc4WLp4MaZxMsBPhA
         7JggdyQ1GFJoniJQ1c1VI1B/14IqX4FZSGXlSKsHVm+9TravBabLovIFOLj+dqgPvVol
         VDDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GeF+Yeyg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8vjwQ8gvCbJSZC/TzO8aN8JWUwe4LNOhzYjQxQGD4LY=;
        b=DtDKDm4jhXXTZ+6Ez9tjaX8oZa8MwbaMmnObl+jiZZULUQWpdJrm0fpmf3EG62BAeM
         WFQARZzOnbhBlMv7P/Tnvtemy0f3p9fosBbBLWGr1q2GdYZjbLmvWCtbJnP/gGL87tpS
         7QwI12/Vap/Zoo7+Mvf+SQQD2AsZgcnhKRqbgb5ZFaiVM4e7zxyKIjyHXHgugcCaN3IQ
         933UjhR1bbvhDTZS5t5VZJcFUin1XLBt72Bz68KsfcC61EDgxmc54l8pPa2hM9yVpl2C
         r4fWDk1Bv4D1qqT7PiQwkuJjavn3mw4id/Gk8O9T0NSg2tGalTuID3Md86SwagwGIjuu
         Qzpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8vjwQ8gvCbJSZC/TzO8aN8JWUwe4LNOhzYjQxQGD4LY=;
        b=7/ozrLfxW8xX30cEaUAWdv2+LjicOj/IyXBFiqk6B/oxyO/i5QYP5qBPui1ge8DFcL
         EfnDlC8XX/Su8CJ6+kKvCwl9dZ/AggY5qyr6ZDYmBgoXXZHShJAe54U/IcHdXtdyOZ2k
         Pk79QPm/Frhm0vWfk8T8uMP0TCQ45Nie8p5vF06BU4G37aTGfFIxxWUoiBnR2ouSrYiB
         Lh5cTiMT/lXEzPcW3S7WoM2Z76zOS69a/7MpeDgjSH0TGzjLzRfhzsmb1gvSQ6oitGL9
         i05fG1ECNEW4L2WWyqk9v5J4lMhAf81mhsIn/m/QAow8+gss+xDhy/a6nuck+sXgSd7C
         lhdA==
X-Gm-Message-State: AOAM532MNfom0vh7Fi5zYEO8u5ywcdsf8F3wbQreGSOJDs4flFlR/ng8
	BQAJ4nqIHfBXLcr9lBxyrw4=
X-Google-Smtp-Source: ABdhPJz8VrR1Ae2UJqgpJuoYbzfgOHaZ5+K8yEgSjJhsZ08QtpoBSq8W+bercPs1W3XJn9BKWRvM8w==
X-Received: by 2002:a63:6947:: with SMTP id e68mr483944pgc.292.1638466707035;
        Thu, 02 Dec 2021 09:38:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:80f:: with SMTP id m15ls2643282pfk.0.gmail; Thu, 02
 Dec 2021 09:38:26 -0800 (PST)
X-Received: by 2002:a05:6a00:2441:b0:4a0:ddb0:a6ff with SMTP id d1-20020a056a00244100b004a0ddb0a6ffmr14133718pfj.74.1638466706424;
        Thu, 02 Dec 2021 09:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638466706; cv=none;
        d=google.com; s=arc-20160816;
        b=qQGjf6d2K1F2hrjNNZZOtXtVFYUImSJn4SZ8vHS5b+dR4ty/3Lmb7mCgUmPk9wEnTc
         pFxYrv9/oQfdNTQB9L67Rr1r2DsuTGJol0/GOuIgX22PdVsdZqTlp+WdX2jn/Em0B33g
         hMZGX7oeDNgVc0M/Mv+sMJbpyNENVGaoPb4mtpERBIbOiiHpms/TE2Xq+PYO8nfO1sPO
         pbVPzQ2cXXmfnVcZzrRyrSRdxUBhJEK6ccNwqNnS1xnvMBPelFmTlhuPcSukEd5g+aCf
         gUf3nIPv/tSwsmZah3/YpolWWIOaqsdgiNIJsS4doa9+giBcJIu22uewqoL5nT1vwDwF
         HkBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ur6dUBVD60Gl/OuuEHFc1N/ZnkqMrKChf9cSJr/RUAk=;
        b=pDbsUNpPslRUH6xUF+dJ7F18vSx7eGZ7XZILhUpGVN1KuZ+8gPoi1YHVMdcIL88wDX
         GFASaejoSWTnDkON0QKXjqX8YZs/3uucqXRIqPwBDcpKJzZrdFHM1qqF1+mX9iWmL6UK
         hksdPReC78EjpaBRBnWBLsROcnJubUS/TXGvZCT3Oy3fvN7Bo75CLpJ16ki3Zd6iAS4S
         4jKESyRhFSzgLDxoxOLaCxEO1TxPyriDvYCKBKpsyp15O8ugL0covondaycZvAoA2los
         gC+SUvULZDqPMxPtobRHW8vaROcjTlQdiUHMuGikHUdUi/pEDD/n+w0NHO39LxjdufXL
         WQCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GeF+Yeyg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id l17si24844plb.1.2021.12.02.09.38.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 09:38:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id be32so555388oib.11
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 09:38:26 -0800 (PST)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr5492643oil.65.1638466705594;
 Thu, 02 Dec 2021 09:38:25 -0800 (PST)
MIME-Version: 1.0
References: <20211201152604.3984495-1-elver@google.com> <YajdN5T8vi2ZzP3D@hirez.programming.kicks-ass.net>
In-Reply-To: <YajdN5T8vi2ZzP3D@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Dec 2021 18:38:13 +0100
Message-ID: <CANpmjNM4nxnwt7iWF+kCT862H21CHL-cshYyugBei0ysGAt5uA@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if ARCH_WANTS_NO_INSTR
To: Peter Zijlstra <peterz@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Nick Desaulniers <ndesaulniers@google.com>, 
	Nathan Chancellor <nathan@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=GeF+Yeyg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Thu, 2 Dec 2021 at 18:30, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Dec 01, 2021 at 04:26:04PM +0100, Marco Elver wrote:
> > Until recent versions of GCC and Clang, it was not possible to disable
> > KCOV instrumentation via a function attribute. The relevant function
> > attribute was introduced in 540540d06e9d9 ("kcov: add
> > __no_sanitize_coverage to fix noinstr for all architectures").
> >
> > x86 was the first architecture to want a working noinstr, and at the
> > time no compiler support for the attribute existed yet. Therefore,
> > 0f1441b44e823 ("objtool: Fix noinstr vs KCOV") introduced the ability to
> > NOP __sanitizer_cov_*() calls in .noinstr.text.
> >
> > However, this doesn't work for other architectures like arm64 and s390
> > that want a working noinstr per ARCH_WANTS_NO_INSTR.
> >
> > At the time of 0f1441b44e823, we didn't yet have ARCH_WANTS_NO_INSTR,
> > but now we can move the Kconfig dependency checks to the generic KCOV
> > option. KCOV will be available if:
> >
> >       - architecture does not care about noinstr, OR
> >       - we have objtool support (like on x86), OR
> >       - GCC is 12.0 or newer, OR
> >       - Clang is 13.0 or newer.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  arch/x86/Kconfig  | 2 +-
> >  lib/Kconfig.debug | 2 ++
> >  2 files changed, 3 insertions(+), 1 deletion(-)
> >
> > diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> > index 95dd1ee01546..c030b2ee93b3 100644
> > --- a/arch/x86/Kconfig
> > +++ b/arch/x86/Kconfig
> > @@ -78,7 +78,7 @@ config X86
> >       select ARCH_HAS_FILTER_PGPROT
> >       select ARCH_HAS_FORTIFY_SOURCE
> >       select ARCH_HAS_GCOV_PROFILE_ALL
> > -     select ARCH_HAS_KCOV                    if X86_64 && STACK_VALIDATION
> > +     select ARCH_HAS_KCOV                    if X86_64
> >       select ARCH_HAS_MEM_ENCRYPT
> >       select ARCH_HAS_MEMBARRIER_SYNC_CORE
> >       select ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 9ef7ce18b4f5..589c8aaa2d5b 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -1977,6 +1977,8 @@ config KCOV
> >       bool "Code coverage for fuzzing"
> >       depends on ARCH_HAS_KCOV
> >       depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
> > +     depends on !ARCH_WANTS_NO_INSTR || STACK_VALIDATION || \
> > +                GCC_VERSION >= 120000 || CLANG_VERSION >= 130000
>
> Can we write that as something like:
>
>         $(cc-attribute,__no_sanitize_coverage)
>
> instead? Other than that, yes totally.

That'd be nice, but I think we don't have that cc-attribute helper? I
checked how e.g. CC_HAS_NO_PROFILE_FN_ATTR does it, but it won't work
like that because gcc and clang define the attribute differently and
it becomes a mess. That's also what Nathan pointed out here I think:
https://lkml.kernel.org/r/Yaet8x/1WYiADlPh@archlinux-ax161

Let's keep it simple.

> Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM4nxnwt7iWF%2BkCT862H21CHL-cshYyugBei0ysGAt5uA%40mail.gmail.com.
