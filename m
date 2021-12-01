Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD55T2GQMGQEYYYJEGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 3704346528E
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Dec 2021 17:10:58 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id s2-20020a632142000000b0032173c0daf1sf12324047pgm.16
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Dec 2021 08:10:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638375056; cv=pass;
        d=google.com; s=arc-20160816;
        b=MsG/B2/FGyq6kIr1hHJhIb67iHIZgkk+d0elWQHdkkAvDj1vhA3SyP/pI6ky4Itb7n
         DJAZKkM/D7atvIMMFtEqmPMKf52MSfvBsuPx0nUHsU7lSZtuM5BmGsfDyN1nuux+d19b
         Q0cXgkeNbNFKFITV6o4RhcSifdsl49v4nBsYs66rVvRfq5Wp0Moch5q/EUp5BBiZSFNu
         qgJYS+udD4+Duh9/ytnceEVgi5lmRPOIZ2kr8tAy86rV7eZDCwVxlgMntsKxarvwGO+R
         3A+p51PSiZq0pzkj6EkRcvCnLUKLwJxMOxnCrzO4sdStv7rmCB6WVf+Qyk2OlMcayB52
         s3Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h+Cez6KwsrpWzI1ic0zdve5kf7FLImDMdUe0kOenM2U=;
        b=BjjRE/Nteic8TYRJRu8qwtuUXJf2SJOYgf2dY9MebpaZWVXq8r0rwHOM/O3iWTLQZ4
         Ovc4a9cVEV+b/yreKFsRM4LNDVRyZbpBKRMoLBpE3JX9aTKP0EBsB7jOKS83o4ktvQZv
         s8i0Negzxu5g/Eu8hn/uycT+5Yge8ByDH7ziNgarzbI0xMNp9FDOJK6Zv0Y2UT2Zcf8W
         Xsz9PrGLKnNcybxlqnbD8JaDDcZjMUOm9thYfQbOjdc55YL0ce5nK7q0yySmseevnS8l
         dO3B8NF2BwI6FXVIPU/EGnN/FSwB4OPFm+cfmr9U/cEXXvO7Grtf8w7VnuaZncIPQ0Ih
         ucfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="RLrKil5/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h+Cez6KwsrpWzI1ic0zdve5kf7FLImDMdUe0kOenM2U=;
        b=fiFTV+jcDeLIbIn03p0Sx8dSzX22E569OlpY0gPllR49RvAmEew8DHd/ZS4JblU0AV
         qHWVjHsLW/ddsdvZiQ8lD9u6Jgn0Z+iVOBip1VPJr7CCuyugyisFty2rtEkH5sVDh6iO
         IfmW5dU7Pa5RlqLqJw23viF/ZRe9EBQZjpDLcBUjPjL0yqpzCQWFs87NY+K62VlgMdvS
         0gAOP5C3jaElnOTeBZDdVTcnsmPXckcDBbYyU/wVJDlcNka06dOMxnzV/aZQSJHX1IIZ
         tfzPgGWP4jZE3AQu+fEfzuK5UYvHUSeqrO07xLtASE3zKBBC56NNclXj1HHzPKhzP0c0
         C4lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h+Cez6KwsrpWzI1ic0zdve5kf7FLImDMdUe0kOenM2U=;
        b=Izj9xgcRZFhf/KrW7ZKoYea04J43i25IFHGTxNHMXSBUXN7l3hDR6Lsa2zorGCOJnr
         Hu1W7DanQZauWNK3oyYKx11CQY2YsRCfGmV9K5aEPwiXCpp4XZQ0ISlIqkVMO/CD6fcX
         B1s2I5x3d7iCDjGv6eiMBuxF8IbjnOhI0doe5xpyRasay8JmPQuyVbswqeue0ZdVGrlx
         x/oJ4ezOFMzF2/Pv4i5qBLfz0/uWRJcy9YOibG7KE/39e4H7gZZvvw9xIrwU3V3MnQ4b
         LX5qsyCT8oRcUwLh0j5Gfytkdufv+Th3XasTeLsC9Fz5OLBDvlIFtbrCsmNAhazgkXIw
         cIGw==
X-Gm-Message-State: AOAM530zUIMRE8nX9p5njObCfcp5DX2I6geIpXAA4MKzWCKVttYn1iV1
	7a1e7LhM473f/BYRJNLfO6M=
X-Google-Smtp-Source: ABdhPJwaWohNpU+ouKkZC0LDr7Zi29ej80VVK7tNB2t4GVCAGzdlve503gC1b2ZnOsFrqUxge0nw5g==
X-Received: by 2002:a63:2b83:: with SMTP id r125mr5384536pgr.92.1638375055697;
        Wed, 01 Dec 2021 08:10:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1946:: with SMTP id s6ls1195641pfk.5.gmail; Wed, 01
 Dec 2021 08:10:55 -0800 (PST)
X-Received: by 2002:a05:6a00:882:b0:4a8:342:659c with SMTP id q2-20020a056a00088200b004a80342659cmr6906746pfj.79.1638375055074;
        Wed, 01 Dec 2021 08:10:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638375055; cv=none;
        d=google.com; s=arc-20160816;
        b=pHh5OXWYbRt+TRSL9WxS4g1NGLWQWoF2cmoU7NuyDDeGfrAV505J8JKdHK4g2hVXYh
         O0lE8LoFzUoe1OlEuFxpCiAa+3LNu2GgD5MwyEMd+qBHQUzD46LKfasGag8Dz2nRC1RL
         PLWIH11iZ8RJoK6CkRysWCtS4giCnOw84+bUyNWbTCWaXlKB1bhggdJflFmAXoP0BpWn
         XHP6wbrHobgljZcZwYQsn0dX0LzZ8cgADOTuiRi4duiwPebqdxE7iIbdY6aArMXdDrr1
         jD4nMnfPLQfbZtvt7Kvq0P8onFzQga0kblQmR8QMmqvU0pEoqkPcBBMmJd6gvXRBA03C
         8LVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qEqb4KAOgMzFJNLkGQkPT3DXIyCBroaySsB9I+dSD/s=;
        b=BpjPFAZNCZuExkL0weDTkR9YZoFtSv5EEvh4FpYekr4rz4zfcLr5sX5tvzQAybpWZb
         576Y4BCiT5DtylkhhKsBQ6yi6wAXR/yB/7pFnoAvmaFTbCrJwODFruac0bWqX7QIgvXw
         VLBHMg3E81hd1nCN2Lk6xe/Zd29cM5BbElG+zH4bhzt4dktXlzACCA6c4G26qOinzSP2
         R8tcsPBlN7RRiUjtmq3N8ajEskP0s8vcIVvzgOlxlmJGwaYV8nbLbKhK2Q6mqMoL/yEP
         Ku84rjPyAeqbKFw/54eSiGPBFo+heKnp+hdNb+1nRiepSzUWSDwMwYRDxZIAXHyGhR6w
         F26A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="RLrKil5/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id t14si14654plr.3.2021.12.01.08.10.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Dec 2021 08:10:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id v15-20020a9d604f000000b0056cdb373b82so35838061otj.7
        for <kasan-dev@googlegroups.com>; Wed, 01 Dec 2021 08:10:55 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr6449697otl.329.1638375054586;
 Wed, 01 Dec 2021 08:10:54 -0800 (PST)
MIME-Version: 1.0
References: <20211201152604.3984495-1-elver@google.com> <YaebeW5uYWFsDD8W@FVFF77S0Q05N>
In-Reply-To: <YaebeW5uYWFsDD8W@FVFF77S0Q05N>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Dec 2021 17:10:39 +0100
Message-ID: <CANpmjNO9f2SD6PAz_pF3Rg_XOmBtqEB_DNsoUY1ycwiFjoP88Q@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix generic Kconfig dependencies if ARCH_WANTS_NO_INSTR
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Peter Zijlstra <peterz@infradead.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nathan Chancellor <nathan@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="RLrKil5/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 1 Dec 2021 at 16:57, Mark Rutland <mark.rutland@arm.com> wrote:
>
> Hi Marco,
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
>
> I agree this is the right thing to do, but since GCC 12.0 isn't out yet (and
> only x86 has objtool atm) this will prevent using KCOV with a released GCC on
> arm64 and s390, which would be unfortunate for Syzkaller.
>
> AFAICT the relevant GCC commit is:
>
>    https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
>
> Currently we mostly get away with disabling KCOV for while compilation units,
> so maybe it's worth waiting for the GCC 12.0 release, and restricting things
> once that's out?

An alternative would be to express 'select ARCH_WANTS_NO_INSTR' more
precisely, say with an override or something. Because as-is,
ARCH_WANTS_NO_INSTR then doesn't quite reflect reality on arm64
(yet?).

But it does look simpler to wait, so I'm fine with that. I leave it to you.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO9f2SD6PAz_pF3Rg_XOmBtqEB_DNsoUY1ycwiFjoP88Q%40mail.gmail.com.
