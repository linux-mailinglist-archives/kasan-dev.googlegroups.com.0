Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYXD6OWQMGQEMGWQRNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D6D9847153
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 14:45:08 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-29658a95990sf48259a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 05:45:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706881506; cv=pass;
        d=google.com; s=arc-20160816;
        b=dZ41uPGWIyxP0BcRTpNTDl9S6Y/FiZt3ejw5d/mtv2qB+szcAAs/Cu/UL914Ck+JjV
         t/mDG+TRwKI0NhyJI4nQXPA5OI3BsiLvWFNOX7QFrgaDowPY7drqhtXQ6scif5WI69yh
         RgUtYSc0vmZC/cw2o4twaNqvtrQPTFWmvOi9damHYGwDgQVBxtGOPPHWxf+9d5cfgTw4
         P59fSJlcvTFn1en5aXR/IAPymbNdZlPg1E1SxXuNBVZFoysYV6rCNNZRCBUgcARsw0vy
         hgJrJ/KhvOPKTJcfmrPvXR/aV3rHd+AguHsM5fiu7IAGpKDdBtd7W3FFsMJT+wZoJtdM
         7BAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KaElX8upTCirRBH0B7gix0xGjaNCQ4nS0imZuAOo0jU=;
        fh=teldc+bpxP7O3XnRTlpeRXFswt3H9sDDMbTtBIeRXbM=;
        b=Ub19onCglwj0gSb/QOQlwgVCn64ThCQDIGpnGN7xouZXhc4hFvgAcLL9tp0hCHFDmv
         6R8k3nchV1OV5BqyXPSz09NgIYI3WITyqxdBpNFwBKCH8XUGFQogMh4fmr9D3wfwV/+y
         HdgGradQ1Y37jCDyM7qmcc4DVtRoNoRLY/4kTfMSI6Q2P+iQqJC59ZIQV1ldkHKaIXsD
         IQlzksUWOvxwoio31gI++4a7JyhQXeP8UUxHJh/Enstm/XaHhkUz4sgEbMCnE+TEgvBw
         X1FiHh5OXdSPJDodK3esqyHEZeT3EtVC8UPSEV63DKS30/Qtk2XDYmwszRLTsAG+8yFD
         3c8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1YGWGrFt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706881506; x=1707486306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KaElX8upTCirRBH0B7gix0xGjaNCQ4nS0imZuAOo0jU=;
        b=I8vSDqnsCwQ6UYFupptaJG35Il1PyS679CCBS3tH6KsjF0WNE0LzItEtw0nth8D68k
         m90Uu03O2jJv7vYkisaAgxNo/QT0gJIXfK9zSryY+n2qyvyKxfAqziwg3808zEaphvEM
         OwWreW4P9XdQFeyFvQjCpxLWnoUiS8x29aXYgzLAbl4RJr2ipY60AfqHHtJbMNoUbCb/
         OtTdDfaqkxZNQj1K6nmWIrkgo9HnHWRmS9hEBkUhpvj5561MF4i/lEbOH6ocNTrX/LL9
         9HYTLcOFlLdzzD3XddafxPHWv+LEG6QTK3tsmiYZmUmgIbUOO/IC2A3KUOwCgpONGJQn
         YMkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706881506; x=1707486306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KaElX8upTCirRBH0B7gix0xGjaNCQ4nS0imZuAOo0jU=;
        b=TM/nGGF3bcbWLuT5Z6kafKk3Kff61xYyvw0i5jwjVWvmUB217aPQpy+ecemSXQjSpK
         8SBfPdd+jsd0Alcr38lc7REFCzYOcjq37RS+rjlWOsQlaXKVdg4s+zHEqXCJX63sQlDB
         grCJUksljRAEMl0LsXIYFO07eFPpnS/um4CarSbFkT29oZG6uCeNoJD+XAFQdpXTKWR1
         jThs2tEmTXuFPnDoY3mvwZvdqnQieTyHfCK7Z450zjJxMsNpLFhD1GiDZ1Mq/oeupL7F
         Tkb/UiTxkqobVES3NgZQ+v7u4tRp9EShkKWu7Hr9b97PNyMR1JMXf9/MAQiipqURgEUN
         QvGg==
X-Gm-Message-State: AOJu0YzvlBqkkGPF5oIaLx6AQJe5q1HpUIopQPo1lcfVrnHZSi5AOXqy
	VkUoHWy4L6VVZvgU8zNiDzQ6rGra6rT56+IU5T84HMZEF6dvc/TJ
X-Google-Smtp-Source: AGHT+IFaDwbqNbLhEJ9WlGQ1cIYlEd4jzo4DObXkpNXDfbUNBNFXdSfKZSN+C3Sn/+rNGaKjCnq2Ww==
X-Received: by 2002:a17:90b:911:b0:296:286c:4dd6 with SMTP id bo17-20020a17090b091100b00296286c4dd6mr2186132pjb.46.1706881506294;
        Fri, 02 Feb 2024 05:45:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1c11:b0:296:3e18:669f with SMTP id
 oc17-20020a17090b1c1100b002963e18669fls544742pjb.1.-pod-prod-05-us; Fri, 02
 Feb 2024 05:45:05 -0800 (PST)
X-Received: by 2002:a17:902:e84c:b0:1d8:f21b:809c with SMTP id t12-20020a170902e84c00b001d8f21b809cmr2479649plg.60.1706881505076;
        Fri, 02 Feb 2024 05:45:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706881505; cv=none;
        d=google.com; s=arc-20160816;
        b=GKvdYABMjjhZvJsT5Fqv++jI6tMFogxrMKaHw/XhHxAZ2EGMh2dFkEdJvB7w2RYuoX
         0xhweWLql2gAPI0NhlY5Ss2Inpdu2DknvrEdDh2PR3PHkJY1jg0JJROA1Y1sk212rRUR
         qOEkAJAw5bDCONnEN9SavT/dcLZ45pgkXwpxF9ZwUwGpaAKuYgDMR1YIN3tb2r8fDtbe
         GgPCbe/pJOmeS7oJhr152awqB/MJlaSiXcprEt2OSnmBlCdA6ThxRXHII6s0thXkpgsX
         umUneMZZYVGybdZtRgG/C2IOJyfX4ltlH9pcGmpgK2JpIfrTrZDGYWscE5QzeIwh1dPG
         5ViQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IIzUaTAWY721VAmsfjicI7pRblrKzWu2/3eiQAJEETw=;
        fh=teldc+bpxP7O3XnRTlpeRXFswt3H9sDDMbTtBIeRXbM=;
        b=FW+fALffSyO2VlT2+VtB4XXY0MjXFoS7EJ1Rvve3bqWNZ8SnodUpVwtACer7tTDbj5
         4wRlKjvHUZOe6n42t5phwAs0UyEAEq4NcjzZg2Lx+JsqOR/gxallQXlFeDojA+SrACGS
         ANFkBHbYUBiXy587z2EFTFXgcBorU5z+PozcxZLPXkZ6KIjhk0ZV6Tddh+TtTNQ59bmZ
         vpyivPZ4lgH4qBnJ399cxf5KPdlyj+8STYqPrNXMIW256YMThTZOFw/H31rCrnfW8l+t
         NvYv5dky5NHLuQ8Sbh7FsW8m+RZagDe44wB53bwp/egu2+Bb28Bd11oi9JuCKXurvWgB
         k2BA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1YGWGrFt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCUsMeJU34xNVTVCnd0+EqQTJD63ZGjOW1/4TDBTNTCWrbsahIkNBhaEKM0tV/pwnuBs/v7XlHJV5Wur2shrcNtGoR2XqZjq3B5oXQ==
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id q23-20020a170902bd9700b001d8e76e7179si110482pls.3.2024.02.02.05.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 05:45:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id 71dfb90a1353d-4b739b49349so780593e0c.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 05:45:05 -0800 (PST)
X-Received: by 2002:a1f:f4c9:0:b0:4b6:bdba:8460 with SMTP id
 s192-20020a1ff4c9000000b004b6bdba8460mr1847799vkh.9.1706881503872; Fri, 02
 Feb 2024 05:45:03 -0800 (PST)
MIME-Version: 1.0
References: <20240202101311.it.893-kees@kernel.org> <20240202101642.156588-2-keescook@chromium.org>
 <CANpmjNPPbTNPJfM5MNE6tW-jCse+u_RB8bqGLT3cTxgCsL+x-A@mail.gmail.com> <202402020405.7E0B5B3784@keescook>
In-Reply-To: <202402020405.7E0B5B3784@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Feb 2024 14:44:25 +0100
Message-ID: <CANpmjNO-4A4LMK8kbWiiODB-vOZqc5gZndWtnYDc5RCGDBcoSQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/6] ubsan: Reintroduce signed and unsigned overflow sanitizers
To: Kees Cook <keescook@chromium.org>
Cc: linux-hardening@vger.kernel.org, Justin Stitt <justinstitt@google.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Hao Luo <haoluo@google.com>, Przemek Kitszel <przemyslaw.kitszel@intel.com>, 
	Fangrui Song <maskray@google.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nicolas Schier <nicolas@fjasle.eu>, Bill Wendling <morbo@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Jonathan Corbet <corbet@lwn.net>, x86@kernel.org, 
	linux-kernel@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org, netdev@vger.kernel.org, 
	linux-crypto@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-acpi@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1YGWGrFt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2c as
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

On Fri, 2 Feb 2024 at 13:17, Kees Cook <keescook@chromium.org> wrote:
>
> On Fri, Feb 02, 2024 at 12:01:55PM +0100, Marco Elver wrote:
> > On Fri, 2 Feb 2024 at 11:16, Kees Cook <keescook@chromium.org> wrote:
> > > [...]
> > > +config UBSAN_UNSIGNED_WRAP
> > > +       bool "Perform checking for unsigned arithmetic wrap-around"
> > > +       depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
> > > +       depends on !X86_32 # avoid excessive stack usage on x86-32/clang
> > > +       depends on !COMPILE_TEST
> > > +       help
> > > +         This option enables -fsanitize=unsigned-integer-overflow which checks
> > > +         for wrap-around of any arithmetic operations with unsigned integers. This
> > > +         currently causes x86 to fail to boot.
> >
> > My hypothesis is that these options will quickly be enabled by various
> > test and fuzzing setups, to the detriment of kernel developers. While
> > the commit message states that these are for experimentation, I do not
> > think it is at all clear from the Kconfig options.
>
> I can certainly rephrase it more strongly. I would hope that anyone
> enabling the unsigned sanitizer would quickly realize how extremely
> noisy it is.
>
> > Unsigned integer wrap-around is relatively common (it is _not_ UB
> > after all). While I can appreciate that in some cases wrap around is a
> > genuine semantic bug, and that's what we want to find with these
> > changes, ultimately marking all semantically valid wrap arounds to
> > catch the unmarked ones. Given these patterns are so common, and C
> > programmers are used to them, it will take a lot of effort to mark all
> > the intentional cases. But I fear that even if we get to that place,
> > _unmarked_  but semantically valid unsigned wrap around will keep
> > popping up again and again.
>
> I agree -- it's going to be quite a challenge. My short-term goal is to
> see how far the sanitizer itself can get with identifying intentional
> uses. For example, I found two more extremely common code patterns that
> trip it now:
>
>         unsigned int i = ...;
>         ...
>         while (i--) { ... }
>
> This trips the sanitizer at loop exit. :P It seems like churn to
> refactor all of these into "for (; i; i--)". The compiler should be able
> to identify this by looking for later uses of "i", etc.
>
> The other is negative constants: -1UL, -3ULL, etc. These are all over
> the place and very very obviously intentional and should be ignored by
> the compiler.

Yeah, banning technically valid code like this is going to be a very hard sell.

> > What is the long-term vision to minimize the additional churn this may
> > introduce?
>
> My hope is that we can evolve the coverage over time. Solving it all at
> once won't be possible, but I think we can get pretty far with the
> signed overflow sanitizer, which runs relatively cleanly already.
>
> If we can't make meaningful progress in unsigned annotations, I think
> we'll have to work on gaining type-based operator overloading so we can
> grow type-aware arithmetic. That will serve as a much cleaner
> annotation. E.g. introduce jiffie_t, which wraps.
>
> > I think the problem reminds me a little of the data race problem,
> > although I suspect unsigned integer wraparound is much more common
> > than data races (which unlike unsigned wrap around is actually UB) -
> > so chasing all intentional unsigned integer wrap arounds and marking
> > will take even more effort than marking all intentional data races
> > (which we're still slowly, but steadily, making progress towards).
> >
> > At the very least, these options should 'depends on EXPERT' or even
> > 'depends on BROKEN' while the story is still being worked out.
>
> Perhaps I should hold off on bringing the unsigned sanitizer back? I was
> hoping to work in parallel with the signed sanitizer, but maybe this
> isn't the right approach?

I leave that to you - to me any of these options would be ok:

1. Remove completely for now.

2. Make it 'depends on BROKEN' (because I think even 'depends on
EXPERT' won't help avoid the inevitable spam from test robots).

3. Make it a purely opt-in sanitizer: rather than having subsystems
opt out with UBSAN_WRAP_UNSIGNED:=n, do the opposite and say that for
subsystems that want to opt in, they have to specify
UBSAN_WRAP_UNSIGNED:=y to explicitly opt in.

I can see there being value in explicitly marking semantically
intended unsigned integer wrap, and catch unintended cases, so option
#3 seems appealing. At least that way, if a maintainer chooses to opt
in, they are committed to sorting out their code. Hypothetically, if I
was the maintainer of some smaller subsystem and have had wrap around
bugs in the past, I would certainly consider opting in. It feels a lot
nicer than having it forced upon me.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO-4A4LMK8kbWiiODB-vOZqc5gZndWtnYDc5RCGDBcoSQ%40mail.gmail.com.
