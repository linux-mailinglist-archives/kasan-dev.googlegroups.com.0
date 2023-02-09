Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSEGS2PQMGQERVAF5QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id A476D691487
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 00:35:37 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-15ba18af8d6sf1761058fac.23
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 15:35:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675985736; cv=pass;
        d=google.com; s=arc-20160816;
        b=TsWvTN5ib7axfMWxKk87JfXGrHKfutncawX87oWEtx9GLu8ZSQ2TdUJIQ/EMG5gr6J
         Zz9suhiToTpV6oW8Zge87Aj/A8/RZFC/7QFblwpMWW68wVY4pghNSiDsvUbs/3nU4udU
         dAt9J7RhRDwfyVjr2hlf90YZ5rOAtE8smLXsPFF9mpI1cXDSl8elLM6aFLV5diEApXOZ
         Scc75e1ZJv/4CeEF4eLVF5Rt/X8hj7AlARXRA2D7Xkw5gpKX7idc+BHlsTHZEiV+I5Px
         p/R9efR7XpIynf0cWWB1mtmdAf8bahEnQPIlr5NKfBQuo7hL7e8j4KGXT+y+rVJ73qCt
         4nQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=XmkQ5C9YtsxDP8tQqcoBk++ouIVMJp5zfrLD5kW3gj0=;
        b=f9XY4RgqlHjYuV9MYylzqcCa8VIT+jo4GoaqmwJnEvuSLEfocjlnHjcskOSUJAnufz
         0Q2Bt1GWlG44IxLDrQguPiwQLK/bXCOLYVh5JEY5f92KWugt0QZJl1DLVoZp1rIrmGFa
         VdpG6rbsphvpuMjcV4dXTdwKR2TJJ5DoCQBsQarMb+QXQDOSZna66XgCdD0fRV8+1QqE
         CHHI+yLygTYUW/YpUwAIUPAeGRckeMbniH4/8HJbnx2HJGszHCi+mgRi/OfjA+wV/Ius
         fGX8cAlYEZR92j5PQGYXow5GcYD40pF3jgZGSyRh9F5INyc8x3X6JfY9M9e/Ysqou9HT
         4R5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KKm34kjz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XmkQ5C9YtsxDP8tQqcoBk++ouIVMJp5zfrLD5kW3gj0=;
        b=CiOCo3C7QrEXw6z5m6SA/OTggPOLSCCS/5VxvFxuPBzcvSKczC2jhwjlIBO7p+HRvF
         Zo6WFjEMUSamwFM3G+SkfrH8nY0HCnwjoh25dZjK8egSsW84rJ8FYzzzcjW3ZTj2Cyv/
         p77ejVjzxlXUbpIgRI49jxJftFbrOs16zzaymkdRoEDNR63kgBH8NYhNKIr3dE1oZXbh
         BBtfrQmMXurc4o3XsZbsugs7h7Qbj/w+rz05PhDC8y67eIQxwOoB/Cy/GD69lP3usMuu
         ntVwo0bntWCFDliidmwE11D1EnmOT2YudBTBeguoPsqwRQ1KMw/ew0K1lK1uAh1DIxNH
         ovGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=XmkQ5C9YtsxDP8tQqcoBk++ouIVMJp5zfrLD5kW3gj0=;
        b=VVxQPT9rB0981uuPnyDMGXE8pp22yQ4J8r5YYMbGPj9fVC6iHlYmLcbH5xtnpY8159
         2tIf96v31fonVueVSHBgrweBI3ZicszkifOd0Zz3aY5+WWm2g+it7tgTL+3RX+9beoQ/
         4+00vjL4dxdg7MwJOJJyKU+P2l7HgSUjhTwwwtN9QtwNLGpiaGqhqtae2Hqn+lOpjwvh
         npTm1iR5pCTxVJjfm82RBsInuOQtcdskwYhlOCTLTlUUKvxhHDFtthpXfEjgdObtJeC/
         zr+Oa1jVnUd1DaZVSI4iuc8jh7fErU1X048nSCYPwC93IDZfOuhItNz3vOaQT+SObnV5
         DB0Q==
X-Gm-Message-State: AO0yUKVB7EO8C5tWYVaKhr1WqDdApFVvCiaWaMn2JsEsmotPhtJvicMS
	SURXMVa88RgHR0BVHL2UwZo=
X-Google-Smtp-Source: AK7set8mr6tPx8/j5GtcnJZa9W33UvVOjlktru0/EcRpeslAGPivbMttMMmL7Jn4s7KP0jM0hySDPA==
X-Received: by 2002:a05:6870:8895:b0:163:1f20:3d6f with SMTP id m21-20020a056870889500b001631f203d6fmr1284101oam.81.1675985736209;
        Thu, 09 Feb 2023 15:35:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1706:b0:36e:b79c:1343 with SMTP id
 bc6-20020a056808170600b0036eb79c1343ls434232oib.7.-pod-prod-gmail; Thu, 09
 Feb 2023 15:35:35 -0800 (PST)
X-Received: by 2002:a05:6808:8c3:b0:37a:daa1:baf8 with SMTP id k3-20020a05680808c300b0037adaa1baf8mr6074123oij.48.1675985735637;
        Thu, 09 Feb 2023 15:35:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675985735; cv=none;
        d=google.com; s=arc-20160816;
        b=S1++G3RYuY5ol4UIAEtgbSJ0yA4Hx5VwwhE1vLwqk+NI2e37fr/kVL2R5hqMWBjOAC
         JWuV4xe7QHvY+GDyPZcPJHki57Y9Evtsd9mUPXZSj8CAByUfh8tsHm4L4m43iiS5GD10
         5GBHCPtT9yxa04+m8d/QoYKAmR3r8JBDKaqrggz1sghOLGfLXLQu8Dr3Jh20HmmTuadg
         h5awBgpsQIfA0a06uyn2Wz8F9v7kN6/5Jd4Y38rsgTgUvgW3ZzaPUZ3jtGXwTxhOTwiX
         DNqS+VwwpFiT2GCfypdu0H2wouBdHLPXpMkKXINitafZBptazX1pB9Z2DDI12OeYMPU8
         3fIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E3YfaKNVl2yQShNL4EAUThiXwGLjN3/+eFNVq1mrd+o=;
        b=bBms0v7nWIiqGpW275pkkB7vCOT/9c7FCrrhJ2RZw7J1+KBkfthVsDw/+lfC0MvKj7
         leqSE4INI5KX/VF7P0FjrCgen55YWpM+0rHRFD4tb10ps9jMOVf+3bv1jcRx0Fq6HHuh
         CeEjoVNjev0nW+CUmssPbwFqdZMatSz/bukEaIyZe+Zb7NX/0T90tcHJOGHnPWUZKuHI
         ZWvwAGir9Ok/OrYBftaODssYI4+LiFRPVdX1C3zxDflGdlmx6azVDKWqBDOTtwTpd0w3
         AgG+QSCxRYI7T1LKifaVjaecXMumVWZP8HeJHaUEU9vAF3r6+puAT+1y0vIeDmlw/EZb
         nvQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KKm34kjz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id bx21-20020a056830601500b0066e950b0580si500512otb.4.2023.02.09.15.35.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 15:35:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-520dad0a7d2so46821767b3.5
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 15:35:35 -0800 (PST)
X-Received: by 2002:a0d:c906:0:b0:526:8ea9:49bd with SMTP id
 l6-20020a0dc906000000b005268ea949bdmr1250620ywd.339.1675985735029; Thu, 09
 Feb 2023 15:35:35 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com> <CA+fCnZeU=pRcyiBpj3nyri0ow+ZYp=ewU3dtSVm_6mh73y1NTA@mail.gmail.com>
In-Reply-To: <CA+fCnZeU=pRcyiBpj3nyri0ow+ZYp=ewU3dtSVm_6mh73y1NTA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Feb 2023 00:34:58 +0100
Message-ID: <CANpmjNP_Ka6RTqHNRD7xx93ebZhY+iz69GHBusT=A8X1KvViVA@mail.gmail.com>
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, Tony Lindgren <tony@atomide.com>, 
	Ulf Hansson <ulf.hansson@linaro.org>, linux-toolchains@vger.kernel.org, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KKm34kjz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112f as
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

On Thu, 9 Feb 2023 at 23:43, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Wed, Feb 8, 2023 at 7:42 PM Marco Elver <elver@google.com> wrote:
> >
> > Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
> > with __asan_ in instrumented functions: https://reviews.llvm.org/D122724
>
> Hi Marco,
>
> Does this option affect all functions or only the ones that are marked
> with no_sanitize?

Only functions that are instrumented, i.e. wherever
fsanitize=kernel-address inserts instrumentation.

> Based on the LLVM patch description, should we also change the normal
> memcpy/memset/memmove to be noninstrumented?

They are no longer instrumented as of 69d4c0d32186 (for
CONFIG_GENERIC_ENTRY arches).

> These __asan_mem* functions are not defined in the kernel AFAICS.
> Should we add them?

Peter introduced them in 69d4c0d32186, and we effectively have no
mem*() instrumentation on x86 w/o the compiler-enablement patch here.

> Or maybe we should just use "__" as the prefix, as right now __mem*
> functions are the ones that are not instrumented?

__asan_mem* is for instrumented code, just like ASan userspace does
(actually ASan userspace has been doing it like this forever, just the
kernel was somehow special).

[...]
> > Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >
> > The Fixes tag is just there to show the dependency, and that people
> > shouldn't apply this patch without 69d4c0d32186.

^^^ Depends on this commit, which is only in -tip.

> > +ifdef CONFIG_GENERIC_ENTRY

It also only affects GENERIC_ENTRY arches.

> > +# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
> > +# instead. With compilers that don't support this option, compiler-inserted
> > +# memintrinsics won't be checked by KASAN.
> > +CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix)
> > +endif

Probably the same should be done for SW_TAGS, because arm64 will be
GENERIC_ENTRY at one point or another as well.

KASAN + GCC on x86 will have no mem*() instrumentation after
69d4c0d32186, which is sad, so somebody ought to teach it the same
param as above.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP_Ka6RTqHNRD7xx93ebZhY%2Biz69GHBusT%3DA8X1KvViVA%40mail.gmail.com.
