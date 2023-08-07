Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIOFYOTAMGQEN3NMWCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id EACF17723D4
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 14:25:06 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-3fe57d0e11esf6434405e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 05:25:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691411106; cv=pass;
        d=google.com; s=arc-20160816;
        b=G2w3dRSMWTAwTqe1z0bMvK//7F41M+I514HcPZPtREUX3RhH1qORzlRZGuYFHNufpm
         Iuh4rDysULovcU1kjxazWsA+8f6wYqSki7XsBybOLPpgt3z39U2/r+SkggCuoNwf5Pev
         ix+F9T3BiHQ7K0zRxWLaYD9F8UtVHUNxysEtw/Elm3WqoJUCzDAo59WAp1wCfO3aUYWG
         StD2WKR1B+DWI7mz0q/EkPA+Dak/St73G4yByJrN9c45/vj2dFc5aVSddxHGlnF7q4j/
         0vXIr1XQK/GiFE+8gc458CBZ8XSCmz2RAMYpZjKYGRcyqmaKQcTme8mm4Xl4trdLzcJR
         fQ1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FGMGBlDFF+BELg4kspQJQJAa3kJc2uo78oAroH95eys=;
        fh=1SDi47oGrpqur8xV0aEdP8wLJTQkRDmiYi8k1DxcVM8=;
        b=qwmWn1rxzbUhcKPxwsve22opF5Aui9KveWlCqkrBvYEvCnrnse5ZUn13DRCca+E2rd
         OrsYlT8cSRN6YjdJnERvONPa1jRicqToBe1CnFewv9EwzY8bqJFykzr3RAOclEU2zNfS
         i3mpaCsQgPSf9se2n8PJkwW8Vach633DufLynTtvK+GbGvdG5iX8TKpz9AKtrNDQIOrJ
         QCOo5UEneSekJ4/Dc6hml039a7sjA/RSdnsCyM08ZZDBlMGrjjpjx5WFrTP/O7mgrF2V
         Ln17tLK/+BaF18OVjBdxmNZpPgjmBX3MosoHwty0FvHNIxWwO4VtnRoqK90u1xVWdO7r
         NewA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HCbP5hja;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691411106; x=1692015906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FGMGBlDFF+BELg4kspQJQJAa3kJc2uo78oAroH95eys=;
        b=rQTsxVQV5sCKhpwG3SDOEcsZzscColg/kPi1VHwSsQ/eWmjVytSwhtu96rJE32j8Zp
         L907/COGlPFAPvFtxbjY4djFgYlUJUwLoQTNvfDMYBMcON8PElh91gIUBnCcA8n9+qty
         PxDhiB534YMokp5FUPN7YF2A21h/7NAKrgXAWBPMkM8rHJdHB8AUmiyA8bTfhW3PLdYu
         e8UO6btSm8kmVferXFCepfdtcjv3ljRxiYu94JT4yUTq11VJTDugwbZitnEsHgxsYJn5
         J+enNfh3uESZbt7/kQ0QsYJ7RzUHt6FRNwruz09kR8Bo9dRVlpXnQmHJhhMtF77H0ac9
         asIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691411106; x=1692015906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FGMGBlDFF+BELg4kspQJQJAa3kJc2uo78oAroH95eys=;
        b=ca1Mp7j9jwiltnhbbSou6uFwG74aXmkbWUPZTKA859PWgkakqEdMjkaQXSqDP2tqht
         ucHo97r8pOeHXh+CgGdY0oNnYpMz+IlP7c4G9hPMDutIhfy57bmgfk0Y+b5V6iQik+QU
         zjkpmOOVrPPDOn4yZQlNM7mrGivbFPNkgTpFLWHF1Ss5JFS6LTXYv2ye1sl52urZAgs8
         iYvkENP/WJvoTN+tvVs65k+x7X/xpcI8FRDe/eq+SCYBO+tGcKGZ7BhdUuaF5CfxfulY
         pmu5YAkJ+4hI2eaGxUuX4iM7FZjfUiLYkoFLh0QQurtFTlz2M1Gv+3nFX0DkF7gnKvq4
         t3gw==
X-Gm-Message-State: AOJu0YzyNLdeu9T+Epx8tS1qIt49P/B7yJ/2y9Qy0Udm7l5/MpeFfCzH
	HcjUIpxEsYYNWUxotFeWYU4=
X-Google-Smtp-Source: AGHT+IGE+Z2Zj1ORaiZRampnUXm/lBz6ogBxTnZ1rNIX5gVhyLOlCLqIomVRiEN0JPiSFieFTELyEg==
X-Received: by 2002:a5d:42c4:0:b0:314:1d53:f3aa with SMTP id t4-20020a5d42c4000000b003141d53f3aamr5457430wrr.50.1691411105846;
        Mon, 07 Aug 2023 05:25:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:524b:b0:3fe:490c:3ca with SMTP id
 fc11-20020a05600c524b00b003fe490c03cals760967wmb.0.-pod-prod-04-eu; Mon, 07
 Aug 2023 05:25:03 -0700 (PDT)
X-Received: by 2002:adf:f410:0:b0:313:e80b:2273 with SMTP id g16-20020adff410000000b00313e80b2273mr5989871wro.46.1691411103585;
        Mon, 07 Aug 2023 05:25:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691411103; cv=none;
        d=google.com; s=arc-20160816;
        b=YR35llLp52Ug61AiAjE/XAb5ihDpRioYyQDJToAYbr5RSvQ48UiGiOFSnId3ZFNSR0
         +iDqzop1604FAcVPdFC5XqUa6o2rba9MNXTMAWFXxVTAhtICEM2BGQPVlfNGG0NrNGF3
         UXB7mMN5FA2KGflG0L9yqDZnDu1Jo1lkWwqo+KNSriPQncB4HC0C3htjRp/Cex+NYunR
         xsgwOOkp0gOL7NSj+x5TYIT6zudif62SnNYeQw/K+4QsDSDGBiyp2N0DWP9OyvfYdk28
         TgkSslHZjhPhp+m7x3krwicy1ZQcOU5Mi/XQVpT9uiwotlRdLahexXfXTiBTQVueJprl
         Mnwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fsP5nkPghUp19sfWVmpj073CCh46k2F98rtPHNJSKVE=;
        fh=VfFMGhjO+6FaJXNGtdRcycTOiKXgCawKFW/Q7I8tcFQ=;
        b=fl91Q4L69Fvt8V36sgUqZUK7I/e6r4nQ5ldf9vC+bud5coPzaUqYHSidWLLzd16cTu
         EgDnhI563+J0TkabrPbDWUkMbO/tAC6RisyDJYY5aNQW7cZ0S4CrhhmypUC5w24cT2l4
         gKMuE4q/ND9ufH2q/2P3ni6lkXoNZqwAoEvnSd+X+rPj8gdSj4f5fdLdf/aglAiqIA9M
         7smjzvyvCmdhC3xbc2lfWRqupS2D4VsXsxcTo8/x7ObetlZE7HdCvICMU4nrtpi6o8rl
         OIkcvy2aQPcX+2GXM6k5Qf2zKfw5bKs/VKrNE/P9hMnegGs8oxa9dRisClKfqRAj99mZ
         8lKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HCbP5hja;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id az26-20020adfe19a000000b0031596f8eeebsi573766wrb.7.2023.08.07.05.25.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 05:25:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-3fe5695b180so11696495e9.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Aug 2023 05:25:03 -0700 (PDT)
X-Received: by 2002:a7b:cd94:0:b0:3fe:3521:d9ca with SMTP id
 y20-20020a7bcd94000000b003fe3521d9camr5908666wmj.3.1691411102967; Mon, 07 Aug
 2023 05:25:02 -0700 (PDT)
MIME-Version: 1.0
References: <20230804090621.400-1-elver@google.com> <87il9rgjvw.fsf@oldenburg.str.redhat.com>
In-Reply-To: <87il9rgjvw.fsf@oldenburg.str.redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Aug 2023 14:24:26 +0200
Message-ID: <CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
To: Florian Weimer <fweimer@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=HCbP5hja;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Mon, 7 Aug 2023 at 13:41, Florian Weimer <fweimer@redhat.com> wrote:
>
> * Marco Elver:
>
> > [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> > convention of a function. The preserve_most calling convention attempts
> > to make the code in the caller as unintrusive as possible. This
> > convention behaves identically to the C calling convention on how
> > arguments and return values are passed, but it uses a different set of
> > caller/callee-saved registers. This alleviates the burden of saving and
> > recovering a large register set before and after the call in the
> > caller."
> >
> > [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
>
> You dropped the interesting part:

I will add it back for the kernel documentation.

> | If the arguments are passed in callee-saved registers, then they will
> | be preserved by the callee across the call. This doesn=E2=80=99t apply =
for
> | values returned in callee-saved registers.
> |
> |  =C2=B7  On X86-64 the callee preserves all general purpose registers, =
except
> |     for R11. R11 can be used as a scratch register. Floating-point
> |     registers (XMMs/YMMs) are not preserved and need to be saved by the
> |     caller.
> |
> |  =C2=B7  On AArch64 the callee preserve all general purpose registers, =
except
> |     X0-X8 and X16-X18.
>
> Ideally, this would be documented in the respective psABI supplement.
> I filled in some gaps and filed:
>
>   Document the ABI for __preserve_most__ function calls
>   <https://gitlab.com/x86-psABIs/x86-64-ABI/-/merge_requests/45>

Good idea. I had already created
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D110899, and we need
better spec to proceed for GCC anyway.

> Doesn't this change impact the kernel module ABI?
>
> I would really expect a check here
>
> > +#if __has_attribute(__preserve_most__)
> > +# define __preserve_most notrace __attribute__((__preserve_most__))
> > +#else
> > +# define __preserve_most
> > +#endif
>
> that this is not a compilation for a module.  Otherwise modules built
> with a compiler with __preserve_most__ attribute support are
> incompatible with kernels built with a compiler without that attribute.

That's true, but is it a real problem? Isn't it known that trying to
make kernel modules built for a kernel with a different config (incl.
compiler) is not guaranteed to work? See IBT, CFI schemes, kernel
sanitizers, etc?

If we were to start trying to introduce some kind of minimal kernel to
module ABI so that modules and kernels built with different toolchains
keep working together, we'd need a mechanism to guarantee this minimal
ABI or prohibit incompatible modules and kernels somehow. Is there a
precedence for this somewhere?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNN4h2%2Bi3LUG__GHha849PZ3jK%3DmBoFQWpSz4jffXB4wrw%40mail.gm=
ail.com.
