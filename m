Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL6ZYOTAMGQEGEPX3BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37FCD772507
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 15:08:01 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4fe38a9f954sf4285999e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 06:08:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691413680; cv=pass;
        d=google.com; s=arc-20160816;
        b=fc3oFxStEYYgYgXQ0ZnU5W5cPLMk9LH6meV1p92cmVEh9aTEJqwIalX+Q8SuqUpU1H
         X1mBtilGbIIvLthu0Q/38PMgDsAFEVmo0X+l4P3yDwdFNW1iYL38cqeMu53YojIzwAzt
         XPFbfaN9MFtyB9igwgtqxTkyNL0FhFAoBBRPBKU9RR0dhRJo8LJ2dwejMenKl+rVzYGt
         m887gnF+irWlpp+/4JWW6ONkQvUgznK1UXDUN8VqH2/ME1jKpIA2OaKrGOh0+RDH2M5z
         1RMukkYXWsEl0yoKm7bXZvWloaO13cjNhOJCB36ps8asw9wieZMILCSEHp+MLIIx0FNi
         t/hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nx9Dke1KFI6mK8fnDh9YybCiDFBA5KhH0HOwdaxDNkM=;
        fh=1SDi47oGrpqur8xV0aEdP8wLJTQkRDmiYi8k1DxcVM8=;
        b=PHm02VRozQWO7Youb0K0oplh+uWbu9ROLy7mQcZhw6WA8eDXDvYLjkQ24O/mZOTdsH
         RpvBA6IpNAiqNErMsN4MiPy3GTJOSG4csxAmCHK6g8ERrxGWlpPUYbSMLhItnuWBtN4X
         k5wnM9WGLjbJ8X2BEvPY13Csu8I6FJr/wqz+YqVkOkAPQiNSuSdOZkKElefkk/+AR2XW
         VQkcy0EfOvnsAikd2xmVTmCi676m2uCnRV9KjzyM77c4j2GyMppB066SIXbTH4Y4dHCn
         3+3UDnbqJHfLbFUpJyRcwnPg0I0jdb8Bn9ZYY7rmPbAH7DFra3V0ZvC4KVU2b3tMvwx7
         MVHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=CZsy0pok;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691413680; x=1692018480;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nx9Dke1KFI6mK8fnDh9YybCiDFBA5KhH0HOwdaxDNkM=;
        b=Rl5AgGk16EAo2eGRp3kS0GYPmCc9xvEJGCHQqwXC6mer/IM6obp7VZltzuF+/3EWyv
         V9aODMghch+p+OQEpRHldwIVSBlPiY0722lfisebqpBWU7dgCVBiKdowfB4QboqbKhld
         eeIvb+5vNeO+CgkHyErZrho2WQifGjaQ2sKpewK8YNr2qzgdAH5rVV1OPAYuPrwNd28n
         Zr8kxx7GBOllJRZhztxkNMl4L6sT7Bn6Lzv/lciUxiza6gqN9v70jJuq0HR6DhIfuubI
         seQ09YTe4JPPRKLWNsYZX1mz65Gb0ymPQwUsYNylqrrYowtrE6deYqEmAsgK9xOFgInT
         zDqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691413680; x=1692018480;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nx9Dke1KFI6mK8fnDh9YybCiDFBA5KhH0HOwdaxDNkM=;
        b=AKaN+kxmyco6/YLoN0yZYGCSXxA9+lk7LseTmiywmyuVPymi0+IK1XbD709pvbbihL
         x5IA6B0wIsYGGntLTjRfiT+sToJffuRItsmS+Tf2h3fM8k4C6RueIe5OpN80dh7l9Bv4
         RudfK0mBh7nyYqxY9+ntjg9abQEQ/7RruVLC6wZvIRBBGxgwnpmV/xVkFp4SIIz3vkqW
         0pORk1sfBvNxjGsPj7BMi3buXoLgoTrq0sCYpGOMX39HOK1NQM0IOnBawnfE2awmERaB
         y2HWh/P/YlmIDkfsGWMcwL3QixT2FacR38L/jNbQwakThZD8KCLvaezta++7l8NFTQMm
         pEEw==
X-Gm-Message-State: AOJu0Yxk6cbVkx8EOSLM1eCurAHq/JhfUnSb5JsnKbHRyAt/v9cWK1DB
	4IX0EKGDn3qVvB0efhM8foE=
X-Google-Smtp-Source: AGHT+IH3Cw3zPnQYud76dmesg4ja2wSHdA6PUr2f1ywcwWZDDy3i8Nvf+hgDw+FiYJnwrQ+SFnmnIw==
X-Received: by 2002:a05:651c:1030:b0:2b9:e230:25ce with SMTP id w16-20020a05651c103000b002b9e23025cemr6163154ljm.12.1691413679917;
        Mon, 07 Aug 2023 06:07:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a22:b0:2b9:34cb:5cdf with SMTP id
 by34-20020a05651c1a2200b002b934cb5cdfls812929ljb.2.-pod-prod-09-eu; Mon, 07
 Aug 2023 06:07:58 -0700 (PDT)
X-Received: by 2002:a2e:2c0e:0:b0:2b4:7f2e:a433 with SMTP id s14-20020a2e2c0e000000b002b47f2ea433mr6014662ljs.36.1691413677895;
        Mon, 07 Aug 2023 06:07:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691413677; cv=none;
        d=google.com; s=arc-20160816;
        b=kvR0t70wqfAycNyBqXVA+gyO/pltlDXss6EZOyw6FPdjl0CM+BIFcZxOPbd1kh1OvT
         ghHiIEtgNshVmlTyN+SpAnBMXZpguuzbSirxjvdnUIBgOtEuSCnQgiG1hld/6N+DYpdU
         nYJNRmhGCpsKlVC+rBRda/EVEj6E7HKUfhZ+jibmviO/yzBQdMLv8+nyeborEwVnMjnI
         hrTq+DV4Z6Sl9xaV386oN8L8Gwoa6eyh81E82ULjT0ejMU5aC3BHAzbYcfR0HL4mZGgx
         87bn5NHYeVREEte32A9mC41RPSN6kFeXv1YOTavG2+56fuoz0Po7d9ib8FBfndVa+wHF
         h/EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y/4R25p4daYUTehiyP/H6NfDF6hC+5JyB6EXsqzz6/k=;
        fh=VfFMGhjO+6FaJXNGtdRcycTOiKXgCawKFW/Q7I8tcFQ=;
        b=vYgOaRUXYNzLP+xvP49eLvmUe3uaYeCUGDf7Ly5HDgTYZR70cr8ZXmRi2/k4bqyIPa
         xttfA9MFoDWPlkJ14ap2RcNpmSHMtoLtgzBAui1PFlYtQnUm6KpfY1O2yxebewbYqMvx
         xGW0Ix0/v92/Q3eix0fdF/9yceNp5hC8VVuBxpjTHuxVnN2sWp8O+n0hC05MkC08cKFc
         NvCqOGTn3afmzqMjfeEBck+4wTcHmPGlLb2TjMDIVQZBekCQ4W5ZbYrMFCyDv9gqnLIb
         SegkCrGjNQPsvvidLYZdXDNB5b1cN96uU+PuWerN3JyrKr5rWS0dyuSGdDmPvey5jaeC
         IFeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=CZsy0pok;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id vh11-20020a170907d38b00b009885c0ef8d2si730503ejc.1.2023.08.07.06.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Aug 2023 06:07:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-4fe28f92d8eso7065990e87.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Aug 2023 06:07:57 -0700 (PDT)
X-Received: by 2002:a05:6512:358b:b0:4fd:d4b4:faba with SMTP id
 m11-20020a056512358b00b004fdd4b4fabamr5211620lfr.51.1691413677214; Mon, 07
 Aug 2023 06:07:57 -0700 (PDT)
MIME-Version: 1.0
References: <20230804090621.400-1-elver@google.com> <87il9rgjvw.fsf@oldenburg.str.redhat.com>
 <CANpmjNN4h2+i3LUG__GHha849PZ3jK=mBoFQWpSz4jffXB4wrw@mail.gmail.com> <87pm3zf2qi.fsf@oldenburg.str.redhat.com>
In-Reply-To: <87pm3zf2qi.fsf@oldenburg.str.redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Aug 2023 15:07:20 +0200
Message-ID: <CANpmjNMoxZYZQNyZcnci_rC6d6X4WKpS+fX9goaBdGCJFPjUNQ@mail.gmail.com>
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=CZsy0pok;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::135 as
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

On Mon, 7 Aug 2023 at 14:37, Florian Weimer <fweimer@redhat.com> wrote:
>
> * Marco Elver:
>
> > Good idea. I had already created
> > https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110899, and we need
> > better spec to proceed for GCC anyway.
>
> Thanks for the reference.
>
> >> Doesn't this change impact the kernel module ABI?
> >>
> >> I would really expect a check here
> >>
> >> > +#if __has_attribute(__preserve_most__)
> >> > +# define __preserve_most notrace __attribute__((__preserve_most__))
> >> > +#else
> >> > +# define __preserve_most
> >> > +#endif
> >>
> >> that this is not a compilation for a module.  Otherwise modules built
> >> with a compiler with __preserve_most__ attribute support are
> >> incompatible with kernels built with a compiler without that attribute.
> >
> > That's true, but is it a real problem? Isn't it known that trying to
> > make kernel modules built for a kernel with a different config (incl.
> > compiler) is not guaranteed to work? See IBT, CFI schemes, kernel
> > sanitizers, etc?
> >
> > If we were to start trying to introduce some kind of minimal kernel to
> > module ABI so that modules and kernels built with different toolchains
> > keep working together, we'd need a mechanism to guarantee this minimal
> > ABI or prohibit incompatible modules and kernels somehow. Is there a
> > precedence for this somewhere?
>
> I think the GCC vs Clang thing is expected to work today, isn't it?

I, personally, wouldn't bet on it. It very much depends on the kernel
config used.

> Using the Clang-based BPF tools with a GCC-compiled kernel requires a
> matching ABI.

BPF is a different story altogether, and falls more into the category
of user space to kernel ABI, which the kernel has strong guarantees
on.

> The other things you listed result in fairly obvious breakage, sometimes
> even module loading failures.  Unconditional crashes are possible as
> well.  With __preserve_most__, the issues are much more subtle and may
> only appear for some kernel/module compielr combinations and
> optimization settings.  The impact of incorrectly clobbered registers
> tends to be like that.

One way around this would be to make the availability of the attribute
a Kconfig variable. Then externally compiled kernel modules should do
the right thing, since they ought to use the right .config when being
built.

I can make that change for v3.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMoxZYZQNyZcnci_rC6d6X4WKpS%2BfX9goaBdGCJFPjUNQ%40mail.gmail.com.
