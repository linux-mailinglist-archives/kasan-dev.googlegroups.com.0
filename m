Return-Path: <kasan-dev+bncBDW2JDUY5AORBB7STKPQMGQEM3EA7DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DA6669295F
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:37:13 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-16dc25dcbedsf962587fac.15
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:37:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676065032; cv=pass;
        d=google.com; s=arc-20160816;
        b=D+wf/t8XY0iFuj1lt5rYdsRe4F78GW518YWmqB1Nb6s7eT7PccvcbyWM++zenQ/9rI
         ftPbNu8mxSN6sUmYjJwTBGotdeaw+xR45i/g9IIZblG9vQrMwF3gEp9pkChc3fgE77SV
         aV+AwU2zClan1e3jNTcglZmg64kf48JFEMvNN+rkChoLfVQyGwxr700hezcu/huNXDBa
         6SHJlndE/ysPi6m1MJSebR9iiiNX7QPmamvmnyuqthsPD+YVXmGKbMtls8aqzz6moZzk
         YNono03CBtzY6D9XohyU6D69aLgb21jmpXC3HQExq7ItrIGbXXBsL5NaTCMm9JeJ5ADH
         RqKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Q0lp1ngXgov35ABcwa6EvO07a/XusBrq+uaXjCNtk8c=;
        b=ZzndzZTy23HXit0H0CWdUk1iMFzt7RVvjd0J4R6QIsgeh0sqrKatpgZsGaWb+bHyYO
         yNPYSDIxN96wsl536q+ZkWDO1mfkPdPxya+w14DuDqq2zCmS9W/fZyzF0UxhUzH3XaM7
         jn4uhCrxZjq6ZjcP7IbE4KxOWdr4WXq3S5twTCPHFyJwDQx/P8aMCsjPa0dnzowJSCN+
         a+L0xLJlnwHqMVGIOtAnkynZFqHGAad/louAk74fRbSLPhJO33S6EivUFmFdZ1Yr0w/0
         gP+Jj13q7Ju3MIwf/rYxD1q40zL1YwYKO3eGnot+jYgVRFig0lOcWffQFxmsiNkcE+9Z
         cIbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Wel3VrAb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q0lp1ngXgov35ABcwa6EvO07a/XusBrq+uaXjCNtk8c=;
        b=V3Z/vEmYwPrP1VuJ07vZbsNZ1GJbYNfyemistRMEQgQG/nXjTR9My4C8NcwKSZFGbJ
         qlKA+tazTRS67trLJatMFXW5sDDQYpw0ejuiufANArh8IImbmmCb9DXgdSNCA9OKZXNn
         k9zoGx/XLEM+jPje+nt3SiPtNIHqyhUs8GpAoTjHUiSYCmvwAa0I7PGhSe5CXCgp93es
         VtwTwfD7CdKYhxpUGhMwMED6jTH6RPA3YCGnXEB3Sf5BM/OBYADznV+Hi/Ajk6pAXcUv
         Ew9pcaWuuirKjDO7vmqiqlZTpuJUblJk485TvA2vdpexnRjMalmvpdXT5930+/GmRPKR
         W9fQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=Q0lp1ngXgov35ABcwa6EvO07a/XusBrq+uaXjCNtk8c=;
        b=CPS+7lpug/+WQQoo000YoNIbouIvsew8KB+/Wajo4Ip3tIiDKGa2JsHzrgCmv6kWYQ
         53I6UZAr/UEnsTvrs72sKad8/esD/hTDx5BUgQYPkV9+Sg5ntZwtVgZuPXGNky8O5TdZ
         0eCteXNexaaGPw++epmeGFJM2p4K56bUdXRy2Lk70y+xRyK3xbEWlFoBaCo5QfcUWhXF
         Gvv9S7j4JlTsk4/yrc1FPG9LEh2MY/dyrCdckKvfdZEUENXCnbb/EVk/7vniTeXvHNjg
         XXjsCVahkfsTn4GGEzdYy0wA44ocu8fmsDBHlmrKK/slHPNz/n6lYt4q+iqer/vamIO+
         OwFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q0lp1ngXgov35ABcwa6EvO07a/XusBrq+uaXjCNtk8c=;
        b=Oc13CxzMryHwqPaVqvlZqDaa2y2E27y/VzZGEEYCfTZXFsNwQmQ9N6Ps/qWkwKASN/
         p5wEkp167XSbBmj8KWG32hPvLR2p4afEhTFNq7SdO5YIPyuLcGIsvM/6Pdq1DCgWGDTk
         csn/pe3IOP/ANp9sc9pIErULjW1JIUeJD72AvzfjET1yBnrErFE9vr+pxDGM8UxAbJB5
         9+8PQhFeMAk/Jx7PEDaKFkTfwgOGjav4gLkpj8ItFufas4MNp8P6xzZqB9vn1u/0J5fb
         3YQFPhRkWJfO8FFbUy19515cPbxZgvZ8xEzm6l3j5kGZOj4r+sLAtrffvZfM0Nz7DhlS
         TQNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXmGyW/q1Ivq2k6HvN+WeLlPzliYEXUShfL4YlHw9+MMdNlbBvF
	KS4f3kueGlOq4Lo5kI3bVhI=
X-Google-Smtp-Source: AK7set8d6+d25ze0G5o11EfM4QsjK+Wk1BcZfea9RMFWln+q1viWAsKseGF0L/pZ/hX18NBOmaBRkw==
X-Received: by 2002:a05:6870:80ce:b0:16a:9ca5:72fc with SMTP id r14-20020a05687080ce00b0016a9ca572fcmr824953oab.39.1676065031994;
        Fri, 10 Feb 2023 13:37:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ba85:0:b0:4ce:8381:c214 with SMTP id d5-20020a4aba85000000b004ce8381c214ls266740oop.0.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:37:11 -0800 (PST)
X-Received: by 2002:a4a:6b0f:0:b0:511:f3d2:bb8d with SMTP id g15-20020a4a6b0f000000b00511f3d2bb8dmr8418271ooc.5.1676065031541;
        Fri, 10 Feb 2023 13:37:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676065031; cv=none;
        d=google.com; s=arc-20160816;
        b=c/VXM/hPPL1Kz6aA9mWzomU+3wRH+N+SX8nsc2O7jblg5oRM8aPAIpVIZJrk7hED2i
         cSTGsrIVpvuzdcHOfePwcWcgOg9fRYMIqgjQBSIUQzEAiTEEw4OhwAhZILYQfSqNTF7k
         Tb7Wgam8PTUDpWgHXf8mSRAaj5RnHH2TK7fVh8v087dheky8Qk2esRDyJ20ogGguEpMm
         fPz7meJcSJGAtmfHyuNfCvALYKeorDi9aCL3sy/h26b0wEuefhgBfbuJsX4PYVnE2Rou
         DF/FhJCXyVQgjmFHUYosW+hJtu3WWJes0PEc9xbSRBKP8KLveQWuFPB704prv8IvRDq3
         XNGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vdG7jpPdQQ/bqJN4zEtXLDG93Zy6CAZv4n243xZFPTc=;
        b=YGRsIkH0ADkpdbeOy+Xj2ItVWpP92H0MjUFLVI4kwSxY4lX7vTTFarvgl0YRVS2zjL
         ignBVTA0KKqx4/KASBPJ+LkUjNPMfKk+yN6C3nG1Zx9GupwsnamPnO+4Ps1jM/YCQWwS
         jEDfGQ4TP0x4Ap3ox2VM1N2C4zCzIspE/EBrClPvtZjeDH/cg3pYHWtGa/40aWLOJ0qC
         0hXp7fg6vSV2VmwsXhSnwLY9KionUAm+f/UBksmQaLY9u/cW4OKiCYEeYYRLgn6tHxWR
         4fPYH+xiN1jUZ4es4Pe5HOEbGH+CTKw5+qgElQEB95ZFyulXP79hgWtpzfM1bbzPGCGp
         p5sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Wel3VrAb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id e200-20020a4a55d1000000b004a399d01471si616171oob.1.2023.02.10.13.37.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Feb 2023 13:37:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id f16-20020a17090a9b1000b0023058bbd7b2so6859453pjp.0
        for <kasan-dev@googlegroups.com>; Fri, 10 Feb 2023 13:37:11 -0800 (PST)
X-Received: by 2002:a17:90a:d310:b0:233:c521:271f with SMTP id
 p16-20020a17090ad31000b00233c521271fmr84307pju.139.1676065030767; Fri, 10 Feb
 2023 13:37:10 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com> <CA+fCnZeU=pRcyiBpj3nyri0ow+ZYp=ewU3dtSVm_6mh73y1NTA@mail.gmail.com>
 <CANpmjNP_Ka6RTqHNRD7xx93ebZhY+iz69GHBusT=A8X1KvViVA@mail.gmail.com>
 <CA+fCnZcNF5kNxNuphwj41P45tQEhQ9wX00ZA4g=KTX4sbUirQg@mail.gmail.com> <CANpmjNNH-O+38U6zRWJUCU-eJTfMhUosy==GWEOn1vcu=J2dcw@mail.gmail.com>
In-Reply-To: <CANpmjNNH-O+38U6zRWJUCU-eJTfMhUosy==GWEOn1vcu=J2dcw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 10 Feb 2023 22:36:59 +0100
Message-ID: <CA+fCnZcaNpX6f9fWU2ZU-vMRn1fQ9mkr4w1JyOn3RmmoBK4PmQ@mail.gmail.com>
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
To: Marco Elver <elver@google.com>
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
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Wel3VrAb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Feb 10, 2023 at 7:41 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 10 Feb 2023 at 17:13, Andrey Konovalov <andreyknvl@gmail.com> wrote:
> [...]
> > > Probably the same should be done for SW_TAGS, because arm64 will be
> > > GENERIC_ENTRY at one point or another as well.
> >
> > Yes, makes sense. I'll file a bug for this once I fully understand the
> > consequences of these changes.
> >
> > > KASAN + GCC on x86 will have no mem*() instrumentation after
> > > 69d4c0d32186, which is sad, so somebody ought to teach it the same
> > > param as above.
> >
> > Hm, with that patch we would have no KASAN checking within normal mem*
> > functions (not the ones embedded by the compiler) on GENERIC_ENTRY
> > arches even with Clang, right?
>
> Yes, that's the point - normal mem*() functions cannot be instrumented
> with GENERIC_ENTRY within noinstr functions, because the compiler
> sometimes decides to transform normal assignments into
> memcpy()/memset(). And if mem*() were instrumented (as it was before
> 69d4c0d32186), that'd break things for these architectures.
>
> But since most code is normally instrumented, with the right compiler
> support (which the patch here enables), we just turn mem*() in
> instrumented functions into __asan_mem*(), and get the instrumentation
> as before. 69d4c0d32186 already added those __asan functions. The fact
> that KASAN used to override mem*() is just the wrong choice in a world
> where compilers decide to inline or outline these. From an
> instrumentation point of view at the compiler level, we need to treat
> them like any other instrumentable instruction (loads, stores,
> atomics, etc.): transform each instrumentable instruction into
> something that does the right checks. Only then can we be sure that we
> don't accidentally instrument something that shouldn't be (noinstr
> functions), because instead of relying on the compiler, we forced
> instrumentation on every mem*().

I meant to ask whether the normal mem* calls from instrumented
functions will also be transformed to __asan_mem*() by the compiler.
But following the godbolt link you shared, I see that this is true.

Thank you for the explanation!

So the overall negative impact of these changes is that we don't get
KASAN checking in both normal mem* calls and the ones formed by
transforming assignments for GENERIC_ENTRY architectures with GCC and
with older Clang. This is not great. I wonder if we then need to print
some kind of warning when the kernel is built with these compilers.

If these changes move forward, AFAIU, we can also drop these custom
mem* definitions for non-instrumented files for x86:

https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/string_64.h#L88

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcaNpX6f9fWU2ZU-vMRn1fQ9mkr4w1JyOn3RmmoBK4PmQ%40mail.gmail.com.
