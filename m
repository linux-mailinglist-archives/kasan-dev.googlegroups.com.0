Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF6ITKPQMGQEKWYIB4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5094F69279F
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 21:07:53 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id h1-20020a17090a9c0100b00230353d4d2asf2872936pjp.8
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 12:07:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676059671; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4wcGMRvh76RR8u94BBKtGtRxyB1FkRzFQ93INIeUEScVs7qYTnAGpJ0WiwRWoPb7d
         oqzdzsd5UbVfWOqu1RyrzCo+2NBZHd5+gi4IWMKoyropWdXdomVxfJ/kVr+ZEwt96Agd
         DkiwXIDrIL/X2FvtuczVq79yz5ijhtOY9ahMRwDKRtEQz8vHO0ucDUR46hZOxQt9SXvW
         cnamtAusaICL0A0AXuWtByZe+VR7vzB0T564XhK2iF47ibNEl1EG1UwZxreBto0mnPyi
         3CmmlIEDkspNlgzvkC4ywVhHApRHSGaJ3ozL/q0L7OBynOZ3mF7BOaF1OTSMBAPmeI19
         5YQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=09N6B7Qi70RRLBo5XRMBEkxbyUX3GtBy9bKOzOJSnSk=;
        b=mGJ2DpQTSkjVb2wOnWgYi3odJt/B0x875qvjpGZqesfNJCg+dnrk/qy4RUu28O5nrj
         /B1qQD0cUe3aadtm4ANnTCzCtcqxxb7hbaeDS46RW/ZL0OJAXrASFwwxb0BWZ7R13XMl
         lEp8UojrNJ8Krn7O9/sZMsYR2xdhw5cBih7LBCq1pHpDzMHEX1s0doBhZk0EmjTJf9Wd
         BjnpSIbua/W9EDfq+DiRHBczZfAGkRY6TBSxPqioEUadtCOGRHTU3oXNMXcjcggaZ2aM
         6mbxNyv2TG3ki1TO8z/s/VugR3QeuAS/dureZfHJNJXMwQkCgQgrEiDVxvG2khx4rzt/
         HOLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hOWYki28;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=09N6B7Qi70RRLBo5XRMBEkxbyUX3GtBy9bKOzOJSnSk=;
        b=Zn1/8okCNjNUlr23nESgkueBSlmY4gqJCxhnEE99MLcGX2bbUr+UfTcvcLFlBW5hSH
         njfzekX2yj6Kjf5v5I15vcFr4SSz7vNOmKh2ZRCg3i14Mx7KgJeq5QQKwaT7/csCE0dz
         AG6y5XpFoAMYHkUdWTVkDblJVw+Yhxp8rm7zhAxcfbnS2UsMqyh8ue6hyVNFFySCfVTC
         bshPaLWGtb+OPNr8bS/JrSeR76piV812HujAxADnJv9sraLTXtHL28ZYdnTVQBRgdE2n
         8HwlgHNx7OM9s1OtNsglYshGgOhR2dK8p/+OwaQitVGI78VxzW/5eZivEigrHGbbzG82
         mx+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=09N6B7Qi70RRLBo5XRMBEkxbyUX3GtBy9bKOzOJSnSk=;
        b=lXJfJ8wfOj444UL+w8UVasxuGgB6NW1rvtOeu3QsfJaMwZruiMoiGDGbcW5jmjmR62
         MCVKh4p7zl/dC/PBNfplvxa+FyUQcI6x/znDnuWyjXShGIFoFCEbbOwduangLwJUH0BF
         h+a5Jze6SJSKh6vPz+Xts/cNS6tU6s/zaXEjqyilyi/JhaADdDlvqkTZWeVJzf8t3OAe
         xuuLyyqvHi4kiMQmcnh7ZJP+LlqaGJYnQkIjPy73P+N8vhQsoQZ8nHZQ4Luv+QzgySxi
         Zu+ckqyTAaXRzf55Zs026nHi6DRUNKV5SFxVXvCm/1Qb1RFUsuzhUiZEfh3uGP6SM7cs
         dkkg==
X-Gm-Message-State: AO0yUKWXI9CEZCjYPzpwwW5ewoRiiRTUgrKvKDU6yQvyfnxrj152PT/p
	B5WgEOh8H6jJ15X5FSdUYoM=
X-Google-Smtp-Source: AK7set8K0UlqEsXLTjeSHF6awDK1T7HNOtNazpPj5CmZ5DqNc8ez1CycELJhaOD+R8HYfDzfN1erlA==
X-Received: by 2002:aa7:96ec:0:b0:5a8:5821:b8d with SMTP id i12-20020aa796ec000000b005a858210b8dmr1288513pfq.46.1676059671697;
        Fri, 10 Feb 2023 12:07:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d650:b0:196:751e:4f6e with SMTP id
 y16-20020a170902d65000b00196751e4f6els6612504plh.10.-pod-prod-gmail; Fri, 10
 Feb 2023 12:07:50 -0800 (PST)
X-Received: by 2002:a05:6a20:b2a8:b0:bf:58d1:ce81 with SMTP id ei40-20020a056a20b2a800b000bf58d1ce81mr5938747pzb.0.1676059670814;
        Fri, 10 Feb 2023 12:07:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676059670; cv=none;
        d=google.com; s=arc-20160816;
        b=TATAaEVv21/phGgyam4DAUC3FTvEU2ZE3Es6rZiDbpb5wPJQPIIxmwfj0DHafvg3L+
         ub5VRYEzz47shqj18wSxEQ5Do35u6KuGBISdfgp/JP5yG/UCh1NzFsnSjaQLDKsnSpXn
         XZBq89gBdU0XM52bDTmp6o0yFOgAaNt14obbBfuUvlrnZgjnjZaf+4s1Zknai7+3I9Jb
         bGcTKclna1gvYWJlKykTCKA5nfIzzWSDd1DhSK3q3vP4YxLQycTp6MbgGzZLsBx/c5Dl
         Wxj8GP0fL3jnQ7qNaX2aShApublXS0uk+QhBQYcHM9fCBzFdn6DSpTnR3IU9Y+2IwOT0
         /6Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=541R7X11Cy7AiuNbaDBckfxjLzUeKrAJruA5EVPMTQQ=;
        b=p/WLVwiBquDPQCe+CTtrQw2MWtj9jDs7a551NE0Ej4/R8i0xhp8qmwLTgaq2G7KZMG
         VcEquOx1Uyat8A+7sg4UwGKLtEqdHfdnNbqE8ttd+IP1/IpP1HMgsyuVppDc8y8kBlSw
         tn3xeURU1jWaclGk10lRTfx/HX6Qd8AJFq0fvVWmUIOHlBklX3Eos3v9CT0oPpuRsstN
         7KQwA8m5ByRg/H5UWJmJ4z+M1qfAcqftmkAvENxrR678cQsyQVzQ58z029n0qW88hFcF
         0vp5w10N/EBDPcdrZY4GkVzN+Yzw2ueKbFDM4oPKlryCayVBxU+yphnhWvGC1t42o3Vl
         Ya3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hOWYki28;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id 34-20020a630b22000000b004e968328928si323146pgl.1.2023.02.10.12.07.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Feb 2023 12:07:50 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-5258f66721bso83098777b3.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Feb 2023 12:07:50 -0800 (PST)
X-Received: by 2002:a81:7dc6:0:b0:52a:1bac:b96d with SMTP id
 y189-20020a817dc6000000b0052a1bacb96dmr1660623ywc.349.1676059670297; Fri, 10
 Feb 2023 12:07:50 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com> <Y+aaDP32wrsd8GZq@tucnak>
In-Reply-To: <Y+aaDP32wrsd8GZq@tucnak>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Feb 2023 21:07:14 +0100
Message-ID: <CANpmjNO3w9h=QLQ9NRf0QZoR86S7aqJrnAEQ3i2L0L3axALzmw@mail.gmail.com>
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
To: Jakub Jelinek <jakub@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Ingo Molnar <mingo@kernel.org>, 
	Tony Lindgren <tony@atomide.com>, Ulf Hansson <ulf.hansson@linaro.org>, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hOWYki28;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
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

On Fri, 10 Feb 2023 at 20:25, Jakub Jelinek <jakub@redhat.com> wrote:
>
> On Wed, Feb 08, 2023 at 07:42:03PM +0100, Marco Elver wrote:
> > Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
> > with __asan_ in instrumented functions: https://reviews.llvm.org/D122724
> >
> > GCC does not yet have similar support.
>
> GCC has support to rename memcpy/memset etc. for years, say on
> following compiled with
> -fsanitize=kernel-address -O2 -mstringop-strategy=libcall
> (the last option just to make sure the compiler doesn't prefer to emit
> rep mov*/stos* or loop or something similar, of course kernel can keep
> whatever it uses) you'll get just __asan_memcpy/__asan_memset calls,
> no memcpy/memset, while without -fsanitize=kernel-address you get
> normally memcpy/memset.

> Or do you need the __asan_* functions only in asan instrumented functions
> and normal ones in non-instrumented functions in the same TU?

Yes, exactly that: __asan_ in instrumented, and normal ones in
no_sanitize functions; they can be mixed in the same TU. We can't
rename normal mem*() functions everywhere. In no_sanitize functions
(in particular noinstr), normal mem*() should be used. But in
instrumented code, it should be __asan_mem*(). Another longer
explanation I also just replied here:
https://lore.kernel.org/all/CANpmjNNH-O+38U6zRWJUCU-eJTfMhUosy==GWEOn1vcu=J2dcw@mail.gmail.com/

At least clang has had this behaviour for user space ASan forever:
https://godbolt.org/z/h5sWExzef - so it was easy to just add the flag
to make it behave like in user space for mem*() in the kernel. It
might also be worthwhile for GCC to emit __asan_ for user space, given
that the runtimes are shared and the user space runtime definitely has
__asan_. The kernel needs the param (asan-kernel-mem-intrinsic-prefix)
though, to not break older kernels.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO3w9h%3DQLQ9NRf0QZoR86S7aqJrnAEQ3i2L0L3axALzmw%40mail.gmail.com.
