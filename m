Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUM7TKPQMGQE3ZKELVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 91C6D69257E
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 19:41:23 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id x15-20020a05680801cf00b0037b427d8f40sf1741168oic.21
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 10:41:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676054482; cv=pass;
        d=google.com; s=arc-20160816;
        b=xsvjtyBGnr4nWoSMlaW1E2kRt4W4xrDkF8gHVRONQ3U9yojMY/9uD1hCwIJ8qbPJya
         K/QXoCOfbbsgAVjPPsTJ6EwTOelYmXSazU/sNHMZvqOTZlthbQBIbsHS0IR/hjoaZZNd
         GltRZG6LPlyMxPbNLdc6QFhwXMwjwioa9naHrETErIUYzVdXr1sa4SEVYkaOukWeLACK
         5mRWlUey2qaWGhkuQt8Piz+XFwej5ESchcuOKNyldlCwmB+Va/WdnxvTUPgdGCsB87wL
         /svLH8z6yW74GxBHojPiUCI7hxZxfmNg0A88x4NmZ0aNdXQnydbFZRozYqUoOTPy/b8H
         4uKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=o+01Qk63DcELrjNQ8ame45RmSGsPse2sb6HotZPd89I=;
        b=s5oINZb9QKYR1wXN0+rak4dgB96zJ2t/hysWHjXAc3i5gELNxsp0k6913AX4Nv+RdN
         Od9F7zkwCXzK/2LhBPbBooSZOSLm3AhZyn22WOcCiLdopm6s4zb6zNvkEx3AjFTTx4En
         CF9HWX5BJKoCKcRUoawXgy0hWRuWfkBb6OtMpzlzKadjSA9hG4POvQT87Lb44kAULNyx
         e3dSbyLZL8QGGDqcg7a+4UgA5RDXqdvDdhlm241rVzDTSi8NA7UXzD7yYCKduTVPLKT7
         PzYdTM2V0Uj+UWqSNHPFQwSjwnXHr/lu8X9ueVL+mgOPGO5YRfPXhX0agLckHzRy9kZ7
         6tDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iRmtp991;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=o+01Qk63DcELrjNQ8ame45RmSGsPse2sb6HotZPd89I=;
        b=P7dKQXUoXjlPjeMsMlvTEq3JPYy8NnBZwz3aZkfF8tZwDfciulXh3xM54gltJphJJ7
         fHz9Xv3Gqr4vIw4PeHzlDHddAkxdFcuTTqbaneEDelv8sEHogHg5ag4t1Omf/vpMCekF
         +vcTyOs/ZIlaFC3xd1S6DtbIOOfkxGY5pXxW/aymYjum3IrSubHWTLYljWZ49wLhKasP
         IcIaw0A1SRdkO6fnZk7z9kiXVSSvS0W5eKHils5gbeJoMPjeELGDnZtjtIWJk2XscJEk
         Af80q3OWlt3eOOWFRdiepCik5iGHL4x8Tlj2fFt1y4DW9jKf7AI0WShNDJX+aR5TcOZJ
         72SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=o+01Qk63DcELrjNQ8ame45RmSGsPse2sb6HotZPd89I=;
        b=XzmqQ0WoTKmUiKTT+YJIqXwj74XaoGe3bzcpOHMxSh1ECTUAA0ur0uD/FB68rm5W5q
         UiY0zbN1bhK0932uX1C5914kNH8CnHYWbKInuvYYpim2t016nyi4bT4H1gDqKVwfW108
         gH/eyc16lff+7dVegoodLomL4+IV8rK6NC6xWxaO/Vz47zP/EP8bTQptWMRLtXIeErwi
         VmaUqsNVjx4xAalrNTqqVQH8+SZQkQfy1g7f3pjGbUrmSqqgXZeMycd+L5wKii+GwkoW
         SHMHV+ybkyGPzrMEHS8Uddrk1cajPxWh6q21k6FQi3ZWpsig2SyYkbYFCRhYBn7Z4+RQ
         kN9g==
X-Gm-Message-State: AO0yUKWF0AE6tYKU/CM3/kGHfRgUCGD38vCn2BYQNVpyHhpmEjKBiZdn
	06njpU4EQeDaFO7pREYy9Tw=
X-Google-Smtp-Source: AK7set8csXMbcrycyYDuvJx1iKh/FehzXsXKfiBvYdbQrAmGwlLZh6bkKcSZc0lzuLLNwJUmfxro3Q==
X-Received: by 2002:a05:6870:9f88:b0:163:463c:7492 with SMTP id xm8-20020a0568709f8800b00163463c7492mr1380490oab.82.1676054481968;
        Fri, 10 Feb 2023 10:41:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5387:0:b0:68d:68bc:8d10 with SMTP id w7-20020a9d5387000000b0068d68bc8d10ls922929otg.4.-pod-prod-gmail;
 Fri, 10 Feb 2023 10:41:21 -0800 (PST)
X-Received: by 2002:a9d:37ca:0:b0:684:e09b:439b with SMTP id x68-20020a9d37ca000000b00684e09b439bmr7785401otb.9.1676054481458;
        Fri, 10 Feb 2023 10:41:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676054481; cv=none;
        d=google.com; s=arc-20160816;
        b=v5rdgKjR7QH1Qe2HzPpm0p65K/bpfgUT2Nu7rKlErTmp4M9OK7sBI3my4O2+DCQZtN
         FBIDrz/Yz9xmLah+nc+NHwEW3T20Di6BvkIxQwGQ1/RqBNxeCglBmxc6YpAUkK1GiC5f
         qXzrasbfC36OHoiBp9EOR2tDFyl3tjBP1VxlVEPqloi9Ys+5E/TqfKuYxpTOp9U+7aPi
         0TPSeCK2b3tINhkh8NzvKUqlvEBGG5cxRZ9JYrqJSySxFtv6p+CgXyRclubcgf4Tp6jw
         YO459NYlh1y9nPXTIfe0KWojlWp/ADHmiUobyatanEGGg6xe4bcW+spbBMDXJobBISfa
         +40A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HoyBTwj66Ay0J3w/gr1HIoKq5C1qctdqphazc4onVf8=;
        b=fgjV9n9ZJyDWGIBu1n2dPw8GdrYdHn4zEaGv2yOyP3izlPpYKX+9ZYnp6Yk4qZEXeT
         H4JBi6atnjG2PBvMDXVvqbtSztImlAlOrqwHriDNct0Pjttx0Oi5j0YCCGWPdaZw3ZFV
         MMjPaXZMQPkMVi5aatWhkVdWQV5sqIBmIM2g4+chqsA8gjue4SrUdgvhsAknOOoe6Yei
         s0+gBeNmLRHBSNwioLxXy9qnnYDpQDZdIl4ZpmRG6WVUwvMydL5gbXjstY9wVlzD/GrU
         bU9tLRWbFNYG8JxguHuA3XlUvPyA+6015hmKhBNFQDwg394DFvV3XBwYbCsmz2CP6sBm
         KC3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iRmtp991;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id br2-20020a056830390200b00686e40e1e0esi735931otb.1.2023.02.10.10.41.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Feb 2023 10:41:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-5258f66721bso80000097b3.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Feb 2023 10:41:21 -0800 (PST)
X-Received: by 2002:a81:7406:0:b0:52e:e6ed:30ae with SMTP id
 p6-20020a817406000000b0052ee6ed30aemr17351ywc.558.1676054480876; Fri, 10 Feb
 2023 10:41:20 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com> <CA+fCnZeU=pRcyiBpj3nyri0ow+ZYp=ewU3dtSVm_6mh73y1NTA@mail.gmail.com>
 <CANpmjNP_Ka6RTqHNRD7xx93ebZhY+iz69GHBusT=A8X1KvViVA@mail.gmail.com> <CA+fCnZcNF5kNxNuphwj41P45tQEhQ9wX00ZA4g=KTX4sbUirQg@mail.gmail.com>
In-Reply-To: <CA+fCnZcNF5kNxNuphwj41P45tQEhQ9wX00ZA4g=KTX4sbUirQg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Feb 2023 19:40:44 +0100
Message-ID: <CANpmjNNH-O+38U6zRWJUCU-eJTfMhUosy==GWEOn1vcu=J2dcw@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=iRmtp991;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1135 as
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

On Fri, 10 Feb 2023 at 17:13, Andrey Konovalov <andreyknvl@gmail.com> wrote:
[...]
> > Probably the same should be done for SW_TAGS, because arm64 will be
> > GENERIC_ENTRY at one point or another as well.
>
> Yes, makes sense. I'll file a bug for this once I fully understand the
> consequences of these changes.
>
> > KASAN + GCC on x86 will have no mem*() instrumentation after
> > 69d4c0d32186, which is sad, so somebody ought to teach it the same
> > param as above.
>
> Hm, with that patch we would have no KASAN checking within normal mem*
> functions (not the ones embedded by the compiler) on GENERIC_ENTRY
> arches even with Clang, right?

Yes, that's the point - normal mem*() functions cannot be instrumented
with GENERIC_ENTRY within noinstr functions, because the compiler
sometimes decides to transform normal assignments into
memcpy()/memset(). And if mem*() were instrumented (as it was before
69d4c0d32186), that'd break things for these architectures.

But since most code is normally instrumented, with the right compiler
support (which the patch here enables), we just turn mem*() in
instrumented functions into __asan_mem*(), and get the instrumentation
as before. 69d4c0d32186 already added those __asan functions. The fact
that KASAN used to override mem*() is just the wrong choice in a world
where compilers decide to inline or outline these. From an
instrumentation point of view at the compiler level, we need to treat
them like any other instrumentable instruction (loads, stores,
atomics, etc.): transform each instrumentable instruction into
something that does the right checks. Only then can we be sure that we
don't accidentally instrument something that shouldn't be (noinstr
functions), because instead of relying on the compiler, we forced
instrumentation on every mem*().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNH-O%2B38U6zRWJUCU-eJTfMhUosy%3D%3DGWEOn1vcu%3DJ2dcw%40mail.gmail.com.
