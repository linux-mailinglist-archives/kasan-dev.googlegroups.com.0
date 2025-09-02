Return-Path: <kasan-dev+bncBCLM76FUZ4IBBHHS3XCQMGQEQIS6GXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E33F0B41096
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 01:09:17 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e96f179466esf8279251276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 16:09:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756854556; cv=pass;
        d=google.com; s=arc-20240605;
        b=BCVJvbQGQl114RxPcoRCZSh+Q/FbmueAT1vvk9Tnl7bJ3ZcJ9irozsx8E4I9zq3/VS
         wCvWgnoYvAH7JJK+2nPr4VUwlGlOn0igzUthlbqrM6Im/ztCA4rLhByRSyyXx/ms6ZFA
         4sMMoWrCEQbo0PfHOs6rjnznTm2+JYq3IeUcl4EO9uf9KtNrSdqYvPpZaZC2aWdie+/g
         IpeqUBoop4cy5mtUJPMhcRDuN+bZblz2zfnDax76UsEFF3jxQ+EgDG37VSPg8FGvd8el
         VSdshnXExdLCznzCsnicsFAWhEn7xiq+Oa4xMF7oqxgz5tLSBP5ymn1dZlL7bB7vybrX
         oUaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jsPEHFwDFg+xppoN5MngFa9Fe8pRELK4Vu+Q1Rz929M=;
        fh=mx6OT7yzLBjcrTFVh6gyc+Vf3XEWLiLFsc9tSu3Ql/E=;
        b=V9vhAsmy/OQlOINULGmo3f5vkMeMCwGRes53VUHzI5hSaXNsD1tkX91FOfu/fL4Dsu
         w6reonq5vEvG3LJztiXmHcPF6hxgfVx/FLEXLsqO/ZOU8S1MHE20BpwUVwVHDiZDauTX
         KFpr9kZM5NfiEuJ3Ne53gsRi0oPkHWkT5jkty0/ErLQo6zQAHWW98s2Qep502/exBntD
         6PQWuvK/PLOmTM3sPPzA55Zmj388MOQWKB798CfKUBb347CAo1fc4FPdjvW7cIp+D36M
         2blr12NK388S24QIQmO3OKXiPL5F51Aah8Yg5gHW9SQ+sbbirtg6q7Z0AUNfr3NrcW4G
         JxFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yjgulkP9;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e35 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756854556; x=1757459356; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jsPEHFwDFg+xppoN5MngFa9Fe8pRELK4Vu+Q1Rz929M=;
        b=XrurZC+pLGeYEKCiiQLjU8GFxti4Gq8PYsiCv7nYSC3WlJ+HRYPMcU4yFDpKTMRcqF
         8TR/b88hYBry1AcWVPFRcqMxFwaU6/64N6TCek7jKKjJHyUDuvzdx42ZFt9DNh7Y2zDT
         blvVt7xV7LF/0eDmjUnfdEGthfmzd895AcF8pMD4UPUu8EYRv00DGGElbgeXjAStz/Pi
         dWseG7uZkNOa8fNTlwBvy92z2mQgVXRkQmlPzBhnGQIWluCliu74w3NoDGpn4XCOZD9t
         hNq3xVCUehPLrne+qDQFeSgbBbXAuID3yQf6K06SvmoBLZNY8D2O26AlUrxw1FhYEV0S
         GhNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756854556; x=1757459356;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jsPEHFwDFg+xppoN5MngFa9Fe8pRELK4Vu+Q1Rz929M=;
        b=uFBLk3AjvrQlr/ea5elQ9IrQIRZqY3+89DiWpoXG00eIpzAqmPBULYwOSBC5qNLGwI
         UIHEiK8L6tgcqMcgHWiTVuHerTvl8JE7oWk1oB+8lT1U69P6NkIr0Xg5dhDpAX/N9dDe
         MLAQmr3Y+riuY3derQbHbZdMuQAvIBrTgZjhcKx/cqzkS0bwIf5ShNMcu4MCz6NJOPvh
         4wLKPhdCSo+4+RpjNDqxb6El5urbKenSAtGjs9N7wwqAf3vRXcM2GpwoRdrxQ5YuV62I
         2yLi5GDjPS9qQLLdeGzqiais0lz/yS/U4eV0PmLbgkuSo7iH4XjAN4THi9olYtd8S+Qs
         EeaA==
X-Forwarded-Encrypted: i=2; AJvYcCUK1I08Fppgp+J0LAW3XenAZVOGDJubk4iNFGbzSOobXqItOcCzhQyjRnDSxAhRzG/M/CeMEA==@lfdr.de
X-Gm-Message-State: AOJu0Yx0sYgTaVHDGP58SIi9qHUqmZ0WB/eu5vS+VSJnXbEZ+XJD7TlG
	8yjHB+5nJMVsGppX+gAAPreqxh9iXvoTmdBUwzQMWS6ejAORBhsnZlcO
X-Google-Smtp-Source: AGHT+IElTVUbFa4MXwjtAaY6ViNewPTgnlvlzqttxmfEtFoDfPe5w1ygWtBmOf0gh2M1tTXpJOe6Dg==
X-Received: by 2002:a05:6902:2583:b0:e96:c4c4:f635 with SMTP id 3f1490d57ef6-e98a578c8a3mr14310434276.16.1756854556451;
        Tue, 02 Sep 2025 16:09:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdDKQvotRvj+5WP4jhJ6O9quIYxmvYhlSPtsk3XDa9gqQ==
Received: by 2002:a25:aa26:0:b0:e96:f782:76e2 with SMTP id 3f1490d57ef6-e9700f1c3c7ls2962654276.2.-pod-prod-08-us;
 Tue, 02 Sep 2025 16:09:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXccKkDwWstyQf2LbH0xFwp44vOqCeUuswOGzq5eqIYKpuu1MxaGY4VmlZKvsqFAVZSlzjhim9R+Ys=@googlegroups.com
X-Received: by 2002:a05:690c:6006:b0:71f:b944:1017 with SMTP id 00721157ae682-722765844e4mr142114987b3.50.1756854555526;
        Tue, 02 Sep 2025 16:09:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756854555; cv=none;
        d=google.com; s=arc-20240605;
        b=YSP1XsfrI6MUhvR1g2yIvDCIF80B1NJmSI55BAvyFqmvKaOcsC8nd8z6nP80+t64kU
         2ada9/adUWYTQKAdqmDgeEO4Y3yyZnjvcxJ0eKG1Zz1vErn0F1jCjTKFg2qb1FC78Qbx
         VABV1BNpHlCrqcPOS3s27okRzIi1gGrGuxA63+S8aeg2NhiH/hqLfeJYlXYDtn0daETQ
         8SN64NpV6r4TG6JKPxOY0nxcCwEalN6LFC8891/EQY31oWUS2+BRO/4wLHYOcNvkJsAO
         L5khw33rxeyFAgn+EgVFAYYboeJLiyAk+FbNUBOP3fr5S5kWCBMo4V6mVX2EMkfxzl+M
         OY5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Ok/LzY68t77UKOxDiwSjWGMeBPTcLr/jFtZLJbmSzEE=;
        fh=AgrhBa7yukDW0hvs6K16Dlbyf1dYSXTs9DG0qrdun8Y=;
        b=F5ij9pu2P5r6rahgpAjalnczoxnVfU0v+jMmNOdzCLVj3OqEcszFJndBxyUzhPSUNG
         +pvDVyYOQuppknUZhlyVaCdbZBnXRCZJLtZvglpob7fFL8nnEPj2u1cw3jawnKOhFYWM
         5isMWNOhKMaX+nQ1DIuRbaURU0hSTg55yZ3R6hQgzKNJCotRbLmW6+ZML226vKfqQ5zG
         q/5lUpW++bv4WuazyZmb5ZNyHcRT//GR0j1M38uDAJmHLYidtGB8vgwOvqQF7mCxGBoq
         j3vn4lpAhfI3qf0qkyrE5fIMJOG/ipPNyBB5hHAZM5q4lA1FJlE0Ew+h3zfPoGJwiTaW
         TdtA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yjgulkP9;
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e35 as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vs1-xe35.google.com (mail-vs1-xe35.google.com. [2607:f8b0:4864:20::e35])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9bbdf49ce0si136015276.1.2025.09.02.16.09.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Sep 2025 16:09:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e35 as permitted sender) client-ip=2607:f8b0:4864:20::e35;
Received: by mail-vs1-xe35.google.com with SMTP id ada2fe7eead31-52992b299feso1173292137.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Sep 2025 16:09:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWY68eiky4e9dUuRs1u5I6UX7qFQlnZbb6OkSG2aDvc+kpQfvOPS8W2Ek6fPaB8ON9q3do04kH1zU=@googlegroups.com
X-Gm-Gg: ASbGnctBKneZBidijxHetnMRsHLIhx9gC26gRM0BSd34cG8drDwotl1V5hu2J1nS4vN
	ebpB6O8/pcVa4qdY3Ea/oHwAEXWlup5mUf4KeLQsd3oz+bQqttpXo2KXOEboWhktHf7xEoUR5jw
	RfrTn4ktMaQuQQtVakylHDzLSNk+r0v13BDp12Q4cMBS8anLKOh5TqqYTK/VbVh9z7mWL6vHV9L
	/7BPsE9njohaQrAQEfeSijLmQ/a6L/scbaQFqxkTfU=
X-Received: by 2002:a05:6102:3053:b0:4fd:35ca:6df5 with SMTP id
 ada2fe7eead31-52b1974e50amr4309938137.7.1756854554786; Tue, 02 Sep 2025
 16:09:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250902-clang-update-sanitize-defines-v1-1-cf3702ca3d92@kernel.org>
In-Reply-To: <20250902-clang-update-sanitize-defines-v1-1-cf3702ca3d92@kernel.org>
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Sep 2025 16:09:04 -0700
X-Gm-Features: Ac12FXywF_5PF4EJJMAvgc55AUTlDfNYbymSWMWfPLD0aBiRhuuGXQUjDtVsZ0g
Message-ID: <CAFhGd8qku6wkpqNCq+KpM4TMh-djVQW4UEdXON1Tk1BRtN8V6g@mail.gmail.com>
Subject: Re: [PATCH] compiler-clang.h: Define __SANITIZE_*__ macros only when undefined
To: Nathan Chancellor <nathan@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yjgulkP9;       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::e35
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

On Tue, Sep 2, 2025 at 3:49=E2=80=AFPM Nathan Chancellor <nathan@kernel.org=
> wrote:
>
> Clang 22 recently added support for defining __SANITIZE__ macros similar
> to GCC [1], which causes warnings (or errors with CONFIG_WERROR=3Dy or
> W=3De) with the existing defines that the kernel creates to emulate this
> behavior with existing clang versions.
>
>   In file included from <built-in>:3:
>   In file included from include/linux/compiler_types.h:171:
>   include/linux/compiler-clang.h:37:9: error: '__SANITIZE_THREAD__' macro=
 redefined [-Werror,-Wmacro-redefined]
>      37 | #define __SANITIZE_THREAD__
>         |         ^
>   <built-in>:352:9: note: previous definition is here
>     352 | #define __SANITIZE_THREAD__ 1
>         |         ^
>
> Refactor compiler-clang.h to only define the sanitizer macros when they
> are undefined and adjust the rest of the code to use these macros for
> checking if the sanitizers are enabled, clearing up the warnings and
> allowing the kernel to easily drop these defines when the minimum
> supported version of LLVM for building the kernel becomes 22.0.0 or
> newer.
>
> Cc: stable@vger.kernel.org
> Link: https://github.com/llvm/llvm-project/commit/568c23bbd3303518c5056d7=
f03444dae4fdc8a9c [1]
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>

Reviewed-by: Justin Stitt <justinstitt@google.com>

> ---
> Andrew, would it be possible to take this via mm-hotfixes?
> ---
>  include/linux/compiler-clang.h | 29 ++++++++++++++++++++++++-----
>  1 file changed, 24 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clan=
g.h
> index fa4ffe037bc7..8720a0705900 100644
> --- a/include/linux/compiler-clang.h
> +++ b/include/linux/compiler-clang.h
> @@ -18,23 +18,42 @@
>  #define KASAN_ABI_VERSION 5
>
>  /*
> + * Clang 22 added preprocessor macros to match GCC, in hopes of eventual=
ly
> + * dropping __has_feature support for sanitizers:
> + * https://github.com/llvm/llvm-project/commit/568c23bbd3303518c5056d7f0=
3444dae4fdc8a9c
> + * Create these macros for older versions of clang so that it is easy to=
 clean
> + * up once the minimum supported version of LLVM for building the kernel=
 always
> + * creates these macros.
> + *
>   * Note: Checking __has_feature(*_sanitizer) is only true if the feature=
 is
>   * enabled. Therefore it is not required to additionally check defined(C=
ONFIG_*)
>   * to avoid adding redundant attributes in other configurations.
>   */
> +#if __has_feature(address_sanitizer) && !defined(__SANITIZE_ADDRESS__)
> +#define __SANITIZE_ADDRESS__
> +#endif
> +#if __has_feature(hwaddress_sanitizer) && !defined(__SANITIZE_HWADDRESS_=
_)
> +#define __SANITIZE_HWADDRESS__
> +#endif
> +#if __has_feature(thread_sanitizer) && !defined(__SANITIZE_THREAD__)
> +#define __SANITIZE_THREAD__
> +#endif
>
> -#if __has_feature(address_sanitizer) || __has_feature(hwaddress_sanitize=
r)
> -/* Emulate GCC's __SANITIZE_ADDRESS__ flag */
> +/*
> + * Treat __SANITIZE_HWADDRESS__ the same as __SANITIZE_ADDRESS__ in the =
kernel.
> + */
> +#ifdef __SANITIZE_HWADDRESS__
>  #define __SANITIZE_ADDRESS__
> +#endif
> +
> +#ifdef __SANITIZE_ADDRESS__
>  #define __no_sanitize_address \
>                 __attribute__((no_sanitize("address", "hwaddress")))
>  #else
>  #define __no_sanitize_address
>  #endif
>
> -#if __has_feature(thread_sanitizer)
> -/* emulate gcc's __SANITIZE_THREAD__ flag */
> -#define __SANITIZE_THREAD__
> +#ifdef __SANITIZE_THREAD__
>  #define __no_sanitize_thread \
>                 __attribute__((no_sanitize("thread")))
>  #else
>
> ---
> base-commit: b320789d6883cc00ac78ce83bccbfe7ed58afcf0
> change-id: 20250902-clang-update-sanitize-defines-845000c29d2c
>
> Best regards,
> --
> Nathan Chancellor <nathan@kernel.org>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AFhGd8qku6wkpqNCq%2BKpM4TMh-djVQW4UEdXON1Tk1BRtN8V6g%40mail.gmail.com.
