Return-Path: <kasan-dev+bncBDW2JDUY5AORBD7FRWBQMGQERX4XBDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D364134F137
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 20:48:47 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id t4sf5737298lft.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 11:48:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617130127; cv=pass;
        d=google.com; s=arc-20160816;
        b=I730Z/XcnxVk3eU4KWNsXtzeVgRzON9uyDJ6pDfhUn6qoAghLrXC6JO43YTQSG7ZfO
         tIKrCG6g0ytKgqw9YYFi9KaBvTBZhDA7pMjsps4goEjxiWxcfHJXquBm98oG2zhx6wWX
         wTOjQgtG7uLS2E5ykB7QqsFYN7X2JDm4kpwlUf5SjqgJLZ+P5hMMkzWqThC+9kClsGRn
         ymqiMao1UOO4Mq956/J7HoBEp9CY/ieSFg58HnB3pc03NuC4aJqeqhHAC6revW6eXkJ5
         EGXnmzbjSzxg68OWffCRarK3XNLndHk7ToW2l/vvYRWK8QQSoYRZJJiX5vZUZT7A4Oho
         UqSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=rpYgZicP4miYw4cTQiK+hW2HSIGGoKvg4Y6Sjxr6b2M=;
        b=ELu/Wr2ZRPYrxSJdr9JMWgWf5EMqkYAsw3dsubzTdq5DFNhL+UPFbxJW6XYbiC8g4d
         l5WlSPqK0ZcmT9QOYERQHeIGg74pCDjORp/QpGLK3aahcHMbdZZ57aWgo5K+ExXrvBBa
         MQN1yDicaDJC3oSxL63CSv8belFbOBi2Y9dbX+vCZVHMse+jYOzxftLfzxX0J2acVLWW
         6yS52ncefW+4X98wnpkZLIbFELO2HxijAAW0QLX9mS63KbktyLobeBC8GHQJXG/Xz7Kg
         vN2Xv0U/BJCHteQ2gf0ELaG5/6zEExi2qRH7fP8XE1aglzQRWPyma3VysMTRJnuGdJbK
         JC1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JylleUcV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rpYgZicP4miYw4cTQiK+hW2HSIGGoKvg4Y6Sjxr6b2M=;
        b=bq4aqb2IPm8w9seW3UO76gQlrvNwcQAqVVIf+biFvSAydLvKnWkfXE5AWHaocu3Uk4
         JJtSyG2HVeLutbtAj7GEEQEhz7mTYI69FQIRp14Rts2mCcLaztB4jtqmc1BuYawqty9J
         LGC/nMPVja6BqWTlFjzGQGgfKap1olRmhHfQlpNO/vntp5MijLyaX/k7vstlmj4+GZOq
         4iid3Q3+7o3e4liv98oXTYRrebpXsc0E2ADc3rzKjqOOjue4ofsKCByhkN2X07CGJQDy
         5JD0Tm7nE+gOkodygfzUmxmaEuE9MsrCl+D1b1w1YRcrjDyJiF2wqg2xEmwNZHiU9egv
         npjA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rpYgZicP4miYw4cTQiK+hW2HSIGGoKvg4Y6Sjxr6b2M=;
        b=bGOOhhLub/tDoTqvCni9AHw1tVQnwDtYzn6xu/nBoGUkFESMYGsc+Eyxyz5G5d8Y4O
         YjXUuJWPnALxZbGaSMCagE7uGhfsd5fNm0UOZRakMMegs9mkq3vwm+POTZh8LpyYetgk
         ajgpvi6EqYm7+eOBOS6qQz8IvRUst+OMjX8G2PQu4tPZJdoWxnuMuHt8dne5mXx946SB
         Sv98lh8o5wt5ElOqoERn8eM4ULB/xQFoLc8zIV3OXtABOASR9s909twIAyyUTL3ispaG
         eXO5d8veHKfzxO3yvDs7fz7LW0LMFBIWsvVcvfN1/7z7S9kLlRLzGiaPgKn2pdl8IuuY
         pnDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rpYgZicP4miYw4cTQiK+hW2HSIGGoKvg4Y6Sjxr6b2M=;
        b=nFFC8qNMV76dsBCufA7F73YCSYqQP5ca5xYdaHueABDT11hbcYqqAfS84MevbVS9GE
         gSp5TmXytcnLX8SGqF5oRVLx07QXtEKC3w/OwT9aPoqbvyh/KmMiOgxxwaYVO9Z/lfk3
         2DbiclnjH3VLtzd+xv/tk2XAetFZD3sfuBIsmmbu3kWLCGnOZB3auCURoOwRiK0Knj+p
         nAPNIX5fPUayoYGfvSaCt9SYp4mrELiVY0eNNyL6vRbVQPhmMAdswvaVNk4+9T05Y+BG
         OIYOihdSI4IWIvPFQAkYym3evVJaOTEpSYktr+YKtsOtusGLlNQ5113zg10FcVoTaAqV
         48XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531l0BbscagZGC329kz28ulc8Gb4IgoW1BlHiGYjQKQLBa0x1cC3
	63tbVeaghIABITxvGyFZpww=
X-Google-Smtp-Source: ABdhPJydlhyNjbZrr/YLoNE/vHn1pUkNjCF8e02+GPDrzJRrjgfOrlP7UFYxDtouHyCKjEIns+Htqg==
X-Received: by 2002:a19:f107:: with SMTP id p7mr20496073lfh.613.1617130127409;
        Tue, 30 Mar 2021 11:48:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f8:: with SMTP id v24ls7760814lfo.2.gmail; Tue, 30 Mar
 2021 11:48:46 -0700 (PDT)
X-Received: by 2002:ac2:4254:: with SMTP id m20mr21042059lfl.474.1617130126358;
        Tue, 30 Mar 2021 11:48:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617130126; cv=none;
        d=google.com; s=arc-20160816;
        b=rV4Z8Je934qf9Dwp5D7ekiOXrH+bF8ehxWYwQNIpQP6oDOd/SqJ4W30IHRw73D6SnL
         7HqPzVC7F+lj95qida0a684CZRDchHMHTjAcw+mjEgrK+/CfcwvrL/EcO7QfQVh64SEp
         bXmTjPK9a2WiL+RitasLQLMXsndgzFLtm8VWstXUBkm/4091WG6rHH/iMOwHzxLEO8k9
         D3hP66OjWDWRLu5c0YQDAhoNnei4lMCuFDPsqGoKCL4MtKUItBW2Ucz4OK+YQxnTVo1W
         om+pH2ELSGd+zMPmBPYBVWSuF3V7XFBTP3pYV9XELmopZ3UbSZH15+T9dvZOoVOaWkLt
         DXqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eN+6HYZu9ai/bWKIofpS3d379/+m4z1HTTkJ2Rk0/xc=;
        b=GJi8Wuzc43eRTTww1NB5djnm9s99s38UL96+fH1QwgbExKO3l6bXToq+jPQbVsAE39
         XvKVpTLnocIE1T1+iSG5w/JYeUrHZuNgl4MFu9yDgrtMbjZQbd+9b/XdDJ+hvUKqAkEq
         6/4vt8gm3EMFv0gcEa83GmK6S8Nl/xrse723LkFxSUF8Ac9w2xv8XVn5YA7sloShVb6S
         7eM5RIwBLhwhVgp4LYXh1FPPUB8iZ4fkuKovgIm+tLFDvRS/vCxgtEZo1kbJSsjSkR5J
         iEYFurFoJeeD6ilSmX8bllcGxySX9ftGK625O2nCwrG4GWLBPSpGbZbBmA0gGnFRFov3
         59Lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JylleUcV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id q3si1023260lji.2.2021.03.30.11.48.46
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Mar 2021 11:48:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id a7so26342976ejs.3;
        Tue, 30 Mar 2021 11:48:46 -0700 (PDT)
X-Received: by 2002:a17:906:4e17:: with SMTP id z23mr34847959eju.439.1617130126127;
 Tue, 30 Mar 2021 11:48:46 -0700 (PDT)
MIME-Version: 1.0
References: <20210323124112.1229772-1-arnd@kernel.org>
In-Reply-To: <20210323124112.1229772-1-arnd@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 30 Mar 2021 20:48:35 +0200
Message-ID: <CA+fCnZfZre1d07eUq0PBzznn8b6Co0Scp9Dnwad6ZaGp4LyrCQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix hwasan build for gcc
To: Arnd Bergmann <arnd@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=JylleUcV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::633
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

On Tue, Mar 23, 2021 at 1:41 PM Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> gcc-11 adds support for -fsanitize=kernel-hwaddress, so it becomes
> possible to enable CONFIG_KASAN_SW_TAGS.
>
> Unfortunately this fails to build at the moment, because the
> corresponding command line arguments use llvm specific syntax.
>
> Change it to use the cc-param macro instead, which works on both
> clang and gcc.
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  scripts/Makefile.kasan | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 1e000cc2e7b4..0a2789783d1b 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -36,14 +36,14 @@ endif # CONFIG_KASAN_GENERIC
>  ifdef CONFIG_KASAN_SW_TAGS
>
>  ifdef CONFIG_KASAN_INLINE
> -    instrumentation_flags := -mllvm -hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
> +    instrumentation_flags := $(call cc-param,hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET))
>  else
> -    instrumentation_flags := -mllvm -hwasan-instrument-with-calls=1
> +    instrumentation_flags := $(call cc-param,hwasan-instrument-with-calls=1)
>  endif
>
>  CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> -               -mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
> -               -mllvm -hwasan-use-short-granules=0 \
> +               $(call cc-param,hwasan-instrument-stack=$(CONFIG_KASAN_STACK)) \
> +               $(call cc-param,hwasan-use-short-granules=0) \
>                 $(instrumentation_flags)
>
>  endif # CONFIG_KASAN_SW_TAGS
> --
> 2.29.2
>

Hi Arnd,

This patch breaks SW_TAGS build with Clang for me with:

arch/arm64/include/asm/current.h:19: undefined reference to `__hwasan_tls'

The reason for this is that cc-param is only defined for
KASAN_GENERIC, the definition needs to be moved.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfZre1d07eUq0PBzznn8b6Co0Scp9Dnwad6ZaGp4LyrCQ%40mail.gmail.com.
