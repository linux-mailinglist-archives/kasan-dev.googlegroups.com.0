Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQHMTWZAMGQEWLZM2XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0314C8C8941
	for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 17:22:42 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-36d92a840absf64021605ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 08:22:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715959360; cv=pass;
        d=google.com; s=arc-20160816;
        b=xT0scBCQWhJVcQ2DTCelQJAWxLi6TNKsAeKWOFxDW9DSrbw1425M7RBnaPRw3Gf9HW
         g+7zB3XDrVdO0KsuNAt8YX58fYMZoiGTHc02gjXOTtAXOiRNoDwyZ/IhCEwzutGXESX8
         cu1TKFUCvoEW4Pcqcy3RVaIsP9cy1TX6BhzD5fy5GhKoniK3bBkdjT+BHulwU+3l/TZQ
         IxbQwT20wJOj05C52P/he+WL3cRg5zz5zM2gE9VcyR5W0pKL8fAQCNXypMfjNuQ2teli
         iGIuJbrSHu4gFi1f1TgNG5z7lbJoyzf5fRwMOekSuHOz2HN6bJ8P7uZq/Z3Ytp+u+/uF
         Ki4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kWucBpO9kFTS4xYa0X60n5F9nV5WMy3BwwaArLgHRGE=;
        fh=gL1gLGgb3PmvvyI2ylby1ggPGX1NPEKne7Mpt8kSxbI=;
        b=BbvfFpJw+tpxXWj+HSpqvcwOJwwmx0xGkno0do7Ya3tE9dlggvF0Nyp8PBALKnHLLq
         FqCq5PmxXtItIUroonXngenypZUNztwmSD9luXqFWbNC1hOzAwdfJEjSG3hOdOayyyv/
         2Nt0qj9HfbiuQo/CBWk2gqQGj/6GTgUm7jlwReC2owk/L2M8nBZSLpVz3275pTZ4jGtY
         0Wkj2EIY8oVky4GLN1+z0ThMc8jB5HJnXHK8nlijVzevTNi6XpNA6BTypeYr4whIC9fk
         dstagjQRpoNu0nm5UN0Jyt/HsbdeGkfiDmcEOMOTsUwQve0JqP1vEhAyULHKp7W3NYfJ
         eLzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Zsg/cCFm";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715959360; x=1716564160; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kWucBpO9kFTS4xYa0X60n5F9nV5WMy3BwwaArLgHRGE=;
        b=ux558bki2YpSB6PW9ABOU9NinmUe2C9D0JNs5T/yXIS7FaQLASWFicmM8rH2orN0XL
         wBGy3Ea/vYpA2/wp3awduoCrqeoAdoW/gc3vrYkYCWUR7DbKOf7IpjbDZ0Je/avUe5U3
         b80NTNFODKzRtnlONmohW8C+YOb+pGu37Wxydr8oNnxc4AqTeh2ubTB6yTAVxXvqUk5f
         qJiO3Nhf8lqBmfpYTa13F6rhtb/V0dBppB4bDNarXpFzYUG6c1ifAvwxecebGsCpiqOg
         q4FpUdBnvMYG+UIhVYwdmViVNpJVkdEDRGgj4rLoPC47Bpsu0OksE2R493s/pFtHRhZo
         cKdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715959360; x=1716564160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kWucBpO9kFTS4xYa0X60n5F9nV5WMy3BwwaArLgHRGE=;
        b=b2PUQK5+iV0yVv3CYcVj4ZkbpC9M71gVuPTZ4BsTrvsg6Osaf0GzYTzMSDTOUU/Y6R
         v/QknJCPJ/XP/hMaN773jmBfjcBHzgRKYozs4ya1vfaTe11vBZiYB5OFQEN2GlCNSj/i
         RWIzKvORR41a+fNcgTu62kpFwogd+olGRaEx5qogeHlUeiy9jTTHwNtHLkgIM8cnlTsF
         xziFka88rmQoLCTdSe40e4UAO1LTxN3BNvUpiLMYmAkcPKckowp1k9zdewooy/o8Y+I7
         sbu8iuKsG3WB/oBGdeyS5vojV/jW9CV0TdHy9bPwt/CTW/XNcLXZq6McRLGF3LuEytHP
         4diw==
X-Forwarded-Encrypted: i=2; AJvYcCVjlFbpSTNjkFxaeeAJDO1Ye9RzOH55SP5LttdwX94YrxVOaUB5RvWRXGbi+WPipA7TRt5Oi9NbtDjQAoR8faEyA9YLQwN0Sw==
X-Gm-Message-State: AOJu0Yw5w1YtX2RIhNe+AdVk5uRYLJoHjWldFFl29CXkPU6WCcP9z2Dr
	OCJ1FSstjRZBjrPaArULrhMlzKht/9arYKpnrWA2QOs9VxCofH7M
X-Google-Smtp-Source: AGHT+IG//SsFZKlFgr9m4fb+C1++FXWODGTREPKtZEbewfWEpe4B7nqNKX+O4cI/vVsgLuaV6eAfqQ==
X-Received: by 2002:a05:6e02:20ed:b0:36c:5022:af8e with SMTP id e9e14a558f8ab-36cc1465e3cmr238051325ab.19.1715959360695;
        Fri, 17 May 2024 08:22:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7305:0:b0:36d:be88:1bfd with SMTP id e9e14a558f8ab-36dbe881cb1ls8481705ab.0.-pod-prod-05-us;
 Fri, 17 May 2024 08:22:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8EFywUdxdGGYcoC6coG+TqNUbLpgEm4yO4o/JnVsLu5pcbgz1vPEB2TT8SSnq0NEpxW2r62d3Yt7D1pIGTaDh3KX1Ow+koaxZeA==
X-Received: by 2002:a05:6e02:1a43:b0:36b:26df:ccde with SMTP id e9e14a558f8ab-36cc14e1caamr280506215ab.28.1715959359616;
        Fri, 17 May 2024 08:22:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715959359; cv=none;
        d=google.com; s=arc-20160816;
        b=ETHUDImSgDpUPo9hP1Qh3NieHyYXd5yM1nSkWt+NdKGisGBK9KkFPE1Q4fI62cP6NB
         wviXCLZuYv8HicV+CcXojDCudissiPryNuursiqciIwIeMWJn2lq5x0Uez+JjkligusO
         Op5/TVQtvzMnJx9OzpiQdfQSZrugwKkrn3bczrGc2vWukCg+egbKnFa1U9u7HV7RX75M
         iPOqiIFiVV3/py2ZTEIz94iEpfuxdTJYEyDBe+p09CPyGNwHiLMg4QrrVhVje5I4Db3b
         MYUDbFcQg+hRRj9amjKG0nvUJyGHrjJNMCXJM1t3WxhyVBCPEsTJQz7bEwquMVEXGXDA
         XeUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a0X1IdGrvgRbIDZDbKlklVPOFj9du4fG+oJBScJlx9I=;
        fh=EP1M1UkeYPV7qoyXsC0h7F7y7+RLciVMDFS9f7ziddk=;
        b=tND0/Ik/WbQa6sFoxrJXvulWFRHPOMVlqv+8ctNJaD8M03bPk1bltlFS/Epm7sp0gi
         3qAGS+FIkQJ1shrONRQzUyWJYerFvfZF6QpdOgRsAlZ1oJDXMATFYD7XfHAhWvZsUoeO
         5CmOoT02+cCoTaAvfyXVdYE690A3nHV3r0kDAwhNHMrWjv/LxhuqZV9QWXp8Cc3Mpf0u
         XhHDA5JP5TP77Fk1BtBbCJC+45cnUmiuWptADB13+vW/9KG5FEJ0WNs2GfYhJb34knrl
         xAh7hAvCg5AnPHEh9Jsqh6SQlTEGG2lUt+YkatenkPAC50B50wFrb/Vw6EDt0GzNRaP4
         l6Sg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Zsg/cCFm";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa33.google.com (mail-vk1-xa33.google.com. [2607:f8b0:4864:20::a33])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-36cc657b584si11860765ab.1.2024.05.17.08.22.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 May 2024 08:22:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a33 as permitted sender) client-ip=2607:f8b0:4864:20::a33;
Received: by mail-vk1-xa33.google.com with SMTP id 71dfb90a1353d-4df3e3c674fso253624e0c.2
        for <kasan-dev@googlegroups.com>; Fri, 17 May 2024 08:22:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnrqm3h7AKQgE7Jkw9NeGG9BW7wO+ir5eKCSBt9ml1jtCqvX03eU1vwr+HBjrbwF7CiWvhynZTdT3qXsJBZlC5DZniILSO9wSw8Q==
X-Received: by 2002:a05:6122:98a:b0:4d3:362f:f9c1 with SMTP id
 71dfb90a1353d-4df88359107mr21578723e0c.13.1715959357364; Fri, 17 May 2024
 08:22:37 -0700 (PDT)
MIME-Version: 1.0
References: <20240517130118.759301-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240517130118.759301-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 May 2024 17:21:58 +0200
Message-ID: <CANpmjNNNW-URJjyEpb9CYM2kvYdzNu-jbmk2V2fukbTU=PB29Q@mail.gmail.com>
Subject: Re: [PATCH] kasan, fortify: properly rename memintrinsics
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Erhard Furtner <erhard_f@mailbox.org>, Nico Pache <npache@redhat.com>, Daniel Axtens <dja@axtens.net>, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="Zsg/cCFm";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a33 as
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

On Fri, 17 May 2024 at 15:01, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> After commit 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*()
> functions") and the follow-up fixes, with CONFIG_FORTIFY_SOURCE enabled,
> even though the compiler instruments meminstrinsics by generating calls
> to __asan/__hwasan_ prefixed functions, FORTIFY_SOURCE still uses
> uninstrumented memset/memmove/memcpy as the underlying functions.
>
> As a result, KASAN cannot detect bad accesses in memset/memmove/memcpy.
> This also makes KASAN tests corrupt kernel memory and cause crashes.
>
> To fix this, use __asan_/__hwasan_memset/memmove/memcpy as the underlying
> functions whenever appropriate. Do this only for the instrumented code
> (as indicated by __SANITIZE_ADDRESS__).
>
> Reported-by: Erhard Furtner <erhard_f@mailbox.org>
> Reported-by: Nico Pache <npache@redhat.com>
> Closes: https://lore.kernel.org/all/20240501144156.17e65021@outsider.home/
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
> Fixes: 36be5cba99f6 ("kasan: treat meminstrinsic as builtins in uninstrumented files")
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>

This is getting rather complex, but I don't see a better way either.

> ---
>  include/linux/fortify-string.h | 22 ++++++++++++++++++----
>  1 file changed, 18 insertions(+), 4 deletions(-)
>
> diff --git a/include/linux/fortify-string.h b/include/linux/fortify-string.h
> index 85fc0e6f0f7f..bac010cfc42f 100644
> --- a/include/linux/fortify-string.h
> +++ b/include/linux/fortify-string.h
> @@ -75,17 +75,30 @@ void __write_overflow_field(size_t avail, size_t wanted) __compiletime_warning("
>         __ret;                                                  \
>  })
>
> -#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +#if defined(__SANITIZE_ADDRESS__)
> +
> +#if !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) && !defined(CONFIG_GENERIC_ENTRY)
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
> +#elif defined(CONFIG_KASAN_GENERIC)
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(__asan_memset);
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(__asan_memmove);
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(__asan_memcpy);
> +#else /* CONFIG_KASAN_SW_TAGS */
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(__hwasan_memset);
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(__hwasan_memmove);
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(__hwasan_memcpy);
> +#endif
> +
>  extern void *__underlying_memchr(const void *p, int c, __kernel_size_t size) __RENAME(memchr);
>  extern int __underlying_memcmp(const void *p, const void *q, __kernel_size_t size) __RENAME(memcmp);
> -extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t size) __RENAME(memcpy);
> -extern void *__underlying_memmove(void *p, const void *q, __kernel_size_t size) __RENAME(memmove);
> -extern void *__underlying_memset(void *p, int c, __kernel_size_t size) __RENAME(memset);
>  extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat);
>  extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy);
>  extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strlen);
>  extern char *__underlying_strncat(char *p, const char *q, __kernel_size_t count) __RENAME(strncat);
>  extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size) __RENAME(strncpy);
> +
>  #else
>
>  #if defined(__SANITIZE_MEMORY__)
> @@ -110,6 +123,7 @@ extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_t size)
>  #define __underlying_strlen    __builtin_strlen
>  #define __underlying_strncat   __builtin_strncat
>  #define __underlying_strncpy   __builtin_strncpy
> +
>  #endif
>
>  /**
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNNW-URJjyEpb9CYM2kvYdzNu-jbmk2V2fukbTU%3DPB29Q%40mail.gmail.com.
