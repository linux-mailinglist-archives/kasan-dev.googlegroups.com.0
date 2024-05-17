Return-Path: <kasan-dev+bncBDYZHQ6J7ENRBEPKT2ZAMGQECCU45IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C3FD8C8CFA
	for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 21:50:43 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6f454878580sf9399393b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2024 12:50:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715975441; cv=pass;
        d=google.com; s=arc-20160816;
        b=NRzZmI/vvpMuUDQqvba/kxAerFcdzg2miTS8Dti2lPcPBhoTe9ozc7Hx7tIfgdLN19
         8AvnQ+LrRc8nGrdT+kjZ7DdvbAcmVB4pfvcvk/+3MmFV3XMjtNXacTntfYTZl8zn6YSu
         WjEkgXJCnIqAXQFpPqcRKhcdqbZoGFk0Mdb3x6WOq1r4sZGlQcEJ+K/aRxircKdy88z4
         ZyJpWwqcjID9mJYMTXfs16RAY/ANX9iU6pvOFqrJPvTDc7m0QnzR0/Bsx/Lxg/J6xc1u
         rNrAuwhZ6VzPta6u5KwY6gvVRWjwrAYvXvIewmmGz1qdrJvdjp1vluh/teFnkPDzvA4w
         5VLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=zv1zUJ7WKCg5TFIPqWrlxmrmtCVm9toM7vXqGrwfvoc=;
        fh=uSaCDmKIor0VtybZaBnE/uNJ64pYBqFrvdZjZ37QSSM=;
        b=FVqg2zuvQxeCVPhbURYQs1tBt8oUi2vcDOTgAYZ5P2oblCPu7GJJRhFsnRuVVSi0LW
         DiN9F1GILLUYlhQyQ4+6JW8HbVcX9XoMz+nSIaPnJ4NGdt6cH6Dh/jzlV+ZRUkKAlt1O
         15xZlkVPoQXyEvhkmK8T9Vzg+TyZbeVndY+BQwDzWfljSQE7sw0xQ9HU0tsO81gzk3UY
         8wquAicLisTdNiJrfZkQ3HcOUJMrshX9sz6B5/7wUsyYMmCjlpwB2CMsstbEFYuXeUeD
         GRHArM8Pfbw4zA3op6GCYxnnoM1ldUfn75xbkEx7S7t4NX52zafZjYRybcc75z6PK0AV
         Fn3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Gr9jCqjK;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715975441; x=1716580241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zv1zUJ7WKCg5TFIPqWrlxmrmtCVm9toM7vXqGrwfvoc=;
        b=e8JPFMgEcTyEXayZVUzrxzVpSXVpTjT6G+p1cpOlRB5lyk6X47mwmjJxL/mlhwxQcj
         3WkfLbgXkIAy8H7+OcIst33owDQ35Te/4Rjaf3i9Nnu7+umndR2akZKatlkmIcjspMfL
         e76mopBuhIHfe3It5w7lhkMrFNnmrY9WhzuqS5VgqybvFCMRpatPMqoRSfeWiko3nAH1
         jJGAfFUYp343NdE9yHSOhoyJ58jj+SzV6AhSflbh3KrDGBAmiNbBIlODqkbMtg4wlFc0
         l02SKTlQlhoQueBFY5RefrtgSeFF6FPz9joKRzEEUHMMyBxEh2CG+0xepwSHGwbOReoV
         5Ehw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715975441; x=1716580241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zv1zUJ7WKCg5TFIPqWrlxmrmtCVm9toM7vXqGrwfvoc=;
        b=gf8BWL/9VW3JL0Rv5QmhOvm8iIVU8rZvJ1BmV4JHuRa5LWnWI8vFQ+/S1UW1wT4jw+
         GRkB3JBftVtQ8AcIzxS9b7DdQVb/t5Z7OC5V53h2kCavgsOWYJrrMQNf8pJMUaV/fwjU
         HGM9GXOpKkS/CrqxdVEcpE8mhnuILtUU36MfxgLskKUWS1uJRXgU1W2B7Hyeqf2aUMOy
         XV0nLBmUr7zRH4daHUHYEb8SW8NkDOtKDRMVTWjhoMX5kLriFqIdbpFbjXYaU1oEqVXI
         deMmezcofvH1ECspvs/nFKdAfuzZtKlJCYSsyxveE4thSUYovLtcv3rRdBRlItwqweTO
         6hTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBWnw6zs2hxCQc0YUfWTV1SX1u+5vAbmFUcFIyv0J7UwcmJ1OUcyVmjtKVUghb6UspOLZgbFA431qaJvOMawoeZT6WN0+UGg==
X-Gm-Message-State: AOJu0Yz+clTIzVQUyhWnlk3bbUm7B2sERFJR9aV5H8ojds+BXqz1B+a2
	x1m9O/fu3xSp+YOBJV33nlyE+eaiI3S43FDjDNtdow7kYowPM14K
X-Google-Smtp-Source: AGHT+IHPOjd0ElnkshTRSB+pDe37lW+wDGq79TwaRiPMazNPsRQnzuK13nCK52NinpqdJezQbP0opA==
X-Received: by 2002:a05:6a21:279a:b0:1af:d228:ca5b with SMTP id adf61e73a8af0-1afde0d5488mr23500359637.21.1715975441396;
        Fri, 17 May 2024 12:50:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d11:b0:6f4:59b9:ffa1 with SMTP id
 d2e1a72fcca58-6f4cb790dadls7919960b3a.2.-pod-prod-03-us; Fri, 17 May 2024
 12:50:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbSpgaiQ5r0CLtGiH/zx0WJVSMO7Pf0aYDO6rKWPkOE7K1cqjIOp+8dnvpx4qa6qaHyQFpcW9Db+y8YlMhtRs9yHFZmCHElm2+gA==
X-Received: by 2002:a05:6a20:9f88:b0:1b0:25b6:a72a with SMTP id adf61e73a8af0-1b025b6a92fmr7887376637.23.1715975440066;
        Fri, 17 May 2024 12:50:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715975440; cv=none;
        d=google.com; s=arc-20160816;
        b=gI9AtK63pIhB5QP7y7MzjJlgqex7ftuCMhQYjL1QSuyT/YBPEgdm+Q1s2PDMU5wvLV
         1a8MqlNrtBA4ySHflQrzmongOAAYFrI5nk5NsNitWtEukmYHu8yBiMTrT1S5+ybIuNLH
         dqWkqG30Xy4heCQzCPstrV2iG/1jI0jk7Xor2gs2KIUyqi8CGIz9ldP9AEBOEMkkn/qB
         FPEXiIV+9+2OcU2R+LCxjDONZXS5Z/Eipv93bDSTw6jGoS7DEZ/o+1P95Xvh+lEVIzXr
         BntSZ66lRFKZ6Baa+S6n+OcMt2XfDz0FSexlkOy/qlTUdmZsmpPj19JwXO9dy3FAkQGH
         M80w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1bxakr/BFBoeB5Z7JNvpJE420hX0IdbRkXcnTw/5V8o=;
        fh=qEG53hjPnFyeWlOkYxGMR5sEKHrKwGA2aCAkxFQqFsQ=;
        b=APOTCS8r5n/gOOSAUqkY824njE+mwIxqkOJqGS+JKmmea9isCvVW/r1h8AgyiLKQmB
         tmBAavtI/sXXPMh4a4RT/rIS2378QRWCMuiAz5y4aTToiFp1kSq+AW6e2ima8rQ3zpJa
         uVZAd9f5MaXiNA7EOJkxkfGMu2t43BKll3bPbhhLEyFX7xk36cUqSXQnYh6VvraNb1kz
         ZsNqJhUPeAA7o87Im/01sbneJAmDMZuRmPPBkxCqOcI20mTDFFXrvS5EyEtfqXUyfwch
         JkSO6if2OsGI6PwxrzS7EsG49hjlpJz6TGWBqOWOU7E7XVgTyyWISjplhS7usg/qT0il
         ZS/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Gr9jCqjK;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-657ee3aaef5si393107a12.0.2024.05.17.12.50.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 May 2024 12:50:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-yw1-f197.google.com (mail-yw1-f197.google.com
 [209.85.128.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-20-f_ch5LEnNFG5lXxMMWxvwQ-1; Fri, 17 May 2024 15:50:37 -0400
X-MC-Unique: f_ch5LEnNFG5lXxMMWxvwQ-1
Received: by mail-yw1-f197.google.com with SMTP id 00721157ae682-61d21cf3d3bso166849227b3.3
        for <kasan-dev@googlegroups.com>; Fri, 17 May 2024 12:50:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWA4DIVj6G/puJeDx96HCax69f3vHieASKD/iIbdaoXkgp8iZ0v6u2vijBaBr/WwVThyCLMX/razVFLKsxXA1zihJ6UrbnYh8fqPQ==
X-Received: by 2002:a05:690c:6401:b0:615:35e1:e512 with SMTP id 00721157ae682-622afdb76b9mr250824407b3.0.1715975437050;
        Fri, 17 May 2024 12:50:37 -0700 (PDT)
X-Received: by 2002:a05:690c:6401:b0:615:35e1:e512 with SMTP id
 00721157ae682-622afdb76b9mr250824237b3.0.1715975436677; Fri, 17 May 2024
 12:50:36 -0700 (PDT)
MIME-Version: 1.0
References: <20240517130118.759301-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240517130118.759301-1-andrey.konovalov@linux.dev>
From: Nico Pache <npache@redhat.com>
Date: Fri, 17 May 2024 13:50:10 -0600
Message-ID: <CAA1CXcAdG=OFkBzjPqr7M_kC7VZUdj-+vH_2W4UidfbQwfQbeA@mail.gmail.com>
Subject: Re: [PATCH] kasan, fortify: properly rename memintrinsics
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Erhard Furtner <erhard_f@mailbox.org>, Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: npache@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Gr9jCqjK;
       spf=pass (google.com: domain of npache@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Fri, May 17, 2024 at 7:02=E2=80=AFAM <andrey.konovalov@linux.dev> wrote:
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
> Closes: https://lore.kernel.org/all/20240501144156.17e65021@outsider.home=
/
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() funct=
ions")
> Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memi=
ntrinsics")
> Fixes: 36be5cba99f6 ("kasan: treat meminstrinsic as builtins in uninstrum=
ented files")
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you for fixing this !! The test no longer panics :)

Now that the test progresses I also see rcu_uaf failing.
    # rcu_uaf: EXPECTATION FAILED at mm/kasan/kasan_test.c:870
    KASAN failure expected in "call_rcu(&global_rcu_ptr->rcu,
rcu_uaf_reclaim); rcu_barrier()", but none occurred
    not ok 31 rcu_uaf
 I can open a new thread for that if you'd like.

Tested-by: Nico Pache <npache@redhat.com>
Acked-by: Nico Pache <npache@redhat.com>

> ---
>  include/linux/fortify-string.h | 22 ++++++++++++++++++----
>  1 file changed, 18 insertions(+), 4 deletions(-)
>
> diff --git a/include/linux/fortify-string.h b/include/linux/fortify-strin=
g.h
> index 85fc0e6f0f7f..bac010cfc42f 100644
> --- a/include/linux/fortify-string.h
> +++ b/include/linux/fortify-string.h
> @@ -75,17 +75,30 @@ void __write_overflow_field(size_t avail, size_t want=
ed) __compiletime_warning("
>         __ret;                                                  \
>  })
>
> -#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +#if defined(__SANITIZE_ADDRESS__)
> +
> +#if !defined(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) && !defined(CONFIG=
_GENERIC_ENTRY)
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) _=
_RENAME(memset);
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_=
t size) __RENAME(memmove);
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t=
 size) __RENAME(memcpy);
> +#elif defined(CONFIG_KASAN_GENERIC)
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) _=
_RENAME(__asan_memset);
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_=
t size) __RENAME(__asan_memmove);
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t=
 size) __RENAME(__asan_memcpy);
> +#else /* CONFIG_KASAN_SW_TAGS */
> +extern void *__underlying_memset(void *p, int c, __kernel_size_t size) _=
_RENAME(__hwasan_memset);
> +extern void *__underlying_memmove(void *p, const void *q, __kernel_size_=
t size) __RENAME(__hwasan_memmove);
> +extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t=
 size) __RENAME(__hwasan_memcpy);
> +#endif
> +
>  extern void *__underlying_memchr(const void *p, int c, __kernel_size_t s=
ize) __RENAME(memchr);
>  extern int __underlying_memcmp(const void *p, const void *q, __kernel_si=
ze_t size) __RENAME(memcmp);
> -extern void *__underlying_memcpy(void *p, const void *q, __kernel_size_t=
 size) __RENAME(memcpy);
> -extern void *__underlying_memmove(void *p, const void *q, __kernel_size_=
t size) __RENAME(memmove);
> -extern void *__underlying_memset(void *p, int c, __kernel_size_t size) _=
_RENAME(memset);
>  extern char *__underlying_strcat(char *p, const char *q) __RENAME(strcat=
);
>  extern char *__underlying_strcpy(char *p, const char *q) __RENAME(strcpy=
);
>  extern __kernel_size_t __underlying_strlen(const char *p) __RENAME(strle=
n);
>  extern char *__underlying_strncat(char *p, const char *q, __kernel_size_=
t count) __RENAME(strncat);
>  extern char *__underlying_strncpy(char *p, const char *q, __kernel_size_=
t size) __RENAME(strncpy);
> +
>  #else
>
>  #if defined(__SANITIZE_MEMORY__)
> @@ -110,6 +123,7 @@ extern char *__underlying_strncpy(char *p, const char=
 *q, __kernel_size_t size)
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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAA1CXcAdG%3DOFkBzjPqr7M_kC7VZUdj-%2BvH_2W4UidfbQwfQbeA%40mail.gm=
ail.com.
