Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBNWWY3AQMGQEJDF4IYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id DC61BAC2F51
	for <lists+kasan-dev@lfdr.de>; Sat, 24 May 2025 13:19:19 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-494a0afbbfbsf31093271cf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 24 May 2025 04:19:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748085558; cv=pass;
        d=google.com; s=arc-20240605;
        b=kURYUwPZsF1OCnIAW1kTBUcixyZAt1Lqf1urkgMG/VIdcG5aahbtGG+CpEpvJlo6pn
         VVGYZh6hT5mXT4YrzQwa2tTklldXTzm5+DqFUBfIwFHVaZaJh8tOE+WnB8mzXxAqGnWK
         9nVedj9d4OUMuuW4HHspQ/6PRJwNVvtvKzau2pk7EREuxDXsFMgnmjAyHfWNhoCMuWTG
         MLMqjiFMhcR+17RHEjxKVHW7oXKErZD+4L/TZc5WbThbGJMgBXhwXsSpX+DREGUaSGZ8
         FPR0t4/5h26vT2+iIZR6sPwUt28Q56ccN+GKyffczmEpxlwkCjderLHvMh1KAm/+GnIE
         0A7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:message-id
         :date:in-reply-to:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=eCpy6ERKJ58I9RfLMhA7XF3pN99iDdxL7Aeej/QaZPU=;
        fh=s5/NNf4b3wN8PcnCKM3F/KouZr355b0kbNbtw9BCkiM=;
        b=XaqPlx4v0lkdCu57mCWTeSw8iIgCi7HolAwAoGHoca+q3Zw/5Qv+JqFl60xPIyT7MV
         IlCSCpcJqqzSx5XKnYuKA9c/0DTiAZf0N2UA9TwmMS0Dq+g46mwnVVgdVdwzqTlJrKFJ
         4pk09s94Y+XRV4Zd+UlDOVCz/zVOMskzbh3Ctg2szVk1epufkppPY+QzZAL35Sj6S6gS
         tqdF3fGU184JC5IAQ4Lv5zjmJY/B2/VmKSB3UT89ICGIG4WEY8U8Mz8kJS1I0wsZUCdq
         L2lPjR24ad0UjqpMbLvblqzzxEaAHk43Q1Ab6KwSqWdtEmU2DwjmAAzGKjTg9h0Ei0I5
         /pWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Yrmkjtbr;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748085558; x=1748690358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eCpy6ERKJ58I9RfLMhA7XF3pN99iDdxL7Aeej/QaZPU=;
        b=b37ynaaBYubM6bDmrRqP9rWeZwi67ZmA3N6Kp9ZRmYOHicnepYsiycKw23KXadYoDR
         XCqVe/NNr3oFGh3kV4OMtLfPwYxxLqQSRkSmDXMtMJ3MwL0CL27UZCMnQc7WqOLJZl8s
         T9cZGt2/q+66rDHbqIgmPbVnbZ5+8yoqZKYzyvU9tSf3C3A6XdHa1v3MpjGj8vRL5veY
         BoOGd+2qxsJlTMWpiWvOStM2WgQ04WMnn7BaMH/GnDJbEJUKdAFSDZDkIReN2bRoc+ME
         iXz1hSejzUjv0VCca8oGwh2NGoAsi3d68vw9MoUyl6UbWYE/c6uNd2r0awoFiIYm8sJH
         H2bA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1748085558; x=1748690358; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eCpy6ERKJ58I9RfLMhA7XF3pN99iDdxL7Aeej/QaZPU=;
        b=KWIFji7c/akSTqvk8wp/m4Kby6k47JbvcIKWcKjwLQpLwui13HvjCdLu4Jzu0o7lvL
         k6CeY7/1eWORnBF0NORSBvQg5J1m+h6OTlh09hY0dL62KNoNS543737aU3LOXuI1eShD
         ly7fsOKxwB7hZo2N4wnbU6b3yaU8YEJ9BGnwBqSco/iajuPS9keu3Bc6NeSwcSpLptLy
         VbeMCv2JmuiOTDRHay6xKPcz6+KYm2/cQRhvAxE185wsDxFF6OL7BSlHGqUb6+lMyfkL
         X1WsV9Gmit6k6CsQjGpir/tqyrg54FNG8tDDYECbJqOQGFF1AilQD2WKMjNNL+YUSqbv
         rTEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748085558; x=1748690358;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:date:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eCpy6ERKJ58I9RfLMhA7XF3pN99iDdxL7Aeej/QaZPU=;
        b=klt7aF45XAvM+AmH0+P54kXxSCWaXr9moQuC2NioYNAQVXrXSgZO1FHLisFY9IIYve
         6xoZi8nLmfvJKvmrIHm7qogNFLnhGii5YLzcYG8vrDNAftQ43nlger8W48X7N/JBdBOw
         WLq4XL6EgFqjvCfSEKWgrs0QN4OQjOY8XPAxhKFAgfHs5qQWUUmRGdKDXO7jWJbXhGo3
         63A/EsVw09jdyivX83yA0wjJMrVW3TwObfcAvSs3fyEzf15MgiveMUcSZWbO2ktWMrRT
         EAK8/MngERLD97adGanWwQ8Wld/6e8Aoanp13rSrXyK5rQ0HtEmobS7VWQrjFxcjRzqN
         /tyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzpnbt7VcoRe44bQ6gjoJDT+rPDm2ZaSP2fYzHbWHZ56RPhpbMjuzAFckiBzCUS0JBRCgFFA==@lfdr.de
X-Gm-Message-State: AOJu0YyVGlZ17FnkLvhjk9zcseA1wSQsVHncqzbkgSH+tYY7DW0pr5RB
	8E30prBwqFe7Du7Lczxn5nqoLng1x+jFEGjzqOBhnfoq2EqLXKQryNse
X-Google-Smtp-Source: AGHT+IFivUxf5hVBu5XTjiUak6wMs5WZqidbKZL6AGiNCJcwMffh8bxo0O3HgvT9jjx+Fj9zpOsdIA==
X-Received: by 2002:ac8:5049:0:b0:49e:815:b6a8 with SMTP id d75a77b69052e-49e0815b6famr57653991cf.1.1748085558442;
        Sat, 24 May 2025 04:19:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFPKrjNBY1y4Y18+4GQTWIl+zAmrqU0y7ZAzfQ5XZGL+A==
Received: by 2002:ac8:5053:0:b0:476:6eec:3aa5 with SMTP id d75a77b69052e-49f2f264ed6ls10100731cf.0.-pod-prod-00-us;
 Sat, 24 May 2025 04:19:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVVpAZC9SjF4wY9/gD6cx5w7Icx9AZuzN0cJoXLQGn/xYxi47vyaNuVb3BjznEYEfBsFX/ByT1SKXo=@googlegroups.com
X-Received: by 2002:a05:620a:4441:b0:7cd:1afa:81b3 with SMTP id af79cd13be357-7ceec49d8c7mr356293185a.19.1748085557334;
        Sat, 24 May 2025 04:19:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748085557; cv=none;
        d=google.com; s=arc-20240605;
        b=Jz1qs/lDO+lp/b6/MTCl6O2T3f3U9mOuK6Em/0pOQLXK/fDH1zaHJ5kudiJemdAq0I
         PvyCqgL85bbZT6AxUl/7se1bPR6mBw3w+IjQ/lYdLFDahsf9nAacRrMxdF9Y2U6vwVss
         yeR1bxuGrBaVAw3PokpNXPJbO3Rwfj3BOfh186wrz4JDBRwD+Vk+rOx+Z7rlocKXFO4u
         DJn/fG1/xVKL6fqKztuA7QNlqu8jQ+iA8FvJu+EB4BYQAcLEuXStLGrLzuCeEJbZziuS
         TQwZX+4BYmUSnH2rFL5ScGZQugGDhpYrUXUd2czB5Z5WXT+kgT5KRFpa8msEaZGSoHIT
         G8zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:date:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=rScpXVbASUqjAgnv8asCUXuGu69m7xK2h2FjiRqoUxs=;
        fh=clK7u6NH2f7+JwMsUCPFUbR3mrBG5AA6HsM8wvE15wI=;
        b=F/hK2NNF740rd99lOyFDO2DpLz/f2u1fYXII6KIzRh87wo5deGAEoh4EUUmWklMWDG
         3FHZ0nsnmkBY/PGJ4mkXdqwZyGsuy7wsdQ/N0TeCmBq2bE3tXo7xLzZ5kh//iPBEbqMP
         x7HC+0htM+01/NYqwecGZuu9tSv/EwGGTHUHiFMtTDn5YyxZA7LqN/q3YjuquHQ7F2Y2
         UO2dGfJ8h7CUCgEdf+Ouv1m9FXLTOqD3jpBVY33v+clm2sNFa39f4dSxxlKGa/ZTHWC9
         x5lDTOsOk4sBxu5834kSZozg0ML4pGdfA3smPYOP80dHgVpXVvcIGqGkFebNdo5FSa0w
         lE3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Yrmkjtbr;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7cd467c4081si42829285a.2.2025.05.24.04.19.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 May 2025 04:19:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-7399838db7fso605975b3a.0
        for <kasan-dev@googlegroups.com>; Sat, 24 May 2025 04:19:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWieGh1oXEXmsUNTajiJ0leKzLaVb5Ac91p4LHdyTXA8qIUcG5VbcfrC3ks6twsZSef7sB4aclF/so=@googlegroups.com
X-Gm-Gg: ASbGncvX2oerJxQLP/OirlWJyLSJYOQFLra3RgrQwUErd17SmmAra9854mQSiEg5PRg
	2XGGdOo6Kk/LDOuZGFne5hNTIxCzSsP2H4AEYbvwQ8nGG1M0qR1A09ywhbhNEhHCNUreAeRsPE/
	ilJHrZ01ayQqtXVr2qBuFQKip9sJ4EOXcR1qXTVJqIWCSeW172IjlbvcmAjGz7pHvLFehFCz/n9
	Vtip0ExJqqS/hiJulJPcsaU//BoXOPXM0BtvFrCDj+2EuIhQ8EMxsA00RHDPjSs9LlgQH0Bfsj3
	iF4XTI2f2VbQ5nNRkGCh++9K2Ao1OAv8xyabVaC9FPYodrL0yaEUSrQ=
X-Received: by 2002:a05:6a00:1903:b0:73e:2367:c914 with SMTP id d2e1a72fcca58-745fe068d61mr3795551b3a.7.1748085556260;
        Sat, 24 May 2025 04:19:16 -0700 (PDT)
Received: from dw-tp ([49.205.218.89])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-742a96dfacesm14024380b3a.5.2025.05.24.04.19.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 May 2025 04:19:15 -0700 (PDT)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: Kees Cook <kees@kernel.org>, Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>, Madhavan Srinivasan <maddy@linux.ibm.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Naveen N Rao <naveen@kernel.org>, 
	"Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linuxppc-dev@lists.ozlabs.org, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, x86@kernel.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org, 
	llvm@lists.linux.dev
Subject: Re: [PATCH v2 08/14] powerpc: Handle KCOV __init vs inline mismatches
In-Reply-To: <20250523043935.2009972-8-kees@kernel.org>
Date: Sat, 24 May 2025 16:13:02 +0530
Message-ID: <87jz662ssp.fsf@gmail.com>
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-8-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Yrmkjtbr;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Kees Cook <kees@kernel.org> writes:

> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> s390 this requires forcing a couple functions to be inline with
> __always_inline.
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: Naveen N Rao <naveen@kernel.org>
> Cc: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
> Cc: "Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: <linuxppc-dev@lists.ozlabs.org>
> ---
>  arch/powerpc/mm/book3s64/hash_utils.c    | 2 +-
>  arch/powerpc/mm/book3s64/radix_pgtable.c | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
> index 5158aefe4873..93f1e1eb5ea6 100644
> --- a/arch/powerpc/mm/book3s64/hash_utils.c
> +++ b/arch/powerpc/mm/book3s64/hash_utils.c
> @@ -409,7 +409,7 @@ static DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
>  
>  static phys_addr_t kfence_pool;
>  
> -static inline void hash_kfence_alloc_pool(void)
> +static __always_inline void hash_kfence_alloc_pool(void)
>  {
>  	if (!kfence_early_init_enabled())
>  		goto err;
> diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
> index 9f764bc42b8c..3238e9ed46b5 100644
> --- a/arch/powerpc/mm/book3s64/radix_pgtable.c
> +++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
> @@ -363,7 +363,7 @@ static int __meminit create_physical_mapping(unsigned long start,
>  }
>  
>  #ifdef CONFIG_KFENCE
> -static inline phys_addr_t alloc_kfence_pool(void)
> +static __always_inline phys_addr_t alloc_kfence_pool(void)
>  {
>  	phys_addr_t kfence_pool;
>  

I remember seeing a warning msg around .init.text section. Let me dig
that...

... Here it is: https://lore.kernel.org/oe-kbuild-all/202504190552.mnFGs5sj-lkp@intel.com/

I am not sure why it only complains for hash_debug_pagealloc_alloc_slots().
I believe there should me more functions to mark with __init here.
Anyways, here is the patch of what I had in mind.. I am not a compiler expert,
so please let me know your thoughts on this.

-ritesh


From 59d64dc0014ccb4ae13ed08ab596738628ee23b1 Mon Sep 17 00:00:00 2001
Message-Id: <59d64dc0014ccb4ae13ed08ab596738628ee23b1.1748084756.git.ritesh.list@gmail.com>
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Date: Sat, 24 May 2025 16:14:08 +0530
Subject: [RFC] powerpc/mm/book3s64: Move few kfence & debug_pagealloc
 related calls to __init section

Move few kfence and debug_pagealloc related functions in hash_utils.c
and radix_pgtable.c to __init sections since these are only invoked once
by an __init function during system initialization.

i.e.
- hash_debug_pagealloc_alloc_slots()
- hash_kfence_alloc_pool()
- hash_kfence_map_pool()
  The above 3 functions only gets called by __init htab_initialize().

- alloc_kfence_pool()
- map_kfence_pool()
  The above 2 functions only gets called by __init radix_init_pgtable()

This should also help fix warning msgs like:

>> WARNING: modpost: vmlinux: section mismatch in reference:
hash_debug_pagealloc_alloc_slots+0xb0 (section: .text) ->
memblock_alloc_try_nid (section: .init.text)

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202504190552.mnFGs5sj-lkp@intel.com/
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c    | 6 +++---
 arch/powerpc/mm/book3s64/radix_pgtable.c | 4 ++--
 2 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 5158aefe4873..4693c464fc5a 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -343,7 +343,7 @@ static inline bool hash_supports_debug_pagealloc(void)
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
-static void hash_debug_pagealloc_alloc_slots(void)
+static __init void hash_debug_pagealloc_alloc_slots(void)
 {
 	if (!hash_supports_debug_pagealloc())
 		return;
@@ -409,7 +409,7 @@ static DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
 
 static phys_addr_t kfence_pool;
 
-static inline void hash_kfence_alloc_pool(void)
+static __init void hash_kfence_alloc_pool(void)
 {
 	if (!kfence_early_init_enabled())
 		goto err;
@@ -445,7 +445,7 @@ static inline void hash_kfence_alloc_pool(void)
 	disable_kfence();
 }
 
-static inline void hash_kfence_map_pool(void)
+static __init void hash_kfence_map_pool(void)
 {
 	unsigned long kfence_pool_start, kfence_pool_end;
 	unsigned long prot = pgprot_val(PAGE_KERNEL);
diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
index 311e2112d782..ed226ee1569a 100644
--- a/arch/powerpc/mm/book3s64/radix_pgtable.c
+++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
@@ -363,7 +363,7 @@ static int __meminit create_physical_mapping(unsigned long start,
 }
 
 #ifdef CONFIG_KFENCE
-static inline phys_addr_t alloc_kfence_pool(void)
+static __init phys_addr_t alloc_kfence_pool(void)
 {
 	phys_addr_t kfence_pool;
 
@@ -393,7 +393,7 @@ static inline phys_addr_t alloc_kfence_pool(void)
 	return 0;
 }
 
-static inline void map_kfence_pool(phys_addr_t kfence_pool)
+static __init void map_kfence_pool(phys_addr_t kfence_pool)
 {
 	if (!kfence_pool)
 		return;
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87jz662ssp.fsf%40gmail.com.
