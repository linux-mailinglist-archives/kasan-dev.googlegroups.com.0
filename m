Return-Path: <kasan-dev+bncBCSL7B6LWYHBBCUN7PBQMGQE4GPBWKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4529BB0CD72
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 01:00:28 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-456013b59c1sf28973865e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 16:00:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753138827; cv=pass;
        d=google.com; s=arc-20240605;
        b=kV0xp+Xe8iL5+NdhAcmIB2h9mhShp32mwc50t8+4si2PCzTFkgV+wg4P5jdW2ly271
         IU7sGdAXrEEOFeefUtZpJsqQzuW+08cwap5NtcPef3khZ2Ctdbjnl2lbHAZFA25mrLGY
         wUZWyceDvXhbSUYTNSmYsFyqIntDyYpHJwd5Y/cnh19tg/KILv4cs9bzdEMd/k4zQax5
         9fVq6uw3v/C1d7ijqMDJF8RlACiYQlturHO5AfIT1F9qNPIKAj2Tl4SFirzzYJ0d0uq8
         7ouCmlhQdGCpR+DJTmkagFwpY4Tl1oljzb8zySBNyFVOs0ALh4usgxkr9h7pvn65e3dt
         0KlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=ch0EsLAvR/4n2Gc6d1NlzRx+3RXVl8QSw2i49GgTdDI=;
        fh=IYGGg6NbSHk7kvyUG2Dhj4jPzMOTOfCkkZOzLdjDWZk=;
        b=G5vz8y0NoygcU5ZtMlD4XQShZUiNPbUDUK8sgENoe8gvy6+wkczv79nAFzqC+8vRdG
         A67S/K8yk0pwGGvUqn4zqsZszV6SamoGXZaUnJjkjDK/0afQHcaqMA9sLUUl9UTWFMUU
         bgeqFdZy4hCLvk1s80nB+vSNDvRw/oGiDsWeqF7BiLBHmhLlr777132mNhX6FJK+CgzJ
         +5TqmDDwRThvuch6yb+Ps6PRtleuHRVByx5shsXFoNBP4RKYZY9R87FCbkCi4ag+zLuF
         7GuifiOBHYu9x8S3Y8CJ29cTSlcYVGjDe8JC9JC9MQBfLMQ7j6FO02JZLdIJ6O32yxkY
         isJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nsVMWLPi;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753138827; x=1753743627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ch0EsLAvR/4n2Gc6d1NlzRx+3RXVl8QSw2i49GgTdDI=;
        b=nyvGm1Ek97OuUZv2YYXOgC/tHEfT1+UKU5HezHCoxs6MZX7NIFsSKCWiTiQGmWJOeD
         dbKpVaE5xNELlg/otILP1xO+QRi5E5jcKOdjj9EVl5ff/SIhp1bSaWOyVHf0UhMxYYUA
         RITR6DzMJuYhJjFnK9JwdUwhzNnWISndE4EsRvY/e068JzoXad5voKGX6bdv6zoHDZqx
         trULOQsYmt1//GLx1Dt8aSqtgCLxbknQCXaJrWfNb3t28oBgG7rwbXPNdDFIyzsngAKC
         fTf2OTzvFq7g1Mb4v81qvk9PyDPOsK1JiE6MCbkVWo20t0JSuw+xgkfQBQCwpLDKe5Kk
         VfOw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753138827; x=1753743627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ch0EsLAvR/4n2Gc6d1NlzRx+3RXVl8QSw2i49GgTdDI=;
        b=JofSSMXcO40bPETklRHzkarTr7AH/3YeE2VrSUs4WKiHATpoyntWvCe2O09VK7/9+x
         yJ8kmQyxE4aAgZr+LZPtHQ6efO+J7dVLoy4UrwG4cyX2+jKFTt1vAz+GshByC2MtCKnH
         wERLal380nuSUu7W6pMGjUgQiY7e6uWlZHNsd5OTbS3Z0A62Rqem99IZ7S8MeNOjvLb7
         Cn2Jfe7axay6q/pTmdCOAhY/3ajG6Tct3zRQhABiUrI6Dlh8/UCkp6ypHYF9EmZ24OK8
         kAn6mlrgX1Dz7RxSWGcKSdBLQT97KrHRjNUdZhBlJn2l2F0J7+MIPFgiKNIRdgm7kExm
         aigQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753138827; x=1753743627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ch0EsLAvR/4n2Gc6d1NlzRx+3RXVl8QSw2i49GgTdDI=;
        b=SzI3+cLwPQrG6uIi+GFf7wxLtQRGVUi0eky3NEV4PDgG8+/ML0JAJSAUPU3e+WernL
         g+3fo82T0Y14c0nZY1wIY4ufpaTvMX/ruP3mnKNBGfljXKaDMaU/WnRrbXLyT9AKTHcg
         iBQYuMt7Z08+F/CojK7jpp2HdXpTl8VDFpdy06tNbCpQPvpmE7O3uxksTh5hI05KZNkl
         WvI1gciV/nBn/2DOlF0KAl1Y+Y7CALZXTQnwb+KlZ+4J7c5MiFPcn8Iw/bNeOqP8WxBc
         1V+aJyM54hf7S/bSE+4zRNX44wDDiDnECnzRRoiTzQP8uKCUNKuWYgPRb+LWyZhiH/q5
         ZzkA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXMSdFpOnOjY/Oj6wpqvSRLkQ0J7EPWZGmQlaRSReQoRh6eeCgM62pUVlGO7z5Jyi+ezi7PEA==@lfdr.de
X-Gm-Message-State: AOJu0YzmICNAt3LF/LtitVf8dio4MJi43qL7/zqVs6w2CUlhwvv/2vHR
	57aHC1CdF85G5zByaNowZDqXTg+NxrE4pvNawZessg9Goawbt9ZttMaf
X-Google-Smtp-Source: AGHT+IFO/4VnQH4rx2YWV6JRoS3TUNxUC7fAt7nJTmlIzGNd6twXWbJv+se6aSYDgnrzz0D+rhNlxA==
X-Received: by 2002:a05:6000:2087:b0:3a6:e1e7:2a88 with SMTP id ffacd0b85a97d-3b60e518b33mr19470638f8f.57.1753138827049;
        Mon, 21 Jul 2025 16:00:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfgIbVm8yWWZzqMZNkuX3oEJTB8rfcDTrzDFaSCb3NZQw==
Received: by 2002:a05:600c:1c25:b0:456:241d:50d0 with SMTP id
 5b1f17b1804b1-456341b19eels29917735e9.2.-pod-prod-07-eu; Mon, 21 Jul 2025
 16:00:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWh/Jk/1tn1ORhw0AZE3V5LYjxELafbd9VfpsQTF+f6wtTnYX946V2bWFzEcY8Lkgnfa/AL9q4MXBQ=@googlegroups.com
X-Received: by 2002:a05:600c:4ed3:b0:456:1a69:94fb with SMTP id 5b1f17b1804b1-4562e33d914mr208359625e9.13.1753138824008;
        Mon, 21 Jul 2025 16:00:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753138824; cv=none;
        d=google.com; s=arc-20240605;
        b=fJ5ffslB7KSpbAE2ESwR3WInUnwyOtTYP1hHZTe9GpvPog5AH/XvGK34UfeHnf+7Gf
         C1/F6J98iaLh5fYO8hh79MUdvZJxwjzi9pk0OODSXwXqXjKeglMhVJcHwAkxU5vLzL7X
         L9Z7vXozwgfJTKOP2ZSeGm8RofXOHminc5Wo9tVawI4ZN05RHzrb8FTu0p/nulFH9JhW
         JP34D9KEkXCfVvpMXuo1C9WU7FQPZ3YwtfTs6X7K0fZ0Ioxu0nFTbYfKMybSy8fgcILz
         iS5XxkFzfPh+yxk84/hrT3NwH6HCS6SPcvT36gia88Mnbq9HF31jEsiAMmzOCIyQpSt0
         GkeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=I50g8CBYTAJgx5jeL63ocp0XmC4ojzYZYl9cwyXAxL0=;
        fh=e7rrSG0s4sj80q+lrXWWnwAt8T6npsN3x4q6BF0e2wI=;
        b=brczTekgQiiaN8DLXcGkQeFgsQrOq0Y/2VhrINcqUgCy6BMURbvOUsZCEK5y9MF6kB
         SixP0NBHjPbatoX0R7d3lACIvsn7rTHkT1ola0qZunu64TaVQOWQNq/TVNg18spvjXJM
         DISXc/oBjztESJC6o29hXXbD1BrkVJR7nDHNKQFub0ZroY0be1g+8e4GqabR5bfU0Nl0
         +47jzHKOrrXTqTuF9aEtNzeF0QX/Qd5ZiSPfReScbSiKd9m5efHYRq84953WOUrv11bA
         NJsXlK3lKv+V9dj9ZTN9DyluoxvaFKZKCM9rJ6pdbEUdoLr1x3Zix6LP1cla4o3n4bXo
         k2AQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nsVMWLPi;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4564a28d996si1107775e9.1.2025.07.21.16.00.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:00:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id a640c23a62f3a-ae3ead39d72so86729166b.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Jul 2025 16:00:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVTcw2mhu/qy4wbuDvHnYYoam77Y9Uf98u80aUIfA6UHW+lFaaJTe2IHSVEBQV5yk73i1qYnEzF194=@googlegroups.com
X-Gm-Gg: ASbGnctK7RWWZ8KO7hknVyFsdEkviK0cOnSsn15gmSfb4A6gPBaBK1wPz3fRkyyO3Gx
	eRcM87ejWbABRcE29pBx8fefWIdL0PK/Q0yg6rkuWPJFQ91biD5AHcCw1WPivekqziqrDH3n3YU
	Y3nZjDQzPxo9yqtyuK5ih6N23ITP7KL6yEyYgRwOVeIEP4d2x/k5MlVXskcqlrIqu+Ov0jU7SkI
	Kt1ubJSr1T+qmU+KJHFaoGY9e/KWgkgdYih94dnSEiqzdwcJ1CHf5D7PJW4iTAO+eyITtM6JP7+
	h/xYMxAE7OErfkvpNicjrai98Z60jjerJ8CqLJiNpFxXsgA0nhfi54WNjx+teq2X30pkPiuSXFz
	eG132HbG/BahOeDILKtaHdxd8XX4BDcg9mmQoBnibk0REQMVBP7x4wGyvGXDu7AQhFnpH
X-Received: by 2002:a17:907:db15:b0:ad8:882e:38a with SMTP id a640c23a62f3a-ae9c9b8e572mr853708966b.14.1753138823178;
        Mon, 21 Jul 2025 16:00:23 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-142-142.dynamic.sbb.rs. [94.189.142.142])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-aec6c7d8357sm753164466b.52.2025.07.21.16.00.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:00:22 -0700 (PDT)
Message-ID: <85de2e1f-a787-4862-87e4-2681e749cef0@gmail.com>
Date: Tue, 22 Jul 2025 01:00:03 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 08/12] kasan/um: select ARCH_DEFER_KASAN and call
 kasan_init_generic
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-9-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250717142732.292822-9-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nsVMWLPi;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::62d
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
> UserMode Linux needs deferred KASAN initialization as it has a custom
> kasan_arch_is_ready() implementation that tracks shadow memory readiness
> via the kasan_um_is_ready flag.
> 
> Select ARCH_DEFER_KASAN to enable the unified static key mechanism
> for runtime KASAN control. Call kasan_init_generic() which handles
> Generic KASAN initialization and enables the static key.
> 
> Delete the key kasan_um_is_ready in favor of the unified kasan_enabled()
> interface.
> 
> Note that kasan_init_generic has __init macro, which is called by
> kasan_init() which is not marked with __init in arch/um code.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> Changes in v3:
> - Added CONFIG_ARCH_DEFER_KASAN selection for proper runtime control
> ---
>  arch/um/Kconfig             | 1 +
>  arch/um/include/asm/kasan.h | 5 -----
>  arch/um/kernel/mem.c        | 4 ++--
>  3 files changed, 3 insertions(+), 7 deletions(-)
> 
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index f08e8a7fac9..fd6d78bba52 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -8,6 +8,7 @@ config UML
>  	select ARCH_WANTS_DYNAMIC_TASK_STRUCT
>  	select ARCH_HAS_CPU_FINALIZE_INIT
>  	select ARCH_HAS_FORTIFY_SOURCE
> +	select ARCH_DEFER_KASAN
>  	select ARCH_HAS_GCOV_PROFILE_ALL
>  	select ARCH_HAS_KCOV
>  	select ARCH_HAS_STRNCPY_FROM_USER
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> index f97bb1f7b85..81bcdc0f962 100644
> --- a/arch/um/include/asm/kasan.h
> +++ b/arch/um/include/asm/kasan.h
> @@ -24,11 +24,6 @@
>  
>  #ifdef CONFIG_KASAN
>  void kasan_init(void);
> -extern int kasan_um_is_ready;
> -
> -#ifdef CONFIG_STATIC_LINK
> -#define kasan_arch_is_ready() (kasan_um_is_ready)
> -#endif
>  #else
>  static inline void kasan_init(void) { }
>  #endif /* CONFIG_KASAN */
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 76bec7de81b..058cb70e330 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -21,9 +21,9 @@
>  #include <os.h>
>  #include <um_malloc.h>
>  #include <linux/sched/task.h>
> +#include <linux/kasan.h>
>  
>  #ifdef CONFIG_KASAN
> -int kasan_um_is_ready;
>  void kasan_init(void)
>  {
>  	/*
> @@ -32,7 +32,7 @@ void kasan_init(void)
>  	 */
>  	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
>  	init_task.kasan_depth = 0;
> -	kasan_um_is_ready = true;
> +	kasan_init_generic();

I think this runs before jump_label_init(), and static keys shouldn't be switched before that.>  }
>  
>  static void (*kasan_init_ptr)(void)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/85de2e1f-a787-4862-87e4-2681e749cef0%40gmail.com.
