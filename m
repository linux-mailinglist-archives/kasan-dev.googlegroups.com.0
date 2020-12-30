Return-Path: <kasan-dev+bncBAABBPUYWL7QKGQE5DLCWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id DCD5E2E79EA
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Dec 2020 15:18:38 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id m67sf10370260lfd.6
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Dec 2020 06:18:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609337918; cv=pass;
        d=google.com; s=arc-20160816;
        b=GD/JQGjcsMdvwcDplujCL2UfUEG6bKmHaGgX2grlLyoLlOGsOMQ+qhW0DaXiPOOXsd
         Z/IjsvHevLsHTEFPKAN36YCb0tdie8biTtAG9naLiaxHW2JaJjhAZ3uCpUebKyT4mRhH
         Kb6YqFArIVa7eiIatfisZG1TQWtsz1QwlwetBky5oD1XqZdhwYvT5N0HxvnnAIMCTnC5
         UZvilgr3eAYzMsxzJUUicEUiWneUT4uei3xYCH5ldw6UEvTlM7pZsZzuB4TsCNXVY3fU
         DlgYoRTEVR6yzCyzl6oU6Qw0RTSS5MfosY64Jbk5VTHA/wyJR18i/YkjGxD1R51D9auS
         Eoyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=nxkZhrGK2nDRa2uAj05DflrTGeYin/kwm8B7+C5UO6Y=;
        b=ROrAY5ytJpObjEFDGnxnTnfPjlllpjHGi2M3GouGArr45Jq3bLIKotDFF/QV+CP17N
         mq8feb+ApmxEx7wSeCikSJVKvRFRZGTG35ykhbjTjepphFcepL3J7BkzN9mZiIYBV0zT
         3vq6HUBlEeengc628GtiXrKntUGjWY56HPBuD7E2CQ98oelqp8SnyMZ452ek8UiNhIgG
         +OTKTzB8A5CIZOwxkBp4vGsFhIt0q3/eMPRiYbLqpKFWD/3+jDtk3gxWfjFtRHkGwS/z
         pD/Oz8Xd76PUlTy7Xabz0maxjoLRPHil0lf7oKwhkBP7jTq3txzIYPbfNKjvDFP+cJIl
         svaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a.fatoum@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nxkZhrGK2nDRa2uAj05DflrTGeYin/kwm8B7+C5UO6Y=;
        b=J3aZ+rQ7Y5fUyzKjStOYg/0H7cjMB3F+/2iCNVuwZg2lWDWFU/Ju2Lo1RXZSJliqnX
         5LC9Zf0/aSzQ5hVO04COOKKVL+kv505Je8fCwnjsQf/9WqqSaBEd4AZ7yI8AHDqa1XOl
         MJXcvTz7/b0DsfLYwYIive1X35lF3ue506nc6l/O9COESEX8/Os3aLF10PMxNDY4nXKZ
         FTO2djE2GIsAPkQx+HT5FUrAtxaDGdUbhjj1O0z/PdXWmH0xN6//HegdK2FlA3aYtXLB
         9hHfZ0a9UT4eRPFPFdIcdk5+eaC1nEap5UdfsRFO4AAIuomnPJeGNSH0jYtShFpMc2X+
         bbRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nxkZhrGK2nDRa2uAj05DflrTGeYin/kwm8B7+C5UO6Y=;
        b=ZLK1sbZDQxtpQzGMGu0Bye6HuQm1AyDhrNXcEHo5JBuOXmdtPr0UbTfChAJmeBKwFF
         Ck+lEQt13gearO7ZSPd0QMENRozm2TP+DO0HMmlflqIdqOJuzRAdOdnl78jsNXIa0hGv
         /xFrq2AUm16kyFwNFUqA57yASy9uJOrfi2FviaFWFbTLcOELg3kCiiiwUfCJndvr4ZpN
         OpZ9pYBVvs7JWx9w1y/fmwTM0HH8G1jd51kSZeQi1lsvW+btMnoxdUpWOMZqFfwxhbkI
         vfk23OgSEHTNgp5Gg6K8OHodLK0W5hNumpiLbYdbG7dT5Ytm13vGGCWzrBwMmMucotme
         mdCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532oRCfNPhfXGwo6f0VdRKkXfYQKnKOF/qdivLqfjrIV/2Opw2AH
	3F3mwfPdq05cPF5nSlPkecg=
X-Google-Smtp-Source: ABdhPJw/mOotWYLAuZ1ww9dM8xbMJ7eEvDgZtrUmpkTX38884cAZVS8raLxF3XZKm8IZj7psLqnK3w==
X-Received: by 2002:a05:651c:1027:: with SMTP id w7mr25084763ljm.297.1609337918367;
        Wed, 30 Dec 2020 06:18:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10d4:: with SMTP id k20ls2392189lfg.3.gmail; Wed,
 30 Dec 2020 06:18:37 -0800 (PST)
X-Received: by 2002:ac2:5199:: with SMTP id u25mr21943820lfi.438.1609337917508;
        Wed, 30 Dec 2020 06:18:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609337917; cv=none;
        d=google.com; s=arc-20160816;
        b=AhuH8NGhAr/BJ7Xc91vIOp33wzpxNZdgT387f1Inm79pHFQiHKWhPxxkB5jQ2cE6cw
         3ZzXdfAXNFqeYgrxjzwi2tJ2tP9f9GoBMiSYD+15CA90AS3kSVLCwP+tn4O7cWEhkzM/
         uLH3geYTaHWy6klVzJFohpIL1oVkQplvtD0emJogvuFXAYfHmKP4t+4UQGQFfsLIZB71
         U+mn3mx8vzd6eFgZrUBXpIxg9CV03VWHRBATF7yHmsyzWMnzJpmAy4lI6Q79glrcI907
         VHiJuDUNjbkquB/gGYQ/PReHyN6z0s0IwKaWkLYKUBIWVM5xEvasQd3EHI0ZBVDv4fpo
         pYwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=x1C1qcuXjYsDZ4AEgKpLs6Zp+QxclLh0oWlSXg6bVac=;
        b=A7igM5ERk2D5lmbkks/UXVQrX67+45KLj2a63SYQfjBRDc6QTgSdMXE9MVdxyhvb+A
         OqRk/4HQ3sRjBGXwyeNhR8eL/AFukyzCKz7TqlpJTiLdzWuTH6xEtgXgcNfvY/WaWcZh
         EH5QCCaD8sliAAuI1nJeQyXXo24t3TSt+odxhFa+txAVyB1hT6OJD4HAx3dWBCq3Ku6W
         0BkJD4nK8ZzlzK2UTZdG2FY2qnUt5pWDxiQGv2Magl41ziH61tknGGPElzxVZY8UA5Ka
         lHQgmOxL21ffzW/7uuaUx0pC9yB8SKNPFyMMIzdRVDrBKo623DnqIiJMttMGdXpizfaL
         AEAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a.fatoum@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id 70si1286900lfo.4.2020.12.30.06.18.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Dec 2020 06:18:37 -0800 (PST)
Received-SPF: pass (google.com: domain of a.fatoum@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from gallifrey.ext.pengutronix.de ([2001:67c:670:201:5054:ff:fe8d:eefb] helo=[IPv6:::1])
	by metis.ext.pengutronix.de with esmtp (Exim 4.92)
	(envelope-from <a.fatoum@pengutronix.de>)
	id 1kucIt-0005xZ-9o; Wed, 30 Dec 2020 15:18:19 +0100
Subject: Re: [PATCH AUTOSEL 5.10 01/31] ARM: 9014/2: Replace string mem*
 functions for KASan
To: Sasha Levin <sashal@kernel.org>, linux-kernel@vger.kernel.org,
 stable@vger.kernel.org
Cc: Linus Walleij <linus.walleij@linaro.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Ard Biesheuvel <ardb@kernel.org>,
 Florian Fainelli <f.fainelli@gmail.com>,
 Russell King - ARM Linux <rmk+kernel@armlinux.org.uk>,
 Abbott Liu <liuwenliang@huawei.com>, linux-arm-kernel@lists.infradead.org
References: <20201230130314.3636961-1-sashal@kernel.org>
From: Ahmad Fatoum <a.fatoum@pengutronix.de>
Message-ID: <25b25571-41d6-9482-4c65-09fe88b200d5@pengutronix.de>
Date: Wed, 30 Dec 2020 15:18:13 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.1
MIME-Version: 1.0
In-Reply-To: <20201230130314.3636961-1-sashal@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-SA-Exim-Connect-IP: 2001:67c:670:201:5054:ff:fe8d:eefb
X-SA-Exim-Mail-From: a.fatoum@pengutronix.de
X-SA-Exim-Scanned: No (on metis.ext.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: a.fatoum@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a.fatoum@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33
 as permitted sender) smtp.mailfrom=a.fatoum@pengutronix.de
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

Hello Sasha,

On 30.12.20 14:02, Sasha Levin wrote:
> From: Linus Walleij <linus.walleij@linaro.org>
> 
> [ Upstream commit d6d51a96c7d63b7450860a3037f2d62388286a52 ]
> 
> Functions like memset()/memmove()/memcpy() do a lot of memory
> accesses.
> 
> If a bad pointer is passed to one of these functions it is important
> to catch this. Compiler instrumentation cannot do this since these
> functions are written in assembly.
> 
> KASan replaces these memory functions with instrumented variants.

Unless someone actually wants this, I suggest dropping it.

It's a prerequisite patch for KASan support on ARM32, which is new in
v5.11-rc1. Backporting it on its own doesn't add any value IMO.

Cheers
Ahmad

> 
> The original functions are declared as weak symbols so that
> the strong definitions in mm/kasan/kasan.c can replace them.
> 
> The original functions have aliases with a '__' prefix in their
> name, so we can call the non-instrumented variant if needed.
> 
> We must use __memcpy()/__memset() in place of memcpy()/memset()
> when we copy .data to RAM and when we clear .bss, because
> kasan_early_init cannot be called before the initialization of
> .data and .bss.
> 
> For the kernel compression and EFI libstub's custom string
> libraries we need a special quirk: even if these are built
> without KASan enabled, they rely on the global headers for their
> custom string libraries, which means that e.g. memcpy()
> will be defined to __memcpy() and we get link failures.
> Since these implementations are written i C rather than
> assembly we use e.g. __alias(memcpy) to redirected any
> users back to the local implementation.
> 
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Reviewed-by: Ard Biesheuvel <ardb@kernel.org>
> Tested-by: Ard Biesheuvel <ardb@kernel.org> # QEMU/KVM/mach-virt/LPAE/8G
> Tested-by: Florian Fainelli <f.fainelli@gmail.com> # Brahma SoCs
> Tested-by: Ahmad Fatoum <a.fatoum@pengutronix.de> # i.MX6Q
> Reported-by: Russell King - ARM Linux <rmk+kernel@armlinux.org.uk>
> Signed-off-by: Ahmad Fatoum <a.fatoum@pengutronix.de>
> Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
> Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> Signed-off-by: Russell King <rmk+kernel@armlinux.org.uk>
> Signed-off-by: Sasha Levin <sashal@kernel.org>
> ---
>  arch/arm/boot/compressed/string.c | 19 +++++++++++++++++++
>  arch/arm/include/asm/string.h     | 26 ++++++++++++++++++++++++++
>  arch/arm/kernel/head-common.S     |  4 ++--
>  arch/arm/lib/memcpy.S             |  3 +++
>  arch/arm/lib/memmove.S            |  5 ++++-
>  arch/arm/lib/memset.S             |  3 +++
>  6 files changed, 57 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm/boot/compressed/string.c b/arch/arm/boot/compressed/string.c
> index ade5079bebbf9..8c0fa276d9946 100644
> --- a/arch/arm/boot/compressed/string.c
> +++ b/arch/arm/boot/compressed/string.c
> @@ -7,6 +7,25 @@
>  
>  #include <linux/string.h>
>  
> +/*
> + * The decompressor is built without KASan but uses the same redirects as the
> + * rest of the kernel when CONFIG_KASAN is enabled, defining e.g. memcpy()
> + * to __memcpy() but since we are not linking with the main kernel string
> + * library in the decompressor, that will lead to link failures.
> + *
> + * Undefine KASan's versions, define the wrapped functions and alias them to
> + * the right names so that when e.g. __memcpy() appear in the code, it will
> + * still be linked to this local version of memcpy().
> + */
> +#ifdef CONFIG_KASAN
> +#undef memcpy
> +#undef memmove
> +#undef memset
> +void *__memcpy(void *__dest, __const void *__src, size_t __n) __alias(memcpy);
> +void *__memmove(void *__dest, __const void *__src, size_t count) __alias(memmove);
> +void *__memset(void *s, int c, size_t count) __alias(memset);
> +#endif
> +
>  void *memcpy(void *__dest, __const void *__src, size_t __n)
>  {
>  	int i = 0;
> diff --git a/arch/arm/include/asm/string.h b/arch/arm/include/asm/string.h
> index 111a1d8a41ddf..6c607c68f3ad7 100644
> --- a/arch/arm/include/asm/string.h
> +++ b/arch/arm/include/asm/string.h
> @@ -5,6 +5,9 @@
>  /*
>   * We don't do inline string functions, since the
>   * optimised inline asm versions are not small.
> + *
> + * The __underscore versions of some functions are for KASan to be able
> + * to replace them with instrumented versions.
>   */
>  
>  #define __HAVE_ARCH_STRRCHR
> @@ -15,15 +18,18 @@ extern char * strchr(const char * s, int c);
>  
>  #define __HAVE_ARCH_MEMCPY
>  extern void * memcpy(void *, const void *, __kernel_size_t);
> +extern void *__memcpy(void *dest, const void *src, __kernel_size_t n);
>  
>  #define __HAVE_ARCH_MEMMOVE
>  extern void * memmove(void *, const void *, __kernel_size_t);
> +extern void *__memmove(void *dest, const void *src, __kernel_size_t n);
>  
>  #define __HAVE_ARCH_MEMCHR
>  extern void * memchr(const void *, int, __kernel_size_t);
>  
>  #define __HAVE_ARCH_MEMSET
>  extern void * memset(void *, int, __kernel_size_t);
> +extern void *__memset(void *s, int c, __kernel_size_t n);
>  
>  #define __HAVE_ARCH_MEMSET32
>  extern void *__memset32(uint32_t *, uint32_t v, __kernel_size_t);
> @@ -39,4 +45,24 @@ static inline void *memset64(uint64_t *p, uint64_t v, __kernel_size_t n)
>  	return __memset64(p, v, n * 8, v >> 32);
>  }
>  
> +/*
> + * For files that are not instrumented (e.g. mm/slub.c) we
> + * must use non-instrumented versions of the mem*
> + * functions named __memcpy() etc. All such kernel code has
> + * been tagged with KASAN_SANITIZE_file.o = n, which means
> + * that the address sanitization argument isn't passed to the
> + * compiler, and __SANITIZE_ADDRESS__ is not set. As a result
> + * these defines kick in.
> + */
> +#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> +#define memcpy(dst, src, len) __memcpy(dst, src, len)
> +#define memmove(dst, src, len) __memmove(dst, src, len)
> +#define memset(s, c, n) __memset(s, c, n)
> +
> +#ifndef __NO_FORTIFY
> +#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
> +#endif
> +
> +#endif
> +
>  #endif
> diff --git a/arch/arm/kernel/head-common.S b/arch/arm/kernel/head-common.S
> index 4a3982812a401..6840c7c60a858 100644
> --- a/arch/arm/kernel/head-common.S
> +++ b/arch/arm/kernel/head-common.S
> @@ -95,7 +95,7 @@ __mmap_switched:
>   THUMB(	ldmia	r4!, {r0, r1, r2, r3} )
>   THUMB(	mov	sp, r3 )
>  	sub	r2, r2, r1
> -	bl	memcpy				@ copy .data to RAM
> +	bl	__memcpy			@ copy .data to RAM
>  #endif
>  
>     ARM(	ldmia	r4!, {r0, r1, sp} )
> @@ -103,7 +103,7 @@ __mmap_switched:
>   THUMB(	mov	sp, r3 )
>  	sub	r2, r1, r0
>  	mov	r1, #0
> -	bl	memset				@ clear .bss
> +	bl	__memset			@ clear .bss
>  
>  	ldmia	r4, {r0, r1, r2, r3}
>  	str	r9, [r0]			@ Save processor ID
> diff --git a/arch/arm/lib/memcpy.S b/arch/arm/lib/memcpy.S
> index 09a333153dc66..ad4625d16e117 100644
> --- a/arch/arm/lib/memcpy.S
> +++ b/arch/arm/lib/memcpy.S
> @@ -58,6 +58,8 @@
>  
>  /* Prototype: void *memcpy(void *dest, const void *src, size_t n); */
>  
> +.weak memcpy
> +ENTRY(__memcpy)
>  ENTRY(mmiocpy)
>  ENTRY(memcpy)
>  
> @@ -65,3 +67,4 @@ ENTRY(memcpy)
>  
>  ENDPROC(memcpy)
>  ENDPROC(mmiocpy)
> +ENDPROC(__memcpy)
> diff --git a/arch/arm/lib/memmove.S b/arch/arm/lib/memmove.S
> index b50e5770fb44d..fd123ea5a5a4a 100644
> --- a/arch/arm/lib/memmove.S
> +++ b/arch/arm/lib/memmove.S
> @@ -24,12 +24,14 @@
>   * occurring in the opposite direction.
>   */
>  
> +.weak memmove
> +ENTRY(__memmove)
>  ENTRY(memmove)
>  	UNWIND(	.fnstart			)
>  
>  		subs	ip, r0, r1
>  		cmphi	r2, ip
> -		bls	memcpy
> +		bls	__memcpy
>  
>  		stmfd	sp!, {r0, r4, lr}
>  	UNWIND(	.fnend				)
> @@ -222,3 +224,4 @@ ENTRY(memmove)
>  18:		backward_copy_shift	push=24	pull=8
>  
>  ENDPROC(memmove)
> +ENDPROC(__memmove)
> diff --git a/arch/arm/lib/memset.S b/arch/arm/lib/memset.S
> index 6ca4535c47fb6..0e7ff0423f50b 100644
> --- a/arch/arm/lib/memset.S
> +++ b/arch/arm/lib/memset.S
> @@ -13,6 +13,8 @@
>  	.text
>  	.align	5
>  
> +.weak memset
> +ENTRY(__memset)
>  ENTRY(mmioset)
>  ENTRY(memset)
>  UNWIND( .fnstart         )
> @@ -132,6 +134,7 @@ UNWIND( .fnstart            )
>  UNWIND( .fnend   )
>  ENDPROC(memset)
>  ENDPROC(mmioset)
> +ENDPROC(__memset)
>  
>  ENTRY(__memset32)
>  UNWIND( .fnstart         )
> 

-- 
Pengutronix e.K.                           |                             |
Steuerwalder Str. 21                       | http://www.pengutronix.de/  |
31137 Hildesheim, Germany                  | Phone: +49-5121-206917-0    |
Amtsgericht Hildesheim, HRA 2686           | Fax:   +49-5121-206917-5555 |

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/25b25571-41d6-9482-4c65-09fe88b200d5%40pengutronix.de.
