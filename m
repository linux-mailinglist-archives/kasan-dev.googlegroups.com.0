Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUG3Y6MQMGQEGSAPLLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 372535EAF92
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:22:10 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id u203-20020acaabd4000000b0034f684ca118sf2248721oie.7
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 11:22:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664216528; cv=pass;
        d=google.com; s=arc-20160816;
        b=JZ30oO8009NXSCSlOAkVUlFIl1JstiZwfGggzf1KeY/b5LOaS1u8YuPsz+MGaRFqSZ
         +DIbzijx1uptey7ErgaEqiojD/Ksdk0RzWfKcbue5LEx48qeOnTmVz1R8ojP2r4lmUVV
         cLcjkPMI4FW1WF5sPwCTvZqWiRFAKbVu0RY0wXQOvoJi8G4oNqiEkrhJN83I1jEtLifO
         d+FUMp0uykRgU2aLoPY03YAb3+aZy5YTAU2wYmVWigCXDnp77HnMsitR0sLdiJwlgpYq
         nGYXyNhjgTXs0OzUJ+6BEls8XIfDAAns3aNsu4oZRRQ5kY0Vzip4t6qIF1QQLBzQOyZN
         QU7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=A0cMXIcDRb9/811n3THLis2RocRKg/g6ENB6c7XJHVQ=;
        b=IC85ZL7vxvMS1k14yOg0h4Rz/oy00cKE2MbAh2xzk3PsFbr+DanR2+82ZVBJYroqRL
         mLRm3z8SvkEtbMvkqKIoSMQDnL2RuKSkFo1NNLAhmrsPU0xqgkKCb8FdnV8goU2o3w/K
         /qjc+482FTvENI/o6vit6VklXHZzvFXVZ6eDWdngBZpUXjcFml+bxx0S9L4xVMaSWh95
         KGR2jxpgr+f0HToPOEwKDJTGlksFytRBu2CX8uUYD/+8VdKsQ6NxKoKotMA7l/ZGskK8
         J/EO98CdKvifPY6xOyvtTF0Aep4f8Y3SNYngxQhtuZxoTAKkayp2GOC3vifKTeCo0sJj
         u8fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=W9WSI3Nw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=A0cMXIcDRb9/811n3THLis2RocRKg/g6ENB6c7XJHVQ=;
        b=hxAlKJrx7yK5lAKgTXuz+9ZywCR+4CJ8xqxxJas+qzrl9MtqkmqqQZiiWzVXlVpoD+
         ORdzLJyQo1oVqA1PLSE+9Adi7LBrQIasB8Dw05JWGSN/6O34ifYIqAhXr9G99rNXZq7r
         LiozrmQtNHfUR9YxOSSyny3wrCNDob7DGgf6hSlFqegv2+zM7PkQ3ezottz+GRanfRtW
         AaDJ8em38f+O5JmpWLsKsq9rrkcTl2mwcQK2LWm9MHedqexCdgT048+qDX0rwQUgW1mM
         8zTYaiNA/u6kepIm8DuIUuZPZL2h0d5togtEeGmbitKZYVvLhQtJN9CweUEc8zYNI3s0
         R2hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=A0cMXIcDRb9/811n3THLis2RocRKg/g6ENB6c7XJHVQ=;
        b=Rhynw57t5vsyi21apGI52agOyWb22jgSgo16jkBVp2ICKrpcFepIohGNYey0BT6ru5
         ZHMryudoZI1679eeYp4RTqoE+tYniB8I/+D/d6UpG+1lNfhEPWluEeyTHIBYSPSMeIcA
         WlcGlnc9tI5+r9yXmo96ECAB09zWrM/ta22PhmTQ13llkVXCLRaJRt1zAKqO6tCu0Qca
         azHNfbCzTfKjjjvTZDDSj+l1IyAvi+E0elbSzvA77YxQJr5dXcSBj+huntlkk11NmA4e
         xMimqam9gR/8OMVv41+UqEhRfS9R2EMkUTyuWj3Kk9x5GNstufc2labDu6QxXYglNz3G
         8E5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3V2Ieh9cprLu4R3AFyoYGG/8nRV8knzYu3pSBWdwhSpaccT4M4
	kolJFoITYyPtgKA0DuB9jXE=
X-Google-Smtp-Source: AMsMyM48yZWtQgstKujmdrv7hmUSUjpaTlvYS/iver3hB34J6xxqK4yR9uCZlJndzvgYSmq65Wh2Qg==
X-Received: by 2002:a05:6870:14c1:b0:12d:be49:8c23 with SMTP id l1-20020a05687014c100b0012dbe498c23mr22553oab.21.1664216528737;
        Mon, 26 Sep 2022 11:22:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:149:b0:351:2f34:6fc0 with SMTP id
 h9-20020a056808014900b003512f346fc0ls49180oie.2.-pod-prod-gmail; Mon, 26 Sep
 2022 11:22:08 -0700 (PDT)
X-Received: by 2002:aca:ab43:0:b0:34d:8e17:f481 with SMTP id u64-20020acaab43000000b0034d8e17f481mr28236oie.188.1664216528398;
        Mon, 26 Sep 2022 11:22:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664216528; cv=none;
        d=google.com; s=arc-20160816;
        b=JUIUExlQSaBYptFqgT4nZNbZQy2OF8LAzBvwTJOUxz2h5RtHBfOZ9wY8Itza/UynWJ
         4GOga4O/bifpOqnOZp2TgYlb3WrAk9nkoR/cb3pf5rf2rZBVrBMuzn076vyzW+cZaF8v
         ADqBe0ETwFkhIIx8W+NfEooLBcIV/GgqTOX56BCFL1yc3Goqj+WZNSNiIkWapYG5zDj/
         RK6WYeUF9cIRAi6E0muCvj93VfTA8LyvaMJ8jenhI18TQQsKs6ciCZwe0XjVDeJ+Q6sH
         US58830eKI4z0aFZB9etB6OVPazssC1k81G/NE+1nGieDccvEfRZDV1q5/2ZUHUSRvWG
         qlCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LiwNBqos6xaaK3YWH+/WPpsFGSo0QKCNP2I5hOKKSHY=;
        b=IbomPBw2bIvrJt9AYmQAmYu9v6cwFYulfGZf+6lYW1Z9fs/+oBc0m7ekkDidVi9vOi
         BVTUx3pNvjRwtYCgQ+l0R7HGfhx0O2/vL3I4RxTLrStnZLXBnZQTi00BEf145aR/f4L6
         BtbrmN+U8xpJh1LAz35dAPMSaAO/vukNXhl6phu1ZtXQX1frg9VLW7j82KP2tFtbVLxo
         MuKu1nO6jnfVyya+1gixVs5FzDyw3f9ZkLvDl6eB9zH6yKKzctTueiqg+HSTJVIX45du
         WhHhYtvRcWVk9LpZeK3dgUoNLgpXdkUY/PMuV/ZDDHRGLnSIZECOuUAK+4U+YMulWEDJ
         jCbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=W9WSI3Nw;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id t14-20020a056870638e00b0011ca4383bd6si1759175oap.4.2022.09.26.11.22.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 11:22:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id e68so7544237pfe.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 11:22:08 -0700 (PDT)
X-Received: by 2002:a63:f917:0:b0:439:1c07:d1da with SMTP id h23-20020a63f917000000b004391c07d1damr21017743pgi.13.1664216527669;
        Mon, 26 Sep 2022 11:22:07 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id q16-20020a63cc50000000b0043be31d490dsm10768624pgi.67.2022.09.26.11.22.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Sep 2022 11:22:06 -0700 (PDT)
Date: Mon, 26 Sep 2022 11:22:05 -0700
From: Kees Cook <keescook@chromium.org>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] random: split initialization into early arch step and
 later non-arch step
Message-ID: <202209261105.9C6AEEEE1@keescook>
References: <20220926160332.1473462-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220926160332.1473462-1-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=W9WSI3Nw;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Sep 26, 2022 at 06:03:32PM +0200, Jason A. Donenfeld wrote:
> The full RNG initialization relies on some timestamps, made possible
> with general functions like time_init() and timekeeping_init(). However,
> these are only available rather late in initialization. Meanwhile, other
> things, such as memory allocator functions, make use of the RNG much
> earlier.
> 
> So split RNG initialization into two phases. We can give arch randomness
> very early on, and then later, after timekeeping and such are available,
> initialize the rest.
> 
> This ensures that, for example, slabs are properly randomized if RDRAND
> is available. Another positive consequence is that on systems with
> RDRAND, running with CONFIG_WARN_ALL_UNSEEDED_RANDOM=y results in no
> warnings at all.

Nice! I like it. Notes below...

> 
> Cc: Kees Cook <keescook@chromium.org>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: stable@vger.kernel.org
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---
> I intend to take this through the random.git tree, but reviews/acks
> would be appreciated, given that I'm touching init/main.c.
> 
>  drivers/char/random.c  | 47 ++++++++++++++++++++++++------------------
>  include/linux/random.h |  3 ++-
>  init/main.c            | 17 +++++++--------
>  3 files changed, 37 insertions(+), 30 deletions(-)
> 
> diff --git a/drivers/char/random.c b/drivers/char/random.c
> index a90d96f4b3bb..1cb53495e8f7 100644
> --- a/drivers/char/random.c
> +++ b/drivers/char/random.c
> @@ -772,18 +772,13 @@ static int random_pm_notification(struct notifier_block *nb, unsigned long actio
>  static struct notifier_block pm_notifier = { .notifier_call = random_pm_notification };
>  
>  /*
> - * The first collection of entropy occurs at system boot while interrupts
> - * are still turned off. Here we push in latent entropy, RDSEED, a timestamp,
> - * utsname(), and the command line. Depending on the above configuration knob,
> - * RDSEED may be considered sufficient for initialization. Note that much
> - * earlier setup may already have pushed entropy into the input pool by the
> - * time we get here.
> + * This is called extremely early, before time keeping functionality is
> + * available, but arch randomness is. Interrupts are not yet enabled.
>   */
> -int __init random_init(const char *command_line)
> +void __init random_init_early(const char *command_line)
>  {
> -	ktime_t now = ktime_get_real();
> -	size_t i, longs, arch_bits;
>  	unsigned long entropy[BLAKE2S_BLOCK_SIZE / sizeof(long)];
> +	size_t i, longs, arch_bits;
>  
>  #if defined(LATENT_ENTROPY_PLUGIN)
>  	static const u8 compiletime_seed[BLAKE2S_BLOCK_SIZE] __initconst __latent_entropy;
> @@ -803,34 +798,46 @@ int __init random_init(const char *command_line)
>  			i += longs;
>  			continue;
>  		}

Can find a way to get efi_get_random_bytes() in here too? (As a separate
patch.) I don't see where that actually happens anywhere currently,
and we should have it available at this point in the boot, yes?

> -		entropy[0] = random_get_entropy();
> -		_mix_pool_bytes(entropy, sizeof(*entropy));
>  		arch_bits -= sizeof(*entropy) * 8;
>  		++i;
>  	}
> -	_mix_pool_bytes(&now, sizeof(now));
> -	_mix_pool_bytes(utsname(), sizeof(*(utsname())));

Hm, can't we keep utsname in the early half by using init_utsname() ?

> +
>  	_mix_pool_bytes(command_line, strlen(command_line));
> +
> +	if (trust_cpu)
> +		credit_init_bits(arch_bits);
> +}
> +
> +/*
> + * This is called a little bit after the prior function, and now there is
> + * access to timestamps counters. Interrupts are not yet enabled.
> + */
> +void __init random_init(void)
> +{
> +	unsigned long entropy = random_get_entropy();
> +	ktime_t now = ktime_get_real();
> +
> +	_mix_pool_bytes(utsname(), sizeof(*(utsname())));

(...and then obviously don't repeat it here.)

> +	_mix_pool_bytes(&now, sizeof(now));
> +	_mix_pool_bytes(&entropy, sizeof(entropy));
>  	add_latent_entropy();
>  
>  	/*
> -	 * If we were initialized by the bootloader before jump labels are
> -	 * initialized, then we should enable the static branch here, where
> +	 * If we were initialized by the cpu or bootloader before jump labels
> +	 * are initialized, then we should enable the static branch here, where
>  	 * it's guaranteed that jump labels have been initialized.
>  	 */
>  	if (!static_branch_likely(&crng_is_ready) && crng_init >= CRNG_READY)
>  		crng_set_ready(NULL);
>  
> +	/* Reseed if already seeded by earlier phases. */
>  	if (crng_ready())
>  		crng_reseed();
> -	else if (trust_cpu)
> -		_credit_init_bits(arch_bits);
>  
>  	WARN_ON(register_pm_notifier(&pm_notifier));
>  
> -	WARN(!random_get_entropy(), "Missing cycle counter and fallback timer; RNG "
> -				    "entropy collection will consequently suffer.");
> -	return 0;
> +	WARN(!entropy, "Missing cycle counter and fallback timer; RNG "
> +		       "entropy collection will consequently suffer.");
>  }
>  
>  /*
> diff --git a/include/linux/random.h b/include/linux/random.h
> index 3fec206487f6..a9e6e16f9774 100644
> --- a/include/linux/random.h
> +++ b/include/linux/random.h
> @@ -72,7 +72,8 @@ static inline unsigned long get_random_canary(void)
>  	return get_random_long() & CANARY_MASK;
>  }
>  
> -int __init random_init(const char *command_line);
> +void __init random_init_early(const char *command_line);
> +void __init random_init(void);
>  bool rng_is_initialized(void);
>  int wait_for_random_bytes(void);
>  
> diff --git a/init/main.c b/init/main.c
> index 1fe7942f5d4a..611886430e28 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -976,6 +976,9 @@ asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
>  		parse_args("Setting extra init args", extra_init_args,
>  			   NULL, 0, -1, -1, NULL, set_init_arg);
>  
> +	/* Call before any memory or allocators are initialized */

Maybe for greater clarity:

	/* Pre-time-keeping entropy collection before allocator init. */

> +	random_init_early(command_line);
> +
>  	/*
>  	 * These use large bootmem allocations and must precede
>  	 * kmem_cache_init()
> @@ -1035,17 +1038,13 @@ asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
>  	hrtimers_init();
>  	softirq_init();
>  	timekeeping_init();
> -	kfence_init();
>  	time_init();

Was there a reason kfence_init() was happening before time_init()?

>  
> -	/*
> -	 * For best initial stack canary entropy, prepare it after:
> -	 * - setup_arch() for any UEFI RNG entropy and boot cmdline access
> -	 * - timekeeping_init() for ktime entropy used in random_init()
> -	 * - time_init() for making random_get_entropy() work on some platforms
> -	 * - random_init() to initialize the RNG from from early entropy sources
> -	 */
> -	random_init(command_line);
> +	/* This must be after timekeeping is initialized */
> +	random_init();
> +
> +	/* These make use of the initialized randomness */

I'd clarify this more:

	/* These make use of the fully initialized randomness entropy. */

> +	kfence_init();
>  	boot_init_stack_canary();
>  
>  	perf_event_init();
> -- 
> 2.37.3
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209261105.9C6AEEEE1%40keescook.
