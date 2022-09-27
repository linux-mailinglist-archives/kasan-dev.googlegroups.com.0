Return-Path: <kasan-dev+bncBCWZBO5OREMRBJ5TZKMQMGQEJROTYSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 24A505EBAC5
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 08:35:20 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id i27-20020adfaadb000000b0022a48b6436dsf1812702wrc.23
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 23:35:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664260519; cv=pass;
        d=google.com; s=arc-20160816;
        b=SAzZLIop6iSHrUk47MXoo+6JDFk1TPxWDYhdXUvcXgC6O2quVTHRt+3oP6txJTcaAG
         jfHwA2i2AXfs8IX0RejAfhCfu2at7gLoBVPVjBBONgttkW9gKZQJKPubSZjDyTQ9NcIi
         Bxx7UVZoUqI6lkI/mdInqgNhgAYtC8wbdI5FXjMeP2EBFMsr81PERWpjIBCKtJlqQ+hL
         XlPcBjePTRGHSwAxW9hOvVfVrIQiqTb07V21adI4B3URX+nkfOxRRN669hwCccOokI6W
         qfAk98/LvoGKsbWn95irJgYjYC8sM6vnD7Jo4C2ygREpkMJvODpV9jrgaT019kfaQKhF
         VUag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S8P7iGH+/LaEho5Ua7yrHGF2FyeirRJ8C7/5PAD7WbM=;
        b=L/35FGXH37G8CeANcDzm/LWRdr6WwyY8kfWiLd3pO1rysSqbd8FCn7V0GuRMy/GWjL
         ostOPNhT0yaqOwmf7G2/lvuwJgFTftMO7dA/KY+mXLAPBgNo0Yz87t8WlUDxd+hIrCWJ
         Rb67qUefpjYT6SglrnIssx9oCcZfUZEO7mkPy8jV91QB6bgSauYt4pfh7WGaPkn1mprt
         baz6cUpk1BpvRDayyN6P1HmESqvAVQ1CmnsB9jyk1s5VlDk//nlnpal4h+hodFnG4BBP
         DGOhQlFCui9shpeS/M67Ym/RESFNj5vdqIf5pYLxD97mFzbr1ifHBorQ0egiyhqqT2fB
         aAtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 136.243.71.142 is neither permitted nor denied by best guess record for domain of linux@dominikbrodowski.net) smtp.mailfrom=linux@dominikbrodowski.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=S8P7iGH+/LaEho5Ua7yrHGF2FyeirRJ8C7/5PAD7WbM=;
        b=O2Mh0bWA848YYL7wkGjFhXj6C//CQ4cvq/yLSa3kkRW/1Rbj+4rKJQYbW44nU5toMF
         tC4wcbkTm0Zl5FGsQVSlsCLEu2NnVj3hqP6fDe6tZs7RLk5xb88jjisuqmDZLxjpgMQN
         T1mcmwfco4qn+8iXyRpzCxOltseYcwUVqrbGFobSPB6Oyboxq3zclLvEEB9a7BU736DF
         w+GcqEHcmN1fJvk0YPCwrCT1ZBoPWOLFYtve0MhjSLnvRuJaDrdIA+ZZvStrcnK6G2Fh
         o5ki35nVEgwBxLkEybZYsqgnugc027tDOR7BK3i6dhxbx0Pv4sgXp096x2ne6IB2p9VS
         emqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=S8P7iGH+/LaEho5Ua7yrHGF2FyeirRJ8C7/5PAD7WbM=;
        b=RCjimXRpxcf22kbZr1+mpSH2VmVpJx8vafeTxTCYhE3n30EVK4u8uXWkgi5s+X7iWc
         AaQfoqbj5Q7cwTfzlbptVfMhJHpPRhzLupVMehakbsTfLDMu/Bor3FMS5u97L2neJFhL
         JUK5uhKW109oNPHE2Y94TVwQ/dET69bXMVR/sm510cwWPqOq06PeGu2kGfp4a8MZlolS
         P4ImtH6dq2x3GXXtQya+vP924YUVrWUDUHSlA0MyWqrM3LwBGrSGI3B3lkWz8pC1yYzf
         ntlHCCeLT16w8Q5t4xX1ktLXaaz02IyM46OA87xGJ7DRfh2lwK8tb+/19ik5LAw+kBv7
         wRSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0l1gXZ/JcWIKQleamUe8QyH+QEyVKyU2QIn/EDQxDYcfELkV//
	ge539p6M1effqLHur9VLanU=
X-Google-Smtp-Source: AMsMyM6cb1TM9It6K6TxQMIm/n1O4hAo/s4NghYwsJAip2Zzh3ypTeTGdDpjjRuTwkz55IATY4K/8A==
X-Received: by 2002:a1c:7315:0:b0:3b4:e1b8:47b2 with SMTP id d21-20020a1c7315000000b003b4e1b847b2mr1360331wmb.165.1664260519621;
        Mon, 26 Sep 2022 23:35:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4b11:0:b0:3a5:24fe:28ff with SMTP id y17-20020a1c4b11000000b003a524fe28ffls476247wma.0.-pod-control-gmail;
 Mon, 26 Sep 2022 23:35:18 -0700 (PDT)
X-Received: by 2002:a7b:ce99:0:b0:3b4:9031:fc02 with SMTP id q25-20020a7bce99000000b003b49031fc02mr1416999wmj.154.1664260518483;
        Mon, 26 Sep 2022 23:35:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664260518; cv=none;
        d=google.com; s=arc-20160816;
        b=ZcdRSd8FK/BUCSMSOqrrHmclQS4bQW5FvsffEGvIQSyFIXfOMY7u3bAbiLCrHYgMrL
         gC05A296WXJ0cMC6CsKoYfqAPOpcxd3JsZWVltj/EQiE0Pi8XqQyn+4F1VMWzekZa3n/
         yaFzKXpQ0MkImsT9PPv/7obUnz0PQWM9cRhWKedRl6TUb70J3K1UEbBZBjUmeYGcQrDj
         trrsZ/VhJQVNGwveRjOOfqA7MfD8wRiTVl5xbiLam4RczBcmavn+hgCVSx+QaP7nOknf
         YQS2DgADKI3ogjwFrxbVTtLnDsfyZOQcofEPA23EM7MA9mPTz+v7JGySTA1dULNiJsHC
         NAdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=SBMGM6+2Z/ixqQYdWeAELZ6LNs3350/MmWMj81IrLYw=;
        b=0kE5y+G6gHPSsS4BJ/ZQ5cnqLcAtJTA+R0giqVUFpX40xcmTM5qn7qgTOfQw70inyy
         vFZJM2uMFjYgmXwXp4jU+qGNs1useREP90MG58FGSjONS32QNRwjazQxC5ivSaeuIF5X
         BSA20DRfDoQQgONWa1GLYVk5HbtyngcpzW98NeXVprOJ4M3FJIQ6GETfUrO8q5SaM0zf
         BNPklhcX8KmjfYGy0jiC9iowGpFLBtxq4ol4YGtjv7enHjc2CwvCj7WpGdcIvGAsJfcB
         SIYxj0MG7/Sh1rrGGiXQpl4N9es2hkamP8oXLzqOB2+XxNqBzlYBEeDnSwjbP4TtFAIW
         ouaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 136.243.71.142 is neither permitted nor denied by best guess record for domain of linux@dominikbrodowski.net) smtp.mailfrom=linux@dominikbrodowski.net
Received: from isilmar-4.linta.de (isilmar-4.linta.de. [136.243.71.142])
        by gmr-mx.google.com with ESMTPS id k185-20020a1ca1c2000000b003a49e4e7e14si50449wme.0.2022.09.26.23.35.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Sep 2022 23:35:18 -0700 (PDT)
Received-SPF: neutral (google.com: 136.243.71.142 is neither permitted nor denied by best guess record for domain of linux@dominikbrodowski.net) client-ip=136.243.71.142;
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
Received: from owl.dominikbrodowski.net (owl.brodo.linta [10.2.0.111])
	by isilmar-4.linta.de (Postfix) with ESMTPSA id C6814201327;
	Tue, 27 Sep 2022 06:35:17 +0000 (UTC)
Received: by owl.dominikbrodowski.net (Postfix, from userid 1000)
	id 0FD2E80536; Tue, 27 Sep 2022 08:35:10 +0200 (CEST)
Date: Tue, 27 Sep 2022 08:35:10 +0200
From: Dominik Brodowski <linux@dominikbrodowski.net>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>, stable@vger.kernel.org
Subject: Re: [PATCH v2 1/2] random: split initialization into early step and
 later step
Message-ID: <YzKZnkwCi0UwY/4Q@owl.dominikbrodowski.net>
References: <20220926213130.1508261-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220926213130.1508261-1-Jason@zx2c4.com>
X-Original-Sender: linux@dominikbrodowski.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 136.243.71.142 is neither permitted nor denied by best guess
 record for domain of linux@dominikbrodowski.net) smtp.mailfrom=linux@dominikbrodowski.net
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

Am Mon, Sep 26, 2022 at 11:31:29PM +0200 schrieb Jason A. Donenfeld:
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
> is available. Without this, CONFIG_SLAB_FREELIST_RANDOM=y loses a degree
> of its security, because its random seed is potentially deterministic,
> since it hasn't yet incorporated RDRAND. It also makes it possible to
> use a better seed in kfence, which currently relies on only the cycle
> counter.
> 
> Another positive consequence is that on systems with RDRAND, running
> with CONFIG_WARN_ALL_UNSEEDED_RANDOM=y results in no warnings at all.

Nice improvement. One question, though:

>  #if defined(LATENT_ENTROPY_PLUGIN)
>  	static const u8 compiletime_seed[BLAKE2S_BLOCK_SIZE] __initconst __latent_entropy;
> @@ -803,34 +798,46 @@ int __init random_init(const char *command_line)
>  			i += longs;
>  			continue;
>  		}
> -		entropy[0] = random_get_entropy();
> -		_mix_pool_bytes(entropy, sizeof(*entropy));
>  		arch_bits -= sizeof(*entropy) * 8;
>  		++i;
>  	}


Previously, random_get_entropy() was mixed into the pool ARRAY_SIZE(entropy)
times.

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

But now, it's only mixed into the pool once. Is this change on purpose?

Thanks,
	Dominik

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzKZnkwCi0UwY/4Q%40owl.dominikbrodowski.net.
