Return-Path: <kasan-dev+bncBCJ455VFUALBB6VQ72MQMGQEQ4PXB6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E43B15F730A
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 05:09:47 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id x38-20020a056a0018a600b005627bfe4769sf1947807pfh.20
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 20:09:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665112186; cv=pass;
        d=google.com; s=arc-20160816;
        b=RKgUxBqr2fwBDXqjCi41Ghl/B2NwFTzan6JlNyEuLYg5DTG0b+0WrrNCxcCrIrh8Ki
         phbN/uXZsidjogopMMQUMXA5HrLoNQgwn1/wVqAWyIcfLvQwRCEpcBnNKiX2vbvAIGsN
         PHgbPI1cLqJmRkmN1VdGik1zdqXAD3HPmTygKqySFPoDOXx+/8pa3Ep74loNZcPImrFy
         gl9NE7Dys3pUt8Tufjml3EbT7eR/MunmO5fqgnyd926/TWjl2S3tBnYgjfNswfbJlZYA
         agBh43cG8JOKPYXndbGJANwQzM391Q8fsxMnRBx7WOj5Hj/dA9yzbV9JYaEx34Y+oHFD
         fiYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=MxDpNQH72I099IPsUOaIU2XEQrrJ2K6BQa73v897bTg=;
        b=UuaF+sTzwBW5acl+5XF7ogfT7AoUm5CRWuT6mtlS7l3kZnC2S/lf4bTBb9N2de/gXK
         bh/144l+A7aFE+XItfRMxKYdgqB1b8+qX3q/cRq49QGV3+vIt/lNkoj1hhkCmeCw3FmP
         pSVCtBFXAya87aY/lWG7EdBaf3ckD4gBEbRwvYTWuHfHpUDGq6nZe6mb/R7tusFq9euX
         IYGqGyiSzFXRsTXmZmKFmVOLY4LX+Qitp8G4C8FA2PxGbCCuaX/OqY31TbJxqFzvQB6o
         GWdPm5Jx37XgS7nfKDDRoL4asJxWRxL1NX/QTLBkMRT+4ttv0BK2gybfG9iKq2DYw9r4
         IzJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="nfOOp/zi";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MxDpNQH72I099IPsUOaIU2XEQrrJ2K6BQa73v897bTg=;
        b=TZtlawOI4dr7pvRh0kqMZ9euCpyfWks/d1zl5r6r/In65a2swFXaYuBpxPscI/+/Hp
         AAE8piAgz1dWVwg52OkAT972Z3qvLPGETSlpJ+Y02wZYaz8Ppv8fKz7BjmQg1GbUhgJp
         Dp0O+C9JBliCkBeLeMz+Ij0DAWnZuhJgh7TLufLHwHqXB/W995QqeyHSZhmug5zdubOE
         oAM/gdC83XrYz1RK/ztW4ID6fjb8apmiahNtj2Wb6JrY23Jfnk9f5UkH0JUoc9cNYr0w
         fxNqE8LUjWMUMHbJEdZi5AO68BYdZhKoxmv6C89u6zgKQjP9VmWKuKDAOXcS0FfGbTjw
         ZFPA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MxDpNQH72I099IPsUOaIU2XEQrrJ2K6BQa73v897bTg=;
        b=OJ5e7VRakhUodAdir1iO0GyMfxqg/Gi7tBvfVyR3phU+eK8isoxPNGvIGdR6Ju9M0S
         GjvNBY+pWZV9voIZXi+GDrodfpyISJVetWmlhFXByoBiQpR6wSgpzg+R/+qz7EYDACez
         pM87sLKRUFSanoS3qkBrVE3WDZNT27/gd/wyfoKoUKw6VoCvFIRIc6/RMZDR0MUPvRpW
         Ss2ZEtUVKGypo9WqmUdjoRfuUWo0liuPJSjViRyyk3JhVf/oxxQB3V14MsF776I32yIh
         XxH7JnqLuhUsYK9akAd3/jn5Mgy6wvGFOQCswkJlEAV3wpn3i9u7YnWmk1WcardStQ8D
         Clug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MxDpNQH72I099IPsUOaIU2XEQrrJ2K6BQa73v897bTg=;
        b=8ATmWPo5n646wGL2KLIQJV9UcMbg8w9XOvf14RUY0XT6lp/N1Cn91sYLkh9TqAN7+G
         pwvAsgZ/YbPU0OwNhZ2E/pc3/kU38jyZSdLhAuTjV+5LLNmsOPWM8J7xR/PZb3dNoDlq
         nnmK577O2qGfENQIfUD+dxX61pXaTME4FZN1fg1VcmYw7oMhyZqT/o7Wl4C+NWl9hC72
         Z23Hv4KrU69Yoe/j7SpZBg4fBx9ba7OyOeTLCoGvBfXQ1AMzltUF4ug/zgkY1gpnx2t9
         KNCLRqTYYQhA81FMK+7cj+zwvcxrABE7qK906SoD08R5EKkPP/iIegq5Qk6NgdWu0WgK
         pcYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0u8j/Wi16fuQ8vTi2DMupzxwQ951V4hxFoXm+JhayakcJTVX+n
	Ts3KME2bsnpkWbVmTJYp8UM=
X-Google-Smtp-Source: AMsMyM4/Q0LKC7uJ1P+IEyY+d6Wgh5wXRGkLLLYQJ7Xt9xsJpFHHchfjWeWx1qrLL29DOqu9WXO3kQ==
X-Received: by 2002:a17:902:e750:b0:17f:71fa:d695 with SMTP id p16-20020a170902e75000b0017f71fad695mr2985435plf.105.1665112186299;
        Thu, 06 Oct 2022 20:09:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ef91:b0:178:5938:29de with SMTP id
 iz17-20020a170902ef9100b00178593829dels2881590plb.2.-pod-prod-gmail; Thu, 06
 Oct 2022 20:09:45 -0700 (PDT)
X-Received: by 2002:a17:90a:ce82:b0:20a:b20f:6d0e with SMTP id g2-20020a17090ace8200b0020ab20f6d0emr13782029pju.125.1665112185563;
        Thu, 06 Oct 2022 20:09:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665112185; cv=none;
        d=google.com; s=arc-20160816;
        b=V81WxShuniJ6JlUV60LwWeaQb8gEDWvRfuOcE0EUoeGkiYQwaoLolc5xCFId3jX7ac
         IjQ4barAplyUdkg3atQixsm9wW4Qi1dgxbh14keWx32WtpIg+d7/gHFO9MtVphisGadS
         DUU9LP6J5aVKoFbvgqn3QWUdg5PzC6NzoTyYO4MvBY3YyxpvjZ047FoWrIp+UavjtRSZ
         wG/fR/cT8GRHugwgjTc9eKuzyVQVWV9r7gbjxZ062hYalaqv7WClcVyI0mNPmp70eB9u
         pUbmP5fAyVKACmQiNicucw/vjJWwpDyMpA5PWJQ01QV2p4QeSuCIT1I5XKQQIp7T6hEq
         QQ+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=nNSxrEKnbM/YJCfYZKBXPasbkt11mg0gMP8x+dp5+t8=;
        b=v+ARBVMH8ep8MecY6m4/9zywrz7W6XIpjf5TAjQYQlREqoOneT7wPRtJuWnIdiK8ro
         gPnB6ssaBy9GIq+kdE3QkmAUrX6ylY7pTNlcal+zqYlEGC+YtkhHLHa6MVkTPRX+S+K5
         i4vk6juTO9fagkRVOzl2aRCVcG1n1wahDXOP5kL23IBkhHE3/gCMUdgrfCH3RqNwIAsW
         SGNx+2votoYOuk8BfSiYhvyxgm24WC90ujjMwojG8L2y2tbjI7mtPOPIjUiMOd3SpYac
         f29dN5rQZzNiMi7GcGGXB2Rs9Z45ALsGd6J3eHvBM9dbMk7pi300xiu0S3YHeTU4hhdR
         VCKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="nfOOp/zi";
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id k133-20020a636f8b000000b0043238c0bd99si59114pgc.4.2022.10.06.20.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 20:09:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 129so3503530pgc.5
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 20:09:45 -0700 (PDT)
X-Received: by 2002:a63:1301:0:b0:457:f3b7:238b with SMTP id i1-20020a631301000000b00457f3b7238bmr2636559pgl.262.1665112185106;
        Thu, 06 Oct 2022 20:09:45 -0700 (PDT)
Received: from [192.168.43.80] (subs28-116-206-12-55.three.co.id. [116.206.12.55])
        by smtp.gmail.com with ESMTPSA id k11-20020aa79d0b000000b00561beff1e09sm366130pfp.164.2022.10.06.20.09.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 20:09:44 -0700 (PDT)
Message-ID: <6c0f1d6a-27e6-5a82-956e-a4f12e0a51bf@gmail.com>
Date: Fri, 7 Oct 2022 10:09:26 +0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.13.1
Subject: Re: [PATCH v3 4/5] treewide: use get_random_bytes when possible
Content-Language: en-US
To: "Jason A. Donenfeld" <Jason@zx2c4.com>, linux-kernel@vger.kernel.org,
 patches@lists.linux.dev
Cc: Andreas Noever <andreas.noever@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
 Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?Q?Christoph_B=c3=b6hmwalder?= <christoph.boehmwalder@linbit.com>,
 Christoph Hellwig <hch@lst.de>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>,
 "David S . Miller" <davem@davemloft.net>, Eric Dumazet
 <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "H . Peter Anvin" <hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>,
 Helge Deller <deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>,
 Huacai Chen <chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>,
 Jakub Kicinski <kuba@kernel.org>,
 "James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>,
 Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>,
 Johannes Berg <johannes@sipsolutions.net>, Jonathan Corbet <corbet@lwn.net>,
 Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>,
 Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
 Mauro Carvalho Chehab <mchehab@kernel.org>,
 Michael Ellerman <mpe@ellerman.id.au>,
 Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>,
 Peter Zijlstra <peterz@infradead.org>, Richard Weinberger <richard@nod.at>,
 Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Ulf Hansson <ulf.hansson@linaro.org>, Vignesh Raghavendra <vigneshr@ti.com>,
 WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>,
 Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org,
 kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
 linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mm@kvack.org, linux-mmc@vger.kernel.org,
 linux-mtd@lists.infradead.org, linux-nvme@lists.infradead.org,
 linux-parisc@vger.kernel.org, linux-rdma@vger.kernel.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org,
 linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, loongarch@lists.linux.dev,
 netdev@vger.kernel.org, sparclinux@vger.kernel.org, x86@kernel.org
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-5-Jason@zx2c4.com>
From: Bagas Sanjaya <bagasdotme@gmail.com>
In-Reply-To: <20221006165346.73159-5-Jason@zx2c4.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="nfOOp/zi";       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::52a
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
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

On 10/6/22 23:53, Jason A. Donenfeld wrote:
> The prandom_bytes() function has been a deprecated inline wrapper around
> get_random_bytes() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---
>  arch/powerpc/crypto/crc-vpmsum_test.c       |  2 +-
>  block/blk-crypto-fallback.c                 |  2 +-
>  crypto/async_tx/raid6test.c                 |  2 +-
>  drivers/dma/dmatest.c                       |  2 +-
>  drivers/mtd/nand/raw/nandsim.c              |  2 +-
>  drivers/mtd/tests/mtd_nandecctest.c         |  2 +-
>  drivers/mtd/tests/speedtest.c               |  2 +-
>  drivers/mtd/tests/stresstest.c              |  2 +-
>  drivers/net/ethernet/broadcom/bnxt/bnxt.c   |  2 +-
>  drivers/net/ethernet/rocker/rocker_main.c   |  2 +-
>  drivers/net/wireguard/selftest/allowedips.c | 12 ++++++------
>  fs/ubifs/debug.c                            |  2 +-
>  kernel/kcsan/selftest.c                     |  2 +-
>  lib/random32.c                              |  2 +-
>  lib/test_objagg.c                           |  2 +-
>  lib/uuid.c                                  |  2 +-
>  net/ipv4/route.c                            |  2 +-
>  net/mac80211/rc80211_minstrel_ht.c          |  2 +-
>  net/sched/sch_pie.c                         |  2 +-
>  19 files changed, 24 insertions(+), 24 deletions(-)
> 
> diff --git a/arch/powerpc/crypto/crc-vpmsum_test.c b/arch/powerpc/crypto/crc-vpmsum_test.c
> index c1c1ef9457fb..273c527868db 100644
> --- a/arch/powerpc/crypto/crc-vpmsum_test.c
> +++ b/arch/powerpc/crypto/crc-vpmsum_test.c
> @@ -82,7 +82,7 @@ static int __init crc_test_init(void)
>  
>  			if (len <= offset)
>  				continue;
> -			prandom_bytes(data, len);
> +			get_random_bytes(data, len);
>  			len -= offset;
>  
>  			crypto_shash_update(crct10dif_shash, data+offset, len);
> diff --git a/block/blk-crypto-fallback.c b/block/blk-crypto-fallback.c
> index 621abd1b0e4d..ad9844c5b40c 100644
> --- a/block/blk-crypto-fallback.c
> +++ b/block/blk-crypto-fallback.c
> @@ -539,7 +539,7 @@ static int blk_crypto_fallback_init(void)
>  	if (blk_crypto_fallback_inited)
>  		return 0;
>  
> -	prandom_bytes(blank_key, BLK_CRYPTO_MAX_KEY_SIZE);
> +	get_random_bytes(blank_key, BLK_CRYPTO_MAX_KEY_SIZE);
>  
>  	err = bioset_init(&crypto_bio_split, 64, 0, 0);
>  	if (err)
> diff --git a/crypto/async_tx/raid6test.c b/crypto/async_tx/raid6test.c
> index c9d218e53bcb..f74505f2baf0 100644
> --- a/crypto/async_tx/raid6test.c
> +++ b/crypto/async_tx/raid6test.c
> @@ -37,7 +37,7 @@ static void makedata(int disks)
>  	int i;
>  
>  	for (i = 0; i < disks; i++) {
> -		prandom_bytes(page_address(data[i]), PAGE_SIZE);
> +		get_random_bytes(page_address(data[i]), PAGE_SIZE);
>  		dataptrs[i] = data[i];
>  		dataoffs[i] = 0;
>  	}
> diff --git a/drivers/dma/dmatest.c b/drivers/dma/dmatest.c
> index 9fe2ae794316..ffe621695e47 100644
> --- a/drivers/dma/dmatest.c
> +++ b/drivers/dma/dmatest.c
> @@ -312,7 +312,7 @@ static unsigned long dmatest_random(void)
>  {
>  	unsigned long buf;
>  
> -	prandom_bytes(&buf, sizeof(buf));
> +	get_random_bytes(&buf, sizeof(buf));
>  	return buf;
>  }
>  
> diff --git a/drivers/mtd/nand/raw/nandsim.c b/drivers/mtd/nand/raw/nandsim.c
> index 4bdaf4aa7007..c941a5a41ea6 100644
> --- a/drivers/mtd/nand/raw/nandsim.c
> +++ b/drivers/mtd/nand/raw/nandsim.c
> @@ -1393,7 +1393,7 @@ static int ns_do_read_error(struct nandsim *ns, int num)
>  	unsigned int page_no = ns->regs.row;
>  
>  	if (ns_read_error(page_no)) {
> -		prandom_bytes(ns->buf.byte, num);
> +		get_random_bytes(ns->buf.byte, num);
>  		NS_WARN("simulating read error in page %u\n", page_no);
>  		return 1;
>  	}
> diff --git a/drivers/mtd/tests/mtd_nandecctest.c b/drivers/mtd/tests/mtd_nandecctest.c
> index 1c7201b0f372..440988562cfd 100644
> --- a/drivers/mtd/tests/mtd_nandecctest.c
> +++ b/drivers/mtd/tests/mtd_nandecctest.c
> @@ -266,7 +266,7 @@ static int nand_ecc_test_run(const size_t size)
>  		goto error;
>  	}
>  
> -	prandom_bytes(correct_data, size);
> +	get_random_bytes(correct_data, size);
>  	ecc_sw_hamming_calculate(correct_data, size, correct_ecc, sm_order);
>  	for (i = 0; i < ARRAY_SIZE(nand_ecc_test); i++) {
>  		nand_ecc_test[i].prepare(error_data, error_ecc,
> diff --git a/drivers/mtd/tests/speedtest.c b/drivers/mtd/tests/speedtest.c
> index c9ec7086bfa1..075bce32caa5 100644
> --- a/drivers/mtd/tests/speedtest.c
> +++ b/drivers/mtd/tests/speedtest.c
> @@ -223,7 +223,7 @@ static int __init mtd_speedtest_init(void)
>  	if (!iobuf)
>  		goto out;
>  
> -	prandom_bytes(iobuf, mtd->erasesize);
> +	get_random_bytes(iobuf, mtd->erasesize);
>  
>  	bbt = kzalloc(ebcnt, GFP_KERNEL);
>  	if (!bbt)
> diff --git a/drivers/mtd/tests/stresstest.c b/drivers/mtd/tests/stresstest.c
> index d2faaca7f19d..75b6ddc5dc4d 100644
> --- a/drivers/mtd/tests/stresstest.c
> +++ b/drivers/mtd/tests/stresstest.c
> @@ -183,7 +183,7 @@ static int __init mtd_stresstest_init(void)
>  		goto out;
>  	for (i = 0; i < ebcnt; i++)
>  		offsets[i] = mtd->erasesize;
> -	prandom_bytes(writebuf, bufsize);
> +	get_random_bytes(writebuf, bufsize);
>  
>  	bbt = kzalloc(ebcnt, GFP_KERNEL);
>  	if (!bbt)
> diff --git a/drivers/net/ethernet/broadcom/bnxt/bnxt.c b/drivers/net/ethernet/broadcom/bnxt/bnxt.c
> index 96da0ba3d507..354953df46a1 100644
> --- a/drivers/net/ethernet/broadcom/bnxt/bnxt.c
> +++ b/drivers/net/ethernet/broadcom/bnxt/bnxt.c
> @@ -3874,7 +3874,7 @@ static void bnxt_init_vnics(struct bnxt *bp)
>  
>  		if (bp->vnic_info[i].rss_hash_key) {
>  			if (i == 0)
> -				prandom_bytes(vnic->rss_hash_key,
> +				get_random_bytes(vnic->rss_hash_key,
>  					      HW_HASH_KEY_SIZE);
>  			else
>  				memcpy(vnic->rss_hash_key,
> diff --git a/drivers/net/ethernet/rocker/rocker_main.c b/drivers/net/ethernet/rocker/rocker_main.c
> index 8c3bbafabb07..cd4488efe0a4 100644
> --- a/drivers/net/ethernet/rocker/rocker_main.c
> +++ b/drivers/net/ethernet/rocker/rocker_main.c
> @@ -224,7 +224,7 @@ static int rocker_dma_test_offset(const struct rocker *rocker,
>  	if (err)
>  		goto unmap;
>  
> -	prandom_bytes(buf, ROCKER_TEST_DMA_BUF_SIZE);
> +	get_random_bytes(buf, ROCKER_TEST_DMA_BUF_SIZE);
>  	for (i = 0; i < ROCKER_TEST_DMA_BUF_SIZE; i++)
>  		expect[i] = ~buf[i];
>  	err = rocker_dma_test_one(rocker, wait, ROCKER_TEST_DMA_CTRL_INVERT,
> diff --git a/drivers/net/wireguard/selftest/allowedips.c b/drivers/net/wireguard/selftest/allowedips.c
> index dd897c0740a2..19eac00b2381 100644
> --- a/drivers/net/wireguard/selftest/allowedips.c
> +++ b/drivers/net/wireguard/selftest/allowedips.c
> @@ -284,7 +284,7 @@ static __init bool randomized_test(void)
>  	mutex_lock(&mutex);
>  
>  	for (i = 0; i < NUM_RAND_ROUTES; ++i) {
> -		prandom_bytes(ip, 4);
> +		get_random_bytes(ip, 4);
>  		cidr = prandom_u32_max(32) + 1;
>  		peer = peers[prandom_u32_max(NUM_PEERS)];
>  		if (wg_allowedips_insert_v4(&t, (struct in_addr *)ip, cidr,
> @@ -299,7 +299,7 @@ static __init bool randomized_test(void)
>  		}
>  		for (j = 0; j < NUM_MUTATED_ROUTES; ++j) {
>  			memcpy(mutated, ip, 4);
> -			prandom_bytes(mutate_mask, 4);
> +			get_random_bytes(mutate_mask, 4);
>  			mutate_amount = prandom_u32_max(32);
>  			for (k = 0; k < mutate_amount / 8; ++k)
>  				mutate_mask[k] = 0xff;
> @@ -328,7 +328,7 @@ static __init bool randomized_test(void)
>  	}
>  
>  	for (i = 0; i < NUM_RAND_ROUTES; ++i) {
> -		prandom_bytes(ip, 16);
> +		get_random_bytes(ip, 16);
>  		cidr = prandom_u32_max(128) + 1;
>  		peer = peers[prandom_u32_max(NUM_PEERS)];
>  		if (wg_allowedips_insert_v6(&t, (struct in6_addr *)ip, cidr,
> @@ -343,7 +343,7 @@ static __init bool randomized_test(void)
>  		}
>  		for (j = 0; j < NUM_MUTATED_ROUTES; ++j) {
>  			memcpy(mutated, ip, 16);
> -			prandom_bytes(mutate_mask, 16);
> +			get_random_bytes(mutate_mask, 16);
>  			mutate_amount = prandom_u32_max(128);
>  			for (k = 0; k < mutate_amount / 8; ++k)
>  				mutate_mask[k] = 0xff;
> @@ -381,13 +381,13 @@ static __init bool randomized_test(void)
>  
>  	for (j = 0;; ++j) {
>  		for (i = 0; i < NUM_QUERIES; ++i) {
> -			prandom_bytes(ip, 4);
> +			get_random_bytes(ip, 4);
>  			if (lookup(t.root4, 32, ip) != horrible_allowedips_lookup_v4(&h, (struct in_addr *)ip)) {
>  				horrible_allowedips_lookup_v4(&h, (struct in_addr *)ip);
>  				pr_err("allowedips random v4 self-test: FAIL\n");
>  				goto free;
>  			}
> -			prandom_bytes(ip, 16);
> +			get_random_bytes(ip, 16);
>  			if (lookup(t.root6, 128, ip) != horrible_allowedips_lookup_v6(&h, (struct in6_addr *)ip)) {
>  				pr_err("allowedips random v6 self-test: FAIL\n");
>  				goto free;
> diff --git a/fs/ubifs/debug.c b/fs/ubifs/debug.c
> index f4d3b568aa64..3f128b9fdfbb 100644
> --- a/fs/ubifs/debug.c
> +++ b/fs/ubifs/debug.c
> @@ -2581,7 +2581,7 @@ static int corrupt_data(const struct ubifs_info *c, const void *buf,
>  	if (ffs)
>  		memset(p + from, 0xFF, to - from);
>  	else
> -		prandom_bytes(p + from, to - from);
> +		get_random_bytes(p + from, to - from);
>  
>  	return to;
>  }
> diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
> index 58b94deae5c0..00cdf8fa5693 100644
> --- a/kernel/kcsan/selftest.c
> +++ b/kernel/kcsan/selftest.c
> @@ -46,7 +46,7 @@ static bool __init test_encode_decode(void)
>  		unsigned long addr;
>  		size_t verif_size;
>  
> -		prandom_bytes(&addr, sizeof(addr));
> +		get_random_bytes(&addr, sizeof(addr));
>  		if (addr < PAGE_SIZE)
>  			addr = PAGE_SIZE;
>  
> diff --git a/lib/random32.c b/lib/random32.c
> index d4f19e1a69d4..32060b852668 100644
> --- a/lib/random32.c
> +++ b/lib/random32.c
> @@ -69,7 +69,7 @@ EXPORT_SYMBOL(prandom_u32_state);
>   *	@bytes: the requested number of bytes
>   *
>   *	This is used for pseudo-randomness with no outside seeding.
> - *	For more random results, use prandom_bytes().
> + *	For more random results, use get_random_bytes().
>   */
>  void prandom_bytes_state(struct rnd_state *state, void *buf, size_t bytes)
>  {
> diff --git a/lib/test_objagg.c b/lib/test_objagg.c
> index da137939a410..c0c957c50635 100644
> --- a/lib/test_objagg.c
> +++ b/lib/test_objagg.c
> @@ -157,7 +157,7 @@ static int test_nodelta_obj_get(struct world *world, struct objagg *objagg,
>  	int err;
>  
>  	if (should_create_root)
> -		prandom_bytes(world->next_root_buf,
> +		get_random_bytes(world->next_root_buf,
>  			      sizeof(world->next_root_buf));
>  
>  	objagg_obj = world_obj_get(world, objagg, key_id);
> diff --git a/lib/uuid.c b/lib/uuid.c
> index 562d53977cab..e309b4c5be3d 100644
> --- a/lib/uuid.c
> +++ b/lib/uuid.c
> @@ -52,7 +52,7 @@ EXPORT_SYMBOL(generate_random_guid);
>  
>  static void __uuid_gen_common(__u8 b[16])
>  {
> -	prandom_bytes(b, 16);
> +	get_random_bytes(b, 16);
>  	/* reversion 0b10 */
>  	b[8] = (b[8] & 0x3F) | 0x80;
>  }
> diff --git a/net/ipv4/route.c b/net/ipv4/route.c
> index 1a37a07c7163..cd1fa9f70f1a 100644
> --- a/net/ipv4/route.c
> +++ b/net/ipv4/route.c
> @@ -3719,7 +3719,7 @@ int __init ip_rt_init(void)
>  
>  	ip_idents = idents_hash;
>  
> -	prandom_bytes(ip_idents, (ip_idents_mask + 1) * sizeof(*ip_idents));
> +	get_random_bytes(ip_idents, (ip_idents_mask + 1) * sizeof(*ip_idents));
>  
>  	ip_tstamps = idents_hash + (ip_idents_mask + 1) * sizeof(*ip_idents);
>  
> diff --git a/net/mac80211/rc80211_minstrel_ht.c b/net/mac80211/rc80211_minstrel_ht.c
> index 5f27e6746762..39fb4e2d141a 100644
> --- a/net/mac80211/rc80211_minstrel_ht.c
> +++ b/net/mac80211/rc80211_minstrel_ht.c
> @@ -2033,7 +2033,7 @@ static void __init init_sample_table(void)
>  
>  	memset(sample_table, 0xff, sizeof(sample_table));
>  	for (col = 0; col < SAMPLE_COLUMNS; col++) {
> -		prandom_bytes(rnd, sizeof(rnd));
> +		get_random_bytes(rnd, sizeof(rnd));
>  		for (i = 0; i < MCS_GROUP_RATES; i++) {
>  			new_idx = (i + rnd[i]) % MCS_GROUP_RATES;
>  			while (sample_table[col][new_idx] != 0xff)
> diff --git a/net/sched/sch_pie.c b/net/sched/sch_pie.c
> index 5a457ff61acd..66b2b23e8cd1 100644
> --- a/net/sched/sch_pie.c
> +++ b/net/sched/sch_pie.c
> @@ -72,7 +72,7 @@ bool pie_drop_early(struct Qdisc *sch, struct pie_params *params,
>  	if (vars->accu_prob >= (MAX_PROB / 2) * 17)
>  		return true;
>  
> -	prandom_bytes(&rnd, 8);
> +	get_random_bytes(&rnd, 8);
>  	if ((rnd >> BITS_PER_BYTE) < local_prob) {
>  		vars->accu_prob = 0;
>  		return true;

Are there cases where calling get_random_bytes() is not possible?

-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6c0f1d6a-27e6-5a82-956e-a4f12e0a51bf%40gmail.com.
