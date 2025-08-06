Return-Path: <kasan-dev+bncBCSL7B6LWYHBBC5UZXCAMGQEU774CSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CA21B1C6DA
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 15:35:09 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-61563bdc8dasf6368896a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 06:35:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754487309; cv=pass;
        d=google.com; s=arc-20240605;
        b=OK0acDyr0bPKh7S0IchBcXhiN5Psivz3Ddqy/1gunPRStvgi7oJks2UDx/PajT407e
         +fOJOPScs9YKlq/8qFZsl5is8OWaCF8UJPbxuSJKRKQcg8tnnsYYO6VgxZ9s4cTYfZE2
         hIsl3DzAon+Mqi2Il/H1mpFA2EFOrU+851i37HAGdetr9qsLzZ+OifL5GI4RgAws3j8e
         rvnZF+lGnwd3WVRkvpqZpwS5edxgRVRCG3lN6sn08L12/xRkDFp9aP5+A7uGrx+dU23z
         Y4SbCM0WOZHtBr4EXTxkM5pE9OaXXeSHef6ddMtvUTQIynalGEGnckDlKfs8t6HiOawW
         thMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=KzSNPTupZsIDHHi21UWBFTecHX5eoWRUvqt3u/uV8ek=;
        fh=yDNZ2P6z4Qc7d549D6X2oTPhd9/BfULycmKGJHSpyvc=;
        b=h7k8hlOzor1a8/u6584VedpB8LiVC6Yux9UYLuKTWCV1wdsTZUAml8ARO2X+2ZgMIM
         h0DJoRa40SZNlgnNouleO+2tj4qbdBDGX+FThMQx3cRUK36kZL/xRdOcUH6uqGTgXK2w
         5EEeOF/CjlusrBkZsz1c/XYrjnyQ3ucOq4rsd06ph/GSK5cqLRcXcuGC17DjVyoi+4vQ
         Xckl2+xG57IWvDjYY8PBs/ipD0TgVaVVvpSZxhooHlFYnZzzEnF3psZfGqECQv2SOFDm
         Nb8QgvWLrQAs0UgEbYyMg+izG+bGjgmgIPPjfb/dgw9LQMyfZolhuwjpqCB+bDe8YJKU
         fxWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nUnkHDnB;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754487309; x=1755092109; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KzSNPTupZsIDHHi21UWBFTecHX5eoWRUvqt3u/uV8ek=;
        b=uiRjEGWpIuEaX9GVjiZyGcRR62tGjTTfFexd2y6W+ct8loD7+lzRed3o83YXk14AMr
         WhygQJcSzsU531irlP/+Q73jZ2JwBXqfHYaqsdq79U+l6LJjm7W7itEA1HcxS/MwWyWZ
         JHJba4gmQEVqEI2fmP8poh3VKA99XbyRJE6nOTIMvOVTp1lC9f3qurNVTbQJ6NzeZ1zv
         6irE0bowB9kyTLg0GfNDIwt7A131bllvk2q3b8nK6lap5tJioxUjTYnFEebooCqjJgsR
         S6Sirt0D+sH15lyT9QGCgGNscto1RaXC0i5kI/vN6t4m7HGWJ7NAGv1tipYnCQXJZ5zU
         ERtg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754487309; x=1755092109; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KzSNPTupZsIDHHi21UWBFTecHX5eoWRUvqt3u/uV8ek=;
        b=Xmaz5O4+obcDS8I89Z4nCpWneqSZ7N2VwKhN9UYI9kxG2cw6P0CvFp331j8dDbFK0g
         jdmRBnS94DyAr5IGIujAal+hz8k2QcSujRGt6s0p2ompKWSX2EkpfSKy3wJbHQOGyfue
         ASCs6zTng03+Wf6IHSXNiHQp7Spf3tX8UtcPN+TkX8aCcQEcQFSP+m+culjOJHoyd4Ui
         zRy+6nDHDgsUwT64yhZqxVuP+Qf2B4BlbP2FO4PHDRIz4jnsHpTAH5yRgKClUjBjKaph
         VKJtBjFEl6VqI+bjYtBCErL3sT52HFoS+M45Y3h2komIBiO+0QUeon+VBVE68Tg5ztC4
         TQ2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754487309; x=1755092109;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KzSNPTupZsIDHHi21UWBFTecHX5eoWRUvqt3u/uV8ek=;
        b=AJAOjqgdV7ZRxR1QXGQesjAdISY0IMVc6oCYsRhv15JN3bI/J/owlbdMaqyZprVDsX
         cc1Z/4rHQ9BNlGWrLg8wF7R4j0YXezw/RlDXzBF5OQZdtWjcPu0Trh4NKGx0bDqjT119
         NZkSuMvgS1UrxkJrNM0FYTyLxvI/YQYydxUCOgzPb2CoTUGNOV2UaGA4jWzk3D6ewZCK
         v/ilRQIPluG/8xrcDwVNFTEJlUg0CynH/vNMVQoxZFm41GU+pWrxURknkoBSlPNooCOw
         zjj6rTdI7rfT5R79lRkgtlRIQqrCd6KCAqrj7zuUtBQGl0eBt0UCfgliR53porNhxjRy
         Lbqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPgEBETbLpn8P8oxw0xfhy5m93R0A9wy+g+H5R5K8WyGxHy0akI+ZOVWPJuvzosxaIZaxTAw==@lfdr.de
X-Gm-Message-State: AOJu0Yz4U6rEcPs9H+TqLQ8qupFG2PbOxNh/deFYbCWNn3inUitbD2Bk
	ahdsFkaUmZb9poxgcE8zlZss8Clmd5OeE3qhQr9jlgqKpQRju4iQQjiX
X-Google-Smtp-Source: AGHT+IHAKAL2sGPw9EZ6iUKQz7Q3i8YuwiMGcShT5x6NTxwUVMnCdYF9q6dJQ4t5YnBKAbfM8l1bBA==
X-Received: by 2002:a05:6402:5208:b0:615:37ed:b255 with SMTP id 4fb4d7f45d1cf-617961c751amr2824892a12.30.1754487308331;
        Wed, 06 Aug 2025 06:35:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfXPzjkHu+AfmMUbL/ZsDfwIbr7NBJ1SX39CFJwW98Jww==
Received: by 2002:a05:6402:26c5:b0:615:39c7:3951 with SMTP id
 4fb4d7f45d1cf-615a4febd1els5590163a12.0.-pod-prod-01-eu; Wed, 06 Aug 2025
 06:35:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVShm/7XIVeplMZwPbTwQfWAL45ekczUaNg3mjxO1eC5He7Czp91cHz/5ydLavBQwX5Luu/v+gvg+A=@googlegroups.com
X-Received: by 2002:a17:906:7955:b0:af1:1dfd:30f4 with SMTP id a640c23a62f3a-af9903cbadamr259672166b.47.1754487305300;
        Wed, 06 Aug 2025 06:35:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754487305; cv=none;
        d=google.com; s=arc-20240605;
        b=gQvZ+k5XoKDaZdFkspCtUeAnXw0aFLbMOg9gCm6Yyaowv8hFm4ECiSdPtyv+0M1/5r
         BEIvmplpefg682Ak02DwIrmtsNPNhy14f5eF1qJvpfyGpWpexozMxZg4BPWQpcU6BMJ1
         gA6TPmwXEDKJAEKzt6Q7QLsIyfEMCUfWy+AgouTCuKk+1wB716vsNq1DfcM8fiYuId+w
         cNzsWjxGUMYWqMuaKMcOQktaivufcHCE3joYLQ2R3HjJNRW51WOo2lWCyzeH/ydGd048
         sPe0ixBQo8RNOBiTDnZ5D/c2gGOfa6LueYqQ8O/SXkxgDuihj7P845CME9bW/MZbrS8d
         ESSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=GkBywKSK+jarcaDEWkMpZ6690o3qyLvHV2Ljs5N+BnY=;
        fh=WA6I+eYHrIoprLgM2jFZk97fT8xJy/1kEtPiELzYGGA=;
        b=LcO4qFuFq56eo0w9q78hiQ/vMLWN8gV5/HC9U4T0kWBUqWWtBTy8jZ794UoOOoF8dj
         0OgplyG5K7ODczmMmPsRlNEW4fu8wkWj20W6CpwUAPi8osNe0TcjA2Fnh2OPMWDZU+Lk
         kVosx4EbdI2JE60u5ghYMXJ/66lHilXQe6MfeZKPEDBx10021DM+b9uww2bF4XZvy4i9
         jtmb1tbu6GLx4+D5K9PDIrFzED8pDhwgZHgFhfwbdIrFGDFVDmfaB3q1nIwnyottyx6G
         OWI2GIqsHLHBhAGS85Sqi9aC9LQCOsNtrBZQc/PkYDeDq2C8ZQF+u7Fg5floqtwx1s5i
         Vq8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nUnkHDnB;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af91a0c4398si37143366b.1.2025.08.06.06.35.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 06:35:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-55ba2644bdaso562221e87.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 06:35:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWw2jSEVARGlXgIiCQz4GVm89cxuyihU9/c58iUs6YQIRo54sEUDU0jM4Bjo5SQ8oN/VQZWVimDCoc=@googlegroups.com
X-Gm-Gg: ASbGncuK4yapUbxwqN5Bf3IxQ1PHdt/nafW9uu3ZUoSTkdbrHfcLdlCEZ0w+Ub0DI4E
	RIUfheYlYrHV9fB17sYxJYXijre/A0EwvyZMde6j+Bf1joekdd9G8/6CRyieNDZU/ziKcgvLOhx
	YUB1E7cKiMp74gA3B+OnKtaaGa3Bpbi/ibn1/uJ/Yhpy8rMIGTfy7xIPkLh3+ckp4YyWxnx1fR2
	QXA9MGwwbqRXBJVzVR0+oCujkn1/h0fSkhZHPW10lwSluXceC8PTD9R4dgCsYfieNBLUS1vL0PM
	JG03lbBGDJzm3bw658P1h9BVfpvZCdtd8zB8r9OfReJKGdLg1Zjf20s/GuzIygbzwo9AwkvwV9P
	US5ZfX5S3tpp+KItbIdIXxteCopi7
X-Received: by 2002:a05:6512:ad1:b0:55a:4d9e:6536 with SMTP id 2adb3069b0e04-55caf2f956dmr417291e87.2.1754487304191;
        Wed, 06 Aug 2025 06:35:04 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b8899ebd2sm2302283e87.42.2025.08.06.06.35.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 06:35:03 -0700 (PDT)
Message-ID: <5a73e633-a374-47f2-a1e1-680e24d9f260@gmail.com>
Date: Wed, 6 Aug 2025 15:34:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 1/9] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn,
 trishalfonso@google.com, davidgow@google.com
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250805142622.560992-1-snovitoll@gmail.com>
 <20250805142622.560992-2-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250805142622.560992-2-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nUnkHDnB;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131
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



On 8/5/25 4:26 PM, Sabyrzhan Tasbolatov wrote:
> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures that need
> to defer KASAN initialization until shadow memory is properly set up,
> and unify the static key infrastructure across all KASAN modes.
> 
> Some architectures (like PowerPC with radix MMU) need to set up their
> shadow memory mappings before KASAN can be safely enabled, while others
> (like s390, x86, arm) can enable KASAN much earlier or even from the
> beginning.
> 
> Historically, the runtime static key kasan_flag_enabled existed only for
> CONFIG_KASAN_HW_TAGS mode. Generic and SW_TAGS modes either relied on
> architecture-specific kasan_arch_is_ready() implementations or evaluated
> KASAN checks unconditionally, leading to code duplication.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> Changes in v4:
> - Fixed HW_TAGS static key functionality (was broken in v3)

I don't think it fixed. Before you patch kasan_enabled() esentially
worked like this:

 if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))
        return static_branch_likely(&kasan_flag_enabled);
 else
        return IS_ENABLED(CONFIG_KASAN);

Now it's just IS_ENABLED(CONFIG_KASAN);

And there are bunch of kasan_enabled() calls left whose behavior changed for
no reason.


> - Merged configuration and implementation for atomicity
> ---
>  include/linux/kasan-enabled.h | 36 +++++++++++++++++++++++-------
>  include/linux/kasan.h         | 42 +++++++++++++++++++++++++++--------
>  lib/Kconfig.kasan             |  8 +++++++
>  mm/kasan/common.c             | 18 ++++++++++-----
>  mm/kasan/generic.c            | 23 +++++++++++--------
>  mm/kasan/hw_tags.c            |  9 +-------
>  mm/kasan/kasan.h              | 36 +++++++++++++++++++++---------
>  mm/kasan/shadow.c             | 32 ++++++--------------------
>  mm/kasan/sw_tags.c            |  4 +++-
>  mm/kasan/tags.c               |  2 +-
>  10 files changed, 133 insertions(+), 77 deletions(-)
> 
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> index 6f612d69ea0..52a3909f032 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -4,32 +4,52 @@
>  
>  #include <linux/static_key.h>
>  
> -#ifdef CONFIG_KASAN_HW_TAGS
> +/* Controls whether KASAN is enabled at all (compile-time check). */
> +static __always_inline bool kasan_enabled(void)
> +{
> +	return IS_ENABLED(CONFIG_KASAN);
> +}
>  
> +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> +/*
> + * Global runtime flag for KASAN modes that need runtime control.
> + * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
> + */
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  
> -static __always_inline bool kasan_enabled(void)
> +/*
> + * Runtime control for shadow memory initialization or HW_TAGS mode.
> + * Uses static key for architectures that need deferred KASAN or HW_TAGS.
> + */
> +static __always_inline bool kasan_shadow_initialized(void)

Don't rename it, just leave as is - kasan_enabled().
It's better name, shorter and you don't need to convert call sites, so
there is less chance of mistakes due to unchanged kasan_enabled() -> kasan_shadow_initialized().


>  {
>  	return static_branch_likely(&kasan_flag_enabled);
>  }
>  
> -static inline bool kasan_hw_tags_enabled(void)
> +static inline void kasan_enable(void)
> +{
> +	static_branch_enable(&kasan_flag_enabled);
> +}
> +#else
> +/* For architectures that can enable KASAN early, use compile-time check. */
> +static __always_inline bool kasan_shadow_initialized(void)
>  {
>  	return kasan_enabled();
>  }
>  

...

>  
>  void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
> -int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
> -void kasan_release_vmalloc(unsigned long start, unsigned long end,
> +
> +int __kasan_populate_vmalloc(unsigned long addr, unsigned long size);
> +static inline int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> +{
> +	if (!kasan_shadow_initialized())
> +		return 0;


What's the point of moving these checks to header?
Leave it in C, it's easier to grep and navigate code this way.


> +	return __kasan_populate_vmalloc(addr, size);
> +}
> +
> +void __kasan_release_vmalloc(unsigned long start, unsigned long end,
>  			   unsigned long free_region_start,
>  			   unsigned long free_region_end,
>  			   unsigned long flags);
> +static inline void kasan_release_vmalloc(unsigned long start,
> +			   unsigned long end,
> +			   unsigned long free_region_start,
> +			   unsigned long free_region_end,
> +			   unsigned long flags)
> +{
> +	if (kasan_shadow_initialized())
> +		__kasan_release_vmalloc(start, end, free_region_start,
> +			   free_region_end, flags);
> +}
>  

...> @@ -250,7 +259,7 @@ static inline void poison_slab_object(struct kmem_cache *cache, void *object,
>  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>  				unsigned long ip)
>  {
> -	if (!kasan_arch_is_ready() || is_kfence_address(object))
> +	if (is_kfence_address(object))
>  		return false;
>  	return check_slab_allocation(cache, object, ip);
>  }
> @@ -258,7 +267,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
>  		       bool still_accessible)
>  {
> -	if (!kasan_arch_is_ready() || is_kfence_address(object))
> +	if (is_kfence_address(object))
>  		return false;
>  
>  	poison_slab_object(cache, object, init, still_accessible);
> @@ -282,9 +291,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
>  
>  static inline bool check_page_allocation(void *ptr, unsigned long ip)
>  {
> -	if (!kasan_arch_is_ready())
> -		return false;
> -


Well, you can't do this yet, because no arch using ARCH_DEFER_KASAN yet, so this breaks
bisectability.
Leave it, and remove with separate patch only when there are no users left.

>  	if (ptr != page_address(virt_to_head_page(ptr))) {
>  		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
>  		return true;
> @@ -511,7 +517,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
>  		return true;
>  	}
>  
> -	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
> +	if (is_kfence_address(ptr))
>  		return true;
>  
>  	slab = folio_slab(folio);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5a73e633-a374-47f2-a1e1-680e24d9f260%40gmail.com.
