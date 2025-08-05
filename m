Return-Path: <kasan-dev+bncBCSL7B6LWYHBBV7ZZDCAMGQE3QZA42Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 63048B1B922
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 19:18:17 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-55b9f899bd5sf1264040e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 10:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754414296; cv=pass;
        d=google.com; s=arc-20240605;
        b=PgF0Ywhp2D/JCdKVwfeHY/bCCuDLGYIDX6K4flsZCWgq8dlLDNkvuafaNK86hHN/L9
         Fs0gk/WVDFLAM/FyBMFWau/Hp3ze88mwqFPRhTJX23fx+BGhjXK41l+I9KrBtFZL2bQW
         UhEfaw3Hz0VuSNvV0lsmqZZAFByTDPTNW7UbjA1ssagMGgc4iNpduHgYNI55E33Zy1dG
         GZn0rqrcGxzbA7aK9txPQcSkZercrHaC58WJR1SDqIUtm8X3mg3DUT0fyVVeiYSGicVK
         tkrv2y2MT4e9MPZhCHTQPDbBVvK63ovbZHJwKnQO1jNV2V8+ADuMEzOC7NRhVPu1L/l4
         yewQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=6saut6sgkPjCP1Xp/f9jTViyoiCf55F79ItlRfN19yw=;
        fh=kI9gHLD8D/ge0vZlXRsoz5btMOdMbdfEwVwJZFZKzp4=;
        b=HZJptG9f/zwrJTrqhcySxkVBE7wLnb0ETN5krGuJi7h+cJ0KNUQOf/zTIHcoTPaHw7
         EU47/ada7KLJlJ76X/Ju+VA9d43tsjrZ9BoqQ8dIqy0aIKhkjgBKWYZO6/sKxI5lxqov
         UmLRk8YIJtx3peQ41CKTGR/gDsscWjByStBd4mpMpUoy+zpJxlRx9mT5IqVxMKRZv9Mt
         XfC/I/HyfXIDRhUJ9GXCbzVmlBmMZjNX0nij/OhwqLKLHLrubqmA9cx2ouOQ/7u9ysc2
         zBUnIn5UWAQEZcUyzhkIje1G3KB/ebSggZ0doS8Gb1UkhZK5LXl4BK5PBAZdGHpA5PPP
         FoEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hanzDFLM;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754414296; x=1755019096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6saut6sgkPjCP1Xp/f9jTViyoiCf55F79ItlRfN19yw=;
        b=OKAX6nqfxkXoQMSKgDoAIZW4GilaeL6m2Ggy33b+x/IZ0ONraLgPyRkOiwyQX1CpjQ
         ALTg6tKO2TRNhAVpxHryo8mHS70FMLdJgxvdZDaa3uguOZhwadXq95H8y3+6BAzBQ4Lp
         houwJs51xMkb7ovlCeMdOaz92l3OmJomgoQmmUOti1KsG3GNtL4YdSGTBg6ekBnDTuxf
         eTHu6cooetuw1TEYaA/G6IWsZtK+GUBVQmdwa/s38BQDKlvsuD8u1Q/WptKkNaRxBOHl
         XenqSsXmD4FHOP/1idz1dEHyXxfT3twMJ3NNGX1P2TtaidPNN/tgRFzPHNqKaQqA44+o
         S2Jw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754414296; x=1755019096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6saut6sgkPjCP1Xp/f9jTViyoiCf55F79ItlRfN19yw=;
        b=QjFNTzrHriuoo7ZueB5pE5mvTtSm/jDIcimmJs49aEPRlYG+EtDf/+TBHNOiZziJqj
         IzK1pDe1VW60HDAhqquz6pWbGRCJlVP99xNM2J7rbVoFUp/dMCo5Lne8WvdshP9EzORp
         etx0JuxTUGc5qLOzDQyccuuM4tDJc8wrTJ+fjF0iJNW68OB1hcS99X/fv8JvjwjIo4Ci
         tE0kJZVXIljYE2swHrQxmVCP3p/g6f7EwFuUtW+BbaskPa51GtoZa+HQienO64lc21xN
         7U1DbhnM8LfPR04BKKvoY8Ha0FTfCabNSYP/UckVb7WZ5Ql4rTf2Im/8asv6qEooU5Cg
         hDlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754414296; x=1755019096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6saut6sgkPjCP1Xp/f9jTViyoiCf55F79ItlRfN19yw=;
        b=FuWoQb/RngJU+i79AT37S5WevnejM6DrQLZOfgw80dYARRRva32xiV/QKP98Z7fnM2
         amIfOHM84jlTJiMDXUJ3DCe+Arrt4OFlh3+KR8e5jevNA+fFpJIRYQmyOJ5cLjJEEsfi
         j3bM2UCiov1nkfOGhZJFgzLVHo6cHPyMTiA6bYH4qPArXp4o/bPG8C9l2UK35bkbRcPl
         WRPz12+6I+NJ12G9bgJJfMJk00Lk/gXqj0Emapki19jCZ1yIb0plkCNWBIqbdksE22U9
         ZS2Tt+ekQBRp8GShfhI56FxI3Mnrf7WcohH1pTfDB81wcAOYd/5n816yt4kHfC0MmbTE
         KwKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLnWquiLwg3d6Swltbl7UZpjmGLvIz1niESDG5EViVFIk5DxZY3RlZze/nnQBVNKvV2Y6Shg==@lfdr.de
X-Gm-Message-State: AOJu0Yz5ipOB7qYGt4gg5Ze6RQW7RzVRT/QSyQ3Fq6PNiebG81N74hXB
	HBeRwDFvuD5qXVG8v/TUFYVx0G6zQ6SLRWwFSJlVQCFyjPpUq9Sdrfuy
X-Google-Smtp-Source: AGHT+IHw+ciDzBitn2uai714uZ73iWxjN5FZ7q7AoAPDw/6eiGVFRLRVtlOK0RcpYh5eqSd5C/rd8A==
X-Received: by 2002:a05:6512:1111:b0:55b:8849:425d with SMTP id 2adb3069b0e04-55b97b57a42mr4370750e87.38.1754414295887;
        Tue, 05 Aug 2025 10:18:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdKIcGd1hy23J8UdmROPQHUhhSa2ceH7NYWYcre/PAJCw==
Received: by 2002:a05:6512:6719:b0:553:66c0:cc33 with SMTP id
 2adb3069b0e04-55b87adbc43ls1569206e87.1.-pod-prod-01-eu; Tue, 05 Aug 2025
 10:18:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtBiruKrakzTT612fSYz7ZKxVCcJO7L80SPz5oNRZrIfceVoIkWR940sQiBj4zBK4tB96tqErZPlM=@googlegroups.com
X-Received: by 2002:a05:6512:3e0d:b0:55a:90b:7a37 with SMTP id 2adb3069b0e04-55b97b83e92mr3910382e87.50.1754414292640;
        Tue, 05 Aug 2025 10:18:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754414292; cv=none;
        d=google.com; s=arc-20240605;
        b=Gce2rV7I4+HTM8V+RNEpiiCCjZGyIj4TvK6bvUlOmKwVDjVwHUuCzSFqRyP2Oq44/b
         bZQNTdf+Nkd6jqlaXEi5WFPCLRAds6W00hkIOgiZSBMugKtL/w7RG0Wust1rq9s86FIa
         Ph8bdE5c0zZszRNND5UBk1h4Hsui0bJUN1NbpU+X+Adxj93bZJBD4u6MVLdFvFNi/YQ0
         mEwwKkcQOCg6yzn5Gn8Zsjep9oSgt3oM8kCuMeCfXuWxq2K3ulFQrQhsIlqgP5A9Uqi0
         XHUg2hSOXVBoK6/310aVqgFHztpym2w9+ODhmb5xzAaa5dmkiLD6wwPAOv3rxsYLIX+0
         pBOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=RZ2R+1+DK7TrYxovSWYDOowvbSOnIqHJEfLqNkyHn6I=;
        fh=8f/S+TBfejjQc+wNyR0OgorEY7CixHOtUxpTsiQWBIk=;
        b=RULr/IFLuTiuZlwO977rQ6khlhcr8oHfbB+wM/CPv8IcwY/KcnYjCW4Erx1l5DuGRF
         +qH/FqyS9iQa6OBw2NKu+dVbBX8kFmVXBTYCmaP+/Kh/wN729fBK7+1pk3W5q8ivxnNb
         quy9GmvdEfqQu+PgoaurEZIdbmm/NMkrRUaypzFC/tN0EPUnFN8xDK7EsYxgfVjU+XFM
         0nq7tLudblrFk7kDhYGQj44PYz9V2EZyTTiqJv4yDuV2TxLr59qFmOg3zKnkn+MNcBt3
         0pTN0fjjRWxWz6Ptsah2ZFcrdSr668m5ohZlmPXKdhFTa1TH9wgsvJfd695UwDfWbq8L
         LV7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hanzDFLM;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33237fffb5fsi3361061fa.4.2025.08.05.10.18.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 10:18:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id 38308e7fff4ca-332341d99dbso9826151fa.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 10:18:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV99wYf3Ux/azjUlf3on/SEgvTv2Z3OylUYaPRQwL04msZt6kXMsXF/0GA8qhouwmmq3iwTXHyelJw=@googlegroups.com
X-Gm-Gg: ASbGncswb5dF/xWlazV24SXZRynHMtFm9hpg/5lwwBI0ruWGCagl68HwJ/tKDOSm9G1
	+CKd1Ts41y3hTneY7xNglWWAobORfrOC1hdP1H3pRk6RAWNPLIuDOLM25I8PWqKZNmsZute6rdg
	M5N1v47awRmNdi+aIJ8WKMtLRFfFi0H6lL5P3up/LS5FU/oYAWe6tvYKICuHY6+u9TrxA9tM8Aa
	LNuKtozFmMDjlsGxDH8efdiQGNsM9UDTsfzXosat0ddFjUH7s5ECeRQ+aXTcM23zw2/jZpTKcjJ
	x8SzNcq8Lm2wOQqGRXXJxPZ+6ATFnab2whuREaqox7J6EAhXH7X9oQUyqw2wmCeRQhPA7q7v4DB
	Zofg0y/y8Vnq6mEO/m4E3x59eMyIqrq+uJteJwTxVIb1QIYGAYA==
X-Received: by 2002:a2e:be24:0:b0:32b:5a24:b9d8 with SMTP id 38308e7fff4ca-33256856534mr14686731fa.8.1754414291879;
        Tue, 05 Aug 2025 10:18:11 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-332382be4a7sm21072541fa.32.2025.08.05.10.18.10
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 10:18:11 -0700 (PDT)
Message-ID: <e15e1012-566f-45a7-81d5-fd504af780da@gmail.com>
Date: Tue, 5 Aug 2025 19:17:25 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 5/9] kasan/loongarch: select ARCH_DEFER_KASAN and call
 kasan_init_generic
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn,
 trishalfonso@google.com, davidgow@google.com
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250805142622.560992-1-snovitoll@gmail.com>
 <20250805142622.560992-6-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250805142622.560992-6-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hanzDFLM;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::22d
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
> LoongArch needs deferred KASAN initialization as it has a custom
> kasan_arch_is_ready() implementation that tracks shadow memory
> readiness via the kasan_early_stage flag.
> 
> Select ARCH_DEFER_KASAN to enable the unified static key mechanism
> for runtime KASAN control. Call kasan_init_generic() which handles
> Generic KASAN initialization and enables the static key.
> 
> Replace kasan_arch_is_ready() with kasan_enabled() and delete the
> flag kasan_early_stage in favor of the unified kasan_enabled()
> interface.
> 
> Note that init_task.kasan_depth = 0 is called after kasan_init_generic(),
> which is different than in other arch kasan_init(). This is left
> unchanged as it cannot be tested.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> Changes in v4:
> - Replaced !kasan_enabled() with !kasan_shadow_initialized() in
>   loongarch which selects ARCH_DEFER_KASAN (Andrey Ryabinin)
> ---
>  arch/loongarch/Kconfig             | 1 +
>  arch/loongarch/include/asm/kasan.h | 7 -------
>  arch/loongarch/mm/kasan_init.c     | 8 ++------
>  3 files changed, 3 insertions(+), 13 deletions(-)
> 
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index f0abc38c40a..f6304c073ec 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -9,6 +9,7 @@ config LOONGARCH
>  	select ACPI_PPTT if ACPI
>  	select ACPI_SYSTEM_POWER_STATES_SUPPORT	if ACPI
>  	select ARCH_BINFMT_ELF_STATE
> +	select ARCH_DEFER_KASAN
>  	select ARCH_DISABLE_KASAN_INLINE
>  	select ARCH_ENABLE_MEMORY_HOTPLUG
>  	select ARCH_ENABLE_MEMORY_HOTREMOVE
> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
> index 62f139a9c87..0e50e5b5e05 100644
> --- a/arch/loongarch/include/asm/kasan.h
> +++ b/arch/loongarch/include/asm/kasan.h
> @@ -66,7 +66,6 @@
>  #define XKPRANGE_WC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_WC_KASAN_OFFSET)
>  #define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
>  
> -extern bool kasan_early_stage;
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  
>  #define kasan_mem_to_shadow kasan_mem_to_shadow
> @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
>  #define kasan_shadow_to_mem kasan_shadow_to_mem
>  const void *kasan_shadow_to_mem(const void *shadow_addr);
>  
> -#define kasan_arch_is_ready kasan_arch_is_ready
> -static __always_inline bool kasan_arch_is_ready(void)
> -{
> -	return !kasan_early_stage;
> -}
> -
>  #define addr_has_metadata addr_has_metadata
>  static __always_inline bool addr_has_metadata(const void *addr)
>  {
> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
> index d2681272d8f..57fb6e98376 100644
> --- a/arch/loongarch/mm/kasan_init.c
> +++ b/arch/loongarch/mm/kasan_init.c
> @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
>  #define __pte_none(early, pte) (early ? pte_none(pte) : \
>  ((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
>  
> -bool kasan_early_stage = true;
> -
>  void *kasan_mem_to_shadow(const void *addr)
>  {
> -	if (!kasan_arch_is_ready()) {
> +	if (!kasan_shadow_initialized()) {
>  		return (void *)(kasan_early_shadow_page);
>  	} else {
>  		unsigned long maddr = (unsigned long)addr;
> @@ -298,8 +296,6 @@ void __init kasan_init(void)
>  	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
>  					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
>  
> -	kasan_early_stage = false;
> -

There is a reason for this line to be here.
Your patch will change the result of the follow up kasan_mem_to_shadow() call and
feed the wrong address to kasan_map_populate()


>  	/* Populate the linear mapping */
>  	for_each_mem_range(i, &pa_start, &pa_end) {
>  		void *start = (void *)phys_to_virt(pa_start);
> @@ -329,5 +325,5 @@ void __init kasan_init(void)
>  
>  	/* At this point kasan is fully initialized. Enable error messages */
>  	init_task.kasan_depth = 0;
> -	pr_info("KernelAddressSanitizer initialized.\n");
> +	kasan_init_generic();
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e15e1012-566f-45a7-81d5-fd504af780da%40gmail.com.
