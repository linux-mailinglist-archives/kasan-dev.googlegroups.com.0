Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTUZXSTQMGQE7WUM57Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A3F078D493
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 11:33:04 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-500777449e5sf6038822e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 02:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693387984; cv=pass;
        d=google.com; s=arc-20160816;
        b=0W42kISaptTV5cy7Zd+r8SJ0Qg2KcirVSawNVkhMDtqPjv8nCF6UiVwUhsowsL4VPm
         GVS1HQGyO1L9+7m/ivC69j1Hl38OdBD0uVDhXblOr58Pcdw86Vd3fE3n3swC5CeDt6x0
         yvjEbiY4CuYJgBltTMr/z/uHs7Mlqs2Tw+J3mfWi8nM9p51YiJz5vrW2nOQUeQC5Epmy
         nKyAH/4a4XValx4cH6xAzc0tQ2GgcSM5LDBtWNO8IN8NGglCdlfR5Jha+Z0KU5v7keIG
         FlYjVk9PVOP1pTYmlv8oszaO3RTBhVFDn/dDs7dtNksF2xWiplUUP0NjqfDKLlYqKEll
         NVAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hx0H2+wtYOPNEdpP/wuLQ3roMD5yv/dJbeVPJ0nrqtw=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=zNAGTLc1rYndsK4P5vIYHINpYNaFDaWfBsdo0IaM6as75i4bwfVOYvmoy2/p7+ncBc
         Wkk/iwiJMPuEWc5ZMnlbkKRzLDDnBg7oxuT4nLviQNz+MlLAcoGXpk+KcD7Y9qK0P++q
         Go2jfuyrvbA5eYhVxv2K4SeSF/pnQNbYQyAGM5jAta+51yOzVMHMTr7IzgtHG34f9m3W
         RXKSMA2Rv5Wd8DNGuXRrikYEhNleUQRBZPxj8kzwtP1+iVDVBQ7ShonrDiXrmNgl0v6P
         4YIaM+n53bswrLEqU8hbfdYtwniTXj/E4sSWr9fmEVhyLUzYDGJq0KynFfI3GUFZdKL6
         n1oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5kzKBmdi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693387984; x=1693992784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=hx0H2+wtYOPNEdpP/wuLQ3roMD5yv/dJbeVPJ0nrqtw=;
        b=CsPZPJdLZaYa/qwK+ARfC284zOCz3woXGw+IPVHzWiV1D9I8yGPQwcZ5teGPtLd9OG
         yQ4h2NREblMDJpj0MbsI1ghZvTMnQQf3AvcxO5E64orAbPT1jMFcrtCeM34T84+4tm7l
         Krxls5HYTVgK9jKec2aEt2+F2Dbar7r1EcVT2BI2BDANaA1DBRoOmaJ7piAVY+3WhCnn
         rRgYbMztV6HMJwsx02rzQHf7dCIQkSqcAJsav/aTHa92dRDPygGaUXTU6jeNPaAHVDYI
         BEfh+KeQ41ArE6MzVHTyVzTPHKXBIu81Gr+Tfh+3fICN4Oh4cUyeYbvyPaGZgToGBOEU
         MD/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693387984; x=1693992784;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hx0H2+wtYOPNEdpP/wuLQ3roMD5yv/dJbeVPJ0nrqtw=;
        b=SxfF4PQF17+6Ebb7l++WCqm8B47eOjSEEChNY/7X3n/qwM8QE2c20V3kV+vmxKaLIE
         wc/EGqI4AUjZL+7LxT2IQTT0aKYO7JB6uyLuiYuG0u5jcjzWmLpJ69v3rfyEuSUWQN3g
         3BhjOg3E8qKiYONvXNSIvGD04pSZtOC0NWzMivjJQifu9xEwCSmiU+2FkTcOgv7dO2Ji
         2avhr2wUfTrnribqkgTjl5SZn66wegXBQvf7TzsMrYqb8lb1mieZbYUve6lV+QU212Mr
         zGBoooazcpQTopLSJxtXelbJaw3g8wVCcdtJzAYz3QylX7eRjNRTc5Ujv9b1p3YScYu5
         /LfQ==
X-Gm-Message-State: AOJu0YwGWftPoXIgHjSE9Uoey9FaItlTiS/XesBpnT8/7h9ypcFzbj5k
	N78DS1EUQa1e7Y6Kvf3tFBA=
X-Google-Smtp-Source: AGHT+IGEq2IhcUv+pJ4Mr1nzZiZUgfeulgHrd+QyghzfdYRuXV4SQdLCLxYJHtS2Ja6pL7qMRWBinA==
X-Received: by 2002:ac2:5f4d:0:b0:4fb:fe97:5e35 with SMTP id 13-20020ac25f4d000000b004fbfe975e35mr1014120lfz.47.1693387982966;
        Wed, 30 Aug 2023 02:33:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:5014:0:b0:4fe:1116:70d1 with SMTP id e20-20020a195014000000b004fe111670d1ls1652352lfb.0.-pod-prod-09-eu;
 Wed, 30 Aug 2023 02:33:00 -0700 (PDT)
X-Received: by 2002:a05:6512:a83:b0:4fb:8bab:48b6 with SMTP id m3-20020a0565120a8300b004fb8bab48b6mr1064713lfu.52.1693387980831;
        Wed, 30 Aug 2023 02:33:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693387980; cv=none;
        d=google.com; s=arc-20160816;
        b=guvHvErzSJbFlYUXWGdx8SDtk7TIciFOpaJl/jd4AP7Wvfk9f4ADUljcfLk+WHm4bf
         TLRo2qj0LSVCtBVmOUEDNuNKDLUBjYwTdLO2XXP1UfzDDFSnEeoqa01LVLa3ThbLZqz/
         mERwq8lnZZpMl97Ki/Cryf1k/QsZ6Ul5gc3ZTj8tg7cPLa5LmJ9IkJ5QkLys7hEoec7p
         ZFmeIAMM7y6SDXyhswg1w1TqXTx/cUMfJ/Zm8maQhvB5bqFqCAk9inCKMAdiYFy3Ypm8
         uwZAcO8TQ9JRFCCve1D6UfEZPXTHtOJQElgdDG+4G7gHgYbUieoGAfwSlD2iuG2TX1DN
         rzHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1/pN5Sj2lXQgLLmHsNhZTE0RFeJiDl6tBaSGS7xws0g=;
        fh=kVNHuK6sH0u+sBJWWlQLGzcqa7WwSE0AcR3KrlGWuEY=;
        b=Expp+eOZx7uex3peCrezt0rpj9jFHaxsD6xi4Wk7nuZV/t0ThKC3SNMGLPX0PBolxR
         OY26KJGbZ6G3y595TlYyTYcw14g51c/q2HRhuhMMF5+I4NXjKL/y6T8pAtCZ8XdhnBX9
         0fbQNJ4Me9ZjQeW2LK7HIzR6kkyR+28NSXrLcDf9THKO1o0OiUXcNKM8YifjNl7xd4LF
         DteYGCH/ss+6qotmpUv/K2b6NHFfk9gAQlst4BeR2xiRFe0542S+Yfi85WffiugBhD6f
         Bn8Jqenn/upRFNKhwOyCHjZgljHfGALrNNKZrLMIYwjJhHiKS3b7o+tncr4ajf6UZzty
         1zDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=5kzKBmdi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 23-20020ac25f57000000b004ff9e56b934si812756lfz.7.2023.08.30.02.33.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 02:33:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-3fef56f7223so48134515e9.3
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 02:33:00 -0700 (PDT)
X-Received: by 2002:a1c:7217:0:b0:401:b53e:6c57 with SMTP id n23-20020a1c7217000000b00401b53e6c57mr1358749wmc.9.1693387979964;
        Wed, 30 Aug 2023 02:32:59 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:3380:af04:1905:46a])
        by smtp.gmail.com with ESMTPSA id m18-20020a7bce12000000b00401dc20a070sm1668612wmc.43.2023.08.30.02.32.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 02:32:59 -0700 (PDT)
Date: Wed, 30 Aug 2023 11:32:53 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 12/15] stackdepot: add refcount for records
Message-ID: <ZO8MxUqcL1dnykcl@elver.google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
 <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=5kzKBmdi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
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

On Tue, Aug 29, 2023 at 07:11PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a reference counter for how many times a stack records has been added
> to stack depot.
> 
> Do no yet decrement the refcount, this is implemented in one of the
> following patches.
> 
> This is preparatory patch for implementing the eviction of stack records
> from the stack depot.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/stackdepot.c | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 5ad454367379..a84c0debbb9e 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -22,6 +22,7 @@
>  #include <linux/mutex.h>
>  #include <linux/percpu.h>
>  #include <linux/printk.h>
> +#include <linux/refcount.h>
>  #include <linux/slab.h>
>  #include <linux/spinlock.h>
>  #include <linux/stacktrace.h>
> @@ -60,6 +61,7 @@ struct stack_record {
>  	u32 hash;			/* Hash in hash table */
>  	u32 size;			/* Number of stored frames */
>  	union handle_parts handle;
> +	refcount_t count;
>  	unsigned long entries[DEPOT_STACK_MAX_FRAMES];	/* Frames */
>  };
>  
> @@ -348,6 +350,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  	stack->hash = hash;
>  	stack->size = size;
>  	/* stack->handle is already filled in by depot_init_pool. */
> +	refcount_set(&stack->count, 1);
>  	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
>  
>  	/*
> @@ -452,6 +455,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>  	/* Fast path: look the stack trace up without full locking. */
>  	found = find_stack(*bucket, entries, nr_entries, hash);
>  	if (found) {
> +		refcount_inc(&found->count);

If someone doesn't use stack_depot_evict(), and the refcount eventually
overflows, it'll do a WARN (per refcount_warn_saturate()).

I think the interface needs to be different:

	stack_depot_get(): increments refcount (could be inline if just
	wrapper around refcount_inc())

	stack_depot_put(): what stack_depot_evict() currently does

Then it's clear that if someone uses either stack_depot_get() or _put()
that these need to be balanced. Not using either will result in the old
behaviour of never evicting an entry.

>  		read_unlock_irqrestore(&pool_rwlock, flags);
>  		goto exit;
>  	}
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZO8MxUqcL1dnykcl%40elver.google.com.
