Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU7NWD6QKGQEHCN7ATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 663732AF8B5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 20:09:07 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id z62sf2776290wmb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 11:09:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605121747; cv=pass;
        d=google.com; s=arc-20160816;
        b=1LZsQTot6leuhByGtaK+qt94BUc4c5kMSKCbla1RFuTC6/8ZiLKURvcC+oUd0KPwwI
         ma0OrRkdf+Au0/ApGYe2hdyE0NjueiXuiJ3nanfPwmDgLR2BMflPV35BA+iuVjqLgEwP
         CnUYCb4rOeUFQ/O0B0ycifrBL038U6+wpE2KLsxZHw2UFEZzq3LF8JsHwciU2QawrCY8
         bfIsQMV5uV2uEJRxnq2K6vPDZ6yHLwT5yV/a3bDUd09l5Eiqfpjvm0i9FBVdi8ZI29fh
         I09wtGhvKgNlE+2Sc9ffcuTpGxmfcSebgToS5n4kbSWCnZDS25IuCjT5YvaZSVfhmG/M
         NZWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hAPiVcgMo7HIsVL7feFZ2O/D3FA6m9VASpgwMR9PuaU=;
        b=x/MxpBM7a++L4Pgw4iqQe9/eUQicQtoln6c0gr5ztutKe1hNW8sGDvA7BfO5dk4iEo
         FYiLAnCSsBsFHTFrqfMYlP6FoDou2j9iLqUnLivV1szNIs/3IxBQ/WFZOZGd9C3nAJrg
         NBv+nwDBnE5mEmhv9vwJZICswWbZIR+eLiiV6b5qCYpQzjuIzmKu5tbn3YJiyowSQxYz
         QPSRAh38IjZaw4DBfhpkPJW4nkomtyLCB7JDsH/EslC7u+3+aaXtZQ3qmp5kLdoarP+E
         w+EmTRVgCcVuiXsmiZpdJZc7bujoVg6aSUocAjudIhhpVPAQEXkDbPRSJ6f87FChqyY5
         2ErA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K4eTAtSN;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hAPiVcgMo7HIsVL7feFZ2O/D3FA6m9VASpgwMR9PuaU=;
        b=Gc4U2WEXkzqpfpAtHAgKDA9Hr69Xe4FCxz36eqdZx45PkXbapl5K5pHZcO5JRjKPpW
         zBxaLgfcZs092396rrDF5hqEE65mowAgZc14PEdkvLu22+AnbJyiE05nQZ46PY95sbS3
         jbPNYe4zO5Vn6bsaBnkJrVlkIXY1e9x/h4AgeUsD57gwY/LJ77+fNdtLny84e21bJebX
         +Fmp9elMg5yXnR+RzVOC6tqkISVZR3b8nqEKmyCYnXfHmMP/S1vGTPXZrps5NGV03GWy
         gHe5XzqMCWtlBpDq7/Mfa+yb0Ni2tc71tBfLSOtVxfAK+Cd4jYrBeeGHQlibHgX9/MX9
         Ijvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hAPiVcgMo7HIsVL7feFZ2O/D3FA6m9VASpgwMR9PuaU=;
        b=Lh9zRh8PSAcEbTHtDfkaQTyMwkhbOkARQummfv35/2PYAfZdthN31zXb0b8gScDAlr
         eO2AA3aPfvXv9C8EoqeXU4Y7ywIPJb5e1iWzWFlGsgvQLTTb0i4DatU4eaGiY0dZ5uwM
         3hDRDxRF1CwC93Er9bymzrM5E8qxfHXyEXo+Keh/EfTcpiAjSK6xeDEIGorgHE5Ruo4t
         W+7FDBvrI7mAROdpyPerRG9yuMH/YDqH+YPVLgtHWk33RVCINZ7BNFP3hpHXtFnFF3Do
         9eUm0szUgV1d4bqZSbRsbnBToMTpN8Uyq/izdm/q1R11Nx+ppzt9x7KHGAUpned2GFPW
         xuLQ==
X-Gm-Message-State: AOAM53053ZKGkhGniS8sGFjrF8tl0KnY74WW1PcZdVSAjGRBiY9L2nAy
	UdqSWWFq4YQE36rjqEsiEJU=
X-Google-Smtp-Source: ABdhPJytu6My3nfURMklhbnI1cHmoTsTJegbo0ygefR2WWlDK8oldYfUhaFG3duFNCDzp5p1hA6xCw==
X-Received: by 2002:a1c:c343:: with SMTP id t64mr5953850wmf.140.1605121747193;
        Wed, 11 Nov 2020 11:09:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls724765wrp.1.gmail; Wed, 11 Nov
 2020 11:09:06 -0800 (PST)
X-Received: by 2002:adf:e512:: with SMTP id j18mr29842491wrm.390.1605121746145;
        Wed, 11 Nov 2020 11:09:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605121746; cv=none;
        d=google.com; s=arc-20160816;
        b=jMIOs83iVM3D9Q+H615U/lyvBK3KrfF0EN5FgV79TYwmWXNkC1miNNHrkJOH+zPvLT
         2crzf0q6P/kIWQyOx5KCPg4Zquv6068e/6rK0kdd/DiruKhtC/4IwyMCgWqXtEcLX86h
         qTvHtS0FlQ/IR29ex2AHskO7QpfdkkuhFla0vSynfCK5wfpSvvapDBMYg3UeqvUAt/2X
         0BS6bQob/cV3t4MY+I2E16e4LPX5yW/oMy+2tdUR4VJvJS/PxM7H+Roa3Pw/qUSTRIWS
         mNTRZy3qz3e68AfuheDh0Dn1DRPU5fzLNWw1Bc4KPR0RQF4qEKnygYy93GWw4op93j35
         cJug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3pzzdEUXqdlUXkCITd16mcn7xREtcEGzt0MbcAZyF9Q=;
        b=bizUmdCPFcSKsQxFkzS9UzXlNj/N7HGkCpYsWIRQ45EWfEOMR9y6LRenyyHNjr1kQQ
         D++jyfHSEb+QS9wnt3NgAuhQZIYqSt01UyzxnhLeIhRaYg9vOuL0inP+Y2TEj5vhzbQE
         0aVD3yHOocaAGW7TT6vnu5fxkNoresh1RTKR1PH1AmqUx9IsuxbkKdJtfCbMwCPL9fxT
         qSsQhfOKWtSzW2ANhY1CfckU6U9jvwLv3w4vv9PenizHy5npmslfJQSy8GqkadiJ7I3L
         w6fBo860ZY75oVleieH+zyXqCIv8pvNhYBIvNKai6LKY1i2/7SgPDK47MmPwmBQs62jj
         0mbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K4eTAtSN;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id m5si108798wmc.0.2020.11.11.11.09.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 11:09:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id w24so3365517wmi.0
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 11:09:06 -0800 (PST)
X-Received: by 2002:a1c:46c5:: with SMTP id t188mr5871850wma.68.1605121745575;
        Wed, 11 Nov 2020 11:09:05 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id 130sm3739700wmd.18.2020.11.11.11.09.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 11:09:04 -0800 (PST)
Date: Wed, 11 Nov 2020 20:08:59 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 15/20] kasan: don't round_up too much
Message-ID: <20201111190859.GQ517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <b11824e1cb87c75c4def2b3ac592abb409cebf82.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b11824e1cb87c75c4def2b3ac592abb409cebf82.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K4eTAtSN;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::341 as
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> For hardware tag-based mode kasan_poison_memory() already rounds up the
> size. Do the same for software modes and remove round_up() from the common
> code.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/Ib397128fac6eba874008662b4964d65352db4aa4
> ---
>  mm/kasan/common.c | 8 ++------
>  mm/kasan/shadow.c | 1 +
>  2 files changed, 3 insertions(+), 6 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 60793f8695a8..69ab880abacc 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -218,9 +218,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  
>  void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
> -	kasan_poison_memory(object,
> -			round_up(cache->object_size, KASAN_GRANULE_SIZE),
> -			KASAN_KMALLOC_REDZONE);
> +	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_REDZONE);
>  }
>  
>  /*
> @@ -293,7 +291,6 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  {
>  	u8 tag;
>  	void *tagged_object;
> -	unsigned long rounded_up_size;
>  
>  	tag = get_tag(object);
>  	tagged_object = object;
> @@ -314,8 +311,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  		return true;
>  	}
>  
> -	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
> -	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
> +	kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_FREE);
>  
>  	if (!kasan_stack_collection_enabled())
>  		return false;
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 8e4fa9157a0b..3f64c9ecbcc0 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -82,6 +82,7 @@ void kasan_poison_memory(const void *address, size_t size, u8 value)
>  	 * addresses to this function.
>  	 */
>  	address = kasan_reset_tag(address);
> +	size = round_up(size, KASAN_GRANULE_SIZE);
>  
>  	shadow_start = kasan_mem_to_shadow(address);
>  	shadow_end = kasan_mem_to_shadow(address + size);
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111190859.GQ517454%40elver.google.com.
