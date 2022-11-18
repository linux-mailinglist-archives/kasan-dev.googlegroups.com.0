Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBRV63WNQMGQE4JL2LJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id A635662F29A
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 11:32:39 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id k1-20020adfb341000000b00238745c9b1asf1409879wrd.5
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 02:32:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668767559; cv=pass;
        d=google.com; s=arc-20160816;
        b=WOAy3ZQRcALuaraHn57egSN8bK8LnYqMKpmzbCTJnN7KxdjZhlvgDT39zHEtBY/ShU
         o+2iVRFj6sqSqMn8dN/morNfUUX0HqzUzB8ODScCuuJb7m2EIEjfzu/bjJl6eCItRkT0
         /FEbWKG1nYiznm+GdpCatfc0MQ1GUToZrmCtvEbAS9hW7H5Bd2x9Au/dA+7IHaLNddjt
         vmkVABZow2nlx3CNyQN38VXCp6kEGrYUVXUjjk/FMUP1TbQYx1TmD0yio29xqn6PgWw2
         NDbKccRCp8jSR2C1tXv53hVtXXgbVSiWJ12/STzi7SiXOBQqzOFjjyI+mbZFTyO12q5W
         BEPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=a4h+FAZ/oHLDUediB7E04ZgfubiFnTSTk/h/KtG6zoM=;
        b=UTlQYqtR8Nny4G3xd/y/S3o7QvmH5uSHObsLYpdHvZ+Q/MBYSKFG1tG+Gsfra4xqn+
         XESPiOdesRbS81f54o/4Yc0/qgd1XhC6BaFlasqbgp/oreIrB0mj66UbSpgfa9ZuCFu5
         yRAwAhtCu8XJGilB34hxfWzJ28jfxBakkgoxrLYxn4dg8SIpdcEq8QPt35/ehrlam3Qa
         cHeSB5m7dloVXLz5axix700h03Bjlm5QFCclYR4EVOZZfD+Ii59RKEPDjf2Kn420aZX/
         0Sp8Cm7qJUTocIFknnVz9qrAsfHGvv8vEb5iyW8SIGAOc7yOev2la1bKsLTj0oen6GDY
         76NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g8xwvhAw;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=a4h+FAZ/oHLDUediB7E04ZgfubiFnTSTk/h/KtG6zoM=;
        b=a6dtrwTLd0aRQzViwdUKUZ6/35Dm5yNOQuEeP+et8k12e6pq34/DLCFfgyWqxTb5S0
         5Z8+ffGXkxE+5+dGpEIfv9Vgit5ZpdG0XNAmmX1P0CdHH8VKN0CP5XrlJGA6lxZEM/OH
         FaqyvyTE3LycvXhlpKjGTO+1kj6Wmmr8P0eorsoSESSShnkM4YXD+AvVmj1NmhlentnR
         n2v+YQtrMTSUQahf8HGkgUv/9BMJb+tuSVg3IWyIVAxKBuPPZrdV0y+O7OzIcntyyk3P
         XdP8R/oW6qpvRiNTuSQqP2E/EnJ2ULrk8oJScHU4x5g7bVBrx/VGglS6oHe1I7JsVtRB
         +jCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a4h+FAZ/oHLDUediB7E04ZgfubiFnTSTk/h/KtG6zoM=;
        b=pQqIb32srFlIqIV9um2b7oDCTXP4zkPAMds8PnAAaq7OtsOtlbedqV3BFOP80cbH/9
         5Puy9H0GqbzTCoNdlyTmK+M+wLbgLUFCdnIpIfls7/vyYoTLRGdkWvNb2mDsm/QAgq9M
         N5fvjcWciu8mC5EP86bU5XhyepZpvxA525N04LDVBudWO6xqGacDFs8eOW6Y47lBZjAd
         2fofTRZaeLYr39pr83cGsX8W7P92qoRHyBEd1z58lRABfV8ZTx3NYlaay7CiILalcfRZ
         5WrtD7cmm8qJxj/U29zodpfpAiIXHsAP5CYSZuaPIoWGNvRu3WihERtW+5/RX52d2ORI
         EbnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plC76I6WKKXA3HUclatRzlwtMMmY3CWHf4jtALbFozqtlzJw5JQ
	uM2tetHcrylN3SQuHd5t2aM=
X-Google-Smtp-Source: AA0mqf7xMc4qHy0UTIs4CiI1JJG6IdBCLqdqplkWwf6/+a7f8i1X98KCwuXauEH1CC6dHSTs/QSSkA==
X-Received: by 2002:a5d:54d2:0:b0:241:c224:201e with SMTP id x18-20020a5d54d2000000b00241c224201emr1210801wrv.43.1668767559148;
        Fri, 18 Nov 2022 02:32:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1f9a:b0:225:6559:3374 with SMTP id
 bw26-20020a0560001f9a00b0022565593374ls4236885wrb.2.-pod-prod-gmail; Fri, 18
 Nov 2022 02:32:38 -0800 (PST)
X-Received: by 2002:adf:d219:0:b0:236:599b:d09c with SMTP id j25-20020adfd219000000b00236599bd09cmr3940354wrh.433.1668767557860;
        Fri, 18 Nov 2022 02:32:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668767557; cv=none;
        d=google.com; s=arc-20160816;
        b=a3TnIQnDf2PTitDHfVlegsTPlxeTaR9Aq4dXzO12Nf5Hs50d1QMcxADqE0QFX5LRPh
         /xz1o9F5gNS5NXr/jvlYlYKB8BJs0RiaPonlipm0Kf45n19MkkHIa77O/L1k05na2nm9
         SLVGpveU7PJL/Y/QlIWJF4I2oINiEbTTHy5KZ9ym2K9SwRWKSdLFmKydwhWoB6VpMWVQ
         88HqteNS9isPx96gwoPUWEcBsKs5ukjHzK6Rj+PNRFLXPcGsmt5tsDKGgI2dqfahKdjr
         MF47sWyqMLBQqlXIOJjbSPz6hu8BKFEZAOMsz6sRwFepnKDMw/yF0wW13AZpyUWWQt3F
         YClA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=XzHJXeK3Q2/Bx013Ighw0ir5MysszSUlvQpViISJqBs=;
        b=O+9lMICQ+JXWpFXSUQ+yXXCpNkwWLDX69xh2lsF4sTLbxdGWWIptPSAnySVZiOBs+d
         QRErNs13lg7ox34tXctqe77ac/lpgrfkik4ZRhQRD9zjBbYBz9DmUUbQhgkHdXJL2rIV
         kOtiAGuMfhyfbQ/pIXL8tDSdGo2HQsyiqIK9MELIAQk12J1i5sLJY7dSiak+qIlz/Vgw
         tsHrDH+9WPDy7k/6AExzIYVZr3/He6IOlW96OcQdEEDPA0NS9qiCFr4TejecggTvaGlc
         d/rKyiRTzAOomZgUNZZqW2MNrdh1+be4yJ10OMBbHoe/uRgEuh4ccGHUe74EuThaYqcv
         NYJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g8xwvhAw;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id v4-20020a5d59c4000000b0023675b014acsi107355wry.6.2022.11.18.02.32.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Nov 2022 02:32:37 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7D77F1F890;
	Fri, 18 Nov 2022 10:32:37 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3C66113A66;
	Fri, 18 Nov 2022 10:32:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id XG5tDUVfd2NwRgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 18 Nov 2022 10:32:37 +0000
Message-ID: <230127af-6c71-e51e-41a4-aa9547c2c847@suse.cz>
Date: Fri, 18 Nov 2022 11:32:36 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>, Andrey Konovalov <andreyknvl@gmail.com>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20221118035656.gonna.698-kees@kernel.org>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221118035656.gonna.698-kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=g8xwvhAw;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/18/22 04:56, Kees Cook wrote:
> With all "silently resizing" callers of ksize() refactored, remove the

At cursory look seems it's true now in -next (but not mainline?) can you
confirm?
That would probably be safe enough to have slab.git expose this to -next now
and time a PR appropriately in the next merge window?

> logic in ksize() that would allow it to be used to effectively change
> the size of an allocation (bypassing __alloc_size hints, etc). Users
> wanting this feature need to either use kmalloc_size_roundup() before an
> allocation, or use krealloc() directly.
> 
> For kfree_sensitive(), move the unpoisoning logic inline. Replace the
> some of the partially open-coded ksize() in __do_krealloc with ksize()
> now that it doesn't perform unpoisoning.
> 
> Adjust the KUnit tests to match the new ksize() behavior.
> 
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Pekka Enberg <penberg@kernel.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Roman Gushchin <roman.gushchin@linux.dev>
> Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: linux-mm@kvack.org
> Cc: kasan-dev@googlegroups.com
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
> v2:
> - improve kunit test precision (andreyknvl)
> - add Ack (vbabka)
> v1: https://lore.kernel.org/all/20221022180455.never.023-kees@kernel.org
> ---
>  mm/kasan/kasan_test.c | 14 +++++++++-----
>  mm/slab_common.c      | 26 ++++++++++----------------
>  2 files changed, 19 insertions(+), 21 deletions(-)
> 
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7502f03c807c..fc4b22916587 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -821,7 +821,7 @@ static void kasan_global_oob_left(struct kunit *test)
>  	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>  
> -/* Check that ksize() makes the whole object accessible. */
> +/* Check that ksize() does NOT unpoison whole object. */
>  static void ksize_unpoisons_memory(struct kunit *test)
>  {
>  	char *ptr;
> @@ -829,15 +829,19 @@ static void ksize_unpoisons_memory(struct kunit *test)
>  
>  	ptr = kmalloc(size, GFP_KERNEL);
>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
>  	real_size = ksize(ptr);
> +	KUNIT_EXPECT_GT(test, real_size, size);
>  
>  	OPTIMIZER_HIDE_VAR(ptr);
>  
> -	/* This access shouldn't trigger a KASAN report. */
> -	ptr[size] = 'x';
> +	/* These accesses shouldn't trigger a KASAN report. */
> +	ptr[0] = 'x';
> +	ptr[size - 1] = 'x';
>  
> -	/* This one must. */
> -	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> +	/* These must trigger a KASAN report. */
> +	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> +	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
>  
>  	kfree(ptr);
>  }
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 8276022f0da4..27caa57af070 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1335,11 +1335,11 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>  	void *ret;
>  	size_t ks;
>  
> -	/* Don't use instrumented ksize to allow precise KASAN poisoning. */
> +	/* Check for double-free before calling ksize. */
>  	if (likely(!ZERO_OR_NULL_PTR(p))) {
>  		if (!kasan_check_byte(p))
>  			return NULL;
> -		ks = kfence_ksize(p) ?: __ksize(p);
> +		ks = ksize(p);
>  	} else
>  		ks = 0;
>  
> @@ -1407,21 +1407,21 @@ void kfree_sensitive(const void *p)
>  	void *mem = (void *)p;
>  
>  	ks = ksize(mem);
> -	if (ks)
> +	if (ks) {
> +		kasan_unpoison_range(mem, ks);
>  		memzero_explicit(mem, ks);
> +	}
>  	kfree(mem);
>  }
>  EXPORT_SYMBOL(kfree_sensitive);
>  
>  size_t ksize(const void *objp)
>  {
> -	size_t size;
> -
>  	/*
> -	 * We need to first check that the pointer to the object is valid, and
> -	 * only then unpoison the memory. The report printed from ksize() is
> -	 * more useful, then when it's printed later when the behaviour could
> -	 * be undefined due to a potential use-after-free or double-free.
> +	 * We need to first check that the pointer to the object is valid.
> +	 * The KASAN report printed from ksize() is more useful, then when
> +	 * it's printed later when the behaviour could be undefined due to
> +	 * a potential use-after-free or double-free.
>  	 *
>  	 * We use kasan_check_byte(), which is supported for the hardware
>  	 * tag-based KASAN mode, unlike kasan_check_read/write().
> @@ -1435,13 +1435,7 @@ size_t ksize(const void *objp)
>  	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
>  		return 0;
>  
> -	size = kfence_ksize(objp) ?: __ksize(objp);
> -	/*
> -	 * We assume that ksize callers could use whole allocated area,
> -	 * so we need to unpoison this area.
> -	 */
> -	kasan_unpoison_range(objp, size);
> -	return size;
> +	return kfence_ksize(objp) ?: __ksize(objp);
>  }
>  EXPORT_SYMBOL(ksize);
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/230127af-6c71-e51e-41a4-aa9547c2c847%40suse.cz.
