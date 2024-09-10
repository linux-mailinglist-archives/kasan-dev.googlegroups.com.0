Return-Path: <kasan-dev+bncBAABB7FVQC3QMGQEPNYBHBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 3183397313F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 12:10:06 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-7a80b9f8771sf108860885a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 03:10:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725963005; cv=pass;
        d=google.com; s=arc-20240605;
        b=VJpM5CO5Nxf36kWcg0RbMsc1qGfdjJ0PzKJafmY9GbY+Hn2Q/CDZrheURl+GnfKKeS
         6MIdyCn338hlhQnz/BH2kWjRPW0V8zHd5rTUIPEa8NDjNwsun7UII2BUv6Rc7sef7H4R
         d6Px9rZD1GhejkMAiGhuF+us87TDotJjE5PZBbAWPwJSSi+1G1abZOqnUlMJjRmS2+LQ
         9AmANd+AcVngR8f8+D0QeZFsM412STTI8aqu+RWwgkSN8Pr+vb4n8YrCqPMT/nLgZRBU
         uvVpZC7vuU5U1smh/5jnTJj/1di3jDNWWnhdc8rJit59E55gqPD8Qv9dINb++09xhdsy
         lATQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=NVS8efyMuJvcwM5Oge9qLEtKO/DeWQNjsgEp8lNRwIY=;
        fh=PelamxlWC/VfOM9a/XX35qRiC0vtbHJRy75E1pp22Cc=;
        b=gfkTocZpLAQzQ+dMVgJoO6j7qDlDLusqkyGavw7YSNhg/Q9pCrLBq159BMFgfgM+EE
         A/t9Yr8swcGpWPvCnpfqcvFr98KG306cz1Uvpv0/6TjkoRx3HIyCNuvFdw3qv/OwgDkx
         AvH1RzuBmxNZMjLl/9QAKBXulQcVNsgORUIDDlzzegblWy7kG8Ebi5GvEPX3SVNzgfak
         n1TzuuHj/bomiRjqwzfsiBtli/ln9o8f8BUgxk6iXtHA3gAYqbP1vRaRVTvjK0YKG0gh
         mIW1ZZdVE8zc6zbY7goCwqDHzpVX1a/zWkXI4pr9lG6BlyG49lB660KZ1UKZk7IjjrtO
         YeVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jkMysAmN;
       spf=pass (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725963005; x=1726567805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NVS8efyMuJvcwM5Oge9qLEtKO/DeWQNjsgEp8lNRwIY=;
        b=IlLXIgsVEtgSyn1vzcwgHehaHG3EwJdpXfa+2XAaKYg7aLb1I0+hbt4oqc2a867OIg
         GBf9OQggco/RqPzwUdVqBa7xvthI9yuTGTo0xbcCRQvd+x5TFlCc6UrOos0HKk+A9gNQ
         EPzTcFX+7fPxbKMwEmeAf/p8/mDc5c3jjSM8gcQtjHfOMqeh+z5LudXz0d42Fe+CLQC6
         O3IplebJ4hUo9VoG3PjCVenHTGI5zwcqLK5GTGf73jSK+SMvMRI6pVeXj/Zya8VbPBWO
         9nF68QgxLWYwU7T/1tJc+1+/2gVYzo7/gkMtpaRV/+gFGHf7AZaZRs3XLFdDlU3agITE
         KCVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725963005; x=1726567805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NVS8efyMuJvcwM5Oge9qLEtKO/DeWQNjsgEp8lNRwIY=;
        b=w5b0oAelGatgamIeF92j8N2QUFrT+Yqn1gEkPQEt/rQ+bqVKQ2h6kSfGGZeUDhmKgk
         P6COpWUn9JfSgNC/UKpLDBsJeQtr9hwfjFQxzYvSjAXW12/m+CAnook8W4tNtLaJwIRv
         RHIORfxP8dzN+aXvwfsM+dD7NVsqZm6nV2rd2D/6A4+8d3hnqS0UVPK1wfZGrzbik9R6
         rHPCgKjZs50DNH2VkIfLpXPF/wgNQlK9/iapMh4f+3sh6lEy1SykQlf55HShwyty0p8S
         bKd7AKQx2fV++Z3ZsAr1cxDDYejbCBC2mX39yWVFmIfodMUE0+snSX5tL85r2mYPyIaL
         hV5g==
X-Forwarded-Encrypted: i=2; AJvYcCVsURJbSo1iP8biU9vvO1EVIro6Y3B6Oix8N7J5eXnScwJiEBTSTC/O77/T349nnOFtzz0yvg==@lfdr.de
X-Gm-Message-State: AOJu0YxZ6zHuaJx7o9PxcJiUg9H/Qw5bnToEG/6NQR00beouzcZsUk0q
	ELzMT/jpQacUvGSklRIZ9RRSzP0Mm04UbHwRvUlBYr9e71mpTno7
X-Google-Smtp-Source: AGHT+IFOBElrwIzJuAP8nShZRyy51YEP6viN6pOtkjXCBZhx5TvvAMkPLRIUiBtmJEYx/D+a+knJuA==
X-Received: by 2002:a05:6214:418b:b0:6c3:6de3:fa06 with SMTP id 6a1803df08f44-6c5323e1f1emr135320116d6.9.1725963004760;
        Tue, 10 Sep 2024 03:10:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1314:b0:6c5:1c54:7283 with SMTP id
 6a1803df08f44-6c554d5f0cfls13163096d6.1.-pod-prod-03-us; Tue, 10 Sep 2024
 03:10:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlJai/oSVpnYysPLvlVpkxwhs5PaFCA76JRJhw1xbiQJs6PrJbw8Y8xFFvCNLOAUPJSO3WAM9Ma4g=@googlegroups.com
X-Received: by 2002:a05:6214:4306:b0:6c3:5946:ea0b with SMTP id 6a1803df08f44-6c5323e28a9mr133407736d6.11.1725963004210;
        Tue, 10 Sep 2024 03:10:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725963004; cv=none;
        d=google.com; s=arc-20240605;
        b=ZJ5Y4OL8jMoQcJFPXl6sAcde/APqNZRiVAkF3L4Vp+ZhEtUIvRoYt3XHwLnEiThkkQ
         7a10CjhqSlAdeTJ8zeOLrhL37vs3W0Uzkgxc1FNp/CrLIHN1TJn3tq5zqErr42+xsMHr
         lHVuqk69HI+pzXZK1ZHm/x8Ezqy46CuV+UAY4hrJm5BEy1iSGp1n75quKuAbTnyw1JxH
         Bviv3pzxIafMPqAT2I0SSRay44zqa26AX4hJjLDesWaNpy7xaePDHP/cXegADuGD1Wb6
         gRfTYA0HFycAsVvIzgHkXcBJ5UbxxUIpTuKXiSsxqyoc6xDKn3Ba989tiMXOG+djzMQP
         5fCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ToHfxJKUDW+fB118lwo/I8pw2qWsaWqyNmDco0o/OMo=;
        fh=p/5McWUtjK+qScMwUrO14iqiNHfhg8r/y+oykbgK3/0=;
        b=kEqqCAe+IckxKinmaO6Hd0fAzzsyw/w/VGKIwwzwljXQEPaTOiz+LiUWPwVLcxTAMq
         VDEK7bJXbNHxBpt+99vjclNRsst8PXHZ6ANVb3QVBY7Kwocpdtzgz7rCZe41zBfBIyO/
         DyqAvRpUFgFmGSEm8ZujGw9wuYfMDX3PCllfYwHqxs6s7wNGJfhQbhgXxWjnBi2eZS/R
         KlJbVGqQB+v2B7EkRZwqJhuAVM6R6qnvvnxvYXPBA46/JCPnj28F5ue9MkdxLL8ZSWUD
         ZJ0x7uwlYpQKWLBEkCR7EsFk3on4wdzI13OEPWTOo5XQVhAXMfhO32tNr/ozBBy2yVKT
         CUwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jkMysAmN;
       spf=pass (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=dakr@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6c534266c96si2853726d6.0.2024.09.10.03.10.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Sep 2024 03:10:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2858E5C068A;
	Tue, 10 Sep 2024 10:10:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2EE6AC4CEC3;
	Tue, 10 Sep 2024 10:09:59 +0000 (UTC)
Date: Tue, 10 Sep 2024 12:09:56 +0200
From: "'Danilo Krummrich' via kasan-dev" <kasan-dev@googlegroups.com>
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 5/5] mm/slub, kunit: Add testcase for krealloc redzone
 and zeroing
Message-ID: <ZuAa9DxCNwvFsZ50@pollux>
References: <20240909012958.913438-1-feng.tang@intel.com>
 <20240909012958.913438-6-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240909012958.913438-6-feng.tang@intel.com>
X-Original-Sender: dakr@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jkMysAmN;       spf=pass
 (google.com: domain of dakr@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=dakr@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Danilo Krummrich <dakr@kernel.org>
Reply-To: Danilo Krummrich <dakr@kernel.org>
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

On Mon, Sep 09, 2024 at 09:29:58AM +0800, Feng Tang wrote:
> Danilo Krummrich raised issue about krealloc+GFP_ZERO [1], and Vlastimil
> suggested to add some test case which can sanity test the kmalloc-redzone
> and zeroing by utilizing the kmalloc's 'orig_size' debug feature.
> 
> It covers the grow and shrink case of krealloc() re-using current kmalloc
> object, and the case of re-allocating a new bigger object.
> 
> User can add "slub_debug" kernel cmdline parameter to test it.
> 
> [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/
> 
> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Feng Tang <feng.tang@intel.com>

Reviewed-by: Danilo Krummrich <dakr@kernel.org>

> ---
>  lib/slub_kunit.c | 46 ++++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 46 insertions(+)
> 
> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
> index 6e3a1e5a7142..03e0089149ad 100644
> --- a/lib/slub_kunit.c
> +++ b/lib/slub_kunit.c
> @@ -186,6 +186,51 @@ static void test_leak_destroy(struct kunit *test)
>  	KUNIT_EXPECT_EQ(test, 1, slab_errors);
>  }
>  
> +static void test_krealloc_redzone_zeroing(struct kunit *test)
> +{
> +	char *p;
> +	int i;
> +
> +	KUNIT_TEST_REQUIRES(test, __slub_debug_enabled());
> +
> +	/* Allocate a 64B kmalloc object */
> +	p = kzalloc(48, GFP_KERNEL);
> +	if (unlikely(is_kfence_address(p))) {
> +		kfree(p);
> +		return;
> +	}
> +	memset(p, 0xff, 48);
> +
> +	kasan_disable_current();
> +	OPTIMIZER_HIDE_VAR(p);
> +
> +	/* Test shrink */
> +	p = krealloc(p, 40, GFP_KERNEL | __GFP_ZERO);
> +	for (i = 40; i < 64; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
> +
> +	/* Test grow within the same 64B kmalloc object */
> +	p = krealloc(p, 56, GFP_KERNEL | __GFP_ZERO);
> +	for (i = 40; i < 56; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], 0);
> +	for (i = 56; i < 64; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
> +
> +	/* Test grow with allocating a bigger 128B object */
> +	p = krealloc(p, 112, GFP_KERNEL | __GFP_ZERO);
> +	if (unlikely(is_kfence_address(p)))
> +		goto exit;
> +
> +	for (i = 56; i < 112; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], 0);
> +	for (i = 112; i < 128; i++)
> +		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
> +
> +exit:
> +	kfree(p);
> +	kasan_enable_current();
> +}
> +
>  static int test_init(struct kunit *test)
>  {
>  	slab_errors = 0;
> @@ -196,6 +241,7 @@ static int test_init(struct kunit *test)
>  }
>  
>  static struct kunit_case test_cases[] = {
> +	KUNIT_CASE(test_krealloc_redzone_zeroing),
>  	KUNIT_CASE(test_clobber_zone),
>  
>  #ifndef CONFIG_KASAN
> -- 
> 2.34.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZuAa9DxCNwvFsZ50%40pollux.
