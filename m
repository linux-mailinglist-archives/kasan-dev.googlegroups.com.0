Return-Path: <kasan-dev+bncBDXYDPH3S4OBBW4NQG3QMGQE42HHHCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F18E97386F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 15:17:17 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-53661526719sf424521e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 06:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725974237; cv=pass;
        d=google.com; s=arc-20240605;
        b=kwBZyvL+tqbWJ0PUgiAqGI2lVjpSRO3T2QKpg7EaFHfIJ2+IT0rDAAubq4w7c6oVor
         IpWW4tZGbOe7TxrYfUMUSFYcZkRa31J6rvUX9mLb4909FHdjkwvZMG/6TAmTnGCJuxcp
         eHgYWXImye+8mbi9o+0s874zZa/SA5nFZfgN6M+5zsEfHXY/YKiR61pspi06J8EBXrVf
         NRtZ59PeGG2+EmwWL97jriGW6tC/aYNhmiyT61/BpF8cS0lU0YSXA51sxS9LXoWUquv9
         LUzePWYZs6IrPaRphP59NUbTbgpfUNa00rBw5Syn46//O8BU5QYklMql/iClneLKriT3
         WAtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=HX28VKC7/+Vo6jRQjc3xDFhBQB9lJquZpSUcKhauLL4=;
        fh=4LLl/ONvGcyFHwcCrJQEfwSDod85unWXqWwcLqqdx9g=;
        b=hjSa6jAAhay/KmclyZI8cHlZuemlxDffUsA9KKr8jgZp8BvlxRQIiVb9q6csXA6yKJ
         55rViZOeNyJm3CuxdxzRaGu1JxQdHPfyrpxmwg95FuZ8NyRuSjaUMmAP6Q29EOslIqnF
         QXhbMFbTScq/6TTls8aOnNPW1jOXxgnjCm8q7e7KRIQ+NqE0Y8FHJOzZH299x08R2zkT
         LcQQFpqPNINDtdF1rl7pz57b10cjbTo6R7S7U+qJIcucdrnmQyMe7MOr+XgBfFqEUO9t
         NaVJ/ya+0VsLIe5TVGWfkk4bDIR1bLqQcoWbDduNgZIeJPdHoC+BpXrj0Id8Fyd3+xf0
         NHtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aiqJxqDO;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=GZelPNQF;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lnB3oJnH;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725974237; x=1726579037; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HX28VKC7/+Vo6jRQjc3xDFhBQB9lJquZpSUcKhauLL4=;
        b=xhn7vpUTkafKqT8x8pQo35Pw5LpN+oMsvF2chvzUS4m+J7ubiteHemEfhNJAlb5hBt
         nLYHO0L5tnkq3IFTx4PrVNaJXzKHnXNgXgm1MbqG0LuynSIPnGhKtLLMwaQ1jZRX/Vln
         8u4MyfizkcpXT9JwVRTiL9VcBBZJhLRAdns+5NiuIIAYXSAV1H0s+Hjce20ySb8CRDw+
         PxUdA7tGtxo+Syk9Btptsp5gkgZhdpoDka0gypO8PUudGa4RXQI1S8BvRNc9GcWZi877
         t5RNVRStWdlTCNrNYI/gdlkInrzS6CyK1R3m4dlWwz5qesLfZEJUnoznDrzUqbh7HTKS
         rX3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725974237; x=1726579037;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HX28VKC7/+Vo6jRQjc3xDFhBQB9lJquZpSUcKhauLL4=;
        b=PQTmt6epZ1/fxHxVHY9+jgS/hiaRLFYLAlSoxrQ2heJLEXXLJmfeYFl5fVEgChYD99
         t5sTHByS2UTbzS4gno9kl39OJWASc2/GE04HzVY7XmwNn7XQYSK0vFCVf8FnWiIp/KcP
         /tDINalwGJ9tHDZ6yJNF13e+zYXtH9WiS44z1ZgaRYbgx3Uo9Dcoqz7QkajFhA+I/acE
         hs9JJiNOUy4PY/gkwFip4NXFGHt69cJkP0jSP9xW/wi5IruwvFSsZ6hY+doUZbESCPXN
         IeoDkoYJ533OP17h0TdzMVkUFRtYHHJBtUS70n35FtFnj5LZ9Ilic3TFwDsBeGHBxx7z
         pLrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6zptZcF4TnAqRMA/m4PqEBpTCfUxiALdiPhsV7OMAZEgPRwvpex3/vyr3KnIlP7i+n6AzdQ==@lfdr.de
X-Gm-Message-State: AOJu0YzrBVjxbNoo5GEFubIKOGaKTiHYYnOutmSq2bPR3cX4nUu7rouF
	dD6k5ROm+aGpIrbM0WqzkqDmHb5VRI6fPpKOHZBEQnbQKT4hxLOr
X-Google-Smtp-Source: AGHT+IHpKYnKSeqnW3F+hvQiFLBbSRVUlk9cRCH8SsRBqjjNnzMCeCK1VLrp4M80CndqrPTlm0W5WA==
X-Received: by 2002:a05:6512:6cf:b0:52c:e086:7953 with SMTP id 2adb3069b0e04-536587aa733mr8697422e87.4.1725974236066;
        Tue, 10 Sep 2024 06:17:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e1e:b0:52f:186:fdc8 with SMTP id
 2adb3069b0e04-5365784e79fls514543e87.2.-pod-prod-08-eu; Tue, 10 Sep 2024
 06:17:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFFykgV/xh3T2MUXc4uanVG3ccJiz3/i0kvI0UZAlWEUvCCzTx6FwT/03DaDIeHEtHDl68pRn+AwU=@googlegroups.com
X-Received: by 2002:a05:6512:3d09:b0:530:b871:eb9a with SMTP id 2adb3069b0e04-536588067b5mr8993004e87.47.1725974233888;
        Tue, 10 Sep 2024 06:17:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725974233; cv=none;
        d=google.com; s=arc-20240605;
        b=KxH4anx97DmtV1zT5t9JOLvShTKNSGCSZE96a5vY+0HyvFvzD9e2qMTHZ27mw1psvQ
         92ibb7BSH5OQUKh+k+v6bNvTDfRw3wBipL7NZ6pYJga1zov5eNBF9aG4RcSTfmpteITV
         MdUlMWAnuW3lZXpNJQ6swNoT0au45vf9bpU66sosqVQciD7m9yUwTTURInyPpnfNi7zf
         u5gM4D587aW0U3r8LeT2kmFPiqtNyxYXFPx2b+DK+b7d27oQkiYlMUpT5GYDsYhjyVnT
         fWPW2PowTlPLzbH5DoeOOb4hO+onKPoBYLj5YftjHM5CtpXH7J0QsZTYNAN6x1zBSnC8
         BDpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=iRV9z4RKePmWSHFei7LBoPZfAEv2b3gzpKq/qXRIvZ4=;
        fh=0xRBb/eFYt1OwNgyWpv0boRELUlsWEBHSNu42J9xXtM=;
        b=Zq2QdKA8LzSattSvyHR1uHm6VaW7tGP8MAAmrrAV545SXYTJxFduEwhrFnt+48pKTs
         mPIbtdP12nYUg74n/h1KtJw+VvCjG482XL2BCBdwEQPJYOAnULIFOkvKUjSHH+EFxUiE
         OSKPZREV/FQASFEQTI7DvTgDsOZNPrdVPzR5T36ijoQHR6baIP10fiaJXFyESsqZhjej
         ISB/RZ1us+0omYGz5/kelMv35YrcJdwG8oTS3f3N2s13r4ebKjI+v83oFwU2JNjJr7am
         g6I6772Uf6UyZsW3TF8rv9cqSz+jigVLiQWA8XV4uafXPJNnhB8c5d55FEyMY0aHyY8f
         hEow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=aiqJxqDO;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=GZelPNQF;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lnB3oJnH;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5365f8c6dbcsi138635e87.9.2024.09.10.06.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Sep 2024 06:17:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id CA7E11FCE8;
	Tue, 10 Sep 2024 13:17:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9FB4F13A3A;
	Tue, 10 Sep 2024 13:17:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8qiiJtZG4GYlGgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 10 Sep 2024 13:17:10 +0000
Message-ID: <4b7670e1-072a-46e6-bfd7-0937cdc7d329@suse.cz>
Date: Tue, 10 Sep 2024 15:17:10 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 4/5] kunit: kfence: Make KFENCE_TEST_REQUIRES macro
 available for all kunit case
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>,
 Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20240909012958.913438-1-feng.tang@intel.com>
 <20240909012958.913438-5-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240909012958.913438-5-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,linuxfoundation.org];
	TAGGED_RCPT(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[16];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,imap1.dmz-prg2.suse.org:helo,suse.cz:mid]
X-Spam-Score: -2.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=aiqJxqDO;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=GZelPNQF;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lnB3oJnH;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/9/24 03:29, Feng Tang wrote:
> KFENCE_TEST_REQUIRES macro is convenient for judging if a prerequisite of a
> test case exists. Lift it into kunit/test.h so that all kunit test cases
> can benefit from it.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>

I think you should have Cc'd kunit and kfence maintainers on this one.
But if that's necessary depends on the review for patch 5...

> ---
>  include/kunit/test.h    | 6 ++++++
>  mm/kfence/kfence_test.c | 9 ++-------
>  2 files changed, 8 insertions(+), 7 deletions(-)
> 
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 5ac237c949a0..8a8027e10b89 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -643,6 +643,12 @@ void __printf(2, 3) kunit_log_append(struct string_stream *log, const char *fmt,
>  	WRITE_ONCE(test->last_seen.line, __LINE__);			       \
>  } while (0)
>  
> +#define KUNIT_TEST_REQUIRES(test, cond) do {			\
> +	if (!(cond))						\
> +		kunit_skip((test), "Test requires: " #cond);	\
> +} while (0)
> +
> +
>  /**
>   * KUNIT_SUCCEED() - A no-op expectation. Only exists for code clarity.
>   * @test: The test context object.
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 00fd17285285..5dbb22c8c44f 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -32,11 +32,6 @@
>  #define arch_kfence_test_address(addr) (addr)
>  #endif
>  
> -#define KFENCE_TEST_REQUIRES(test, cond) do {			\
> -	if (!(cond))						\
> -		kunit_skip((test), "Test requires: " #cond);	\
> -} while (0)
> -
>  /* Report as observed from console. */
>  static struct {
>  	spinlock_t lock;
> @@ -561,7 +556,7 @@ static void test_init_on_free(struct kunit *test)
>  	};
>  	int i;
>  
> -	KFENCE_TEST_REQUIRES(test, IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON));
> +	KUNIT_TEST_REQUIRES(test, IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON));
>  	/* Assume it hasn't been disabled on command line. */
>  
>  	setup_test_cache(test, size, 0, NULL);
> @@ -609,7 +604,7 @@ static void test_gfpzero(struct kunit *test)
>  	int i;
>  
>  	/* Skip if we think it'd take too long. */
> -	KFENCE_TEST_REQUIRES(test, kfence_sample_interval <= 100);
> +	KUNIT_TEST_REQUIRES(test, kfence_sample_interval <= 100);
>  
>  	setup_test_cache(test, size, 0, NULL);
>  	buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4b7670e1-072a-46e6-bfd7-0937cdc7d329%40suse.cz.
