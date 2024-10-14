Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLFRWS4AMGQEHRHUZ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B190399CB2F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 15:12:14 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2f759001cb1sf28710331fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 06:12:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728911534; cv=pass;
        d=google.com; s=arc-20240605;
        b=fCJ88FvMybkh/N6CON2fn4ANGOYpjOlzjpK33IRT6RDjZ3fumxAV6tphtLGcdyCPnT
         DfnXMHCXWo1OgteSHKVEWesJmV7fJbA1E+fW2KPuEzqgAumtLCryxgk96CrKWWAa1lhF
         lkeh26LaP0mIzFR7cNzV+tH7Q0CHNVdyqVTzrvBVNIuIX4/IZULgPSJr9MMaMWQfku84
         d20HWGfHIbr86dpteQJeVt1maZpBkjOByLZcc638hCUAHihNyPu/JZ//ttzvvwQHSZ2r
         ZemJvu8CiCaReTZ7Yn0iC8J6TVLb7URe4WQ6SRxZk0ltK3Xf47LklE2v3eQy+aOc8UFQ
         h60g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=coGDyWJSLER2FpbtIM2Fy1cmXTdtzcW1WrfEiwA1Qq8=;
        fh=pbRFeYrC8RkPknKQC7qwFAmP9Rnixl+uGyWkmuNh0i4=;
        b=QGcN3k7qAiEywm9orjeCJzGS1T4tbLFP1VGPsRfOCpGUhAfnB7NnGDgM3ls07ABpNE
         fSlp+ar4FoI2O2+BmTlc2fs5+jpOnBbpa425uRIAuW2ygLuJpLFMKew5mv+IrtfE1Odh
         n8XQWjcWupXJLBdHtXlmftReWxPua22Z+gF9Kram9ZRfCQS7gyIuoYkms5RNlRq2iM5Y
         0tC1ZxZQ9HLBSkaJHcVXP7hHZ+lJ1P0WchPzdMeDVs290e9gG635BzrQuHorEoS2aK+y
         NzVSkCZJ1yoYSAy+WavohqSPM0MWomconyv5nQscN3VZmGXF679iYgkGtKNS11DPIbyy
         eEKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FfMDbpv1;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FfMDbpv1;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=f8YLxQaJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728911534; x=1729516334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=coGDyWJSLER2FpbtIM2Fy1cmXTdtzcW1WrfEiwA1Qq8=;
        b=E/I0tLYG/XKeoxAY3ul4qZIdG1IuJOYFoik+1z4JPaboqWynuWUq+/MuobZ6rZXcDM
         uskhf5sj+adomECK0kscw+69RNQnODobSjoDQIImDqLfr1Iu2J6kgyGXHIbUjq1pnfB9
         OzuMy76USNtonnynOb2XF5FHYLhsK2mjQEKoTnu2VS7whgAaU9dT6v37BFkfEYYAwynk
         pUXq69CofVtiCN9gAOZTT1p7+v13mU9TmHZx9w1nJaJB6CkLNEzfxeGiyIArQgWzgNYK
         LI1+PtvHciNoLGqotQCCPIooU/VTWA7ZEvFNFrXlmTXoHmW5luZZNySeJJLEL0MQEoq+
         uAdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728911534; x=1729516334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=coGDyWJSLER2FpbtIM2Fy1cmXTdtzcW1WrfEiwA1Qq8=;
        b=kE0bGGOQKU0+k5cs9gJN2sAjJd0ocOQdN3XoI6qrng6y/8Nc6JN1YTfQq2z8DA0h1k
         1510gXUv0K7MqmxTgK1svKcyGj3eDpOjCKYYZhw3ATiaQEQ5v+x70BlS0UJC20qoo5aY
         5A4FeogF+bdkEqZViy3o6wtRZhrkE0dwTwZdkVz2P09Giu9FrUk221jysySGi88f0bE0
         i45PAnh+tVNQJT5GxZniObj2viVFFQ05zj7LCCMN8Y0aG1oqg68dsapv70XL2Hkon7gC
         pXc9eelTtDVN0u1ejpAGrEUOkujHQ5y+ro0duFUGoWSYMGP5/L15X8xnx1pS9WMRG8OV
         KK/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlrECBk2FpkDHtfE1P94X4A2o/FWMjYcRFMPegg1yf5xJae85RjBZTwbUY3PQmsSgrOIgl+A==@lfdr.de
X-Gm-Message-State: AOJu0Yy5MAm+H8LDdiFaQEIDcy1HKGA9JVkVH82J1bboqCKROVWSlhnj
	yDrVcqPSS5keJYrKM0B5w8YOlXYhqen5NNZBUsdHurKeidxKnA9b
X-Google-Smtp-Source: AGHT+IFQEJkQUoieRxHkOaNoN6qw7V64RQ2npAdff3ilwZLhetNlJiAE2VW4y/buunYxrJ57QPjXjQ==
X-Received: by 2002:a05:6512:2202:b0:533:4620:ebec with SMTP id 2adb3069b0e04-539e54d7713mr3737537e87.3.1728911532953;
        Mon, 14 Oct 2024 06:12:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2210:b0:539:907d:1ed6 with SMTP id
 2adb3069b0e04-539c9be5b8als40656e87.2.-pod-prod-05-eu; Mon, 14 Oct 2024
 06:12:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrwBp0VdxTg5ittA1qAw9rz7tcmrMvTT6NTl5bD16elXzVlKiXrNU3OizxLdL8cdI3maztc519F6U=@googlegroups.com
X-Received: by 2002:a05:6512:3da3:b0:538:9e1e:b06f with SMTP id 2adb3069b0e04-539e5501c8amr4311871e87.27.1728911530681;
        Mon, 14 Oct 2024 06:12:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728911530; cv=none;
        d=google.com; s=arc-20240605;
        b=LmcEilCYsnnod0hjqpX1n7BX/gQ908e+c5974xe4Yxsyr6T2Eg2z56eZwlBWKe8sCd
         6F+bzzaJ9Gjs3cpdkyvSJjJNGQVitvn6v3Bff2bolef4z22Fdmp07HGmtSY37YyEkplX
         cVknC//EJ1bO9sLpeu0SgPlL5RQVvTqLFXulJwBSQ7a9FHY1+n4dq4C+x8cw0dc9sIN2
         6hM/S0df5JeaUM1pzHEk6Ex+nUirKkRUOuBOTlGTAMcRNLzRTAU16Y9HevVTHS4HCsgG
         6j0/+zZ0M564TCpAn9R58gcn0w/orbBRppZRarHog1iR0kV70ZFSgRef/AZIz5hrCn5G
         x8Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=zqarmSZKN2z2nIPNDdOcCc2rTYxaKohP7Uy1zHoY2f0=;
        fh=NfEqRkCQjd6fkh4jQ8Pn7Ur0TYmMflEYEbYdXS1k450=;
        b=X4s93hRlbQPtoQiWzFELAy4SMUvLNF0ouBPAHL6qyVZceVV3fXu3YDrzeZTYR8fajr
         O6aykeZewXXw/MQ3kGZtTYrRYCDZYMZh/3m4GZGtqhu9/dzRlike5X5TAW06nfqYcxOm
         KkA2K/007VVabtHW5LNlMCHM6vh7P33Cxf7ARKqlqvFx9K+CFcp5IU4Jl+upc4cJhZQR
         3z6+8Yc+9v1AluIeHLPFo2Dcu/k89q4sy7webFrsv5ZyIah5LOtwdzc20mLar+WtXQ94
         weMkhyo1zcmbzpo5vu1i/M3Fi9lfnuzEGpEfozamA0lceTiMzeV73jNHdrJukmJj1Y0L
         xhNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FfMDbpv1;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FfMDbpv1;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=f8YLxQaJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539e314b5aasi114479e87.7.2024.10.14.06.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 06:12:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id AC7991FE53;
	Mon, 14 Oct 2024 13:12:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7B26513A42;
	Mon, 14 Oct 2024 13:12:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 3oR5HakYDWeOUAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 14 Oct 2024 13:12:09 +0000
Message-ID: <0e8d49d2-e89b-44df-9dff-29e8f24de105@suse.cz>
Date: Mon, 14 Oct 2024 15:12:09 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Shuah Khan <skhan@linuxfoundation.org>,
 David Gow <davidgow@google.com>, Danilo Krummrich <dakr@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 Eric Dumazet <edumazet@google.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
 <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
 <ZwzNtGALCG9jUNUD@feng-clx.sh.intel.com>
 <a34e6796-e550-465c-92dc-ee659716b918@suse.cz>
 <Zw0UKtx5d2hnHvDV@feng-clx.sh.intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <Zw0UKtx5d2hnHvDV@feng-clx.sh.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: AC7991FE53
X-Spam-Score: -3.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[22];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[google.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev,gmail.com,linuxfoundation.org,arm.com,kvack.org,googlegroups.com,vger.kernel.org];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FfMDbpv1;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FfMDbpv1;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=f8YLxQaJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/14/24 14:52, Feng Tang wrote:
> On Mon, Oct 14, 2024 at 10:53:32AM +0200, Vlastimil Babka wrote:
>> On 10/14/24 09:52, Feng Tang wrote:
>> > On Fri, Oct 04, 2024 at 05:52:10PM +0800, Vlastimil Babka wrote:
>> > Thanks for the suggestion!
>> > 
>> > As there were error report about the NULL slab for big kmalloc object, how
>> > about the following code for 
>> > 
>> > __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>> > {
>> > 	void *ret;
>> > 	size_t ks = 0;
>> > 	int orig_size = 0;
>> > 	struct kmem_cache *s = NULL;
>> > 
>> > 	/* Check for double-free. */
>> > 	if (likely(!ZERO_OR_NULL_PTR(p))) {
>> > 		if (!kasan_check_byte(p))
>> > 			return NULL;
>> > 
>> > 		ks = ksize(p);
>> 
>> I think this will result in __ksize() doing
>>   skip_orig_size_check(folio_slab(folio)->slab_cache, object);
>> and we don't want that?
> 
> I think that's fine. As later code will re-set the orig_size anyway.

But you also read it first.

>> > 		/* Some objects have no orig_size, like big kmalloc case */
>> > 		if (is_kfence_address(p)) {
>> > 			orig_size = kfence_ksize(p);
>> > 		} else if (virt_to_slab(p)) {
>> > 			s = virt_to_cache(p);
>> > 			orig_size = get_orig_size(s, (void *)p);

here.

>> > 		}

>> Also the checks below repeat some of the checks of ksize().
> 
> Yes, there is some redundancy, mostly the virt_to_slab() 
> 
>> So I think in __do_krealloc() we should do things manually to determine ks
>> and not call ksize(). Just not break any of the cases ksize() handles
>> (kfence, large kmalloc).
> 
> OK, originally I tried not to expose internals of __ksize(). Let me
> try this way.

ksize() makes assumptions that a user outside of slab itself is calling it.

But we (well mostly Kees) also introduced kmalloc_size_roundup() to avoid
querying ksize() for the purposes of writing beyond the original
kmalloc(size) up to the bucket size. So maybe we can also investigate if the
skip_orig_size_check() mechanism can be removed now?

Still I think __do_krealloc() should rather do its own thing and not call
ksize().

> Thanks,
> Feng
> 
>> 
>> > 
>> > 	} else {
>> > 		goto alloc_new;
>> > 	}
>> > 
>> > 	/* If the object doesn't fit, allocate a bigger one */
>> > 	if (new_size > ks)
>> > 		goto alloc_new;
>> > 
>> > 	/* Zero out spare memory. */
>> > 	if (want_init_on_alloc(flags)) {
>> > 		kasan_disable_current();
>> > 		if (orig_size && orig_size < new_size)
>> > 			memset((void *)p + orig_size, 0, new_size - orig_size);
>> > 		else
>> > 			memset((void *)p + new_size, 0, ks - new_size);
>> > 		kasan_enable_current();
>> > 	}
>> > 
>> > 	/* Setup kmalloc redzone when needed */
>> > 	if (s && slub_debug_orig_size(s) && !is_kfence_address(p)) {
>> > 		set_orig_size(s, (void *)p, new_size);
>> > 		if (s->flags & SLAB_RED_ZONE && new_size < ks)
>> > 			memset_no_sanitize_memory((void *)p + new_size,
>> > 						SLUB_RED_ACTIVE, ks - new_size);
>> > 	}
>> > 
>> > 	p = kasan_krealloc((void *)p, new_size, flags);
>> > 	return (void *)p;
>> > 
>> > alloc_new:
>> > 	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
>> > 	if (ret && p) {
>> > 		/* Disable KASAN checks as the object's redzone is accessed. */
>> > 		kasan_disable_current();
>> > 		memcpy(ret, kasan_reset_tag(p), orig_size ?: ks);
>> > 		kasan_enable_current();
>> > 	}
>> > 
>> > 	return ret;
>> > }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e8d49d2-e89b-44df-9dff-29e8f24de105%40suse.cz.
