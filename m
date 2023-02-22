Return-Path: <kasan-dev+bncBDR5N7WPRQGRBOV63GPQMGQEFQLLCHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7752869FAFF
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 19:30:20 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id d12-20020a05680813cc00b00383b76f4171sf2442322oiw.20
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Feb 2023 10:30:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677090618; cv=pass;
        d=google.com; s=arc-20160816;
        b=owY6oH0nCBaT0qV6MT2+yjOvSnbpPbzti2yB/pHpWgwIADjJbjhR7pAN/P+/u50i+h
         Tx2hw8RLkxjbDJ/NetJQnftwWi7uWO0pM0CgexDhznCkQMuLElIE9TUuV9T4Oop7WDoK
         PYgYDD+MfbRbKE2uhy8rKQKpvgbWKGvR5QjKoWyYBIKujIDkVnO2DTPd1O2Aga6+mJhT
         fCWe1oBCEZpHkKrnLHZPGha2DgwsprqLNPgB7Z+qPRjcvk63AtJyKjOSZZsNxmCWDyAk
         sk+5XR/dnT2Q129daar2rLyiHn9nHsvdoApPnOhuVR9kWDwdMzM85v8YCDk8dNd8AJ0F
         /n2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=MnKnHgpzKSnywaqJ0E+M1uJMz5JR2vXOZWmEnXPbls8=;
        b=Y+pgk1UEXj3rjxERm5Up3lIWtwHbm4jPRwmACK+N+3V56jmcW9Ydqd84Ysj1VfVr/x
         HKRRBLvSLrw2G69dR/3u5bKG3qYhdcELMKoGganLHHK/3UswuOjU+OfENGmwVdp3yWKL
         9G3bXRtdIg5sMYUH0h0Hh8pRy57TO4EcUkAu1JFPGIUdFBYqn8O/sFvq4DfYHDLHo9il
         Ut4sknM6NGhhDni0GfvQ9PRX/oJ3S/mG3o66KRxMEe9DPhQhwEvUvyBA3s2OnjngN3BG
         E0lyfNUOVUKkeQKo97BJTO60aP2UmZ2lOlqWBvJ43WC3LOBZV6GRylSZc1gWn47SSKg4
         rAGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=W+vuxZLU;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=axboe@kernel.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MnKnHgpzKSnywaqJ0E+M1uJMz5JR2vXOZWmEnXPbls8=;
        b=fQi2BgGpZnQ9Fzadh9KCMmcfTbBu1edMTs1jrKMjXgjhqnLP8EWY6Ef2lZuIZwWn3P
         iylq73vyfzbpO7TEy4i+hjx9//3Sx+fS3hAESJF53dukSzxSkOX1oR6GusacKB5rs+wD
         sEiuZVrNr8ZIuQ5kH4ZnNPv7fPNXXEDktczffW4U39kkkyGLxs2DKqRiPOvT4D4k6wfW
         y8lIm/6ux4wCtuPXoT0Lip/F8ORXu7m7dWaqOiQiSk3UBv/Xbi1hunrN7yyc5s01sDaQ
         wqv6onPoUBQ8MabcniubOs2UAlfgydXj02aOVFVgmnH6zYpXU1jb4Wocik3k3MLkZrOe
         /dWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MnKnHgpzKSnywaqJ0E+M1uJMz5JR2vXOZWmEnXPbls8=;
        b=Bsf5k8L32RRPlPGyNNAbSryHyDh99epX60tkR/yKmym3J11I1xfhbqAscE+lvBYzqe
         GmqFmobrRzw28ooC88iIhm9poSZ91yA7vhUVU0gi4ul5tUW5P0Ve0j2ZgyQWfivh7MqC
         mxg/9RfTvbILmNks+KWGv6edp4wqov18Rtur6evoF7KczurbnC+lli5xIjs46UCyZaIo
         +xbzy8HIunmDu2CuZOfbCuZFaoQ6IGrqm8SGWujzoY40S+KSgWEXf9vxs7ir4NYGBKSu
         YSLRQe8N9RoDxtdCrPqA7R33V6C7lwTsLAvsE9R/ulMR2HQSKAY2o4o2KIqmHkd9qMdU
         4IUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVww1AnczrqDqOK8vluQAgf/WiS+q58jJmN0l6DfDCp9viNZu61
	m8WSLHKcBB3Nb78zAFTRgys=
X-Google-Smtp-Source: AK7set/V0zLQpjT4h4xJ3OYvjp27XM8bPa2NZVOvjaQGCxi4z7V18PxBQUuGX6SYXc6IGUHmiPcdhA==
X-Received: by 2002:a05:6870:eca1:b0:16e:25e:f294 with SMTP id eo33-20020a056870eca100b0016e025ef294mr1483372oab.81.1677090618560;
        Wed, 22 Feb 2023 10:30:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4609:b0:13c:4c86:219f with SMTP id
 nf9-20020a056871460900b0013c4c86219fls3593337oab.7.-pod-prod-gmail; Wed, 22
 Feb 2023 10:30:18 -0800 (PST)
X-Received: by 2002:a05:6870:e0c8:b0:172:55cf:f6cc with SMTP id a8-20020a056870e0c800b0017255cff6ccmr1432577oab.51.1677090617948;
        Wed, 22 Feb 2023 10:30:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677090617; cv=none;
        d=google.com; s=arc-20160816;
        b=bpsZX9bo9He5rug9kGcj6oLLGMLsdQR+qf+8eVYI+rOy10pLPrdXZUY/cC4rnWLFF/
         iL/jVRTGpA9gMM9/X82cUJb0TxqVJvUFKBzJSSwH4TxpRwuGRLx7Foje0NOpzqnZ+6l8
         G/NlQ28V3ZkyRh+8VOgKBj5lokKXHjpo3aQvckW4BrB4+OJN7Yi1KHSSReq4SgsAT8yo
         AD4vZoozaOZotxJPqW4c9A5/3Wp+5cGCcJXeQ9eeSKk1PJFdL354JYIcmeW6N7GI5Ytl
         Gg8okTU40FmmwwkoZrjCDqz75VI1vChX9jDL37wUTpg6eE1xgO67xOYI43HKwE7mKWRi
         oHVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=/OiGxXdhMijif1OrnbqcE7MLbFzI92LPmx4R6TbKMMc=;
        b=hSx3dSAKzNwLhBYHRpyQx2II75sTwC24SgTV6D+MOnNaj8lyGDHru1/QSx5qUCDiLB
         A/HOMMinhsZEJLs9MbGfdw+B7dRtcSqdeV+EH7+vTuVeapzZbp0h5VSNUD5xp76M8u/P
         DpkkljSHYDmIeUHl3yFAUuoV1JzP3Wjqyg5OCIrwbUEu12Qfk0xHth9UnwaCxc+ceExq
         PwW8o+EZL1ublHgNjKSQ6M9PpZs9IY1eXBP/ci1suh6tTUtNexMGg9tJr3kctMWhSVFR
         VT/FyptDhn02FgCl2gf4UQDx0PmvkZsNUr+lxspdKHGFquRGZdFrlegyPenDKaNEG5dy
         gkiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112 header.b=W+vuxZLU;
       spf=pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=axboe@kernel.dk
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id q10-20020a056870828a00b001725b7c6cd3si173214oae.1.2023.02.22.10.30.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Feb 2023 10:30:17 -0800 (PST)
Received-SPF: pass (google.com: domain of axboe@kernel.dk designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id x6so3930550ilm.11
        for <kasan-dev@googlegroups.com>; Wed, 22 Feb 2023 10:30:17 -0800 (PST)
X-Received: by 2002:a05:6e02:d08:b0:316:e2ee:3a15 with SMTP id g8-20020a056e020d0800b00316e2ee3a15mr2621798ilj.1.1677090617221;
        Wed, 22 Feb 2023 10:30:17 -0800 (PST)
Received: from [192.168.1.94] ([96.43.243.2])
        by smtp.gmail.com with ESMTPSA id g14-20020a056e021a2e00b00313d86cd988sm2579889ile.49.2023.02.22.10.30.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Feb 2023 10:30:16 -0800 (PST)
Message-ID: <b0c82199-fb96-08a2-6158-cb1655b6ba3d@kernel.dk>
Date: Wed, 22 Feb 2023 11:30:15 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101
 Thunderbird/102.7.2
Subject: Re: [PATCH v2 2/2] io_uring: Add KASAN support for alloc_caches
Content-Language: en-US
To: Breno Leitao <leitao@debian.org>, asml.silence@gmail.com,
 io-uring@vger.kernel.org
Cc: linux-kernel@vger.kernel.org, gustavold@meta.com, leit@meta.com,
 kasan-dev@googlegroups.com, Breno Leitao <leit@fb.com>
References: <20230222180035.3226075-1-leitao@debian.org>
 <20230222180035.3226075-3-leitao@debian.org>
From: Jens Axboe <axboe@kernel.dk>
In-Reply-To: <20230222180035.3226075-3-leitao@debian.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: axboe@kernel.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel-dk.20210112.gappssmtp.com header.s=20210112
 header.b=W+vuxZLU;       spf=pass (google.com: domain of axboe@kernel.dk
 designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=axboe@kernel.dk
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

On 2/22/23 11:00?AM, Breno Leitao wrote:
> -static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache)
> +static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache,
> +							size_t size)
>  {
>  	if (cache->list.next) {
>  		struct io_cache_entry *entry;
>  		entry = container_of(cache->list.next, struct io_cache_entry, node);
> +		kasan_unpoison_range(entry, size);
>  		cache->list.next = cache->list.next->next;
>  		return entry;
>  	}

Does this generate the same code if KASAN isn't enabled? Since there's a
4-byte hole in struct io_alloc_cache(), might be cleaner to simply add
the 'size' argument to io_alloc_cache_init() and store it in the cache.
Then the above just becomes:

	kasan_unpoison_range(entry, cache->elem_size);

instead and that'd definitely generate the same code as before if KASAN
isn't enabled.

-- 
Jens Axboe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b0c82199-fb96-08a2-6158-cb1655b6ba3d%40kernel.dk.
