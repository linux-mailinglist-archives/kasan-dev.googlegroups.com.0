Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7N7CVAMGQEYJZHZ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 547637F4DF7
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 18:13:33 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-542fe446d45sf15380a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 09:13:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700673213; cv=pass;
        d=google.com; s=arc-20160816;
        b=D22FUd4BiEc5iWKdxhjkj1Q1L5f79VzqLYQ9NKjcRmzCZC+3JvTzlrjnqHwp4MzXDQ
         N5ULvdhaSPufcnGunBpTS/rLON8Ip8+F7VmPw52QRNuWGZMRV1bneptZvAK5Pc77CsKk
         ailkoxDnC9eC4J41KTx8bpp8PJllo5b+iadSCmIovuG/pomhv40un2QLy5Ci233FRQ3w
         3hZ2bZa3hA47d5RDw0IkYNXKe6KEAk8N83XFqvcAgEJTFExulMpR83FAVYcGOdjjnb9h
         DUYqlACkMxAz6NKvyu6RzMIy/B9U1700vAem1Ny0DGOohoCNQXaltCsQW6R62POdK1Uv
         Oy+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+hF+5Vnu6WPMFWAzVVz7eyh0GvajjWEdUIX082YsDCA=;
        fh=Avg7wGSBRsZ0DIpZn8URTxt87FNBdQgwxmFYDqTvEPg=;
        b=Ng+gT/CS/YrEPh6SjTilvfpdssBh1mIQj/QGWf/uAhJ0bRGTJ6Nl1qad0euTUmN8Hj
         cXk7K0fM6xxNz7NU58p/mqFrCNVDBiEohRw4HkwnBez7Rk/B3td1Yl222fGeG4b3TzaO
         gQ389VuWFPeibDcNRwS9wIpRTGIO1ZgmtPKqIt4hTc574E1IDTj7k/FU0z2bWwplXe/K
         TeMRvzP0HyJICwc765KT3h8pdMsu2X9p8fAjwN/fNWGbY1shONOG/1feg5WucNyQ3dCN
         xFqm8k+/DyTV5v/IQ7i98RTP9e+RfGyaFNwlSKDFutpxFpS2hmPQc/UEZE24N16P5ZfV
         jW0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JsYEBX8t;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700673213; x=1701278013; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=+hF+5Vnu6WPMFWAzVVz7eyh0GvajjWEdUIX082YsDCA=;
        b=lj8jrKYmO5Ro90jsS/W5HgyEwaclygKNtxxjt4050H8YsztDgg79pGIhY8I0fW+mtw
         0UNGTkk6w6BoB6pVz0Y8bn3gox+J54uVGWlpIO0UvSj31howgb8q8dNJ4ew9aAwslsS/
         ut1l/pU2sY9dmVsEBV4TOF3YVk1sbSxP0M9tB76wpORrQL2Pup+8PWelPpY8bMRyLD7K
         2iEB8x3aXWcUNpbhClebbR6VHwTSZXQYgVHbmqzyeb1YvzMbUifLUzlM2cXbRU1dMgU2
         kKh0qQDVBczSjie4ESEhSxy0HXwNOPLOvRjbFOS8PGpN89iyISjXvS9R4Q3M7AbsqRJQ
         mqpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700673213; x=1701278013;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+hF+5Vnu6WPMFWAzVVz7eyh0GvajjWEdUIX082YsDCA=;
        b=FhonS9bQ1L7Ws1goXU8svgPlSN3Iw+i0p+pSI2pfTW0XC+U7PBs41OUGVcHEJoDSkZ
         K2+6KVcIWMKAVV+D3f37hZmNeUFvsFG4T/4iAmBWx71pNzl1YD3268QrM71XwXnjNdhv
         H1MDOXuMyWXCrZaVPHumf3ymwqfoKma5huQsXUnxnO+7FOWL1PY02aVQjSsCnmxqZyYZ
         Dzox7fhFcxie+jtGTdBvvvqJ0RJE8jk0ywOfuG6DleqP4wRl7mowiDBpl13KxKHAtuWG
         qiKMBYDiJYqedRQ/L2N1lbxlYqzJ4T1tk/7rAOP6/I2lFk5Gep1TWqpXGSk/F+ofAllU
         rFxQ==
X-Gm-Message-State: AOJu0YycM63er3GFJkqF20qdqoIxsv6/s4JrujGXGEv51emxXLgqBylr
	QVXyR05yJ6IRQfsJaP4bPTA=
X-Google-Smtp-Source: AGHT+IE1H4HeHM2J7IIDdFkvsQL+0OyH5WR6OaD7z3MJjObjQka6xCAQD6Ah702qkGPuObHnwKvQnw==
X-Received: by 2002:a05:6402:3585:b0:53e:1b:15f5 with SMTP id y5-20020a056402358500b0053e001b15f5mr2627652edc.39.1700673211874;
        Wed, 22 Nov 2023 09:13:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f15:b0:546:dce7:3ac7 with SMTP id
 i21-20020a0564020f1500b00546dce73ac7ls24789eda.1.-pod-prod-03-eu; Wed, 22 Nov
 2023 09:13:29 -0800 (PST)
X-Received: by 2002:aa7:da44:0:b0:533:4c15:c337 with SMTP id w4-20020aa7da44000000b005334c15c337mr2415727eds.16.1700673209585;
        Wed, 22 Nov 2023 09:13:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700673209; cv=none;
        d=google.com; s=arc-20160816;
        b=D5zdFi2cfcaCrA3laMjRkrG55fU1sehLrwIVMCVW/y9/yM7Tpi4NeZu+ZEcGoo//3+
         q4ymtflQq1hgaIcl9N9ZOyeNkdNoOlF4FJ0oioGTmd2OYRNV425pKYK4HVM91L/hpQFi
         1znsS1lS7ndeSCmSUs46KhGmRusfV0ugyvx6+rXOCjL5LVxXz1KH25JikUuo9b/09jOJ
         ST1yvkm4cYYtStDYh/m1eeUygMKgq0QpIwYjPCItN6lTJAViRGz/4IXQsfzEyBuUSV7w
         7qCnEe0nqNtafX1df/devUI0Uwf9HEk/7iRutou4tOsq6zSkCmI5dP2qHnLQHzvB8fti
         gACA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=iREYFokOV8dvymG/8i5EmbN9PgByJeos08X2K2e+878=;
        fh=Avg7wGSBRsZ0DIpZn8URTxt87FNBdQgwxmFYDqTvEPg=;
        b=Ds7e+ErH+/Y/J4gUe3jG0OANhezGzVAKT/XpY2rqzHct9b4YHblmH6e0yjs/wyCt/b
         BcraLWoLcq+2p3X2E8EFDPcHVhe2NdOhD+Nc/+kZ+zjOgNyQfobWTQmUe0ZL0Fm3QJfN
         tC9M/7gfCxOFHZD8YFD4U/aPzv/aSwAIVCCToQhqBzoOumpb8ifunlDBrTK+CWI3dYHi
         qvUh0btjs9KOOU177jyQS5W3tXexqUbU2z3cOwQqV6ArcvKR6qAa+J4m8dlcAB/MqfLC
         sKPIwdv6+AxJ6tqH7Z1rf6KPHsZG2XfUj1F4lAkymC0s1DFC26Nw2SLT8y9389Ko+umA
         f+ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JsYEBX8t;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id g38-20020a056402322600b005489dbe8653si390eda.2.2023.11.22.09.13.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 09:13:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-40b2979a74eso15393075e9.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 09:13:29 -0800 (PST)
X-Received: by 2002:a5d:64e4:0:b0:332:ce3f:a370 with SMTP id g4-20020a5d64e4000000b00332ce3fa370mr2275817wri.51.1700673208904;
        Wed, 22 Nov 2023 09:13:28 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:1dcf:36df:c2d9:af51])
        by smtp.gmail.com with ESMTPSA id b15-20020a056000054f00b0031980294e9fsm17633839wrf.116.2023.11.22.09.13.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 22 Nov 2023 09:13:28 -0800 (PST)
Date: Wed, 22 Nov 2023 18:13:23 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH RFC 00/20] kasan: save mempool stack traces
Message-ID: <ZV42s_c3BzCAEwgu@elver.google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JsYEBX8t;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
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

On Mon, Nov 06, 2023 at 09:10PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> This series updates KASAN to save alloc and free stack traces for
> secondary-level allocators that cache and reuse allocations internally
> instead of giving them back to the underlying allocator (e.g. mempool).

Nice.

> As a part of this change, introduce and document a set of KASAN hooks:
> 
> bool kasan_mempool_poison_pages(struct page *page, unsigned int order);
> void kasan_mempool_unpoison_pages(struct page *page, unsigned int order);
> bool kasan_mempool_poison_object(void *ptr);
> void kasan_mempool_unpoison_object(void *ptr, size_t size);
> 
> and use them in the mempool code.
> 
> Besides mempool, skbuff and io_uring also cache allocations and already
> use KASAN hooks to poison those. Their code is updated to use the new
> mempool hooks.
>
> The new hooks save alloc and free stack traces (for normal kmalloc and
> slab objects; stack traces for large kmalloc objects and page_alloc are
> not supported by KASAN yet), improve the readability of the users' code,
> and also allow the users to prevent double-free and invalid-free bugs;
> see the patches for the details.
> 
> I'm posting this series as an RFC, as it has a few non-trivial-to-resolve
> conflicts with the stack depot eviction patches. I'll rebase the series and
> resolve the conflicts once the stack depot patches are in the mm tree.
> 
> Andrey Konovalov (20):
>   kasan: rename kasan_slab_free_mempool to kasan_mempool_poison_object
>   kasan: move kasan_mempool_poison_object
>   kasan: document kasan_mempool_poison_object
>   kasan: add return value for kasan_mempool_poison_object
>   kasan: introduce kasan_mempool_unpoison_object
>   kasan: introduce kasan_mempool_poison_pages
>   kasan: introduce kasan_mempool_unpoison_pages
>   kasan: clean up __kasan_mempool_poison_object
>   kasan: save free stack traces for slab mempools
>   kasan: clean up and rename ____kasan_kmalloc
>   kasan: introduce poison_kmalloc_large_redzone
>   kasan: save alloc stack traces for mempool
>   mempool: use new mempool KASAN hooks
>   mempool: introduce mempool_use_prealloc_only
>   kasan: add mempool tests
>   kasan: rename pagealloc tests
>   kasan: reorder tests
>   kasan: rename and document kasan_(un)poison_object_data
>   skbuff: use mempool KASAN hooks
>   io_uring: use mempool KASAN hook
> 
>  include/linux/kasan.h   | 161 +++++++-
>  include/linux/mempool.h |   2 +
>  io_uring/alloc_cache.h  |   5 +-
>  mm/kasan/common.c       | 221 ++++++----
>  mm/kasan/kasan_test.c   | 876 +++++++++++++++++++++++++++-------------
>  mm/mempool.c            |  49 ++-
>  mm/slab.c               |  10 +-
>  mm/slub.c               |   4 +-
>  net/core/skbuff.c       |  10 +-
>  9 files changed, 940 insertions(+), 398 deletions(-)

Overall LGTM and the majority of it is cleanups, so I think once the
stack depot patches are in the mm tree, just send v1 of this series.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZV42s_c3BzCAEwgu%40elver.google.com.
