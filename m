Return-Path: <kasan-dev+bncBAABBONSRCWAMGQEAWX46KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 6630F81937D
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:29:14 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40c4124a064sf332315e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:29:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703024954; cv=pass;
        d=google.com; s=arc-20160816;
        b=cv1giqh9iih/WyeuEaOc16dK52XxjLOiusXuYrJ9Z9diZi/QfZJLtmzTiylcC+LBIz
         ceSXvHmqpcleG+nxJGNw3rDDK8SAJTm3UJ6hhrJ0V6+uic+uIdtiP1VrbKb54SrsWLyu
         woDLM5YFu0vNUrkU2dTiIU+lxnNx+0yms2/r/ctiUNKmKL2jjSJD0Yo75MNgFduIEfGe
         +T/t19PGDLO0tJijmeyQpa/YHFgeZQKBbbrB6GYI5mt7RfHSACG73ivHy8yOvIBMHpBt
         lZgbFaqujr+iRSMBORFhuuCC0wMC5bjDCvr2ckLVFsO2t02/qnCtnCH9rgA5ok+FyrNq
         h0zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=K/Mm+RdC60r2UyX1ln2yH4TBfCf0oyaX36e4zq+4K4s=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=EEeRaoOQxEXFSSLUGCNCvZAplugoAx4hnr9veUq9zFBTjTPPZOdnJsDq0O7YUi7fl8
         WacCxei0I02pv3uKSZc3LqGlt1ONYkRrzIBvW2CQzTkoAfAl+KKQ0j3B5iXMaMIH6L1H
         /c3DbZ8l/+/JLrohXZ7Pfu65e7kpOI/bqwdxf0/IaK0Oa0iyTeR53m07QkGNiabby89T
         ydfQsCKq2ep1k9KiwTK/lVy7RrCaAq50oJe2zOdbj3lUQrajssqxvKFdYb9pEM7BhCv2
         yn+T49JurwaVBmzQns0nZdBVd2lJ4DIuS6EjbL0tIiVL/osHH1kh8lZXzkMvyGZ/ZZzU
         N0SA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cmqIC4mq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.184 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703024954; x=1703629754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=K/Mm+RdC60r2UyX1ln2yH4TBfCf0oyaX36e4zq+4K4s=;
        b=fQZYGt1QueK9D3A3R64R5L8Hosbmizxc8LqVx8PHudEgKECUjjUp5Hd241rOXd2Tf8
         2huH2Nzh0w950/hyaodyZHQdp9ga6KRYp5VlopLVvSotqls5h5G/pmtkSDak+RDFOkC8
         I1eKq17VS+5OKSSSJR49j6jjkZMdA4qcLE8zLnz8Wa8ruTrJkCRa3wqrNEr11ahcURuh
         Lb+vBuyuuv3lT2KdOCu+DOZ+7oenUg+S0DuE7C+6qoY6E9ML0RpSPFeDHN+jjNXsloHv
         GtGPTDVLyEcRvm33+V/c/1I5Zrglq7cLAyvdtTYwc3R/0SY0d7Qug1gsWZaDHDM9ZZ59
         ptVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703024954; x=1703629754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=K/Mm+RdC60r2UyX1ln2yH4TBfCf0oyaX36e4zq+4K4s=;
        b=GDk7ByZFim4nfCu5JTuclXRjLw5CLbo80rEhUx4WL398qPJN4h7CtcFyhqXEhI4uNz
         PN71PMJLqAnY3IdQxOdh6nRx3rjxB4bfuUl1D2mdHcNfnON3sVfO2VMvxhGgetf5SLmP
         /0NTQdQPQR8fH8TRkFYAg7xncyYEKL9kBOsUF0PjOkkZ+6jA7yoddtYqGPC9bGvWYmq0
         wdg+L2jYNXEFaDzO53hkeS4DdX+1yKdfwpaPX5IDIKGDYpfBPGY4FwxB62/Um77UOrt6
         jdW+RHX97rXrbOge/qXGir0Ff+CbPlWy2smI4ubOrmK2W6t7Q9UM2t9Q7Osg9rtsFeuo
         cgJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywn32GkdzA1NNCT1zUhIPl9spz2ZDaNlwZ8j3IHSvZ+Cx0m2GHA
	50BoeDbO8MME0iVOFaoxTaM=
X-Google-Smtp-Source: AGHT+IFVewNVacclaNv34NPi6TXNYWZ/to0FzBcVg7EDm08ImpHruzZT+/JrjpWQaTEWFTYeniTV6Q==
X-Received: by 2002:a05:600c:1c9a:b0:40c:256f:756b with SMTP id k26-20020a05600c1c9a00b0040c256f756bmr61073wms.2.1703024953250;
        Tue, 19 Dec 2023 14:29:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c04:b0:40c:3e0b:5c6e with SMTP id
 j4-20020a05600c1c0400b0040c3e0b5c6els389073wms.1.-pod-prod-02-eu; Tue, 19 Dec
 2023 14:29:12 -0800 (PST)
X-Received: by 2002:a05:600c:4507:b0:40c:91f:506e with SMTP id t7-20020a05600c450700b0040c091f506emr7010372wmo.126.1703024951679;
        Tue, 19 Dec 2023 14:29:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703024951; cv=none;
        d=google.com; s=arc-20160816;
        b=yDnEX7FttRGkW5EB3t/NyNa8e4yEvT2yDYveZwQVDjxA3IryYU39+GmrtCTECqpq2Z
         2U8ix82j6Lg2RcfdMQ0C41QmqRGuOKBRCsCrw8HoKHYIXBQac3zXGcSHuEsTycqPzC0Z
         /+/zvKUL5CHSrIIGNLDIavCDp686qsjZv03usiuobbTj0mUtxgaeLWgq+dbkHcW7QGhq
         AuaDCOkpjWx5Me2mzSqdwLwG36tjpTHms5SaX+j5JUnwcBPXGajbggvPtcEGzm2sD3K3
         6Wn1DFzQZG3DAiYN0qfJ1kBpFlJSjumSG9PNgmqkMFdv2MV6Jfk5AeIxa61nJq4A4Rzx
         VVkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=4hIWKlq3vwUHvNMJIcXvuTboO6P/RRCs5XS67UMRG18=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=jVuuT2Q5dlh5ERxtn+NdY/LhmCdd86+NFyD3wNirb/mDe1B8d00d+ckFeLRdCI2ZRB
         BO73XTUGnQuTjJ/fWYSGkAv/yQzaTteqmpBEvXCocG+AINJNx+pozLwcm9MM8Qe2f7js
         l6WxOVkonNlqJFfqVgW2EdHQXDFLDyy2jfxbUTp2I/UYLosHwFIIXk/YMNJciUFJIdhE
         4HrkyiB1BtYZxaNrPnet3a73mbkazotZYyictDxHewpQioa7uuStCYG5zXew6kBLuZ1N
         AQ7xJXAv1adUs2Y76plOEGMffkoNxXVv9SM4hDfaX2FZGon3qgQXYCZ9P0hVeRRdqmiD
         JOnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cmqIC4mq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.184 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-184.mta1.migadu.com (out-184.mta1.migadu.com. [95.215.58.184])
        by gmr-mx.google.com with ESMTPS id t18-20020a7bc3d2000000b0040d27e9fb0bsi101307wmj.0.2023.12.19.14.29.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:29:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.184 as permitted sender) client-ip=95.215.58.184;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 00/21] kasan: save mempool stack traces
Date: Tue, 19 Dec 2023 23:28:44 +0100
Message-Id: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=cmqIC4mq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.184 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

This series updates KASAN to save alloc and free stack traces for
secondary-level allocators that cache and reuse allocations internally
instead of giving them back to the underlying allocator (e.g. mempool).

As a part of this change, introduce and document a set of KASAN hooks:

bool kasan_mempool_poison_pages(struct page *page, unsigned int order);
void kasan_mempool_unpoison_pages(struct page *page, unsigned int order);
bool kasan_mempool_poison_object(void *ptr);
void kasan_mempool_unpoison_object(void *ptr, size_t size);

and use them in the mempool code.

Besides mempool, skbuff and io_uring also cache allocations and already
use KASAN hooks to poison those. Their code is updated to use the new
mempool hooks.

The new hooks save alloc and free stack traces (for normal kmalloc and
slab objects; stack traces for large kmalloc objects and page_alloc are
not supported by KASAN yet), improve the readability of the users' code,
and also allow the users to prevent double-free and invalid-free bugs;
see the patches for the details.

There doesn't appear to be any conflicts with the KASAN patches that are
currently in mm, but I rebased the patchset on top just in case.

Changes RFC->v1:
- New patch "mempool: skip slub_debug poisoning when KASAN is enabled".
- Replace mempool_use_prealloc_only API with mempool_alloc_preallocated.
- Avoid triggering slub_debug-detected corruptions in mempool tests.

Andrey Konovalov (21):
  kasan: rename kasan_slab_free_mempool to kasan_mempool_poison_object
  kasan: move kasan_mempool_poison_object
  kasan: document kasan_mempool_poison_object
  kasan: add return value for kasan_mempool_poison_object
  kasan: introduce kasan_mempool_unpoison_object
  kasan: introduce kasan_mempool_poison_pages
  kasan: introduce kasan_mempool_unpoison_pages
  kasan: clean up __kasan_mempool_poison_object
  kasan: save free stack traces for slab mempools
  kasan: clean up and rename ____kasan_kmalloc
  kasan: introduce poison_kmalloc_large_redzone
  kasan: save alloc stack traces for mempool
  mempool: skip slub_debug poisoning when KASAN is enabled
  mempool: use new mempool KASAN hooks
  mempool: introduce mempool_use_prealloc_only
  kasan: add mempool tests
  kasan: rename pagealloc tests
  kasan: reorder tests
  kasan: rename and document kasan_(un)poison_object_data
  skbuff: use mempool KASAN hooks
  io_uring: use mempool KASAN hook

 include/linux/kasan.h   | 161 +++++++-
 include/linux/mempool.h |   1 +
 io_uring/alloc_cache.h  |   5 +-
 mm/kasan/common.c       | 221 ++++++----
 mm/kasan/kasan_test.c   | 870 +++++++++++++++++++++++++++-------------
 mm/mempool.c            |  67 +++-
 mm/slab.c               |  10 +-
 mm/slub.c               |   4 +-
 net/core/skbuff.c       |  10 +-
 9 files changed, 954 insertions(+), 395 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1703024586.git.andreyknvl%40google.com.
