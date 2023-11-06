Return-Path: <kasan-dev+bncBAABBPEQUWVAMGQEZID7E7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E73557E2DBC
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:10:38 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-507a3426041sf5447939e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:10:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301438; cv=pass;
        d=google.com; s=arc-20160816;
        b=qfaZjG6yhgg15RUzQOFoJzqGtGuiJC50FqEUBwqdQY2IA/SFGgWk/ckJqLpCxk9h5Y
         jfMm/74EIC3txEV8+muXvfgfMGy1cQl+1g9UqQRS61Uce9dCboXO/WZ5vrkzpp+epNtP
         aQGDgmx6Gn6wWFMbot+PAH9Afrs3jBWfzkWnIfL9v+eMZ/k5kYiQ8qCekF54wvwMEnT2
         MFVyeOWX/mDh/Z1pCBhq8RpQdWz7uMykpKucRnfldG8FQAB+HkMbol6Khu0s6wprGzU0
         i+kSoruBiE6mJmC7B3N+mCFsMszv3St8kOvQRf8z3lpPm0i1KHjrHqkZqP/dcNpG1OQ/
         VAQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Tsgh7RH/JIcRRfSTSHHmtpFJhahEwG1WkIUZ93pCO9o=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=vkQGCthXWkGoU8Lmc09AFQ5jdNrPKQkyHsuglQoqgxe6NLWjvMC87ful5OWI4hPp/5
         KkKjq2gXPNzXSvBh1YS2aqs7AuH95OvnqaS9reVN6uebtNvfbsNi2cDinlm5QisMYlGw
         F73RmnVqV6D3pXi9uDkEn+Mr+zL0OJClrVdkXcsLnDX/iaC/MnHkCNphDa4nXRnyPBu/
         lJD4MZ4WrdMCe6RyIxTIKn6iFJMQ7ZZtMVuWOyN4OcfoBWsoCJBG7RIAIh8Ys6zjT6lI
         APz/Q8FJrwax+cNeQGXpIDWY8gFWO9cHQrdLgkZeQ+gJgqaPIk0ux5MnyugZBEWARvo4
         0PbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BE0rMBjP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301438; x=1699906238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Tsgh7RH/JIcRRfSTSHHmtpFJhahEwG1WkIUZ93pCO9o=;
        b=jSkBGxVTUneWWmooxfv9I+crP14SWqSaiBVrdjB8q8hacvWDvGjYchKO8aRKbWzn7H
         6A18ABCx+QViFSEv9pbQX6MVHGJ8aNt7LOLGcqazsHwSnCtmtbUn54uq0jxRI+KsBtF7
         QRSnHk8MdioxlRyMalELgEsdGlFHr7t0wtEh7dlibkwyJ7pIHdok8w0Q1aVN65vUm1Tq
         80YUMp9qHyD3FUrY7Duq0+npYuYzyXF763eZ4yNQXRwrsTRzuxvugDehp8hjQAmRGC4T
         HT910HejeUDTg38ldHQ0S0Ti6PJLTt2hNHhPcqd46sYFS1YnJXMCmTDxzZRmRLlp485s
         rA3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301438; x=1699906238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Tsgh7RH/JIcRRfSTSHHmtpFJhahEwG1WkIUZ93pCO9o=;
        b=Zkh8GuM6a1uo+92zTCw1Qwb9NHcsjxnWN9aMKE6MVL7jL/B77u4Mga7np5LmJtySPo
         Kv4jwGYTRnU4wjSOW3njfcVFOMzFR/5FH/gDIMTtE+DCJcc8GYyKRGquzTdBlICK0+sB
         M4U4oROpTDMhX+vsn1DAkc0vwg+imC77lfuUTIAD+HpMjqVaobDMbSiJEWJhFu5b3Xkn
         ERQ7LHIcFqSwYVHMLQsDgFcxtSA/S+G6aEm5H9EUOwK9DCezd98uUIbBR6ovvJYfrI2Z
         n6WJeaT7kGfHwdGAFfLOGF0jP8K1ccOP17VZqQ8/JoTB7mTD3KtF1HpDaQCWzNa5lNiq
         lJsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzx0p3t8efqKRKFUzpk5BQJctCBklHCRdjyWh0U2g/ZkRWe9f3m
	dpsUPoWF5ale+IlWHKqy6sY=
X-Google-Smtp-Source: AGHT+IEuGOJsbfFdqcejAz2JoKU9DungwE59H6tlDaSbkCq9yOZt9woUrW2XQdSuvir5zc6iIwXdlA==
X-Received: by 2002:ac2:5456:0:b0:509:4f70:f6f3 with SMTP id d22-20020ac25456000000b005094f70f6f3mr8960311lfn.64.1699301436908;
        Mon, 06 Nov 2023 12:10:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8e:b0:507:b8d5:d6d3 with SMTP id
 g14-20020a0565123b8e00b00507b8d5d6d3ls1557479lfv.0.-pod-prod-09-eu; Mon, 06
 Nov 2023 12:10:35 -0800 (PST)
X-Received: by 2002:a19:430e:0:b0:507:c871:7888 with SMTP id q14-20020a19430e000000b00507c8717888mr22721478lfa.9.1699301434961;
        Mon, 06 Nov 2023 12:10:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301434; cv=none;
        d=google.com; s=arc-20160816;
        b=CN7CN2KD6TLa6tZS8+iMy04wamtu/vBFgHQLRhS64ha/FnkCF06aWffDhwjXAMQZoS
         EVBK/NHWjYXs3v3XRSbb6arOnVXSN+3K2Gg8/06yOSUDWLwZwSB1IgA44fOPlGh3dyuP
         LXGVq0r87PcE1AyLJzf99dkSjwmUnQ7HMZoiU2H3dSEs8YCiDghkVViw5gre1RrKpybl
         3C+UmlnANXLHYA622H4pfDiuiinnmKSmmkI49hXOwo5Sa2pSLrfwlfA3QPli0ypgfl4p
         3lxF9dpb9mwQ+PF7UYh/8ABjpa8sz8mpcyb9vMAmuW0HbIoppJhPYW+JrVr5WRmKHU4k
         wIlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=2N8dClZX4LkeO9h3I7+1TV9x58bgqnnBtKmXGx6mG/E=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=lWDlvCgOmk6Y4BMd8EWd1aztnogucqBtL5M0cf602xq7awkfn4trVRQMLo9d4Ff1wU
         NLck/IB4L/y9LJXfnBNGBHnODKraiRnfiYXphJbMOKBi60fj19Rt/6GddYygGtgGGicT
         SbIVpAFSMSsJLQ3jBulkijXr/0AhITNt0lMzEhc8AUPdQbPGTTJHSMa42FH9WbuvtRQ+
         stJk3uyKb2ArBRBSM6PzwjMFC/alputB8spIhT7MNts6+UTK+LypIz0SvwPUnjrZkd9L
         N8F2jjdLO9Nq1SxTGRChhE5XM5XfBn6dDLsBRMw6mDHx7rdYh1Yw2jH8uuWSNUFLL76E
         iQ0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BE0rMBjP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta1.migadu.com (out-177.mta1.migadu.com. [95.215.58.177])
        by gmr-mx.google.com with ESMTPS id bp17-20020a056512159100b005068bf0b332si506336lfb.1.2023.11.06.12.10.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:10:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as permitted sender) client-ip=95.215.58.177;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 00/20] kasan: save mempool stack traces
Date: Mon,  6 Nov 2023 21:10:09 +0100
Message-Id: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BE0rMBjP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.177 as
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

I'm posting this series as an RFC, as it has a few non-trivial-to-resolve
conflicts with the stack depot eviction patches. I'll rebase the series and
resolve the conflicts once the stack depot patches are in the mm tree.

Andrey Konovalov (20):
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
  mempool: use new mempool KASAN hooks
  mempool: introduce mempool_use_prealloc_only
  kasan: add mempool tests
  kasan: rename pagealloc tests
  kasan: reorder tests
  kasan: rename and document kasan_(un)poison_object_data
  skbuff: use mempool KASAN hooks
  io_uring: use mempool KASAN hook

 include/linux/kasan.h   | 161 +++++++-
 include/linux/mempool.h |   2 +
 io_uring/alloc_cache.h  |   5 +-
 mm/kasan/common.c       | 221 ++++++----
 mm/kasan/kasan_test.c   | 876 +++++++++++++++++++++++++++-------------
 mm/mempool.c            |  49 ++-
 mm/slab.c               |  10 +-
 mm/slub.c               |   4 +-
 net/core/skbuff.c       |  10 +-
 9 files changed, 940 insertions(+), 398 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1699297309.git.andreyknvl%40google.com.
