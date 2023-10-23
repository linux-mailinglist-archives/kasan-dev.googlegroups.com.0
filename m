Return-Path: <kasan-dev+bncBAABBZF33KUQMGQESEK6CQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CD557D3C41
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:23:03 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-507ceeff451sf3632635e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:23:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078182; cv=pass;
        d=google.com; s=arc-20160816;
        b=ugcujRA6RKDPgUWPSBocqGym3yYcS2tIwnxbR1bGijfV8uw72wx53RyMG2Ln+RHi+G
         OSDVXd2nSg5J/Qih3P2qKK+eYMCM3Ldr74Q/fz398Jeiu1P16UCbt7n13iEjWD43Q5F8
         J9oeeMUxvalxlXvs++4htbrfyYigvCwU+AtCWVrqMw44C6A9+QjIlF4kvfey4v6fn49b
         HrV/w0yI8CaJxFM5Se2Uz2KnXdW9TERpwdHuYOKHx9LVjz35h8ceOqZQgK8jw7ZFPMuM
         /ed1nyiHgJgkmqLH7/pUCdCJqC9pLfNSqsFEO+zCMt1DhHVplf69jpK15c15ESPwKadc
         0uxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Bfg1mtd7i6huChFTEefBS9eqXTxm3xk2t/u/lk9Okbk=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=r83EEgZLAe1LuxnkyJmVpdIYIePcqZipMKv+dwz87acVFBryWk4z47A36qxmZY0zkp
         VWZg+0KXbOdf/QI4V7+oiFSl9JSZXvdX+Us3MtEiDBjTac13BkU1jhujTLyfGVzVC8kR
         F/dyepHqLctNaRjJ9lUhjm19bn4do5Esxcm4qdhcjcepeO9CGki833gI9IzTSztaD+ka
         VAPGrZwhWkodbDqj+ZmIFLkKmUEnbahCTcqfwiKMwTCXo/3y3lwqtjNWR8sPAgfa0xk/
         8lPJgaUbs16pGaS5mQAxx8eCjYBYZl0ujfnBlhnvDBl6hBvhGR/cNjnl4TRZe8uKFTTH
         Ua3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BwPbMNBq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078182; x=1698682982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bfg1mtd7i6huChFTEefBS9eqXTxm3xk2t/u/lk9Okbk=;
        b=OyEDc/Z7ffmKMhwzzbfq5evTkePXBcBGiH6w/ok1cFlDnAGdfAqyvYNIYpExDBfSV0
         RvtRGaqLL509eC9WkSFKS30YFFDtuOiaSJqoIVaT27syvWW0MKn5fSPWejihI2gk9RJl
         89686h5YUuPrD3imXPTl8DfJXKiogo/a+g/XnCXF96REni2LWN7mxmE8ZbRCvFUHLE47
         dVpUHomBJIkrjoiFs+eVCq3y+rTMwBFDBQ8CAXY8hL6Dk0su6YBrnrRGgCZYFhL0Sv8P
         LeakiVIiSSBgUJMqY5RGEotookChcdh15J6T6w6Fha9spyCqo+tOLdLTdxf/lrJoOhY/
         AHqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078182; x=1698682982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bfg1mtd7i6huChFTEefBS9eqXTxm3xk2t/u/lk9Okbk=;
        b=m23hVIfiidBB6RCLnvN/WKq56SsKlfzhrWsYyLY8YhCtNKpUvvJ9zV3pF4bnw13oYy
         y5vOflZG+/VfHKFSy9VtxIoW4IHPoQ1m4rnVsQqmd92tW1tVQEg+sa4/qcKaqPR+WDdp
         QhlFWHc+crKzD46wi+7xtpIwD3QPhyn5DnEXXYdzrX4ZqWLb6lK8WEqbirhnq71T4lay
         Qn22jVuaS0ZAhB7JMpA9+WsIZPL4TTM5qhiVIXfODB2B8ZKJQdirquoIsVVJ9xAEdput
         gUHCI0CGwPbVa9syT6ejHaaL3Okia+FN1ejQ8y5S07GCiEdHnKon+ddWohDu1QdnKuwy
         yZRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxtNt8mkERlBr8XxuJeqU+LA9r7W5O/4HUcH43LVU5wlmcR92lW
	YR23q6G2zuChGjKqWMCJK7k=
X-Google-Smtp-Source: AGHT+IFFaCYoj9b5EM7fEjYrQ8wWUUcZZ8oz8uTJnxmbkMaVvb+F+SukACFmxYASXQh/5TRHil+u+Q==
X-Received: by 2002:ac2:4d10:0:b0:507:a984:bf3d with SMTP id r16-20020ac24d10000000b00507a984bf3dmr6553238lfi.36.1698078181176;
        Mon, 23 Oct 2023 09:23:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ad0:b0:507:b8d5:d6cd with SMTP id
 n16-20020a0565120ad000b00507b8d5d6cdls47929lfu.0.-pod-prod-02-eu; Mon, 23 Oct
 2023 09:22:59 -0700 (PDT)
X-Received: by 2002:a19:4f4c:0:b0:507:9f0a:60e5 with SMTP id a12-20020a194f4c000000b005079f0a60e5mr5952095lfk.43.1698078179457;
        Mon, 23 Oct 2023 09:22:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078179; cv=none;
        d=google.com; s=arc-20160816;
        b=qsGkuEGseHIpT6mHZTU3Q6t0g2CjapW2pgoVfYyqbVNQ8Vvh596gDEVv8RRwryXJaU
         0raSlbuXUaBP7AR8MEm20P3ov5R5ue/U02RcrjOKsIYyKW4i9VDt5YrY/5Q1VMNDxvts
         Qjcyv0a3RH7odQ0/7+U9BuVK88fHhz6fp/Ei7ujxgisquDUUX9Jf+EIW80qxidUcnupH
         LwqGdHgd9VlivbHglTFkGGL0WQSfiZbeYf1piriE+MD151O1fITN6RdDhJ3ZZMLGreRn
         FO3q1uq7ASx2SORn77geiSpzaV4NQSTOAeaZgS3lSI8/NUSDrO1BQESF2S4HIRJ/Q3M4
         PBiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hlykGlfL2an/VgWBLR95t+wE6CpOLlFaVT0cHbSVLN0=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=dUjGQj/TvGY9lEn7t+hJ75rYA5fjwNKr/16OgcF7dmyhZZII2eCItK9B4gOdRkOfMk
         1PjT2jcXPfRhJOAQNnIfXBDzjRo7sr8OyE8fZnpLs2kUO15QQeTSVt3KoB3h5VPHOKdV
         A6QcxrdD0nP+cHEna12qpePVpg3UpnVuRSvaoLnGO0NzAQScbgpptew58i8EvF2DaJUr
         1J3qCtIJBcF0i4D49WIQ2VkddC6X+lWahj1wT8YifIo3WhF6sxC93r5f6eKUg51SeEhi
         pYkkVk+nzH1vSJiJBmKjl8iUyzP2B78SiTq7nUL9MMn3bFPSR9irGA0nHUanikZifQCA
         u74g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BwPbMNBq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-200.mta0.migadu.com (out-200.mta0.migadu.com. [2001:41d0:1004:224b::c8])
        by gmr-mx.google.com with ESMTPS id j21-20020a05651231d500b00505701698aasi236772lfe.2.2023.10.23.09.22.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:22:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c8 as permitted sender) client-ip=2001:41d0:1004:224b::c8;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 02/19] lib/stackdepot: simplify __stack_depot_save
Date: Mon, 23 Oct 2023 18:22:33 +0200
Message-Id: <6ff0d1e89e50ba74618eed30fd3170dc78decea3.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
References: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BwPbMNBq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::c8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

The retval local variable in __stack_depot_save has the union type
handle_parts, but the function never uses anything but the union's
handle field.

Define retval simply as depot_stack_handle_t to simplify the code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 9 ++++-----
 1 file changed, 4 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 3a945c7206f3..0772125efe8a 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -360,7 +360,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					gfp_t alloc_flags, bool can_alloc)
 {
 	struct stack_record *found = NULL, **bucket;
-	union handle_parts retval = { .handle = 0 };
+	depot_stack_handle_t handle = 0;
 	struct page *page = NULL;
 	void *prealloc = NULL;
 	unsigned long flags;
@@ -377,7 +377,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	nr_entries = filter_irq_stacks(entries, nr_entries);
 
 	if (unlikely(nr_entries == 0) || stack_depot_disabled)
-		goto fast_exit;
+		return 0;
 
 	hash = hash_stack(entries, nr_entries);
 	bucket = &stack_table[hash & stack_hash_mask];
@@ -443,9 +443,8 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
 	}
 	if (found)
-		retval.handle = found->handle.handle;
-fast_exit:
-	return retval.handle;
+		handle = found->handle.handle;
+	return handle;
 }
 EXPORT_SYMBOL_GPL(__stack_depot_save);
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ff0d1e89e50ba74618eed30fd3170dc78decea3.1698077459.git.andreyknvl%40google.com.
