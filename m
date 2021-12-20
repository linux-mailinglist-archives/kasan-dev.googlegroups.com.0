Return-Path: <kasan-dev+bncBAABB5HXQOHAMGQEZ6WTVYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C76F147B566
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:56:04 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dsf224507wms.4
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:56:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037364; cv=pass;
        d=google.com; s=arc-20160816;
        b=jpFkKBtoCNyxmY8ZJapg3yArl7yOH04LeyHOpmY/hzLZEhWXaGfhJjH+uDxhLegkHH
         XM/H/aP4TqDWTUTWjUi6i4uxx7HgfyNG+JVRyrK/31y0oOGyO3JtrN5nfYtrmXUtcD44
         4B4Y8DtSNazphCYUuZNecGqrYw2J5awxnKNOI3MtFi7rI5mRzccQUUoGpoTeBVrXW4t9
         YWPcf57teMqzJP+cks4VIXxGvlBK0k+3j/w/xMUrUQDCcBogFesOFdGsvzNxQy7kx4Y8
         Uhp+rPLehz0CGlZf2jFp+hoMlPqN46kxfBcm33JUuofxa/+5j1cQrenB7KQqA3/y4UeY
         Cj2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=yPsuc+HM5xH0m/Q4cuooSRt4/hBEJgXqEjEAWZSB6l4=;
        b=YJxHR8uXbONWuZ8PjQrJZ/u7W5UCijK6B+XJjA+JqTt+cz1vDp8lGcvXoOERfLmJl4
         KCSMyilPd62p6yl1c/0bYCqEU2zSuQYwCJ/XNhVCVUc/CYPg5NonKrGxDcnt1Gq0fU0l
         zN7EmP43oHa3DDT5j3Cxh2GoIraXEyQ7jNzG508grlzF6f8/0OXsBgDMh5Ov8Dgl4ZGU
         vJ+7IrAnZ1R77+FOVHtcjGnT6a5/E+7BJEPykRcBAezql9PhXSrACWNl85rFLkDpqyDw
         ii5tFLyqhR/RBwAGED/TUpfPlY0GzFFc/sEAnDJMwq8PzT0q66Oz1tippovJamBjmZEg
         Enpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e8P88o5M;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yPsuc+HM5xH0m/Q4cuooSRt4/hBEJgXqEjEAWZSB6l4=;
        b=ZoKSQV0XsR9uY+58Hf+YqyIxHdHTxvRim+9KpufjPganOOvoOcEDoSHIVnPQ3Pk1L9
         bQ/mEAEPHbFlRkk/ARS8UTtDd5Jv94vbuiZPtAmGzmlhgpuNCJmNnAJXUe8sVKNyn2lp
         e7+/VaR0bcIGHMC5G2ns7tazao+hqJ7sFOmVyYTyYWHb5vYFhPP5lX3KDFxj0QCzBmCC
         hhRcRUkeHTgjz/kvk+zsSGV4w/Bo1aQW11CQn8a1mMV1fNySa0CuCfrW/m1ZL94UQkFb
         Fq4ilLdo6N/q4jUqyjgIuTV91nRJmqlGCbU3yhLFsT29rW/SqbpWC2WiIfaV5SWy6F74
         UFrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yPsuc+HM5xH0m/Q4cuooSRt4/hBEJgXqEjEAWZSB6l4=;
        b=bxRaFlMAPtxgSrQGS1COp6OLEgNubax+ZX3QuKwV/L/hAWnOutZsHO1xwpr/IX/VfF
         Y0tH3EXI4SLXpYJ85L3C9fzeX2OseMmAemIFp2D02iPmx5pRcwEQ5PZeG6ovabCCDURr
         zSRUl5IgJE/57Xd8LbyPmAAj9PgC3wtrqMdZ+gYOhqxZlOtaMCIeJVdnxXgFM2SGoV0p
         Kl1hdAMSUmi1n/sMitxVwv/KXnT7Mo/5My1vKi3nbMrYt+q6t/FAfeku+dU8YUcg8rCF
         sCs3TVXmk9c/7aWKn4XEvNCx1qa8yPbJ0yKVZB1grtW3C0iBaKORu9o48IknWknNceN4
         4wAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MEpGpzblejVAOsKNroat4QGES0AfbR/5zmMCK1n45sRR66ILX
	8bmrQugqZrYeI5QpyKQSPNg=
X-Google-Smtp-Source: ABdhPJzTGApRTJIzV5UNYH6+kvuW2F9UNFR6XpZa5/Y029/QaS3NxfgJhHqlMGLDSakr9qzpcQeOjQ==
X-Received: by 2002:a05:600c:1e8d:: with SMTP id be13mr25672wmb.79.1640037364486;
        Mon, 20 Dec 2021 13:56:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5082:: with SMTP id a2ls6369831wrt.1.gmail; Mon, 20 Dec
 2021 13:56:03 -0800 (PST)
X-Received: by 2002:a5d:4804:: with SMTP id l4mr71695wrq.629.1640037363757;
        Mon, 20 Dec 2021 13:56:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037363; cv=none;
        d=google.com; s=arc-20160816;
        b=BhKPbCA0oB8BHzwtcmObsAVvtd3gfD6m9VZSjwpy6mcXBCDz1rkZgDv7zHuDQQ19AA
         vNwHfzvjCVKGBzpXN8kvON/xuXnZZFbh487VdvjT+Yei+2k3bxzlyRSgEWtEa1yDf3S5
         81iZX2EvOfep/FwGF5MqOqtCn1N6+OtGZudoEUyMMv8o0ArM1XPHZplCGvkMWaVfHfqF
         RNGT2cOVKV7Et8xE9YNmWtAhrpzn1y02hbU/O3UBbBCfx2JtxGHnQibn6lAzOdDEqKUv
         2qAdQKjKKwAH16fyUGVLPqQEkY59q1lvBthU9WOSYkpEDJ8KsNPbZsAhcTawCZXL6okk
         iMGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1NLhsQtLh77LdZHgbT2kusq/cP+dmXSyIjhww1oL3wE=;
        b=W7eBbBfEfBZPUw3SnE4qXI5ggFbAmE9/wLxRRZHXASjtMxWMpVIByu+jjfQgbv/Her
         cJmpThM4uCj0MGyoCD59QZ39cYgQl5lbdQU2dKp3YRyYT4nD34P5bz08gsoXSLj+1hOQ
         /lfil8N3I7QOnS9qxMx3RYWQu/UpQT9gl+az/AY0dNCysnNNCct0Wf7J0wOrh+xBZ+pV
         zSdvoodVz8XRN4fFdo4ovXR3nl7Wh63bI3GA4yjoBgAAJ495HNlnR4p6UrOCZLzsu1um
         o/9pwl8MXqYjGnZlulAq3OZyGErwFN6/4aP3aG/PqIojALiCIlRZcoJZQ5MP1+m7VGuY
         4Oww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=e8P88o5M;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id i12si33780wml.2.2021.12.20.13.56.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:56:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2] kasan: fix quarantine conflicting with init_on_free
Date: Mon, 20 Dec 2021 22:55:59 +0100
Message-Id: <2805da5df4b57138fdacd671f5d227d58950ba54.1640037083.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=e8P88o5M;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

KASAN's quarantine might save its metadata inside freed objects. As
this happens after the memory is zeroed by the slab allocator when
init_on_free is enabled, the memory coming out of quarantine is not
properly zeroed.

This causes lib/test_meminit.c tests to fail with Generic KASAN.

Zero the metadata when the object is removed from quarantine.

Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Use memzero_explicit() instead of memset().
---
 mm/kasan/quarantine.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 587da8995f2d..08291ed33e93 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -132,11 +132,22 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
 static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 {
 	void *object = qlink_to_object(qlink, cache);
+	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
 	unsigned long flags;
 
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
 
+	/*
+	 * If init_on_free is enabled and KASAN's free metadata is stored in
+	 * the object, zero the metadata. Otherwise, the object's memory will
+	 * not be properly zeroed, as KASAN saves the metadata after the slab
+	 * allocator zeroes the object.
+	 */
+	if (slab_want_init_on_free(cache) &&
+	    cache->kasan_info.free_meta_offset == 0)
+		memzero_explicit(meta, sizeof(*meta));
+
 	/*
 	 * As the object now gets freed from the quarantine, assume that its
 	 * free track is no longer valid.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2805da5df4b57138fdacd671f5d227d58950ba54.1640037083.git.andreyknvl%40google.com.
