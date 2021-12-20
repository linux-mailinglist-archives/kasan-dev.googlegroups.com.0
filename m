Return-Path: <kasan-dev+bncBAABBOXCQKHAMGQEWHV3SGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id DCF8747B12B
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 17:37:14 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id a203-20020a1c7fd4000000b0034574187420sf5794569wmd.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 08:37:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640018234; cv=pass;
        d=google.com; s=arc-20160816;
        b=tEJoqUfZK9oVkKjspfkylKj9Zx4+ngybb38oFpOvJBfF/9Lt6JrcZ3HBHxadjGiYbO
         nC9Z5Xn2qvT4DYZaSDauOsyuzj3eUsmLmxJC79uhL9popjTY3Bzydykrtl0Me6SYGZfk
         2ZGrKOpimITooAnt1YFX+yMuA8ppnIAx1AaakXe6bO943XML35sfEy3VtslPJQa0XxTY
         jUTjOfgB/M52BaFsIGqQ7CnlNvH4UeMn5skgDrvJtr5XKq7RzjxcuCii3xEr7D9He15w
         nwAsdypLahTHLpunWTWGvvLm3jUhe9SF+4Suej65WXfJ8vPnmvtnx+7JKQeXhH5uGXyB
         iS2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=gXJSYiCV3uz5cx2FYP/DzIjFfz8Lvw3nu4eDnyfSw38=;
        b=MxtsljBx4oftVrN83b84/KhBkLEuyiF1TU8uZMZCJmJP6nGhhoz4/f0B4A55lI0UUa
         L080X4sFtvpesixmYO9Et87o6fJJaB/dN4aZIG9UYEl+FHXGSntZFKqdxz/11+GsSdBh
         OLca59XQYis+o2eMxB4Ld/fJPRpXsMRx/BJRFDiVMF8QCUsMsUAyIi9apD4jD2l+jdlO
         RtSQ1BlOIxCpsrbpmYHfXHrQKIyKgAcuNMQfw+W5n0kJ+KigQk2eISfvNNwqAch1sr1i
         L8sTfqRHra4TtyP7vjNbvcSjnMKs8GW0phhMSaZV6y85E5YPbP27KZ2x9h/jfn9pDFd3
         qpsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b5kkaiey;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gXJSYiCV3uz5cx2FYP/DzIjFfz8Lvw3nu4eDnyfSw38=;
        b=XIoYN96G1ivoNZEOXyCnFjQ1Me5DLpVxgSGtcnKpaQVGH/PnOfwHIcoKESg5bB4nWo
         pjdTiqJAf64otS7gZf4gK8jzW92xoPUY5TPW8DuRgwVwL7/UduYtqB5bwtQxpCU4CoS/
         B2taam1Kju0rmLHSXt+Zt7Z3YuCMQJRsnHnsH8mGhlE+oPVgzPZjiX1mY6f6s0ngETnv
         TT+OBNHdxDKer0Xi9aFZeCLyQ9iiOcwzfxuKkubHWBdj8E/5juKDPhkO6CL4S7joxpWQ
         R2beKTcI5VEWFN67QFMJmSvkIthfW68Rj9QiOSZa6ec1YUK9WoIBDZvMse6DNQxQ/GH9
         6dtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gXJSYiCV3uz5cx2FYP/DzIjFfz8Lvw3nu4eDnyfSw38=;
        b=g3n387qynvWrEd8H4zNnI/fCA1QRWlNcOtByguBEyhti8x+ugMjm5KJorGY0Pm9Zdo
         mRDjC1MczqUnMzhtFY+XSlfgzm2BvEYeoFeoMqXC4o11FvcaP+wsn+VHyAhmavcXyjGG
         FlpB6xBiEQD8PyycO8z8KUO5u4FoDrELCdIcAFDBvGaemfYkwLVWZP5wZx9s1PBH4P9+
         CT7C3QdoTaalt7b2s5FUwl7DHKk/hLcKJgVEte79yDhlI47Gt4yMGMW0JkFV10LBGBCB
         sbmT4EWOA3yMA5vOLhzBd/5KAC8yDFMDNDxN70EyGa2jyrQxlLz9mClQHZuLUftMf+2x
         NKtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dw1dGKwSY9UTBVYMj/fVZg4sb9f48ik+51w0ZoGgZ+Ek+bWwK
	ZefSUeLHSz853Owvjo5DNbY=
X-Google-Smtp-Source: ABdhPJy9IV5WXuxy2sjA0FmBAEF0HbZ3jheVAADBjrjE6CIeye9zqVGfCSUWtd6ObvXfa/3BQUIwPg==
X-Received: by 2002:a05:600c:1ca4:: with SMTP id k36mr15085393wms.169.1640018234597;
        Mon, 20 Dec 2021 08:37:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5111:: with SMTP id o17ls3454072wms.1.canary-gmail;
 Mon, 20 Dec 2021 08:37:13 -0800 (PST)
X-Received: by 2002:a7b:c94f:: with SMTP id i15mr14789577wml.79.1640018233825;
        Mon, 20 Dec 2021 08:37:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640018233; cv=none;
        d=google.com; s=arc-20160816;
        b=w98xJnlvkH4l60PhrPjTo1w+4vQqDgYfbXABh6ab6mlzNFPKuQqYWkhC/NMRxr5zTG
         mdRAHjbgLO6BGn03Q1xetmytCM/FTPgdEdpcOvn17dEDVlH4cti5HxJtf7QBx5kHiVlt
         HIyFcZ1xlRG139yhs0Bw/1d8pTZMp0WKyfsZJNMtx6tXgY1oYyRXzouGX8l97J1aJ1AG
         YWPn/brISHDfYIfkZ2HqHZcZY/w0t2NuGnhfd/VMuzvUoF3bxTcTS3Kj1Ry1E76Kiquz
         hqAc6SIpzB+RLF1HFM8HkgxV1tqQTOD3JkaLt48fsT25tyrp+10HNmufz50qsjmrlgJl
         3Qmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=beAzXMbqzjPx2jOpUAjr1xMuur29YHypIVsXOOXBjkk=;
        b=NpFW60iiw/aNRuxDv8BzVm+qpPuLnFYL6gS0q1wweqb1SENDJ2QoI1LmiBpEn60bnJ
         5YNJv+UN/bwsdjB96P+oGZZjZe7mhghhNrc+xWPDL94aXMl5fu2KOKbZo2fbBysn/LqV
         cL/nXelacTJ/VUS7eGsxVkFe7drPD9CCubaWOSwvHuPN4XFNUheK/zd7hhXztptVlrwj
         EuhydA2p/PQ+oECoC+tALq4NOoQNu8J25GCqm9dhoFjJvJ2Lt0XLPdwph72ZGhy4Xyid
         rzfC7aHriJom94cNqhnLus/WpzjKD845k1hLzPYQgQayHH7Tb3zbICkCSqYkhDAe4eo4
         q/HA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b5kkaiey;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id p22si17894wms.1.2021.12.20.08.37.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 08:37:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan: fix quarantine conflicting with init_on_free
Date: Mon, 20 Dec 2021 17:37:04 +0100
Message-Id: <a746b5baebbf79f8160c1fe09d6f8a5ab7bde1d7.1640017993.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=b5kkaiey;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

KASAN's quarantine might save its metadata inside freed objects. As
this happens after the memory is zeroed by the slab allocator when
init_on_free is enabled, the memory coming out of quarantine is not
properly zeroed.

This causes lib/test_meminit.c tests to fail with Generic KASAN.

Zero the metadata when the object is removed from quarantine.

Fixes: 6471384af2a6 ("mm: security: introduce init_on_alloc=1 and init_on_free=1 boot options")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/quarantine.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 587da8995f2d..2e50869fd8e2 100644
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
+		memset(meta, 0, sizeof(*meta));
+
 	/*
 	 * As the object now gets freed from the quarantine, assume that its
 	 * free track is no longer valid.
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a746b5baebbf79f8160c1fe09d6f8a5ab7bde1d7.1640017993.git.andreyknvl%40google.com.
