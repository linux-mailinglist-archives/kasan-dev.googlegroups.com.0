Return-Path: <kasan-dev+bncBAABBJ7ZQOHAMGQEXVNMAHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id D708D47B56E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:03 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id v18-20020a5d5912000000b001815910d2c0sf3942923wrd.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037543; cv=pass;
        d=google.com; s=arc-20160816;
        b=DhLOYAw+Dj4NaDNshAGbvh8w5BmkUNsVyGIw2pzjpjJE9qbX4J2uIE3iX3dUcCx9C+
         kadI+2gZqX0pNgtL3HOlL0Ug/wjgge+9baJvJMXczTxof2Mvli+43DbsJkomUvgPWrr0
         4ZzmEuVT5zLJWvpWXpr4szdVE6EDOkPeNZXCvuVRdB9eNunGli4gbkCBPTLLBd/UcVvR
         n5UX1XrwBme4ZHrXQFrYyZIY+yxIBHG0ufDTt84+BKbCbiZY0ZOEkqXpa3gJE9WG4zZp
         MfBoRM5DEHnIsg4TNPU5zfnt9MLdLMIih39nk2lx4d06G3fvAYeuHMYdMqgW8Z746chL
         aKcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xGPcUMB8ZHuO7J/PqDQeRQDrkbM5Cw0v8TpiF9PiuwM=;
        b=gqNzUGhAe/WyeNSe8dgag3vZJrcf+Hym0cgeeWSUGCCRbCuzB9gbMdez9sOiORhNWa
         JM/mG/glbuXe8lq+APmdx6q2wa47BvntB1/wBtimM6eCoiJFweF4dB6xbucGB/lF46Vo
         b+t6t2irVEcLK+lL/ACwBRkbYFyfkyRlENVes93FrYTLZTjjkNMUM+C9qwg+CwKh2L8o
         j+EHTcdbW+661c5SwC+2XGDbATruR7m7hdZihHjtVLfkV8YusHo18i91octThkxX5T2c
         jqef7mtczvrOVHQe0TIuS5jOS3l669n2p5GfkHUES5mpb0ysTvi45YGcsPrYAJDQm/ru
         yKRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xsPBZg4G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xGPcUMB8ZHuO7J/PqDQeRQDrkbM5Cw0v8TpiF9PiuwM=;
        b=KAmzU9/OFQRkyxdQrOvSXL8Coh6FE8nbSg+WzFrqwJhJ13gqpSFNnbnrYtRGx5Ar+g
         bGq6Vy6Vr9DVEb/r7xjDszSBcZqe62KQOXZGX9rllcuRU8ffYgpjT09AJ3UFfvsdl1Dn
         1/zB1ae/oAiHkhbKjPv1PK/Nv+2zfX/QPcreToG7tHqfIHSyVFuarYFJBh3En8wWWVNb
         Y/DRUQuHaNSjvUgyG9PtTN0m4Q5eqjU9vozVgRZy9znAUiL7at+UcEXLy8rZq3yPFyW+
         KLRGOYgGRELYipN4ckVIKTeMUUSa/2b8Oi6jUFyNUc/aG7AxXuFr2vSahfPgZd/rgQQ+
         P9Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xGPcUMB8ZHuO7J/PqDQeRQDrkbM5Cw0v8TpiF9PiuwM=;
        b=ZKwsHSHFDk76AXGyodAgJoQFtn/PParXjeqL4JwMV32oEY5y31CRytsocDYwHcc0YJ
         s1DPcUN1AUrU+GbNfk/d7PvEtxyFQPSJt8WnU8vGhO568kFCZUSFsaULjj2WZmIHzc2N
         sf61/bDB1lk/2YPbM/+LwIvO/shSxQB2IOcucsmNFdklWoklEu+hkSnID+k/hO8A+L79
         LVxleExdcC3PQq+ax3UJ3YKwg6SpLiAFO+i8TNOZJ7OL270ujsbUutWCHnU5NZ6383Zq
         9L4ENWaVaNdTotYm9OTtEi1Cyk3V8xPkkfq3HmO/Nd8WkLAqp7GtMauyU1c06HvydsqN
         o0fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MYJLhGOP/bZBKx8eNzh41kyDlw3dhJ0muQWcqy2ZQ7+dQ/ajZ
	5pcqkws0zYxT5X+Sn1E0QTE=
X-Google-Smtp-Source: ABdhPJyHumievqZHwhOEC3XG8GTKVQxMjx3WPbVZ1MMOeOAiNNKg1r3lkuFHA4/64vGIThd6kUGJOw==
X-Received: by 2002:adf:c186:: with SMTP id x6mr104512wre.580.1640037543631;
        Mon, 20 Dec 2021 13:59:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls233593wmb.3.canary-gmail; Mon,
 20 Dec 2021 13:59:02 -0800 (PST)
X-Received: by 2002:a05:600c:214:: with SMTP id 20mr53693wmi.84.1640037542942;
        Mon, 20 Dec 2021 13:59:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037542; cv=none;
        d=google.com; s=arc-20160816;
        b=HDx4dMnp8TU61kMsdlDp+HMgRJyxZlsXjvp582fY7syG5oVc+g04tEefkRhGfcKLIa
         1itnOYz/ybIYiFXeAfoM/+l6+nIpoWvTaR76HayOQgc4hZa7IvPyurv17nRIDakfI5PC
         B341SnJdJnoHdiIwbJTtaadKtCkNqV7cnNrnr3JltbuUF+0Q2LIhQ2z1NVLPDrGCcuYX
         bBNN5N2OoMLQaj5HZ8z6N3uuUCnHLGo35rZkRratfxg6P/Ncsl8x8Oo4dNFeAbnBNxiz
         rxrbB1kOdSXAWpEKylPG5hu+vNixxBX62k5a4aaGfkFKDXlp3j7/t4jvgXXGXRj3Blh7
         sNug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YEOG1fBxE2urzqqiJsu6t18C/X8DZDEufDfmYZqUEJQ=;
        b=J1XRIXrHGhSreJlVyBhQg9SlkpZYkdNsF7cKB16ghD2beWe0E0g5HjwQm+mvWNQuMH
         Jv6nvyUoMZdgOSVU5X3VhtRYcu2AnCTx2sO6WLGavgAnpmS0mg8blQrIwuYyFski0Pbt
         HdAxYGlsnYtJniKTFQfVKhPy4395nRxNXE+zz80akWmhczy/pQkB/0/nEO947v5e+ScR
         G6dxL7s6C8zOIEWPrXsajl8NYrExRfBeaQ2ghAPAwVqQpYzUWvNYD6BC9n17GJTfU3Uq
         PQO37jm2qzmkCAPpP7mHLmSEaEQCqhh1HFVMrcda2apkrjesYmBNTh2IDFT2cI+xQ8zW
         cP1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xsPBZg4G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id g9si966780wrm.3.2021.12.20.13.59.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:02 -0800 (PST)
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
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 02/39] kasan, page_alloc: move tag_clear_highpage out of kernel_init_free_pages
Date: Mon, 20 Dec 2021 22:58:17 +0100
Message-Id: <87728d80f8b580ddcd91693f3d42ffb36b22faa2.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xsPBZg4G;       spf=pass
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

Currently, kernel_init_free_pages() serves two purposes: it either only
zeroes memory or zeroes both memory and memory tags via a different
code path. As this function has only two callers, each using only one
code path, this behaviour is confusing.

Pull the code that zeroes both memory and tags out of
kernel_init_free_pages().

As a result of this change, the code in free_pages_prepare() starts to
look complicated, but this is improved in the few following patches.
Those improvements are not integrated into this patch to make diffs
easier to read.

This patch does no functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/page_alloc.c | 24 +++++++++++++-----------
 1 file changed, 13 insertions(+), 11 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index f0bcecac19cd..7c2b29483b53 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1281,16 +1281,10 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	       PageSkipKASanPoison(page);
 }
 
-static void kernel_init_free_pages(struct page *page, int numpages, bool zero_tags)
+static void kernel_init_free_pages(struct page *page, int numpages)
 {
 	int i;
 
-	if (zero_tags) {
-		for (i = 0; i < numpages; i++)
-			tag_clear_highpage(page + i);
-		return;
-	}
-
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
 	for (i = 0; i < numpages; i++) {
@@ -1386,7 +1380,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 		bool init = want_init_on_free();
 
 		if (init)
-			kernel_init_free_pages(page, 1 << order, false);
+			kernel_init_free_pages(page, 1 << order);
 		if (!skip_kasan_poison)
 			kasan_poison_pages(page, order, init);
 	}
@@ -2429,9 +2423,17 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
 
 		kasan_unpoison_pages(page, order, init);
-		if (init)
-			kernel_init_free_pages(page, 1 << order,
-					       gfp_flags & __GFP_ZEROTAGS);
+
+		if (init) {
+			if (gfp_flags & __GFP_ZEROTAGS) {
+				int i;
+
+				for (i = 0; i < 1 << order; i++)
+					tag_clear_highpage(page + i);
+			} else {
+				kernel_init_free_pages(page, 1 << order);
+			}
+		}
 	}
 
 	set_page_owner(page, order, gfp_flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87728d80f8b580ddcd91693f3d42ffb36b22faa2.1640036051.git.andreyknvl%40google.com.
