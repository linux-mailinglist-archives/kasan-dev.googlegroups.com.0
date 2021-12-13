Return-Path: <kasan-dev+bncBAABBCEB36GQMGQEOWAEMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DD374736C2
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:09 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id w21-20020a197b15000000b00422b0797fa3sf807367lfc.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432328; cv=pass;
        d=google.com; s=arc-20160816;
        b=WIFd8r6nXlnZ8OJYkTrv6Ga9bXbCc7KqJIPK4lADcr6WdcqUCYSHQxYgv7EdeRJnqL
         oQptsa0NOLbHI0dk3p92yZidf92CwOEpVOrPF1KQTEVOd8Gppw77PmH1POhL+jhm5+mT
         mIbgc4/Og/gQ5lvavWKYE30SbQVV44oidINZNGD6sywq7jB/gOdq+Z1Q2iE7/2ulTokU
         CqGM11+wGdPhC8rX6gxbBte4uaKo+8AvjLOCQkLWim59pSSnx9FlidtVGGgxRmjAQXHM
         ahYs2hq3jcQ3ZT45sIymHJ8jPA6keHOZ7t0t79SlaUf8iJB0BXZDFYO0wLgWqdt0kguS
         g9jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6TwRc2QTlDbjMk1cwcbA/NwxqwOrilHtCL9D9sQQWww=;
        b=VvekwKUU5f3Ty6qck/1GMf1PRcJvXxnjhTu1Qkcz5iuCHGXrsjtUX54bXCxN1NUvCo
         WQH0mmFfBn+AyKa7HAdyV/jOGVYbq5jBF90BmEt3H1bk5yS8S/cGFY/bHi6xmEw+lgRm
         3/K36+z9ftZVGLIFV3XZ4yYCuQZWzSCfZp6hIW8QrZqDo6fa0AMvNd6oOQYbdPMZd0Jt
         t7wEwKhE2hIMzaSSnNzHFw+4F22Ifc3psytzFNtxulqz3y8e5pDvec3gx2kMCGP8vv4G
         +Has66r2PJfJtCZDh9Iu+6DMqMORxNeNEWRQ2yEg9LZF+g+fE1T3s7xQ1Nb/1/9n5Ea/
         0auQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ox773wiF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6TwRc2QTlDbjMk1cwcbA/NwxqwOrilHtCL9D9sQQWww=;
        b=NmzxV4eS60F25gkZaWzBeGxGolrgFoKCsAkfayDm4qdoctB1cuRe6gPdIy91sI3f11
         +izxFCQfQVw5l/zncyJHzfszGrMO+BJIAEysfz0WK0y2gUHy9MZU76zgEA5LZ7uFKjrw
         8tkF10DfRzoDu94Rsh6HDWXXzLUaugIqgrqfoTWGhNo0nuyAb5M0V6G2gxI9dPMr0Cny
         mZFwgnZtvNuMDKVTRf5ARSJjrn8TvnQ0Z4LWs73lAFyVQpn21hSLw21rmP1erMUJiGlR
         FrG5gnoE7nToD2RHVbw4VQHc95U7BvNRbkg5TMaECeBEfyikpZdRm/sE9bePI8DyXDAR
         fQAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6TwRc2QTlDbjMk1cwcbA/NwxqwOrilHtCL9D9sQQWww=;
        b=6FejjGOmGYOWPz5EFEPfgdyuWpF/6tYYhEFhxG3MpjJ0ApSGh0MWhzETjX0ZlVEsfc
         +RJRRfXmWcyqHiKHwAPACp1d3dcL5Mg5evb4R0JU4Gwnzv4cUmAW4XxYfN0cDbu45UTC
         pGGJHLEP2m31x4GxcMojmD1SNb0QJnF2rzybP7grXj+Zr9pWZQ/N2UPo0c6LTAQS4gxc
         8RvmiYyFAWu/COMsRksgn+2nzoSuGHZcyo1ojki+fRPmGZPvF+5nO3bA9+hgxzsiTb8g
         Iy1q40Q3lpwS8LUbB7saGxcO0HYWgX7vgRBk67PVffcu93w8zT1SMeQevKuTbZ3K3/e5
         t+Og==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FQY6041JAH3WQeb+z+Qc76ic5AqSOI7Jqntw1AIbqDT4IHsc8
	tpWr4Z5lZZ1xZIpuAX/K3/U=
X-Google-Smtp-Source: ABdhPJxcTtJrLEkw2o7/mSCBuLUmY+uowJlXTcNM8c8Q/RrOpeutchCJxSqLA+6RdySbyRgZT4ofsQ==
X-Received: by 2002:a2e:9653:: with SMTP id z19mr1104222ljh.29.1639432328675;
        Mon, 13 Dec 2021 13:52:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1687:: with SMTP id bd7ls2709791ljb.10.gmail; Mon,
 13 Dec 2021 13:52:07 -0800 (PST)
X-Received: by 2002:a2e:2e0e:: with SMTP id u14mr1100669lju.28.1639432327796;
        Mon, 13 Dec 2021 13:52:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432327; cv=none;
        d=google.com; s=arc-20160816;
        b=Kxk+XRBl+eWeNVIuTXCalqHlB/ywGCVMdGRt1pak68oRQ+OFt4aspe1LlWlowaF6jx
         ZFKT6e2CCaVGayvK+Bl7zdCAzxNsK+abAUCuN6fpuohLbG1HlvCGFdgtZi4irkyEwQUb
         T5VlS9ZRKXiO4jm1l4xITR7O7W24DsU9scxb0S81d3Jp7BjP0x+e6wxgXBttkvbBtxTi
         ecpoeZwEGG5m49Nl5XbqjORpJi92iiM9aTQ4IUweyK2QdBS0GfuhUnSEd0zdUPQDYD8q
         OnSqOhcLqaLWkOIKWZUssJzw5Nu3cZdpBLrnJuwj03urcqswovd32cXosKgOi989gmkT
         20fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YEOG1fBxE2urzqqiJsu6t18C/X8DZDEufDfmYZqUEJQ=;
        b=oxxCl2OEOVvZq1qnJvjHlWtInZ+BbCb8TZJwyBa+AseeUmwLpjnOulofsEGqoPj3gJ
         WKsR7kLp80iJ2lMogh8Qyl75c9otyQcO/BzwSMGIFgPz0gKZ490mPXh6RMgCSF0yUEVB
         BLVHWdf+I+B4vNMBp0lk8+ecWSwDkimCUXW7/nHC7LlY3SyEV7DUJ1TQzcqgys4QdIs3
         l5kxv0JtWbKj3KWGcB7Z7+BZzZ/bhYrspcY287lO5++hW2e/2FgXcJOk8ORlsV7S2pnr
         yDXjOtEHVwEbbjbCERmYHuN1AU6P2JWFYn1xPch6Da+0+SlVwyk3Xv9Qg+GC7BwKJ4bH
         A8kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ox773wiF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id g21si810472lfv.11.2021.12.13.13.52.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v3 02/38] kasan, page_alloc: move tag_clear_highpage out of kernel_init_free_pages
Date: Mon, 13 Dec 2021 22:51:21 +0100
Message-Id: <1c0a5b8e9488ea2d34844ed2ab04383873612d1b.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ox773wiF;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c0a5b8e9488ea2d34844ed2ab04383873612d1b.1639432170.git.andreyknvl%40google.com.
