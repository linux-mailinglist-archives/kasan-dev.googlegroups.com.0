Return-Path: <kasan-dev+bncBAABBMUJXCHAMGQETTG7DPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id BAAE0481F7A
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:12:50 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id p2-20020a2e9a82000000b0022e01240c1bsf2130128lji.20
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:12:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891570; cv=pass;
        d=google.com; s=arc-20160816;
        b=qPs10Cx0nK1mHW4K1dEZ+pci5tQGntU8Kfw3epVxuHPLiSaGipm9fxCJ+Ursc4J5On
         sR5+2cwgU+93mlWzJQFHLXwCj7GIQQYJrGr4fnJ6W80qCp81StKTmk3L6fYwI4zdxbZX
         tFYD+bLuWmB0UFKf38y5OyR2xtjM3D8umrHwcCncsCev7cVB6FMFogWcQBWJ1exuVr2K
         5soorKo8F4qDbkmeAsVmlQB+2+6Rzto9vLQBSF8e5m48IWCe9DTnZRcJV9EcXXxALkwc
         SL4wIQbbIJwi/LL42s2yCzfPbDclvS0/3GpDlkiweR2jIwfmtxnWOKqd/WxS7DO18Pmu
         /PFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pLYyxHKHceuJStiSUey+vq7Tgrp5o2C17uS0PgqNhZM=;
        b=H/S0nG1ibi+mLF/T9IdFaAw7gpPByZmo0lkcMeZ1vjP+ExcsDOhrAJ8J3MbP8PNCsV
         ddmmDPJZenfvS6LBBue+kdqFdQOZ+4tvO5Mq/PfU1+uvh25BpC8Kt2+7Gyjx2S5SkoVO
         L1KQCxg/GgS0hRJDJmsANtjjSkLdJsO+SGfhToAVuPQ5Acivq+ab3LhNrlkMBWnkzCGR
         s5Qa2vByZg1c9vxj5yzk0Rh8nMjOTkGnAA/dQecL0ljDtxsshHMifb5rWCBjip2pRuE9
         T1xF+sUmHMygRAlXHzR8AaAjlfzyTHpoOzxkRnZnUJi3zDygWysyIXHFVLBtLZ55ZKdE
         Pe8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EiKTjB9r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pLYyxHKHceuJStiSUey+vq7Tgrp5o2C17uS0PgqNhZM=;
        b=leyDr/icF2fM5TamJN7U/0brjcfzmq+/9deZrvBFiLUguuJOA4OZwoMAwY5BwjHjEi
         wmEgysuL5pBspj+vduoHro7Nvgl8z/HRbuLcd11j3p4UbXVGkr0ShFHIS+UykUPpvuQn
         yet9jmRlkxZeBjbFWhPq0oUdsSAmgdZCzEL0JtxYpuPXhcKwzGqo5SA88vtyRZ7Vxvn3
         Aqzyh+Rst6d/LlrLwyAZ/vQcZy0yFB+KaZiE+cSD89xdMg0cVMyistvCqXQIZ+f/hY5O
         zhtnuQacCzOmRCfkQMHg/43AFqU737koleI6JPV7a64XfTJHDKvVYksPqXpe1xA8APS6
         VIHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pLYyxHKHceuJStiSUey+vq7Tgrp5o2C17uS0PgqNhZM=;
        b=pDo8fnACTffXpFgMd23ocdZt+PWrsoPmYzdC/kzc0OGCCMlMKdmq0SvfUbGmV5vHC7
         BiGaFIuZE1WVUuxQX7WtHxnLOYIXFHwiIpjIHu43YL0rN2iEReL0nkcfiWfMIB0i06Dd
         jMQsf/LbwgVKhRehMfV0e4JLaoaxykkg2ASmEWFIxkXf+pmu9leVeWicFJ77UHXNzh/x
         vaImx9ns9dMZEE6CdP4NPrStAHZpoCTxbVZ/ynSNMkc8PljnvubhM/WRZtFGc393f4Og
         lMuP0Z6nbO8m5pCHQ9mAw6hO4cyYXVWEmN/ZiY0oqXS1V++jGa4OzhmGdzP6hT5XL8vQ
         PfvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53013t6KkL+DI1X7ILg7CXkzkRUAQ1nLL3rnC3wfKHVcpfJAr6zU
	w3cXYeYjs0DG5eUUnBoeY7w=
X-Google-Smtp-Source: ABdhPJyua3DxX8I6OkpVtJ6XzGKxwC0gjzXVPyYiV2uddlFIQnglGaAi5+onWWyxUkPZvgqVipITMw==
X-Received: by 2002:a19:501a:: with SMTP id e26mr6329235lfb.15.1640891570192;
        Thu, 30 Dec 2021 11:12:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:a0b:: with SMTP id k11ls1837908ljq.6.gmail; Thu, 30
 Dec 2021 11:12:49 -0800 (PST)
X-Received: by 2002:a2e:b894:: with SMTP id r20mr27476020ljp.304.1640891569524;
        Thu, 30 Dec 2021 11:12:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891569; cv=none;
        d=google.com; s=arc-20160816;
        b=K+l0FV+tOVQctxnKzjYK19fOvd9rhIuOyL76iKeRrXXE7G5OsFE1JZY9KNzmSpPw0j
         Zx0RqlOI3JWDxgAZ4s+3XBinaOHIFJB/wwBXUwDvIKUNasFrVFe6YXy7a3OwxYKE9AVU
         LnHQPnKnNK1RmBssljP+tKa3rsEYEsEkMgziXFg5QSdqCbLMmzzwIhOhyg0V3ZN+Qq2t
         vjPZF5iKhETNJCnWS++32LgzX0SPZCYUqJb3cbjqWC5vFwQ63aEzTRswTxgW+knezx7w
         Cmd+MugHwotR4c6jEZca1Dz2RAmTzR2z9EzV37izmJVQmTgWqhOehYLrVGFBBNdAakOb
         nypw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=P44oexPNaHyUsu55BCA7H5CWXGIjtRryCcrTR5E8p3A=;
        b=yEzpH4I5GA8Y4ITa9lME5qOfe6RVGqLd/UZ+WQVwpxE7bhwl7hbmaVCb1WFN2gG1jP
         5KRsZSAAivpGTt4V/tgW7wfOSQGd0AaIdRxL8gOPxWAhy1kgiFb3DIuj0XTK/fNRzJ33
         aFtzYSXYVSpxoSJnurKQvZEJrLpwIAv9Z35ueNz09gJ73iDaeiRHchZH1w1SwexpPbT9
         OlV/HQ0ql7nx2bKqVPKc5KXR6dYlbSAyDpOUwR8RyDUCGqBK7VD4Mb2YJb1cBXFFdfsM
         lZY8pAn1W0ub1l3jAfvoodjEycBf1KSzp0kD32AzcuXd0ZKn3Qrj9/gMwbtS3LkcLX3u
         wi4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EiKTjB9r;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id c2si626310ljb.7.2021.12.30.11.12.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:12:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH mm v5 03/39] kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
Date: Thu, 30 Dec 2021 20:12:05 +0100
Message-Id: <4a4fc0f2c10e3b7fda2ee5e853461b127469dc3f.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EiKTjB9r;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Currently, the code responsible for initializing and poisoning memory
in free_pages_prepare() is scattered across two locations:
kasan_free_pages() for HW_TAGS KASAN and free_pages_prepare() itself.
This is confusing.

This and a few following patches combine the code from these two
locations. Along the way, these patches also simplify the performed
checks to make them easier to follow.

Replaces the only caller of kasan_free_pages() with its implementation.

As kasan_has_integrated_init() is only true when CONFIG_KASAN_HW_TAGS
is enabled, moving the code does no functional changes.

This patch is not useful by itself but makes the simplifications in
the following patches easier to follow.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v2->v3:
- Update patch description.
---
 include/linux/kasan.h |  8 --------
 mm/kasan/common.c     |  2 +-
 mm/kasan/hw_tags.c    | 11 -----------
 mm/page_alloc.c       |  6 ++++--
 4 files changed, 5 insertions(+), 22 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 4a45562d8893..a8bfe9f157c9 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,7 +96,6 @@ static inline bool kasan_hw_tags_enabled(void)
 }
 
 void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags);
-void kasan_free_pages(struct page *page, unsigned int order);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
@@ -117,13 +116,6 @@ static __always_inline void kasan_alloc_pages(struct page *page,
 	BUILD_BUG();
 }
 
-static __always_inline void kasan_free_pages(struct page *page,
-					     unsigned int order)
-{
-	/* Only available for integrated init. */
-	BUILD_BUG();
-}
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 static inline bool kasan_has_integrated_init(void)
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 92196562687b..a0082fad48b1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -387,7 +387,7 @@ static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 	}
 
 	/*
-	 * The object will be poisoned by kasan_free_pages() or
+	 * The object will be poisoned by kasan_poison_pages() or
 	 * kasan_slab_free_mempool().
 	 */
 
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 7355cb534e4f..0b8225add2e4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -213,17 +213,6 @@ void kasan_alloc_pages(struct page *page, unsigned int order, gfp_t flags)
 	}
 }
 
-void kasan_free_pages(struct page *page, unsigned int order)
-{
-	/*
-	 * This condition should match the one in free_pages_prepare() in
-	 * page_alloc.c.
-	 */
-	bool init = want_init_on_free();
-
-	kasan_poison_pages(page, order, init);
-}
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_enable_tagging_sync(void)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 106c427ff8b8..01dcb79b3ee1 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1368,15 +1368,17 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	/*
 	 * As memory initialization might be integrated into KASAN,
-	 * kasan_free_pages and kernel_init_free_pages must be
+	 * KASAN poisoning and memory initialization code must be
 	 * kept together to avoid discrepancies in behavior.
 	 *
 	 * With hardware tag-based KASAN, memory tags must be set before the
 	 * page becomes unavailable via debug_pagealloc or arch_free_page.
 	 */
 	if (kasan_has_integrated_init()) {
+		bool init = want_init_on_free();
+
 		if (!skip_kasan_poison)
-			kasan_free_pages(page, order);
+			kasan_poison_pages(page, order, init);
 	} else {
 		bool init = want_init_on_free();
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a4fc0f2c10e3b7fda2ee5e853461b127469dc3f.1640891329.git.andreyknvl%40google.com.
