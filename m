Return-Path: <kasan-dev+bncBAABBC4B36GQMGQEWV2Z6OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 75A144736C3
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:11 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id i131-20020a1c3b89000000b00337f92384e0sf12209189wma.5
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432331; cv=pass;
        d=google.com; s=arc-20160816;
        b=VBMc3cx2r5ozqomPAaaBST6xFh2vjzOsOAmTHjpWG+uTq55fVdLm2gxyPoszmjGXkI
         zP5v5Vv1iRLqbZy7anmDRg4SvJ/pdhVzL1teHo8kg1XhAlP6ETv3r7Vv9DoVEQA+4c4d
         7Jef/CfMCbeq/ObsK3AnPwj4Vczjysa9w9Ju/DdB7jBUJD84qWy5+4u/ByjNkcNtjGML
         owEbZaISJK42/VIdctaZVCyKR8+wvzZv2qRSF7BMcL2rLVeN2O934wj4GAO3J06uCjbC
         CbrdK4e66WJJDAL4JVEqbr4z7mcWi8eBWG62dElreLUpAnI66pWneJoK9deILsHSDCje
         +Raw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ugoiNnQGq66U++1iFF6d0dWqsJAbMJXPXy3ahhX+tYc=;
        b=wYzTkjKOkrIKBfMmXA2+SPHj+QQx6D4bUgsYZO0/wGg1cFGuxscjbO5aE3VV3Vs+lP
         xzfqaVoUff40B9SJ4UOUa/0rLdu3a+1mF8PnnuimCsM/+xtnveeFt7mfJCl7a5Swr5NN
         g4FvZUBaTB6mQVXNbOTAk0IklYIbMvQs1pBHJMBgMI29JC3iL2MBa2I7OYC8AhhzcCcr
         /oV9iOsiW9FrMJ9p5fO4gAqWmQ+CRlGQtPFD7Ry4Qyhclv/N57lGVnEAUapcsYidoo5z
         OrBWNoXGmx1cyO1cVRIFHkpuasjW9irN+s0+ug8woBBRsJ0vFhqeoEaVNENGWTCXlbxr
         cb+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RU4B+gZH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ugoiNnQGq66U++1iFF6d0dWqsJAbMJXPXy3ahhX+tYc=;
        b=Ko8C/xCuZY/+q5Ps2ueCRCxp+7nSzwP3u1Bp7H5PDGE4wcTRHIShdUNkoeolPNMrXi
         FiyHhyOAmKr3BUG1wWdmJoOM7I4kPPstJq+V6b6A02c3r+XtUq2neSO5jyIf3It8XK9n
         HFSbSsEnA3wAHWUx0JnOp+f5BIOjsAaw0qcunvS5k1e5oFpmqZJk1bCpvnreopp74Jwd
         kq0gRA2LnOJqtoGLiYsby0p0bXWRIQj2muuJ5ebp1INlVcUg0SHB63l8jqQvsaCpbimX
         0fnHgRu/UW4G6VX6yBi483k6VUuiGlUrztHsbwSE3gvZisUuwtsb7rBbLQ6nxQaYNObh
         ljFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ugoiNnQGq66U++1iFF6d0dWqsJAbMJXPXy3ahhX+tYc=;
        b=fUhPOMO1FEw3ypAemE3Xk+xB2wqq7vezY05AB9hIKpbBzh60bQGh/Iv4/4rDT0pMs8
         ueYXQWRCTWqQvgi2frVBVsUvSP9uSnPfhKUKMK97JIG0IAlgQg62jIr45F4L4K98PFMK
         Tgn1z1mqHTzuWMY4/g7TXioFE7L+rD1lPKrp+DqN0sr5FC3jHDp1DyimTMs2TBzpQjb2
         xRZAVJ8eBMLtd+QeqH4w0rGpw0jcxC+v3A/emTSCbxoiSmvSdcoJw/ubGN7xX1PZODeP
         dQnoZPf5k395ujLiPUvkW3M4Z+MJ5iz7fnRG228qhacul/f2tz0ctrVO9E1b3bxyGZLo
         yqZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531nAPBXpUvzkau9OgFlna32Jy64xjch5z5RHio2y/x39H881Zwv
	s5UYFneVVKpJJo9ZCv8Gs7c=
X-Google-Smtp-Source: ABdhPJxgBRsBSPT3KdcUK82c/G1aKLLX9dvlg4hwONESB2d+yaf9f1ghJjhvJO5+n5O0anthOFLhXQ==
X-Received: by 2002:adf:e58e:: with SMTP id l14mr1280476wrm.518.1639432331184;
        Mon, 13 Dec 2021 13:52:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls496137wrp.1.gmail; Mon, 13 Dec
 2021 13:52:10 -0800 (PST)
X-Received: by 2002:adf:e6c9:: with SMTP id y9mr1160780wrm.697.1639432330437;
        Mon, 13 Dec 2021 13:52:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432330; cv=none;
        d=google.com; s=arc-20160816;
        b=OjtfEtj9OFTMP+Odgv6++1xa7ONxMJm8xqOTFHM1t7ddQFjJ9bJcgdkACpdbOJ6Qvh
         EkHCj2z/o0TZYujPKTGobMY6z5eBJjlTOcAhQjyNcnOQRlkEuNx8ALKipf0tSqVVW7G9
         V5arwAOVt2jLKTGTaJhlPklYQTMjKnXqEArYTcRSuqv0XNijEcIuNsC5dI328wNS4+4i
         BN/Sv8ofcZXHQI4kICLyH/C7tgpJrb62P+xepPxPAQ/3UlKB63SYcANh7nwCaJnDmhyu
         17zvvyPwU4nTAQkp1cG33y9IwvTDd3U+C1aFpfZPWnw1zNyNxKWbY3cx40fjhFS8kNRQ
         /MMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C/H8xEvLFjZpRKDTHcIRqvJZF1FN7N83kytVLUev48w=;
        b=E8j84N46Bjs6U29zgP6VS8HdXiz0fZ4XjZzh5gpND+2NcqtFc9PeZzaObctJUNWk9T
         SgXtO+aqZKlMIqJ+H61KlGAh5ZsDUJ7jcCfBSIgOIPgpg1+HqU+FfhZMYJ4WM/gRB8lL
         MQ37l0yfCMX1tkr9AaTgTTX3S8d5XLS6YmnXjo/OYiPemsluYxhVYhFmIyScQIZ8DlqR
         fI+L24i/LA6FjSSL2NC3nre+wsh/elFgIgrA90nK65SAKdfIgyrDlEFPEU2jdXF71CVy
         Qidf98ZYfAlDzFYZOwg8ukeON96wLIAFDBvT2MRT/b2EsecsHQG8IK+p/S78qyLVbcwO
         JUzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RU4B+gZH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id h13si472118wrp.1.2021.12.13.13.52.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:10 -0800 (PST)
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
Subject: [PATCH mm v3 03/38] kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
Date: Mon, 13 Dec 2021 22:51:22 +0100
Message-Id: <fbd6374a0687dde28d04062807bd0764f0291dfc.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RU4B+gZH;       spf=pass
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
index 7c2b29483b53..740fb01a27ed 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1367,15 +1367,17 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fbd6374a0687dde28d04062807bd0764f0291dfc.1639432170.git.andreyknvl%40google.com.
