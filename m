Return-Path: <kasan-dev+bncBAABBQ4JXKGQMGQEGULIXXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id CDDA946AAD3
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:43 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id o15-20020a2e90cf000000b00218dfebebdesf3843182ljg.13
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827203; cv=pass;
        d=google.com; s=arc-20160816;
        b=PD+JOirNRjSf+f+DclnWSV0SAqhq/2xeglqb4k44u5gi3dHtS2R/KXCGl08uRd6pyu
         wkwzxk2A1feH9ZNTDjSVyBSigTdhJHES8TQDi/EPifRsO9wX0R6XMVorUfe329oTz5AZ
         KUHJeQCCrCC7KZIqkBJtQKxwvfLX6/KLWFITt1LbsKJJWML+1JJIwev+Ze7ew3LT031Z
         dVqYstOV+Bm/uIP3EBunWB7T75Y3U35U6WG5LsQNLlMea9iq8FFxuze/wACvQ8D+9pF0
         TexNrK5U0gdXEn9FjgF/r02LZVQesnJjNl+YyTn8ZJccu8taYZut64XIOwC82KwZ6C3V
         8QmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IHc98r9BSTE22xp6xDy3iRnNonGsx/lbPNd21EMawas=;
        b=Vwiy/M0nAhyqYd9mJyG5qsKYh27mAzw0yBiRzUY+f0vTzVivBsIS91wp9EhrmuobPW
         Btv1p5W4tvX0KuaTK3m6+TXLkr9xjW4JiNplaY85tebTVEV2kPI1qkkAFS5CiIPxUBHe
         nbPpM48ckfEBgUisILVmxjoUHhO1CBhevELc9J0om+3AtmkPqMiEMKmtb0lQOfSBBjuj
         Vjsq9RtTRYVUILW2Dw4fRaqLB7w5RtUvYzdeuF5y1rEToYS6Le85OiVhBSd3qBmW++zS
         D9JyblhmxazUFo4/9OmXpzXlAJQWc9BzeqGwfBFRj1GfYkSU1bGSwT3gKhA9rVHL4rJb
         kIYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dv+XWoVf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IHc98r9BSTE22xp6xDy3iRnNonGsx/lbPNd21EMawas=;
        b=mvG0cXD3AdwfdxYyld3t+JmwzRSki4Xgo7dOfwU4y+/OJpGlHT/HBku/uO0gNytt1T
         yZCaX66Clb/lh1rzn4YPbHHzT/dAZTs+bAuvnYbJdK7v2qwjohZgAb7no8xT8+xZeqvb
         tB8ydSG6p9QqHqgEnZIm9BzUwD9YFBalJ321xchp9PY1YTynQr9Ig2jeu0pLK/5hBmRX
         6Hjj+1rRd+4LbopbVpT4I4cpBdo6ShgK8WWZ6RLYCNFYeK40INQXfGQQ2Aot0Sh12ur0
         rMUMOOo91Vt9MW/QbiLYHGdCorLIhUB6Ygu4Go8RI7xKHMv0unP2EnGOwOyIMPb2LOdw
         M95g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IHc98r9BSTE22xp6xDy3iRnNonGsx/lbPNd21EMawas=;
        b=1f3jJSoFvj2tC/QDpond68RFWgasa8vZSg2bOOuN+yraJSax6ck1UbpAkfEV5ydOJy
         d8SRVJA7K4fz7jd1nIw6na4FyXdqI74HDkQjkt/O+G9Rwn57bRvFvDdcClAVN7EFRiMT
         q9K3SAoeZqHDwtkY+3QaOy2ujG2o/xe14WbP23uFnfM/wcGfmUvxbxH+aeIh+/YvwV/e
         PSDsuEZmnRio6XKrwWCV6aJGcLGE7JZz7uPq7nGHJVC+3ZQsHD52HEqRFK68sERA5ZKJ
         WRTPG+SflUy+WLIq9VYKxmwKAajVlAe22r04ebus1R3BOFrvbdq1w1+tfA/oB6MTxxIX
         lT0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530FB7LgnsOZXvF1UST2YaOJK1OGjMQJvPuBQSaUPQTYv2DXpt98
	Tb5G9gm84u0ewwxA7g/TVHA=
X-Google-Smtp-Source: ABdhPJzoGmmFRPjOJJEpTgKRlutSsI9Vuz7WZ5+HZzatKIym51nSDV+NXpo1AFH5SQ+7LiEY/YfqHA==
X-Received: by 2002:a2e:bc24:: with SMTP id b36mr38719888ljf.54.1638827203375;
        Mon, 06 Dec 2021 13:46:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1927986lfu.0.gmail; Mon,
 06 Dec 2021 13:46:42 -0800 (PST)
X-Received: by 2002:ac2:44ba:: with SMTP id c26mr36782052lfm.624.1638827202574;
        Mon, 06 Dec 2021 13:46:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827202; cv=none;
        d=google.com; s=arc-20160816;
        b=oy842Jb5b647LPW6U9TNtD08nWsJeOnpQwU3rP/jmlOPOxMxurBvrkn/a6O+EUmjX7
         p0m/PEa+OxwJA9+JkbTlIrrUWw77GApywQpMMIfmYw7jOJyU683g/5umMS5D95b/jO2P
         xXt0MB4zaMpDIrTVoFXiW4jWkgyHtI0MCG6pbArUhmhUBi0zdk2SB58u6pKhW/J3WJie
         uq4kncfURpDqrTR5+sjvkHrDEqCgbOJdK1qlJjkfdYU5xGD4teeA8eEPN+E383CkUoEb
         W5vXnHvHRpcOc03EPRtAyJW0QGNLmqJh8wkWB8zayzZzrJc5Y4lyFUy1E1wKECWSHIp3
         4olQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MyllHPB10Kx40eayZCcKDlRSKUaneC5WeW2VZ41vX/A=;
        b=SfBfblhMqX+8+eakGGKLr4czVD7O8jKxyizB/EwRncaflQE5Ozgcwzoy/sDZhB8lm4
         muurrT64x5ITPlplRPz/yEc1kmG+/a4ka42uzhHxp9ABRPUCeid8uWMS8YgX1fd5XqII
         joTMlxsN32Zhb7+uxfH9wekS9PcZJ4mC9X7/pVpCtNrUWFtbSCV/6N1Yt60LzOawFx0Z
         +m0m9zarU+mhy9POzIl3jQsiozw0vZcuT8sEZTjQZIfAGrZIb3bgYCLCMsxqthUEMHEv
         mXO5aagiL0jEHvfQkyxvA2sdgIfq8P+XeAPOmqIAe8e2nyk6aNyoD+3Az77iqoedXXmY
         aZgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dv+XWoVf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id i16si906005lfv.2.2021.12.06.13.46.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 27/34] kasan, page_alloc: allow skipping memory init for HW_TAGS
Date: Mon,  6 Dec 2021 22:44:04 +0100
Message-Id: <e7527bc49c8b318443c8627565cbab3ba2f4da76.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dv+XWoVf;       spf=pass
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

This patch adds a new GFP flag __GFP_SKIP_ZERO that allows to skip
memory initialization. The flag is only effective with HW_TAGS KASAN.

This flag will be used by vmalloc code for page_alloc allocations
backing vmalloc() mappings in a following patch. The reason to skip
memory initialization for these pages in page_alloc is because vmalloc
code will be initializing them instead.

With the current implementation, when __GFP_SKIP_ZERO is provided,
__GFP_ZEROTAGS is ignored. This doesn't matter, as these two flags are
never provided at the same time. However, if this is changed in the
future, this particular implementation detail can be changed as well.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 include/linux/gfp.h | 16 +++++++++++-----
 mm/page_alloc.c     | 13 ++++++++++++-
 2 files changed, 23 insertions(+), 6 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 8a3083d4cbbe..5dbde04e8e7b 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -54,10 +54,11 @@ struct vm_area_struct;
 #define ___GFP_THISNODE		0x200000u
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
-#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
-#define ___GFP_SKIP_KASAN_POISON	0x2000000u
+#define ___GFP_SKIP_ZERO	0x1000000u
+#define ___GFP_SKIP_KASAN_UNPOISON	0x2000000u
+#define ___GFP_SKIP_KASAN_POISON	0x4000000u
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x4000000u
+#define ___GFP_NOLOCKDEP	0x8000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -234,7 +235,11 @@ struct vm_area_struct;
  * %__GFP_ZERO returns a zeroed page on success.
  *
  * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
- * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc, provided that
+ * __GFP_SKIP_ZERO is not set).
+ *
+ * %__GFP_SKIP_ZERO makes page_alloc skip zeroing memory.
+ * Only effective when HW_TAGS KASAN is enabled.
  *
  * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
  * Only effective in HW_TAGS mode.
@@ -246,6 +251,7 @@ struct vm_area_struct;
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
+#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
 #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
 #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
@@ -253,7 +259,7 @@ struct vm_area_struct;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 7065d0e763e9..366b08b761ee 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2395,10 +2395,21 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
 	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
 }
 
+static inline bool should_skip_init(gfp_t flags)
+{
+	/* Don't skip if a software KASAN mode is enabled. */
+	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
+		return false;
+
+	/* For hardware tag-based KASAN, skip if requested. */
+	return (flags & __GFP_SKIP_ZERO);
+}
+
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
-	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
+	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
+			!should_skip_init(gfp_flags);
 	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
 
 	set_page_private(page, 0);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e7527bc49c8b318443c8627565cbab3ba2f4da76.1638825394.git.andreyknvl%40google.com.
