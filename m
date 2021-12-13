Return-Path: <kasan-dev+bncBAABBLUC36GQMGQEXDBY4XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id BEA984736F4
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:54 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id m2-20020a056512014200b0041042b64791sf8075313lfo.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432494; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sbg0UevlV/AYh4FUcFV+3Is2MS509T0p0Wqibmj/R/eTbmIdmiSQibO7UGQCcO+jcW
         DFpFX0E64ByJKEEV+5LctEukp0x9jXHQ52clYMJlGRdcLBg7L+hFo/rScHNxTZ8zrGtn
         8kLUB3mOv/IS2qzlCecMlVLpkzJheT2TSrHmVjWMxuOXU6gK+mTgHUcbLvrzHiW9u39a
         Tk7PW4d2M0doWoSdtseIPzmVmaIQNI0IhW5xUNwNblICZS4wgozAyVVQ2XLZZ1b3AxzB
         plcfImhKbg0lo5T35SIZjJoAk99jHUAIZGavrZUJPchBBn4OSrZ5b7Ja76wkbWDmLg4d
         ndtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tB+HsaKNxlP+3jLC8yzAkScwH/zpBV5XrvcGe7fLJp8=;
        b=Pai6QH0hxsd6cj4cINSUWgaIaAiIBiH82rHruKhzMdSQ+55ZfUSlaA8GePSoc+q1Gw
         Q6aNjWmPRosmmGt5FfZFKQAf971oQi1tfs8ZF5ZjCGJCAs0gyNCV0TPmlOM7LHspVHTJ
         2iFuB7awAY4gpI4+h1oi92fZMgjFetr9WhorinH9zBxKZva+UGzwCy/1jmvAmbEeJRPe
         +qi0kpXQb11TXMBhWzB7UJVoKvEPTTivsBKixVzfZ8Zi7fd7z0YX/Qe3CTg9jSp3koO3
         MTx7Shf9oEVDg0RzdtsHXmXzyQbyTEi2yVSfLWE63EzW8AWoNbP3sZtkly024By7sJQM
         SB6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Do0iPBff;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tB+HsaKNxlP+3jLC8yzAkScwH/zpBV5XrvcGe7fLJp8=;
        b=mrGOgFh5/wVsJCbP9rr0WLboD6Xk9WMk7NVirhwYI8rfL70EO6/iuC/cucmi9RW7kk
         piaGWLVfaD4IXBWeREWK6YuRyWeyC2R5U52JiYtcI2EpvL3kQ21Py15FVn4U9s1/0IXs
         sO89OZnZxxzHtNgyT4y7U0DCOI/aQrL3Obf0IPx9PpOECHVqF/pARN3bcca4yoK87ITy
         WadIDcCeemT2fh8Qitu/MxfRyc9aB+c9U9szZnHmHTTXmSxXSrkvby/G6OgMKHNGPXDX
         A5MVP6kc07hG/j7ugnhTEzJc7LHg4QzKAyp5yL85IjiKYMAOwhKOmpMatH7558x0Exk8
         QJAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tB+HsaKNxlP+3jLC8yzAkScwH/zpBV5XrvcGe7fLJp8=;
        b=N1FndEZrc5d1QrDHkZUEspQpJMS+tgqRFHzE+4xPndTl1uJ4BJMQMbf51hEDcmoosM
         G77lDI16wTaem42FRchoDOpV7uoIgHwYxRIeolHHnEjLOiDoGoyyDAJWVzNqHONzUjOm
         4eLylpH2eIwrxY5WJtLWciXnLF2tSjvp50cVtsyIp4bQrHvDKmAi3XCqgOOWjAsOSWtS
         55g/v9lZ8Kd4LFni6+pu22XXWKQYegxX3L9E6ov/ks7GoNbzE0ybCmqJUx4tsMmbHaJu
         MM03P1BABHvJrZlmsJ/pg5LUmXjf2pgUvqppOyzLoWhpdPmGVz399VFHU55pwvdWpg6X
         WlLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lgMfx7EbnD5SmiUaghboKN0bbMszDaZQ44/cx6xvuKMZoLViR
	lG+rcBJlyZYm0rfRwTRMIfM=
X-Google-Smtp-Source: ABdhPJw1/7GrZjzDv+Gxy/3dhseMWmHQlA0Xmv++hiQTLSsJwIHiHX01eNY47eaif3D5yhLHl3E/8A==
X-Received: by 2002:a05:6512:1287:: with SMTP id u7mr988634lfs.226.1639432494371;
        Mon, 13 Dec 2021 13:54:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls2715644lji.1.gmail; Mon, 13 Dec
 2021 13:54:53 -0800 (PST)
X-Received: by 2002:a2e:8906:: with SMTP id d6mr1146996lji.454.1639432493702;
        Mon, 13 Dec 2021 13:54:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432493; cv=none;
        d=google.com; s=arc-20160816;
        b=prQ4NqlKq+IeUVFhzl171/OCGnDVL9ksiEjNdvtxRB3qmZNvOUUfKmHnM5Lgnn+/0h
         li6fs9rkEMyrVRg40OOR9Fz4TIbu6F5zKQSQK7fJ8vH4ASZGbVFO21w6rrk9qyOu3A8M
         XAaHXJaSOhFAES3R1+1tcbU8dvnDtHKddN1Ywrj3NQ51rEivnB5M3Scaj7blzplqmctx
         OBMzPvjrRf474Kj4AqChowKvEexB8+Bw9S3FAe5G6jp1CpXGbdrOlwp5Zc/Lwc4uEcte
         Li9nc53S+R4ltgn1lIF0ke4mx1gV+Xet6Bwk45YLvPyZZgYHgLFmHSSyqXyFhOzfHPmS
         CcDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QDgjdOHXILg4GWhjSGrbYe4VuRV1pyqBKHdDzboDC2U=;
        b=uxY2h2Vw1UwMPcvw7j7+D3KTwwp97gsPXYh5h0lYZ1EZmjWrpXIAxI/SnmBR77ADgX
         w8JuedCGQpL83mhai66E0x9fcfSSEW6Wl81f4QmK3mVDllfaHhukYmCqdKJOxMWoNe1K
         XcFBEb8C1iQogRmNLFhkJo0B5ejeNFlHE9R/JxoFfgUcSFDa0apoSstKMMoiNp58aU7u
         w1RNLubmSMhlyPU1CpUbYzXcAS5f1TvKk2WPPFgjo4ALzmRezFaj9H7CiIR/pFYz4yVz
         Ey8lHTR3ExTGxHG339c07wADb02ebry6S/3owQ6xkvcF8dQEq5MgufqGUj5bxHPaR3UN
         PAYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Do0iPBff;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id u13si547976lff.9.2021.12.13.13.54.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH mm v3 28/38] kasan, page_alloc: allow skipping memory init for HW_TAGS
Date: Mon, 13 Dec 2021 22:54:24 +0100
Message-Id: <cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Do0iPBff;       spf=pass
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

Add a new GFP flag __GFP_SKIP_ZERO that allows to skip memory
initialization. The flag is only effective with HW_TAGS KASAN.

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

Changes v2->v3:
- Update patch description.

Changes v1->v2:
- Add this patch.
---
 include/linux/gfp.h | 16 +++++++++++-----
 mm/page_alloc.c     | 13 ++++++++++++-
 2 files changed, 23 insertions(+), 6 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 6781f84345d1..b8b1a7198186 100644
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
@@ -230,7 +231,11 @@ struct vm_area_struct;
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
@@ -242,6 +247,7 @@ struct vm_area_struct;
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
+#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
 #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
 #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
@@ -249,7 +255,7 @@ struct vm_area_struct;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index f1d5b80591c4..af7516a2d5ea 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2409,10 +2409,21 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl%40google.com.
