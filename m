Return-Path: <kasan-dev+bncBAABB372QOHAMGQEAXF7F2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B882947B5A4
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:23 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id a28-20020ac2505c000000b0042524c397cfsf5166167lfm.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037743; cv=pass;
        d=google.com; s=arc-20160816;
        b=UisKpcfpKHVxouDiOZfZCdYNYFIrQS37LJZyMLUD1QnOCOCvktEbs9eeo1Ny6Ex1U2
         c780TGmFNmpLCKTKJqiPsE7+aIDd8wUDnXq0BQNeystJ5zN808GRs+jEgl1+4yEp7onk
         P3i9G3YNStsdoo8F9weSqTur8ArEm8ADRBMv9NUvhH0JhjPH81Vf3kkCejJHPkhY2Swe
         0T+9pwlowKmu6OAtWtgBoN+kqwM6V4iL8rv7gGg1XuG58ZRc7U4yXLpn7BcXrCYQimc+
         GVU8A5vY4vFZjEHZRA9D4dk+O3X5cPlaiwjrviHRM4OyN6WESnpy1rznXnRpsHa9Z2/n
         hrCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EGruUOn9IMc6W3kUsAJaAZq8V4eyqzdsxdTG4xU5Gc8=;
        b=wca6OX6kwcdisd6k5w1OO1Y9bKxtV387zDnfFe/PTTqZzhHYgdcGkhx/0R9uGlOttq
         x2B9F03OXLPyNXo2p2NyvAbnGDeQ57+i7Hy8S/jN1zVmxJxAUbTg9AGgbg470+SUkYfB
         Zp/8t9iFDOLeKDRo4ewxEfoGFTaN+RTnNlk8swHLMC1yhUMiuIQV+tFIEVZxlHVF17QV
         fnmg+RlCva2GRkbwRrVVwMW9/oaCcAHLO8W4aEpLVTIVzCfZg8OFzqb7sd7kuKCO1qgJ
         6gWVQzdCrqWemkkX2mtabHL4ho7CiNsL28Hl5YVMhCBGV2Hre8DJWuLxfz0LsjMsBBtA
         wS+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lY1RxKt7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EGruUOn9IMc6W3kUsAJaAZq8V4eyqzdsxdTG4xU5Gc8=;
        b=l6g4pG1aIbnSn3mDrD1UhAyVXOYlr72IoJ9GWtLx7kf49OGrWiTYD9Ar0RQ9u5+fHq
         BBAD37c6BPdME5wVS6BMs8MZYeVL3wA4q0qj4Nu+kRUaqhwxSivz4f4yb0SW/Hj3Vlrb
         O0KW4SjDx6AvZHTH7PWnVC/KjdtmgRky2fEQkwI9qfgs+Jg05SDUFxQxkm6V0ZlUv97m
         ThmyU3VzPERnx1WOG1U1xdZ1CMCNkppeaiXqnCXwnzNqHi4eEh89bOr6SIEJZ+F0ATYx
         jk4HGobOn1TIUJGA45FdLKkkwM7xfhBq7sBU6Q45DvF65XSKxtP8Zq2OAjSp9lAjiBy4
         Fu6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EGruUOn9IMc6W3kUsAJaAZq8V4eyqzdsxdTG4xU5Gc8=;
        b=hhe1hF6pPly/zM3sLKewanF8AXbxOvNTsqcy1ir9LqSn1cBQRK5OlZTdWQnAiIqegk
         smSaZkpnTY86J2LvSJPkRnlLlAfClttj2So1N6b4NpYlyIsAd00ykL+Zd5agap7KyboC
         dkBcCJ5tFRfXj+uD08WNHkCevZweu0u+f6o0J7faZaGgruU9RCjVsupnRss+oj+/Lnw4
         XnJ/6OPRTZVKUcZ7sq5EKFPK80y3qk6FmtIjQSMR64Y4MiX/2sgM2L8xP3ppF4AfGR87
         b6wAzrrtQPD1QJsTuiJprNY0JIC0bJzP10Vc2MxWoxWz4xb14WqGxZ1/0GGlU7oaIJ/F
         7/KA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QpsHszZv+42bdaNcaosvWS8U8xA87r1XlAx7QXN7zOkNSx8Nb
	ATDeC5/3UpxM9C6VY5ap6R0=
X-Google-Smtp-Source: ABdhPJwHHw/XlJqns0K0NzdvIYspDgB5EDxBYkLdtrHSWiiHAHifPh3j+tXU9hbb9AJx4zucyQgWBg==
X-Received: by 2002:a2e:b541:: with SMTP id a1mr61798ljn.289.1640037743316;
        Mon, 20 Dec 2021 14:02:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls802773lfu.0.gmail; Mon, 20
 Dec 2021 14:02:22 -0800 (PST)
X-Received: by 2002:a05:6512:1151:: with SMTP id m17mr187499lfg.154.1640037742632;
        Mon, 20 Dec 2021 14:02:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037742; cv=none;
        d=google.com; s=arc-20160816;
        b=jYmusPD+WdnxVeRAsTtC8+92ovDD4nYsZXa0avvfctGBxt4NWhCu804E5EqY9+ZfBm
         214HhnpQgjwJklWSeSYN9Z1j64I8aSvwjq+2JoWruzGtCz0XBH3y5FWJUz138cMe7xJg
         pdUE6zWzHBE1dvwcf1rOhCh5PVTx3xg79a3nETADqDsgWpUjeKWgouCpPe6KBoW4Tav1
         9z9QDJbGO+iGSJ6CeDWoG/ufm+mgspg1VqhcGq6YsgSWLgR1LuqntQEmfl3eH/xGnKAs
         urp5eluQ+KuEzv7ge0wMorX2ASUwXeaBkt+zPRZyh3n0Nk+ub4I+cxlmNGWBIIj4Rsf7
         KBZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YFZt1HrIZYuYxTaQojTxU5EnY7ilBJpM8FVgR+Q355s=;
        b=hs4G8d9wXz1DQ4RPdqh069UhGxKb6TccyG3W5gKzsshGGDT6oEzRO0XLhdh+9qln2q
         Tk7adiAZNIpL1q1qI3lGbw9KH36qaebUe2yyjkYOxl/qHFb/+oxlDyljRywwbGT4eiqh
         LOSI0mA0E4Gz0nBcNmBUXBe8T6xlgiNowISgC/qtO5v2Ca+QdMr6ejoek2FalknTJVI7
         SIPQdQwwTV2It8w50Eoi7zccb9qksRP33dFCvUdnX2hWocYX9sEMxiAW+0sEf15SDl7l
         GRHh+1yf5WR+AHRDVG24VLlYekqDS5m5huyKwyWWSPg+FG/qm8xzbR2VdbMEm4BZqux9
         0SDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lY1RxKt7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id b7si260623lfv.5.2021.12.20.14.02.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 29/39] kasan, page_alloc: allow skipping memory init for HW_TAGS
Date: Mon, 20 Dec 2021 23:02:01 +0100
Message-Id: <dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lY1RxKt7;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Changes v3->v4:
- Only define __GFP_SKIP_ZERO when CONFIG_KASAN_HW_TAGS is enabled.
- Add __GFP_SKIP_ZERO to include/trace/events/mmflags.h.
- Use proper kasan_hw_tags_enabled() check instead of
  IS_ENABLED(CONFIG_KASAN_HW_TAGS). Also add explicit checks for
  software modes.

Changes v2->v3:
- Update patch description.

Changes v1->v2:
- Add this patch.
---
 include/linux/gfp.h            | 16 ++++++++++++----
 include/trace/events/mmflags.h |  1 +
 mm/page_alloc.c                | 18 +++++++++++++++++-
 3 files changed, 30 insertions(+), 5 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 600f0749c3f2..c7ebc93296ed 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -55,14 +55,16 @@ struct vm_area_struct;
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
 #ifdef CONFIG_KASAN_HW_TAGS
-#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
-#define ___GFP_SKIP_KASAN_POISON	0x2000000u
+#define ___GFP_SKIP_ZERO		0x1000000u
+#define ___GFP_SKIP_KASAN_UNPOISON	0x2000000u
+#define ___GFP_SKIP_KASAN_POISON	0x4000000u
 #else
+#define ___GFP_SKIP_ZERO		0
 #define ___GFP_SKIP_KASAN_UNPOISON	0
 #define ___GFP_SKIP_KASAN_POISON	0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x4000000u
+#define ___GFP_NOLOCKDEP	0x8000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -235,7 +237,11 @@ struct vm_area_struct;
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
@@ -247,6 +253,7 @@ struct vm_area_struct;
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
+#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
 #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
 #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
@@ -255,6 +262,7 @@ struct vm_area_struct;
 
 /* Room for N __GFP_FOO bits */
 #define __GFP_BITS_SHIFT (24 +					\
+			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_LOCKDEP))
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 1329d9c4df56..f18eeb5fdde2 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -52,6 +52,7 @@
 
 #ifdef CONFIG_KASAN_HW_TAGS
 #define __def_gfpflag_names_kasan					      \
+	, {(unsigned long)__GFP_SKIP_ZERO, "__GFP_SKIP_ZERO"}		      \
 	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"} \
 	, {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,			      \
 						"__GFP_SKIP_KASAN_UNPOISON"}
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2076b5cc7e2c..5e22068d4acb 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2414,10 +2414,26 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
 	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
 }
 
+static inline bool should_skip_init(gfp_t flags)
+{
+	/* Don't skip if a software KASAN mode is enabled. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		return false;
+
+	/* Don't skip, if hardware tag-based KASAN is not enabled. */
+	if (!kasan_hw_tags_enabled())
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl%40google.com.
