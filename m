Return-Path: <kasan-dev+bncBAABBIOVXOHQMGQESNCLJ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C3EB4987C6
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:06:26 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id f21-20020a50d555000000b00407a8d03b5fsf3545975edj.9
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:06:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047586; cv=pass;
        d=google.com; s=arc-20160816;
        b=O0L2xHlKE+jyzNz5JA3j+G8ntw7VQNqSPz2CR6GOhyan/Y515T8gAVG4rffhJGqczt
         21CJ1Esyff41Glzwc1bvTpKuvVhgScbsW8STxSvRp2qG1Fb8Ciww/U8nZ7zikH2c+ton
         jJR903Q8sjlK66yYTeAY4PditYOR7TQdK+xHkPhKm+8YEg8+J78wj18YcqwxNXYvOCBB
         CdrjdxoyVG4w6McGHZKQAAD/5CQpaW8tbif6VtUNDFWzN9cCGQSG0bfJXo9G074eoIXS
         s2/L8DizXdw0o/P5U7q5gUtq/jFRQKhb3Gje6/BxeoZ6/dFPBAoB15FTRo/XKsbYSHbJ
         uQTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LEJAXNB9FGq6ET5v4RxQr2xGEzNb2z7EqA4xtDYpiFw=;
        b=WJewLUSOOIb8QVatAV4Q19NR7rO/VvkpNCU0FuK4fuK5mr72RasrgwRC/btjL4mQOa
         7h3EQG2JETzKUHtZauN453FkMglwGR/YHi+l33Y1IzeNqT2MKj9L90O802fCDLXQ3YIq
         ibOHBottHVyJV52SFcGYZTPzhJRUswRrR1CojgL7Qol0M2xOFzANUxyjVnUpJdS5Mccv
         yfYIV5RA9CPN/MRquen/3SdmUmVexaa/doP+JAo4FR27tgG618nIdnlmozw3bFFq/e05
         Du60n74su06EjBwhqAHXycuX8g1tyAhiNIcPwix0j9CjKyVnLWF8SnAmbH7LbPApDYll
         1cfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jY5cVJPF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LEJAXNB9FGq6ET5v4RxQr2xGEzNb2z7EqA4xtDYpiFw=;
        b=cwtQqe5hU4Lb3TksBJ7v1Dj79ypCRJLIDyLUCURXaBEQFjPgkl4+AGW4oE6MIEQ6bR
         W292zIO5Jin2x+LBodXEJLy58OjE0W5cxkS6dA3R+26iAKoIpzkNUKmSLTZ9jZA0RvA8
         1Wb7Sj6Or2VdWx+EaZt6MNSIRHLzu3oEYG+pR7M+ocb4IKBdpXG/i5l9qD6CxjwqGMZD
         Z4s3T9Fj0FAhuSWVFGTsUOUgfSDiEI2Z3Grp3a+HzCNsOEohMDJAh6ha246e74pG8wXt
         rZcVSroOXaqlpYnNJkdYX97C4HEF2Lpq8WtS4f1gBxTd5Wn3xS2aW9yW6Z7vQPMT5adI
         UBNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LEJAXNB9FGq6ET5v4RxQr2xGEzNb2z7EqA4xtDYpiFw=;
        b=oybfNiekdEs0Hjuw5RoKrHyQSKJSAMse3UKdZBC6+K3tCzSSU6XTjVmC7aJDjsxxrm
         IFTD9Nd8WLxlw40yEw15dK0FwurVTSfVFOcadYJGQF9mH45lGAE/V4FwPqxy9Vcd6APA
         RTPWXsqplctN2WBrTNjKtRYvLFjrvRtsVmc3gNGN8aA/h55P4ZAbJ5ISW4tuXIjav6cg
         QZp5v/XJ437iD2YjaOtobe3bSfqPLSox0cEWxPiJHB+7aGGjlJJV272aMXZzSlwrDPdb
         eizUe7exKYEVjU4MIjgMJ9T0dEHaWIHc/rlW76i4rEsVKH69TZyuMii19ShZlv+vUoVD
         Wzfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532g/UTF62O4Qt2phLiA5QSM7MYYAXhiMvzLR1hYaU/zubKg/naH
	yl9Ve5+7ZcZbNVJld/oIUXY=
X-Google-Smtp-Source: ABdhPJzJpiIjfsqlqalBzf+ZbJfZGh0Wy+XowDNrfdXrfaYtAtAalvNwF2UGmKCNqISIxym5HNH4yA==
X-Received: by 2002:aa7:d7d3:: with SMTP id e19mr8005217eds.74.1643047586098;
        Mon, 24 Jan 2022 10:06:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4ec4:: with SMTP id i4ls2167123ejv.1.gmail; Mon, 24
 Jan 2022 10:06:25 -0800 (PST)
X-Received: by 2002:a17:907:8a1f:: with SMTP id sc31mr2261510ejc.392.1643047585191;
        Mon, 24 Jan 2022 10:06:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047585; cv=none;
        d=google.com; s=arc-20160816;
        b=aunD5cvWcXcSNeLFrt/9BGDcrpS2JtyJQywEYt2AhzB1Nfsa/E7p1sTuAdkvbenXG0
         S6vDT1JTN9dgoFgU14HGI1d7lFKmy24gDq44Mv+XwuQCKeGq6lOIGh8dIKo92cGk1p1I
         owsydkWnWkDYuTPatoICwS/PSxtGm2CJh4GWM0eBlSgWcP5N9Ya481kx1Y1ftH5CEkku
         hABLQPkZ6NRfallPqLcQj//6TAgokpdj1DQqX/xXzrDmIXC3goS+iMZRIF7ly3RxD/St
         CtotrO7kt4jyevS70jwqF7J1r6gr70JRtj2fWSAScNmBdEiq0p3CO6FAd/m2QKsFkwxe
         0uxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hHzmzy1f4cPzWu7uvPj5X+wL96Wl9C2siP6FRJTw3ao=;
        b=UeNtWPTyuBPzjj4tVi/GcTeeKFGZfe/KCxUgGi3TgHkSNDeRL0RQphSyS8hXKnMWYQ
         lz+Pr9q4YgriDZbppz6liWRz3MrbzQJhBsb+pTEW7WRIVeK6o4Ts8Q4PD8TYuHVuu3yJ
         YQdfVtxK9SMrbgfnjCkU2BwK+Ok4Xyuoe464g1uOL2nlnYE0vnlVlnYIZ0HeaxvnpIqX
         qGeTM764rm3M97FQqX3U4wxmh8X8nqbmYxuunKKY9d2zYOnoZmHSU4UIDRU1qQBrdbLX
         e3ELxIVYUfPAgyzOBkY/cEqzFFBANRt/RcI3s4S/B7iH3LxgEoSlQZpnHv9b9OVS4rUv
         ECzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jY5cVJPF;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id l16si674921edb.1.2022.01.24.10.06.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:06:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH v6 28/39] kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
Date: Mon, 24 Jan 2022 19:05:02 +0100
Message-Id: <35c97d77a704f6ff971dd3bfe4be95855744108e.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jY5cVJPF;       spf=pass
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

Add a new GFP flag __GFP_SKIP_KASAN_UNPOISON that allows skipping KASAN
poisoning for page_alloc allocations. The flag is only effective with
HW_TAGS KASAN.

This flag will be used by vmalloc code for page_alloc allocations
backing vmalloc() mappings in a following patch. The reason to skip
KASAN poisoning for these pages in page_alloc is because vmalloc code
will be poisoning them instead.

Also reword the comment for __GFP_SKIP_KASAN_POISON.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v4->v5:
- Cosmetic changes to __def_gfpflag_names_kasan and __GFP_BITS_SHIFT.

Changes v3->v4:
- Only define __GFP_SKIP_KASAN_POISON when CONFIG_KASAN_HW_TAGS is
  enabled.

Changes v2->v3:
- Update patch description.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h            | 21 +++++++++++++--------
 include/trace/events/mmflags.h |  5 +++--
 mm/page_alloc.c                | 31 ++++++++++++++++++++++---------
 3 files changed, 38 insertions(+), 19 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 96f707931770..7303d1064460 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -55,12 +55,14 @@ struct vm_area_struct;
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
 #ifdef CONFIG_KASAN_HW_TAGS
-#define ___GFP_SKIP_KASAN_POISON	0x1000000u
+#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
+#define ___GFP_SKIP_KASAN_POISON	0x2000000u
 #else
+#define ___GFP_SKIP_KASAN_UNPOISON	0
 #define ___GFP_SKIP_KASAN_POISON	0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x2000000u
+#define ___GFP_NOLOCKDEP	0x4000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -241,22 +243,25 @@ struct vm_area_struct;
  * intended for optimization: setting memory tags at the same time as zeroing
  * memory has minimal additional performace impact.
  *
- * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
- * on deallocation. Typically used for userspace pages. Currently only has an
- * effect in HW tags mode.
+ * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
+ * Only effective in HW_TAGS mode.
+ *
+ * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocation.
+ * Typically, used for userspace pages. Only effective in HW_TAGS mode.
  */
 #define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
-#define __GFP_SKIP_KASAN_POISON	((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
+#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (24 +					\
-			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
+#define __GFP_BITS_SHIFT (24 +						\
+			  2 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index cb4520374e2c..134c45e62d91 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -52,8 +52,9 @@
 	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"}	\
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define __def_gfpflag_names_kasan					      \
-	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
+#define __def_gfpflag_names_kasan ,					       \
+	{(unsigned long)__GFP_SKIP_KASAN_POISON,   "__GFP_SKIP_KASAN_POISON"}, \
+	{(unsigned long)__GFP_SKIP_KASAN_UNPOISON, "__GFP_SKIP_KASAN_UNPOISON"}
 #else
 #define __def_gfpflag_names_kasan
 #endif
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3af38e323391..94bfbc216ae9 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2395,6 +2395,26 @@ static bool check_new_pages(struct page *page, unsigned int order)
 	return false;
 }
 
+static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
+{
+	/* Don't skip if a software KASAN mode is enabled. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		return false;
+
+	/* Skip, if hardware tag-based KASAN is not enabled. */
+	if (!kasan_hw_tags_enabled())
+		return true;
+
+	/*
+	 * With hardware tag-based KASAN enabled, skip if either:
+	 *
+	 * 1. Memory tags have already been cleared via tag_clear_highpage().
+	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
+	 */
+	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
+}
+
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
@@ -2434,15 +2454,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	/*
-	 * If either a software KASAN mode is enabled, or,
-	 * in the case of hardware tag-based KASAN,
-	 * if memory tags have not been cleared via tag_clear_highpage().
-	 */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
-	    IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
-	    kasan_hw_tags_enabled() && !init_tags) {
-		/* Mark shadow memory or set memory tags. */
+	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
+		/* Unpoison shadow memory or set memory tags. */
 		kasan_unpoison_pages(page, order, init);
 
 		/* Note that memory is already initialized by KASAN. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35c97d77a704f6ff971dd3bfe4be95855744108e.1643047180.git.andreyknvl%40google.com.
