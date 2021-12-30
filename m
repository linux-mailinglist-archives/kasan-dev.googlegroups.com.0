Return-Path: <kasan-dev+bncBAABBY4KXCHAMGQETVSJBLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B6FD481FB0
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:48 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id i5-20020a05640242c500b003f84839a8c3sf17620469edc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891748; cv=pass;
        d=google.com; s=arc-20160816;
        b=PUsh+GrNll/OfxkMjMXlmTYi8h4oMrhIxuGzLNAJ/lyAZ7Ik29f9msoYcZX/9GI3vi
         ipEoDk8KFn6eXlkmHGSJz3Yh34K78lPuteXQdOe/M/B8P87Z/mPbvLP7cMV7+hoenErP
         2DIZCFBnYCHFcQSX49oOuiD9G8F1OmZg6dgLW0Ors0TGXXsbEbS01VvTrJM9/49oEWBT
         fHFbUgKJoAr8pprd3L8cBbQHS4nbxo+SLUWls4fTa+AT0kKoewSZdkLsuqM0iQmOiHg5
         f2bs3zY5Y8udfgql8+02jSNBW+aQcDS8xG+NWDFrNthXovnmlHmkof9IGVrxcDQIhN26
         hd7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=F+aIGBS5YTC4gABlAyBwRVSvsNecs0XIrl9sqBvTRCA=;
        b=GaKA/5sZmkZB6JwZFdit1adDZCaJxz+8XNH+Y1IKtbDpGjbIUtzg9TaN0MrSbrdYPG
         HKRUusT3s2qzloEvW+lMC5s+nnwXRbUxlE44AWu1IhBFpK5PHdb1qQXs48OIHySYax5V
         zymMz+Rx3ysL/yQyUlNKZaesAEmg2jR95RSjvrbEzhhw5e4jFWnigBbW1dcruLuI9CgA
         9DtaHiUgHL6oIHG+3/0P1tG9xh6WD/oSiAlgqfVJeENPX2pmRK9TUYxyjwU12fy3y5D5
         5Zh70lpl24iYK6WmKSBRUJVFIgsCB/oZB6LqsOYVVyuSaO3uzvPlEAig0K1sqX1vEyV/
         j+OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=szv7fmK3;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F+aIGBS5YTC4gABlAyBwRVSvsNecs0XIrl9sqBvTRCA=;
        b=cKrRx1a3ATesCt+aupF15bJZA4uhcxe5Lbgg0sjpCDd31C5gYRr/PczwYbWSEBA9mP
         SN5pOrkYi/SCVyN2CGgkzWiRG/A6vzqSg3Yh+ShA5oTsISXoDyLP65ljHUeC/cmEJ48j
         2E5BDqXcKEKYULEDQ85zVpWk1nLRNqDb0y7JlbCQXg+poA4p5LYXJNZ1aUtvBjhHTwIH
         j4TwC6z6Zw8Ekza1Lp/w4UE/H7S67SsmO76sgKip5WqYolvCNWwL0PSZ6Anf9KAKc0SI
         XLj2xOt8/3gJ/iTP/jTS/FC6T+OT1zKdv5t1cvAcOB6cigVSJeE5TTMa2KmNI02HFCLY
         su1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F+aIGBS5YTC4gABlAyBwRVSvsNecs0XIrl9sqBvTRCA=;
        b=UWQBRuFiqqesGMyoU7K+pZiJPBcNgU8GNjJLVNW1wo2j8jLRtPwNG96tzl+joSClZR
         dQy1I6X7OaLygaM4mMS8/vjLclev8aOTRMlu4fPW6uQMojdRBICMp6Vc56d4B9e9yLZJ
         a/OV9q2kNirFAJ+JMwiSz/i6BOMp2tXVVI9jp3AQW24/d9Viz4jGh1MBSz88T5aEzwu5
         yp7LiyRs/dY9ZZC1BsLIZG4LK5su0edkg13OJKg1YsOclLWcfynamD6mydCL4fAyBJ2c
         AeYIdh9iCTozEb8O8ECCkvyeLmNhfKbv1vHJi7qkLHKOgBopFvp946f5ujV6sbRqR+4n
         usng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KXWfs8iYAAMU0QpJYxDjAcNwbZI1uoqrRo55i4cTYwBZdZU+5
	XrL6K2qXq1uLrdaupFzh5Ts=
X-Google-Smtp-Source: ABdhPJw3Uuk6ZIuuR19HZMpZ8zQIg0Oga3+7ES3pnQYPGZ2xU2++4Z4fNj/0026S9ilPzgzWew3lkQ==
X-Received: by 2002:a17:906:b759:: with SMTP id fx25mr26681934ejb.753.1640891747807;
        Thu, 30 Dec 2021 11:15:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:168a:: with SMTP id hc10ls302375ejc.1.gmail; Thu, 30
 Dec 2021 11:15:47 -0800 (PST)
X-Received: by 2002:a17:906:58c9:: with SMTP id e9mr27877210ejs.30.1640891747032;
        Thu, 30 Dec 2021 11:15:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891747; cv=none;
        d=google.com; s=arc-20160816;
        b=Ye5/pvpwt/KlfTpbRt1yos3uVHtCzpU8hhHY4CGf69hdBXa/rcPTUXHwDfe95XvHmg
         D+kPY/WoKGcfQrI/8SbrdsPRPVICOJG907pXOMYYyL6jJFlFbgmgX7n3X0GZPIJJUdmY
         BeT7TarXFxvP7lbbA9WwC/bmUspz6TGZO+hvVtRluheLvlWUqUtMdN8yUVE8l1olBefz
         jsoRCqY8PXHddQlaeD62x4Cz1CSPiwMSA4Ehapzy63NLayQBLo837EwmybXZaFBbkpO3
         cKg8VrqPLXs8fZ7/JEER/F6/kxnhQzU9lK8WN2vq0N3i7CL+AWcSi+twQPAvp6KMuJ7K
         y6kQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=orinIhozX6Lv2fOl+6jtoSO4TeHf1WCxLPhG4UOICeI=;
        b=ZIBuuIWODVkEZWGCM2guk0XOx9i4ZOWT9MnTGqr2S250I3MjvbIYFlZveL/cWUQHs8
         bsMIKelU2vlDOsHMWOM+xSxlFPjA0uml/3WhqQ2qV+sgzvj9Bi77Fg9MC71UXGGN86ak
         I0LrQPEY/I8dcrECJ/5PR+5t4g6nSv9Wj1NkcSDpL+yxwqXkVRNr27six+w72jfGJQQX
         wy8Lk3rFyLBTEXAi/g6Bc4L8JVn/RyYED+37nQBTZY3UkrK6Gt+AWy/jYoDSxNMv88uh
         gpv8i5T1HlPYdb8dkYWHMC+ygmWbt7ToqWbSjE471dZYL1d+KhkBdj2OZvgH93f/jL/K
         WsBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=szv7fmK3;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id bs25si1392332ejb.2.2021.12.30.11.15.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v5 29/39] kasan, page_alloc: allow skipping memory init for HW_TAGS
Date: Thu, 30 Dec 2021 20:14:54 +0100
Message-Id: <88f2964f4063aa6fd935ef8c8302d02d8d67005b.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=szv7fmK3;       spf=pass
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

Changes v4->v5:
- Cosmetic changes to __def_gfpflag_names_kasan and __GFP_BITS_SHIFT.

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
 include/linux/gfp.h            | 18 +++++++++++-------
 include/trace/events/mmflags.h |  1 +
 mm/page_alloc.c                | 18 +++++++++++++++++-
 3 files changed, 29 insertions(+), 8 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 487126f089e1..6eef3e447540 100644
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
@@ -235,9 +237,10 @@ struct vm_area_struct;
  * %__GFP_ZERO returns a zeroed page on success.
  *
  * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
- * is being zeroed (either via __GFP_ZERO or via init_on_alloc). This flag is
- * intended for optimization: setting memory tags at the same time as zeroing
- * memory has minimal additional performace impact.
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc, provided that
+ * __GFP_SKIP_ZERO is not set). This flag is intended for optimization: setting
+ * memory tags at the same time as zeroing memory has minimal additional
+ * performace impact.
  *
  * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
  * Only effective in HW_TAGS mode.
@@ -249,6 +252,7 @@ struct vm_area_struct;
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
+#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
 #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
 #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
@@ -257,7 +261,7 @@ struct vm_area_struct;
 
 /* Room for N __GFP_FOO bits */
 #define __GFP_BITS_SHIFT (24 +						\
-			  2 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
+			  3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 5ffc7bdce91f..0698c5d0f194 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -52,6 +52,7 @@
 
 #ifdef CONFIG_KASAN_HW_TAGS
 #define __def_gfpflag_names_kasan ,					       \
+	{(unsigned long)__GFP_SKIP_ZERO,	   "__GFP_SKIP_ZERO"},	       \
 	{(unsigned long)__GFP_SKIP_KASAN_POISON,   "__GFP_SKIP_KASAN_POISON"}, \
 	{(unsigned long)__GFP_SKIP_KASAN_UNPOISON, "__GFP_SKIP_KASAN_UNPOISON"}
 #else
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 102f0cd8815e..30da0e1f94f8 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2415,10 +2415,26 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/88f2964f4063aa6fd935ef8c8302d02d8d67005b.1640891329.git.andreyknvl%40google.com.
