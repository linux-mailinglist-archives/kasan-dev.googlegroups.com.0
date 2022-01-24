Return-Path: <kasan-dev+bncBAABBXWVXOHQMGQEMB7YL6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B54484987CD
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:07:27 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id j11-20020ac2550b000000b00436c45fe232sf3083696lfk.12
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:07:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047647; cv=pass;
        d=google.com; s=arc-20160816;
        b=fRvfLKCvqaTUhlLQzu5wOZ1nvB5yfBXvkHOhp2ssu0KvzCeWrKg1wVsHn7+3atMMLV
         AXbn+3UoZvcr8zcRVYemgJbW/SDnzM/u7sFVj+7CHGUK5q1tqLL7aVbZcCWLshPb6TL+
         5zyVIT40yxSwp1p8T4S8WH1/p+8UZ3Lz3bKxzWpyLjV5T6C0ZTc604bGYVP7mtPiRXQ3
         cXFT2h8QYRQr60tizs6MXR+LowkmFbBXaMcAgCkr9o5+Ss7FHdRk8yXfp4o4D+6BVgS+
         TIGeXDZ1yQtKlWIiEd/bmw3syniXb6Su18gJmyAvq3BcnQOjXKbyQTz8DfKGRhxkR48S
         fMVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o2YLIs1CgJKGfOByj/3e0KSS9BuCbE28TN1zRRBc3zk=;
        b=Wsh2FdZ/ka+1I5U8KKXBUOlXMo2mn7pf8q/9N/juQcPCz9uMVRaIyRDMGSJRxlLPY3
         oheOZJnGTD83TJYDrjzPXdee/c9hXeZkY5X+UT2S5EJqSnJ4ELzZN1HjHXPGL+kW1jD9
         Y9kqMZYWiQb1gvb7DMJxjJw22Ay0ls/fa+4PuAB2EAKyIe4PtiheApkdq8Ok1304D4Qj
         yOIakknvpqY3xhNgGUwncUcbIdXpkW+Ajew0d3lN1HXabnM5vSLYS7WnYs5yMgsvF1Gc
         K8YDmJgI7wiWAUoSfpBFZe2kEafSqsDgS/4f8zknQB/VHrxfYHaozrcowAEMHp30gjRP
         R9hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LsRQuM19;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o2YLIs1CgJKGfOByj/3e0KSS9BuCbE28TN1zRRBc3zk=;
        b=X96FZLSlNFa8kT9r+cJHTvBB3ncpggzokGrAuf8yl2B9JbAYK0QmyFnMwmfNaW0JZu
         dfe0qNrC9b+pyURmrKJJkz+fWEvCwnxvnsmsRNjmy3/wakFBb3lwb6KWPwOhMQlDOVAY
         +GRmL8ldTD1RKrhZPEGFmcEFEeXywLDMQmUhqNEF0b/sn2yanJ7eVEzcupVjRc43R12s
         ZeMaJRETyUTjEDaKlygu7f39p55jHZ9IoqMtRmP3rYM8Kl2HM4Mce3lpyxgMMGkH62Pb
         ScAgi87gG9Nfs5Z1zTcEo9TwjCWG8A6htllsgXt6WLoIfGUZwDLbclvd5xA36ZnQGv5b
         a1nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o2YLIs1CgJKGfOByj/3e0KSS9BuCbE28TN1zRRBc3zk=;
        b=sQZooNoP1o4Ckyie9DTfULpWqTkMN+VF/yBlsRfl2z4DkeSlwgHNzNxuhsIzdHRKrN
         bKZ273Y7bletZygmWX7aBkr26EyCzHBYs4KeH8+9SrUI4LHIf45CBrU5kbQXavv4LTcs
         FqOBXATaBVe3RNGwxkHhqO9SC1ex6Gb3LgLmSdSY+ShqpKZ3nEZknZe1W6DXdkqHYjtg
         fzr3DLp2gnrjbdz1M6BPQPjr4EnXlGEFMSpdmHrXzG2KpkNubwpJuWWXY28xbt2ayfXu
         LlWuTwVkrBgP11dl9ogV9+ECoz2QL3ZdS3FSrAF4VHKZO3paUr21iDH2PRI/kRNa9RFx
         7uew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dZ5RFLaEGz5jzMwLT2a5wTOdSss6AxRP5jNdgnU+kQQz43J7F
	YWeyWXe+Lj1/JR2gxB9Tq2g=
X-Google-Smtp-Source: ABdhPJzayuG+pEvNAdpZCQZ1nFOp4Z2F5/J9MwW+k3UcAYyNATzWccZKwUmSYmKJYs2EvQ+U9dLhWw==
X-Received: by 2002:a2e:9ec7:: with SMTP id h7mr12023476ljk.394.1643047647190;
        Mon, 24 Jan 2022 10:07:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac9:: with SMTP id n9ls574135lfu.1.gmail; Mon, 24
 Jan 2022 10:07:26 -0800 (PST)
X-Received: by 2002:a05:6512:3ef:: with SMTP id n15mr5670332lfq.414.1643047646486;
        Mon, 24 Jan 2022 10:07:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047646; cv=none;
        d=google.com; s=arc-20160816;
        b=p1nsCeIyipmUZWDR6Ney1mrq7QJdOUQRSG8pgxVJUqTjTOvXXqinim8qA59pr4GZpy
         f4AgvCvbCEnLWgY9iPqxJWWm30tVNvPv7g65t4i2gpccEapSEswT44aUbemLT+7MRbXz
         G+zDzyac2Q2XdIhJ9qPu5sKY604VW56EU0Yjjpep+n4hokx/xtdB1GrSEQ620T/9O69W
         LS6vlMU4CfwxQ+h8o/vwNMDufYXbmXqMsuYn1ivgc+7P7PvNaMlVlK4F/g8VRlc46fBs
         dFZgMaQ8T16g+BopkF92VLzklmYwAolVUEN7bvteIOtX/mSX/4ZDq4+3sOTzPj2/j7XI
         Ipuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6d3Sqieb3hI2XdYdLDF/VqdqByrjj81xNK30fIIEhsQ=;
        b=mC2/Gvh4Wn3PWhS39ritHHSYaUS4QpE6XWEOjyEQR1otBaY1TdVuYiOXeeBqqb6By2
         XxNgBOh5FBKnfWAKdUoDVUshRLDvCkFXCZUhIfnMt7mClWtou7k7o+/xbAIts3kFHGJn
         oRQL1elXhM6XUXaRfYbdmy/SyCSE1BG2e9uaeFsz52iUBjoAkvBUseEems1sHlSkqQW0
         vyq4/ejGNmGX3OA1WO3NtTtmiyEHPQ94R8Q4GOCxWZKCioJ0PsdYBBO96mkB4vylPXas
         4aqlNEObUmtkGHV7SbpFUEAG8MaglpZMgod3cxt7d0EEh0rkf5p0G4dSs87DTN9283ov
         +uzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LsRQuM19;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id g17si380207lfu.4.2022.01.24.10.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:07:26 -0800 (PST)
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
Subject: [PATCH v6 29/39] kasan, page_alloc: allow skipping memory init for HW_TAGS
Date: Mon, 24 Jan 2022 19:05:03 +0100
Message-Id: <0d53efeff345de7d708e0baa0d8829167772521e.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LsRQuM19;       spf=pass
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

Changes v5->v6:
- Drop unnecessary explicit checks for software KASAN modes from
  should_skip_init().

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
 mm/page_alloc.c                | 13 ++++++++++++-
 3 files changed, 24 insertions(+), 8 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 7303d1064460..7797c915ce54 100644
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
@@ -239,9 +241,10 @@ struct vm_area_struct;
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
@@ -253,6 +256,7 @@ struct vm_area_struct;
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
+#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
 #define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
 #define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
@@ -261,7 +265,7 @@ struct vm_area_struct;
 
 /* Room for N __GFP_FOO bits */
 #define __GFP_BITS_SHIFT (24 +						\
-			  2 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
+			  3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 134c45e62d91..6532119a6bf1 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -53,6 +53,7 @@
 
 #ifdef CONFIG_KASAN_HW_TAGS
 #define __def_gfpflag_names_kasan ,					       \
+	{(unsigned long)__GFP_SKIP_ZERO,	   "__GFP_SKIP_ZERO"},	       \
 	{(unsigned long)__GFP_SKIP_KASAN_POISON,   "__GFP_SKIP_KASAN_POISON"}, \
 	{(unsigned long)__GFP_SKIP_KASAN_UNPOISON, "__GFP_SKIP_KASAN_UNPOISON"}
 #else
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 94bfbc216ae9..368c6c5bf42a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2415,10 +2415,21 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
 	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
 }
 
+static inline bool should_skip_init(gfp_t flags)
+{
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0d53efeff345de7d708e0baa0d8829167772521e.1643047180.git.andreyknvl%40google.com.
