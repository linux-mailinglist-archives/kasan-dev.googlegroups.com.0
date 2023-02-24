Return-Path: <kasan-dev+bncBD52JJ7JXILRB7F44GPQMGQEWWE4EFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id C1DE56A16C3
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 07:51:42 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id o38-20020a635d66000000b004fbec68e875sf4731894pgm.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 22:51:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677221501; cv=pass;
        d=google.com; s=arc-20160816;
        b=xEucfUZCqVsaaOkhXlkyiRQc6lO7ahgLqNbTxJ4yRgBUs/kcv14wZhzHTFC33BWaUc
         SM5ea9D/Y8/Gwz9ogwLAy92LzsewZec8ySWne9poHdF5Sx0CH1vfLdgXu4lApIR2kvQM
         H72uOUMEcsTnNVZt34rsuMYTFnqejc4QZ8lJz5K959anPCmX7+ZvD2IDD3cFQKDSVA8O
         5SI7oCAaAV9yrLGNjCNNF82/VDSv7vNVWQ8XsAJ3GB1pUUrHyYOJ34Ny5X87MGLyV40v
         r8zhHTYoeY+2eFrcecLEuAmanpP3hnPv/opKRpJyg3qOAa1mLpY8/hAcPZnj2oqAqfZC
         Wv/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pWFmUvNGI1KUw2bmK3kkFkBmeAqiCr6Pk+dV/pnWgKQ=;
        b=ys0zLYay3nMWbB8hh1+wbtGszEFHoxySQWU0BkR8YwvkWBdSqLmU9VjAtEWj37BEON
         NI4lEeEJeT34v4ICdgRl/0wPZ20nTRSCdXpN5whlAXmVXshGJwq54MpGBMNDyPBKONMp
         YrRl09FZdiJvhTPcfGdKr4a3rx/QeT8iaFNsdYDoxDo5ebRnQqiZouITnTInggWoI5+R
         zpW523vBrDwf0VUyjOd/FFB+E0BvksqfICJ1ELfgF53aLeqhR7aqMQ+64PdKcgQGvt2b
         M9Txi+Ai5nQyxRvGUvwGTSJD/v54S7vhttPD1KPXr1ClLaOCjwXTyJ+Mn2wqgxqFviFK
         7g7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R0D2B1ci;
       spf=pass (google.com: domain of 3el74ywmkct8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3el74YwMKCT8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pWFmUvNGI1KUw2bmK3kkFkBmeAqiCr6Pk+dV/pnWgKQ=;
        b=tcKsTrOpoaHdmHHlrKDcnl/uCQQzG1zokA3DVobmPoqHAUNPJZXgoux9yiLdX/BQvI
         1Dh/S/O4+FuCmPIEaO3gVIgsVVNDrD6viw9GvMqOHKCJ7MpNwco9X9dauNZybB524woi
         Q9lYe3aBOmr5RJm4Qy0Yi+OTi7QDwjdfKp4KnMkZxUKDHGdZqpCIEthirV3W77vdGOgJ
         foHzAc4X+q5QJyzmqC42V1Vw2oB388j9hTK4A9++jv364K2VoDqC5ecmqKpybEOrhrQE
         Y8Kz9tnbBuMQh1RRfqkufe/YlmSl55FoEBof/WeQ3sBOkXDOIze5F/ivHqh9bIiFre3p
         5kiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pWFmUvNGI1KUw2bmK3kkFkBmeAqiCr6Pk+dV/pnWgKQ=;
        b=m2YO+E5M4Psv68yVUL8PPO4JRaSVKpzHuaBVkOUd4vsrgDvmtU/y3cn0IMtDZdIfpB
         Bn+2rg86sLXkZfp9qe7mcSZklMioZ1tD4ZUoMQ5YjrHbcVCK9bI/iPpShwkboM0OPY1X
         oAzWdupOqPYGbwLSTY/shwqYYilLr45oyK8W5H+7dxFjlb0DuSdihPv324j45+U2z5cp
         AkWnfcDnFuqbBArAUwDb9ShIXxFyh+3nMQndej7xGYlWqg+F2wwcKuRjZ8Y/duJZb0Uy
         RBM5zqYAXyOrB5+YOJ/jMLPsMFbQsvo4Xkkmfavz6MnMetOTv5SX5WMEonUmANCgoFtd
         osdw==
X-Gm-Message-State: AO0yUKW5R8lQhU3j72ZRBtRBkhFpztkWsbVCFLCwscGc6S3f3EPt2smX
	Ce24/tQuxhjY8nDhGWnnlU4=
X-Google-Smtp-Source: AK7set/37l67haNyca2XXxRVYbLSVSTsWN5fQNoxtyzkVYQkN4jufJkRg8rW+jLy+r6b5cuvNChLpw==
X-Received: by 2002:a63:3dcc:0:b0:502:d7c8:88f3 with SMTP id k195-20020a633dcc000000b00502d7c888f3mr2176527pga.8.1677221500970;
        Thu, 23 Feb 2023 22:51:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2881:b0:225:cae6:ff24 with SMTP id
 f1-20020a17090a288100b00225cae6ff24ls2749288pjd.2.-pod-preprod-gmail; Thu, 23
 Feb 2023 22:51:39 -0800 (PST)
X-Received: by 2002:a17:903:2441:b0:199:bd4:9fbb with SMTP id l1-20020a170903244100b001990bd49fbbmr16702671pls.43.1677221499604;
        Thu, 23 Feb 2023 22:51:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677221499; cv=none;
        d=google.com; s=arc-20160816;
        b=OSlHtMgdnnWo+mfs+0toSmnPsyHf+eieAIol72SiuTrMYUyv/rVZQlyzno1pAn3I/G
         4XTSmnx5W1z6irQyhFKl8wZsABL5fx9SYyggutugsdNR7GI5AEFTEHD9lNboVJhxM8yB
         OHzg3R4nhkeL3uaVqvX7dAhhUhBhi2THObYcmAurJWUgpgZzY3SMnhnn0tW8TksXZjNe
         i9w9nm/eouKUpPNrEGlfu2SCheCyXM07dU9RNLEPXlH3KVlxwmaMBfm69P/6Cvnpn0Th
         etEBneGt6nchliA+4Fmx6Rn+NlHfr0i6j8iL4eRU0ht3rY9wHeRkrzc+bQrwvGFBhufg
         3FWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=/4/Nn6TgzmPpFqf86zsQoyjbMesN0EC9v3sEz2T6CKI=;
        b=zwL7sX3pGEKL3t8e3aoKNpoRv4lfp/xy7+ADEdyAoxg2pwyVQyJQFByJwBvhPs3HIj
         crptMhdYr+9TEGxJIrviQgjWgtwKateTWcY+sreH9kCXjigj8swc4Umul4ZjN2OBCzFb
         YVhDmngtFSPqCf9aiehsWnzh2r9khOyI+1iFD7hYXKSQuREO6vI+aq975G9kvEQfDFPT
         R/hNHNMid4MGYKKMWrjxvV5cXays5x+R6i45HKLpmLEYSCO94WMOnQnDuOAScU7Tl9+A
         Wo0OWtSePE6CWcT5t9g8f/BmDqX5+TFE9OhDZixwy0bm4KaC11WCRFhlfbwkDhccEjXo
         tX8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R0D2B1ci;
       spf=pass (google.com: domain of 3el74ywmkct8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3el74YwMKCT8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id x11-20020a170902820b00b0019cac961ee6si341268pln.5.2023.02.23.22.51.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 22:51:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3el74ywmkct8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-53700262a47so129654007b3.4
        for <kasan-dev@googlegroups.com>; Thu, 23 Feb 2023 22:51:39 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:d302:b63f:24c7:8a65])
 (user=pcc job=sendgmr) by 2002:a81:7146:0:b0:52e:c8c9:221a with SMTP id
 m67-20020a817146000000b0052ec8c9221amr1364413ywc.519.1677221498805; Thu, 23
 Feb 2023 22:51:38 -0800 (PST)
Date: Thu, 23 Feb 2023 22:51:28 -0800
Message-Id: <20230224065128.505605-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.2.637.g21b0678d19-goog
Subject: [PATCH] kasan: remove PG_skip_kasan_poison flag
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=R0D2B1ci;       spf=pass
 (google.com: domain of 3el74ywmkct8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3el74YwMKCT8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Code inspection reveals that PG_skip_kasan_poison is redundant with
kasantag, because the former is intended to be set iff the latter is
the match-all tag. It can also be observed that it's basically pointless
to poison pages which have kasantag=0, because any pages with this tag
would have been pointed to by pointers with match-all tags, so poisoning
the pages would have little to no effect in terms of bug detection.
Therefore, change the condition in should_skip_kasan_poison() to check
kasantag instead, and remove PG_skip_kasan_poison.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I57f825f2eaeaf7e8389d6cf4597c8a5821359838
---
I sent this independently of
https://lore.kernel.org/all/20230224061550.177541-1-pcc@google.com/
because I initially thought that the patches were independent.
But moments after sending it, I realized that this patch depends on
that one, because without that patch, this patch will end up disabling
page poisoning altogether! But it's too late to turn them into a series
now; I'll do that for v2.

 include/linux/page-flags.h     |  9 ---------
 include/trace/events/mmflags.h |  9 +--------
 mm/page_alloc.c                | 28 ++++++++--------------------
 3 files changed, 9 insertions(+), 37 deletions(-)

diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index a7e3a3405520..74f81a52e7e1 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -135,9 +135,6 @@ enum pageflags {
 #ifdef CONFIG_ARCH_USES_PG_ARCH_X
 	PG_arch_2,
 	PG_arch_3,
-#endif
-#ifdef CONFIG_KASAN_HW_TAGS
-	PG_skip_kasan_poison,
 #endif
 	__NR_PAGEFLAGS,
 
@@ -594,12 +591,6 @@ TESTCLEARFLAG(Young, young, PF_ANY)
 PAGEFLAG(Idle, idle, PF_ANY)
 #endif
 
-#ifdef CONFIG_KASAN_HW_TAGS
-PAGEFLAG(SkipKASanPoison, skip_kasan_poison, PF_HEAD)
-#else
-PAGEFLAG_FALSE(SkipKASanPoison, skip_kasan_poison)
-#endif
-
 /*
  * PageReported() is used to track reported free pages within the Buddy
  * allocator. We can use the non-atomic version of the test and set
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 9db52bc4ce19..c448694fc7e9 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -96,12 +96,6 @@
 #define IF_HAVE_PG_ARCH_X(flag,string)
 #endif
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string) ,{1UL << flag, string}
-#else
-#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string)
-#endif
-
 #define __def_pageflag_names						\
 	{1UL << PG_locked,		"locked"	},		\
 	{1UL << PG_waiters,		"waiters"	},		\
@@ -130,8 +124,7 @@ IF_HAVE_PG_HWPOISON(PG_hwpoison,	"hwpoison"	)		\
 IF_HAVE_PG_IDLE(PG_young,		"young"		)		\
 IF_HAVE_PG_IDLE(PG_idle,		"idle"		)		\
 IF_HAVE_PG_ARCH_X(PG_arch_2,		"arch_2"	)		\
-IF_HAVE_PG_ARCH_X(PG_arch_3,		"arch_3"	)		\
-IF_HAVE_PG_SKIP_KASAN_POISON(PG_skip_kasan_poison, "skip_kasan_poison")
+IF_HAVE_PG_ARCH_X(PG_arch_3,		"arch_3"	)
 
 #define show_page_flags(flags)						\
 	(flags) ? __print_flags(flags, "|",				\
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 7136c36c5d01..2509b8bde8d5 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1380,7 +1380,7 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	return deferred_pages_enabled() ||
 	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
 		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	       page_kasan_tag(page) == 0xff;
 }
 
 static void kernel_init_pages(struct page *page, int numpages)
@@ -2511,22 +2511,13 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Take note that memory was initialized by the loop above. */
 		init = false;
 	}
-	if (!should_skip_kasan_unpoison(gfp_flags)) {
-		/* Try unpoisoning (or setting tags) and initializing memory. */
-		if (kasan_unpoison_pages(page, order, init)) {
-			/* Take note that memory was initialized by KASAN. */
-			if (kasan_has_integrated_init())
-				init = false;
-			/* Take note that memory tags were set by KASAN. */
-			reset_tags = false;
-		} else {
-			/*
-			 * KASAN decided to exclude this allocation from being
-			 * (un)poisoned due to sampling. Make KASAN skip
-			 * poisoning when the allocation is freed.
-			 */
-			SetPageSkipKASanPoison(page);
-		}
+	if (!should_skip_kasan_unpoison(gfp_flags) &&
+	    kasan_unpoison_pages(page, order, init)) {
+		/* Take note that memory was initialized by KASAN. */
+		if (kasan_has_integrated_init())
+			init = false;
+		/* Take note that memory tags were set by KASAN. */
+		reset_tags = false;
 	}
 	/*
 	 * If memory tags have not been set by KASAN, reset the page tags to
@@ -2539,9 +2530,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	/* If memory is still not initialized, initialize it now. */
 	if (init)
 		kernel_init_pages(page, 1 << order);
-	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
-	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
-		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230224065128.505605-1-pcc%40google.com.
