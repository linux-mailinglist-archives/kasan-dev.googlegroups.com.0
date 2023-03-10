Return-Path: <kasan-dev+bncBD52JJ7JXILRBSXEVKQAMGQEQTKPI6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 79A906B359D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 05:30:03 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id g13-20020ac8124d000000b003bfba5d76a3sf2285609qtj.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 20:30:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678422602; cv=pass;
        d=google.com; s=arc-20160816;
        b=h7ANFPkModCH0bXkE+9ky7tgYaC66eXLSjmcFRWcGYxhBJGOIT2fb9WaID1klTXdj3
         wk+KRN/HS+QOrEBvJ/JBBo0IwSRETQCfCQJ4MW6SM4OlGBjjueIA8A9VqFWzkJ8gTl5H
         dJl3SVuFEgjWRJ1FUJ9WsuUZ1rx8UdzPfqJ0F8dPpk7eOXdTNVMuEtUAnYqSSMnjFJO4
         kFG0XmAeBXw2b5EW7Tfw7XUc7wLwS6xZF6f/BWtiXFjHV6Xj7iylhTFXFKCmzzQsPmV3
         cOXW96aRL4iNEadDBO/mmFn2m1AkqoNqER/MoJODHtkksleID4qDS1S1t9UZPfZXZg1e
         sE2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=XJUhRAbCzYNKEPfQ0P1PJ8TuVRa+Mr35td183cc0298=;
        b=1EAuM63YMpvmVzuxePfFW2fyOoe+cza2JosHlB2O9ubz9T1N36/ldLazHohqXf2ZG+
         9ARRnu35+oWWvVYLW9356ufXs+ea+bfKeKMzWNPnxDyyW8rvLWCbG+c5vuJgH8p2VS5N
         Y+jks7uxxSF/gdo7PsrIfK8XFjXQHOqW7YyZSiquvgPMNycrvE7G29t3Grfjmt/N7/jm
         teA1P6McCS1mpkkk2WVsif0lpED4+6PkVckE4LP68zhGfxOmGHIMRqV31GpQaPHmmjyE
         rSzFZsN1Y0KaLih+YF2AYDWBULxamSirR3MVOw4UVSelAHr3q55bg5GuSc09E5Q6fIOw
         rYdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q2JEHoLx;
       spf=pass (google.com: domain of 3sbikzamkcf4viimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SbIKZAMKCf4viimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678422602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XJUhRAbCzYNKEPfQ0P1PJ8TuVRa+Mr35td183cc0298=;
        b=AdXGH7bCJYISKNnGUMPxapSgySVwh98XhWC5bdiyuCSumeVugI3ZrrFWgukm0K9lBj
         5xLuoRBA1VF6P2g7uT/7+DSRDIks4n0qMJ9/0WZptg7af6SosXkcY2DElO7ijL09OUNW
         3hG9UmE+jeLSMstLLaK1dURwo/LIelis4jf9E4uHVdXTzGHwdZRiNsnAvPuqUFUPByzT
         cQJ1QOG/pjdE7R6CKKO8cuHITXbwA0AFtddAhE9zlD6/zyDtuPFUgH8MKCkt1rHBZAFz
         n48dxxgZq7ZvU85DWKhQqMHSnc7jlrz8ADVvUtipvUtGY/U8MjZGTexk+heseotb2Qhm
         jN2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678422602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=XJUhRAbCzYNKEPfQ0P1PJ8TuVRa+Mr35td183cc0298=;
        b=Nvc7Dt4sNFJP6I1irT87nqjvhsRNu6hUtygxSw7yw+41so0+Uy2JNa50bOet1R3PK+
         o/MekRurBf6alznOA6IaG0gWxed+bSs+yi4j8JK66fXmWL1v0m5LsH9WyIFEvLRkXVwm
         Me4xTvIlAShAWJZdSpwuWHCk2/qPsex7EeGnGF/lIsH0q4vRskSWYoLyPHJCjYKZrqz+
         eWrFZei3f8cLCIpN6h71lfJElhCv2yJ34jPOYB/lqUZJGutb0Niex3jYWJVA3N2wdqwW
         CcDo6CdnXs1q+2TO5xSz8igDI9iI26/IMCLoItz222NpbLx6mfWnYCvzcngYL/YtXLHe
         vbfQ==
X-Gm-Message-State: AO0yUKXLqXU4IVN5Aif9bYwU+mWmOZ9HVJQcDW8stB/iCJyN8AoiO3h7
	J7D70BN5UnoVKCMkcOkQkTY=
X-Google-Smtp-Source: AK7set+zPaZwDsHDgkcnb+Vde5aM7s2WkVBKqc4CRPt2uQ12ckeeAuUCFktDsbDyvrspH0PVkFUB5A==
X-Received: by 2002:a05:620a:e11:b0:73b:9bb4:1f68 with SMTP id y17-20020a05620a0e1100b0073b9bb41f68mr398109qkm.9.1678422602341;
        Thu, 09 Mar 2023 20:30:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4894:0:b0:3a9:8ab2:1bab with SMTP id i20-20020ac84894000000b003a98ab21babls4472909qtq.5.-pod-prod-gmail;
 Thu, 09 Mar 2023 20:30:01 -0800 (PST)
X-Received: by 2002:a05:622a:1650:b0:3bf:c5a3:6143 with SMTP id y16-20020a05622a165000b003bfc5a36143mr43327286qtj.27.1678422601742;
        Thu, 09 Mar 2023 20:30:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678422601; cv=none;
        d=google.com; s=arc-20160816;
        b=S03jKeQ4uAUGR7cOW19cpvBvB8oQXJ7B/jrL3Lys3izUouSf8CbnsO9I5XfWvhtitl
         zjM+u3ihfezRBSrY7Zf2tbuJlQyOVoXDyh+Kr7Dp31IS8YSuNFC4uriyTrbvwOc9MP8s
         TsDsbIFHcYMHzdu5smNaZyU/lBSBstXmMB1KgR8XscJZamTisz6GfaN483u3aWA8Ez7F
         2ubU0Fr655ZgHZmCzSn+NXX5RlEK89wf3gttXqSSn4EHw3+Es7s1D/G4ykRYceJnyI/h
         UJ5SqSdKSr+DqdTyklaNg16GVPSEkPhwzHg0+nw67cfXI3ubCFijm4/fMNP7nNMocgJ/
         6C2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=hPpibPG6fh6YQoXzVokXBbAJ/B5/ZQPeLynzU+wCe6c=;
        b=MoS7uI8Q68jouOV24MesF+g2Lv7GKbcpKUv+t3ANh+YKjCremsE6cXV/sKZrnBxYMG
         wn4skCnm6Fx5do21nfeMenz12xkHjQgvqOJABGs69sGh3rGR/Nx4GOKO9hWrcoubQ/z7
         2oCOioyXFWQawBtCild+K7ceQywbErlOhRwNjgXt1XwO0ZvIj9e8eeK7UbqXkOXeo86F
         ebYSloGa5TqZQ0L1mOpnZ8bgvj/I+zPOIGUUq5yIkXhbniXsD2eVUNPS4JXoXQFaWKrM
         lHtPyNGbG+fV2p/X1sGeXyvB042oRU1ZwvB5Ii5V4tMERL5djnZX+cROz1Bb2xNN9Cks
         wqkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q2JEHoLx;
       spf=pass (google.com: domain of 3sbikzamkcf4viimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SbIKZAMKCf4viimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id r22-20020a37a816000000b00725bdb9a8acsi25447qke.5.2023.03.09.20.30.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 20:30:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sbikzamkcf4viimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id m202-20020a2526d3000000b00ae90d688ab4so4613110ybm.5
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 20:30:01 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:4760:7b08:a3d0:bc10])
 (user=pcc job=sendgmr) by 2002:a81:af4b:0:b0:533:91d2:9d94 with SMTP id
 x11-20020a81af4b000000b0053391d29d94mr15728006ywj.5.1678422601498; Thu, 09
 Mar 2023 20:30:01 -0800 (PST)
Date: Thu,  9 Mar 2023 20:29:14 -0800
In-Reply-To: <20230310042914.3805818-1-pcc@google.com>
Message-Id: <20230310042914.3805818-3-pcc@google.com>
Mime-Version: 1.0
References: <20230310042914.3805818-1-pcc@google.com>
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Subject: [PATCH v4 2/2] kasan: remove PG_skip_kasan_poison flag
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q2JEHoLx;       spf=pass
 (google.com: domain of 3sbikzamkcf4viimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3SbIKZAMKCf4viimuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--pcc.bounces.google.com;
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
kasantag instead, and remove PG_skip_kasan_poison and associated flags.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I57f825f2eaeaf7e8389d6cf4597c8a5821359838
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
v4:
- rebased to linux-next

v3:
- update comments

v2:
- also remove GFP_SKIP_KASAN_POISON and FPI_SKIP_KASAN_POISON
- rename GFP_SKIP_KASAN_UNPOISON to GFP_SKIP_KASAN
- update comments
- simplify control flow by removing reset_tags

 include/linux/gfp_types.h      | 30 ++++++-------
 include/linux/page-flags.h     |  9 ----
 include/trace/events/mmflags.h | 13 +-----
 mm/kasan/hw_tags.c             |  2 +-
 mm/page_alloc.c                | 81 +++++++++++++---------------------
 mm/vmalloc.c                   |  2 +-
 6 files changed, 47 insertions(+), 90 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 5088637fe5c2..6583a58670c5 100644
--- a/include/linux/gfp_types.h
+++ b/include/linux/gfp_types.h
@@ -47,16 +47,14 @@ typedef unsigned int __bitwise gfp_t;
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
 #ifdef CONFIG_KASAN_HW_TAGS
-#define ___GFP_SKIP_ZERO		0x1000000u
-#define ___GFP_SKIP_KASAN_UNPOISON	0x2000000u
-#define ___GFP_SKIP_KASAN_POISON	0x4000000u
+#define ___GFP_SKIP_ZERO	0x1000000u
+#define ___GFP_SKIP_KASAN	0x2000000u
 #else
-#define ___GFP_SKIP_ZERO		0
-#define ___GFP_SKIP_KASAN_UNPOISON	0
-#define ___GFP_SKIP_KASAN_POISON	0
+#define ___GFP_SKIP_ZERO	0
+#define ___GFP_SKIP_KASAN	0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x8000000u
+#define ___GFP_NOLOCKDEP	0x4000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -234,25 +232,24 @@ typedef unsigned int __bitwise gfp_t;
  * memory tags at the same time as zeroing memory has minimal additional
  * performace impact.
  *
- * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
- * Only effective in HW_TAGS mode.
- *
- * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocation.
- * Typically, used for userspace pages. Only effective in HW_TAGS mode.
+ * %__GFP_SKIP_KASAN makes KASAN skip unpoisoning on page allocation.
+ * Used for userspace and vmalloc pages; the latter are unpoisoned by
+ * kasan_unpoison_vmalloc instead. For userspace pages, results in
+ * poisoning being skipped as well, see should_skip_kasan_poison for
+ * details. Only effective in HW_TAGS mode.
  */
 #define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
 #define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
-#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
-#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_SKIP_KASAN ((__force gfp_t)___GFP_SKIP_KASAN)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
@@ -335,8 +332,7 @@ typedef unsigned int __bitwise gfp_t;
 #define GFP_DMA		__GFP_DMA
 #define GFP_DMA32	__GFP_DMA32
 #define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
-#define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE | \
-			 __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNPOISON)
+#define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE | __GFP_SKIP_KASAN)
 #define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
 			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
 #define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index 57287102c5bd..dcda20c47b8f 100644
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
index b28218b7998e..b63e7c0fbbe5 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -55,8 +55,7 @@
 #ifdef CONFIG_KASAN_HW_TAGS
 #define __def_gfpflag_names_kasan ,			\
 	gfpflag_string(__GFP_SKIP_ZERO),		\
-	gfpflag_string(__GFP_SKIP_KASAN_POISON),	\
-	gfpflag_string(__GFP_SKIP_KASAN_UNPOISON)
+	gfpflag_string(__GFP_SKIP_KASAN)
 #else
 #define __def_gfpflag_names_kasan
 #endif
@@ -96,13 +95,6 @@
 #define IF_HAVE_PG_ARCH_X(_name)
 #endif
 
-#ifdef CONFIG_KASAN_HW_TAGS
-#define IF_HAVE_PG_SKIP_KASAN_POISON(_name) \
-	,{1UL << PG_##_name, __stringify(_name)}
-#else
-#define IF_HAVE_PG_SKIP_KASAN_POISON(_name)
-#endif
-
 #define DEF_PAGEFLAG_NAME(_name) { 1UL <<  PG_##_name, __stringify(_name) }
 
 #define __def_pageflag_names						\
@@ -133,8 +125,7 @@ IF_HAVE_PG_HWPOISON(hwpoison)						\
 IF_HAVE_PG_IDLE(idle)							\
 IF_HAVE_PG_IDLE(young)							\
 IF_HAVE_PG_ARCH_X(arch_2)						\
-IF_HAVE_PG_ARCH_X(arch_3)						\
-IF_HAVE_PG_SKIP_KASAN_POISON(skip_kasan_poison)
+IF_HAVE_PG_ARCH_X(arch_3)
 
 #define show_page_flags(flags)						\
 	(flags) ? __print_flags(flags, "|",				\
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index d1bcb0205327..bb4f56e5bdec 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -318,7 +318,7 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 * Thus, for VM_ALLOC mappings, hardware tag-based KASAN only tags
 	 * the first virtual mapping, which is created by vmalloc().
 	 * Tagging the page_alloc memory backing that vmalloc() allocation is
-	 * skipped, see ___GFP_SKIP_KASAN_UNPOISON.
+	 * skipped, see ___GFP_SKIP_KASAN.
 	 *
 	 * For non-VM_ALLOC allocations, page_alloc memory is tagged as usual.
 	 */
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index c58ebf21ce63..680a4d76460e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -112,17 +112,6 @@ typedef int __bitwise fpi_t;
  */
 #define FPI_TO_TAIL		((__force fpi_t)BIT(1))
 
-/*
- * Don't poison memory with KASAN (only for the tag-based modes).
- * During boot, all non-reserved memblock memory is exposed to page_alloc.
- * Poisoning all that memory lengthens boot time, especially on systems with
- * large amount of RAM. This flag is used to skip that poisoning.
- * This is only done for the tag-based KASAN modes, as those are able to
- * detect memory corruptions with the memory tags assigned by default.
- * All memory allocated normally after boot gets poisoned as usual.
- */
-#define FPI_SKIP_KASAN_POISON	((__force fpi_t)BIT(2))
-
 /* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fields */
 static DEFINE_MUTEX(pcp_batch_high_lock);
 #define MIN_PERCPU_PAGELIST_HIGH_FRACTION (8)
@@ -1370,13 +1359,19 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
 /*
  * Skip KASAN memory poisoning when either:
  *
- * 1. Deferred memory initialization has not yet completed,
- *    see the explanation below.
- * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
- *    see the comment next to it.
- * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
- *    see the comment next to it.
- * 4. The allocation is excluded from being checked due to sampling,
+ * 1. For generic KASAN: deferred memory initialization has not yet completed.
+ *    Tag-based KASAN modes skip pages freed via deferred memory initialization
+ *    using page tags instead (see below).
+ * 2. For tag-based KASAN modes: the page has a match-all KASAN tag, indicating
+ *    that error detection is disabled for accesses via the page address.
+ *
+ * Pages will have match-all tags in the following circumstances:
+ *
+ * 1. Pages are being initialized for the first time, including during deferred
+ *    memory init; see the call to page_kasan_tag_reset in __init_single_page.
+ * 2. The allocation was not unpoisoned due to __GFP_SKIP_KASAN, with the
+ *    exception of pages unpoisoned by kasan_unpoison_vmalloc.
+ * 3. The allocation was excluded from being checked due to sampling,
  *    see the call to kasan_unpoison_pages.
  *
  * Poisoning pages during deferred memory init will greatly lengthen the
@@ -1392,10 +1387,10 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
  */
 static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 {
-	return deferred_pages_enabled() ||
-	       (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-		(fpi_flags & FPI_SKIP_KASAN_POISON)) ||
-	       PageSkipKASanPoison(page);
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		return deferred_pages_enabled();
+
+	return page_kasan_tag(page) == 0xff;
 }
 
 static void kernel_init_pages(struct page *page, int numpages)
@@ -1730,7 +1725,7 @@ void __free_pages_core(struct page *page, unsigned int order)
 	 * Bypass PCP and place fresh pages right to the tail, primarily
 	 * relevant for memory onlining.
 	 */
-	__free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON);
+	__free_pages_ok(page, order, FPI_TO_TAIL);
 }
 
 #ifdef CONFIG_NUMA
@@ -2396,9 +2391,9 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags)
 
 	/*
 	 * With hardware tag-based KASAN enabled, skip if this has been
-	 * requested via __GFP_SKIP_KASAN_UNPOISON.
+	 * requested via __GFP_SKIP_KASAN.
 	 */
-	return flags & __GFP_SKIP_KASAN_UNPOISON;
+	return flags & __GFP_SKIP_KASAN;
 }
 
 static inline bool should_skip_init(gfp_t flags)
@@ -2417,7 +2412,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
 	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
-	bool reset_tags = true;
 	int i;
 
 	set_page_private(page, 0);
@@ -2451,37 +2445,22 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
-	}
-	/*
-	 * If memory tags have not been set by KASAN, reset the page tags to
-	 * ensure page_address() dereferencing does not fault.
-	 */
-	if (reset_tags) {
+	if (!should_skip_kasan_unpoison(gfp_flags) &&
+	    kasan_unpoison_pages(page, order, init)) {
+		/* Take note that memory was initialized by KASAN. */
+		if (kasan_has_integrated_init())
+			init = false;
+	} else {
+		/*
+		 * If memory tags have not been set by KASAN, reset the page
+		 * tags to ensure page_address() dereferencing does not fault.
+		 */
 		for (i = 0; i != 1 << order; ++i)
 			page_kasan_tag_reset(page + i);
 	}
 	/* If memory is still not initialized, initialize it now. */
 	if (init)
 		kernel_init_pages(page, 1 << order);
-	/* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
-	if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
-		SetPageSkipKASanPoison(page);
 
 	set_page_owner(page, order, gfp_flags);
 	page_table_check_alloc(page, order);
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index bef6cf2b4d46..5e60e9792cbf 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3188,7 +3188,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 			 * pages backing VM_ALLOC mapping. Memory is instead
 			 * poisoned and zeroed by kasan_unpoison_vmalloc().
 			 */
-			gfp_mask |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO;
+			gfp_mask |= __GFP_SKIP_KASAN | __GFP_SKIP_ZERO;
 		}
 
 		/* Take note that the mapping is PAGE_KERNEL. */
-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230310042914.3805818-3-pcc%40google.com.
