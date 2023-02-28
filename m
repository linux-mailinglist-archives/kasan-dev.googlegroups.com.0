Return-Path: <kasan-dev+bncBD52JJ7JXILRBFOA62PQMGQESAQAP2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 648FB6A530B
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 07:32:55 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id c5-20020ac85185000000b003bfae3b8051sf4194230qtn.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 22:32:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677565974; cv=pass;
        d=google.com; s=arc-20160816;
        b=YJwO4L/KeonAHKJFMLGhCbC2QhcrmemwBD9iuz+PMtKSZb3htPlT3mSRpxAr9MyUEd
         THzPiE4k/OUalgvnuDBAc1VLII8vV3/IYyDulM5toBgybC+8xK1TkUAlM7UAx6PG6NMd
         K/8whKpHJcYzyg5iGiIcfJmMmTA6+4lXX2xql4HPnpfBxjrj/FdqoRSs+e/1LsYgMm0U
         /Dyt8pFe+6GiXEGqsD285ckklcFNkUZxKVQCP2FFXFe40ZJj03ZTmqP+Tw9V2PcLPljd
         GljflweGND1jo7vq41bON+C/le3SUR2kpsq034asAhSCjuQbYIhFP8LUtzFMU5f81Eyy
         jcfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1KV/wYyJGZDTqPJzl5S7alzdSbcbMdvmyqk3HdH/OfI=;
        b=NmVpb1WBeuoFpJn+97hfqE/6zpll7zRbbXW6ASqvbXgTZBVhC7x0SyJAptnCAXtWnC
         Rs5Q9RFaV9vMyjbqCXwIx/wlBmT29rqnmhIXJwvZ9oDVnr2Ef9hDg5KLkoHuVvp9lNpq
         mBRlhwn5H4tUHDsQA07y3aBXw9kAlJVqkr6pHtT7Tb2PvD2GTbqY8X++RxOJt/F1Ue2u
         jvv+/yT9F4Vd388dEOgjSIuDGIoTwKOu3EOpkmwEaDw57Bt/7/3MBwGY3+cvsbQHMLCn
         VelD8cJSCwyE7AaQm4igABVX8z7YgaQYY4yGEO2/85eSXiNYUWOOybOekVYKxePKzibE
         CuYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UQZocSva;
       spf=pass (google.com: domain of 3fkd9ywmkcxeerrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3FKD9YwMKCXEeRRVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1KV/wYyJGZDTqPJzl5S7alzdSbcbMdvmyqk3HdH/OfI=;
        b=XJ8E/esJhGMCPb5xxZB1pXqVI7CMZAQwKJ/YAExYLw39Uv45jMSHQVv0HUU840dqZU
         +RK7LKlHiPz/TB7XczdAcgU9j5WfQYbOKa/Hp/3BMChsKH5ztCp/cfeiJjt50vhmeolq
         YADIZDMpMUQ0c79qQe5dZgtlSlexrsu7+ue7aHVpcibY3MPgQ9IvgTxWs8Nwjuk4ayM7
         1h8tM/OnoD4JMpvUTYCjePx3hxOgrqfr8LtTqaJUFohF40cX9Rj7gKopkIi+WzBYboLn
         7+3CivjegULdc/Kp+s4PA3bLX67lMWoabc9dCc8JEWz1IA9OXW7WGw6JU/rXBjWro8CI
         ViyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1KV/wYyJGZDTqPJzl5S7alzdSbcbMdvmyqk3HdH/OfI=;
        b=N1cI3X14D6CGVFHh4SErQR7I8ZY+uFLAQyxDFgEbiGNPbXXMmlRgLxuokzFjwEDPrU
         N/JQ1D1KuWTtk3Lan1hF25xOopy9qK4qlFVhM/5LWpcGpNSmloW+IBEZzSwRjz5DuvT7
         kopoHXv35tZQQQKig8WUjp7MbxZsaAginxsfU7YL0pGL6CIfa4aJV/1JuLb/t2g2bc8V
         GjVrJet/WsQ1Hcs8RxX/S63TO6BjGfXjDVDugBivKoKQAjDguO/IVoHTzuD9bHkDfoX0
         nl6n1x+DQMbC9JnBrnhhhGKMuDqTKol+X02CTL/caKPF+oXoCE7yzuIJUgrOtS7hnU7K
         AF4Q==
X-Gm-Message-State: AO0yUKWtfgKbsNA54OAwZgRKx3GS4WZjhMJpETgj016xaJZeMOCJEjl+
	zJHtpf5mGDg0sHEP4Ol4+UM=
X-Google-Smtp-Source: AK7set+MGfiPZ1iab30izaRqH0+2ypvB/uGVI3amdbn+/Cr/e1uHILWllGy7OwmEX+2KIgcSD8Jf1g==
X-Received: by 2002:a05:6214:974:b0:56f:80e:701b with SMTP id do20-20020a056214097400b0056f080e701bmr599901qvb.2.1677565973928;
        Mon, 27 Feb 2023 22:32:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4c12:b0:3b0:98a4:96b8 with SMTP id
 ey18-20020a05622a4c1200b003b098a496b8ls12378840qtb.8.-pod-prod-gmail; Mon, 27
 Feb 2023 22:32:53 -0800 (PST)
X-Received: by 2002:a05:622a:1c9:b0:3bf:c665:20fe with SMTP id t9-20020a05622a01c900b003bfc66520femr3511342qtw.22.1677565973059;
        Mon, 27 Feb 2023 22:32:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677565973; cv=none;
        d=google.com; s=arc-20160816;
        b=OJvexKIpInOtOSEstas+Xu23EC3SzdbBLtO8MNygqdn0uRS5j15iE1+PCcuRDAoElp
         QoG7CdSClwAhtE/KTV1snVeWxoPkPvlNbT5Wp/1aIConYpa3PFnntMudcqZB2nxYvenf
         dUm5ul1mB8Xav2gGDMPC9fVsT4/IKu2eh1hZA6p2DrZU1Wxi1dewQZ4n9AXfYv/c7Oi6
         EMTDSygdB8FeB5GrxHYMc4IoI9/4pPOHXCJ6sd2Gu2XqbKGy6b15Jusmu1vkTInB1JdB
         kO108YfFR0OASVpp7+kK9C/iATLLGIytMotKDk6V00oeOEdTobtr8s+HJP9V0H/5ntFh
         ppfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=lS6JtWUQ52Qb7wGcCxHBiNyAoHwwQgmvUkclpS5/AjA=;
        b=ghQJ2Cw4/UjMcQeZDJ4e01pD5CriAAW1yq7tX8rdjcVH7DQsmX84yDJ3ATKl0Crm31
         XOwmC29OY6yypV42gIYltZwXj/3F2hMGY3RbXPxoD32Z/KjRcyrA0k58jwQuXBDzh0Ho
         Fin7KQ3RWz22L88Ny6k4sy/VLtnPSMdCnIhuhwUdtHUpWJ92z9KuWyJdnBW0XsGA1M1O
         mzoQjh9exB2U5gh9KSK96Xtj3IwUCOvVqlnUAq7183jfzgbbLJvhcWu/ZM/BV7ze5O7c
         paXSqEY2NwNl1yLIoArn1ihm8JP8M8AbdCc2QBmWuk3fSr1OoLvJnP/LJkvcCIhWemsk
         SciA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UQZocSva;
       spf=pass (google.com: domain of 3fkd9ywmkcxeerrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3FKD9YwMKCXEeRRVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id u14-20020a05620a454e00b0071da5397385si477928qkp.4.2023.02.27.22.32.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Feb 2023 22:32:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fkd9ywmkcxeerrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-536a4eba107so190947957b3.19
        for <kasan-dev@googlegroups.com>; Mon, 27 Feb 2023 22:32:53 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:cb8e:e6d0:b612:8d4c])
 (user=pcc job=sendgmr) by 2002:a81:ad0d:0:b0:536:38b4:f50 with SMTP id
 l13-20020a81ad0d000000b0053638b40f50mr952514ywh.1.1677565972773; Mon, 27 Feb
 2023 22:32:52 -0800 (PST)
Date: Mon, 27 Feb 2023 22:32:40 -0800
In-Reply-To: <20230228063240.3613139-1-pcc@google.com>
Message-Id: <20230228063240.3613139-3-pcc@google.com>
Mime-Version: 1.0
References: <20230228063240.3613139-1-pcc@google.com>
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Subject: [PATCH v2 2/2] kasan: remove PG_skip_kasan_poison flag
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UQZocSva;       spf=pass
 (google.com: domain of 3fkd9ywmkcxeerrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3FKD9YwMKCXEeRRVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--pcc.bounces.google.com;
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
---
v2:
- also remove GFP_SKIP_KASAN_POISON and FPI_SKIP_KASAN_POISON
- rename GFP_SKIP_KASAN_UNPOISON to GFP_SKIP_KASAN
- update comments
- simplify control flow by removing reset_tags

 include/linux/gfp_types.h      | 28 +++++-------
 include/linux/page-flags.h     |  9 ----
 include/trace/events/mmflags.h | 12 +-----
 mm/kasan/hw_tags.c             |  2 +-
 mm/page_alloc.c                | 79 +++++++++++++---------------------
 mm/vmalloc.c                   |  2 +-
 6 files changed, 44 insertions(+), 88 deletions(-)

diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
index 5088637fe5c2..9bd45cdd19ac 100644
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
@@ -234,25 +232,22 @@ typedef unsigned int __bitwise gfp_t;
  * memory tags at the same time as zeroing memory has minimal additional
  * performace impact.
  *
- * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
- * Only effective in HW_TAGS mode.
- *
- * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocation.
- * Typically, used for userspace pages. Only effective in HW_TAGS mode.
+ * %__GFP_SKIP_KASAN makes KASAN skip unpoisoning on page allocation and
+ * poisoning on page deallocation. Typically used for userspace and vmalloc
+ * pages. Only effective in HW_TAGS mode.
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
@@ -335,8 +330,7 @@ typedef unsigned int __bitwise gfp_t;
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
index 9db52bc4ce19..232bc8efc98e 100644
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
@@ -96,12 +95,6 @@
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
@@ -130,8 +123,7 @@ IF_HAVE_PG_HWPOISON(PG_hwpoison,	"hwpoison"	)		\
 IF_HAVE_PG_IDLE(PG_young,		"young"		)		\
 IF_HAVE_PG_IDLE(PG_idle,		"idle"		)		\
 IF_HAVE_PG_ARCH_X(PG_arch_2,		"arch_2"	)		\
-IF_HAVE_PG_ARCH_X(PG_arch_3,		"arch_3"	)		\
-IF_HAVE_PG_SKIP_KASAN_POISON(PG_skip_kasan_poison, "skip_kasan_poison")
+IF_HAVE_PG_ARCH_X(PG_arch_3,		"arch_3"	)
 
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
index 7136c36c5d01..960e0edd413d 100644
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
@@ -1355,13 +1344,19 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
 /*
  * Skip KASAN memory poisoning when either:
  *
- * 1. Deferred memory initialization has not yet completed,
- *    see the explanation below.
- * 2. Skipping poisoning is requested via FPI_SKIP_KASAN_POISON,
- *    see the comment next to it.
- * 3. Skipping poisoning is requested via __GFP_SKIP_KASAN_POISON,
+ * 1. For generic KASAN: deferred memory initialization has not yet completed.
+ *    Tag-based KASAN modes skip pages freed via deferred memory initialization
+ *    using page tags instead (see below).
+ * 2. For tag-based KASAN: the page has a match-all KASAN tag, indicating
+ *    that error detection is disabled for accesses via the page address.
+ *
+ * Pages will have match-all tags in the following circumstances:
+ *
+ * 1. Skipping poisoning is requested via __GFP_SKIP_KASAN,
  *    see the comment next to it.
- * 4. The allocation is excluded from being checked due to sampling,
+ * 2. Pages are being initialized for the first time, including during deferred
+ *    memory init; see the call to page_kasan_tag_reset in __init_single_page.
+ * 3. The allocation is excluded from being checked due to sampling,
  *    see the call to kasan_unpoison_pages.
  *
  * Poisoning pages during deferred memory init will greatly lengthen the
@@ -1377,10 +1372,10 @@ static int free_tail_pages_check(struct page *head_page, struct page *page)
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
@@ -1754,7 +1749,7 @@ void __free_pages_core(struct page *page, unsigned int order)
 	 * Bypass PCP and place fresh pages right to the tail, primarily
 	 * relevant for memory onlining.
 	 */
-	__free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON);
+	__free_pages_ok(page, order, FPI_TO_TAIL);
 }
 
 #ifdef CONFIG_NUMA
@@ -2456,9 +2451,9 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags)
 
 	/*
 	 * With hardware tag-based KASAN enabled, skip if this has been
-	 * requested via __GFP_SKIP_KASAN_UNPOISON.
+	 * requested via __GFP_SKIP_KASAN.
 	 */
-	return flags & __GFP_SKIP_KASAN_UNPOISON;
+	return flags & __GFP_SKIP_KASAN;
 }
 
 static inline bool should_skip_init(gfp_t flags)
@@ -2477,7 +2472,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
 	bool zero_tags = init && (gfp_flags & __GFP_ZEROTAGS);
-	bool reset_tags = true;
 	int i;
 
 	set_page_private(page, 0);
@@ -2511,37 +2505,22 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
index ef910bf349e1..b0c84847e9b6 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3170,7 +3170,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 			 * pages backing VM_ALLOC mapping. Memory is instead
 			 * poisoned and zeroed by kasan_unpoison_vmalloc().
 			 */
-			gfp_mask |= __GFP_SKIP_KASAN_UNPOISON | __GFP_SKIP_ZERO;
+			gfp_mask |= __GFP_SKIP_KASAN | __GFP_SKIP_ZERO;
 		}
 
 		/* Take note that the mapping is PAGE_KERNEL. */
-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230228063240.3613139-3-pcc%40google.com.
