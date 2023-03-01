Return-Path: <kasan-dev+bncBD52JJ7JXILRB3537KPQMGQEJI3F2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C3246A644F
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 01:36:01 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id l10-20020a17090270ca00b0019caa6e6bd1sf6013327plt.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 16:36:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677630959; cv=pass;
        d=google.com; s=arc-20160816;
        b=TTlVEPMX59cQkjFdfjNiZjbpeYqB/DvC6gwDSQXkkeKuw0dN9iTtC90aQV83t9Xyl1
         kviiAUkape3ni8gwh8sfsMchDtJxQCM+hf7rPGV709c4y5E6W22svqCpMgH0epOFD+OA
         ukO0pIGEkFKo5bevb6IENiiEqXL9XNkHIj/QpJqXhxXMUm35SaodL39DLlcj3ImnpfVj
         Rom8L+N8PLVDkkkIDz8Oumips4NzPyA3mfsgBXPYpzz9I5hNWo0m2oqae3FxlZMMmBX4
         u9J5+/ifoIKrAs527b6HJbAsXqjp1IvvIPemqpDY1+pe1xXOydMJf0ODKxj/HSVsikcx
         yrPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lRaO9XFtNbQ8f0OhOH+Zv/0gInW46CGR68Inm5BzGxo=;
        b=TUNwo0TtZ4E5XZsMJpMTODYKedtKR/V+XqgAwWmyZbTUvy67Z6RqT5ggP4k7ou2LWn
         5+bsORueGdry9JskT6ihmbhiIdFr0NYHFlU1EDj/fWxQPuxt43jn6Rt4HH53YIpXb2is
         QCiRwDDc1yeXYIkZu6JPaXpqHUgXkLxwxNPewrKy7xgc/K/7khOUdQWOTLSiovNpOPeR
         F/f1VdTKlpuhEHz4YuUfQZNDui2rTVoNAsI63yLiwI+Bq37Lmo6zALmO7vwV5WUJ16As
         6YgKTYvcNjMd0PKkEA0Cv61jtqPJQs0DfSKwKmoU35p1e3BfeJ3saYCUcuDMeZkmCyJH
         byiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AuslzdI7;
       spf=pass (google.com: domain of 37p3-ywmkcus2ppt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=37p3-YwMKCUs2ppt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lRaO9XFtNbQ8f0OhOH+Zv/0gInW46CGR68Inm5BzGxo=;
        b=WTwkNgqysRMEwPhK9+TGLXKf8Db+Z5pylU/Vku9JKCUBrFQrD3Lea3Csitz9JrBiqr
         zMxwIjQ8QoBKSQGVH0I1rurxxC2V/tbv7IiuYG+f9etcsqYNMSidHEg4W5g/ItG6xgow
         f3F/CSJ2sod9EDAnvkzlKeul1IHRzWxM4xV4G98Mwd+EfNQS6eKdb1cLRXXFISwC9JTc
         WMfajpFUdwyfUg5KoqWpxSs4l6oD02k2gdTNoUR0Sm7VXvWA28ja0U2EOsutYlVEmHSy
         qrXgOH4h4OQnW9MvTaZK/XBMFDlpmC0bky65Ba6E4t1JSnsx0hhyugTJ+S4Fn/LhTw2C
         XEkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=lRaO9XFtNbQ8f0OhOH+Zv/0gInW46CGR68Inm5BzGxo=;
        b=c0McsO8+cXX3j0RQmQbBqthLHVy1VEBKt1HZcBY+Ar71TZ+8e1TfDorpjZIoxrDjT8
         1x73IOxy1xcDtYrkxbhxpG6vfCnFdCCRlcS7raTNa4Cpt4chQaZl+/4a74SC3hw+3rUH
         61rpjRxSo5cRJqBiOtQcS+FryM2PIPBh6L61hsHHdwOnd2Ca2k71VeQBZMWcH7qS6ecK
         SkD/5SR74oUXaRdkQoya8iZG+W3PfpaJgP6m7t6dqoe5n99vsTVXjtvjwE9RdJUTRXDV
         Rjmt7MZDUBvY865/Kr66RqUOD1+aMqXjmq027uqqbjS+pEXknH1p+rcLd7pvxnXZuO4+
         QQGA==
X-Gm-Message-State: AO0yUKWPyrklEkldBx75iHEiSyOm3m5qsZ3FOdUw+KyrX73BR0SCiwtx
	6y+3bGsQAZQNyt6i81a6yVE=
X-Google-Smtp-Source: AK7set+UxT7V0o+mbLaVjN/Ymclbl+ucs/WJIQMXJflg5A9hM7cjLRRyW7Gh8/iXx1mg7u9KUD6dGA==
X-Received: by 2002:a63:935e:0:b0:503:25ce:e914 with SMTP id w30-20020a63935e000000b0050325cee914mr1527487pgm.0.1677630959674;
        Tue, 28 Feb 2023 16:35:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7896:b0:198:ddfb:494 with SMTP id
 q22-20020a170902789600b00198ddfb0494ls15880735pll.8.-pod-prod-gmail; Tue, 28
 Feb 2023 16:35:59 -0800 (PST)
X-Received: by 2002:a17:902:ab57:b0:19c:dd2e:d4f5 with SMTP id ij23-20020a170902ab5700b0019cdd2ed4f5mr3517421plb.36.1677630958869;
        Tue, 28 Feb 2023 16:35:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677630958; cv=none;
        d=google.com; s=arc-20160816;
        b=w0l+pLVu213+Dx6jdn8nQPYaBsh4iAK+7BW2pB3MslGb+4B7ddhhSeiGMOtVUf0QH3
         /ruO/VMxeA85iiaZeW9DaxBzgvDRFQq9uN9S+ONTPy7EBuMnIp4Cvwt15BslpYNZ2Vy6
         Tq/iDdG6LhRQpNFuaOz7JTFqEKuSTourAmMRPxgFiGQsl/GRvhIsiiUTxZhwxJmk8oXp
         pgOzdOeKY8gXxdZHisGH5bCDKikK2DjxrUQvcsVVn5BJ0Xh8t/rMHEm5KcL3T7JeF2KF
         G4SY3OUZKtXFPbeMvDvHCRPyNx3NDtNEZ5S0F22WicGJbQXH93zitXuVY6Lg0Lk4HX6P
         R2IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=NjYZ7qGe/4ra9Gc/ryyn0J5hZXPg6ro+BerrGnTKpQ4=;
        b=nNrhb1rxaYxxV7bVyodVEkTFXU5VBhE/HppQx2Oj5Yc3rPz7IelZXUwq1gtKHZZSzM
         GZsdhWav+jmvKsudDZCLtGyMfZPa/QnHakIhsQrmO8y+j0uIam9ssnhIGxhkzCCio72i
         DbKEr5vSVRFoGdNqMdSIaRLQMxmoHDI6mV9p5vo5dmO2c2uq3R77YsiHJmD+pmiqaTNv
         VQ63JLnCFutfsrVqD3zLLeLLiEkrQQe/0h4oQsmEbE8l1QSIa5XdPkYpcdt6maS5vJJy
         Hd+YiIc9BJyl1eSL0guWJdgdFqOxK6AuvLMT0vATyD2WMi2whC5saPyTC93SbZIHVWAn
         t22A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AuslzdI7;
       spf=pass (google.com: domain of 37p3-ywmkcus2ppt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=37p3-YwMKCUs2ppt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id n9-20020a170902968900b0019a723a83d2si480296plp.13.2023.02.28.16.35.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 16:35:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 37p3-ywmkcus2ppt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-53700262a47so243258057b3.4
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 16:35:58 -0800 (PST)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:cb8e:e6d0:b612:8d4c])
 (user=pcc job=sendgmr) by 2002:a5b:892:0:b0:9fe:195a:ce0d with SMTP id
 e18-20020a5b0892000000b009fe195ace0dmr1054943ybq.10.1677630958111; Tue, 28
 Feb 2023 16:35:58 -0800 (PST)
Date: Tue, 28 Feb 2023 16:35:45 -0800
In-Reply-To: <20230301003545.282859-1-pcc@google.com>
Message-Id: <20230301003545.282859-3-pcc@google.com>
Mime-Version: 1.0
References: <20230301003545.282859-1-pcc@google.com>
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Subject: [PATCH v3 2/2] kasan: remove PG_skip_kasan_poison flag
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: catalin.marinas@arm.com, andreyknvl@gmail.com
Cc: Peter Collingbourne <pcc@google.com>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AuslzdI7;       spf=pass
 (google.com: domain of 37p3-ywmkcus2ppt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=37p3-YwMKCUs2ppt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--pcc.bounces.google.com;
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
v3:
- update comments

v2:
- also remove GFP_SKIP_KASAN_POISON and FPI_SKIP_KASAN_POISON
- rename GFP_SKIP_KASAN_UNPOISON to GFP_SKIP_KASAN
- update comments
- simplify control flow by removing reset_tags

 include/linux/gfp_types.h      | 30 ++++++-------
 include/linux/page-flags.h     |  9 ----
 include/trace/events/mmflags.h | 12 +----
 mm/kasan/hw_tags.c             |  2 +-
 mm/page_alloc.c                | 81 +++++++++++++---------------------
 mm/vmalloc.c                   |  2 +-
 6 files changed, 47 insertions(+), 89 deletions(-)

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
index 7136c36c5d01..0db33faf760d 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301003545.282859-3-pcc%40google.com.
