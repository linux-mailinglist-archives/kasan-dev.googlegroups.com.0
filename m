Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM4NXT6QKGQEGJ23LCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id D16A42B283F
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:36 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id 144sf7660365pfv.6
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306035; cv=pass;
        d=google.com; s=arc-20160816;
        b=nOkIC83F+NdIRUS3fzNO3uBaEodoIO5DoQOPdFfaRO3wK+UhQmYDoCe/7fduhS/V/v
         tSSidz/HyGF0o1zXyTvA90Mn9QzQP45c7+eN5Bjopqcg7pQPhEX1hOWfH43Neb5qdugQ
         l/XAhvjcS9m88alK6JjA5jbVvibAhwokCegLlJHjMsbHIbcd90APsRclslaG+pXaxcwq
         8wxcHT0UU7A4yfUyzY6eBwMFrcrVCnWe/e4JmacEXIh31nDuxxGIA6sU/xePl+rDZtiK
         0BMuJrw2GgR4IDe3s6H7jQrFfkY2DwfmJar4oZbYQuSp06nEXePmMWWw7zPgTUeGW2zw
         HQAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=DwB5lQKKdDkJsomK60bPYGmMHLU41W5xAPj9SqZQir8=;
        b=084jUAcWaXIffFmJBvV9B7GTGHoFpIc0W/AhOOQHplOFNtWz9thex1dfwBzpCgkMVv
         BHHehVpiJMhSCTJ98R3Q6wo1V5H75bD90j7KtwWp1pNmSVYgyniZTyH6vVUx9mvGNh9F
         YrZ5A2Ifz0idtxMzIhnmZrz6OixbpNkUyvR+saEbw+w9vboAA4TRfkHLSH6XGx2Jeb1Z
         EAfviO37TOz+kKxNWOQ7+iOWCWaW0bkiryKWGInBHAmwaC12PyFC1Qu2zGSDhY+Pnlf5
         zBUCqQKAsf0vsetTJvsLlze0nZPGek6P0/9zK6c8Jk6hsZOju9oLXbpUfwWHlikyuO07
         /7XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=avk+IvhM;
       spf=pass (google.com: domain of 3sgavxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sgavXwoKCX8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DwB5lQKKdDkJsomK60bPYGmMHLU41W5xAPj9SqZQir8=;
        b=qqZPPPxvFo8hRGqlPp1iUaZupogTmTXHNrKLnJk/SkuMV0Rm5jKMy1SfdH0PKSqJpP
         bjbDMt2Ugg3Blq6SDPFN1VFViGfjqYO3WTGlcmt4SIx1pH65ukKdjFmhdU/uP/fVRj59
         LVsYZDv7A6Uuafz2Lt1JzkOVTjSth7ODdVPAyK0S9/xL61beiln8xLTZRqn5Z4uN1Aw8
         moKYiM+W1Du+U76cXCtfwGcyi7rGxfFk+bsB8bjj/70YggsLjultSnNHK1gcq35/xYhr
         6tmireLPW+eXTump3iFHKdet7Cdrk/nJ9fNtHvOzqJa/kx0c3OVviJkZnFwAxkvi37R1
         S4HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DwB5lQKKdDkJsomK60bPYGmMHLU41W5xAPj9SqZQir8=;
        b=LCW7wnzjFGR8Whss/3pCCXU9612dSEhWMVlk4rZKttp0ScrIbRBhztrSkgEmosVdM6
         SuMnQq7BrE04h+wOHCrjjJssby4GPEwxYUCN0f9JUNbx22ljDfhDzzc+9iFDvr9swQQR
         6HnhiF+qsOzjVuaQ2TDM4bwZ3yv+hwSiojh3LsdfHbTUN0XVY0u1htP6B5bIISGmqud7
         YUNgJGfl+f0ldIPFNJEkoU42ZIzgUw4JjfWBWNmyB12vCiLSkberL01yQBrmgsdTRfEs
         P2MMb1GAnLKb3nkdet74moKSMDMrDElIs+3hQVzTn3Gve0R5uHEYL6DT0fEuf/RBmsc4
         05Rw==
X-Gm-Message-State: AOAM532/Fh/ng62pHsYF0G1nE5N2DCEyJbnLcmWtiAlzH17hMDBZ1L9b
	NcvCXHOf7VboLR5OaUDGGPg=
X-Google-Smtp-Source: ABdhPJx0LZ1GzI+UNZt6kVS1ABeF0+zrqUeeAl/RlpKSB7Yd/zgNNvaZ8JEbkqL8Sx5w7XSkJDCQ9Q==
X-Received: by 2002:a17:90b:ec9:: with SMTP id gz9mr5220372pjb.105.1605306035574;
        Fri, 13 Nov 2020 14:20:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4e13:: with SMTP id c19ls2558084pgb.9.gmail; Fri, 13 Nov
 2020 14:20:35 -0800 (PST)
X-Received: by 2002:a65:56ca:: with SMTP id w10mr3800803pgs.204.1605306035063;
        Fri, 13 Nov 2020 14:20:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306035; cv=none;
        d=google.com; s=arc-20160816;
        b=WnnSAlyfrmrNq1V1LdplIIu1AZ6qNZjB6Y8t9imjeoyEhsRfmzAFYzRgajP6MV8+B+
         aJWOKqyZiXH/f3D3tUpzLAaXwlSQXQgB+xDmaERHc36/BPcU77eYBk7AZLLotKT/7ovR
         BNxGGmrPqDNtWQFOzl4D97ARM+1Ww38iNu11p2Y1aYap5CVC+TFykysDBTw6N8vFycXk
         0lJmpnp5Fh5Cm5hpiZjYOsvN6dAVNjyDwI4TNDo242qnwHUjG19grJlgMvIu3Rw5ddEJ
         2JRV4MDHdo2RVv5TIaeJLY9t05h5oS5TXCZ19pnM2fBDWYe+GVjchEaOFtNU7EK2eAx/
         Ae0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=YBdsxMVQVE97UJPn5Dc1HSKikQDmHg1H37Pt2LLE+Kk=;
        b=AXoxb6D5oGwlrGi4AdwSRVTSxzaI6Przoa0lTdP4ZxU5eUQowLzIHAvRXh2DWz9wUx
         igMP2TWR2SKhQhm7Tzhh1zd4BMaROLhEhij6T4k8/A1bN7EtA4Gdfob6BG7Cjv0nR7Y+
         gGXgtLE35oH9yfEFYn517QW4E3sde8KyAiX7WpWXxCSRDz4D6nkK0gIOi3qE1Y5KrRqS
         H4iZyNucOqcMqe5HQvgxcG6qGrZjriu0o1JExS0lPgdDNVQrmF2iONNuDMWwquIJbaUn
         3fXkhGmQHuxIrreXHiWilt1SOLC9itnQsuEBmXlPK5IxIlnbiQoP04tG41/jLkZr2mAp
         d7XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=avk+IvhM;
       spf=pass (google.com: domain of 3sgavxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sgavXwoKCX8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id bd7si566108plb.0.2020.11.13.14.20.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sgavxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id ek3so1322508qvb.0
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:35 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:43ca:: with SMTP id
 o10mr4757439qvs.33.1605306034217; Fri, 13 Nov 2020 14:20:34 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:58 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <d42cdd23c59501ccc4ab91cf4e04dd134be57277.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 08/19] kasan: inline random_tag for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=avk+IvhM;       spf=pass
 (google.com: domain of 3sgavxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3sgavXwoKCX8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Using random_tag() currently results in a function call. Move its
definition to mm/kasan/kasan.h and turn it into a static inline function
for hardware tag-based mode to avoid uneeded function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
---
 mm/kasan/hw_tags.c |  5 -----
 mm/kasan/kasan.h   | 31 ++++++++++++++-----------------
 2 files changed, 14 insertions(+), 22 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index a34476764f1d..3cdd87d189f6 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -51,11 +51,6 @@ void unpoison_range(const void *address, size_t size)
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-u8 random_tag(void)
-{
-	return hw_get_random_tag();
-}
-
 bool check_invalid_free(void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5e8cd2080369..7876a2547b7d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -190,6 +190,12 @@ static inline bool addr_has_metadata(const void *addr)
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+void print_tags(u8 addr_tag, const void *addr);
+#else
+static inline void print_tags(u8 addr_tag, const void *addr) { }
+#endif
+
 bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
@@ -225,23 +231,6 @@ static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
-
-void print_tags(u8 addr_tag, const void *addr);
-
-u8 random_tag(void);
-
-#else
-
-static inline void print_tags(u8 addr_tag, const void *addr) { }
-
-static inline u8 random_tag(void)
-{
-	return 0;
-}
-
-#endif
-
 #ifndef arch_kasan_set_tag
 static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 {
@@ -281,6 +270,14 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#ifdef CONFIG_KASAN_SW_TAGS
+u8 random_tag(void);
+#elif defined(CONFIG_KASAN_HW_TAGS)
+static inline u8 random_tag(void) { return hw_get_random_tag(); }
+#else
+static inline u8 random_tag(void) { return 0; }
+#endif
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d42cdd23c59501ccc4ab91cf4e04dd134be57277.1605305978.git.andreyknvl%40google.com.
