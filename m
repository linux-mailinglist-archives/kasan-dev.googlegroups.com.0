Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS6GTX6AKGQELUUCGFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0127528E7FE
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:45:00 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id 2sf244062wrd.14
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:44:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708299; cv=pass;
        d=google.com; s=arc-20160816;
        b=hmdJacmbm18cGX0XgOhfkpZwdfc/42CYdZ5YD17p/YkC1QOyF46koCaRuTmQLl6EFE
         2mx1oxU9CllSMJ6Z1YaXZQNKiGY5d3gsHi+5Xg6crYgwAmHPfvo1KiYi0a9q8q8n0STm
         GI7aj7oa0tKTlQhIUK4GrHQCPgh8p56HmHhOBkEdvWZQrdsM2KEMXLEmtridnPs3qe8N
         VPH9YWtUVuouuYFJtgaHCd7Yw8HKNYxOdGLyNkHd1MGHrTehQThAGbWx7A+/Y+HBa/UR
         AYdMk6uvwtJRTlYymWB2clGaMbrcxIyGR/tyLxUaeD+Lzcgnwf8Pflt14yu351aQd4pr
         cRow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5N2Pooq+qHRWOIUuaLpzA5lJJJTCJb1DthRWJ8eAN14=;
        b=QkX+urL+ECFq3nWt5vysD1Cz+ddCkGfZKDCY3phUFgGkwx1iV6bxlTt86aBcM8PxBf
         d4ZWSOTUm1vL9bxkIOgV+4f4hlWv2eofl6dQun+k7Y5BQ0V7BIAwrpUg511OHDPxIdRH
         JjqKlsjq8VHkCR7pbGEda5TeHZP6z8CJMM8vU91uh3lHmfFs/DOg+MLshkzaWHCn5MFb
         QWyJiJwwYU+sgUpmnH1YcwN2UaXEma1lcuG1jEofZLNV8g7oktoYDzQHqHYU2tXIOnFs
         klMnuTHGzHoI+fK0MI6Mrp/yaUhTulGSS2Gga5ff5HGgJfDa2lr6sJcGO0836/niBNdQ
         pnmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hb9Kmil4;
       spf=pass (google.com: domain of 3smohxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SmOHXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5N2Pooq+qHRWOIUuaLpzA5lJJJTCJb1DthRWJ8eAN14=;
        b=SJ8rq7Io/JyMH3E8LI3opVpDI/nF4ffCDWkfGmTdLH1RQToeQUjFVw58pbe6QMYQD3
         UWfsor0alZ/vto+Og2bUC1mOvFr2T/Z/7JxhMrcl9RYpgw9pxKlbGgf9qNrjsD/tv/6B
         RDRd6ronkFRq2m2F+gCJ+bO+XMTbXmX6LiWQCS5GDAvbVl4+PpM1nuu4hVAU4Q+NdXA0
         D5N3sIC6b9vfHDPQb6tki+fQ8V4OY//uv9GRA0qsvG3tszmh5shTyIdUVnDqDBFjTs4f
         4ji6+y3PAnmhTRplPajdpVPG0zeOfi0+pRgMGLrq79Y51u/uCEs6QLOxh4c+G91evABF
         rYQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5N2Pooq+qHRWOIUuaLpzA5lJJJTCJb1DthRWJ8eAN14=;
        b=Ag/Ov7Fv/3S2soXLS9OcDWKAX4F8dhbNkrXdszanuKQaVv/fx3UT/qvikDJrK6Nd0n
         ZcUz6arqtyv3vRUk85KgzDZ1TgGLlapPFJDfb8IyWj37h4FYlTR081il4ZMNmO2LPC4W
         MBNcGF9T4z+cCvgGhM7RU7xflvwHohGUaRAEZbvI/gEz2jGvqf8PJN8/ZBCBwa6LEic1
         QTjIA5Lbys8oT1sV8+8daXL65w5REGJDrSNeMHL/gnXyi8dGIb+jJSknz3oQqwB21h2c
         /uNP/D/EB4K2x69ssPxvwAjQvT8HXDy5qhw9akoy3pSIa1pstIDdOPaAB6FLOsinif/E
         y1HQ==
X-Gm-Message-State: AOAM531zPfYB+9MRJ7jKNcuuX2s9qNGZdk//Qin1EMvfajyJ7SXwkNPG
	6QLe6XatPsEJ2E7hevZa8n4=
X-Google-Smtp-Source: ABdhPJyDCnW6q++jhwul2a20zUhyMZhH3vpbW2b4wszPNqeCVbcICe6LTmNU+wWS8leXLywrs8b/UQ==
X-Received: by 2002:a5d:6904:: with SMTP id t4mr599391wru.410.1602708299706;
        Wed, 14 Oct 2020 13:44:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4a52:: with SMTP id v18ls765202wrs.2.gmail; Wed, 14 Oct
 2020 13:44:59 -0700 (PDT)
X-Received: by 2002:adf:c3c2:: with SMTP id d2mr563801wrg.191.1602708298960;
        Wed, 14 Oct 2020 13:44:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708298; cv=none;
        d=google.com; s=arc-20160816;
        b=OiEzwptcwb8cDqtzlj5d4+pm8eM0oQswiAv6NLbFiURpArsitINhcyAZeOyUnboZft
         nZwwQys0+DZh7q9RWZ46iSNWMe/vh3c75scI+JbKQDjQspDkwz7qJDXaMYABZRNDLLAi
         Kse6GityjZ4fs2JypHGQVMT1pTagiGEfu6ndRsa3Rv+TImpYZurFAC/JK3mntHNYSX5p
         YI5M+apSm2KRB2LDXfdmw47tZtReI0t2QZ8u1ADvhFEuR2YfrI8ZgZtXZlG6akby5iVn
         EkfuzQ40gz0Vy9SoMAkIynKMsunEIYPYBl8Aw70gAlmjDD2b2XJ8gWkrW4KvSFYbqiQB
         EYEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=K2o7M+jwCbfe3UtigR/EtRx8zIOq967XZxvWYmUAylE=;
        b=tih/82+n1B2Jy6ihGJNeHsOnFTBSEhRQMJ2+t6e7INi1tDtEzEdIkUoNDiv4spRsC4
         4ERvZN+tJxMHJKthxmruLPHSQ5dj5NtTxfSMN/iAGfoG2AievG76wuSgsVler8LYcx73
         0BCvcZ2mFVuiz0wWdfkMarIUTqKYEv14YsHS930izd+nQQRfYRDsYJFbJ8iJewvS4lG0
         i6rhiDwEmrJyKioZSma4azeGx0k2d+aLOXo/YzkdZPuzpJAPdNZ2h+ylsYv3emordEV0
         nD9NFCqsTE+IWkC0klnRuKQP/7Xvr4IsOjwDNIXmktlhTSnLUDzHJaXMWJTLqMKgTa3s
         AOEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hb9Kmil4;
       spf=pass (google.com: domain of 3smohxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SmOHXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id e5si27909wrj.3.2020.10.14.13.44.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:44:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3smohxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g125so423806wme.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:44:58 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:e1d7:: with SMTP id
 y206mr622854wmg.48.1602708298576; Wed, 14 Oct 2020 13:44:58 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:34 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <4e018edd628802e8454e80fb308e220e1ce2113a.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 6/8] kasan, arm64: move initialization message
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Hb9Kmil4;       spf=pass
 (google.com: domain of 3smohxwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3SmOHXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
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

Tag-based KASAN modes are initialized with kasan_init_tags() instead of
kasan_init() for the generic mode. Move the initialization message for
tag-based modes into kasan_init_tags().

Also fix pr_fmt() usage for KASAN code: generic mode doesn't need it,
tag-based modes should use "kasan:" instead of KBUILD_MODNAME.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Idfd1e50625ffdf42dfc3dbf7455b11bd200a0a49
---
 arch/arm64/mm/kasan_init.c | 3 +++
 mm/kasan/generic.c         | 2 --
 mm/kasan/hw_tags.c         | 4 ++++
 mm/kasan/sw_tags.c         | 4 +++-
 4 files changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b6b9d55bb72e..8f17fa834b62 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -290,5 +290,8 @@ void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
+#if defined(CONFIG_KASAN_GENERIC)
+	/* CONFIG_KASAN_SW/HW_TAGS also requires kasan_init_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
+#endif
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index de6b3f03a023..d259e4c3aefd 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -9,8 +9,6 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0128062320d5..b372421258c8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -6,6 +6,8 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
+#define pr_fmt(fmt) "kasan: " fmt
+
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/memory.h>
@@ -18,6 +20,8 @@
 void __init kasan_init_tags(void)
 {
 	init_tags(KASAN_TAG_MAX);
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 void *kasan_reset_tag(const void *addr)
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index bf1422282bb5..099af6dc8f7e 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -6,7 +6,7 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+#define pr_fmt(fmt) "kasan: " fmt
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
@@ -41,6 +41,8 @@ void __init kasan_init_tags(void)
 
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 /*
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e018edd628802e8454e80fb308e220e1ce2113a.1602708025.git.andreyknvl%40google.com.
