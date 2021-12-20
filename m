Return-Path: <kasan-dev+bncBAABB3P2QOHAMGQEMC4DWCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 27DA647B5A3
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:22 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id v62-20020a1cac41000000b0033719a1a714sf2438845wme.6
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037742; cv=pass;
        d=google.com; s=arc-20160816;
        b=XdArtvnTPy7g0jxMwfVAvnaEChpqm4ArUSFebmarlWZLfYerxm6g/JcJo17jQLeGEf
         9CFZQg9pZrtEgl7NRFuWFSNsv97DJFTwDNUihQgz0p8SmAR1Y0RxrsfwcThDqNrlygd0
         RpqmG3NrxWvMDlX+mNB92IJn1RzGgZdbfhVSGrPsV6OANGeko9HQsEozkiwLDAYQ7cyi
         iDINWcU3qvssthxIlg4tdINXUYXE/BaICmr/2iMwVOMo0/Hg7JkerdKxeIxjSDjZTXUk
         g7Y2CeUONNBW0VlWnOxrjSr1KIgjL2KtjZpRYC3JSgAJ3eqRhcLvyb2WD4Ysof5yRK15
         xmeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0tfN60lZoZa+0mOepaUUIuzaIm5aS3ks1UIrbTMPX14=;
        b=BzCc14r2beMfrQVJ19BZ+MCuFBmMIvLV6fQge4qnOngwGMr+f/ilNdQqnI0H6n1XX8
         kFxXvVf3Nba/DR6PKcBu9EINsfc4h2/iMa9zFJFnoDMUYwJ48Hn6lYGM3NhGQknAiDOy
         Tpn8uCc4XOOxGhbwSvYJGYp2VhVYqwsr2RHjG6IbcS2f44GmEySQf90roV6ip1GiiQ9F
         0d8V4ZEJqIla9w6Tfd4Skd4ouaUI7E0ljikNkEMIAt+mK0X3U7r7K+RqtpE9r96K422T
         Fgjdx8XJWqm+JxNJ0JwZYt4Tmm+QVnlm8oAduD5z67c6TMCRHlmQFe7jXaveSi1yL4cc
         S9HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rFvsj83q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0tfN60lZoZa+0mOepaUUIuzaIm5aS3ks1UIrbTMPX14=;
        b=YJ9pM03t+Km9hkh13IAy47BsSpU7auT+GDL/PCCbsvtwt8av7qyTs2WzGHiVqPboGq
         SvVY9TsGpCTEkHa52tI068scssiSaJUADOfk7EqQDAIqNggPkoAUH7AXvxroTTC8Prye
         SQCIwJh65EgaLhkZ1RxG5fXd1mVhCfkSYeb+4UIZf2s6fnCwJXvQiLTyAt3CMz3xBzP4
         NcA+DJCngl0Ue6PDJsxJBr2ZbA8M2YfKSTX6Le8ohN/hiD+AItz9sFK1XsnHBruF2UFj
         qhNGTw2j83krOs9l93un9h1PAmIJ54SLCdtx0aJqX9GYj8KpTCzcdUtwXB2wgVMXxYIP
         0zLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0tfN60lZoZa+0mOepaUUIuzaIm5aS3ks1UIrbTMPX14=;
        b=3MjFr9X/jMtmlZfxxfeg2YVIut7697/EBGpxsLnMspCO0MVWdzJXS810wiY9SzsZtt
         yamdWiF7+dxsHvL5YM2l9pXFzLMfoZi60e4gQGWM7G9S+Y1YK29oPQEv3EVddgCXBOJ8
         6PnuDtyuqQqvnD1V6kkhPgFZIQzOmdxUiFbpYKj6LeONO1XMKJtuUweyJ006kyvWPRbM
         Z28MIjKgkMu6VzaLsCn5X1Y6FMC/WedUy1O7mMKECiTlep2go8jZErJ2rS86XYBhaCAz
         Hrrn4y7U6Eja4kBkCh+eFn9HqA3/2gX0Em3HTUXZiELucv7eiWs3dWtkzu4aoB35PX5p
         DQaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533W6HZskzy3RjakqgROGLbKWUB9/1RT7MufBpcxEx2VzQE146Kz
	ZhR1Nlq4SoZgFDHAgMa3zso=
X-Google-Smtp-Source: ABdhPJyXTdSvHFJ+yxTnJ8y8udon8JyeCsiLpJOqMRraeFWELluNTqN0ZECt2O1v9Ls+jaQ6f3JiCg==
X-Received: by 2002:a5d:58ef:: with SMTP id f15mr128110wrd.108.1640037741956;
        Mon, 20 Dec 2021 14:02:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls1074922wrb.2.gmail; Mon, 20 Dec
 2021 14:02:21 -0800 (PST)
X-Received: by 2002:a05:6000:1869:: with SMTP id d9mr98408wri.231.1640037741319;
        Mon, 20 Dec 2021 14:02:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037741; cv=none;
        d=google.com; s=arc-20160816;
        b=G/p2YYXcYE7wm4+h+3tb1Rl0vBolHWi7q93WgEsvCEplBci2Om6yo7wfV7HmBt5Y8f
         DFsI3NPqqBiEQLQ2oOuzetGKr3hOXDeLpkVlTAfNOF3STBdtzh637TG+CsuX1MGE5z0V
         cJ+IM0NMFF3nPULi0D6PMz0EW3lvj74gEQG3wjRbO63l9USOWDgv/dP5yaM97UZrkHUa
         LJSue6QKtBcDFOGmSFl/46PZ3/iFm2a6/HA962EwNfC179Jqj5cI0MgXPRAmWx1pEDY+
         GzBRmfOWdju4UeM3Jmcn131SujphshkSdGyD8ShVaTPhkFewr3c4WqZi0TWYdpdhhSQ5
         YjqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lgqujwoixk5/zdATKZ/Zn/56oW8wMB5cacRc9FCqpKE=;
        b=q0iJPjI/itpev6K/AgEcG50zertHVAd0gt6HMGs5UCLyXHAGr50t3ppFXTianB8CWt
         WwDVQf23qjS+e3xukfAPaP6evz/w4TQHZeSm/nlxInB4MyJ70JfDNTOM9L38qOA8eVld
         BHEusn2y4JtPaTYFTXPDEezcsbyL2CVuc2MZ96fDMX7fsPq6UXE0o04wuqFlwnMeDL+m
         q1YjEYcV/lBFiN/l6WVnuZ6TjQ8AWgllZTJngyP2SWqSLn8cNjcq7iInEDiywQubOSr8
         ara3aqGVj23/R2aJ57rfQI6x3rWQfhzHsQDOKidp1DF3cfLVebsDwBT88XvA0CS+Q/5S
         Wo1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rFvsj83q;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id g9si967178wrm.3.2021.12.20.14.02.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:21 -0800 (PST)
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
Subject: [PATCH mm v4 28/39] kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
Date: Mon, 20 Dec 2021 23:02:00 +0100
Message-Id: <73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rFvsj83q;       spf=pass
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

Changes v3->v4:
- Only define __GFP_SKIP_KASAN_POISON when CONFIG_KASAN_HW_TAGS is enabled.

Changes v2->v3:
- Update patch description.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h            | 18 ++++++++++++------
 include/trace/events/mmflags.h |  4 +++-
 mm/page_alloc.c                | 31 ++++++++++++++++++++++---------
 3 files changed, 37 insertions(+), 16 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 22709fcc4d3a..600f0749c3f2 100644
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
@@ -235,21 +237,25 @@ struct vm_area_struct;
  * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
  * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
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
 #define __GFP_BITS_SHIFT (24 +					\
+			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 414bf4367283..1329d9c4df56 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -52,7 +52,9 @@
 
 #ifdef CONFIG_KASAN_HW_TAGS
 #define __def_gfpflag_names_kasan					      \
-	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
+	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"} \
+	, {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,			      \
+						"__GFP_SKIP_KASAN_UNPOISON"}
 #else
 #define __def_gfpflag_names_kasan
 #endif
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 2ef0f531e881..2076b5cc7e2c 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2394,6 +2394,26 @@ static bool check_new_pages(struct page *page, unsigned int order)
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
@@ -2433,15 +2453,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl%40google.com.
