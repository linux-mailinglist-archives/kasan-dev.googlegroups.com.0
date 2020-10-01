Return-Path: <kasan-dev+bncBDX4HWEMTEBRBI6E3H5QKGQE4NGPCCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 655D3280B05
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:32 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id j134sf88112vke.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593891; cv=pass;
        d=google.com; s=arc-20160816;
        b=fE8gb65rZwvKFrXmxzcyS14CAT7uTQxJnCqUpNMrkAUmsGlqOY41GLsRZCfEnmBt9K
         ONd1bX1koEtaUuxUtVyWXd84PAyfr5TIIDJxNvRYdtS34VupPELqlEwZbnioZCo0G3oJ
         UMEEzKBarL56EiecEVDLp1u4d1l+GfAXWRkIxSFDKEj6T23QxKQXhjZAG0IKwtmbht+P
         KIj2uTanv8UQPI486tcI/Eo3owMapMnNardoFdeNtMU28j5ITnsvkq0C1Y6A0z/e+Tel
         BLpUXyXEpe89b80QA2g96z5Hz+P/itSgFiE7RVd62+YOSqFFOna8l9ES5/X7TwY/rLxv
         v2tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ltXOzUYthA1pCxeqt6iMzwSF6LvkYF5fLD2sbiep8sI=;
        b=DYyseGJMiC8YzIIS15bLlJlBChsOeoOU2jYEx3JN22bU2DjPUJaWQoppcCru52yFYC
         C6Kvlp3YE6jJHFXvg7WCYErIrGvLO6vsh6lH4+gou7rYKhtPpMpin0huIFZWnbYyax2l
         8mCNraKH1r5dFvR5okRaFx1oO7fbriIOCZKWReLyCtnQZ0Rnz6csIdq80m6ECCMs79dV
         J6VWASWSuBw87G6wnQM4TcGEJeLNOxV19Gw3wR7GnRhzCc9hB6pQBgjjlBnGXAoqcOGv
         c/HTPgN6YXtlYeVfiUsCdaRgL2lkhKseR8Lmv/XQSkI882K8q1C/dEQWzifg7MG1kzL/
         tMpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ghn4zmqc;
       spf=pass (google.com: domain of 3imj2xwokccehukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ImJ2XwoKCcEhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ltXOzUYthA1pCxeqt6iMzwSF6LvkYF5fLD2sbiep8sI=;
        b=Uem33ZheCdQC88+w2eCWIBQwMt0HXrzj4me/4R2JKZNtZi1INSXzC8oscDqE/Ika+Q
         s1z6ZHxeKZtHOKG6OevjzdEPIaa5qzZULNtpvFQjsOLSfj7s/tsZILdGtYNZPs5LGyZr
         Pnt3n5FKPcgkMMToiedo9ROgv7RjEZi2Q6sgFNk45g/FwLn4AJBdRF86o67pdb8qjmsc
         nPE3i/fySWwu33qk0THEzXF5odFPT1H31nhBypVZpBPD1OA82DIKtZp08FsQFB0qNi6i
         Yb6avN+1eCEgaSsw8FU+o6x/ffMnkntaVkCe2Ips9/eY4hxYG9t0+fAmPVfHU3vQVbun
         rzYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ltXOzUYthA1pCxeqt6iMzwSF6LvkYF5fLD2sbiep8sI=;
        b=N4sAahZ8EGXCdzqVnggVv/Ua1SkJxKb5gn0UgMI9uS5CbgjDHD80sRHAgibPYP8MLN
         Pml8fEOSdR/bdCf32+o5WtY/drJb7npQ+QuFZlYpXKyE2ie6s8yhW4QS/DhrbZYx8AHs
         eqk3aV6ZfGvXDVSCUPNHTTASYIQS8Tj3Ep/5HIdpBKBdefZvOXR/PKEzv5qUp7V0I7t5
         JSzGBQWA2NHpquVatZBK9n2qtulzSVOK28dNX5KfnGBZA6s/akHVUkWXc5yn+lZMvOYU
         JM6FZcGy9JbMwM/oRbwvGN/oAs9EObvyUF106/SwPxSjjWU+iyYUKhOkCAOlZzqAI/wf
         0cbQ==
X-Gm-Message-State: AOAM5320uODm/PXmS2PNqQIvJ+HkbymmpbSU3lXAnp0b2+j5YUWHM32z
	ETMmjrZbAwzzTyGz+DYJkGI=
X-Google-Smtp-Source: ABdhPJyDS1ZxT444Xne56+a6NvFjVQOkzycTT6x9GwZb91BVbDuUXpYTvs5fSWFSrLFhrLN3a0BaUg==
X-Received: by 2002:ac5:ccd3:: with SMTP id j19mr6932572vkn.8.1601593891435;
        Thu, 01 Oct 2020 16:11:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c899:: with SMTP id n25ls385561vkl.1.gmail; Thu, 01 Oct
 2020 16:11:31 -0700 (PDT)
X-Received: by 2002:a1f:b247:: with SMTP id b68mr1469731vkf.5.1601593890962;
        Thu, 01 Oct 2020 16:11:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593890; cv=none;
        d=google.com; s=arc-20160816;
        b=N15+9yzrfZhkO2mgomtFkNnnKCm7cj0qheVJ3U3fReR8cz5nah/4uMHhtkjW5PRQyC
         6l0tKzIJOgr7D04z8Cbbh/IADCzja8FjlwDow87+6s7jnnEJ9KQ5jQ69L/wzbUoc8ez0
         qLpMUoCUl1roNmCzVqZim2hSP+R36V8SNYKdgbYyi1kL/d62kz9ioBw/AMv9OaltmOja
         d3Wq9O/qq0UNjdD+cLw10Z3lV5y0GQnVNagWlnDwvXslXuvJd5UhILuEJIO89dfJt2Q1
         SwW9xLvC9mRLQR4cQmGBDiGyJWtyM2PxWV9W8xwGG0TxBdI0zT61rlGKK5lBBc8IYjyS
         bNIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=4j3fVIkcNaRRMYto1Vw/oa1eSdu7boUQdMon3zhrkTE=;
        b=NMfdpy++vdqg9S+YewuaHNgg6Az6fs9vsWP7OWd7U5oQMr7kyzkblzqr5Tc3IYGEFL
         6BVeWNdgc75R0CILnBpvxLoexouu26lRZs3kGgHpfbQtfKdGbQDx7iWvaodEM4fAmD1f
         bVpRyVB2ZeZjcHhapnP9HH0w218P+70nyc8OJXDnvedWKRhhITKNZUwMaI09BziT2hCg
         wYNiZWb4jytimUXg4yqA8OEWTQPGzghF23hTtLr26NwpeFVqNVC+1p+g0PWBCSAvUQbH
         DRvP8DR6+tlnzUpq1h3u8WuLkSs3LQIj2Z2ubygqXqitI1tQ4MVLD2oJyP5wafadNSyC
         a/zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ghn4zmqc;
       spf=pass (google.com: domain of 3imj2xwokccehukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ImJ2XwoKCcEhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id q10si20990uas.1.2020.10.01.16.11.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3imj2xwokccehukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id w126so52319qka.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:30 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5653:: with SMTP id
 bl19mr9568120qvb.7.1601593890546; Thu, 01 Oct 2020 16:11:30 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:20 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <53f9771734cebbe1ff0be648d534172c05c56db6.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 19/39] kasan: rename SHADOW layout macros to META
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ghn4zmqc;       spf=pass
 (google.com: domain of 3imj2xwokccehukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ImJ2XwoKCcEhukyl5ru2snvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
these macros. Rename "SHADOW" to implementation-neutral "META".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Id2d836bf43b401bce1221cc06e745185f17b1cc
---
 mm/kasan/report.c | 30 +++++++++++++++---------------
 1 file changed, 15 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 67aa30b45805..13b27675a696 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -31,11 +31,11 @@
 #include "kasan.h"
 #include "../slab.h"
 
-/* Shadow layout customization. */
-#define SHADOW_BYTES_PER_BLOCK 1
-#define SHADOW_BLOCKS_PER_ROW 16
-#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_BLOCK)
-#define SHADOW_ROWS_AROUND_ADDR 2
+/* Metadata layout customization. */
+#define META_BYTES_PER_BLOCK 1
+#define META_BLOCKS_PER_ROW 16
+#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
+#define META_ROWS_AROUND_ADDR 2
 
 static unsigned long kasan_flags;
 
@@ -238,7 +238,7 @@ static void print_address_description(void *addr, u8 tag)
 
 static bool row_is_guilty(const void *row, const void *guilty)
 {
-	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
+	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
 }
 
 static int shadow_pointer_offset(const void *row, const void *shadow)
@@ -247,7 +247,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 	 *    3 + (BITS_PER_LONG/8)*2 chars.
 	 */
 	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
-		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
+		(shadow - row) / META_BYTES_PER_BLOCK + 1;
 }
 
 static void print_memory_metadata(const void *addr)
@@ -257,15 +257,15 @@ static void print_memory_metadata(const void *addr)
 	const void *shadow_row;
 
 	shadow_row = (void *)round_down((unsigned long)shadow,
-					SHADOW_BYTES_PER_ROW)
-		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;
+					META_BYTES_PER_ROW)
+		- META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
 
 	pr_err("Memory state around the buggy address:\n");
 
-	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
+	for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
 		const void *kaddr = kasan_shadow_to_mem(shadow_row);
 		char buffer[4 + (BITS_PER_LONG/8)*2];
-		char shadow_buf[SHADOW_BYTES_PER_ROW];
+		char shadow_buf[META_BYTES_PER_ROW];
 
 		snprintf(buffer, sizeof(buffer),
 			(i == 0) ? ">%px: " : " %px: ", kaddr);
@@ -274,17 +274,17 @@ static void print_memory_metadata(const void *addr)
 		 * function, because generic functions may try to
 		 * access kasan mapping for the passed address.
 		 */
-		memcpy(shadow_buf, shadow_row, SHADOW_BYTES_PER_ROW);
+		memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
 		print_hex_dump(KERN_ERR, buffer,
-			DUMP_PREFIX_NONE, SHADOW_BYTES_PER_ROW, 1,
-			shadow_buf, SHADOW_BYTES_PER_ROW, 0);
+			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
+			shadow_buf, META_BYTES_PER_ROW, 0);
 
 		if (row_is_guilty(shadow_row, shadow))
 			pr_err("%*c\n",
 				shadow_pointer_offset(shadow_row, shadow),
 				'^');
 
-		shadow_row += SHADOW_BYTES_PER_ROW;
+		shadow_row += META_BYTES_PER_ROW;
 	}
 }
 
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/53f9771734cebbe1ff0be648d534172c05c56db6.1601593784.git.andreyknvl%40google.com.
