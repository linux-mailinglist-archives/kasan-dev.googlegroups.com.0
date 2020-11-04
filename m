Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIHORT6QKGQEPOZYB2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 29F832A7131
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:01 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id r83sf166438oia.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532000; cv=pass;
        d=google.com; s=arc-20160816;
        b=BGanV4GDSRATWcYzSAseG6MaT4juON3fYiGaUOtE73xRzudS5v752V9wcmQMlFulef
         ryWYllcDB+aF3MyYitj0okjvAPCXhwOhsEdVBc9S7wYIKWrj4bJYuPVZsjuyz9IZ++nw
         Cq7x2F1mNMuZOk+IqaLL1o3sm6CJvJjN1GyJGEVFyn0ZBgxcLuPulMmddCJ6tmhkoHFz
         S4PJkXDZPuj/VszFRD4g7dyCNkVggpEyNFEL+vmMrzOa1L12IcRDRBe51f4OXQZkHIsJ
         Q4H9fsq/bppNNKKTBmOofPkez/yCEHWj2KE3HewQJDv8Cz+LVx0qfyE/5bxSLz45ezaN
         2p5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pMHlQxIrJWKMGZRgh53Wc9z04E0szJ20NdS4QAWqV9g=;
        b=xlux0wJzZsjl4aAZ/NgGSXzEXaEJcbN4H/p27F22bD2CnWYTEc/VEmDIN3IFPLoL6a
         Qph+rhBBVxAF1axIjDVAE4DWCHiWhGWPUFx9cdvTDoQmrT6ApNBXdNVrJqfQUx9rMEmF
         HWsDNmDFG6ZamLDKvNNFthRQtl7j73lKE/sCexboHXBRBK17fYgbVjUZP4QMKyx0rn20
         nzVZsobOjCA29uQ9VD6FDDdUcFfj9Xru5ynG2FdOc2r0DvVcDgvGGxvJOkWlb20ama70
         aRFqEEGCpIiaQlT7vHd0BuYeyzGuGzN/aVrAk86wpYQKU5H+t7GK/sJp2TvSzG7EkBVQ
         P2qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ZSx/SUZk";
       spf=pass (google.com: domain of 3hzejxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3HzejXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pMHlQxIrJWKMGZRgh53Wc9z04E0szJ20NdS4QAWqV9g=;
        b=l5bAYc7iwVfkjLbllconekJV1ZVWATa5bklcXUrNhHkDFHyEh5BHGRH//JxzEfVbtJ
         f3g0XrUOGEil0WvF315ltcm0dgzUUs8FoEeSRuJth6g7Bf6/hrJPJV/djTUFLeYrn/hO
         AjKIpmJqpMuJ6DyqSUl6sZOIztslxUYFS7F8Kk4jd2wkf5sRhiqip+ET44UPNtQZLOHJ
         N+xozIweiCVhBfAC29meugpCOvCBi5+UUcFW5SHL68nn+zVO/bdzNjymwrfVHoQe1IFE
         Zz7c905afAZ3e5hI22LsRFoImk3qbFbLIZVj9sWVTcVGNW/VgCFLeExQqkmeblT+qrCR
         D0Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pMHlQxIrJWKMGZRgh53Wc9z04E0szJ20NdS4QAWqV9g=;
        b=Uuk43A2Czivo1C2ogFYLwO6T8UuUdYnCGly2fdLXXZjK+dTzfYeuBMxZzTmXq1csdP
         CM5QzKnQYmeGAXpgLhegCVyqgR0UVXL0ab504PA3tSUBotMwd54o3Hx9lok6GdAc1D8f
         F5vrQdBFavMSxLZa+VlyaDMulw82apcO56QcBd1O8YUbk54rXyeqFKYgHukd1LcpgD9N
         GxBe94N6sYicXdgS3El3bFK1Ahm2UoAw7BzFu6aDakVTdaPe7UA38scwWf2PCl2UnBwh
         2eKVHh4mvV3a4YUJvPD5FOknnjdd6rJnJayz2042abU9mIkPD3DTpV60G5VLvBiW7ndR
         OMUg==
X-Gm-Message-State: AOAM533jxWVs3My6stLX1ydq/fokpySKtp2YoUz4SqkWTt0wMZvUZrhJ
	9QizPu6fOuxuHhg8SjtaaGg=
X-Google-Smtp-Source: ABdhPJx5z8cgM6TXZGFDFroRWPc/bQ3AhLGZpLJu6JK6Y+P9CV1wnWbNuC6vUfwEUvKQ6qvGC3ZkrA==
X-Received: by 2002:a4a:4203:: with SMTP id h3mr396718ooj.0.1604532000134;
        Wed, 04 Nov 2020 15:20:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b784:: with SMTP id h126ls1001317oif.3.gmail; Wed, 04
 Nov 2020 15:19:59 -0800 (PST)
X-Received: by 2002:aca:cf02:: with SMTP id f2mr98115oig.87.1604531999745;
        Wed, 04 Nov 2020 15:19:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531999; cv=none;
        d=google.com; s=arc-20160816;
        b=QAMI4ajs6JU2MY54teXde2KLLKT0f7v0g7IYF5/I/X8jLTrC8gUmQH5QpbnbJnA/r5
         PovWLzStc5tHsRRdL93AElpyf5mWvMbeL6AdRU4Dt6GkbMa8U8kVeVLbr03VYjGpdIgH
         kn8r5dbQbPtVc3DfzsxJgkueudypXm2cZBJALF+7FprTDZvhqTeKLXcricbOwAyATNQJ
         cfT17TgeXFqTMuBIfQfediwBwLNQhVbTD5EDAcaABN1hlJr+GBkxoRoXvRDXXeWTXGx3
         4lqLKUhJUiMVSUWzTzezL6hleIEeFzmgqMWkQu+BAWED4Yb2B16HWFAihG32IN+W9elX
         G1NQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=85BahkB/ARH3bXDyEMCLh1SMwp72o82khunrv9SMNJc=;
        b=ZuJUbMxaTO8Uv4UPL/6OM4spa7vK2wlUqx/zBwoqMD6zVZcnu8WEnGffsanvk/Zcxn
         OHKCFfFJjFxbqMjprTvf4jXZ71HyzjxqoRsIxO7wumpsackTBADjRC8X14vZD/55Igmm
         Uu+SqyiOE5U1DJUIdrR4Bu0+nt2h/3PPm01qwDQkA2NLoUvRX7qtl5ks6IHU8k77JaTZ
         Y9wiDKuzWfsg51xZ4MzOiZj37YnUazoVo4ZgtK0TqE5fWJ3VqRxGEUP4ECs/iuUpiRIG
         nkulVmNK9EawE0dFJNynlsB7HJtSERNYN2xHlS9Uzsphl6hS1w4bvCDpNwmZ2taFgQha
         3E5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ZSx/SUZk";
       spf=pass (google.com: domain of 3hzejxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3HzejXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 104si234617otu.2.2020.11.04.15.19.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hzejxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id i2so14608863qkk.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a8e4:: with SMTP id
 h36mr421233qvc.24.1604531999270; Wed, 04 Nov 2020 15:19:59 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:37 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <5ec82ee9aaa25e2f15ddfbe292632de1d78b87b5.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 22/43] kasan: rename SHADOW layout macros to META
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ZSx/SUZk";       spf=pass
 (google.com: domain of 3hzejxwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3HzejXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
index 594bad2a3a5e..8c588588c88f 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -33,11 +33,11 @@
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
 
@@ -240,7 +240,7 @@ static void print_address_description(void *addr, u8 tag)
 
 static bool row_is_guilty(const void *row, const void *guilty)
 {
-	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
+	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
 }
 
 static int shadow_pointer_offset(const void *row, const void *shadow)
@@ -249,7 +249,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 	 *    3 + (BITS_PER_LONG/8)*2 chars.
 	 */
 	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
-		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
+		(shadow - row) / META_BYTES_PER_BLOCK + 1;
 }
 
 static void print_memory_metadata(const void *addr)
@@ -259,15 +259,15 @@ static void print_memory_metadata(const void *addr)
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
@@ -276,17 +276,17 @@ static void print_memory_metadata(const void *addr)
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5ec82ee9aaa25e2f15ddfbe292632de1d78b87b5.1604531793.git.andreyknvl%40google.com.
