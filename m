Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYELXT6QKGQE25SKSRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 53DDB2B2816
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:05 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id e25sf4859603ljg.18
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305825; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwDi7ylUtfY4ml1zp8GVnYWNRjFmjXj8i1Jot+9mJHHJMrSjZPFSjRHLtyM4xor9Qe
         PkRKLk9kRfLfbenBiLLdGqlAJ7ilwc21IPg1dib9C25pTDenhPE/qMrA0/tPiG+ju/I/
         hMW5H+Fqpy5DO2p+8KkeaZSX7bYiThTfUvXslp06tNIi0mjDUItGtNYDHOVzn+MtBWa7
         A3l+2QHoNvatGZb8NEnORrZIrD2X2VVpiLGmKVjp3agFWcxoJoF2X9UH9h6VsnHcAdGW
         GhcImhiGH0s3FALHAAE+04keqIy4NFOLJ0e16qM4dzWo8iDUlO51wJBFFihqu8TVQuC1
         wyww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=knfa8NtIJTUpH/wwRM3y1saYvesqKCWaQYuwFqnLIWE=;
        b=hOP1ybtU0m8BPUwIHO8zzaJnKXBGGLvrImzP7OANItR48n/9vnQ5uPgqDlWZgPdFWr
         +fuHrR0BFozDLeIWncT3dYOD7YqJ4Aw3ysLB9y/pbkjgnzxDNUO6pEg3ZZX1PsWDIYmt
         +rQRKw1wBdhZw8+VqfXSRMoyax8P4Ez6l6ksKNkeMIQlppmgkquBFmoVTBwpKj2bztNu
         +W1KvHOfdF1EPMhCfeZO6Xm9TshFTZseQPZXyt2zEl5gGqIOj0zhSS1D//yJvDT088xL
         pHjVNkIo7hwzvrHg6WoSgh8bqcC7d7TVes2RCE+bltE0XczUDaq4DQ0DHBHPdiGFt7/j
         3Lkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cFI3+DUN;
       spf=pass (google.com: domain of 33wwvxwokcaokxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33wWvXwoKCaoKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=knfa8NtIJTUpH/wwRM3y1saYvesqKCWaQYuwFqnLIWE=;
        b=m+3PutkHghzVdOkdW0YJSID4R9an4MFWHuPYUbyfakPSp5fEy7DT/Zshu+JYq8ivbD
         2IgrVtCsSlbun4V4yO2stv47zeJf3izbRZcI/CTzJaZOA3zBdtW4tzKIcoYjL4/JIfBW
         IZhaCK3JXPEJWEFY0L+9Hy0bgBdh6i3nzS2zRvXYWrn29LifhhypAoRcWGv73C52CgA5
         b9PtrB+DGh4yWmwEGZpnWx5iFYF8PGdBAzKiCULzIQV5mR5hNCUTZ9InIjIW9gQbJ7Zr
         oYUyYu34DMWgGgYbfYR5EKIaVnvvBg5cLaygg2Uww7ouoAcuFmwppuLSBGnJCB4OaEfc
         FkXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=knfa8NtIJTUpH/wwRM3y1saYvesqKCWaQYuwFqnLIWE=;
        b=jeKjYpllosK7QiElhbWeTN4mExEl25M8ydZo5NZlddW9hgGR4eMuNHXywHjtwzfuT8
         rNQu9OYQUTUh6gioYSYwF1SF56eF+mDvjS5qDvxm84tH/wq5hu5J4r/adDC7BhspTnVu
         Sdr8JgI3tnx8OkQnAfT2dEx8L1ukbXRWwr8FE1W0WYaiF5zmu0BLkLXhDzoxdcLW4R8P
         HIoYg3Z2GyGPq0LuzDJfgTN/mAXz8mGDi7CbpR+WDiP42vUasIDKWy9I1dqqVYW+b58c
         HWpGQPRzWwnqcO5mTvB65mU4+FsqxOnPEXkF+sSnz3yq9DQj2ULFfGDm8X8WElOwz4JA
         XA1w==
X-Gm-Message-State: AOAM5338uxamOzKe3AHh0zR5QDifosQlEUhm7L5QbzxInhPrziBnhcOX
	GoMYuap5cDTCBCrX4TdxO6g=
X-Google-Smtp-Source: ABdhPJxkEHPRTG6/PWPFPqDv+FXkkg/3PWH7AnQcDoI8bp59WDx5OPbRx7MoepqKJXq9IQ86gzT6OA==
X-Received: by 2002:a2e:2419:: with SMTP id k25mr1779523ljk.422.1605305824910;
        Fri, 13 Nov 2020 14:17:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:914c:: with SMTP id q12ls1496359ljg.8.gmail; Fri, 13 Nov
 2020 14:17:03 -0800 (PST)
X-Received: by 2002:a2e:9616:: with SMTP id v22mr1810929ljh.120.1605305823845;
        Fri, 13 Nov 2020 14:17:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305823; cv=none;
        d=google.com; s=arc-20160816;
        b=uImXKMszULXcR09C17gXpQybYLrmXXdmRh83tyqL25j3pAIumcK7FDa7KkaY7g1AtP
         YDDaNLABXefioyuwiXF9hdAc8wmV9HOKxJeWBSfuX2OV+roRVTZWROAVUpPESlzsxRd5
         NMolZR7A5DR35qe3TNtSJRForh8gkTq0zYCuGPJU6Ar+GNy0g9zxC+V0oAckXcvbPtnW
         8lSyo0wKY+shZuPQPREBAECLGuHTM7crZa2VAeiOIzSzx/uINsthxj+kPfYdZdxDj8jc
         gRNKRpH1CAjcQP0X0s6mWVoquxjzr7x3gVjGWWj6J4yNOHcmHZNT6WYTcjPF/eQ3ixnR
         COVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=QYRwj45esNxqkksolgMCeqJEQQGw+HRSTbdJ2ZvWQ1s=;
        b=vwabCp/fEV+17ANJQu6oakiQ4Kz/nuViydYhioBd6qtwKUHGYKULu4qpc1vMdJlQnk
         qKOSMDK5mftrEvqsnbg7qrz7BZafG/2WWRbn17BxBgnsmir0q2R6tM1GXXCRIJxFZOZP
         akA4CtEEWDIZoAihcKy551/qk7PCexNpll4x2E2+z80MjKVeBWSR7ggPnF7mTYc/GGyV
         vjDBY0es71JuPXEuvN1TnAadUA2SqnLTfAhGRIFFXyEkPxgpni9b4y6WeRpEFNr+wrs9
         UYX+K5oY00MuX8kDAoyu+VOgiOjeWCDnlXWFDybWXy1OlX/RfTxLHJskxVgdwgYfH/Ao
         08LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cFI3+DUN;
       spf=pass (google.com: domain of 33wwvxwokcaokxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33wWvXwoKCaoKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id m18si350895lfr.11.2020.11.13.14.17.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:03 -0800 (PST)
Received-SPF: pass (google.com: domain of 33wwvxwokcaokxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s3so4713538wmj.6
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:03 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4302:: with SMTP id
 q2mr4664612wma.182.1605305823252; Fri, 13 Nov 2020 14:17:03 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:48 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <34062aea525fd3eda186646689d41dc74accd852.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 20/42] kasan: rename SHADOW layout macros to META
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
 header.i=@google.com header.s=20161025 header.b=cFI3+DUN;       spf=pass
 (google.com: domain of 33wwvxwokcaokxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33wWvXwoKCaoKXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Id2d836bf43b401bce1221cc06e745185f17b1cc
---
 mm/kasan/report.c | 30 +++++++++++++++---------------
 1 file changed, 15 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5d5733831ad7..ab28e350bf39 100644
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34062aea525fd3eda186646689d41dc74accd852.1605305705.git.andreyknvl%40google.com.
