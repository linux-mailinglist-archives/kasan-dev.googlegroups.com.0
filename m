Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJET3P4QKGQESAWFPNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id EACC7244DCB
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:05 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id y9sf3945266otq.8
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426085; cv=pass;
        d=google.com; s=arc-20160816;
        b=TOXw50Rtfe+kXYfeV2/xszz64x0/q8PwhtLqkMpt5f6+annjShPNf2VYFNXX9ZA7TH
         /Ww3pLH7BGpcLtqx/8debfb2W6pvBLIhZd3mn0AHJ8C0qa3ofONi7JdtzgASPqdfwT3D
         GUSfTYQsGSM0q9KQ3GA2vaeuzuukRiGBH2uJqGTZsdx+3gKU85Ko8z0OEyT4LjJ8tvPt
         QFR7IsCm3Czvbzp7BxvRmyOOMJuM2GcCZ6oTEiiXLWpDk46KDTSARpf54IjbM6OEQv5X
         mEPr5bgioxQ7XW2x0LmOePRupJICuf5lChwciRLe7QXuNH+AxDDcAOYkzv0MlTG6wfAO
         gnHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iO3JPzAfsBzDgI9hzrlbLlk/ROhRrPQrSOCeGhHR6Ys=;
        b=oMaVhy/5795Z5V0kVFh//jGAbMjC+5TRUMAZEa6SSiEDb8y6qcgGSO/HcQ+ClbpgIb
         xDrHxbGNwmqMbhcnJ365xoiN4v7WM+wMhBvIgETK/Ht63byb+GYCcyUyUEYNLGMJlT4t
         iqp3C8M5gkQfSF90nKc6CrlkgK4H6LJ/dU15DyqN24o6YeZziUk9x2ewF+iJq1o9f7q6
         C0TXZFJIgWY/ZI46UpoE3TYorHT18Kb3ep/+j2aaFYX7m2OqfjZJrj1m4FiSV7b77TU0
         X3KYaGsY/spPOhq3uYAXPbmhK6gnDFL/28yufOA29ZKsS88Gla/mHu/MFQtdQfSZPjn2
         8WDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ttJgaF/P";
       spf=pass (google.com: domain of 3pmk2xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pMk2XwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iO3JPzAfsBzDgI9hzrlbLlk/ROhRrPQrSOCeGhHR6Ys=;
        b=NCC7tU4LqD1OSTjGw5f0zEn1smwwcalrJXdy+kbv7DgO8ld4dUfR7V/39HqMHvnleM
         L/tnuOmi9bzNdBarLbgtvzP62s1cILsVx/jEesro4tqNH012bcQl2+0Kx8QEhxKG+yC4
         ETVdQ2MetYfoItbHEivBOJJCrTg4ai3wtZRmFzmw8KKgld1aW+D8VCQJES69ppDhN/M/
         zjopm8yeKDpakY5ISQjt3d9XMLCj6Ha0h/30jOA97t5cmlGGwImye5LlUVblP8oGUs6i
         AoP3jYQc5C2r0dMPrZ9mv5ubymSbUFRbodiS4zn9WtzcNCnobbD5BpuMTloj5l+RVyGL
         dvSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iO3JPzAfsBzDgI9hzrlbLlk/ROhRrPQrSOCeGhHR6Ys=;
        b=NUcL3D4FoEKifhenI5t9sT/gWq5+YrSx3KdeZ2/eQA3kkHWqce3SQEM07B+DOmF80R
         EK52v0gwjJOnJO23339shJbjwxUJypVoKcbnxeXshi/bAMsTxl88QOtTALs3EBWnuuCu
         6I2mj/w23Y2Li4SmEQYanXi0vsIfdVfHhNwHQFwELvjRUuxol+jcIuh0vz2M6VRCXMxA
         fYRTyZwbEHgD5P1M4raruBbR0cdyrLzMhLC9dW+L7Gem3FXYlSvA4KBSrEB0SIp3WpRb
         953I6O2v1nP/ySV2pa3Fx+ZzAcQ/C64IDEfIKvOE2Q8LR90ia62xZXBq0T50lNFDiAQV
         ljvA==
X-Gm-Message-State: AOAM533rFbtr3fe+LGeP3LPk/GBrP6dWkOJHA5xTqH+FnI8sOgf6TYOL
	CUSjGy6wIp2MXaI86y7Q7Tc=
X-Google-Smtp-Source: ABdhPJyZfXDHl4VHKql02RVRslxae6FnZs69oyYN2lpr9hAjmYAMj0IMT/c6XtxpznMmmy93qAlGzw==
X-Received: by 2002:a05:6808:1d9:: with SMTP id x25mr2114375oic.92.1597426084911;
        Fri, 14 Aug 2020 10:28:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4404:: with SMTP id k4ls2011182oiw.8.gmail; Fri, 14 Aug
 2020 10:28:04 -0700 (PDT)
X-Received: by 2002:a54:4518:: with SMTP id l24mr2291696oil.8.1597426084614;
        Fri, 14 Aug 2020 10:28:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426084; cv=none;
        d=google.com; s=arc-20160816;
        b=EfqOQoS5WejrlG+XhMLnIffONgvLX/9xunCekSkIVp6PEXKq9tkqoisECUXGDmm2mN
         5ZoOBGzw9sirMf8YMMuo0Lbi2ZTvP+lr89ksPC/Ljsun+RGu/vsKMePaw/5fI9ODLshE
         Qqr4W17lfaSYQYKVi0A+TFTX0qSYxjJZfhiXsmCD6mRHKAzjY8t2DDTRm8jegx9KSk3/
         JJF/d8tqc21YVmOiYo2AhxatLmCFfO20brDtaPb8eI+ITUyiL6SErV7F3TC03mS/XLEU
         ccvhCRcJZOuPaSy9dXiRg90zzhHJmNOi490NW8sLdJcMfXWpNss1L75j9aDP9xMRHiTq
         FSlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mCvcC3dYzcxUwc7C0YdRc21YWrhNGjweNe7or4+XlWk=;
        b=Nrnwk7ccTeGP2HoUMmj3Q3E0vOGUdsRTWEGqkKZj33TAWSpwJa/zibSP/LMV4kucCn
         mSvGB5Hf4Y7tCqIHjJksrKM8LIsk+vZBh7REm7nEA1o+QmHAdOGRiG1uYTAtXP5RQr26
         MSeCTSycKYZx0lOntkpLZIU+1YW1ao0d29f2Zp/E3mWBuuURMH/kopivCqnw8KebqDJv
         BCA+sB3kIKdHpECag86jwldcDMg7cPIBvBnt0Xn2VsHavW2t9KlG2YtdhlnO3OoayP9X
         T0WOHiI4EAl6woVH2Uaj84+tJx3R/UK4w2/chtuGVW3cF1fnUwCyL7M04DkIkAReTFTN
         XbBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ttJgaF/P";
       spf=pass (google.com: domain of 3pmk2xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pMk2XwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id u18si221380oif.1.2020.08.14.10.28.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pmk2xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id k1so7449182qtp.20
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:04 -0700 (PDT)
X-Received: by 2002:ad4:4ea7:: with SMTP id ed7mr3716612qvb.8.1597426084066;
 Fri, 14 Aug 2020 10:28:04 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:59 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <1142e2ec61dfc863a4ec5b92b60c97120957ec80.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 17/35] kasan: rename SHADOW layout macros to META
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
 header.i=@google.com header.s=20161025 header.b="ttJgaF/P";       spf=pass
 (google.com: domain of 3pmk2xwokcrmt6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pMk2XwoKCRMt6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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
---
 mm/kasan/report.c | 30 +++++++++++++++---------------
 1 file changed, 15 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 2cce7c9beea3..6306673e7062 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -36,11 +36,11 @@
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
 
@@ -243,7 +243,7 @@ static void print_address_description(void *addr, u8 tag)
 
 static bool row_is_guilty(const void *row, const void *guilty)
 {
-	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
+	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
 }
 
 static int shadow_pointer_offset(const void *row, const void *shadow)
@@ -252,7 +252,7 @@ static int shadow_pointer_offset(const void *row, const void *shadow)
 	 *    3 + (BITS_PER_LONG/8)*2 chars.
 	 */
 	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
-		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
+		(shadow - row) / META_BYTES_PER_BLOCK + 1;
 }
 
 static void print_memory_metadata(const void *addr)
@@ -262,15 +262,15 @@ static void print_memory_metadata(const void *addr)
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
@@ -279,17 +279,17 @@ static void print_memory_metadata(const void *addr)
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1142e2ec61dfc863a4ec5b92b60c97120957ec80.1597425745.git.andreyknvl%40google.com.
