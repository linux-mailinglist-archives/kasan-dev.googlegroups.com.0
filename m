Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUO6QT5QKGQEHAFZZWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 83BE226AF5C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:05 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id m10sf153217wmf.5
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204625; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vi3mehG0s77kpFzycOoMxhSdsCnL6V3Molpmn0zMBJ89Dl+m/Cz4GQmFQE5mxVyWxC
         polF3HcSLK48SpS8rm9tEAFYVWwmuIhCa0mmDqEsXSFQ4U5AW2T1+Oj/ENtC3/MVmMWY
         fOX5ZiMquOdDEJ7YvHPNtUEOQctBuCa7sCX0uxKbyroSwXzOWjJHfs21T2a4VGQ0pBhh
         o7nHOhMomHsZdmOfm8ahEH1cR2E+ogb9OyPx4TdYHt4UCXslyEvW96EyQpUxplctNF4/
         MUJbIA19VdZel4ltFsmwVfXGcsZSqPr+Gw2TY+YnvVA3yCemcrf20DI8wYMykxamfgZ0
         B+lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=TviAwObDq+eKNLUgF4MaH8pIFQFC4rNKbVLuArBSUxw=;
        b=n/aH89jDTjx3HiorWyxOhgd6SFpYgPdJR1AtmuCYChJgzyioI9eU82GAu06hGIW1l3
         MZdq7fLvBHMm2t530OBve9CWTdA9tHhyWoA+Mlo2RdfX7IccuaeRZAj054D6j6chFSFV
         Gho3kKOF0gzIE4pNRGUyOnbDGW3e35wl/gWAQPWxMRBpnOFwMRGJA5g2jorFb/kLiekF
         MVe0bGdeUYhlZUK7JGUp4irznAslpQRafTRwsCdg1Y6+9+2U4Evx6BTCu0aQkn5PmbFx
         UuXEq5Q5/bmlXKhuBDd9X2+gLswr9mncHdgSCqany+CU8zUoSJDLQLJtcD9Jq22y3HJ0
         airA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DmRECeLt;
       spf=pass (google.com: domain of 3ty9hxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Ty9hXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TviAwObDq+eKNLUgF4MaH8pIFQFC4rNKbVLuArBSUxw=;
        b=DNGg41k/KoxtynnfN13Bg9NYy581VHp4de2cpplETNX6Wl6OTFgaw3thREoI7rNfzH
         /H85gSkp7doXETWuauWx9W2O51Bz50IiTll4uAj/c6iVXyMSZIc5c49+GRzlcWkWNe7M
         PNT2TenoDuhB5OTEOk3v8d+gYqdHATngKdZH2Dww6McCFdD5mrlSCw1EcgJpekPMMns2
         74bW6T8MeEoit54Bek4wOLLLG6DkHKd5OFvvM7ttIRTYMkKoglk8nmvT7m+G+nJ1crw/
         vfN9MDFBONLAAJX9Fk1e0CkkFky3g3Y3SNm4E2Nsekl3bPWbWtFGKCKpt9w5Qgt/EZ2V
         mQyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TviAwObDq+eKNLUgF4MaH8pIFQFC4rNKbVLuArBSUxw=;
        b=YIeBq/ApyW2FZnGjAxvefXedXgShZzPjQPW/fF63oqB4uJUdZNo6UMTwgpYYDlqNSQ
         xZ9UvOIDvXFpecs5s31fm0JGAr7erWj2RmecDWtEsdWECVVCGWxBg1XCnUTVXLgt/PIJ
         +9if+GYLisV84z2jBPJ6d2yljIqtFHQpBjdSkoDkrOSjN/tj7LFLJ1BsNNvbjzMNcyJr
         ZS1y9Tb9AX2iufjqaA7NwVbS8Q/bdaJ4zMDfP/yWnl552NeUpHowaBNunqM3W4wptxHX
         nbu45T3rfCccJkJaRG+/+ZeXDH99CbowRn/52EfuMfNBUZb5NGwjIX+urZurcUdNSK53
         7zgg==
X-Gm-Message-State: AOAM530JwIqPm76AeEw3hQ2OZ070GjWO3IWGjJrM65UqX3jC9hNOn7Id
	2elVU3/KUNDbX5rvnbr2I7k=
X-Google-Smtp-Source: ABdhPJzMfblWD0t2YAe8NfZvoFCTcUYc/S35H9Hxgj3lekgPigkFwYj/tdWCVDAs7q8cxAeOJZ49cg==
X-Received: by 2002:a5d:4081:: with SMTP id o1mr24052398wrp.338.1600204625227;
        Tue, 15 Sep 2020 14:17:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:81d4:: with SMTP id c203ls102113wmd.1.gmail; Tue, 15 Sep
 2020 14:17:04 -0700 (PDT)
X-Received: by 2002:a05:600c:283:: with SMTP id 3mr1287752wmk.110.1600204624459;
        Tue, 15 Sep 2020 14:17:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204624; cv=none;
        d=google.com; s=arc-20160816;
        b=unRGhSgiHGi5xZsYwxlqIEy1Y5YzCA1LhCIfAkOV/SOJfG45VQ3lzlKNh29ZQjjaWI
         cuJ9yQMv0JCAdRU6GF3mT6zNaoONYep3QcEHp3RbbVCZSroETPnVhU1jCLACXkvjvUJj
         WRlfDFSb4Kryw9LmXcghPN3xUNjx7ylQCaAAG5WPTlHWA/Bgr0sT6knK70vLIYdOcZ8m
         K/9k0uFhgiW9lIoQzh5qG2+s0DVKWp8+qDn3EYL3c3YdkYn8mt//W0xRhF6DLi5Y0/N1
         R8T89vbW/4j7DB4OjD52o2G/NXdCuhlCETAmoFODvnx3oNQs8+cf6Dix5jhfsFvVLj9t
         FziQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5DI33wLk49GBiOtTKNywoiQR13ppWemjtswafD/fR5U=;
        b=WywYZCQPIVUA0bKBniUAZWHUv30aQrHl3MfYzOhcYhkYNWaoauUc2S3vH162PrcDeH
         DnFKR/dqUB7QjJD8lUvTh/Cbx0o5+fBXdoGhEQiIe4+5dej3LWpFU2YiRjGpvAdshSn5
         ShPRZ2O73KwqunrdkDmVIqa7Qav5vfFAFLp3rEBZzKpaLROyJSraFVsmoOVY7YLTQm2c
         2iXkizlhCUo8sHBipSIhSO8UFmc4QoMhcs1577z5lfYMR60tesSV+DZ0mn8auraw54xS
         ZwVFAPAW4Z0haXkYm84H+Kynb+DhV+vkXDiiX5QB65omWBB5Xqugc1Wp20sD+wDj340q
         uWWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DmRECeLt;
       spf=pass (google.com: domain of 3ty9hxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Ty9hXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x1si29857wmk.2.2020.09.15.14.17.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ty9hxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id i10so1706096wrq.5
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:04 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6343:: with SMTP id
 b3mr24815500wrw.179.1600204623954; Tue, 15 Sep 2020 14:17:03 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:59 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <3f3ee8faf0eb24b7bf6121a5708c4f4ac9ff68d9.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 17/37] kasan: rename SHADOW layout macros to META
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
 header.i=@google.com header.s=20161025 header.b=DmRECeLt;       spf=pass
 (google.com: domain of 3ty9hxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Ty9hXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: Id2d836bf43b401bce1221cc06e745185f17b1cc
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3f3ee8faf0eb24b7bf6121a5708c4f4ac9ff68d9.1600204505.git.andreyknvl%40google.com.
