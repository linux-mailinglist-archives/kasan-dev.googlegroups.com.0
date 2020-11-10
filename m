Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMFAVT6QKGQEWOQSA4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 173EB2AE2C9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:01 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id a130sf1670670wmf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046320; cv=pass;
        d=google.com; s=arc-20160816;
        b=vkYq1qXiSlNRK/1+JG0owZOrnVM59RUDErlNiiWEx8bFUsypONWYwNnfTZGyt9+me1
         alM7WEzEDPuJAABsijNPAwyXMTnlKiQNIQBVrG5RaDy257Waj5ZzZLF24we1EV/w8BQu
         cKptC1mLsCDSvfxT16WOFQxDR/2c7nD3+NXjQmfUVXFzBf9D2JReUY6bnMOwXAixwbpC
         CUOHbFGenleEx2gt2bmBi1cG4qSvJrT8EKqwxxEulGAaFBhhCB5FeqHKh2OLdxm2in/d
         10AR4J66JuDSzyJLZqfG/zJioPv+mkjzHZ6YYIk19gdMQZ5wH3ejFAOaqTkkXz7k8iF+
         kZaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=53t1k23Xbkm7wyykFHKKix93j1n/d7nbOv+dKaPk1sA=;
        b=wpycopOyp5JXSPVSBS0pXQkb1DTFVmwLvH8GUKQofE9G49FRBKt19ZYyCqduy1RbsH
         tiNAQInkILTNi6/a4zG6kYNiYN9AHHB9gfkbHFLzr8GxN8aODobfovh3tmZ2OPSjsxUM
         6OIyzCVJ9uYDwG7CVGx+Yn1W6Bb3Rn2VY2FF0jhkOznD9lDBZqMwSG5E2GiWODRVGKRj
         4XrG5G3Q7v7vennAitYIqCHU0i8fl34mSwSp4wlZCb2IX6SldhDIC0DwkYIFwEdUyExE
         ZI8xcUUchpc3k9V6p8bOnM6DPa4fJb4KIZOYbBtP5g/TfzVFtzeDEPChzv26GFbRDg5Z
         SIeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J2IH1uzo;
       spf=pass (google.com: domain of 3lxcrxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3LxCrXwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=53t1k23Xbkm7wyykFHKKix93j1n/d7nbOv+dKaPk1sA=;
        b=kMCohneiEZt6OwVP7kXM9bsZKOru38CRtJ9irYl+kD2Q7B7JdfURU4DVPMtOIPPawe
         tkSt9hlbQde43UhrHbIPZRmODryaU9CcEttGNXz3FeKVcgjVXnYiSh+ODKGGNATrYIUO
         FDyvUPOaIhLVGN19kGOl0aBS1SC3aED4cFxJ4ctK9cxcPZNLMB2LhfNFQawQQ2Cx1Rz2
         UH1PpVmIOzupcuARYXuYdS/2M5ZyvpQtJ5tqp34VoW9w1VUfqJURvq8Gu3VCrT8151MP
         DLusBRpnlR7LeDjRt9l0VvTHfzORwXFdoGklgZqPmUH8g1YjYD1CjeMPD2M/ulcVhrI7
         0rcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=53t1k23Xbkm7wyykFHKKix93j1n/d7nbOv+dKaPk1sA=;
        b=SZZrllLn5fm0oOTwL4KLqjNopWjqbKcbk/qW7BHVO1qnsjYQ6xJMU6UTbnANztj0m+
         7Su7xBhg5DtgaxMEP8zN6PhQWMj1zh4xhulmhMEdSqdLb2v087QuctWHaKx+SiLIPfpb
         KWi7pVH1X79tGOlbiLHLRW04FCnd2ziICdW8jwjUv2CaPaAVA3Eo7a+MMlUJF0WkvtT2
         mgFIrkj7gpJ8peE4F4moaTfyGatSTQor6oNenJQz3kUum8HpXBZ6Gttqa1aqQ+AkkJ5S
         qWu16/HW5z7EmyInxlAobuZHOxfqtDl676e4+JrOVER+tcqgGZNUvQX5qPNewYC5xHyY
         +ycg==
X-Gm-Message-State: AOAM531vxlPRhm5MjqJjqpy5HnBgMg7Bh0u+WttuAxZlTxwfjxRu+I2f
	d5paexA8+XRSLtak/Th/swY=
X-Google-Smtp-Source: ABdhPJxaOEOvZejrWxtl8XLaAJTeCVs4t8tBOL17j7FspE+ai6wAldpuEWmP5A0/KIMw0AvpQFYnHw==
X-Received: by 2002:a1c:4b0c:: with SMTP id y12mr251254wma.91.1605046320871;
        Tue, 10 Nov 2020 14:12:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c354:: with SMTP id l20ls212329wmj.0.canary-gmail; Tue,
 10 Nov 2020 14:12:00 -0800 (PST)
X-Received: by 2002:a1c:c2c3:: with SMTP id s186mr262384wmf.160.1605046319963;
        Tue, 10 Nov 2020 14:11:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046319; cv=none;
        d=google.com; s=arc-20160816;
        b=ENqji5WMZyGHTyZ3olaMqUJ5OE5sIs6w4R09JBnM5lEx+tusQcFIuV1mAbdv4cho0H
         rDsHLScoyZLf7jnohVrD622ljNI9G4S+lUp6Nlitn2XrLmx4rvm/sMRcw/WTcZC9jiTZ
         5akdx5shB6ggZLtww9RCkFmS/MWsIrkhmt+koMrOth/VmsQmNZAuYNEzDb5IZ/8aC6Dk
         R1QqKDjbz9o1r9Myqv4LsN/moSgDv58RerAGT3bXyCIAvdj+I6J/aPlCCKq3MBGnDiia
         fIrTRJFcCg1RHjJM/6UjqLsCC0tEnXFi3LDvTYU/q2eHFLid2P3TeI68VC4YfljpB2vX
         AMJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=7o8isZnuO2uqhDb/44rZc/AlL83I+HH/9hRL3CzWT88=;
        b=h/FYWzYDy/y1gMPPm1IYKP2+Xj39CuYoV9kLzQ0RoUg5U1Lwu2WPW9dFTXa4zGMyvR
         HX5JV3/PsVJBAlDNLM3593czidDg6qnLugbYlAdwglNsZ1QFWYE2spdc+bp7ODWI26MG
         0k/tYQiVp1gBHCS6oSZhP+tA7BCotYpzTzaFXpwECkeORUeNAfhRqvIr6/vX0hIrtnqc
         2DmA0DX90egi+D3J/jJE0QU/I1dprbXHOmOZ9rxhnkBEr1y6Fh6FgLhOJR/XS/qHxsoO
         6LhsFOT7YcFBPFeKt/IC/me0HoMdOpaPY9SkJroR9WtSRkkmn7Tnomzd3eapxtVxWQn3
         dTqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J2IH1uzo;
       spf=pass (google.com: domain of 3lxcrxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3LxCrXwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f18si5792wme.2.2020.11.10.14.11.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lxcrxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id q1so6189163wrn.5
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3b87:: with SMTP id
 i129mr275365wma.134.1605046319530; Tue, 10 Nov 2020 14:11:59 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:19 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <f24f24cf8c75844531a01668b314aced88f5f3e1.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 22/44] kasan: rename SHADOW layout macros to META
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
 header.i=@google.com header.s=20161025 header.b=J2IH1uzo;       spf=pass
 (google.com: domain of 3lxcrxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3LxCrXwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f24f24cf8c75844531a01668b314aced88f5f3e1.1605046192.git.andreyknvl%40google.com.
