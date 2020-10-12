Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCEBSP6AKGQEVNP3ECA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DAEA28C30E
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:02 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id e28sf13128900pgm.15
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535561; cv=pass;
        d=google.com; s=arc-20160816;
        b=BRzG7TzK+YQiF33K5dXW8X/AniUUUM7j52NnHSucBc6VgDE6TWLPF4w2JRUFJE0MOJ
         0j5NKa0Ak6MHKFDcZ60DSDTwKy3UJehyr0jOM6d8qFBsBpsLsy+qtQ0X9vLbiSumEzIl
         OxtAvsdGQCNpWZQdRa2g45Gnfuc5IJfCFxTdPaecd8XCAHVc64Yh1EZrTydAzEpPR4pH
         H2Uj2TIttQqh6oyeP90BXAYGe78JHsibyxL9Y0kxbVG4rj0XlgUjdEuQDC+ldPVPC19l
         jCzZj1eZe6yWDBiLjEFyhalsOE/+veyQA0T6oxbKqygNfRtyK17IMJvc3kwv4HSX1dZt
         BGeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=U5+F4cdErEWowa+D3EtTdOT0JQ5/y6GCN8/zR0vTjWU=;
        b=grvalQRkLy9weJgiQpBPuljufyYIgdrQgedEizDatPf+26E+R8y2sUMAh/1LHKlcTk
         py+gAoIrJfHIpHNoB3tejNLlICJOL3i7HDxdsjZ3qEOCn9FhabQ4NnkP6k8phFntpmX3
         1m+2w/3t7HRySgMxYSuYKUtQat5lNVDjCMnVWMQP4DnqWUpl45Jahhxc47iigr9f0TQ2
         gPk6JCpKovNsrTezyz5W0UOJSers035VoXzKdbosir+kIrLTkK6zR1noAX9ZvA5xxEIR
         t5zuVxNcrEcA9tUFFVrzru+7h3tiOr+FVsnutUfbKne5HhWQ5ZhmOzOQbFcQgNt9bgOG
         6Iyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jJdL0HQ+;
       spf=pass (google.com: domain of 3h8cexwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3h8CEXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=U5+F4cdErEWowa+D3EtTdOT0JQ5/y6GCN8/zR0vTjWU=;
        b=qq11U9i7ItgE6GHxntbYXZ4D3PuepRw+4CRbvokFVZz6ATyD5VuQt2wgDQ5u2d01Mi
         0jo+YdJZNA13T24F3mcJOEFlfEIwifyPyxyMGsfZIAvqN2Ughp5NYvAsJNhr4Udf8SI+
         sPZMsUt1KrDy3iAbZIHwtQhZTBHxdtLABtfZxcGyYutXqM8zsyMBR5ZNOGxjo593u+/T
         /s0AMB+j6qtGrHANANdDjN0xgn9SkamCexTa6rbKVGStiEYZaRU50tlOx/c5PK2EljeS
         wkHLwRJgNGnKpopOl6iQTGuGCi7eNbbtQmM08EwbYuDuEzwj45pM2BQYTHG4wCsadlAi
         zc8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U5+F4cdErEWowa+D3EtTdOT0JQ5/y6GCN8/zR0vTjWU=;
        b=sXoRkV0VHcuhuprEeLK77PIXbpAPF6qQjUisD9caP2f7XEFGOsiwkuNMlQ1AVdvFNS
         q01feMohbksJJO506pqF6kueGUQeck94PfBnpOCsa9gj0ltEOQ+1SFnvIKF3+kZiLs8o
         thA4+hosjLU49y35Mu5xFcWl4/jxiYj71cAzGjoHfsWc2WpHvE7/xY3fsA5sPLMC9w3o
         6VX+GZaQWb1xwflWb5MBWwm9vAYDG8sggtD2wMcqyoEikRRmM4gI2MKDTGho7hNWBGTJ
         ka/aqbX4u8UGGvmhhEBrJ8SxBy+vqS87IhHvrWYRAYy7RX0DLMjrgA2nhCF+pcxn4vHv
         fR3A==
X-Gm-Message-State: AOAM533NttwbCR9Cn+n9AAQ90yad7NCOihNMWWbwCMofARMrDhQh8H+t
	hRhMNhNxSz+9MMHrQVKH2BI=
X-Google-Smtp-Source: ABdhPJx0kuuO3yVYIFAOIixkuR/JWS8ybOwiW9eJHPWaRpjdWIlqUgHBM0JPZ1MLXApnKMA98kue3w==
X-Received: by 2002:a05:6a00:170a:b029:152:6881:5e2d with SMTP id h10-20020a056a00170ab029015268815e2dmr25439220pfc.20.1602535560828;
        Mon, 12 Oct 2020 13:46:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4547:: with SMTP id x7ls6041250pgr.2.gmail; Mon, 12 Oct
 2020 13:46:00 -0700 (PDT)
X-Received: by 2002:a62:7f08:0:b029:155:79a4:1364 with SMTP id a8-20020a627f080000b029015579a41364mr18375474pfd.38.1602535560296;
        Mon, 12 Oct 2020 13:46:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535560; cv=none;
        d=google.com; s=arc-20160816;
        b=m8CeRmiuqyxQB4tscmLFRxK3EIgcBAT2tSTQZR8rFmghCxpWppKVSlkAz5SO0k0VEx
         tlkCzKrujRf6/CD5Rsk3hiZrkRP9UNfJMSUt5gTU4ZKfIGjjE9Qtvl7Lg2Q8jBTRvYaF
         WyrqBC4OOTgokcnY/8SEoIlrnjOBqWn6L93k9HxDQbNgouW2Vpj5u6KaBBnyLvcVVf5J
         QTlAfOzoqODdAURg8wH5YvaoMiUwrPiBU3EwCWqMq5TSZh99osXP46yCYTg5OfrtRPSL
         beuDHfxb44eZHgKxveJBJLxvWKWp0qR7089BN/apXJkc+6QUusIDwA+EmgWnupmmsoq4
         awUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=C/ZkQuBXx2nX9poF1oVWF0/8POPrhJAQWwQRLYs2ips=;
        b=WQy0bCiKDOd+Rzu9xcT+/9jvC4dxDn8QAMwcsWfNBJT+BOeGskod+RpyhUxAuI/X8/
         EtwaItS3ZQKxZHteePqO8+2+g14eGzpDpdDislu+xoTdnDf82xyCL0Jh/5fUbiOfWLLD
         whQZzlTvAshSmiAH0Ag1iMHeIuFHBoCeihODCGG/Z72xeVFMV8pQn1xN0m5wNjKvX2pP
         /R21anhrBYzn9cXbWr4ETDNUpYoocVIVTziex1h8hdvMh6WABlQ2s5zCU7I8/AcbGccg
         p94CZxklgxi/FF+nlkAGRgTRFmRPiaUP5gpHoaq0ciOn7g+0O9sffONA46+gsgWpoKTi
         ri4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jJdL0HQ+;
       spf=pass (google.com: domain of 3h8cexwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3h8CEXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id k65si1279464pfd.1.2020.10.12.13.46.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h8cexwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s8so11434516qvv.18
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:00 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:52a:: with SMTP id
 x10mr26987827qvw.59.1602535559853; Mon, 12 Oct 2020 13:45:59 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:34 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <000f468c5aaba5f1e38dbd4a5b19c2f54d80f7f1.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 28/40] kasan: rename SHADOW layout macros to META
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jJdL0HQ+;       spf=pass
 (google.com: domain of 3h8cexwokcr44h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3h8CEXwoKCR44H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000f468c5aaba5f1e38dbd4a5b19c2f54d80f7f1.1602535397.git.andreyknvl%40google.com.
