Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZVN6D6QKGQEZWSCXVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 72C2F2C154C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:11 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id g186sf1837098lfd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162151; cv=pass;
        d=google.com; s=arc-20160816;
        b=zMoNrVrreuqe99ICPNoXRqKsxkQqLuZAWWrLNg9/Mc1lIJMfpgKQ6Shu1Q7BwRm1hk
         BGQn9yKcW2LsNBRZBGP2eGFKASHU7Q7LY3ukwrJTblpMw93okby39dC6XErvN8rNtPKf
         RjBsOS8MAi+Ew09hdOlFcTgkfv/mnKnKqzKtWOaDKD1DcRYr8CtJd3oHHSDA2AMJKWOq
         EV4hi7O7RSM5NqJz5uVmtv+wq1NAvcUmKgg57Fm/rKe47DCPhI3PVyF8wiZ8NM5Al1zq
         TahOCmxpT7blCCfxFXCyqtFC0KWOwxNYqU6JCTclPW2Sjwci6HOyGJHf7qcH7oEPY8y4
         ZGDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=virZGMa2E+Ny0sBzMMX7KTT6OMc5BlOh57tG0tOwvbo=;
        b=qwWOFQayrOw4n8mRXAh98hta62ybyUcutxvIqiyHHLzEokWRurMPH9ims15hd3m1Ma
         lUCBnyi5O7wenlcZmDpEfMrhIiVPg9dDntZF3Nbnlyw2glHeKmN+rbUShc2lYmA26Csj
         iHRAnXlUasbX6qxwc5fml0Eo9zCu85Lm7c/YUosu8eLVyBSc6B4BYJj6seL7TUZ44/Iu
         5y/4zAcqYAyW688sxypMp8nrY+kY1A9dDov/gC7/4WYFmymTlbgK6Zd0FZNEV7QOIUCI
         e9tWcbKEh03z252Fi940hb2nU50fWOBA3iH+ObZC938MmGkcM/ttenII88DfQA9HFkY3
         wY9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fLNjLZHK;
       spf=pass (google.com: domain of 35ra8xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35Ra8XwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=virZGMa2E+Ny0sBzMMX7KTT6OMc5BlOh57tG0tOwvbo=;
        b=fvXTdJ5LG9C10PwjaHup9uiwYbmBYrd6X8UFxrhA0BbsENbexkvEa2O3MbpP4/+Ryf
         8Y/bVt34ly7CDYHQKqSqFKoJXTMtjxtabPPH7v7twe1BBH0bQ6zvKY6I2XV4FQjDSDtY
         9YNIs9MxUjeouE0I5iBh+Pi86A2P5geMKKSyrdcAIkEFRdJTtljklhXyohB8xVPVU0hT
         hR+i9cL29Tc8hK02MPJtTOR8WCpBewzpC6d/oqiGMuLvx2Q+rlK3kTlkEUiStcpvkrit
         QEDWqw+BUQ1VTAkAd7Ms8EuSBxI8NEv0a6Ufx4yhKMVi+DZxpT77rWDsXY5uwy6PrBu3
         HR5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=virZGMa2E+Ny0sBzMMX7KTT6OMc5BlOh57tG0tOwvbo=;
        b=OmGZ/vUVkYitxRNfcQZe+CV4pE0B10J1uUADNe7bO2VS+7AjHM8Mqec2w2oYvzhbHk
         Pbls+th8zwGSRQyT/vs/hRCEsxfbJ+97NZ6agroafw8hoin1WWmRUakzjQJWh9KHVcOi
         PzPTA8YFNtGPza6KhJ7UMQXpgMAy1PfzYjdA3vVOZ21/MlhhfSs54Fe7usGvw2AbRt/v
         6S2s8XD+dW3V197dl4omTcDohlLdWt8YGJrFdMXZ1HnQBCBBaC6Fa7HKvZSS2x3j5HLY
         7P24ZHy++u2xI2aDIxETRUAYy4TYbn+Ue2QaPs70Xz1WTuFuamTQ55dPpNkYJyBJdgg+
         9IwQ==
X-Gm-Message-State: AOAM533MWKHj/deRZ/0kLJSLJwRytakXcthx2v6IX8HQcZeZiCmxbMvT
	Tco/E/dLrD3TUptcNJ/gxSU=
X-Google-Smtp-Source: ABdhPJzmSE4EZtX/mz0mDrVjDqhAepX4hTEElouIkfVFUK4DfCuQ8uMW/bVh0i2PDneLeiVxrkjRyw==
X-Received: by 2002:ac2:51a2:: with SMTP id f2mr341708lfk.391.1606162151035;
        Mon, 23 Nov 2020 12:09:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:: with SMTP id v13ls2558805lfo.2.gmail; Mon, 23 Nov
 2020 12:09:10 -0800 (PST)
X-Received: by 2002:a05:6512:1041:: with SMTP id c1mr359139lfb.222.1606162150004;
        Mon, 23 Nov 2020 12:09:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162149; cv=none;
        d=google.com; s=arc-20160816;
        b=zMlmbTvRZEH5/TK0Z80joE2io94KVXYzd0cH2tDQnpSsuPy6OSiI/vbFzRfvdyKRil
         njrEZaf79W2f0ZUwSaFeWrLn3sV0g/iTdiTy+QtusJakBVQRNvPtx34c5kor7btEpEsx
         N5FXiYANMjWHCJIMal47pa93k31TIknO/EUu7s4iEBbGnePHE34KDCweG24CtEJvhpm7
         edKiOQ+2H02JSfYVXTgBGHAU2IntfjWDuRhBtwIEHm+CG3cGG9cZUIPA9bAV7C6ZwKMe
         Yl35Pb/fOj+PUra9QNa+kPPeyihbmvBW8pBULSkv+6gOUDbEHIk2MI1qxUBsjwU/BswW
         rChw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=GcVKnuDfFzQJ9e5llEgSJzxpADe2yFJHu5NkpPOoYoA=;
        b=SLO7QLQu768hLJ4oDvDWW/yrWfznVnqtcq2cYsOXWS/WDA3gmsETQY/vXB+cUJdIEO
         bujslhz2ttNcKkg5A7G1Q5SpjVTyYHH0pvk+GC4yjVMusvPCMjKD9NRdm97TUNPktRYp
         fqJriOyiz0fleNRCE7EwKWGz+DLuiOoO0frE+LZgOmoSTSQ2ChvEjAH3dDpOx6weLi87
         xzCpdEmq55uWW/jT2U+WF/+1LjLp7EgKKF3brgWUpHjsODKsv/CGjMt8A9A+c/kuZ5he
         Ap5ILSV8LSHHVe14nROBrMfD2uJlv9M8SRPCnAzTSXK8MgJ0O/Aj6cdTXo1g3YV9cRUR
         4XlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fLNjLZHK;
       spf=pass (google.com: domain of 35ra8xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35Ra8XwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f9si347295lfl.3.2020.11.23.12.09.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 35ra8xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id n19so314316wmc.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:09 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c0c2:: with SMTP id
 s2mr613063wmh.78.1606162149371; Mon, 23 Nov 2020 12:09:09 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:44 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <f96244ec59dc17db35173ec352c5592b14aefaf8.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 20/42] kasan: rename SHADOW layout macros to META
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
 header.i=@google.com header.s=20161025 header.b=fLNjLZHK;       spf=pass
 (google.com: domain of 35ra8xwokcqgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35Ra8XwoKCQgivlzm6sv3towwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f96244ec59dc17db35173ec352c5592b14aefaf8.1606161801.git.andreyknvl%40google.com.
