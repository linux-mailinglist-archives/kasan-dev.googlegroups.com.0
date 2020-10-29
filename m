Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFFP5T6AKGQERUHUSXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DB69229F503
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:17 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id a12sf3711542ybc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999636; cv=pass;
        d=google.com; s=arc-20160816;
        b=wi7yBjjz8rNVu4Jxz3YIw5uR+ZapRdWn0tU1t8n5pDXnzIWpSws2hj0tg5SduNE57u
         0IneAFvxs4DuFOrBzzI2Y06009J7ZWZIHKcqBqmQhhq5L3ZMmTwipbHMJmwSPH9Hho92
         +doXC1nNQIid1Eomj/hHAc2qCAQyjSG0AQwKfsngDEpBKtNmkigb0xsQa4iddPkE7u5t
         noTgmPVaxtPoEVoBC/hdWEDFt2gykC7bnuPMSSw8vT531pftEumEGzk1kNlvVnXRNyxG
         VwtLlQ1Qni0S/2triVZ9isMer8mQOTmHreyAAbhUIyIyp/ymIEkEovP6TOMdC14tgOQ/
         NGww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EdO4xpx3FFTldAPCkyGcudbhFvT2fvNO1u8+fIEqaRk=;
        b=eS5m6rvdZpDS7LfFSssYsUmTDp8kaWzqIoLZMyEbRW635ix4DFhypNNfkIl4PDdwA0
         AUxwS+OBYV4HmXkTfddOK8wXdvDeCyiAasoIOcRb4hxmwMhIDSyGsvP/bhG51CMR6d7z
         Ty/LB5+5KQGw0kxTYesI3TvrBoyt2tUgWzIeeRAoPFo38v+ba2mncBSi4o6q7gegyxml
         PM3750SZPBQ+8yr6RgXrj7EbheuR6vkFoo3x08Or+BXWTW0C6pTHoZjfwtEC4EraydpT
         NEEpi68udqTQcij6QiLUHKGU5zuI6u6ZjeH/KnmdtPFtT4zbi609HuzY/DgKI0nFoM+x
         MZ/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Nu/aCFqH";
       spf=pass (google.com: domain of 3kxebxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3kxebXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EdO4xpx3FFTldAPCkyGcudbhFvT2fvNO1u8+fIEqaRk=;
        b=lQ+8/1sZ++e3bYZ8JYkSLhwuKKUVXPAKT8Sg9YazuWKueKRRpD6xN0FaAWILuMMPQF
         22itZe9diVuJRpXU4JD5x2K5NkTghtt7S8d9/2aKmOdpZREZpsEBarOsFIzUU3ESfkGK
         gwmkHvUzAyuF4dm3MwXqr1tFL0o6jeKawHzbK5iq+ff9qus4GUU/vZOQt0PQF2W7sLX+
         TFJlnPMQrxkYkIym1R1+AmXhmlr9bBeq3gECzf3rxAC/dHxNo1kx72AnwMMP5FfUhQb3
         i9pk3U3Ko1OsQ03GtOYQcmJvYY81PtRQ7EMf/dn11TPTeAZZYMI3WkAekIdDMpSL44RI
         /oCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EdO4xpx3FFTldAPCkyGcudbhFvT2fvNO1u8+fIEqaRk=;
        b=enV9xMaQ4PJAXsrMRxdJfkPgWLWR1E719U4ubW7CyrZT9/ND8h9a0dnAIGf3k2RWVj
         gQ6qd3HUsYeJMWYJ5t7g5Vs9TlM3yLLcdpsL24Eb4z7wiaJ8Tsg75W9S1INE26kp203g
         jMWFY3NFzlK/O1z1m8PIYl/wnEg1YLiS8TvD86TGSrrkSl2z+ZT8hlGKdk2QpqFfUGxn
         6MCwqa9Ptg3mPjy1cmfd84nprK9N3App5rvT9e0FOz5VxukIXkDYg3CvHJkeHyUJOFQi
         rnbibFJI480SCYHOldUUz+UiGtTKPqmlFw7ul99PY7byAL56dSDyUJe04eW5C/3c2/MT
         WArA==
X-Gm-Message-State: AOAM530u0GLYrulVXxcPz9PdAClFvBaCvCjDCszQ166ythWzpze93tb1
	5Mu0pZOwtlD2d8Hlmvn8Deo=
X-Google-Smtp-Source: ABdhPJz0/q7cfxVLcZ2fLHj2+zYeHa/uuKMhhHkUgR4N2SYLS7BfvZ1HMAfK7IlRLGnK+KkTOXFYYQ==
X-Received: by 2002:a25:32c3:: with SMTP id y186mr8669698yby.71.1603999636808;
        Thu, 29 Oct 2020 12:27:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cf07:: with SMTP id f7ls1816887ybg.4.gmail; Thu, 29 Oct
 2020 12:27:16 -0700 (PDT)
X-Received: by 2002:a25:1c1:: with SMTP id 184mr8323731ybb.243.1603999636188;
        Thu, 29 Oct 2020 12:27:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999636; cv=none;
        d=google.com; s=arc-20160816;
        b=q+QWMJfVcFQ7F8By3QphCmYmpeajb06vuuXN8JaGt0now4JSrClpRIigkCYoLf1+ZS
         gsWBJG3lG37peW6W5DqQVbAqf6jgXdafvJ6iDMh2SXUT1igRGbuBx360A6WojnKbv/Bt
         LXtebv+7mLAKBpVMxehwoE/QS3gzGUZdyHSJZTwQsAlnyGP7DAuYTZrQMJJtI/Ie3bHi
         W4kvnBfQWPyurKwFIaN/Cc4OFA5vUvUKxwuJ/fvvzjkqTLK984DzPb9sYkCkZA3bdnxR
         0saQJDFZGDDXhSUeh31dLmkK7wocB7kNqwoupOYLhI6QX6TQwA6hBPav7OkhJYX0HdXc
         RUZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=85BahkB/ARH3bXDyEMCLh1SMwp72o82khunrv9SMNJc=;
        b=rHr8ckm6NI8kYoZqvsj2Skm6kseQMUv7n6dTE3w9vMnJZr59YNSCZRKZjqvOtZMoXB
         VOrUYFeLjMUFzBJ0ZYeZhZKEmBwnbzatRIzskF6vZbISsaqrkbdFjI23nWIP9KEfLeI6
         nqLSEbn/55UA0WQDaBH3CMqS928M8YCSiPR5UU+gw4vfKtnHIJ1twfkl/PmJwfhAX06A
         F2SLPephBjM49urQUWJyEdW30LepzZoem/4kJ9tupUBbGWDZF7ptTyA6w5JxKnP9CymZ
         t5CjEEaCP11+sZvu48krYOxOJro6xNzU1k3TCg6xKiiBNSLTcsqoJdkRNlddFMChbzFd
         nlWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Nu/aCFqH";
       spf=pass (google.com: domain of 3kxebxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3kxebXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id g36si234600ybj.5.2020.10.29.12.27.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kxebxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i15so2530660qti.7
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:16 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:db89:: with SMTP id
 m9mr336900qvk.26.1603999635756; Thu, 29 Oct 2020 12:27:15 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:49 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <790b4b975b5b95351da853c6c4f1c00323758c35.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 28/40] kasan: rename SHADOW layout macros to META
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
 header.i=@google.com header.s=20161025 header.b="Nu/aCFqH";       spf=pass
 (google.com: domain of 3kxebxwokctiobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3kxebXwoKCTIObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/790b4b975b5b95351da853c6c4f1c00323758c35.1603999489.git.andreyknvl%40google.com.
