Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVG4QD6QKGQEBMZ73WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 412D72A2F24
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:41 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id u15sf5973292lja.12
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333140; cv=pass;
        d=google.com; s=arc-20160816;
        b=c2IHBYe7DVnlVzQx/uQcoCqbkBLLr1+KwqNsIsQGoxGRkfkrQlXEendvihzjNlL+I5
         s54vnaNpp5KgWo9CuqScJrr4jji8sHy3dXUa1QVbMgf+CZP2Xw1T6oTtLElfwMzZ3Ei9
         t6rZYwn4HVIxn8Q/gDwhB3kcLS514WLdmiwxzWI23tW9d5rpdpdSg7+KkWfm1ju5btzR
         WqvrdNv/PvcG+Aywp5SK2EOq5j6+cP8AqwI5yLEbp5tBmOJoOcbghZIWh8z8sUpGTqlj
         yhXmvifV5ZMcsnAyM+EQrihzyOisSf6eK/gT+XIvrEsQpSTrWbps4TS28TxERitW1qB4
         NQCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=StS90aWjAsQDFOg9d9w4vITlFMGLzfgnHCITHSBQZYs=;
        b=KMaEKiWZu1k37Yl+QJ0g2XosQhfwOND1tno0rzfUxLy04THOBMZnckDbQCpTT0J9Tl
         quDm5KY8Ggg0CK04NeP4C5gh9S2y5XBKdQtUdj66owHLMBYXpm1n4YXeh0YtarKyAogq
         iF12/LWrAXbqpkJ0oau/pQdXBnvHnPu1m7qm5qoYVcZnkDiPHb8jKpowltDKt8ei1OVz
         MgtrRoQceKiiofETN1Lb1SmHc4SKr2pSss96CZzFDi38Yr1i9Rl/W4k00joZC35FVX0L
         eF3mBhoJ5QVrMDyZLGjX9VX5BN2G7AFoeNZ6SQ3kF7BDyRh3g+SkcmlFK0SQVyyUQQjo
         P8fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RUPRtoeY;
       spf=pass (google.com: domain of 3uy6gxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Uy6gXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=StS90aWjAsQDFOg9d9w4vITlFMGLzfgnHCITHSBQZYs=;
        b=CaAHr9O2RNXYtqCtu05K7HP1/iVyipnnR59I04JIyG1BK2eB7ACi/+eatlOiMEGTFd
         nHe24SqBzXN7qp8DhxmovHndHUB8nb37GoJCYUwL/VyCHffx5uFK7iwJByvg5PPCHrFj
         ns6eNQPRyb2V4JETQKRfTPTtLehcP5F8Ik4lVZn/5WyN8wviLhqe1L05kmLKAWY9MF5A
         dl1BS6DbosoeCblKkos7idbO72Q1jRYdQD2GDxV5+tC+OVCf+Pug/9Im/QoCoycU7PX2
         zOfhjmJxBUnnHh4KOqKPP8qDSDgm5wwAnGvdUIYhquoTZ69FVfIgz6gJpswMfR5Eps4e
         B4gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=StS90aWjAsQDFOg9d9w4vITlFMGLzfgnHCITHSBQZYs=;
        b=QWClsmWm+DpxfscxZqJCWTRjilfyG7giashuoOYyIs0QkflByc2gQpb06NHl8+dr71
         fodGRhIs9uOh/IK0JHEgDuBGfofOfrm+Cxz78MpeMnSCf7kqJUPulWOtGLiJDl6IaKQQ
         URD46WAhkcqcxluQmQP+v28tyjC4o746KCkSMETFhyzk5DikoHPJSvqtBffYaybbRdav
         A8eljWz9zBJRkvm9TCCHtiBYVjeEQvLFMUsKcZMrGD0IJQNmGc8cu/hKTlgBDF/gp1Hh
         zV0UVdqr1BaVRCuMDYMK7CtDgoX/aX3Wn8bapMXYwJ4ZEjwIszBosVp09TSfpsOytLEf
         MM9g==
X-Gm-Message-State: AOAM533puV0ELrTWwEHb9uDsxO24j6c9DMUd1dwSqiEHQgarVIgivdY2
	nLvY4bn/FSDAsANLW3+6AsY=
X-Google-Smtp-Source: ABdhPJwacXwQHYgJGfZqeWcLqxOgGmoTMrd0ntxK3jYfar/ehJA8r1erm3ul45cnntPbcJ5pnOkYzA==
X-Received: by 2002:a05:6512:3193:: with SMTP id i19mr6439763lfe.80.1604333140820;
        Mon, 02 Nov 2020 08:05:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls1378646lfd.3.gmail; Mon, 02
 Nov 2020 08:05:40 -0800 (PST)
X-Received: by 2002:a19:c97:: with SMTP id 145mr6329665lfm.81.1604333139928;
        Mon, 02 Nov 2020 08:05:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333139; cv=none;
        d=google.com; s=arc-20160816;
        b=UF7tgW/OWV3JeYg5qItSScdSvcytIFgl3xQP3ZqEUREoTctqHRuVTpPIumgR4kDNcq
         hDB3VTtHhGg1zuoLGrEv/WDc9/F4KCVXI5XE4jxajHbZWzojFTZ/jTo4nqJZ3JbbeohZ
         tG60It6BCELqdGAtURcS1r4L2sQoAjvVRZoS8MSZP4OdvU09R6ag0g/jnrZt5d1BWv8h
         CyUXUxcAb4v99nbZ2EQuOPOXFbqKnNMManEjuo5LFQXYG6T5ZwirbyizurOT+O7mzjgp
         JhVSmnAW4eqC2IxL4CABo0JbMiFmQiOpIwPFoZllvreqG57P8zMnRekKQF3aTWS/ve8c
         jIWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=EDxSkOG22JFejpo0qUQc1PhNbOVGn2/xi+IwiijzuHU=;
        b=vjdlNsL8HwopESfQSlZ+peHYNRnRu6AB9uhQSFZph9T0b48GX3cMhu3ev+BZli/BpO
         7tO4/kuzSm/wsxv10uxuQv67vI47iCz8q9Qr+F72Jru23BP2RM/Eu8Stnp+9eYO0Y2y+
         T/zKeWOZjyAIrQgkVxF1N9v1Fh0Vk18khaL0JJhjYwD0W+V7R3nRJ7Q7wflZFqgHS+Ae
         s3PfEwZK83X/h4j738yaz4Jk7dDF4nFdxROdYHVCJLCsuvGdYohcVtQlyT84nG02KT5W
         rEG5QDy5Srhft2CuCoX249V0/9Hs41fubTOnOjSRUz1MWPd1NpWXocdK0PZ7Uv4yBzAm
         LvNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RUPRtoeY;
       spf=pass (google.com: domain of 3uy6gxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Uy6gXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id i16si462565ljj.3.2020.11.02.08.05.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uy6gxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j13so6655291wrn.4
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c305:: with SMTP id
 k5mr19135735wmj.102.1604333139387; Mon, 02 Nov 2020 08:05:39 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:10 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <96863d2c75b58de04f0bf599ed87e05e8afd7e59.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 30/41] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=RUPRtoeY;       spf=pass
 (google.com: domain of 3uy6gxwokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3Uy6gXwoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

Rework print_memory_metadata() to make it agnostic with regard to the
way metadata is stored. Allow providing a separate metadata_fetch_row()
implementation for each KASAN mode. Hardware tag-based KASAN will provide
its own implementation that doesn't use shadow memory.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5b0ed1d079ea776e620beca6a529a861e7dced95
---
 mm/kasan/kasan.h          |  8 ++++++
 mm/kasan/report.c         | 56 +++++++++++++++++++--------------------
 mm/kasan/report_generic.c |  5 ++++
 mm/kasan/report_sw_tags.c |  5 ++++
 4 files changed, 45 insertions(+), 29 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ce335009aad0..e3cd6a3d2b23 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -57,6 +57,13 @@
 #define KASAN_ABI_VERSION 1
 #endif
 
+/* Metadata layout customization. */
+#define META_BYTES_PER_BLOCK 1
+#define META_BLOCKS_PER_ROW 16
+#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
+#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
+#define META_ROWS_AROUND_ADDR 2
+
 struct kasan_access_info {
 	const void *access_addr;
 	const void *first_bad_addr;
@@ -168,6 +175,7 @@ bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
+void metadata_fetch_row(char *buffer, void *row);
 
 #if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
 void print_address_stack_frame(const void *addr);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8c588588c88f..8afc1a6ab202 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -33,12 +33,6 @@
 #include "kasan.h"
 #include "../slab.h"
 
-/* Metadata layout customization. */
-#define META_BYTES_PER_BLOCK 1
-#define META_BLOCKS_PER_ROW 16
-#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
-#define META_ROWS_AROUND_ADDR 2
-
 static unsigned long kasan_flags;
 
 #define KASAN_BIT_REPORTED	0
@@ -238,55 +232,59 @@ static void print_address_description(void *addr, u8 tag)
 	print_address_stack_frame(addr);
 }
 
-static bool row_is_guilty(const void *row, const void *guilty)
+static bool meta_row_is_guilty(const void *row, const void *addr)
 {
-	return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
+	return (row <= addr) && (addr < row + META_MEM_BYTES_PER_ROW);
 }
 
-static int shadow_pointer_offset(const void *row, const void *shadow)
+static int meta_pointer_offset(const void *row, const void *addr)
 {
-	/* The length of ">ff00ff00ff00ff00: " is
-	 *    3 + (BITS_PER_LONG/8)*2 chars.
+	/*
+	 * Memory state around the buggy address:
+	 *  ff00ff00ff00ff00: 00 00 00 05 fe fe fe fe fe fe fe fe fe fe fe fe
+	 *  ...
+	 *
+	 * The length of ">ff00ff00ff00ff00: " is
+	 *    3 + (BITS_PER_LONG / 8) * 2 chars.
+	 * The length of each granule metadata is 2 bytes
+	 *    plus 1 byte for space.
 	 */
-	return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
-		(shadow - row) / META_BYTES_PER_BLOCK + 1;
+	return 3 + (BITS_PER_LONG / 8) * 2 +
+		(addr - row) / KASAN_GRANULE_SIZE * 3 + 1;
 }
 
 static void print_memory_metadata(const void *addr)
 {
 	int i;
-	const void *shadow = kasan_mem_to_shadow(addr);
-	const void *shadow_row;
+	void *row;
 
-	shadow_row = (void *)round_down((unsigned long)shadow,
-					META_BYTES_PER_ROW)
-		- META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
+	row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
+			- META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
 
 	pr_err("Memory state around the buggy address:\n");
 
 	for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
-		const void *kaddr = kasan_shadow_to_mem(shadow_row);
-		char buffer[4 + (BITS_PER_LONG/8)*2];
-		char shadow_buf[META_BYTES_PER_ROW];
+		char buffer[4 + (BITS_PER_LONG / 8) * 2];
+		char metadata[META_BYTES_PER_ROW];
 
 		snprintf(buffer, sizeof(buffer),
-			(i == 0) ? ">%px: " : " %px: ", kaddr);
+				(i == 0) ? ">%px: " : " %px: ", row);
+
 		/*
 		 * We should not pass a shadow pointer to generic
 		 * function, because generic functions may try to
 		 * access kasan mapping for the passed address.
 		 */
-		memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
+		metadata_fetch_row(&metadata[0], row);
+
 		print_hex_dump(KERN_ERR, buffer,
 			DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
-			shadow_buf, META_BYTES_PER_ROW, 0);
+			metadata, META_BYTES_PER_ROW, 0);
 
-		if (row_is_guilty(shadow_row, shadow))
-			pr_err("%*c\n",
-				shadow_pointer_offset(shadow_row, shadow),
-				'^');
+		if (meta_row_is_guilty(row, addr))
+			pr_err("%*c\n", meta_pointer_offset(row, addr), '^');
 
-		shadow_row += META_BYTES_PER_ROW;
+		row += META_MEM_BYTES_PER_ROW;
 	}
 }
 
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 16ed550850e9..8a9c889872da 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -123,6 +123,11 @@ const char *get_bug_type(struct kasan_access_info *info)
 	return get_wild_bug_type(info);
 }
 
+void metadata_fetch_row(char *buffer, void *row)
+{
+	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
+}
+
 #if CONFIG_KASAN_STACK
 static bool __must_check tokenize_frame_descr(const char **frame_descr,
 					      char *token, size_t max_tok_len,
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index c87d5a343b4e..add2dfe6169c 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -80,6 +80,11 @@ void *find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
+void metadata_fetch_row(char *buffer, void *row)
+{
+	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
+}
+
 void print_tags(u8 addr_tag, const void *addr)
 {
 	u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96863d2c75b58de04f0bf599ed87e05e8afd7e59.1604333009.git.andreyknvl%40google.com.
