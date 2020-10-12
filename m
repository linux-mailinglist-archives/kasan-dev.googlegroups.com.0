Return-Path: <kasan-dev+bncBDX4HWEMTEBRBC4BSP6AKGQEQQQ5C6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8005228C30F
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:04 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id h6sf6888981ljl.11
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535564; cv=pass;
        d=google.com; s=arc-20160816;
        b=d6PgNP0N+gIK3jQxdT6I9K9YXCBsFelUZnSVtVqYquGDdWHiXHptkXWzgVCovArfa6
         qnAer/16lRblGiqpRKJxSCrIkLGuZ0y0k61RH8NNxYwVNXHO3uu9gXHWWXjI8ouuJDtr
         RqId8RY0GugD/5mPIrHUhsCV+UITp+VTl9DDhcsXgkYkGCm4Jt38uPWa41XNT+x+kaDi
         5PaGKX/AWQFhzF65qrT60VgOWW6Iiz/CouNef4hJ+gNPqIuOzD7nzbtDK0H039KMApP2
         4xqKHFzFO4jldnVNhuy2rJO+FIQYPLVKHdZaE3S36xK45i1kaMn9JFTQkI/D5uNZDf7Z
         Vj5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ioaQEbE6UQE4u/JxqORRffahw345KUi21kxLfqSXpp8=;
        b=fcYCKeuDgYE67/MCl+ZUTGY5Q7CTgAQNsrXxsLV2EGuUmIkLf8cCsW4PPkDz3ifnYK
         NieokPoppAFJwz694fgZpOhG6beUZldQCPSfJlS2XQVtCEQaiKdYEtdSbr5cPKZaOPn6
         fDEhIjYInNGpCuDadGUV66KYUVXs2KoflRCGQaVDqiVqfqmh9QBMPEmV6LE8//InE50+
         qROOOCaVyfghhqwZ/GjPrn/971K7GTQ5ScIfXwfRUTeoJoncA7UwfW9dwfSHY0okj2E+
         qlx8dKY4j9amugLmsJLCoghOzAv5RfGLaD5pw/TbG+LwqAGSEvvsrcC57fpiEmA8iBRG
         LI8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P2R3KXtk;
       spf=pass (google.com: domain of 3iscexwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3isCEXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ioaQEbE6UQE4u/JxqORRffahw345KUi21kxLfqSXpp8=;
        b=BjsqNU+tHwJjK9Xu1kGnDdu/TfAFZuX+xKTAjWtsq+kpWqQTAYy8D+0nxdS3hObEVX
         xgnDaqJmvv86jSjsk1XfJpN3w9KMPnyOwrJXldmhqcoqjb+pdaj0HsDFRbTnXtYltGuI
         7UsMWJbIVQcSUyV06K7tq1cdIno+mGt9mh6js4za4J6ltzt99HFmtrIzj8cDyYfPIpz8
         iQredgracxYhhg5D4Z0l9Jrl3zYMO1AIgD6qu2rKuApXYSIYuH6RUC6IHbtcLaEERd5r
         zb54dvuyoF9+IOn3fvEBc9JaTTwfuNWy10LikAUc6P9L7ow4MDSlMK6FvkcGhqfYO25I
         W1xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ioaQEbE6UQE4u/JxqORRffahw345KUi21kxLfqSXpp8=;
        b=pmDVRpsApJrq8Dk11t8qFMrKoC+Cm7pLqqIRglhNe8munWAXW7On3RzDyznXpM5I27
         c6hlT97ZcRgss8n9fLjEMxNoWfCwkdd0XhRBdhq7+1YW3g+ieFABPePDhKyFO94tOJLD
         1MUiGMCcSyzlRG4krj+S+gfKl+fNnnKNM+VOEsEtcdRGQ0DUrEqLS4+itVEIzAUS9vBz
         CnWdj2vJyInqKPf2bPFJaM1Tb0o3loMuLyUUck4qxE5Mg/QzJXo1yCZ43q+rMYi5vJKf
         /wjjoa5z/ZAAUbCtTTpOBtURXehH96Aa5wUBMDauUlw4F8Bu0iGiNPab/XXsA3rjiZzu
         /1Mw==
X-Gm-Message-State: AOAM532FHACdJAvQGON0nsNj6uajUDKIGMYNilY69kXmIgQP4ls0+72k
	CWb0QZrzV1VSktpheUI+BzM=
X-Google-Smtp-Source: ABdhPJwDI5Q2fAqlc2agv0CXjdcgSf9YsY1zpMOjD69bjwFbCfbtKy4F6rj2nRpOA1we5SIRehSyOg==
X-Received: by 2002:a19:b14:: with SMTP id 20mr9576105lfl.308.1602535564006;
        Mon, 12 Oct 2020 13:46:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls832689lff.1.gmail; Mon, 12 Oct
 2020 13:46:03 -0700 (PDT)
X-Received: by 2002:a19:4083:: with SMTP id n125mr8420222lfa.270.1602535563019;
        Mon, 12 Oct 2020 13:46:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535563; cv=none;
        d=google.com; s=arc-20160816;
        b=sVlmOspAHd+0PqBI24gISPCFpo1MEdLfoqgYaIwQu4ycoXEdPtfkclY2zXIMeMa78V
         3RdWuPFS0+kSUA+rYTciccR19bDmu5xg6QnNrnt6We/XcHz5Uzv7pNIDnGX84ZPB+iCw
         Jlh4XCeBbtn+xeLl/nlO+QWFd0eD4uzJgxtDCmRaXsuv0W5j1pGJ160gVVF32HtYXW8U
         yuQPGWZuuN9/ALmys8ifps7Tds51DkMfati8alAzX0kZrqHboyayMerniJAgi3U+07hL
         xxdag13Wmvbm6xKypd/KJCKXr/C6wpUpJ8XvVg3vXuZ3j9a9a4tL751YQKsCfDB8IiXQ
         P0tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=FxkgJWitnYQ4KCO5g1pFJrvXiUx3cakvbVWfbN/gwfM=;
        b=UbHd+SoGy3WZ0yxHGHD1zT28sgZUFrzXAkEKsT9JP4FylIPXm8dFJ4lbe1rQsVBLK7
         h6IEyxOuw/jDqONyFjtygqXzxh9W9FhwpndlFHPpZyGF0fsSPaUrlVnt0goKJSxbk9XB
         YlB5iOU0AMOvGE3NwZBjc/vImmu5zPDcWKJOX1HVHBXKkj5wwu3eaCvOCfm71+n/tqu2
         RrcFGiSbZfXYhRYeA9LqH3SNOZnArd9Y9Ze3gubUnGBsAixKkvwhlGf6bL6JqXtVH8tX
         MOUl5hDpLBKbirfHohWoMA0zmpJ7rgCLMUkpdvDaVfzSecYe4MvWJIpTXCofT95GGcbT
         6LMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P2R3KXtk;
       spf=pass (google.com: domain of 3iscexwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3isCEXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id l28si148264lfp.11.2020.10.12.13.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iscexwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id dc23so7141781edb.13
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:02 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:fa89:: with SMTP id
 w9mr16233395edr.235.1602535562467; Mon, 12 Oct 2020 13:46:02 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:35 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <10a1185de44bee978449f07b448ebbe52c2435e0.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 29/40] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=P2R3KXtk;       spf=pass
 (google.com: domain of 3iscexwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3isCEXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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
index 420638225c13..9c73f324e3ce 100644
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
 
 #ifdef CONFIG_KASAN_STACK_ENABLE
 void print_address_stack_frame(const void *addr);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 13b27675a696..3924127b4786 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -31,12 +31,6 @@
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
@@ -236,55 +230,59 @@ static void print_address_description(void *addr, u8 tag)
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
index ff067071cd28..de7a85c83106 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -122,6 +122,11 @@ const char *get_bug_type(struct kasan_access_info *info)
 	return get_wild_bug_type(info);
 }
 
+void metadata_fetch_row(char *buffer, void *row)
+{
+	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
+}
+
 #ifdef CONFIG_KASAN_STACK_ENABLE
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/10a1185de44bee978449f07b448ebbe52c2435e0.1602535397.git.andreyknvl%40google.com.
