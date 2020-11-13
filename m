Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYULXT6QKGQE6X4SPMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 692AC2B2817
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:07 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id b25sf12610521ybj.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305826; cv=pass;
        d=google.com; s=arc-20160816;
        b=PtLwBJW/DHrJjCVfNSvovdgTpUt62EInQUo+OQO51FR/ix7ZhyC04Dj94/ufNx79M9
         B2ZNx2drhamGBhl07rSXDmq6eojHTjQSEd8dPezg+dkp494IBOuj2MCr5yHL4Qor0Zvj
         RDs9jICM4093aopsP7rKsCQSkB4FiMb4Hd4ft6AbI1OpAasi3yfVCWSLp4oG2UQ5Mxh5
         GWGZtNf1I1y1zBDBQH3QDmtUPrWg8Pz46YFrZ6634Gt+H3k3iOdNMfAJ/HDNBOqPA3rj
         IN37GksFEN/pTtw58xyZ1TTRZN1OYg52a0/D6Bc6h4muD+VoyVAUxeLNy5ksUOEi13fS
         z6Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=BNFIEPIzG5D1XeR1MW/KOhKYq3mZXtdGQzN6As32SEM=;
        b=lTDyRZAPaHKEd06hgX2r7LngVX1lMJAXwo1n/ZDU3bnYueszRG1CGwPslLqa2JnF09
         YVR8pfWefH8fGMdGfUo1pcwulBI0Ri4atEa18PM52L55NB+Bc+dPZ4jGTOsf+RzRXsMb
         tyvpKRVKaWKOKSYnNTvV0zxCkgSPqXsR+W+YK4BrdvzVOxGR4HlIVV8waZm6BWHvslcw
         Jsj9khpVY/3vBB1wOeqKu8O+5e9RxnA01wYZR4yN/9HqO7VFPB8QUV2WIXjcyPoJIcWA
         iw+eMNjc+yXnw1hH8IwRr74K7VuRfOeV4+Onw94Q9GNYRse64UFOYstRgzOZlrLQp8Vy
         J01A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XQbEEfj7;
       spf=pass (google.com: domain of 34qwvxwokcawmzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=34QWvXwoKCawMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BNFIEPIzG5D1XeR1MW/KOhKYq3mZXtdGQzN6As32SEM=;
        b=EXeQwaZSFzfOMIx1H80kJFICeYJUaQ201/I5lNaUpTxbkgElcMQAxvqncI+qdTKVZo
         Bo5/NKeyORTGfHybu2w8ymTdnSs0OPqXYJR+ZkwHVxgnSchmfwpScP7pDu2rUs5kxPna
         e1eYLruJLCFI10FosYK51vBbC4Z/z31R98IT/yoFCacVlQDwlzDx/0GW7Zy8zebW0SJp
         BfO60foX01MWf/rosIRxUhWDneaHgZwIDNpFTKyxMPwzwOXnqnQHopbarlX/wedydu6b
         AuaijvUH/dOfQ/+UDRzcW73IoMrwbjwhd/IF0otbCQFXQ943+i9J1lU3+js9znuYZbYc
         k8Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BNFIEPIzG5D1XeR1MW/KOhKYq3mZXtdGQzN6As32SEM=;
        b=CjWyHNdOKGF0rb9UTqYbHxczUp+8+IAph91G+Yna202KbDWKwH4dd1aPKsADWHMqKS
         1MR0/YkDKNTqPXqHUkROcOBpyVh6ae8OuKKzFTmiIel70uXAJ8QZ2xaVNwD7LvKBebK0
         afoECp3oSc3Pet6W7KDlnknekc+QMwD1hp4RiQnYg5dzdUQqaZuBqBX2T1yDmC2Nm5jY
         +9g3/oKyr/2gg5v7VoQUqp49pu3yLdBv3nPXN5TNtTSt11qE6CHrv62xenW0HeY1LLOW
         EIIHs90bUkEOi2vujreta1HXR4iW9cJCy2Hxsx6naOud9WDJTsUMIA4EcuHSxQ2HZl90
         HWEA==
X-Gm-Message-State: AOAM531KSpfurj9PjNlEsqO8FejNkRBibKEjEDNMjM6zUndNDCByC5t3
	MquGgOeK4+v1wO+gX/CAvQo=
X-Google-Smtp-Source: ABdhPJxvAUgkRzViuXDIZ0jzrqDY56ttw6WNLgDyTrksMrrLqHWlaOpY3/2NrVzQ8WvJapma5BZsPw==
X-Received: by 2002:a25:e0cb:: with SMTP id x194mr6133047ybg.329.1605305826498;
        Fri, 13 Nov 2020 14:17:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:4cd:: with SMTP id u13ls3987913ybp.9.gmail; Fri, 13 Nov
 2020 14:17:06 -0800 (PST)
X-Received: by 2002:a25:aa45:: with SMTP id s63mr5614311ybi.471.1605305826013;
        Fri, 13 Nov 2020 14:17:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305826; cv=none;
        d=google.com; s=arc-20160816;
        b=whOi3SM3fNlwvISXD73Mw/ElFVY9HFCTlh5XjyLY7DZChwYQ/hkVbAjqpvIClHcv2B
         p11JVaiUNQ4+6ncY6jBqDCYfWYxBjz4Ock/Bs7dHUMbercPypyK7hmcwkqW6B9ApZp9q
         N3atpAuxWRIcf4l9lX3GFF+kM+MbZk7rVvziXS+F9PWOP+fg4WZXQTvBczvV2e7liWDZ
         jt1imoK1g0TbABahfYg/ygirHDFnmpahGgWFSZRT4mwZfZ6raKi7589Rieg9vFi4llrP
         p2UkacewYVFuLgqQP1q9o7uvNeZPd1ztGKTuI564WJj9HSq+LnB+Hmop1KUS5Rlt8UqY
         1fCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oK43zhnJIa0xPYjEbCK8yJmPbhsSh0WepgRvLtVD9B4=;
        b=DYCb+zWKUb88313VUrNew/mBjhz4yQiNy7pvw/uMDSahs66kdzKPVLm5BL/oKNpk+r
         mZwg0Xq7JOA5+Fai3ku4VzodYEKlBkacXs0/dB5S++4Ba7RtusdFBQrLGUn+ixV2WK7g
         reU19Kg+0tkdAEQry/1CmA0Iwcpn6ZE8FJf3XUMJnxW/Si+W3plAT0X2/0sVnJBLOD0b
         tg3lZrIRuFC45SwaQ6+8W13QvCKaImYZzo3sMUTxsywYG6wdTaXOFHCmGEyYSY/RO0l+
         9Vd5zu7M8ZkFUnZDmIRCO9cu7LVwFHK89XuLQoUVWB9Hz5JcNKETh09Y/lCZUgaSY6Do
         u2pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XQbEEfj7;
       spf=pass (google.com: domain of 34qwvxwokcawmzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=34QWvXwoKCawMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id n185si657552yba.3.2020.11.13.14.17.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 34qwvxwokcawmzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x22so7556578qkb.16
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:05 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:476b:: with SMTP id
 d11mr4561342qvx.57.1605305825631; Fri, 13 Nov 2020 14:17:05 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:49 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <11f3e9f4efaca963a40641ed337a2156101109c4.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 21/42] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=XQbEEfj7;       spf=pass
 (google.com: domain of 34qwvxwokcawmzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=34QWvXwoKCawMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I5b0ed1d079ea776e620beca6a529a861e7dced95
---
 mm/kasan/kasan.h          |  8 ++++++
 mm/kasan/report.c         | 56 +++++++++++++++++++--------------------
 mm/kasan/report_generic.c |  5 ++++
 mm/kasan/report_sw_tags.c |  5 ++++
 4 files changed, 45 insertions(+), 29 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c79d30c6fcdb..3b349a6e799d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -58,6 +58,13 @@
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
@@ -170,6 +177,7 @@ bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
+void metadata_fetch_row(char *buffer, void *row);
 
 #if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
 void print_address_stack_frame(const void *addr);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ab28e350bf39..2c503b667413 100644
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/11f3e9f4efaca963a40641ed337a2156101109c4.1605305705.git.andreyknvl%40google.com.
