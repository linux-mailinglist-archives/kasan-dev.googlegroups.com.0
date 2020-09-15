Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU66QT5QKGQEIKAWE2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D591D26AF5D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:07 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id m24sf1813159ejx.22
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204627; cv=pass;
        d=google.com; s=arc-20160816;
        b=nU2+zbHrVyxvqL/cO5Lbrn/zG1Rnuu6DWoea3+PNVzqRftDE5dithj57T2ggT4yWkO
         Rdkq/bcwK+LVWiRNcpcuak1DM7zp1dGiNxKktbAgcT5aRJqBBNVwvZE4gfTkkWD3gIo6
         jI/nW+Kx32oxMa8+XuKdEsLkYwLTLwDwRXbvzBaJAkt3idgAk//glMmxXF6LvKGwGjmI
         F1yke8015hFZ0zr8lGBHD6/AOoDETx+eC5uhvmAU/9qvCmFgFLWaf0SGeHWNSavB8kX2
         8HaIRbA23rssOkuqj+2Hk7NNFKEwuVEonzAe3nHpQ6MkCrqt0DyqgyYRUx51fkQfv1BR
         Hxnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VVrwvQNUzojDZOjnSLp+2/mhmyo5Tf41Nncv/K+BdIU=;
        b=x49K1cD074/1PuHe0zsjrEFLCnJYdLGIO3I3geVK/29fmAu7VY7BBo74nlytQ1zhUd
         ieGmHrraHkUsQ6l7LjTEgcdOD6wA4BUTQecJHEsHkzEadsE/UONntz/WcK/SXd7cHG5s
         N9JezT8u5KEsaHunQwkU9WZMCcG6fwP/34UZF44fi+qF9VRy3Yux6ucKE9JONSsJ5XEP
         jfxVL0Ef313/0Nk39XrwNv/k09gxT3PCIqOWDlWX8Qfece9fLzBoK+JYNi327nBLuya7
         rv3qAivZvJ8pC6ED6/fit4QKpL+VN0RemO5CppL4qdZQjXFgfPsN2BvNi8wTC9QvP4bi
         JhQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Uqy/64yl";
       spf=pass (google.com: domain of 3ui9hxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ui9hXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VVrwvQNUzojDZOjnSLp+2/mhmyo5Tf41Nncv/K+BdIU=;
        b=JIT9K3HxeVCfecmT+9SpAD5m5BuFoRf8tLsuO5ksdcX4r4nvhcNrzEPvIkB36TWx+o
         oK/LAd7GuyVkCslP9aVymImeJjS7SaGzqA3DLm57FU8KcD/30/rSEAg1R5A4A+hWUlxL
         EeChTOwa//bs5vyrCiix51f36QOPkjRSwln3z9vY4jOXTG7luTNHBXfnWuTcSCUd/d1u
         KA+EWxG8R57LVaaYsDoANltk/W58lkLOkkFM8iJIi3/J9OrbBVLP8NKX/ETpHLaD9yAZ
         cSxoxP7E5cHX/PewK+oLQAnXpQjWa6w8aOCht4wtENQhXEvAOXRCt2jCOL6t4HTTDeEH
         Rjkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VVrwvQNUzojDZOjnSLp+2/mhmyo5Tf41Nncv/K+BdIU=;
        b=iWXp64eClSo5Ujl3iMTCbvYQP+FAvF+99DDWFFqp5zUtv9CrECzDLXfv4Qp+t0/Bel
         X/yUw9DZxZ5sIdIw1F/iMtAYOP/Vmz4QdQJ+SxxiV0c2vez9i7rLOxi1bcCESyfaK6/O
         /ibYzPmpsIUWjlS17u+9n6kV3mRrDaRuZUSBJrH7jcKlxCvkmOv/FcIV/W/64K/4P/7y
         dx2yWvLAvUPixcx5uAJVBuO2+6byTA3fvb748UdDn3VW1HGCDl3XVV/Chv+PxEs4SRRn
         6+01PzHBb5Q2/5w818seH8o7DiN8T37yjlaQJeOOIXodmijXrdi+nlVSo5qQ+QJ0kGHf
         PaSg==
X-Gm-Message-State: AOAM530GmAkrLtbjmGkyXjOVMOiE/pE6JAjpVXYOC1yU2u1NnUAlvrHV
	i7M5khoxuh3dX5rYNjliSq0=
X-Google-Smtp-Source: ABdhPJwT9wU+i+Q3WnQngya22POyN17je5P87KBxIj4TFyKjxp/6dxkIkZ2N4FIxxWoXM7VYlUP3SQ==
X-Received: by 2002:a17:906:5488:: with SMTP id r8mr21715251ejo.483.1600204627561;
        Tue, 15 Sep 2020 14:17:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4904:: with SMTP id b4ls50980ejq.9.gmail; Tue, 15
 Sep 2020 14:17:06 -0700 (PDT)
X-Received: by 2002:a17:906:f897:: with SMTP id lg23mr23423935ejb.89.1600204626655;
        Tue, 15 Sep 2020 14:17:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204626; cv=none;
        d=google.com; s=arc-20160816;
        b=TQj6XucwYXV+h3aQCPOXxg0+2Na+5S8Ar+QGYRcYcT9KqtzPTzCnGXbJHnM30KgbHE
         yrmaAtmySmB0fWsvL4rFmgBv6rxhDYN0iHLKWp2iRAHPD52tLkj67QHOZl3M4BhI+jfe
         r7dHWl/B4DXn265AhuxtumOQdRDvkFbRR9dVfVIpGOInnm0RwknE9tx/Oacs63oxbxtH
         59/CmwuHycC3jld00Z6rt/Kd4x1qjC0Sw7UCf4S6/1GBVdBjplApMCM2yMZasUT9tuCp
         UY33pJirUw/95zqN/2hNInuYUm3z44nJUQpW8LojtFeTKcDF818C1IMqjczTOtTPL6Pi
         ZPag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=cNUkjw3h6h2vvdGQHstiUCBBTL6uA9taUHJKEUHsZNs=;
        b=Yfvpb2nvTFRSykohtJSzpz83K0ogTLQhXJZxuGkJ7QWWXUy38IAHnOMIvIgzOGXZh2
         PmONrVXG8FMvAZYB5qvD+MVtjDFQYm/nh/yMsMq153TrU7yjLSVxABzYtiKlgX3SOdXh
         pcy1YHHmMFztUXVFau7mfXqbZuCqIDpcppLfAzgnl/HlQXT/KCmKXJfoRoT+08rK5ehD
         Yj3VmeUFtQChWqZ5QP5D5760+9W4XwC38LtlwylC/8imkwuRVBwEphcLWVhB82PG8y7d
         vQaPYgiJYH5rxj4lFyvBAgbBr0UZ6i0ak0mkxRnb9YIgNveT89HzRmpxwVwfn+TYZYZG
         5owQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Uqy/64yl";
       spf=pass (google.com: domain of 3ui9hxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ui9hXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a16si764475ejk.1.2020.09.15.14.17.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ui9hxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id y3so1697053wrl.21
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:06 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:245:: with SMTP id
 5mr1264364wmj.33.1600204626209; Tue, 15 Sep 2020 14:17:06 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:00 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <ab44c5a0f7edf21d17c4212167a2ec2ca3f69582.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 18/37] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b="Uqy/64yl";       spf=pass
 (google.com: domain of 3ui9hxwokctctgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Ui9hXwoKCTcTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I5b0ed1d079ea776e620beca6a529a861e7dced95
---
 mm/kasan/kasan.h          |  8 ++++++
 mm/kasan/report.c         | 56 +++++++++++++++++++--------------------
 mm/kasan/report_generic.c |  5 ++++
 mm/kasan/report_tags.c    |  5 ++++
 4 files changed, 45 insertions(+), 29 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 38fa4c202e9a..1d3c7c6ce771 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -56,6 +56,13 @@
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
@@ -167,6 +174,7 @@ bool check_invalid_free(void *addr);
 
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
+void metadata_fetch_row(char *buffer, void *row);
 
 #ifdef CONFIG_KASAN_STACK_ENABLE
 void print_address_stack_frame(const void *addr);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 6306673e7062..c904edab33b8 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -36,12 +36,6 @@
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
@@ -241,55 +235,59 @@ static void print_address_description(void *addr, u8 tag)
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
index 29d30fae9421..6524651b5d2e 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -127,6 +127,11 @@ const char *get_bug_type(struct kasan_access_info *info)
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
diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 6ddb55676a7c..4060d0503462 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -85,6 +85,11 @@ void *find_first_bad_addr(void *addr, size_t size)
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ab44c5a0f7edf21d17c4212167a2ec2ca3f69582.1600204505.git.andreyknvl%40google.com.
