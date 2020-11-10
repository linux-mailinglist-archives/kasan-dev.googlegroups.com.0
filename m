Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMVAVT6QKGQEQSTHO7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F0EB2AE2CA
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:03 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id h11sf6170530wrq.20
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046323; cv=pass;
        d=google.com; s=arc-20160816;
        b=MkMzmAru2D+Yq/bZQK6ciMO1GX/oATmJ3fxVduV9gA8CWT7s9LEI4t8v0DRWjUqUZA
         7dDOQZ+a4avPBGjIn+CEV6ElNiEPXf1FS3qVyvXUZOa+pRPVkYKS2eJW9VpUGdL7rzvg
         6mHA11VBPdErWwyDYrADnEIkuMbyGqwW/NgpOff/AtGZdtO/syuj0Oo+dDrVmQSMlyKG
         WoVdn33PZIBx5L3rx9lbQuRssOnhznp+oFkal6p0vyaBxQ6wXYncM0zob4YI3BKylHaW
         jHKS+jjIAdEbw1VqTPhX4L3RduF5hLn7FI5KlDzIn4OxGCyzetNlQKSulA7xFxKLTzpU
         Ut6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+7XQfanstBENEF/gLlHYCbDLxi5dHAssfbURcvbNdgY=;
        b=oP/vynJZcS8V5eT775Pdi630+Iy0Hr7Zlu5FouLdHPlIp8j89DGHKn22S26YnSJeSK
         Vrz8HyPgLLWS7R8OTKwHq1SEjZCO1GJcQtzBX46jKtTt8/olHV70NKBdnJp6+b/J2nO0
         oeRdQZ6imeuBGkrbgNcZUyfOlfplRRENE6wyOFelX4B00nFzc15266kMWxL95NnQfCrD
         YXElsLLpXawaLvZ8k9bSYjh1kHuHGe2LWdzhjSKy4GKJP/nl+dWZ8tPQGK385i2lqz+x
         a+iMoF5UK/p1GQZaolFyjfEDi5/b8ZlA6ZUNIMMdK0uLiE556V6/LBgdm7NLmHMaOxIJ
         3W1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g5ZtoYH5;
       spf=pass (google.com: domain of 3mrcrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MRCrXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+7XQfanstBENEF/gLlHYCbDLxi5dHAssfbURcvbNdgY=;
        b=QqD2UPlVCawqhomTx4TY5eBt+Y8Rpptl8qzY+2aH9n8uV+HjRBGZHDnnK9RnScbd4u
         GdjC+xGZmeu3KlPcyiDHILxa6E/eQ8owZtBwNVIJhSRbKrVRgepbEP0+ztZuWh0zUrLd
         Yr4RKGagl85mttbWkKapwjcPPkly//XHAl0ravLqHpCdCH7T5aKs4IzZjvrNskQ/A7v4
         tdmh0sj++U7T9Dty62M50Gs4CjzXjRLovfsceC+NKhizJD+xMfdUs1dQRPrj1LYFIyUp
         EjleHsAtgZCgt68hfQnY8kqvPXSFHvPxJvQ6hs6EwwEH0L+B91K56Z+KaF3NiBpYUzLR
         G5yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+7XQfanstBENEF/gLlHYCbDLxi5dHAssfbURcvbNdgY=;
        b=M4noFNGK7/Du7KKiz7UJiiAWJvCZntCcuMOX6//aREWolFt8Si6OSICajfI5j2pSCp
         Vx9mmKiWLAHSvfHA2b7UQS1jZgMfhnsjJDUUzrLNsXMW/QA8WfdF+rxqD514y+FdEk3v
         jGbFDrmWWugrdHTR6KsN0yIEMl1RmN64lLqY09JnoZInjpqaV1zBd6mXZwjWzzj7lyuZ
         y9AxRLK9DMMZTYdXAjCo4HqrEbUYkDRezGoDmgpp4wBrnQ+IHvGVPcqaeTO8Ifl8vju0
         zpbMO4adH8bRy8Lb0HmPsaLW0SHqTEqI8Dgiy17J+62iG5mt8iImVJpm1duBYQTb8+MC
         u3eQ==
X-Gm-Message-State: AOAM530sd+BPoewAFSXZBFkz+F2pcge4A3dDecuz9SERvUJ51+heGnd4
	EWeDKNjIpi+MDl2kZRr8u5w=
X-Google-Smtp-Source: ABdhPJyGSWtPwJxubojHjxTXmyPNngctm211em47Lda1cB0iyGe/N2RjPVoOyR1gWEyerGtv+S4Aaw==
X-Received: by 2002:a1c:9c56:: with SMTP id f83mr252928wme.49.1605046322965;
        Tue, 10 Nov 2020 14:12:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5417:: with SMTP id i23ls213337wmb.2.canary-gmail; Tue,
 10 Nov 2020 14:12:02 -0800 (PST)
X-Received: by 2002:a1c:e3d4:: with SMTP id a203mr231817wmh.177.1605046322217;
        Tue, 10 Nov 2020 14:12:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046322; cv=none;
        d=google.com; s=arc-20160816;
        b=bURX4/r7QO6PlxHVDBJQyeHAG7/LcSgJiNgYrNHHJVrpmbigYGMvJzB2m2x6GJmQtL
         /4u+G+6k3Oba7bFGMv1e6+J8VDgntx7eSxyx9Wy8b2cf+Z7hsPg3zr24v/2CVo3DTSCE
         J7hpod+HjD9qm7+lV09doNo6l51FUfTyWhSKfP0M1OIXTFlf/sW0z/cxn5OQleCVzUgv
         yUG6dA977VDIdu7iAUlCWbz262eOv/I81RjXF/C7im/FAnyxKBaqPrcwgN8B1lRVV/UF
         WHlPTdJ9i9fEApnYV8q8kazpqmSMUXeNOp/MW/JA7LXMUwWNtNCE6nQfcUj3yBiND0CN
         Klzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=pixfi5iUumW9KxQnVZszmv/CWS1E2kAbwkJEgbZS8Bo=;
        b=RMFws0vUs765XGS8N5sEhXTWKY/xsVqtEkjZYQnoRxV2mUS63QTX4WQx82xsg9nj4D
         0t2cXGM8L40y1J37VJXpb6hIJMZu5j3tYIUsl6SHBfmNeg8PgN9rjHQ07jeQOslf43wS
         Ozcvj0BXc2k2Plykq4ywxpHb7gSuqlPGvTYIoKKtQ2cQNHyF1/KT5QPSGYZ0jekTXDxh
         QUpfSt4/mPskXD60Jk0cSFONlSTPFx2nETW2/ejt7pRR85eguKy8gkDROxDZx3Owbsl/
         Hf/z8FW8AMEWF/oDVWWF2KuLJAL99pOnz8NLSWe3e+iqitOM03hmA1NSbeNq9FknHwU7
         hgkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g5ZtoYH5;
       spf=pass (google.com: domain of 3mrcrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MRCrXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id m5si5758wmc.0.2020.11.10.14.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mrcrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id o19so1864330wme.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2202:: with SMTP id
 z2mr242194wml.95.1605046321888; Tue, 10 Nov 2020 14:12:01 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:20 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <560e04850b62da4fd69caa92b4ce3bebf275ea59.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 23/44] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=g5ZtoYH5;       spf=pass
 (google.com: domain of 3mrcrxwokcqicpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MRCrXwoKCQIcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
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
index f9366dfd94c9..b5b00bff358f 100644
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/560e04850b62da4fd69caa92b4ce3bebf275ea59.1605046192.git.andreyknvl%40google.com.
