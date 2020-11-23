Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2FN6D6QKGQEBGQC4BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 663332C154D
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:13 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id i3sf1064358ljj.13
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162153; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZIVnty4QnWUmVQoBMJfDDsqLgDBlIl2Ng1dA+3kJ9HydZvO8uNfIq0GbzsNHc5QeyY
         EmPKf5Qv03wjZEH8AqT/5WLndxQ+UkRJh/cwm+1ZVAfHWJ+TmMWEF7lb5pXxNr2SwiCg
         rKC/zJzhL6H4nsG3eHDG+VZPQdNjgmNU6Fx4cMp0f5N9u7+pOcI/sOXxT4fE/HVm6AJr
         KjuOYw2nPJDocNn+F0ke9LFJg7rZ1Vk45H75CKCnuxeSPyigMis4g1Q1KavfHl+nloVK
         +i7cNGwf4FzL/m2WjpMrx3l8+mI18JEcYb8Dy1cJWwfTTrtXtey0u3K/OAXIxoVCG34Z
         Rw8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+2B1oEkOgwU6MjW5khKkY30JgLJ5lMinJnbd6qliEQA=;
        b=jKZ8AWg7XGquxpFQNffIJXfjQxECDrjuwr1eEpf36C0RH0jG6CXiBUNXIDaCI2ugMS
         OLEPiZdJxo5pEJoFNuK50VjpeViNriCF4fwC6lQIV+wm0uhMDHGFP+gxdEnJec3+NCMt
         2Gl7V5D1EVSdpJOEqhpPJnTuaUAxIxQZCF3KrGcRCEE9+ct70LeGtACzsl+wG8VYy6dW
         iw6msVw4yYVPhadtipwCsOnAoegrxB17ITbpY6WGz8BbqDi5Kb9Jiit8WLH7eVi+k/Yf
         KQQo/Cth6Jt1n8DV5yTNCLg+GLHHYv1VAJ68IJ5mN6WY/2oguOQKSu+BI5HMOfOFOfrv
         M6ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bVdbd24i;
       spf=pass (google.com: domain of 35xa8xwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35xa8XwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+2B1oEkOgwU6MjW5khKkY30JgLJ5lMinJnbd6qliEQA=;
        b=gfNXqSrDylIo454+lvoi6E5J1v6QIsQi48F5A0fThWBu3HMfgMSIFiglU4xTM1VEJO
         NjQ0tA8gs36CftikViKoGY5y4W017K0wGLYdwxxH7hExQ7CPoDKnoyODzT1xezKBTvtC
         ZLVIQ0svMCvQVyyytVUsL4CYtbqqp0tvGljmqdGTIFf1MecJMeivKcLsa0Aw7BqzGsOk
         mlz9vzC192/j02CCU9qQszzJJ7bOMqeNCS+ASLL9IIGilXRIZKptaSLWf+V+7oDcP4xJ
         vtqssPEd006U6/YIZT1IVhkkqBNuOhgvXjtsnzLMvCtFnSpbQQ1oUWm9qDNL2CQmmJmB
         UiHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+2B1oEkOgwU6MjW5khKkY30JgLJ5lMinJnbd6qliEQA=;
        b=LfMHU4KQZ+Nr5NAscPnp09UngdNl4PrEkQh9euErBXCF/Ft+bOgbGiacihWf8z60CN
         kK79ZKLmwBBtQj7JtCY4E+AlOQjpbji4wdDjcQT/IRB/o67Ax0w55pSjyzI3gWLwr70j
         xnyuCt346bG95G1stRWwL+HOjUeec2/i4LDMK2ub8SC8ebn0k9W3/MviCF3geDDipp+2
         RXR9TF3ZASRlbbyckImFx09MFRsyJlrHpMebml5VKNz3Ap7a8RoRL61wAYDVJ1lRqNbh
         VZa8wUfqWnRE93scDm4Yz9S7bfx1E6ILV+8vmLFNzUomCz1xx4haW/pgr4Dzi4uTMebk
         6fhA==
X-Gm-Message-State: AOAM533vGOwIOLb6B/a+LotAxfxAGE1qc89bjts3Du3bnpqAH3jSQ+cJ
	XUeLjktlkHlNdG3qcq66iSo=
X-Google-Smtp-Source: ABdhPJzyWNAGkmYpPTIJcau9wUaBQQ2nAC7oUszMjZVLgidp0XvhCFre3s1hpvYEpci1+smPvtpw8w==
X-Received: by 2002:a05:6512:14f:: with SMTP id m15mr350046lfo.514.1606162152975;
        Mon, 23 Nov 2020 12:09:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58ed:: with SMTP id v13ls2558853lfo.2.gmail; Mon, 23 Nov
 2020 12:09:12 -0800 (PST)
X-Received: by 2002:ac2:48b7:: with SMTP id u23mr345157lfg.327.1606162152112;
        Mon, 23 Nov 2020 12:09:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162152; cv=none;
        d=google.com; s=arc-20160816;
        b=OZ95J/D+rUPVzfbiaKjST835K1f0ri1FB19Djm05x/UB7C6LaVFZLgGedMFcNz1ViC
         l0mxhJqNUrr6WxYEMHdPGU2xqB/1idJndLKDcnTlCbG1jOzuGL3KX08GU6e7BTBu7REP
         z02QhmeoGcvs/58HVJQpJIOH0XuF03Fx/DRylFWCq+loCOCqVxntMzl3fvbd+q6UsAu1
         94E8Qw05HgFscBG5GSNCBAXgfGgKqpiV0D7Qb5FmM8/swLqJL3jK9IM4rYCW97NJUkir
         fKOJAIcvLTHa201t3OiWpVEDs32raxYqpHJ4aooKALkGKRxqfkxe5QPBlQNbgUASImPu
         Hg5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=sJ6lYDMOzh2s8bJA3IjWtOTOyr6/j6k+VQaTKZ4N9N8=;
        b=Wgdg99QBWPeABAO/5hdsy4MCIgKXp2F6wmtJRV6Q/aLvpbGQaTbUy7iaIYkkzpCivK
         9aw7eJEevt5cvN18g0GCWIhBVz5aAVhgSSxduhESh3utckZ9dpVkrkiX+BN7m/oZ/fB3
         JleLu9EwR9KTvZrTBtJVCDCSPSgHAnfsnQrfCD5nl+blzyKdWlE/JBk1cFJ8V+vTQPkw
         ZCXFLEMr+lY1NxMEC4vIp0hfO10yxqHBeWn7Kf/10MM8+Y/ZqsCfMSUmeN5GfAuKrABF
         LrY6ysDd+Y1m9wmVTC7CQ4PiMy+QPRyVO5tZWVrVr7OJKkkLe1YtLyzGWL9OWveHILzG
         yYGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bVdbd24i;
       spf=pass (google.com: domain of 35xa8xwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35xa8XwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id f28si21669ljp.3.2020.11.23.12.09.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 35xa8xwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o203so104835wmo.3
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:12 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3c44:: with SMTP id
 j65mr607928wma.13.1606162151581; Mon, 23 Nov 2020 12:09:11 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:45 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <5fb1ec0152bb1f521505017800387ec3e36ffe18.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 21/42] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=bVdbd24i;       spf=pass
 (google.com: domain of 35xa8xwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35xa8XwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5fb1ec0152bb1f521505017800387ec3e36ffe18.1606161801.git.andreyknvl%40google.com.
