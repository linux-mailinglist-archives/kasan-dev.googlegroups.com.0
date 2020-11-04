Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIXORT6QKGQETZG4UPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D4A22A7132
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:04 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id 144sf249743pfv.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532003; cv=pass;
        d=google.com; s=arc-20160816;
        b=kYf0zWRFAB36cQNxq0a5jvec8GmRKQesXglb/lJnY2UjhD2gIjTgbjLjMxuhb3/Lya
         TMT90EIP3zD8hfQPMkl8HS+ryh/QVmZf60GV8r8b6vAz48Sp2ow5IwqlsayCDJBIGKTy
         S5KKXakANXsHg53XrkkLTk0rW39CbgNJaexX22um++zr3y5cdvrKHOS+SIkVeCAonJuI
         sQgOjLsmR1LmYwKl9JRKmubhMmexPjqC3uTCpzTiKNN8+0a2f9a6elS41Q05yNpm+zNq
         6Y1FLqJ1sq+D+g5iaqIv5qI56LijWbXqrtxUej4KfIHYZdriWPd7nQrTS5kKSr+ypJxM
         8lGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EaanmoaChKJ9W7g7sPHinpugiFI0qn+gnyo/lT2vzBY=;
        b=H6S/nY3YB4DsW5zMGsxt0CyRIgMUjyK6EFYHrJHGRDav+QgzDCuj4eFhzvF7Uyff4v
         mJgsuPtNT8Uti4PXmrDILCv9ajBuYMaCI9yinaEjHBknuP84bzzLf3d2x7oEcDXLrySq
         yR6XdcjPUfLdEeXNgaaiMMPt+C6OspT4welNgfBYoJD7ahYp23G9cPmCA5jFvylugex2
         D70tm214OJzf9+CxxgqwICQsM3oDzuZqitbgeqbe6Vr8wdxotZGw3ODxIHrfVSMLITLY
         sqb+3enGB9jBYKNuP0WUOVFTKdXdjzxGQ6mO/lIa6wKeXnhI1A+G/MGbyAg3qIKmagJp
         Em6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nlq0ae6l;
       spf=pass (google.com: domain of 3itejxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ITejXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EaanmoaChKJ9W7g7sPHinpugiFI0qn+gnyo/lT2vzBY=;
        b=qezHQAmtDjpc9iyTlcC5N+RcfusnXOaI0B6Bqwrf+/EIZmIJ9Dcqisi0+C75hCotOO
         9+d6UtAJyRypJ6TCisaUFInDYI8VEqQge7JqZY8R6qGxWrHEw6PXb6RSXWrBHrkvJ5Y3
         /Ftt+pke6+pXFH7vDWGHrAB+RjiolDffyBr7DpjXcMw0j7XRNjEskf8Xj1tabYJO8QUM
         sD0eUUy5xcl/ip/vcThuf6yZ273fR4PEB2wGuip/Yqk52S37oZFHMRYT7rHqT/DERUMr
         HL8HCZukgHBKJA2iWh0emC8Zf3v2pquLB86wL2n2fW7UI3F17UXP+bmInv2j4ySGw3Kv
         zfeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EaanmoaChKJ9W7g7sPHinpugiFI0qn+gnyo/lT2vzBY=;
        b=Na/RVlwxEnDS1beqOV7eOmyN2JpmsTUQ8bu6jyfA+AgSSN1U5qavwsPXLxNgKRKBie
         Tc0IoqknvRFcSGwG2LyIVhyAyOthnRCGfxlur4UzL05DkzvDBrmbp7vu74sRk5FI388c
         4IIuIubcJVyAf25Dchdqij024gV5hzMb2xNyWUwJywtL8Kmql+hYn51f3qiRIaBDkNCy
         FtPklUFFw23WvLx9/v5LQtpv0ciRK++ShnIGLJO8idcniVU8sIapLss7Ji3Deq38UTyP
         46ummEvLdDMu1i17CkYmENGz6sQJw5pJNnzWYmGchFhDjrAwzBw7Ln0KO3xQ7R8+4h6+
         R41g==
X-Gm-Message-State: AOAM533fDZ0Wo0KEk3OX6+TocstE1G8wvyJAz6jp/MfvT9ZEQZDJPVC4
	Ha6KdgXstDOImCRekLIkStU=
X-Google-Smtp-Source: ABdhPJy6oFFFXXFkdduxWVJWjuDIOVyBNGa6nTDy1dtFXEsQHfPXKaLMsXXfOYJ2dBTwFEEgwiFHqA==
X-Received: by 2002:a62:e40c:0:b029:18b:ad5:18a8 with SMTP id r12-20020a62e40c0000b029018b0ad518a8mr182791pfh.16.1604532003112;
        Wed, 04 Nov 2020 15:20:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:543:: with SMTP id 64ls1369381pff.2.gmail; Wed, 04 Nov
 2020 15:20:02 -0800 (PST)
X-Received: by 2002:aa7:950b:0:b029:18a:df47:ef90 with SMTP id b11-20020aa7950b0000b029018adf47ef90mr322838pfp.74.1604532002471;
        Wed, 04 Nov 2020 15:20:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532002; cv=none;
        d=google.com; s=arc-20160816;
        b=qi/H52UVFHOlphtU9UGPQIegdTH407dDmTcqAe1vynztKcixQCFZMgzZj7YURa6zQr
         b9XYhLSF8vmoe82h8y427mLBwwJlCklQFmP95uMocUkkCKfXxKa7cR1BIoAqfKtblmLQ
         mHtoojKA/J1R/VfeLKs3Wgq3EPJahxO8+gyBTV5L5yr9NJlyVy8H3lwMfF3RUvb6QSkG
         cKvlL2mkyIayCMopP2JJDtx7Hyx+A1s47rM0PAPQeMzBbLfBD7UvH8lvak0LYI2WLqI+
         oxtPYLJj2pFGtTo5rVWKzmL0S1YtAXnuZvY0cEuiVJfvEx4Ma7mayBB0E4SESdijAB4o
         BFLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=s8weaoqIU+OhPShGjW212iwVWBqAcMiIGQ+gi/SNz/0=;
        b=WGQhfU0RAtOo3OwhYIA3wKlPk6HrMHfhghGit1QV6kqedwMBmITXSTJR0RuTT/fObW
         2R5GoEKs69FmB0fZjeb0pakq5Sy2MTVkNt/dyKs/2ODbOztoEm53s9v2+/irwFPbdfGe
         vyuFZAHNFRglsV25O5QQMMNe9khuETNBdXPdVo+RN6F5tF6KBFvQN9vqvwyGoIagsNYW
         gngAxZQXonZOrgPW6IP6j+i6iUewIfR9Or7FC2mJjD33jRALc7ZFpHX7bKnVmVh98blj
         3mEF0DRwVAhe/beiY22MQngTr9wsOzRreXgDhbG/CdP9+P5vCVAztVx8QtbEF1nVRFon
         FsJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nlq0ae6l;
       spf=pass (google.com: domain of 3itejxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ITejXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id p12si254367pjn.1.2020.11.04.15.20.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3itejxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id h31so57989qtd.14
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:90e4:: with SMTP id
 p91mr205477qvp.61.1604532001587; Wed, 04 Nov 2020 15:20:01 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:38 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <8282ffd32780b36d85d86c71aac226f485c930cf.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 23/43] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=nlq0ae6l;       spf=pass
 (google.com: domain of 3itejxwokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ITejXwoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8282ffd32780b36d85d86c71aac226f485c930cf.1604531793.git.andreyknvl%40google.com.
