Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF5P5T6AKGQEAWHLUIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D859D29F504
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:19 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id v7sf940353edy.4
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999639; cv=pass;
        d=google.com; s=arc-20160816;
        b=f0Jl/2OEyPP/Cl0kYBB2mghmz1sbj1igr5JEG3G4MRo0XscAeWWQfnzODIi/N7bgx8
         zKKEG0nJb4RU3Q5WZ1n/AAgriazIkt3/kKBtTg4xMW9yF5H00zRhIOMP2wsJjEZ+XoSV
         XmjDgTfCcx2QJ+qPVeyn6VYHztz6t9ZfkyKoB4bI6Dk2GGwt5bJ/SmAQBOMEhaIuLKEp
         cj+F2iKxYQj7QS5gqZ8fuGW0Z9Nfs6npSWvkH2JmU1GcdtvN7Z645uD9iTfod6zhtfLN
         NHjANn/FSSA/fxDu5CHmyo7M+pIaY8hutuc7ZvWPw5zIFIhyMIqZymJmZtyQEcmPNFnb
         RdOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LeVVavUayk6opNVjg3NJc6PD3REazdoxJYEtzBYfcxo=;
        b=zCdbUFAzNQnvxq20ys6MX43sCVqINjNGPOCNiYR2O+bblIJHVb7FA3V+cb0oJlVbj8
         hx6wrGHqaWBXNjBUmlt4OCqwLh4OiGvTAVEYaINa79kiNXZgoDuxhSnMWdMARdRa1u0j
         ClHfgxLmIyxrIGr7+HJ4V2jMqP+5LOb62HKSmWGzgh4BPlfqu7D0xvNHMcGroWgdiS14
         RGH2NnT4Dgss7elOICjD3VSNfBWlYXDrxXm9g89sSHUTi5CKCZw7nsoDvjLdAHJkzqPZ
         a7o2rZEInhyukD68m358DVZMOi50AsZakBfLd4K3wsmL50PIUMmkj97Bw26aSSybZiri
         fvxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qtC8GJWf;
       spf=pass (google.com: domain of 3lhebxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lhebXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LeVVavUayk6opNVjg3NJc6PD3REazdoxJYEtzBYfcxo=;
        b=ir/4zL5vNpAtIjIzp6Gap7IkGP3QnjOynXY61qSDzqTJpeYdIglHZLTTJJpkUVFlRx
         uO1xDJI46cArGJfCSbHM4QvclZdhcsyX4uofbG0pUunVVdCGYKgjYVW/sgFp+6+Xvgn6
         CIwFsao1USixHd0oukl07Yt2FjXEbzFvx6+YBwB4gvnDIqAJsoP2QunYyhSfWZJkCrWZ
         wnQJ0V3GRcAIaNH3Z7F7kt3+P4/5XgzsUQZOX63fywSP9cvWX1NsWpSwPKb7TM72I6wT
         0QXmC7P/7cH5irZrHw79jOVXxaE9j5OWURN/xTii31lR6uEtcP7XNvdM2vvBCUAlLr6E
         z0bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LeVVavUayk6opNVjg3NJc6PD3REazdoxJYEtzBYfcxo=;
        b=KqaYdGnJdpWzrSQIqA2+Kf+EGO0ZCT/+0vj0rDZAyWhje412GnVErQB+dkmJDzKyyP
         qAkU7sgenLdLm1Qtxx48hOiS9hQXeLReL4f3WVIwXeO995KJweSFnP1DvUKaSLGjcTcN
         xUYCFE783X3NXy7O8/fdesKndAjDlMUeH6GcIpmC/bSyauP2daFmH5mdkQKikAanw8l4
         6oWNeC+tSFGyH7+62SQ8oyM2ItiRztgg9/6L3silFWpk2xe+BkF4oEbD6y6lpDjgHC6y
         VU7aLYeNrL5kPR5ksXZ2zaz7GlHBGL4Lmd4bi7PwnP7OlGopMXCJe7wTGngrGgSgmG4b
         aC/w==
X-Gm-Message-State: AOAM533pSoLRWcaEArPtk1h796IlU0mjp23sYILizcu/mVKGVPMdoYWW
	y5QxoAQmth7Jnp3/qRu4GEw=
X-Google-Smtp-Source: ABdhPJxTFtmZCz6sAUntNPykg7/WZLCKFgqZ30cA5cRhJgcRwtc4aQQvLp8eGvY6YtJKP+0qjBM8yg==
X-Received: by 2002:a17:906:4155:: with SMTP id l21mr5848023ejk.204.1603999639647;
        Thu, 29 Oct 2020 12:27:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:160e:: with SMTP id f14ls4139620edv.2.gmail; Thu,
 29 Oct 2020 12:27:18 -0700 (PDT)
X-Received: by 2002:a50:f0d4:: with SMTP id a20mr1074002edm.303.1603999638747;
        Thu, 29 Oct 2020 12:27:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999638; cv=none;
        d=google.com; s=arc-20160816;
        b=fwU++Ew8RZUUAMoktOITaQmHrByEr1b757/UmJDSIcgSEI1xcLKm8Dl35MpJFpoBZ9
         mrK6CtdcADXB2xZoTxPeZ5WTOij/eUPfypBK5Qofm5bMeh9sMfBZ5bIGD2TW0KkYP3qx
         NKXAXqIiRaqyfH0H7Vwbhp2LlZbhZeFfc/dLQUXoDk9tCTXTllXw3/JfL26Sf5tgUMtg
         CPnADAE4Z5PRTS5lW+eQ2qd9WDUu9LKi6lpe1qxem6NWTfPoZrarT3KmwqeP3JJq8m+J
         AUxDy/voXvdzCMFJXLaSfJ8R/aJbPTmWyHDbRdqja82NB9Z6kAnqPbbSXSjNIro3Khoy
         LA2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=D6y+CIC0Y2l9KKg2KkqeRy8uKjxk+iaHagkhiWZoA3A=;
        b=lj79Qw9j+UIGuZL656MR6vnW9LmQdiTVegXzYzVOwzo/nfCrQSgjajnEpoLJPqUAuk
         eTv2TpL2GmSumdk8A+yimyYGUhiFNxap1SdWcWLpuysXHeMZFKTYQDzlE1ozW7OvBcyT
         f0v24/om4LPyqY9cJBN5d/VnC/Sz4yOBXyclKAje3zu16BImbtj612VPTSITtn9Yx57Y
         LZuDXowLvG1n5XKz+HUoNjpSuRl5LNET2YbC5jnM5THdv8AtgMvf2Uka5eyhRlYeNa/4
         uiA+pWaTAp5QsGDNtZJIP41/O+9p42RlDjqpn5g+rleXqGlXjwDFbjWeT9W3XZwZmTbr
         qA+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qtC8GJWf;
       spf=pass (google.com: domain of 3lhebxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lhebXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id u13si52884edb.0.2020.10.29.12.27.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lhebxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id 33so1660963wrf.22
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:18 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:d3:: with SMTP id
 u19mr788879wmm.150.1603999638356; Thu, 29 Oct 2020 12:27:18 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:50 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <24cab955674f7883355a68dc728014c3a0ea60a6.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 29/40] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=qtC8GJWf;       spf=pass
 (google.com: domain of 3lhebxwokctureuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lhebXwoKCTUReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
index 139fc52a62ff..0c1cb0737418 100644
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
index 363afde3c409..dac312f65fb5 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/24cab955674f7883355a68dc728014c3a0ea60a6.1603999489.git.andreyknvl%40google.com.
