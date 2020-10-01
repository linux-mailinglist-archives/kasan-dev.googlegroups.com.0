Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJOE3H5QKGQEMEJYWCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 611A0280B06
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:11:34 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id o6sf133360wrp.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:11:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593894; cv=pass;
        d=google.com; s=arc-20160816;
        b=GCMhp2XHNw+Wj+xfgS9w25lNz7BJVIbvEMFV9hB8umwK00gitxdT/jT0C4aIM0owO0
         0c6d4g3mDRwZZuSvR5GfxNtNF6ujWkGxzn16/gqDPAdXnkAEXivOV1F89/Em/kc3igUI
         56T/uPfKyECdsKRg53IttcG5vM//lbhn+wkBEJ2XWOViwA5zmTJCa6fuBSFe8myWiELQ
         nltCTeG3woN+O82CxD02Jg0emoDhXbFQ1OzOKAeRPsE9cvQc4PpNZZt7pJvy73PkYBgb
         drEKlnYdtwMAFaUgEhFW11IwwlGqnVqKAhran73lUtAmMRzLX1Iy/YlNTfw8oODoJvU7
         3N0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sLl8Je6AaTBYJzZvZtvXwMzadh3u60HKz62Hrl8B3Og=;
        b=GJ85HIsMUVtgEDExMOG9kdXwERZtVhlcc1MqoHPEkt/rBerZnDa8GsJTc1pVwqS3OX
         D4mBOzMf5zCFLNRl/S1fs66NnLc6WQPsTn94oBu25d5J0a/GKnckBMnWSBeu2PLzDI/+
         VSzFZvG2FywN1EckJQIJB/oNsOuyA7P5KXeL0aLY/14qEP6ZweIQd7y3IJtgplPtMpvZ
         9suBAmHm3QWBH1qIJA0LV7spEC17YCeXczs9ew6MrshsH4wwg7KOIWmuRKQgK+s/4jDc
         jbd+rZLrbXtoIwNfnzFGJ3AQyp6Wv58af4T01hqDJUukyFDER7Z6khG+YL4P8JInl9CD
         qHJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RuCpNWfP;
       spf=pass (google.com: domain of 3jgj2xwokccmjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JGJ2XwoKCcMjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sLl8Je6AaTBYJzZvZtvXwMzadh3u60HKz62Hrl8B3Og=;
        b=O72H/XEEtq871RaI65pVfEr9ylRCYLjchqNifSLSTsZm1MBFtCfbpgNOA9VHiR9xdg
         JXRmhIjOvvCXCQpNVdTYTBeO+t1071jVxkEZ3ZC33jONb0APFXgpU3npvFUyNrO4i+Sf
         uTwtt8BU+y8madC7gToTX1otNwAq/XvNelLfJogPMD1YsgRzAqrCvUqAgDltfXDgLYnb
         25W6w40QoVO1IN0MzXW8QrNAC9SDDK7GLrNeBmQWS4HOoz7F/wMVF7nQeXNJM+ZdhOUg
         oaaaBQUphiQfMXX2kWMHNiwu/5QjmraWJiOmLeEl+NTZ2atNTooT9p2QJl/Sb46gT317
         lfJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sLl8Je6AaTBYJzZvZtvXwMzadh3u60HKz62Hrl8B3Og=;
        b=Eq7Qch5lGx8F3QeLwuFmlazxjzSxbaHQ58iQDSSZ6GlRmbKHlGvwW5Fl6sSIu+75/E
         N3xD/E70OpUQBLguBmPPWbRgkludscSRY05EqP8VbswgtqszXEMSKbaG8NnsGa549uHh
         0HFd5cKuNsE2GK136HTenMIH/dCoBfJQVgyoD40i+Cfb1UXfsdFyMv6KKdraOT0uJ/7T
         m9KXH1t+zuGNrRh9NdkzRHFEN6pWErN2tNCSOg4hk/bcI3j1Dd5gSfmA7wLANZkFUX5/
         MTI7HuTn8gr4tcQ/kObU17Va49N3JRYCsDDawCXKQJZNshc1l6aD8G+AvJJp+uyYH4Ao
         nSIQ==
X-Gm-Message-State: AOAM531NJC7lpA+0dPfACKYlst1gvOtDW5hNxlQAERPTKuWlcLBkJlVs
	NSteP3aDd3hSUCJKGC1Pq3w=
X-Google-Smtp-Source: ABdhPJwmcU19XJsuZ6DJIVNoPf01jh9Bgn29IM+HEjT8RFBHjm7xw0GBjt1z8LGHAKl6Avm1dFYhnA==
X-Received: by 2002:a1c:1f87:: with SMTP id f129mr2377837wmf.182.1601593894075;
        Thu, 01 Oct 2020 16:11:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c2c1:: with SMTP id s184ls3642288wmf.2.canary-gmail;
 Thu, 01 Oct 2020 16:11:33 -0700 (PDT)
X-Received: by 2002:a1c:5988:: with SMTP id n130mr2373725wmb.95.1601593893250;
        Thu, 01 Oct 2020 16:11:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593893; cv=none;
        d=google.com; s=arc-20160816;
        b=Wh0pXM6GaCP2ivtcv6XotSX+kt7XskmEX81Gm+e8LR+XVhZ8Iw/zFsJeXBzn6geM4a
         4r6Aq53JycuXubkz6ABxdb4Gk+3MKxlQVzlt/ley2VDgOBTqaktkNmYcnie7k/Su8jpN
         xiLh2Aceuruqmph/7rav4HoeWw5MaNGBrnw/I1PJ+zfR0fuZVV3vnNAa98L3IonYYH9+
         sDacnFH/AlrRA6rD4n+q2abneJ+F1xSrIr64pWCok4PfPZ9aGDpNkunczNut3j5PdLZZ
         Nq8MKXa+p1q4jZTjQJ0kXF4aICppqeGaWzEn8r2r7Nzw0lJIqTf7HIg7gcL65UxULjo2
         cJzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=e1X+1Gk9Gw61swv4CGvlNiC/e+lwR8VGoiXC8dmJ8Ms=;
        b=kDZpCe218o5/2cOZESkaCJyehzq1L2HoVxegYlmfW1g5B81pvgB7JVA2OGshNFxm/+
         fpOV9RLphEOsECcnBrzoaQJuX/vFN6zwbvAZVBBQCH9HDOyv2atF9mzigTffJVIfavAu
         QFOTCJwXCjODOPC6ICydOI+wd5equD1YrfXshuDz6p31ffwHfYkLBQ4/l5hFzKdkwZCg
         nvZdUQA1Wsr3SpESCLD3hs5IXXfiYPYQnbAd3kE9ClLFEZiEsUu4JDJ83Js8Z9amPOEp
         tVWLQ9TW8tw8LacHhJLUnuwdHLHwvlAKqYNJUT6+u3Jplfy6WRgpSCplohmc/mmAAkqM
         y0Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RuCpNWfP;
       spf=pass (google.com: domain of 3jgj2xwokccmjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JGJ2XwoKCcMjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 126si30946wmb.2.2020.10.01.16.11.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:11:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jgj2xwokccmjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id d9so118527wrv.16
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:11:33 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:5f54:: with SMTP id
 t81mr2358090wmb.142.1601593892722; Thu, 01 Oct 2020 16:11:32 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:21 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <23215927d4d1b861ce11de0943f8158fef121031.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 20/39] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=RuCpNWfP;       spf=pass
 (google.com: domain of 3jgj2xwokccmjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JGJ2XwoKCcMjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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
index 0bf669fad345..50b59c8f8be2 100644
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23215927d4d1b861ce11de0943f8158fef121031.1601593784.git.andreyknvl%40google.com.
