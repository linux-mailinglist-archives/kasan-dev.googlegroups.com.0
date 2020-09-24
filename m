Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7OFWT5QKGQELXGTLFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id BFFE0277BDE
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:42 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id i128sf365517pfg.22
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987901; cv=pass;
        d=google.com; s=arc-20160816;
        b=OuhcqgNbWcsWLgpnW5rE/aAfF27jMzF03Khe4aV3TwcCYF1ebGDr+I4sVZua41bl57
         rGOhUemMl6kwtOLK/TP4l8CU/aO8RMpWNp5Q4ALNDet41vufUYtWnQ6n4RUIUi2c1RB6
         BS4lCGxWFSCE498RKW7j1Vot7t+PbP83djJunQEdw3Td2hHwuHjYGzvWMKU0cHwiPvb+
         JGVza/Eki9CC6rQDBFN+WD7tq+yPoQgPJJzkbHW1dBLyhBAU4+NMxBmHmqjfpxF1zEFH
         +xx0XyzWjJNE+reWrPOVVSjxluzzHXbLtccPMFXXog8wBKLa/gQppJTM7BsEYEQC7PCH
         QyYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8IBSCISmIkzgF1SG3+pBcyO9wsX3qUVccgvu9bh57oo=;
        b=cumIwEYPP4yL7r6G1ZsLwDG4Sb9e9akUtTnMuJHLozrrInUU0qjqJD1yH/k8j2siSu
         O15p8wu/Dh9uQ7Ssfthn4c6b4kUfbrnL6zs0hKui/udrcqmkFYWAl+Zukb/7H9xL8jqg
         Uk73DQbGkN7Geyjg7UoaRcRxBKFw0bQG4SPAXWpoXnA8CttNWJ2O2h83UvP4kbbql2Y+
         4XLf1pZ9s90GqEn28l3lHmYIv5RPkp6w7ePWVI16RdJq+8ITDK0egg9iNpVGOhxQuD/Q
         ERS4RZOGthW76PMK3aYiBGVAEHv1sXeuYjCDcy9O2dNek5munWogKqC7pQcjiH+Azd1/
         2VTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kFnIVR36;
       spf=pass (google.com: domain of 3_cjtxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_CJtXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8IBSCISmIkzgF1SG3+pBcyO9wsX3qUVccgvu9bh57oo=;
        b=dpjgE2CQfSSga9AlEBdACWWM5D89lChTtWI2V54+t/jUgL83o2gi3eP3k5pLuN8kkD
         IYvlCBVQMv7YrilaHLj7vg68vJqydZe6xc0IYT4BoaqNVaE/l9M8REJQeeuAL6qVXRrh
         yDMKoeQ0EKTsOBr5Uv5kJgLoWbuxvN9Olj8pcO5gqqKHnl2nQawy2PWPl+9x+CeCMiYL
         HFAn7JMoWQJzFrR1T0sTdTYI+HH5a13Wl+07vFAW33uOfb2djXfFbt6awzE+wnRIv0CM
         oxalKxAaIqvOaW2QMT1zvSw/Z8sqpy4CzketdBSlQuV2xhVT1k/EE+Edxi2fvOs3AtxH
         RmYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8IBSCISmIkzgF1SG3+pBcyO9wsX3qUVccgvu9bh57oo=;
        b=GaIy1HVqibzmzACZ1ipWFgNHRHz3xTlaRFaz5yHHd+hOg5pcgtBT6NAcr18on/SDyf
         skP8OQNpL/63o/3ViWQ0xBh0BS7uWbSot1F/PXcBeFnqcu10k7UP0d1HPoAXJMJ9Drja
         vshjrpLFXc3PB/G7conpqRttOv734iuRNWlbmB2SnH+xR4HgYJQQKTPAbk4izJeN0e42
         MoTCzJruzTrzYslFGrQO4V06bzcUcceoqltRiu1uokwK5/t7DBQkdY7iIPK1bpIZ+5a2
         9SahQtAhazQtyPyluY7FIxIfmaaUZ4a3bpaFRUnJd5v5rChLr5oj6vGjwNTnX4WL06lY
         zYTA==
X-Gm-Message-State: AOAM532oKS2sl0XzoEvwdnoC7IUPVNNo1E1pQ3PqVgbEtpmUM7npuA2d
	Id3z7FNa1ifFbByDUDAl+Ls=
X-Google-Smtp-Source: ABdhPJw77IMRfPy+67Ah3vPjw14KjX8c1Zc45Ua5Xdx27k4EkL1dW25CzGiP4hBE8dmd4Ts/J1euPQ==
X-Received: by 2002:a17:90b:88d:: with SMTP id bj13mr1078757pjb.80.1600987901469;
        Thu, 24 Sep 2020 15:51:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7883:: with SMTP id q3ls398580pll.5.gmail; Thu, 24
 Sep 2020 15:51:41 -0700 (PDT)
X-Received: by 2002:a17:902:ee83:b029:d0:cb2d:f271 with SMTP id a3-20020a170902ee83b02900d0cb2df271mr1419654pld.10.1600987900898;
        Thu, 24 Sep 2020 15:51:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987900; cv=none;
        d=google.com; s=arc-20160816;
        b=xr1Ms1py1+DLCXlSCaZzcT2iNKPyhn3oxmNv48GWhgll32mKGu5CmtUk3GDQTeH0rj
         N1Icpd3ulvaUQfJT7pNk+Eh5JK9brookQIhANx4IXqfFDSHlqowV8H4XbdoBTy0ubEBd
         DFMR7DYwoBMSek54+NXPxL0FhcIB0bL/PW3VRC7eamB2FMjGFnVriv8wetbvrPFBWwx4
         OOU+Uv4fmqcJNqwaznJe0x36K75aDVet0qkuHSfiZBr3BdDRUkSIdQ0Ke7kCkSLucMgR
         tnAbOjcKl/spbz98xNHfhvtyeLXq5O5FOqWdh46yNO5m7ZEsn/M6Lv02MmBUTFV01VBV
         RUVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=EXzMwcaXGb4VWDeaFkKIFgwfWPRKhiNtKqAQiQ7Zess=;
        b=lDjiF8EbGUO8aBU/YEwAju3stQVE7PJfBm40Jgpqw1Htur2hdf4Hs9T1K+k1ISZadA
         bP6PJZtij7NtMyI9o0zQMyjZ9tEfPE6h+kp3PGKPcTMHnl6b23A84TbXWd0KhSbKTk4l
         nEdfAZyt1oGTVGZXQHgtmla/plSSLkApwJsTsoMiiK1qqTz32UCO0CfcrvvUR/xt5yLP
         S8RQ4dakHPvC15Ya5p5WxflTCGmxBzK3lSSfkskHdlKmTl4UOd+5CWKoeYJVwHp5Of1D
         QU0N6VpcYwnqlz0oP+wN4mskEXOPvqsiXl+9ePNWnorO5Y1lsvoHaGh9D40PpeDZk3If
         ILkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kFnIVR36;
       spf=pass (google.com: domain of 3_cjtxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_CJtXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id i4si104595pjj.2.2020.09.24.15.51.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_cjtxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id p20so494077qvl.4
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:40 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4891:: with SMTP id
 bv17mr1524924qvb.20.1600987900012; Thu, 24 Sep 2020 15:51:40 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:27 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <494045645c31b7f9298851118cb0b7f8964ac0f4.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 20/39] kasan: separate metadata_fetch_row for each mode
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
 header.i=@google.com header.s=20161025 header.b=kFnIVR36;       spf=pass
 (google.com: domain of 3_cjtxwokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3_CJtXwoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/494045645c31b7f9298851118cb0b7f8964ac0f4.1600987622.git.andreyknvl%40google.com.
