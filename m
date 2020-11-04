Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDPORT6QKGQE37JH5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 950872A7123
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:19:42 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id i13sf173387oik.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:19:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604531981; cv=pass;
        d=google.com; s=arc-20160816;
        b=HWdJ+M5NjmnNXjxgFHhqgd3zXrZ+K8+xkEkWJfRvsag0soT3qTTrhr5Fta9QExYbAv
         QWgtLwRQwjOY++YhrpsYqNDcZFuVTgSNDvajJCmOAcJP7Mp02vH91uLt/0u05MDah8+M
         Z/KpQ+dtUbhJM8sy45zaXJQInG/IXX7WnIx6N2/7E9n0ac2Tr54rrvkr9JR3BRjVbujl
         kISR+4lecVyqn+6ltx9gZJADGcefVay40sp5iBxtXH2NoJLcurf3vIZZfhzbNGS8/7am
         hTQl3B36sb7r3B2JS6XrzsCLiw0tiIpTdrQjengoXQ+aHZ44itCw8QqZ86+rwtyHf0De
         limg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=JIN26MCRE6on5jw34AYYLLvx6sLUSWS/fG4ukZbR/iU=;
        b=EXUlxyHYzoH7QXFOInKf8TDADXIrZKqYI7ohYpVr5L2SCBdbjm3n/9LqjJa+iHdKMV
         OWQDHbJ/+uD1quutLrNPuQmGtq4Gad4YHMpzjqqmX5rth78jPegP7QSJMV5kP9kux/le
         IFO88ixgJusZtzRP71tdSzgNADfv8L5yUSxb+gD9TGb3yhW56WPB9U8Q1ebvhz4VGJHa
         WDO89aXJjNPonu0voh8SIrWDbzOm2YCZshbycezYRZxeF631W1U8MUNFo+mBxCt0Snm9
         g4y49wVUrSw7oBo0D8qvVQRLu2Wgp2Ls4BvaCg66dx9+WBPCE6SvhP2uhFCJUXavySr7
         OvIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FPOiVHLr;
       spf=pass (google.com: domain of 3ddejxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DDejXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JIN26MCRE6on5jw34AYYLLvx6sLUSWS/fG4ukZbR/iU=;
        b=TDor4P47BoN2bYYVrIxXZW/s/1wuiq1LUgVyd29/z1YVY/Y6jKCdgU9qf2aYZMzURu
         iAa6XF9mK1OCYbK+EoamRhhh0o+qHM6anI4QNMQlLG/iM8kpCbS3QO+UClqT1mxogxlN
         tUBt2+YVLKghCgvbZ5gTSyW0g2FI/94M87O2FydsdM7xrzk2bcNvVTkFpHpPpxWvcv02
         6gh6700lekrTB8M+5Pl/4MhxM1hKj4WM9Ags4Y8VL3Vazho3DFRYln+1h5VpryJGpfa4
         cQ0GdwH0RxwWn5whr/ic033IiPRxI2tITcWl0fCMKMWJODsFasc6ROIiPT9ehBk2lBFL
         lEcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JIN26MCRE6on5jw34AYYLLvx6sLUSWS/fG4ukZbR/iU=;
        b=Zs0XZb0xoS7ybNJDm6wUSU81MgK/Dscfo5hKvojqVni9OpN6fYgAbMfvTU9ReHNGhK
         iNpVE3/VuKbowuu5a7QN4Pw9iOFFWVEi2kA0GU9dJS0UkzCkNPC8ItjvMLMht1I+b2oa
         Pt8M464GcZnyILQdEMDVltDQDuGiru/Y1KIjP1afRDp6rsuOK4AkwlpGcQBSRueByXnI
         HXXuEeViCp9VYslTSZO2rRJlGKjcU8WS7H8xlPAhzMOQ/8eR9k5d2pecly+JlYRmNjPY
         JsXSWwE0okovveyJi1yQ2hTd8bqYq5VCTv6xon681GWAR9U07YEIoMxVbF1ecoTo+vI2
         0lFQ==
X-Gm-Message-State: AOAM530aVOGSQDdCHVK82Mf0wFJNvR79+uOLwA61gbJcw4a9yNNL32MJ
	aEeOCxXEG6bSF2gfx0Nqg3o=
X-Google-Smtp-Source: ABdhPJxyC7owP6RA1ancdwwBfScev95pv2S/ETngDn1UWwHlhaes8c4cJ9jRsoeOChKVIvqe6RbSFA==
X-Received: by 2002:a9d:3de2:: with SMTP id l89mr59024otc.5.1604531981227;
        Wed, 04 Nov 2020 15:19:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:e102:: with SMTP id y2ls1005789oig.4.gmail; Wed, 04 Nov
 2020 15:19:40 -0800 (PST)
X-Received: by 2002:aca:c188:: with SMTP id r130mr98831oif.99.1604531980896;
        Wed, 04 Nov 2020 15:19:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604531980; cv=none;
        d=google.com; s=arc-20160816;
        b=eMFABFrB4se3gH7/BypAnDoPCIfqAbh3p/ad46yZPnrmr/QrH+8A8RkBhhhaF8+Ap7
         M8yxaqKRVRdQNZ0+3peedrXvLT+QVNCfDMRut4FD9dI3vT3XSA+cMXpYqPriE6mWv7ic
         T9kwobdENhfTrX2SUIEUVbKOqa+gbQCXJe7uEvae7m0by6TdxUsBzCRIiQpNnBYooDRo
         /stjQ64zQG5Ei96cqx1kqBwaEBzXgIDz+pzTDmzOd/REtbH3BNSrgTQzijqXD81pEyKc
         1sbLu3Qtx5afbswDAbVqXATZqkzgHnoP88uTRZlQaTvD4tz0UuO/Q/IhFSqDbvpqAHn1
         dqFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=QvkWNjZ+pTIeP6RaRR5npkr/lxVIyBDfgnO8C41H6j4=;
        b=Gd6iblV+uaL5LHtGoyFEtE1mDNd+6KujzeRX4PxzZXzqqdsK0xl8fs8PA2D1V/eaGQ
         numNC7BBrUzz+AQ516T2YKk/km0RJ3TZ/YFIcfoFrELLL1BdE/nazjym9DTX6OwOvBcs
         FArX/YhxAfYcFcziHIhfKCBai2vjryDz57TdJzQd6FkR+ih2LSQQnG2EkXNn50UQ12Bc
         DOv4dfZ2Ow1MY+aosZ7/i1+Kff2n1XGtAjI0KNIDbcf2BQqCNUt2FCP0ZN6wJXmqpZ8l
         UTOc9qhk855+6XRYqKIhLZmEnTo707sVuVRgGSJV1sik98OEkyWhVNnDH7Qq93bDxfDn
         W8jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FPOiVHLr;
       spf=pass (google.com: domain of 3ddejxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DDejXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id m127si341794oig.2.2020.11.04.15.19.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:19:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ddejxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id h16so65736qtr.8
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:19:40 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4f22:: with SMTP id
 fc2mr186570qvb.28.1604531980350; Wed, 04 Nov 2020 15:19:40 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:29 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <f59ec58e3d6c9f10743f570083ab7e96f07e1957.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 14/43] kasan: decode stack frame only with KASAN_STACK_ENABLE
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
 header.i=@google.com header.s=20161025 header.b=FPOiVHLr;       spf=pass
 (google.com: domain of 3ddejxwokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DDejXwoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

Decoding routines aren't needed when CONFIG_KASAN_STACK_ENABLE is not
enabled. Currently only generic KASAN mode implements stack error
reporting.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I084e3214f2b40dc0bef7c5a9fafdc6f5c42b06a2
---
 mm/kasan/kasan.h          |   6 ++
 mm/kasan/report.c         | 162 --------------------------------------
 mm/kasan/report_generic.c | 162 ++++++++++++++++++++++++++++++++++++++
 3 files changed, 168 insertions(+), 162 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3eff57e71ff5..d0cf61d4d70d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -169,6 +169,12 @@ bool check_invalid_free(void *addr);
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
+#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
+void print_address_stack_frame(const void *addr);
+#else
+static inline void print_address_stack_frame(const void *addr) { }
+#endif
+
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index fff0c7befbfe..b18d193f7f58 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -211,168 +211,6 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
-static bool __must_check tokenize_frame_descr(const char **frame_descr,
-					      char *token, size_t max_tok_len,
-					      unsigned long *value)
-{
-	const char *sep = strchr(*frame_descr, ' ');
-
-	if (sep == NULL)
-		sep = *frame_descr + strlen(*frame_descr);
-
-	if (token != NULL) {
-		const size_t tok_len = sep - *frame_descr;
-
-		if (tok_len + 1 > max_tok_len) {
-			pr_err("KASAN internal error: frame description too long: %s\n",
-			       *frame_descr);
-			return false;
-		}
-
-		/* Copy token (+ 1 byte for '\0'). */
-		strlcpy(token, *frame_descr, tok_len + 1);
-	}
-
-	/* Advance frame_descr past separator. */
-	*frame_descr = sep + 1;
-
-	if (value != NULL && kstrtoul(token, 10, value)) {
-		pr_err("KASAN internal error: not a valid number: %s\n", token);
-		return false;
-	}
-
-	return true;
-}
-
-static void print_decoded_frame_descr(const char *frame_descr)
-{
-	/*
-	 * We need to parse the following string:
-	 *    "n alloc_1 alloc_2 ... alloc_n"
-	 * where alloc_i looks like
-	 *    "offset size len name"
-	 * or "offset size len name:line".
-	 */
-
-	char token[64];
-	unsigned long num_objects;
-
-	if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-				  &num_objects))
-		return;
-
-	pr_err("\n");
-	pr_err("this frame has %lu %s:\n", num_objects,
-	       num_objects == 1 ? "object" : "objects");
-
-	while (num_objects--) {
-		unsigned long offset;
-		unsigned long size;
-
-		/* access offset */
-		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-					  &offset))
-			return;
-		/* access size */
-		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-					  &size))
-			return;
-		/* name length (unused) */
-		if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
-			return;
-		/* object name */
-		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
-					  NULL))
-			return;
-
-		/* Strip line number; without filename it's not very helpful. */
-		strreplace(token, ':', '\0');
-
-		/* Finally, print object information. */
-		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
-	}
-}
-
-static bool __must_check get_address_stack_frame_info(const void *addr,
-						      unsigned long *offset,
-						      const char **frame_descr,
-						      const void **frame_pc)
-{
-	unsigned long aligned_addr;
-	unsigned long mem_ptr;
-	const u8 *shadow_bottom;
-	const u8 *shadow_ptr;
-	const unsigned long *frame;
-
-	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
-
-	/*
-	 * NOTE: We currently only support printing frame information for
-	 * accesses to the task's own stack.
-	 */
-	if (!object_is_on_stack(addr))
-		return false;
-
-	aligned_addr = round_down((unsigned long)addr, sizeof(long));
-	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
-	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
-	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
-
-	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
-		shadow_ptr--;
-		mem_ptr -= KASAN_GRANULE_SIZE;
-	}
-
-	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
-		shadow_ptr--;
-		mem_ptr -= KASAN_GRANULE_SIZE;
-	}
-
-	if (shadow_ptr < shadow_bottom)
-		return false;
-
-	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
-	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
-		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
-		       frame[0]);
-		return false;
-	}
-
-	*offset = (unsigned long)addr - (unsigned long)frame;
-	*frame_descr = (const char *)frame[1];
-	*frame_pc = (void *)frame[2];
-
-	return true;
-}
-
-static void print_address_stack_frame(const void *addr)
-{
-	unsigned long offset;
-	const char *frame_descr;
-	const void *frame_pc;
-
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
-		return;
-
-	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
-					  &frame_pc))
-		return;
-
-	/*
-	 * get_address_stack_frame_info only returns true if the given addr is
-	 * on the current task's stack.
-	 */
-	pr_err("\n");
-	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
-	       addr, current->comm, task_pid_nr(current), offset);
-	pr_err(" %pS\n", frame_pc);
-
-	if (!frame_descr)
-		return;
-
-	print_decoded_frame_descr(frame_descr);
-}
-
 static void print_address_description(void *addr, u8 tag)
 {
 	struct page *page = kasan_addr_to_page(addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 7d5b9e5c7cfe..b543a1ed6078 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -16,6 +16,7 @@
 #include <linux/mm.h>
 #include <linux/printk.h>
 #include <linux/sched.h>
+#include <linux/sched/task_stack.h>
 #include <linux/slab.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
@@ -122,6 +123,167 @@ const char *get_bug_type(struct kasan_access_info *info)
 	return get_wild_bug_type(info);
 }
 
+#if CONFIG_KASAN_STACK
+static bool __must_check tokenize_frame_descr(const char **frame_descr,
+					      char *token, size_t max_tok_len,
+					      unsigned long *value)
+{
+	const char *sep = strchr(*frame_descr, ' ');
+
+	if (sep == NULL)
+		sep = *frame_descr + strlen(*frame_descr);
+
+	if (token != NULL) {
+		const size_t tok_len = sep - *frame_descr;
+
+		if (tok_len + 1 > max_tok_len) {
+			pr_err("KASAN internal error: frame description too long: %s\n",
+			       *frame_descr);
+			return false;
+		}
+
+		/* Copy token (+ 1 byte for '\0'). */
+		strlcpy(token, *frame_descr, tok_len + 1);
+	}
+
+	/* Advance frame_descr past separator. */
+	*frame_descr = sep + 1;
+
+	if (value != NULL && kstrtoul(token, 10, value)) {
+		pr_err("KASAN internal error: not a valid number: %s\n", token);
+		return false;
+	}
+
+	return true;
+}
+
+static void print_decoded_frame_descr(const char *frame_descr)
+{
+	/*
+	 * We need to parse the following string:
+	 *    "n alloc_1 alloc_2 ... alloc_n"
+	 * where alloc_i looks like
+	 *    "offset size len name"
+	 * or "offset size len name:line".
+	 */
+
+	char token[64];
+	unsigned long num_objects;
+
+	if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+				  &num_objects))
+		return;
+
+	pr_err("\n");
+	pr_err("this frame has %lu %s:\n", num_objects,
+	       num_objects == 1 ? "object" : "objects");
+
+	while (num_objects--) {
+		unsigned long offset;
+		unsigned long size;
+
+		/* access offset */
+		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+					  &offset))
+			return;
+		/* access size */
+		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+					  &size))
+			return;
+		/* name length (unused) */
+		if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
+			return;
+		/* object name */
+		if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
+					  NULL))
+			return;
+
+		/* Strip line number; without filename it's not very helpful. */
+		strreplace(token, ':', '\0');
+
+		/* Finally, print object information. */
+		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
+	}
+}
+
+static bool __must_check get_address_stack_frame_info(const void *addr,
+						      unsigned long *offset,
+						      const char **frame_descr,
+						      const void **frame_pc)
+{
+	unsigned long aligned_addr;
+	unsigned long mem_ptr;
+	const u8 *shadow_bottom;
+	const u8 *shadow_ptr;
+	const unsigned long *frame;
+
+	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
+
+	/*
+	 * NOTE: We currently only support printing frame information for
+	 * accesses to the task's own stack.
+	 */
+	if (!object_is_on_stack(addr))
+		return false;
+
+	aligned_addr = round_down((unsigned long)addr, sizeof(long));
+	mem_ptr = round_down(aligned_addr, KASAN_GRANULE_SIZE);
+	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
+	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
+
+	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
+		shadow_ptr--;
+		mem_ptr -= KASAN_GRANULE_SIZE;
+	}
+
+	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
+		shadow_ptr--;
+		mem_ptr -= KASAN_GRANULE_SIZE;
+	}
+
+	if (shadow_ptr < shadow_bottom)
+		return false;
+
+	frame = (const unsigned long *)(mem_ptr + KASAN_GRANULE_SIZE);
+	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
+		pr_err("KASAN internal error: frame info validation failed; invalid marker: %lu\n",
+		       frame[0]);
+		return false;
+	}
+
+	*offset = (unsigned long)addr - (unsigned long)frame;
+	*frame_descr = (const char *)frame[1];
+	*frame_pc = (void *)frame[2];
+
+	return true;
+}
+
+void print_address_stack_frame(const void *addr)
+{
+	unsigned long offset;
+	const char *frame_descr;
+	const void *frame_pc;
+
+	if (!get_address_stack_frame_info(addr, &offset, &frame_descr,
+					  &frame_pc))
+		return;
+
+	/*
+	 * get_address_stack_frame_info only returns true if the given addr is
+	 * on the current task's stack.
+	 */
+	pr_err("\n");
+	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
+	       addr, current->comm, task_pid_nr(current), offset);
+	pr_err(" %pS\n", frame_pc);
+
+	if (!frame_descr)
+		return;
+
+	print_decoded_frame_descr(frame_descr);
+}
+#endif /* CONFIG_KASAN_STACK */
+
 #define DEFINE_ASAN_REPORT_LOAD(size)                     \
 void __asan_report_load##size##_noabort(unsigned long addr) \
 {                                                         \
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f59ec58e3d6c9f10743f570083ab7e96f07e1957.1604531793.git.andreyknvl%40google.com.
