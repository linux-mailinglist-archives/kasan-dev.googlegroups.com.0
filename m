Return-Path: <kasan-dev+bncBDX4HWEMTEBRB26FWT5QKGQEE75UCQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E7634277BD1
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:23 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id b20sf306106wmj.1
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987883; cv=pass;
        d=google.com; s=arc-20160816;
        b=i4OSqV6CLoNcwK5hH9KiqINnviYhEm4/L7K957PNg0eqR7QIic3PsSV2FKfaBEh2p7
         u4JV8YojdexpHI38qW3ZawfUi88OAzxduH9fiwmuw8PdWAqfTmuoy46aBU0pvzZ4U7Ko
         S+WylxJcBF5WaJu84elE2/2aTXVce+gxftj952cf9j58NYbMeXwHkp0RVVk7qtnbNXMF
         niyoRl0CZ5+vpBa/kKDj/25wsVKygXQ2qQk9e4MaKnZa8lQNjGoMeAGWRgZrlbotkt84
         pzNmgNX/UMtU1E/gUI+gnFaTHfn/6nhO5hXnZdYSflPT6l60MnrMweQB3zpNwQgK+fyP
         zgzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6hPLPhiidFWCadmLghH0GQw6e1SMAy/dH23wqXISOPA=;
        b=Zikfen4OxGBBYmBGalGYnlDnctU+KsFIOrOLY9dmpZ43bfBlYrm7CIi7QZHig5+/b7
         sG/R2NrJB2/Bbb7KBwjx0jAL7TTj3o+rUp5zzFSJKcwzHr5YBae/YXNT9JFPd13pA59g
         hkfo8h7rdOjBbxBBn0xKAjfw0oS4T1lrAFa+qttkGI3TJWvTh6ydOVTjmy+zfjQ73Mjj
         hd8T1mFLECO6Vgt5YcewhfmsKOSuwyDk/W8cXZaSRlWVTM8HFNfHyWZifeyaji2Bc187
         2Unpsx9Tr6HMby0TRbbVGtdHa5pwEpPWAayAS3TEQM0fw1Tmb36Md6vJBERYGKbZ388n
         bEkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y6h5TEE7;
       spf=pass (google.com: domain of 36ijtxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36iJtXwoKCeUHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6hPLPhiidFWCadmLghH0GQw6e1SMAy/dH23wqXISOPA=;
        b=QJ0zRsODJspoA47I6i2yg615lQpUUVJwfAMlDIM9+0mswJDp1cKKXHZqttjtmkIGWr
         XxquheW0m3c5WgcuMOihGWUcGH7M2Q8GVo9oXfsgtA4ZJBQ1iX6HiB/E8SzFALjF+GJL
         P9+sxRQrIgi9GS6687QiJddMnoeEbnID4obq3TpTCBUD3QyaofjY7OqZQ9Zt7XrDNWku
         7sWM20dDRsS7O5xYRYDHYRhy2TL8uUlpdeH4GDSwPJ+jqBTO3ps//Q97By+AY4uErNXi
         OAVEnvChA0U04lx4KXnW/Z8BmTUmhkQReEJo2+gNqYtjWYe8x5pXmKedEYDA1N9y7Cgm
         uv7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6hPLPhiidFWCadmLghH0GQw6e1SMAy/dH23wqXISOPA=;
        b=lKj3Znl/ACFLabbljA/Q96vzRx8lMoksp9jSw4UBCvJP+wXP0YB1pZvXT8fbevhYt6
         7roVfAHx6RQdQTph75snbxtzk78aHGaIQ1lASFBNpPPI6+IIyVJycn7gGtrhMyVhSchu
         AnuoD2v6Bj39uvzyKug6WhOCfTMn6GVMcE6zMr1buKa6m6FV2pu8TOzXWXjRU47wF1TK
         JeR9Gl12iXHUNXJeuMhmLD3pN8sPTCoNvInqTTk1XCXy/tfaXVh6ENbu7QyEwrRj+Y8L
         3ZEA7cGi1qilEPe9VM+rS+97UWN0k4iBVd8kWX1z79RmCwKJ6kTh+sXuXiIxmlWWX6Vu
         VzQA==
X-Gm-Message-State: AOAM530FhHhmB22puAi1jbDGdnWTHE4LJqUSL6Y5yhgkxJjjMRbZ+XOW
	OtZvcNpTOXMJAOK0x18g5BM=
X-Google-Smtp-Source: ABdhPJyME9KlI2wXcKfA+Be98B37odxcNhKBAhQY6IKzxICVQNu+wdftt+7fFNS3e4dl9MCe41H4FQ==
X-Received: by 2002:adf:ec47:: with SMTP id w7mr1243843wrn.175.1600987883631;
        Thu, 24 Sep 2020 15:51:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls1044394wrm.1.gmail; Thu, 24 Sep
 2020 15:51:22 -0700 (PDT)
X-Received: by 2002:a5d:4311:: with SMTP id h17mr1207105wrq.398.1600987882805;
        Thu, 24 Sep 2020 15:51:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987882; cv=none;
        d=google.com; s=arc-20160816;
        b=FP835gJWS0ewqGvJFM6KpdpQpnOi6Q303qZKGYVrtSlxo+gX8Bm6HAVmKldWAPf3bJ
         Ai9vwn6E7VaRkSgjfYytZ8U+RgfT42G+gjWDzuvwyumUq8wxyslDMejtszeR6Z+RqJpG
         34CGBknkq7xGycLVrCY8gcF5bjeP2FLO/v0Sd0ke2ai/SJE+GYQ+aQgr1gsMHoKn+KQI
         /BFWbM5uozJkYKWajR4FuGs4IME3J/qv1r1q4bdIp4sBiIEh7doMSZUUMT2EnAteGb9e
         t5bXPRBcNM6M9ehHOGnTjuCFGC9+pcNE2hag0U3wedctxQ111KIpkycunPwpTVt8FyZf
         45uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+fjL2a5VUlThsJJ8CwdonS7SEk8+oml37aIzFiD+C0Y=;
        b=amwJc1asT+ni7qXRNSaDfqPpWyD7s3xWJGdHWilAjBlNy4NPL4VMoYpOkV6v/T6nnc
         8lzwoCT1gfcfu7/YOS/VQhvB2WtRrsWfp4MmVD38bGVSWt4tpTY++DTROASEItlXS0xf
         8RA1s5pq6k8GynsYmHNKNsx0dU4bM+fB0+Euaw2cn72kmbmfeNnZnt03PpvjB8BgI1fm
         JedNiVIBojDtk6w5Et5ivgn3z0Oam2CYb8+sOJVgcgx66OA+3VUvgKOlAB5a9aRnWuAc
         MheHgwHQdsMpG4kvHHE62LXLN9iM/E18eiyoXQSnPcxYUDUWwlQMBSY6f2gN5oJy8wHn
         rkCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y6h5TEE7;
       spf=pass (google.com: domain of 36ijtxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36iJtXwoKCeUHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z11si29505wrp.4.2020.09.24.15.51.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36ijtxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id v5so280025wrs.17
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:22 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cbd4:: with SMTP id
 n20mr878141wmi.105.1600987882238; Thu, 24 Sep 2020 15:51:22 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:20 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <4f2a790cc95d2ab6400e5f75fa78ff0a0fdd9593.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 13/39] kasan: decode stack frame only with KASAN_STACK_ENABLE
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
 header.i=@google.com header.s=20161025 header.b=Y6h5TEE7;       spf=pass
 (google.com: domain of 36ijtxwokceuhukylfrucsnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36iJtXwoKCeUHUKYLfRUcSNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I084e3214f2b40dc0bef7c5a9fafdc6f5c42b06a2
---
 mm/kasan/kasan.h          |   6 ++
 mm/kasan/report.c         | 162 --------------------------------------
 mm/kasan/report_generic.c | 161 +++++++++++++++++++++++++++++++++++++
 3 files changed, 167 insertions(+), 162 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3eff57e71ff5..8dfacc0f73ea 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -169,6 +169,12 @@ bool check_invalid_free(void *addr);
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 
+#ifdef CONFIG_KASAN_STACK_ENABLE
+void print_address_stack_frame(const void *addr);
+#else
+static inline void print_address_stack_frame(const void *addr) { }
+#endif
+
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5961dbfba080..f28eec5acdf6 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -209,168 +209,6 @@ static inline bool init_task_stack_addr(const void *addr)
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
index 7d5b9e5c7cfe..42b2b5791733 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -122,6 +122,167 @@ const char *get_bug_type(struct kasan_access_info *info)
 	return get_wild_bug_type(info);
 }
 
+#ifdef CONFIG_KASAN_STACK_ENABLE
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
+#endif /* CONFIG_KASAN_STACK_ENABLE */
+
 #define DEFINE_ASAN_REPORT_LOAD(size)                     \
 void __asan_report_load##size##_noabort(unsigned long addr) \
 {                                                         \
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f2a790cc95d2ab6400e5f75fa78ff0a0fdd9593.1600987622.git.andreyknvl%40google.com.
