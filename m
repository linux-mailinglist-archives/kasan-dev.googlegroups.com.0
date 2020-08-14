Return-Path: <kasan-dev+bncBDX4HWEMTEBRBF4T3P4QKGQEVSNAEEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id A72A4244DC0
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:27:52 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id f23sf3965026ots.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:27:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426071; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q5ixcrBtsranT7e9gnKVZPyfVUqh4tc0zGBeSmYFVr3p2zlF2GAFK7qy4ThseZ61Dc
         iGNLS9YTvco+z8KY118UyjMtE2HlZDddGFNg+7rZnUpuvKpas/b8iQSdG07ph1R55ZW9
         L3AEV1H2VBbderPM25XXOSKNmPKEyGtBnl8u2DZsuc3b7V+dpb5tcqVY5iDdlTB73uCD
         d9BUKwownlRRVevYvYrTxV8JAwSg+VnhoVJJyChR6GpgQySM+FZGaxHZviOxPiifCcMV
         fXY5u0aNbOZR/8qFaIK2NbVofAkSyUznPxxbBV0GtgApPDfndwxlan9d52X4Gz2lYUfP
         akiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ttk6N/rM57Vjp5zsT9gbgAmggj5EcreKULbGTGkJbtI=;
        b=AzS1INxlPvRrVWa6bMur3ohQWgWK0EIg7CLiQiOgYAeoJuFB+XNMTqM2OAI9v9+PVg
         pI+XJxmEds5ctj4nnB8Wy7qzhdG1jU3mHm1ncGPC3QpScUYtm0xSBfHhkmOjUWrO5QSI
         BCR6U0fBMycQ46uDMBsHJgnBxom0mDRlwVVrW1dXuSr9vDkRJITPRLgguDMnYDdHsOnQ
         RS4SwTdii55hfieGQKpqnAcfpH5/s+YQ148o+O7yo/x+fH8+hYB9E8UdjSrp+mr8ikzW
         MAZz/2GEFN9mAoMcrbDIqD8GmWz+OL4GRuAnkGaSZ0XXgWCW4g/nKzCPww19V3vc5+D9
         KptA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IyLP4M8+;
       spf=pass (google.com: domain of 3lsk2xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3lsk2XwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ttk6N/rM57Vjp5zsT9gbgAmggj5EcreKULbGTGkJbtI=;
        b=smVho7Nz9+iR4nISa7cU9BnsIzQy1bZprR8cXc1b9mNxgyvr/jJu3KKTQiUYAvIOt/
         CmMNsJXZbeCQgh2lYhCznytLiPp7mk4wkoswwXLLko5yse/OOeNsz1gCC/OFg1aJaGbF
         SIgPY/bkyXb03rpTF+wTsbXrOJjNxaYU9MevfU2N+s0nisVcHTSwJQ889CxRXMcYRDVC
         L/ACx7ggkvmTFFYO5lA3f+knEk2pUuIJ/ovTXzKCM/Bvf7hALfQjSpTQoSqcCEOo/8C6
         OUWleR1Vw5vlhNRO2uOauFPMAS9ykncPsXlX4HKpLBIZilZ9KN3EkzjsdnDNNjDJ9Mnp
         GG4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ttk6N/rM57Vjp5zsT9gbgAmggj5EcreKULbGTGkJbtI=;
        b=HgninL5/T7rxdAUxYTr8psDEa6RvrO851hS2uMZMj09t0RQL0vWwg93RerAgrHL4nY
         NdLWAqq9zr0foqTWZaqjDN8y7lo8tj0yT/LIpk2Jivx8EPpdOFRpYcBvcD4WWlYP9BNq
         IsCjAnVgPIkeDaPv3xHqyoWr5P0UaLoNkYrzVaj8UyWKvWUdu3BNXeGWBX4D+jKfF3Y2
         00SoiSMN6lqDQWJ/ZxLwXFUJURo5Hn/h5URK6LqtyearZoU8vtNfnv4Huj5fgWc7Vyjv
         SvlK4gfy03YxQ0PNStzT3R/lEGJRwSNM/Ek7z7FJCIzYGcqIkevDZvsoemkNdiQvEKHq
         h+ww==
X-Gm-Message-State: AOAM531H+Jkp0ZmjMa2hYen/7EmZV88h6vulbLXxngLQoi1Rbk27aPuL
	Xbs2WM7Cc2FRm7Y9HqoKWlQ=
X-Google-Smtp-Source: ABdhPJwP3BCuw0toM53LDrJf76p8MKfnt1PDnvULyIPtgAEug+i43MHQI/Ydh4xaZ2nLaXXfeB4eEQ==
X-Received: by 2002:a05:6830:17dc:: with SMTP id p28mr2768112ota.296.1597426071616;
        Fri, 14 Aug 2020 10:27:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:310d:: with SMTP id b13ls2160495ots.0.gmail; Fri,
 14 Aug 2020 10:27:51 -0700 (PDT)
X-Received: by 2002:a9d:30d1:: with SMTP id r17mr2661756otg.277.1597426071296;
        Fri, 14 Aug 2020 10:27:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426071; cv=none;
        d=google.com; s=arc-20160816;
        b=iW1mEK1dR8TSVv+dMCZWqvgqk9JvGYry8MPgwx/gO5tQg7lu7OFczSyQOGAJ5cTyqL
         Lj5hmLIxSxo/+g/R3vAN9Dyl++yRqpr1B4Er0ENwucI2b0bbvLwVuE0S0VLv/t2+tAuh
         PI/aOZek8WNoX/Hg0+gGlyJqioUlB6yhl8/ddMs0GK1CWZ+Kwb/hQCq8SHBHL3LNDJRQ
         +5WiEA044qTp1v84HknC4SyoKAWszWSLZjToqE8+DfNHYKBl2DbvlRpfDoi5gZ3tl+mL
         7pHioWMyo9hmZqTUqCk9j3KGcf9D1N/dCR2VITMckUQqGZei897gn2ryfraASpm/4gdp
         LEbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qURDzYxfKKWxPHfIySAMFEILXPsGiaC6Jh5hYJk5H9w=;
        b=tH9m3/VkLTkzciS8PBQZpYMKtWi8pcT82ACIK3d2fhAupWsH69MmNCCuUqd/bZz4bQ
         TtCpTJj2C4ly2hGLUgFnb9hXCSkQKOWnwXcWewr8+PBL8NfvJjdBsrce2Gmj3TFn2E7I
         OBxbm39alUegqGppk+z1RLawj+GV2nCw8Hw9jcFx/8QCW+z1iy3/D7k/Sct+STx63CvK
         ik5j6uAB7ol0jqUjYpa9pVuGOVXBJPvxH/eg0k7ufYZnKjIn9YLW/J2TmuTlOxGX+fqY
         iy4X4ZVZ3m1HmAA7jZMLqnMxw1aM5nchE1IYz1hNzRePLDTL0sTZqsX/e7j5pexCYJvP
         X0Hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IyLP4M8+;
       spf=pass (google.com: domain of 3lsk2xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3lsk2XwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id z12si465037oia.0.2020.08.14.10.27.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:27:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lsk2xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id i4so6527226qvv.4
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:27:51 -0700 (PDT)
X-Received: by 2002:a0c:aece:: with SMTP id n14mr3721148qvd.68.1597426070684;
 Fri, 14 Aug 2020 10:27:50 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:53 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <7dc3095b3a29c262526eb7b53b06ee0950b73c16.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 11/35] kasan: decode stack frame only with KASAN_STACK_ENABLE
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
 header.i=@google.com header.s=20161025 header.b=IyLP4M8+;       spf=pass
 (google.com: domain of 3lsk2xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3lsk2XwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
---
 mm/kasan/kasan.h          |   6 ++
 mm/kasan/report.c         | 162 --------------------------------------
 mm/kasan/report_generic.c | 161 +++++++++++++++++++++++++++++++++++++
 3 files changed, 167 insertions(+), 162 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cf6a135860f2..15cf3e0018ae 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -168,6 +168,12 @@ bool check_invalid_free(void *addr);
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
index f16591ba9e2e..ddaf9d14ca81 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -214,168 +214,6 @@ static inline bool init_task_stack_addr(const void *addr)
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
index 4dce1633b082..427f4ac80cca 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -127,6 +127,167 @@ const char *get_bug_type(struct kasan_access_info *info)
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7dc3095b3a29c262526eb7b53b06ee0950b73c16.1597425745.git.andreyknvl%40google.com.
