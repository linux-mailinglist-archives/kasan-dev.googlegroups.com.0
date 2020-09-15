Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQW6QT5QKGQEJXK74PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0334626AF55
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:51 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id k13sf1723378wrl.4
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204610; cv=pass;
        d=google.com; s=arc-20160816;
        b=CY+slGoE6JYpHtV8vq1yvxAtAWj/RVDSuHWoMVosNjX+zklkHAFZEbxjf167Cr1RSk
         064Vta63Z2b8eBVEDnen8YMPnVKrLH0bC2wN32FztaEA1zMprLB/Pae1ySlLpbWmJoHy
         P3sGTjqX5sYTd8yZki49zefHE8QMOVM/onc5ssP/WWg8OOA1OHebNIyc2sJMGc9aku/P
         /r+P0MCU8aHI0OfvfuCCngXbORiDTbUr48hTl2bs7LRk72f4VU/xrWXqqjiLJhHuOxoV
         mK2rLkJqz1cDxhTtlwH995gvPQvP76rbwoq3MwwOPFIaS8KCsGJGzp9egAje1STXBt6d
         Jw4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qTlMP+rmn9OhVXTs7chylSPHlsBSl4LowdogZwqiq84=;
        b=T3ZG5ziuq8RbYKKdmJ8hhTarTuMxwpWhtoXHfvemnTgN3eBt95Uhgz1ojHu7SEMiiD
         n4Jmg5siCaQ00QW0iK3a5jMVv17wAiWANAk1nsCmDeNyL3oWb9MfCZXou+Cxu0NsRz5B
         wV9ATNUu6W7q3LnAkCx53x16ZhTtSTphDUtI3Y2+nN47Zlik0Qn0+xvdNcYzQqP55UDK
         DSKgy7BgbHJSxMYccs/zjk359akyZa+XQUqZ/BsxJcAAWeXqKsJDRJLuos8Irvm9dJKL
         EUNO9VVXCGsryg560JDWjrfwYlDphYqVhsBJoCkhjjX12YGRCQrLavRGd2UgLkQYp4cF
         riaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wlgqfbdc;
       spf=pass (google.com: domain of 3qs9hxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QS9hXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qTlMP+rmn9OhVXTs7chylSPHlsBSl4LowdogZwqiq84=;
        b=WvCrQ95j/BtVvMZGhGrILU7WM9EDTO5QThiVbyIW3PLD+FYRFs/PKRTXDeSL5CKpaL
         nyJUTtSd20f8Fk3DextF1ONR4IDvJXyd5UGx43Ps/V+71VP4PqBDInxuvm+Q5qz/8rIQ
         DL8Lyx3rEJiBH35yixg3OnL2OD+h1FCtCRAqZWQ1vCTIeekWTL3zU0wk6d7rqJ33eK7z
         pvY7W4Ga3qE94qDkCN/8nr9Rgz65X1bIb+pfquIQAbL8hY1jEOPvI4u814VaLrM8CH6B
         s9ahH8lx2ddVGzO2bLKeVN128Cptgn+Z++qT+9hVhhqucBSFbq2gOc+fpoJ6aME5zb63
         drTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qTlMP+rmn9OhVXTs7chylSPHlsBSl4LowdogZwqiq84=;
        b=me/C2mmyEYM3GbL/qOE3GR0TqRY1YOae09m2Ghr8uyoAEMgGf5sCXSYLze6QFSHex1
         WBUJ9jmLR/cNoHRSElj2bv/gRuS/5Hy4TJKEJo+F3MM6POIqK5X9kj+67jb1qRDladQJ
         qLLcdJZcGsCBOVnTGj7HqEXG2OWSZ0UVDVuZLEqlYwQxUyxHZIMr7oVe+Qsl+9hO9kc0
         AkLUfuWiMlpu+RGV7KXZCWcee9orxbwFlcec8qCQr2hlNrgNQ6ZfwU3qNFnZKrZuVKpZ
         RA5ZmrWXoTy7qVRkckK4VSStfWHjJE5WYcKdpyrlX2JFycHru04T/SUj+gX0NTYp8j7j
         HzwQ==
X-Gm-Message-State: AOAM530E+sys9lZ0efiBHto5jVa61MPvaBdpSpc82N/UW4qJ2m4HrstR
	3jULnUf2lVLppOicLl5iwXs=
X-Google-Smtp-Source: ABdhPJybyZCdiSNn/QcfNdoojZ+uPXlvAGdRQrqYfJ1c6c5uRFVsToEkiH68JCuiNYVcBfQWRB1moQ==
X-Received: by 2002:a1c:a5c8:: with SMTP id o191mr1245036wme.127.1600204610728;
        Tue, 15 Sep 2020 14:16:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls339148wrx.3.gmail; Tue, 15 Sep
 2020 14:16:49 -0700 (PDT)
X-Received: by 2002:a5d:4c90:: with SMTP id z16mr24758674wrs.170.1600204609909;
        Tue, 15 Sep 2020 14:16:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204609; cv=none;
        d=google.com; s=arc-20160816;
        b=a81gDW+5ILJ0ucO3Z2ue02lRUE0XipVziSo/lEWHIxL/m8rTdPLwWN5loNSFABetNp
         WZDCY27QPY/1oSbBW2hibiPqv2fBJqdsgZSLQgqne6ApPSIXM2azM9pHXCwUGKiapUTS
         Rf4Nd79mYEmccixS0u9JwpnHlI0U5WEhZpWp0uctP9kxtf1TzNN79i+FqT1kC7TTRuyD
         Sixxb1u+B3lVZjcoyMEWDXypq3/GKXVORglPxUw1lC7GXweTiUHMTnLW4AWJ9BpeFTto
         CpSZKbKDeuxJ9bEl3ZACNXv+V07OZ/o3qVWsitSAbqOzkH59gqVytQMp0B/lkZo4r281
         VHjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=il1SIhPFx0Iy9ZzAUl8CD9DH1Fd3wsEA/MCT7vsJArk=;
        b=lKHFwZeX5SAySePiAgOhbFYtAiV70WcbXZkk4RgM+Yy51oZ5zaHwjhOXLOoLFHNpL1
         tYeF3MYUcfa7xyKHMh9db4LkrndsFXNm571bRfjzlYn+L51qHEptz6ebf/TFPbt8CFxX
         U0pt8tVLtEVWenHkG46h8wN7su1QDo/olhyZSaYKdABUrREgzLgNDg1laKYgveUrxmdM
         6ApO9HHFTp9yXPgYn+fp20MLyp1fYwSkcAr/DDZbtKgqBlI6wwYVgJnrkYdG++cgcBfx
         0vtUBGtm7YV65o+YAwF8qFsHSfl9r2NyJhNS8SsLC9ABhTxAgOlo8/bRFz4X0pSceysA
         w1vA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wlgqfbdc;
       spf=pass (google.com: domain of 3qs9hxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QS9hXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b1si22788wmj.1.2020.09.15.14.16.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qs9hxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id f18so1698653wrv.19
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:49 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:6404:: with SMTP id
 z4mr24456902wru.423.1600204609523; Tue, 15 Sep 2020 14:16:49 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:53 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <525c5a6baa12f976590e27afce132dd14bdd0b0c.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 11/37] kasan: decode stack frame only with KASAN_STACK_ENABLE
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
 header.i=@google.com header.s=20161025 header.b=Wlgqfbdc;       spf=pass
 (google.com: domain of 3qs9hxwokcsycpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QS9hXwoKCSYCPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/525c5a6baa12f976590e27afce132dd14bdd0b0c.1600204505.git.andreyknvl%40google.com.
