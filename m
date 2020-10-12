Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6UASP6AKGQECSZRBPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 88D9828C302
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:46 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id g8sf7120243eds.10
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535546; cv=pass;
        d=google.com; s=arc-20160816;
        b=oVnUgmh5t/oMdC93uT39ZuZ5MCLplw8XTtQX5XzPBzAyoWArFDfOfiCq6H1ppJHO+7
         A3qIHxlnGUl8LEOdQRcEKzqh9NFxCa7t/dz1FbWXAqfGSJg4qmYMkeXwaUd1co67EjSX
         TzGl7h7dgoVMToTKbzpxC8xCrjuyME8BevlAsPdBC38dT9zsfqjwE0H7JJsyNLkbn2CC
         ytoYuq5IAssqUKDHQtVvpgOlf6dozRO4Jczx/moaEU8kfAmDdMitDvtsKFRkrukLTw+5
         MBPP6M0PCqMaROOEiGu9fO/yEjYRMR0Lwhtdnl8UAOw3qWgBCi1jYdF6s7va5MJKtWee
         ju7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6Y/JDNNkvpokQv+nR8QowjGcMdHEZmKP+FtRxPhrbaM=;
        b=0TdqNdliWfRT/j8voUGAcljsHqT/EllVt9nv8OJK9kkawyTyowyApzGlHj7VNAgtVM
         agd9Ij3Ttj/HQAX+I4x9QxfqxJ/0p7ZYjR+KKSBMRoSqcfQGp7xR7vLc2HNTfaHLNAqU
         uQZxQbnUeTfc6m2MjZOEejQQpq8tp8CQ1ibvqBbwsyfLxNav1LGR2iLinr9CaXG8RvST
         coSgub0iYmToqzR/SWlxlyxiUtrlAfsZbsvXNWOvADDBTEeq+NtkY8RQtCavwnqvePyj
         VDUMs3x8aXQULNwkfrYGZL1sIqUznUUewrvBXNdoGRCcpV2NfopLk7TaavRRj565iEXQ
         vG5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hq93Rjjf;
       spf=pass (google.com: domain of 3eccexwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ecCEXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6Y/JDNNkvpokQv+nR8QowjGcMdHEZmKP+FtRxPhrbaM=;
        b=juFeYrFwTfr8D2r9s/9kLpIf0AEENZJRJOEH3zPHV3M8bOAac7khxjRnn1taleR0tH
         ag9+7t1AeLyO5VNlSJylcB9V7040NdFf5lpbFCvGHpBkEEdc8MVZ/Yse5jqiXFOSGNC1
         EMvCKllAuBRREgF1cZQz2esEi0jRDL+yuhUlxYtLfZ5zTsBA+mM9qmGqk/6nBV3kNZF0
         Yhi5rrzITgG09yqM2g6KMnbfr8jU1ldhvcpbw2CYQbSDEIg+3ZXcdneBo8YqKEwzq6td
         C1FHy6vpA2YvNQWG9k7BPq4jP7ud4qbkU8Eg7k0Mpv1QF3m38GeJFva4h9GU6AV5SSpG
         v/eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Y/JDNNkvpokQv+nR8QowjGcMdHEZmKP+FtRxPhrbaM=;
        b=iOdMSoEAHyOVb1fDdRdU9VS24rwMxp4YV9GKIkqHzUxenM0Z4m2527n6IQNGe8YQFc
         WoOV8ujuy0OQyGh7xeoVaR15gHLtTq7abcdklp9rbNNBfV4b3nu0OCMH6zIb6eYLwRW5
         uluR483qoFQ5wKHipG26HQxsdFCGcxID8tc2g+1kD/3KRbh8SLjNwrBiWpDod7YkT+LD
         V42GkRWwp8diBeOcOlDoMdciGHd4dy6F6Tr1/4jMRgavlmSwW+D5IVZr5UsezrQCNGgP
         AuK69Wn7yUH3HUNibRMedkDAmL5nUQMih/9hvL4q9sBpRjivd26lQQgMykPvHJ8PVwtD
         093g==
X-Gm-Message-State: AOAM530SDeqVARUz8gzqsJ0/Y4BIvoEQ0upk8vnu7KY5lZviCzHvoM7T
	BTl0JFyJQzWijA2ze6ob2u0=
X-Google-Smtp-Source: ABdhPJwv4JEl26vZ2dB6VoWNTE6pUu+sLz5ufFJVKijgjYt24Q60ibGS8ZD7/PkF7TzaDS6PnzqKKQ==
X-Received: by 2002:a50:ee19:: with SMTP id g25mr16792409eds.160.1602535546281;
        Mon, 12 Oct 2020 13:45:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:2158:: with SMTP id rk24ls2343703ejb.3.gmail; Mon,
 12 Oct 2020 13:45:45 -0700 (PDT)
X-Received: by 2002:a17:906:55d2:: with SMTP id z18mr30897515ejp.125.1602535545372;
        Mon, 12 Oct 2020 13:45:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535545; cv=none;
        d=google.com; s=arc-20160816;
        b=kC4gNOkk4A4RijTQBjQlhvLYxMIMSprdEFY2aCIuiQdLdvSdB6KrfpSGW93OP8ftoW
         m13o0A5FSsRZVW9t/CercDskD+RgxRwxslezbhwNJtsvOvTtTDjyTYmImn68STucDTSS
         n13codyL3ErYInxM+JrB0pyCMns9whBWIs6ID8y7UrsIteyMsKYEQjiwqLBlP3bs6r0r
         d1xQboyJGwE3K2CM7FyMVzd3BhTAGsoXlDC5oXbnUdssVG1jfRQVFeRphyl5jnNo76+b
         bRBT0d7wyDBhWZL44b7+kX/4F5296jMTJxCyf4YLF4MuN/wzwXAPlybEO2F2fLWHfxES
         3VzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=UKG6h207lQbcg3gKz90R/6IRTBBh88nMOsYwnyoNErs=;
        b=kO3BO/bkNqKiBpLaGLBDU+O4msiJAGSeJLltgzo3lyC5MEePPY0ZVLaJmnIkX0bpNU
         EiGeUIM7ebMmA63+oehNm5yQpbWBdCbVvboLdsECfmEeRO07a2aiqEI9N7cxh8flaZy9
         8H8jtT7pDeOdLy9LePiqSI3f/CeT3tl0cyA4iceivTOaynFqSimKw1GCcAsXpUCmO5ol
         Ih1NEGD16vfhzBopFn5+aeOev/zMa0OUPDEe6ymcz8Tu7p9TZnBvVjFCQG9aBdQXVkLe
         6SGmSe3iYxugXq50ejcC+X4xi8YPmeh9dm1Jqcmc8YAi/OM7Bl1iXWQ/Z1ql6v03pVx+
         kcew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Hq93Rjjf;
       spf=pass (google.com: domain of 3eccexwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ecCEXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id u2si377561edp.5.2020.10.12.13.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eccexwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j15so2149730wrd.16
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:45 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cc17:: with SMTP id
 f23mr11676450wmh.166.1602535545063; Mon, 12 Oct 2020 13:45:45 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:28 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <d6018e46aa6b8f9e39c81ba5704e96f8d2a57ee7.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 22/40] kasan: decode stack frame only with KASAN_STACK_ENABLE
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
 header.i=@google.com header.s=20161025 header.b=Hq93Rjjf;       spf=pass
 (google.com: domain of 3eccexwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ecCEXwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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
 mm/kasan/report_generic.c | 161 +++++++++++++++++++++++++++++++++++++
 3 files changed, 167 insertions(+), 162 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 325bfd82bce4..5a69472eb132 100644
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d6018e46aa6b8f9e39c81ba5704e96f8d2a57ee7.1602535397.git.andreyknvl%40google.com.
