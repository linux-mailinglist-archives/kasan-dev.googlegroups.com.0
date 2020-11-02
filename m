Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ64QD6QKGQETXLBLWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A86D2A2F0C
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:24 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id h20sf8725198plr.9
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333123; cv=pass;
        d=google.com; s=arc-20160816;
        b=LToTi02NtumL1ngI1K2y31QctG59UnE5zel3iddqf+wGaApK74StQj/gxLtYVW4xiY
         +AfiOTmK4I8kqNAOyvc6w+fcmgzlZvSRgonjhrxutEXjJ1kgBw310kKaRRb8vhAOiMz5
         utKSDNHXFb1GobP5vFkSrET5I74kywRc5CDHflgMlbc8/RqyzyL3pSdS/xjmPgd2yp/i
         ziWItnVw0nf77WSSGPHbnvypneAL36mIBhVuvxWchP9uaQEjbgfqH4vYJv4hBOBp6hHj
         Fsi3IZXwN8phYu2baUgxI6bKU2II6OkkGPFf+lt/w5UJQl5r2jsyno419+v1ETq6x+to
         Gl7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sDmqMP4cZTsgWW8VPW1Ur/xABtwV4Ynj4RJQnmkDVsc=;
        b=qnH6PBCtrisB5OSirDUtVnr+/ypOxM24dg/UXh9Rfs9L/K+SPB1qmmXlGStmZEfVSy
         24zH5eYJCkDupCyt/X0LYmN3kAXDcF8ag5Mb/3DCTWEA/N6WQ96r95+/d3WKK03csu7w
         7UEypWlTpJgU2QT0buE1Lw2HCGhRO2Ywh9w3TzxaUGomZHSnubsz0NYyyJIVKaMr3mS2
         RF+Pz2cMsU3s35BBlD+8fPkGpLT2HpZGQnKnc5g/vYYdkQ+34OdqNVlnxWUVxBq3drpc
         PFMoSvDhmpbl88UrCxnjTGIqBCCTwvbdcGen2ZRIlie0D3sngjFVd10zkf3PYmJwcfrn
         x4MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k6Gs3D0D;
       spf=pass (google.com: domain of 3qs6gxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3QS6gXwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sDmqMP4cZTsgWW8VPW1Ur/xABtwV4Ynj4RJQnmkDVsc=;
        b=D1NgWY+KWfcuzO2w25zQUdoGw91pEDG2fItpXuSIiE8MWZ+C/8mQrrg+weKGz8fX6w
         KWsE9EqI08vC2ZdrbwO69drK0Crmf2HZV9VTezmNhVgkstaDmWVlNZjjsC42h5KgRs7T
         v9vKAB+jix6ytoS3vyZJfn+zN+vEHmwV10KarE+390n5Jhy0xPh7IMi0bg+e7LgQbOw/
         MQeprU399dZUf6RZVvqwNY5HGmZPJQDtogViO6YxJ807+HllxP4EUNpRYXMrKi5XF4eS
         D6lVMdPxNBwHCWzQBptAwlU7MuuLz/jGmUqDHdOrhRFLhdED+YIA3pMHFnIy5K3EyPre
         1plw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sDmqMP4cZTsgWW8VPW1Ur/xABtwV4Ynj4RJQnmkDVsc=;
        b=XXfEmGstKABqw92ENNBt95bwupGxP7HYUYWoiJq0vnUiezJW/SGli0Row3Y+EQQwN5
         Htw13fwzUzxQjKrBYNulUJVRMgfQ0Zaw9P50ODMxWCM9BxpLqOxv8WXB7izwne1JkwV1
         8VD0pw6ZrI/6N08xXZhL0Hrv4Ve9tCV0OO8kt2CTIKgf2Rf6Nb3pWspZ2dbPHGjlsEUO
         1NQ5RqBgnP5EMj44jYUwwDuHAuZX5Dq3bN7W9Juoqd5LKuiVGsA9Zjp5vjNwLicrbZ5T
         Z6KXUJ6cfsgdbmEfMtNORaTfOX9Vj4D2eFgW06cl6aHIv/cwljyjMBTT6g5Kq98iESsO
         CxTw==
X-Gm-Message-State: AOAM532o9HaeFKFCGtlYDKo1WQn1F2k4RbkadzySs8ea5PjiitMfb6qj
	CJosA2L+157sI0hFvl09VmU=
X-Google-Smtp-Source: ABdhPJz5Zl1v8Vcc8lujGy1qM1+Gdqml6rNGUpZ7mneseyzp27QntA9BIX7cyaNygszff6KVVucsUQ==
X-Received: by 2002:a62:2bd0:0:b029:18a:df0f:dd61 with SMTP id r199-20020a622bd00000b029018adf0fdd61mr7250518pfr.19.1604333123141;
        Mon, 02 Nov 2020 08:05:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6815:: with SMTP id l21ls5128954pgt.11.gmail; Mon, 02
 Nov 2020 08:05:22 -0800 (PST)
X-Received: by 2002:aa7:85c3:0:b029:156:78e8:1455 with SMTP id z3-20020aa785c30000b029015678e81455mr22015896pfn.68.1604333122595;
        Mon, 02 Nov 2020 08:05:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333122; cv=none;
        d=google.com; s=arc-20160816;
        b=YjiZ8QuKrXzlIKqeD3EMs/EgMPRol0Pl4Yu6osZm6gQay/07DmUGeM5/vZV3oPN4+3
         3kDOMSQ3XAL4JGMMuLz6N+cuJNwsvPRN3qwH7C5wYMFe5sK7XBijlJ92AryFg22YeZf0
         rWtSCfdPrJPMmauRbkN0Iy5+WmFcGJ6PrnEwTcyHmBCjiJX4YcmtLr6DpWleuiiiqfVa
         nqkrY5Pny9UcwXRO/UZqRhJ6P6ZrbHAddw4AvqseQUnPU+5sgXPU9jdexBnxzvzdKOdu
         MSJbNlM/84dor79bsABGrnmlWL5fWqPytC5RVNofSFfnzeN/qyVicvYXtsT7AcTRICEo
         IMTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iHpQ8PxT6dfu7tzsqA6eVqgC9qjPb3cyL+5EvuQcjJY=;
        b=u0KAOMzjK5FwLlk7kDBh3mWzJe2YIdz5lYpNhEPM3pgVhVEvqS2ue39cz2p3MXIYKT
         Qa7mOZbc4iYQH1EmKUyA1XFX79ahvOzjDTEqYNuKyQZldVcOLHNwK2nOOEci6x99wkBR
         Lsf4J6+VpFIPo8rqpp/4y+le5JiJGuErvnOKfVcnequjCPFYJjQn9WM3EzTNFvw0Q6aZ
         yBcmlo0jCenc/KAntenGlFSdP5eU0YN6soAhm1rsBs9+Q0ie+hXjP5eaFp2tKNdSyBbK
         M7LFSFv8YD7KNwjxsPYFs2UViFBPhVSzLBKoEzRaZbZx6SJm0axiSmoknoxaRVCuw+HB
         1RAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k6Gs3D0D;
       spf=pass (google.com: domain of 3qs6gxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3QS6gXwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id k24si880404pjq.2.2020.11.02.08.05.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qs6gxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s9so5876899qvt.13
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:22 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e65:: with SMTP id
 z37mr22563915qve.39.1604333121654; Mon, 02 Nov 2020 08:05:21 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:03 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <9242263410372be053a728e2a059baf61e8235e2.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 23/41] kasan: decode stack frame only with KASAN_STACK_ENABLE
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
 header.i=@google.com header.s=20161025 header.b=k6Gs3D0D;       spf=pass
 (google.com: domain of 3qs6gxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3QS6gXwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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
index 04df1481a033..54fc3fac9779 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9242263410372be053a728e2a059baf61e8235e2.1604333009.git.andreyknvl%40google.com.
