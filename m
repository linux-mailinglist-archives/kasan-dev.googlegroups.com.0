Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRXG7LTAKGQEVH2STYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 53D76218EA
	for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2019 15:12:39 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id p190sf5658745qke.10
        for <lists+kasan-dev@lfdr.de>; Fri, 17 May 2019 06:12:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558098758; cv=pass;
        d=google.com; s=arc-20160816;
        b=L9Dy2QRVKnj9lIm7eSJSHWJNiWJ91XaG3WYeTxhuVZl3i4ch+KMCKOj9YlT5sKe66+
         Kb/adDNHMjNaJAIptjbj3gJUOK3Fn0jb4NVqrBnosK98UpekIXESJDUobgHcxEOPa4Ih
         0pAcft3yS0gOWKvCIU5NFfkKBbuVcqfwaqONg1dlhj4BkMcLy0Lxp0D4jg+hzpy1g7LH
         RRQvdMASG1KAwCAD0sDBd97HnqRi0ru+8LR921ZltclEB+0SXtjsxZayzWKDP/EhxaCf
         AArhW9yqM/E9bwqKI50Aksj2aispuVeqeyDeNarkqn/f9sMtjqQ6uZoWKaHYSjPjOrN4
         J3sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=LVfoz00gn3+SKd9HnaoUPa7CgbOQG5OBMTlIbRviZeI=;
        b=0pdQIYh0GXoPE6ogFrj1vLq5sO4kiZ2KbzBlu+NqJfQZ2ry7XrfzZJZnQaQs2edfyB
         zehp77aJ3VjBZA/1Z3T9GNbQWvAOymF71rjILpcdSlpjuycJI53mGLCbOJmUiV4clOxB
         ezxAxZ9QET9JFRbPc/858m9+ZAsF/boTiioZGyoFeObrAyuUpXLHVfud8IwuYQXBiwPR
         NRphsQNUk9dLHsRAkuHhYm18NYu07SkobpcpJFZkurhCZqh9UCRVVZA9sVRWD+96IsES
         l0wyjFEC1e75eas18dcVPjSh5gyR6vwQZyigCWEFqcgs/RT0OGE2X2NNlnWK972+4HRd
         0/NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QISLHjwa;
       spf=pass (google.com: domain of 3rbpexaukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::349 as permitted sender) smtp.mailfrom=3RbPeXAUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=LVfoz00gn3+SKd9HnaoUPa7CgbOQG5OBMTlIbRviZeI=;
        b=oMoZamL4omPPUR8fmKPZ5cX5ARw+4tjakFhhnvAw4wVJ/vgANLVWp5tSWdXRMGQON7
         Od51O3/EvnXOeQ2TCFOH06H1vYoAlfmZc2jHF/NBRmyKqEAEcuAc9PlZCBao4uysOGKQ
         JmJMNqA4Lm+ya/AJSDDCr7FGH0ZYv7G30vzjQutQ2CMsG2dQ96J8ylTCnOHVtlH+p75P
         Q8SxdyHQzaOHU8Rw23PFHQ+fHoTzsAohMrF6wHJGwoJmhKh5iKawh74Hgz5tibrWlCJF
         LjnZM9T0wVxA+ysRynpuRJ2PbuaBLqkA5BigEgF/OFWJkFLyCmIIadE4q9pEQa7Fhy9j
         VJxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LVfoz00gn3+SKd9HnaoUPa7CgbOQG5OBMTlIbRviZeI=;
        b=JYjn5ho8uSYWjZQqT5qMNK2jWbBbqrhqwJYNgSDFGFOi3mzo38taPVJG7dkd15v3BF
         fJEsoTU9jx81Oz0AMf8gmwK1gWP9bkAX+Fk0dmEAuQ+FG2YsOL9QIbAWQVwDS1B20BSm
         L1it4b4mty4akRG3nRsNiA6oURva7sRUn+iehY6yYdKDrqamZsmkbEr5Vsr+nCcfOiOf
         UAH66x5d7X5Lx6L5mMEBIDt3+khcbuf2CmBujHxgJ0MN8x5Eoe8eOrvS2ZnEwgU0buAb
         0Sd704tgX0eRwZhjiGwxzYNT9khfTKWFHlNk4LmmZ3cwL0PeWHnMAibuCDg78BpAU2ir
         D18A==
X-Gm-Message-State: APjAAAXyh0lf6EbVqV6StlgkBIS1BY6794/PJw6zIYzxhxVEJpr7fI8T
	+6iA8z9q2YZZa5dTKGuT71M=
X-Google-Smtp-Source: APXvYqxvjwMFhh4rdj1ABFGUPBWdbleo1q5sNnT51+MlWj5WC7zKFgc1R9dpmulcyEiQWN8KEUXhWg==
X-Received: by 2002:a37:a0c9:: with SMTP id j192mr11587733qke.317.1558098758205;
        Fri, 17 May 2019 06:12:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:23ce:: with SMTP id r14ls1452438qtr.8.gmail; Fri, 17 May
 2019 06:12:37 -0700 (PDT)
X-Received: by 2002:aed:3b30:: with SMTP id p45mr32263018qte.112.1558098757952;
        Fri, 17 May 2019 06:12:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558098757; cv=none;
        d=google.com; s=arc-20160816;
        b=GFUldjKo8YNb/CcJVJZM6OZ97c4nUBQ8icRpIQ3oDAG2Ri+ZoICEU5Tb4bTF9CDijz
         voZ7aYd1FgNGbTJygh9HJTv9izXNMRegdiM0hqkqzA+JSPuXjUGckBhBhseuC16V29B9
         jhbimMxWji03tZE5Hx49LTq0d4zXnYD0PSp3ZX18Q5euB8POCm+sf2Y4gZ5yEjjMaXUt
         9/BaOf5OERzq2L87ef+dvrKQYze+jpRPDDFVgilmplYC+1T85Ne7EwxISyHnqzygEqno
         b2sTGbh/JVpwWgFi8DIaGCxChMVysaxL+M7q0dQ4JY9cbxaCf8UyrUiSv5DRr20LaL27
         5AvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=FJs+O5o+cz5HCB5KlHNqWYoyNOZwk4659YdHbrsYlV8=;
        b=RkswWBkPzVAmsn4FhCXbFN6wN7A6sS/KL/W58DSgWa1f8tZ58rEmS3Lb1gqJAQiufR
         1c0mgFmnVJNwizUv6RiG5hYiDEG/Xx+qFEvyPYKa3/DTel+GYRSB9yL65H8j1JqhmDQz
         xveazFsgeHYwhnazHKF46oW/rd+itO3SfhOmsS9GeaWEQinxfWkElz4WAWonweouAzVC
         lJWFSOtS0p2X6zzfJhYE+P6HbCL0RDUKx1ReezZ71GSVlQ2s0HMBbuasY0hd+/bfwsUd
         Mz1rfb70x3tiw1uEaxy620CUPKObT6/FwbU15kvCjofw8+IKPUbErFOauHfmVovkR202
         mCNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QISLHjwa;
       spf=pass (google.com: domain of 3rbpexaukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::349 as permitted sender) smtp.mailfrom=3RbPeXAUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x349.google.com (mail-ot1-x349.google.com. [2607:f8b0:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v67si782760qka.2.2019.05.17.06.12.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 May 2019 06:12:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rbpexaukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::349 as permitted sender) client-ip=2607:f8b0:4864:20::349;
Received: by mail-ot1-x349.google.com with SMTP id t17so3278213otp.19
        for <kasan-dev@googlegroups.com>; Fri, 17 May 2019 06:12:37 -0700 (PDT)
X-Received: by 2002:a9d:400d:: with SMTP id m13mr14229666ote.100.1558098757436;
 Fri, 17 May 2019 06:12:37 -0700 (PDT)
Date: Fri, 17 May 2019 15:10:46 +0200
Message-Id: <20190517131046.164100-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.21.0.1020.gf2820cf01a-goog
Subject: [PATCH] mm/kasan: Print frame description for stack bugs
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QISLHjwa;       spf=pass
 (google.com: domain of 3rbpexaukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::349 as permitted sender) smtp.mailfrom=3RbPeXAUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This adds support for printing stack frame description on invalid stack
accesses. The frame description is embedded by the compiler, which is
parsed and then pretty-printed.

Currently, we can only print the stack frame info for accesses to the
task's own stack, but not accesses to other tasks' stacks.

Example of what it looks like:

[   17.924050] page dumped because: kasan: bad access detected
[   17.924908]
[   17.925153] addr ffff8880673ef98a is located in stack of task insmod/2008 at offset 106 in frame:
[   17.926542]  kasan_stack_oob+0x0/0xf5 [test_kasan]
[   17.927932]
[   17.928206] this frame has 2 objects:
[   17.928783]  [32, 36) 'i'
[   17.928784]  [96, 106) 'stack_array'
[   17.929216]
[   17.930031] Memory state around the buggy address:

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198435
Signed-off-by: Marco Elver <elver@google.com>
---
Change-Id: I4836cde103052991ac8871796a45b4c977c9e2e7
---
 mm/kasan/kasan.h  |   5 ++
 mm/kasan/report.c | 160 ++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 165 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3ce956efa0cb..1979db4763e2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -43,6 +43,11 @@
 
 #define KASAN_ALLOCA_REDZONE_SIZE	32
 
+/*
+ * Stack frame marker (compiler ABI).
+ */
+#define KASAN_CURRENT_STACK_FRAME_MAGIC 0x41B58AB3
+
 /* Don't break randconfig/all*config builds */
 #ifndef KASAN_ABI_VERSION
 #define KASAN_ABI_VERSION 1
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 03a443579386..c6ad8462c0dc 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -28,6 +28,7 @@
 #include <linux/types.h>
 #include <linux/kasan.h>
 #include <linux/module.h>
+#include <linux/sched/task_stack.h>
 
 #include <asm/sections.h>
 
@@ -181,6 +182,163 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
+static bool __must_check tokenize_frame_descr(const char **frame_descr,
+					      char *token, size_t max_tok_len,
+					      unsigned long *value)
+{
+	const char *sep = strchr(*frame_descr, ' ');
+	const ptrdiff_t tok_len = sep - *frame_descr;
+
+	if (sep == NULL)
+		sep = *frame_descr + strlen(*frame_descr);
+
+	if (token != NULL) {
+		if (tok_len + 1 > max_tok_len) {
+			pr_err("KASAN internal error: frame description too long: %s\n",
+			       *frame_descr);
+			return false;
+		}
+		/* Copy token (+ 1 byte for '\0'). */
+		strlcpy(token, *frame_descr, tok_len + 1);
+	}
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
+	pr_err("this frame has %zu %s:\n", num_objects,
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
+		/* Strip line number, if it exists. */
+		strreplace(token, ':', '\0');
+
+		/* Finally, print object information. */
+		pr_err(" [%zu, %zu) '%s'", offset, offset + size, token);
+	}
+}
+
+static bool __must_check get_address_stack_frame_info(const void *addr,
+						      size_t *offset,
+						      const char **frame_descr,
+						      const void **frame_pc)
+{
+	size_t aligned_addr;
+	size_t mem_ptr;
+	const u8 *shadow_bottom;
+	const u8 *shadow_ptr;
+	const size_t *frame;
+
+	/*
+	 * NOTE: We currently only support printing frame information for
+	 * accesses to the task's own stack.
+	 */
+	if (!object_is_on_stack(addr))
+		return false;
+
+	aligned_addr = round_down((size_t)addr, sizeof(long));
+	mem_ptr = round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
+	shadow_ptr = kasan_mem_to_shadow((void *)aligned_addr);
+	shadow_bottom = kasan_mem_to_shadow(end_of_stack(current));
+
+	while (shadow_ptr >= shadow_bottom && *shadow_ptr != KASAN_STACK_LEFT) {
+		shadow_ptr--;
+		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
+	}
+
+	while (shadow_ptr >= shadow_bottom && *shadow_ptr == KASAN_STACK_LEFT) {
+		shadow_ptr--;
+		mem_ptr -= KASAN_SHADOW_SCALE_SIZE;
+	}
+
+	if (shadow_ptr < shadow_bottom)
+		return false;
+
+	frame = (const size_t *)(mem_ptr + KASAN_SHADOW_SCALE_SIZE);
+	if (frame[0] != KASAN_CURRENT_STACK_FRAME_MAGIC) {
+		pr_err("KASAN internal error: frame info validation failed; invalid marker: %zu\n",
+		       frame[0]);
+		return false;
+	}
+
+	*offset = (size_t)addr - (size_t)frame;
+	*frame_descr = (const char *)frame[1];
+	*frame_pc = (void *)frame[2];
+
+	return true;
+}
+
+static void print_address_stack_frame(const void *addr)
+{
+	size_t offset;
+	const char *frame_descr;
+	const void *frame_pc;
+
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		return;
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
+	pr_err("addr %px is located in stack of task %s/%d at offset %zu in frame:\n",
+	       addr, current->comm, task_pid_nr(current), offset);
+	pr_err(" %pS\n", frame_pc);
+
+	if (!frame_descr)
+		return;
+
+	print_decoded_frame_descr(frame_descr);
+}
+
 static void print_address_description(void *addr)
 {
 	struct page *page = addr_to_page(addr);
@@ -204,6 +362,8 @@ static void print_address_description(void *addr)
 		pr_err("The buggy address belongs to the page:\n");
 		dump_page(page, "kasan: bad access detected");
 	}
+
+	print_address_stack_frame(addr);
 }
 
 static bool row_is_guilty(const void *row, const void *guilty)
-- 
2.21.0.1020.gf2820cf01a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190517131046.164100-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
