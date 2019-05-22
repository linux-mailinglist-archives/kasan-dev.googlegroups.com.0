Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGF4STTQKGQEK2KUHDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 5141726128
	for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 12:02:01 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id g19sf1486949qtb.18
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 03:02:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558519320; cv=pass;
        d=google.com; s=arc-20160816;
        b=RzfiiWB/Pl2kExuSLImCMygfn5kRaZSbld+CrGYbNqRtElbsSQ2+yQj1TxBVMM+BG+
         UDa5CYmblvg3ZYLOL1u6eAeXIiF2DHtqVelhSQzo6784m8OALmtSgIsu5FiWmC9eoL6v
         M82dfz1DdQnMWxFMihWWYLPapw5psTg+1YQKAsOX5nAA/x1K8uzfLH1/k34J2mR6zBo+
         RM0w5h3Ts90jt3yKKoJWp/VXuKtHIPcqagA4Z3qZGzgD0sRd2Q287SEGv6oJCty/5Kv5
         Nvo0cDsEXNtRYg2/qmxfsi4i41WYIAjtIuWlG1RJ6nJ13zGcplqCo2O9o7RYEA94drR4
         syYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=fPZQe7xY/ai2GBASFyevzQD9HxeM0QASN7NAQ2y5zSU=;
        b=C+xLbxVyeUl7MZy9l+SCOsfFH9+0karF6eZ22oixdY3oVijs/vqPeq4c5/xG4TRGdN
         2I8mnu0wx3Zo4/A2/1xVZZ917xL5jD5LTViH8RK3jX6SC9dxqsiJ16uTDsIY1pcv1Yzl
         1Vj5YRn7inmcrF1ded3Ix3mytZUpN4Htz7fNZc9tgYhPWLH3kAk0X93Z6kl41I3k/DEX
         zMODtgkdZgU0LqX94LmzxvBq4vB7r34dDHwdl48r8YABN0P9WbWM23BxbAD5Ey6WalbM
         1yVRHFGMRes44cT5LXjukY7SnKYCcEarSdPthtuWtE8ZGCp3K+ENEM7AbCmtWwuOyNyO
         6MOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mwa0/Ji2";
       spf=pass (google.com: domain of 3fx7lxaukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Fx7lXAUKCdQ4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fPZQe7xY/ai2GBASFyevzQD9HxeM0QASN7NAQ2y5zSU=;
        b=QESe27I0R+y57iqsw7e3dJqC/Zn+V15ef+CgLumC9pi2kPKTzvP7qfAj6viON7ZKO8
         8p4dnYRdaqjcuoHP8X1QVKGZ+kVjDJn8YF3EB31cN9J/OJZuzaY+AvLjDCREzBuQtsl4
         IG9Tv1/ps7wag+0YhIryFi09pX/klEnEvoxV18aKVG2onw9D5p/2rLGvExPLk8r6VUvK
         CRY5ugaugeyhc9hD4ov88uib448N1PL1yt9qWeQDJoqHUvS09WjCiM5k8I8dvOSQPX4O
         ZckDivOBO27ZOtcddSZAoEuNdqeC3DMzp/izqy7BH5YBewWGGN5pHAfcB8uXyxIp6S/N
         5dgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fPZQe7xY/ai2GBASFyevzQD9HxeM0QASN7NAQ2y5zSU=;
        b=JPVA9FtlATJHXq6Ua9aQhT/bQFAS/FqB0ddmkKjsdF8szShThotyBQGK/QPcH6mb+j
         P5Wf2VbM23g5Ejbs+UR2oaxAX+sYYRXrwic1XW0Kt0TKhloWs6RDMm/nbfbn/EkTlSS0
         qDoOjw/ruEq/wkPguLsfC66nk5MYovoQFFGzcE0rRYmJ9vmWNLPT3/I8oUVqKzh/3/M/
         JwVkvKeMpGid0JE8tFddF/d884TOS2tbLM3PxOyAuwiaygIaWAP29kMRxKDAo9zOQ1ZU
         4Beh/kmH/3J9598wokhVueRTDH6DH4rnBRCWuw7Yw9j654219GMstgdQhndOsO2JJOHX
         YwMQ==
X-Gm-Message-State: APjAAAUU5lC7TflpqHDWdvRmHWpCItuGZn0WYTNAxd9ge64sVKKhFiX1
	7NC3QQ976dx1RCxUAtqoaTk=
X-Google-Smtp-Source: APXvYqxITPImeXONXS9uz3qy0fpps8rmF2FTzxlDi+zvZ8HeJ/xtSe3OphANQsZRWJ0k5drf+YDA7Q==
X-Received: by 2002:a0c:aecd:: with SMTP id n13mr62316100qvd.182.1558519320111;
        Wed, 22 May 2019 03:02:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:ed15:: with SMTP id c21ls466990qkg.4.gmail; Wed, 22 May
 2019 03:01:59 -0700 (PDT)
X-Received: by 2002:a37:4804:: with SMTP id v4mr49070921qka.330.1558519319832;
        Wed, 22 May 2019 03:01:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558519319; cv=none;
        d=google.com; s=arc-20160816;
        b=KHf6if7I9XS+HueVd6zeHT9pWC1j6oz/ohnkeUnXIoKbOtbsEAcfbbgsd8hgZDUGhj
         bsWXo5d7VH2h278yqfBe/JvW5KXiF0a5BlMKu2mOgJpDB9IJaoVcCi8qsJrwr8xVZSfb
         xwQwOJcEUZqJOIRBM7URBVQK+g2b8wIdQ9uHKUiotyNWVgF88dHv5toUMwN05FdiA2c2
         DkDfuUiKThbBrxPLW2sdkhYmfJ4JWJKCUASxaWt/vtz3BXELb//R/12i0/WQrF5MwDrD
         4lIGT3bfcBAoX+xGe8Om19ktnNOXKDO8fbyYnMaq5HEfSvc/zn1ZXlAZUlDhm7mj+K+A
         UfRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=YHDO2phcBlcC8egLCS1LoSqogxMYR/g87S2UaCiOpn4=;
        b=CY1FlBghOeSvxCzrKKPZBNHhwpJ8YknOpdaZye4Op5ZUAhkzOejaa+K0DdRQXrWXA0
         fFfvcRRbMLneIGZ9S7DZRfeKbyX5cWK9siTPb9ojTE/oKgVlbfdhBtIHEHK1YA0zvF8V
         yvs/1TvG8bWcWwNkJqvWwY8GB+ugJ0FxFbLB5fmFvFBtHWwg7TnkOGY+CkqHODxSScUM
         aPJyRTtRNxOMPglM6NyObbH95tZN0y5jprqfJBdjYyq8OVGCrz/NoFNXNMPRA3jr9ary
         ggBIda9EUGWGoRG8r8BoytLtXaM1ccFegyPvC9NFoujancxQAGuljDIG2sGI9orJeBKH
         ECWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mwa0/Ji2";
       spf=pass (google.com: domain of 3fx7lxaukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Fx7lXAUKCdQ4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id j35si1381792qta.3.2019.05.22.03.01.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 03:01:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fx7lxaukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id f25so1734052qkk.22
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 03:01:59 -0700 (PDT)
X-Received: by 2002:a37:4cc9:: with SMTP id z192mr59997831qka.198.1558519319575;
 Wed, 22 May 2019 03:01:59 -0700 (PDT)
Date: Wed, 22 May 2019 12:00:50 +0200
Message-Id: <20190522100048.146841-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.21.0.1020.gf2820cf01a-goog
Subject: [PATCH v3] mm/kasan: Print frame description for stack bugs
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="mwa0/Ji2";       spf=pass
 (google.com: domain of 3fx7lxaukcdq4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Fx7lXAUKCdQ4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

Changes since v2:
- Comment about why line number is stripped.
- Add BUILD_BUG_ON(CONFIG_STACK_GROWSUP).

Changes since v1:
- Fix types in printf (%zu -> %lu).
- Prefer 'unsigned long', to ensure offset/points are pointer sized, as
  emitted by ASAN instrumentation.

Change-Id: I4836cde103052991ac8871796a45b4c977c9e2e7
---
 mm/kasan/kasan.h  |   5 ++
 mm/kasan/report.c | 165 ++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 170 insertions(+)

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
index 03a443579386..0e5f965f1882 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -28,6 +28,7 @@
 #include <linux/types.h>
 #include <linux/kasan.h>
 #include <linux/module.h>
+#include <linux/sched/task_stack.h>
 
 #include <asm/sections.h>
 
@@ -181,6 +182,168 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
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
+	frame = (const unsigned long *)(mem_ptr + KASAN_SHADOW_SCALE_SIZE);
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
+static void print_address_stack_frame(const void *addr)
+{
+	unsigned long offset;
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
+	pr_err("addr %px is located in stack of task %s/%d at offset %lu in frame:\n",
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
@@ -204,6 +367,8 @@ static void print_address_description(void *addr)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190522100048.146841-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
