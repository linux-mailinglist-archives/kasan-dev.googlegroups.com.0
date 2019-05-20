Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBMZRPTQKGQEVTKHSDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 46F8623C85
	for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2019 17:49:27 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id q72sf3689112qke.19
        for <lists+kasan-dev@lfdr.de>; Mon, 20 May 2019 08:49:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558367366; cv=pass;
        d=google.com; s=arc-20160816;
        b=YC4cBmkyq4qK9XeOnKsWVFx62lBgHpME2B5j97BP0lmPfWVIZYrRctsNwQgd5lsKZ7
         BvmjhEG8vZL/CXtV0otBxQCXDwN7V/oqlAPqBUOJW4mCLiMlp7fvE7jhAGV8WYh55gJF
         VP+Wn+tJTSvDg03oiWUBAF/cr4ayY4KnWP48BmygvzpE4vvndCMDF8b3YEboxJdDzkaB
         NPxfFg8LNkyp3U6z8HyJQn1CH7cQzS17DIimDkcuhqUA2ajel6n9kj8kblkwuIWh5edN
         kWbq376GoF9esgCD0SoOma6yilyPdFxP8Gkwl0FiAOiea0OHZupoLf1BME8HPZ8ri+jg
         F9WA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=kSMbrgV8cROlMfgxj9LgcnmWzWPgfwqy7yJ3m/cBtgI=;
        b=PGjj6I3tydDfEf3nL7yk6kchKkWNJkQ+Hx/UQ/cJ91sPIdre/WhtG3RrylQCqhgAG5
         O4Kw4mYivr4+YctbBlUZG3c9ttkF9E7R3Bpzjw4X+OJ0gLzf28B4LzvYFG/BDMP1skaj
         4Rt7eG3/mJw6EdqlnrxIpJFDRLFxjVyWTmGmFoGDsxocd/gZWy2CdUUuF+CG13DXbXkZ
         ibxJX5HzZuBwXDvCCKqUeuoDXsMQTELN78jSzcZN77OTDDbM6L7E3gaz0kAT3o6t3VoQ
         5TBPoG4/bbpVYYuDiCzdmN+tEw4S09rF7Xz5O2vErqrwg6SYqhnZjMgYo8FkoWbPMeGU
         dVLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iNzQ2eWV;
       spf=pass (google.com: domain of 3hmzixaukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=3hMziXAUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=kSMbrgV8cROlMfgxj9LgcnmWzWPgfwqy7yJ3m/cBtgI=;
        b=DaM/WShDApCIfFOt7Tzlag80kCqagqezExoNqW/x6sW+SpGPcKxwpjxdv3R2DSjJF/
         /UuzbWPbmICe9NVFP2RUUWOk8OrXJaTS3k0428HPeoddkGrvbqSGhb3/DXEDfc8lmLa6
         iAiunhucDoZymvyj7qkCtRP3Z9lMVe7tZPCNluIYTuHFOuMGQyVSGvFQ0CnioPo82HU3
         THFE/02TdBZ4EWvqgFXZpdUIiW1zJ6LyzOrdMPfygGvaiW/FzV2g1Qe7Um+fLVRp+Zy9
         moKh7p9BT1N/faZq1eXwdGrmk9DB432pYkU2kciEbE5onbZDURkb3G4dLUw85L3OEH6N
         6f+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kSMbrgV8cROlMfgxj9LgcnmWzWPgfwqy7yJ3m/cBtgI=;
        b=P9JgsGX1qemgLj5itCPTgcePeh7Ejt8HqrLr+HwtuDkrXFXunRGhZuFM+q/lIkdlUX
         gVy1U/tTVm5GDgxEIGFBOrTtyUvO7ohtWm+0vMBfp7Bls6fUWmq5NUfG7TLpQ+kzz/E4
         8vV1TRXGp4j7IQOECDCk1nlNJU0SSMRWGckuILxQ4siJEmJDVGZSVFYS7mFvdLgeP6SH
         QBqd0wI6h7TUouuUs72bjkcSDrqML3iq34YZwuuYvVqSWdMu7umBKhSpfo31tX41Hp9i
         gOa3axvx4MYi1vM+ubKbEWC0YFomoWIfu+Xd/aGqeHHN2YxHqOXdv8U0QEQw0B1GTbup
         5rog==
X-Gm-Message-State: APjAAAVXdQIB8W18zoZEjbZ7f1aOoglZZmCZ8GD2IcoB790nOiWBEalE
	JBtQu7/fQo+LihrZoeMYD/w=
X-Google-Smtp-Source: APXvYqwbJ/sybYR6UhWIcSxZTkYTs8kLQxGbucPL3h/obd1z95k2Fj+owaBuz3c9wOCCPYIqvmXe4w==
X-Received: by 2002:a37:ae03:: with SMTP id x3mr5679938qke.355.1558367365181;
        Mon, 20 May 2019 08:49:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e611:: with SMTP id z17ls3361976qvm.5.gmail; Mon, 20 May
 2019 08:49:24 -0700 (PDT)
X-Received: by 2002:a0c:c91b:: with SMTP id r27mr61760168qvj.101.1558367364923;
        Mon, 20 May 2019 08:49:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558367364; cv=none;
        d=google.com; s=arc-20160816;
        b=LACGg6b8vp5sFUTHkSoVyZe/cQCF/NeDKh+bPKgO5OQDDPTXCxs3phg4FKdM828D7d
         9R1CMw7F5tfNYQsbSNT4bLKRXEAUaSGSm6FS+SXjGTIFVYI2y39zgAbbDMlCu6IYjiSM
         f6h++qsXZW9GH94sk1QNIwxIu/ugvheU/GJfxp7bH4yC0qp5P/Y20CejcCdTOesQembN
         ESxWgrsef117Z173jDmfNt8+Lrbv/l3j+DbYPtGszAqr+RNx1ag/TwmhZDpFkKYoHRbv
         BeBJHUDIG9NoBI5Pcd30SFgZf15LR8fPaKA40bbM/ifNWHuQ/rFgK+DP9bMP7WUpLxm8
         DqSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=DI/Egqa/t8z7Z3O4/V5tG0j/kPqJakDGU2aHEa8JEWE=;
        b=NzHRwdjfBm4aEA0v1rKa9rd5X9qovY91FY+M6qVommEx2/RHrYrTcxt/LYVe0yECR4
         B2ysbwYzZUy4O6UPSHP+/1DjqDLPkz4E8LrFlLV00Bor62YvECRq5Oh61I4hxEW6IkMb
         R6Lv+ESkSLp/Vgp8oe8Uqq3Ykv0khy6obgQjTBSlkFvvY/A4oXwDIKXSBYYpKPogsw59
         7j4uMx4AIb8ufUPqqSAhCZVdKdYLDyDsjhyaYvYWJjMMt+G3b9PbaUFco0B0JEa3VlFu
         0TW3qnY7Sxz8r0Ntr/dbvlEgDGrdGWf0zKsQx6xNsjsEj/AQSHPNAacG7oUOr5MFax9z
         sbBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iNzQ2eWV;
       spf=pass (google.com: domain of 3hmzixaukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=3hMziXAUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x949.google.com (mail-ua1-x949.google.com. [2607:f8b0:4864:20::949])
        by gmr-mx.google.com with ESMTPS id j35si977157qta.3.2019.05.20.08.49.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 May 2019 08:49:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hmzixaukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::949 as permitted sender) client-ip=2607:f8b0:4864:20::949;
Received: by mail-ua1-x949.google.com with SMTP id c24so2101496uan.5
        for <kasan-dev@googlegroups.com>; Mon, 20 May 2019 08:49:24 -0700 (PDT)
X-Received: by 2002:a05:6102:c3:: with SMTP id u3mr35250624vsp.0.1558367364526;
 Mon, 20 May 2019 08:49:24 -0700 (PDT)
Date: Mon, 20 May 2019 17:47:52 +0200
Message-Id: <20190520154751.84763-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.21.0.1020.gf2820cf01a-goog
Subject: [PATCH v2] mm/kasan: Print frame description for stack bugs
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iNzQ2eWV;       spf=pass
 (google.com: domain of 3hmzixaukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::949 as permitted sender) smtp.mailfrom=3hMziXAUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

Changes since V1:
- Fix types in printf (%zu -> %lu).
- Prefer 'unsigned long', to ensure offsets/addrs are pointer sized, as
  emitted by ASAN instrumentation.

Change-Id: I4836cde103052991ac8871796a45b4c977c9e2e7
---
 mm/kasan/kasan.h  |   5 ++
 mm/kasan/report.c | 163 ++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 168 insertions(+)

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
index 03a443579386..36e55956acaf 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -28,6 +28,7 @@
 #include <linux/types.h>
 #include <linux/kasan.h>
 #include <linux/module.h>
+#include <linux/sched/task_stack.h>
 
 #include <asm/sections.h>
 
@@ -181,6 +182,166 @@ static inline bool init_task_stack_addr(const void *addr)
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
+		/* Strip line number, if it exists. */
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
@@ -204,6 +365,8 @@ static void print_address_description(void *addr)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190520154751.84763-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
