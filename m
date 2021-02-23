Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYXV2KAQMGQECY3EFWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CDBA322707
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 09:20:51 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id q10sf1182415pjd.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 00:20:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614068450; cv=pass;
        d=google.com; s=arc-20160816;
        b=E+jG8GgzUyXwQvHtGPB2EBEzXSQKuVRJx7n5oNre8j0ziorGCfbbGQZvn3FWTrJ4rd
         z521ouBncSyEsORaeHab4ZUXH4tNlYG8UINvAh1hm/27rwotKoqZLDsAducI88/Jglij
         8MoAJpj5+dwnaRotzqmkwwxnunJv0JuyZcuG6RklVRiJfkjw5A3zH6XXDZ0XCOb6PGXF
         jPEP6DRnz5P8Jrr9vs7K3m3R967fGE69iX31RY0Rf2OapVTaK/uBiZ+ovJ/VWBVO7jqC
         uMlf+AEMY9xGTg9AH0x4bx9O0cCnZeNozmDJish6cXJT1QRcSi/2GW0G80kNshepzmA8
         6t8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=2pFazpT50JRpM40BchlUnxsCkeXS3TUtRYMuCQyRTH4=;
        b=mO388GKueqmHNVK7AOciXZBm2KKv96ojQlwyvqDYSr8KYKIEvg8tLCzHIKj30UfJfk
         BOAD7irhukGK97GhVg6cJPkVNv15QUOYz4OzRtzrRTQ/9vffT3eTurT2+qUfz3LKsVJB
         c7RG0pGbx/k+q+K7MVa7tl9x+Rr9tNQkkRDlqFQOE0RChlEQ4pi6CfpmUT1C1YlGjdhs
         jTFZ9LCMBxREVXalpVcNDhMxy4qBFGGgFrIHcwAwXB3PQrxAPC3A0t+8zvvDS1RSuWSA
         9exNEV01XLh3dcHXzDYCWj8DrClwWHSwUo9pQEnJKMcKxMvc0EpMJ/WyLEY1DaOYC0/U
         SBHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j7cibiZC;
       spf=pass (google.com: domain of 34lo0yaukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=34Lo0YAUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2pFazpT50JRpM40BchlUnxsCkeXS3TUtRYMuCQyRTH4=;
        b=HBhJaAdR4B8Algp5j3coB5r49F7+xb2Pn6BqU/O6Sq/UPv+EJ3rw+tjXwRVprOgM5C
         Gpa628BgwI0322yQHqLfSymiv8sx33k0n2bQaOuZcO94YefJuHx8gkdZbeVH478Q7wWs
         ZthCr5m858Td7qwQbg5GuZC822rZT4/Q5Gotlo1zzZ4HIce/r/6mczx308Hn8TlxHscU
         hIeLQyLTAsVwu/y4ZxR1NFSVKx7oUEbc24sHMhqf7cM9oUYbAVaxTRk3ePt8UPpZPb8Y
         hc8qO5k4aJqZcVKX8diVYdMXIpQbVJK7gqAkrBmWI8OqQxSuaMarni5uC4dMgtfWJDBW
         dX1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2pFazpT50JRpM40BchlUnxsCkeXS3TUtRYMuCQyRTH4=;
        b=JC6bD0o0aIPTE1Yr9bHHXs5ps+diPGXYMtZxOoCexT1y3qWKJK97EVilQXFdVoy1iM
         UpuS6xSxM+ARBsJNoeWaj4fIoRkezzVyk9oZTclLdIZJJ6r0hgPgpXDzb+SseFwKA/Ge
         ixWLTrRAx99F7CZ/t4+IEEUgxNnO3BjGjMD7NiECJT6Q0Kto3D5H7DwRWYnP4GDXsUr9
         xcMOAui1hjC0Duj1NUO47hguwlVfe6NANkmAbFPLClc0kN+Rx864E/KDs9fJ+nnP9cRp
         0wWqNd0y55Nf9NblSVwx5CHoZ+GjxO2kh3ub26FNZSK+MqdPBh6eT0Z4vbYc2KLuoOUX
         Rc0w==
X-Gm-Message-State: AOAM53033cTHvT5QOBR1989+LrGqn5Cx5AR1hadcQ9ZEijajvCZhWrhO
	6HYRPdsxJ66eF8g2h+uNeiM=
X-Google-Smtp-Source: ABdhPJxodbsNkxUjGjpteP6ZZPJ8jDUfEpxeQELzLFPrXYSA0/JGFO1VQm7AGC4Y/X4+cCKRlovTGQ==
X-Received: by 2002:a17:90a:77c4:: with SMTP id e4mr27052184pjs.185.1614068450281;
        Tue, 23 Feb 2021 00:20:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c1:: with SMTP id e1ls9758264plh.10.gmail; Tue, 23
 Feb 2021 00:20:49 -0800 (PST)
X-Received: by 2002:a17:902:968e:b029:e3:a9b8:60b4 with SMTP id n14-20020a170902968eb02900e3a9b860b4mr23985832plp.61.1614068449592;
        Tue, 23 Feb 2021 00:20:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614068449; cv=none;
        d=google.com; s=arc-20160816;
        b=om5sIyO/+efYbZeLSYh0p9e+IAHdZLfwa5mpY5hg5j4PRYVnF1UPpcyITofHGV6ytQ
         Y8hFAJ8l6xPYLV3A3iQ85+z/qlainLpv5z2jIJpoEcFpOjeWYleW0jC1akI6WmQqaQbB
         Fito0fUKkvm+dsWvU+PJfyiGVVOc5lx+n+FALGnhqcgk4lbkBgINJ/7vvSu1Sv+ufEYx
         O9pEdnXbyvf5KMODN/z/uWx2J+PFlVcQQuBWorMZ2PwauDEs5lmUh7HOq/fXI9Jz/6tL
         qE6WPi5SWY82xxAVu3W318cb/wCESufw/a4VJrxKd5JN1u6ZEnigv3DiJC7CrnumvqjU
         TH4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=NFZ3Z7VYF450fBUEwtA9Z/zyGYLmPSNiSMB88RuL4JU=;
        b=W3kzc4oYh6o212duobHnaks2BkRHrEpFR6nsh8+23VSUdXTVyb2RpmCle2K5TtL1Jw
         AsUZgX2kEkgrHGBKCrcTqpjZg9em/121iTobLGTZ3AhdXZmrMyZsH9tELCMolAic0ags
         RGsWclMmg+PV+GZ056U3jm41Ogs0ziqGuMhQs8+AQ21UoV7BEPRTHd8VXfKSnFU6QyaN
         Qun8BhnhcmBmHYQroCTFtQreOULAFGbWxCMoCnE5py/5UgqJnluHjFz67R5k+9Wroyzu
         NtYA/PCg7pnoaj+4tz2lWLmOUp2oBnNdvLDLfSREKZyuZm1pi54JD03UYPW5BIKHj3Ha
         +6WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j7cibiZC;
       spf=pass (google.com: domain of 34lo0yaukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=34Lo0YAUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id o15si114754pjw.1.2021.02.23.00.20.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 00:20:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 34lo0yaukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id p27so11128175qkp.8
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 00:20:49 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:855b:f924:6e71:3d5d])
 (user=elver job=sendgmr) by 2002:ad4:5a10:: with SMTP id ei16mr10879866qvb.10.1614068448741;
 Tue, 23 Feb 2021 00:20:48 -0800 (PST)
Date: Tue, 23 Feb 2021 09:20:43 +0100
Message-Id: <20210223082043.1972742-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH mm] kfence: report sensitive information based on no_hash_pointers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Timur Tabi <timur@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j7cibiZC;       spf=pass
 (google.com: domain of 34lo0yaukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=34Lo0YAUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

We cannot rely on CONFIG_DEBUG_KERNEL to decide if we're running a
"debug kernel" where we can safely show potentially sensitive
information in the kernel log.

Instead, simply rely on the newly introduced "no_hash_pointers" to print
unhashed kernel pointers, as well as decide if our reports can include
other potentially sensitive information such as registers and corrupted
bytes.

Cc: Timur Tabi <timur@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---

Depends on "lib/vsprintf: no_hash_pointers prints all addresses as
unhashed", which was merged into mainline yesterday:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b2bec7d8a42a3885d525e821d9354b6b08fd6adf

---
 Documentation/dev-tools/kfence.rst |  8 ++++----
 mm/kfence/core.c                   | 10 +++-------
 mm/kfence/kfence.h                 |  7 -------
 mm/kfence/kfence_test.c            |  2 +-
 mm/kfence/report.c                 | 18 ++++++++++--------
 5 files changed, 18 insertions(+), 27 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 58a0a5fa1ddc..fdf04e741ea5 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -88,8 +88,8 @@ A typical out-of-bounds access looks like this::
 
 The header of the report provides a short summary of the function involved in
 the access. It is followed by more detailed information about the access and
-its origin. Note that, real kernel addresses are only shown for
-``CONFIG_DEBUG_KERNEL=y`` builds.
+its origin. Note that, real kernel addresses are only shown when using the
+kernel command line option ``no_hash_pointers``.
 
 Use-after-free accesses are reported as::
 
@@ -184,8 +184,8 @@ invalidly written bytes (offset from the address) are shown; in this
 representation, '.' denote untouched bytes. In the example above ``0xac`` is
 the value written to the invalid address at offset 0, and the remaining '.'
 denote that no following bytes have been touched. Note that, real values are
-only shown for ``CONFIG_DEBUG_KERNEL=y`` builds; to avoid information
-disclosure for non-debug builds, '!' is used instead to denote invalidly
+only shown if the kernel was booted with ``no_hash_pointers``; to avoid
+information disclosure otherwise, '!' is used instead to denote invalidly
 written bytes.
 
 And finally, KFENCE may also report on invalid accesses to any protected page
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index cfe3d32ac5b7..3b8ec938470a 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -646,13 +646,9 @@ void __init kfence_init(void)
 
 	WRITE_ONCE(kfence_enabled, true);
 	schedule_delayed_work(&kfence_timer, 0);
-	pr_info("initialized - using %lu bytes for %d objects", KFENCE_POOL_SIZE,
-		CONFIG_KFENCE_NUM_OBJECTS);
-	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
-		pr_cont(" at 0x%px-0x%px\n", (void *)__kfence_pool,
-			(void *)(__kfence_pool + KFENCE_POOL_SIZE));
-	else
-		pr_cont("\n");
+	pr_info("initialized - using %lu bytes for %d objects at 0x%p-0x%p\n", KFENCE_POOL_SIZE,
+		CONFIG_KFENCE_NUM_OBJECTS, (void *)__kfence_pool,
+		(void *)(__kfence_pool + KFENCE_POOL_SIZE));
 }
 
 void kfence_shutdown_cache(struct kmem_cache *s)
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 1accc840dbbe..24065321ff8a 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -16,13 +16,6 @@
 
 #include "../slab.h" /* for struct kmem_cache */
 
-/* For non-debug builds, avoid leaking kernel pointers into dmesg. */
-#ifdef CONFIG_DEBUG_KERNEL
-#define PTR_FMT "%px"
-#else
-#define PTR_FMT "%p"
-#endif
-
 /*
  * Get the canary byte pattern for @addr. Use a pattern that varies based on the
  * lower 3 bits of the address, to detect memory corruptions with higher
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index db1bb596acaf..4acf4251ee04 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -146,7 +146,7 @@ static bool report_matches(const struct expect_report *r)
 		break;
 	}
 
-	cur += scnprintf(cur, end - cur, " 0x" PTR_FMT, (void *)r->addr);
+	cur += scnprintf(cur, end - cur, " 0x%p", (void *)r->addr);
 
 	spin_lock_irqsave(&observed.lock, flags);
 	if (!report_available())
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 901bd7ee83d8..4a424de44e2d 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -19,6 +19,8 @@
 
 #include "kfence.h"
 
+extern bool no_hash_pointers;
+
 /* Helper function to either print to a seq_file or to console. */
 __printf(2, 3)
 static void seq_con_printf(struct seq_file *seq, const char *fmt, ...)
@@ -118,7 +120,7 @@ void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *met
 	}
 
 	seq_con_printf(seq,
-		       "kfence-#%zd [0x" PTR_FMT "-0x" PTR_FMT
+		       "kfence-#%zd [0x%p-0x%p"
 		       ", size=%d, cache=%s] allocated by task %d:\n",
 		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1), size,
 		       (cache && cache->name) ? cache->name : "<destroyed>", meta->alloc_track.pid);
@@ -148,7 +150,7 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
 	for (cur = (const u8 *)address; cur < end; cur++) {
 		if (*cur == KFENCE_CANARY_PATTERN(cur))
 			pr_cont(" .");
-		else if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+		else if (no_hash_pointers)
 			pr_cont(" 0x%02x", *cur);
 		else /* Do not leak kernel memory in non-debug builds. */
 			pr_cont(" !");
@@ -201,7 +203,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 		pr_err("BUG: KFENCE: out-of-bounds %s in %pS\n\n", get_access_type(is_write),
 		       (void *)stack_entries[skipnr]);
-		pr_err("Out-of-bounds %s at 0x" PTR_FMT " (%luB %s of kfence-#%zd):\n",
+		pr_err("Out-of-bounds %s at 0x%p (%luB %s of kfence-#%zd):\n",
 		       get_access_type(is_write), (void *)address,
 		       left_of_object ? meta->addr - address : address - meta->addr,
 		       left_of_object ? "left" : "right", object_index);
@@ -210,24 +212,24 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 	case KFENCE_ERROR_UAF:
 		pr_err("BUG: KFENCE: use-after-free %s in %pS\n\n", get_access_type(is_write),
 		       (void *)stack_entries[skipnr]);
-		pr_err("Use-after-free %s at 0x" PTR_FMT " (in kfence-#%zd):\n",
+		pr_err("Use-after-free %s at 0x%p (in kfence-#%zd):\n",
 		       get_access_type(is_write), (void *)address, object_index);
 		break;
 	case KFENCE_ERROR_CORRUPTION:
 		pr_err("BUG: KFENCE: memory corruption in %pS\n\n", (void *)stack_entries[skipnr]);
-		pr_err("Corrupted memory at 0x" PTR_FMT " ", (void *)address);
+		pr_err("Corrupted memory at 0x%p ", (void *)address);
 		print_diff_canary(address, 16, meta);
 		pr_cont(" (in kfence-#%zd):\n", object_index);
 		break;
 	case KFENCE_ERROR_INVALID:
 		pr_err("BUG: KFENCE: invalid %s in %pS\n\n", get_access_type(is_write),
 		       (void *)stack_entries[skipnr]);
-		pr_err("Invalid %s at 0x" PTR_FMT ":\n", get_access_type(is_write),
+		pr_err("Invalid %s at 0x%p:\n", get_access_type(is_write),
 		       (void *)address);
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
 		pr_err("BUG: KFENCE: invalid free in %pS\n\n", (void *)stack_entries[skipnr]);
-		pr_err("Invalid free of 0x" PTR_FMT " (in kfence-#%zd):\n", (void *)address,
+		pr_err("Invalid free of 0x%p (in kfence-#%zd):\n", (void *)address,
 		       object_index);
 		break;
 	}
@@ -242,7 +244,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 	/* Print report footer. */
 	pr_err("\n");
-	if (IS_ENABLED(CONFIG_DEBUG_KERNEL) && regs)
+	if (no_hash_pointers && regs)
 		show_regs(regs);
 	else
 		dump_stack_print_info(KERN_ERR);
-- 
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223082043.1972742-1-elver%40google.com.
