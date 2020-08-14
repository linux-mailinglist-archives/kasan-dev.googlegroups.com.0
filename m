Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSET3P4QKGQECPS2MOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A451B244DDC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:41 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id q5sf6524068ion.12
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426120; cv=pass;
        d=google.com; s=arc-20160816;
        b=uCCkmZcl5Evb0m2dXFwRVn2BBSMM5COECFf2DvVx9Rvvvbp+RcS8bX0r5NK2gK8Be/
         GxAws8ayCnTFKk/Hz3cRvynxJlr1CpdKccF+p8KeleH9gdVMJu0WDndXWW6eGtfn/Zqq
         Ighr3a6Drol9y+NqsTD55iM2/ywhqTDeTfjqczFNH/STsG1r1olqHKBP87FxclhCTwBD
         jYUv3qiSUlyCTtC98goeXLISes3WngXDykxB8JQYD+qQbtMdAKleA5uKemXSqwgt+4qH
         mhEZR/I6rVkDvbZm9NE1mW3QHcy14e7m2RSd3A4FydUxKmrNCLLlJK7v0KR6a0M6z/kD
         hIfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=UsmFSeTKtB9eeCV4hrsJoOHbtwTlXQoUN8m0kVJEMMc=;
        b=ac9gbezainyyL0YfOxanWzb5Anmk8zoz7Mt+Afc0z3KowMU6Md9ruqyAC/d8m6YZu5
         40DkNH4KKafax22tCV9Vc/VemOUom77LnzbNCMVVtXKv+jyBAPHSf8bRpzabwsm7ASAL
         OXwA3gtovG51t8ZLUtBDMzwRNg8OYkvYBUbBpTzblmsC4z8wsbfage4k5IA6K+JiBWLF
         P4PZw3Ftee3GJfsDoGywXAoHeueSd2Q/Rd8GePHEwRJOUigTN3pnREnQzessRGBo3BC3
         CskWDZGESwKPaHyNgBUEhYs+3USHIRuTweV23CoAn2+0R6vYS5yTgDduL3yXlHYG72WR
         0BSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ku0irwum;
       spf=pass (google.com: domain of 3x8k2xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3x8k2XwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UsmFSeTKtB9eeCV4hrsJoOHbtwTlXQoUN8m0kVJEMMc=;
        b=sYFsDXN67laG+6tcm8/92IXUJeeWc8dVw70muCTMh2NPmFIp0Y9SNF163SDmveqt9I
         UkRC6LYjsKa/fCL6VdzfT8EzwvrE1BX2OwHqdiH4OSAUdoNONPAxHkgo4A5wjKAH47d6
         KMNSm8dVEjbJ5E7NQJ7YI8HoyIG0vPAmmO4KjB1+cAICpsEtqbsIt8xrYcXNvHA5kR9W
         4YG6pf8rRLuOSja2EEYLQX8617SALOzM8pN3mWAfWW0vZXuM6Y5leCPm4Tf1+xDICF5P
         bxdGo/3c0ZWTaUvEX0uvgPFmYOLoSm0y/Ah/j12BgqocMP+9AWvCG3iLkKJ/1uV9P5yu
         GSqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UsmFSeTKtB9eeCV4hrsJoOHbtwTlXQoUN8m0kVJEMMc=;
        b=lFViWTxINMRLCRlBJGQo9v8s06We4vIqcUfbsS1KJF6q01fylo224EwWrqxR7vT2hA
         8tRbySFG7smRGYgRC0PjzXbV1L/W33Dk/9bylL5ODEVvf5POlI1JTUoc/65aS/uIN1/i
         W6dHe5wmD2n+sslTkcFU/niBRgJpSEsJFsSA5XR15ts+OPK6rUQD61P3FtXhZ8T6sesj
         f2OlT5WqoCku5v727JxdpVpV2ONOjmtjJqF8NA7CWZlNRyQLYXK4sRjTdlo3xYZ0OX1L
         CI3LGwkP/thDhpwoOycDEyluHs/4dosWc/A+njCJX1WO08p9lUo+UzBF6i2wggnw0Y0O
         9oHQ==
X-Gm-Message-State: AOAM533V7mIG4+TM1lkny5KdMVi+sTMyt+t7J8RFM0u/NuWoJ3ICv+3L
	8z8yTq0tV2bDGphqHn+dMFw=
X-Google-Smtp-Source: ABdhPJyxG/dhArWfLqWqw1oj/NVlh88zxK7e+tK/4Eq7nI4F27ANaPwQQ6qsqNhwzjk/cqjtcQkMVw==
X-Received: by 2002:a05:6602:24d8:: with SMTP id h24mr2937544ioe.145.1597426120376;
        Fri, 14 Aug 2020 10:28:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:168b:: with SMTP id f11ls1368624jat.5.gmail; Fri,
 14 Aug 2020 10:28:40 -0700 (PDT)
X-Received: by 2002:a05:6638:1643:: with SMTP id a3mr3737296jat.104.1597426120018;
        Fri, 14 Aug 2020 10:28:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426120; cv=none;
        d=google.com; s=arc-20160816;
        b=we/tPnu+6FeBBE8kpX55UYL8JP8w2jnfICOkPHETNMRc6A8DOLRLVdwgvMWScdDpsy
         JyHvIaNM0N0MBTGIuQe9TM1FqX/COkKnT/6UDReA99zaL/ZfBgrrjpc175MO+oiAdaMM
         ADKar7PJwV6vMXQ0jVpLWvd2zEXqw3GBO7sv5aRzLlh1VdH7Im5YV+WrhWjeqTb2XAbA
         IA65z4wAfJrD3a4WBQq0UKSg3wJaRIKRDBvpQ+VVcxcJkxFXWsB4JFJVeHLOajrX0BfR
         SUEw25C/nq+I6MV1GUhPJ8kibWgegXEPexp9HW1woO2KZ42fy7gABgHNHDyv88XqgjLC
         OnkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=q24QkMKZO6T4dOo8z/uPgVahsCI2M3nldwxAJ8Cpi0Y=;
        b=KBFD8szZk3MeIpFAXCd3LUYxCjS7rnFJQjBdf9m8WZpA6uTBMFQenA6YZTHwFuXP3l
         56NUXCPY08p5wZ0bxvqCFhIjw0OuyrZ9JA2r4etWFZyDBVHu2G/DPH8qnMT+FvFnMYXS
         qxuZgKsb63DbBtUyFtSVc+nFhOaHZOGDx4zpbyxJiIfvTCXJpL3bJxIhpMDVpvXRzGux
         nuzAmo9vFfeq+eVtZGFjHCAETMfqV7rLRNWdfMV/Zc6hAnRfMGkWjP1uNeirqCIop6jm
         xHI3RkBNHeHiS4zYhlQ/yuDMJ5fMc6oMmIRiTgxjksW3mfI8pnIFKZJqes5WFBmD220Z
         nDSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ku0irwum;
       spf=pass (google.com: domain of 3x8k2xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3x8k2XwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id u9si493051ilg.0.2020.08.14.10.28.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3x8k2xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id k17so6493130qvj.12
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:39 -0700 (PDT)
X-Received: by 2002:a0c:b895:: with SMTP id y21mr3726762qvf.87.1597426119355;
 Fri, 14 Aug 2020 10:28:39 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:14 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <4691d6019ef00c11007787f5190841b47ba576c4.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 32/35] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=ku0irwum;       spf=pass
 (google.com: domain of 3x8k2xwokctysfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3x8k2XwoKCTYSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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

Add error reporting for hardware tag-based KASAN. When CONFIG_KASAN_HW_TAGS
is enabled, print KASAN report from the arm64 tag fault handler.

SAS bits aren't set in ESR for all faults reported in EL1, so it's
impossible to find out the size of the access the caused the fault.
Adapt KASAN reporting code to handle this case.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/mm/fault.c |  9 +++++++++
 mm/kasan/report.c     | 11 ++++++++---
 2 files changed, 17 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index c62c8ba85c0e..cf00b3942564 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -14,6 +14,7 @@
 #include <linux/mm.h>
 #include <linux/hardirq.h>
 #include <linux/init.h>
+#include <linux/kasan.h>
 #include <linux/kprobes.h>
 #include <linux/uaccess.h>
 #include <linux/page-flags.h>
@@ -314,11 +315,19 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
 {
 	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
 
+#ifdef CONFIG_KASAN_HW_TAGS
+	/*
+	 * SAS bits aren't set for all faults reported in EL1, so we can't
+	 * find out access size.
+	 */
+	kasan_report(addr, 0, is_write, regs->pc);
+#else
 	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
 	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
 	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
 			mte_get_ptr_tag(addr),
 			mte_get_mem_tag((void *)addr));
+#endif
 }
 
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index c904edab33b8..34ef81736d73 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -65,9 +65,14 @@ static void print_error_description(struct kasan_access_info *info)
 {
 	pr_err("BUG: KASAN: %s in %pS\n",
 		get_bug_type(info), (void *)info->ip);
-	pr_err("%s of size %zu at addr %px by task %s/%d\n",
-		info->is_write ? "Write" : "Read", info->access_size,
-		info->access_addr, current->comm, task_pid_nr(current));
+	if (info->access_size)
+		pr_err("%s of size %zu at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read", info->access_size,
+			info->access_addr, current->comm, task_pid_nr(current));
+	else
+		pr_err("%s at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read",
+			info->access_addr, current->comm, task_pid_nr(current));
 }
 
 static DEFINE_SPINLOCK(report_lock);
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4691d6019ef00c11007787f5190841b47ba576c4.1597425745.git.andreyknvl%40google.com.
