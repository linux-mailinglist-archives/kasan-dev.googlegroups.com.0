Return-Path: <kasan-dev+bncBAABBVW6WHYAKGQET6ODNCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f56.google.com (mail-lf1-f56.google.com [209.85.167.56])
	by mail.lfdr.de (Postfix) with ESMTPS id 017C212DE70
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jan 2020 11:07:19 +0100 (CET)
Received: by mail-lf1-f56.google.com with SMTP id f22sf6857099lfh.4
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jan 2020 02:07:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577873238; cv=pass;
        d=google.com; s=arc-20160816;
        b=NSaIUCUt/MrNH708XhvqHG2H/PwZr5C9XwBES6gll11G5fOkhbw1k9/GAqQtcpZUpo
         d8sI9gHgcAOae74054okgWnl/Q/IfI3VNWJoVQyBb8e/W+xrBzHui1bBpwJt/Q7xYpWk
         Hggyh4c2onq8Tzr2ZWqRs8ToYkaUKIEnSjKVP0umucbhMEFZRiN/OwPCMf/LPEqKqErl
         lBwAlz5S4HJWBgIk5S3emhJHg+c4OEVLnijvsAW3f5AmVu2C/qwV53d0NM+pcccjiBdZ
         nEH8fGe1Mzpiw/oDTp+s+l8Ka4O56Nl/vULhsarYpF3RJ/0II4U38igF6YCg7/PYdFBQ
         CIag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=yrwZa7K/Q76RgRA4gma+0KM1kZnS0l1urAiIjTEsjdQ=;
        b=GC9hizBkfTyixS4TXonUXkgV/psGGElNODnjXaSu0qwy9F1LA40hA4RfIU+xwv1Rwn
         ZpDOvvPrNIe2KLGGIea8Z2f5rL6qv5IT6v3yBOz0FHXfkkd63KyLBFwytNJJDQnVEZpX
         Ln90LQFEQ32kUYFLVK7hLE5cV1yb3QLHeGVZtAYJXVIO7H/nWB+j134fzuz/u3YXRHKO
         cPFp6VGQ+YKlkLQP6zw+7IzqFnx2fvHESJ2p2uffIvgvSpt6aZ0UsHsKhK8Lz9T3BgAb
         G4vyTPYF/MJnVlbWyCvQt08Zehu6H88JKUGw8gl+FT20zbwFLwBecOWMy4N3QDB4QpGo
         005A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:sender:reply-to:to:subject:cc
         :in-reply-to:references:mime-version:message-id:robot-id
         :robot-unsubscribe:precedence:x-original-sender
         :x-original-authentication-results:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yrwZa7K/Q76RgRA4gma+0KM1kZnS0l1urAiIjTEsjdQ=;
        b=qFoasE++2efpczl0KnaolzRDSpwPZDSOd1GXw+lxqQVFwmRENBlVcFui4Ub4HZB6XK
         0i61apbeiHeG40CLiP9MBIM4Mr0bEO848ZUlvEjusxnj4/Cvi7dHZ0q8gbElbAdktFWa
         LtVXNfsxGK3zbfWbQvF8d42GitPrAjcyGJ2GeOoKlp0cTCOSmUsFSfiWbwak4MI72z19
         5YxfhE7EE5QpFMv2Slue/LQzqITKPwENmAX1iONVA2ztEiA1cy25aBhrJ65LRt1rX0zE
         3Z5+p0jMOqoZh7+DxYH1nuWtCuHRj5zGfmUwyJAvRxiOdvhax0r6Pf+4LIBB1bJy1der
         Hegw==
X-Gm-Message-State: APjAAAVHX8Fs+8J1h37aCFl6ajuSqfPgE6GPn+ha0ykQm7U6btIQ5OUR
	FrWUQfDmAoDuEjVG5vmBKR0=
X-Google-Smtp-Source: APXvYqycU8mCkt9PEGVTG38X8/lK+oQ0VrhhK3CBaFs7gOLpk4IYmxGgEAjEF04Ah7HVHGcLofcefw==
X-Received: by 2002:a2e:5304:: with SMTP id h4mr46870428ljb.75.1577873238556;
        Wed, 01 Jan 2020 02:07:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3f0b:: with SMTP id m11ls3229272lfa.0.gmail; Wed, 01 Jan
 2020 02:07:18 -0800 (PST)
X-Received: by 2002:a19:4849:: with SMTP id v70mr43632559lfa.30.1577873238120;
        Wed, 01 Jan 2020 02:07:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577873238; cv=none;
        d=google.com; s=arc-20160816;
        b=hpOg63oLjMDm7LL0Zm4ZGXvWPEJJ1LopxUrKWNZSIK0YBNTbTz/JGoMKIxPX9qZd9t
         rXffKbuCsIelTLC73VAdaICrIXVA75PQMTRGSlB4kVyMWa3+GG6rcYazNllwnQ5Ikr6V
         ISCjUgiF1urIAqbBqsZwaCtnySt14f8AGtdoVh9icQDeyVmuqwHnzfX71uh07uskGOR/
         s3ryEen2bKq8Iram10lnxGV7FI4rjmAd0kNCn7GtwH78Gz4GowSMzjL3642gSnGfBDj+
         IVdaykV79nW42DefIUhHSbXo27C3+JKbCiomgJwXkC2Q5TJKAx2fXAbOnbek6Wl873rK
         PV1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:precedence:robot-unsubscribe:robot-id
         :message-id:mime-version:references:in-reply-to:cc:subject:to
         :reply-to:sender:from:date;
        bh=d3+bpax9WGs7ZYjnPN6v5g5h7WK/ETmXRELFstNlTA0=;
        b=mxfdbcyKBaGOxIdtKHYLzImBbxejLmcs9TMrcXfGgD7RTndNqApsOmwJFXu3eqsfhy
         138z50zLtVJqKjSxXb9mCsIPZKerzwJ7u1FsGQXMFpSfpmbuCb654arsKE6Chiqzx1U5
         iK6qgwnuGBgE/LRU6fo2bHdrxhIkhOXPffTYMdQ4ziHKQS3htdtu3yXrOiGxM5Tz6z2p
         7BLt/z7Dh+LvrG4pfroEt2xZWJahAui4jIG8927ilwAw4ruEJjf0Hv+2yhxx7l8Pmqua
         aUuy/k7nGvjLXxPRP3UOK16VaV8aS/QEcLi6kZo0V3iIW6KAL0bhb6RWHjdduO5X6K/6
         IvJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id h8si1620475ljj.3.2020.01.01.02.07.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Wed, 01 Jan 2020 02:07:17 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of tip-bot2@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from [5.158.153.53] (helo=tip-bot2.lab.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tip-bot2@linutronix.de>)
	id 1imauH-0004P3-LA; Wed, 01 Jan 2020 11:07:13 +0100
Received: from [127.0.1.1] (localhost [IPv6:::1])
	by tip-bot2.lab.linutronix.de (Postfix) with ESMTP id 456A41C2C2B;
	Wed,  1 Jan 2020 11:07:13 +0100 (CET)
Date: Wed, 01 Jan 2020 10:07:13 -0000
From: "tip-bot2 for Jann Horn" <tip-bot2@linutronix.de>
Sender: tip-bot2@linutronix.de
Reply-to: linux-kernel@vger.kernel.org
To: linux-tip-commits@vger.kernel.org
Subject: [tip: x86/core] x86/dumpstack: Introduce die_addr() for die() with
 #GP fault address
Cc: Jann Horn <jannh@google.com>, Borislav Petkov <bp@suse.de>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>,
 "Eric W. Biederman" <ebiederm@xmission.com>, "H. Peter Anvin" <hpa@zytor.com>,
 Ingo Molnar <mingo@redhat.com>, kasan-dev@googlegroups.com,
 Masami Hiramatsu <mhiramat@kernel.org>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>,
 Sean Christopherson <sean.j.christopherson@intel.com>,
 Thomas Gleixner <tglx@linutronix.de>, "x86-ml" <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <20191218231150.12139-3-jannh@google.com>
References: <20191218231150.12139-3-jannh@google.com>
MIME-Version: 1.0
Message-ID: <157787323316.30329.2945432496766517547.tip-bot2@tip-bot2>
X-Mailer: tip-git-log-daemon
Robot-ID: <tip-bot2.linutronix.de>
Robot-Unsubscribe: Contact <mailto:tglx@linutronix.de> to get blacklisted from these emails
Precedence: list
Content-Type: text/plain; charset="UTF-8"
X-Linutronix-Spam-Score: -1.0
X-Linutronix-Spam-Level: -
X-Linutronix-Spam-Status: No , -1.0 points, 5.0 required,  ALL_TRUSTED=-1,SHORTCIRCUIT=-0.0001
X-Original-Sender: tip-bot2@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tip-bot2@linutronix.de
 designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tip-bot2@linutronix.de
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

The following commit has been merged into the x86/core branch of tip:

Commit-ID:     aa49f20462c90df4150f33d245cbcfe0d9c80350
Gitweb:        https://git.kernel.org/tip/aa49f20462c90df4150f33d245cbcfe0d9c80350
Author:        Jann Horn <jannh@google.com>
AuthorDate:    Thu, 19 Dec 2019 00:11:49 +01:00
Committer:     Borislav Petkov <bp@suse.de>
CommitterDate: Tue, 31 Dec 2019 13:11:35 +01:00

x86/dumpstack: Introduce die_addr() for die() with #GP fault address

Split __die() into __die_header() and __die_body(). This allows inserting
extra information below the header line that initiates the bug report.

Introduce a new function die_addr() that behaves like die(), but is for
faults only and uses __die_header() and __die_body() so that a future
commit can print extra information after the header line.

 [ bp: Comment the KASAN-specific usage of gp_addr. ]

Signed-off-by: Jann Horn <jannh@google.com>
Signed-off-by: Borislav Petkov <bp@suse.de>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andy Lutomirski <luto@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: kasan-dev@googlegroups.com
Cc: Masami Hiramatsu <mhiramat@kernel.org>
Cc: "Peter Zijlstra (Intel)" <peterz@infradead.org>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: x86-ml <x86@kernel.org>
Link: https://lkml.kernel.org/r/20191218231150.12139-3-jannh@google.com
---
 arch/x86/include/asm/kdebug.h |  1 +
 arch/x86/kernel/dumpstack.c   | 24 +++++++++++++++++++++++-
 arch/x86/kernel/traps.c       |  9 ++++++++-
 3 files changed, 32 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kdebug.h b/arch/x86/include/asm/kdebug.h
index 75f1e35..247ab14 100644
--- a/arch/x86/include/asm/kdebug.h
+++ b/arch/x86/include/asm/kdebug.h
@@ -33,6 +33,7 @@ enum show_regs_mode {
 };
 
 extern void die(const char *, struct pt_regs *,long);
+void die_addr(const char *str, struct pt_regs *regs, long err, long gp_addr);
 extern int __must_check __die(const char *, struct pt_regs *, long);
 extern void show_stack_regs(struct pt_regs *regs);
 extern void __show_regs(struct pt_regs *regs, enum show_regs_mode);
diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index e07424e..8995bf1 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -365,7 +365,7 @@ void oops_end(unsigned long flags, struct pt_regs *regs, int signr)
 }
 NOKPROBE_SYMBOL(oops_end);
 
-int __die(const char *str, struct pt_regs *regs, long err)
+static void __die_header(const char *str, struct pt_regs *regs, long err)
 {
 	const char *pr = "";
 
@@ -384,7 +384,11 @@ int __die(const char *str, struct pt_regs *regs, long err)
 	       IS_ENABLED(CONFIG_KASAN)   ? " KASAN"           : "",
 	       IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION) ?
 	       (boot_cpu_has(X86_FEATURE_PTI) ? " PTI" : " NOPTI") : "");
+}
+NOKPROBE_SYMBOL(__die_header);
 
+static int __die_body(const char *str, struct pt_regs *regs, long err)
+{
 	show_regs(regs);
 	print_modules();
 
@@ -394,6 +398,13 @@ int __die(const char *str, struct pt_regs *regs, long err)
 
 	return 0;
 }
+NOKPROBE_SYMBOL(__die_body);
+
+int __die(const char *str, struct pt_regs *regs, long err)
+{
+	__die_header(str, regs, err);
+	return __die_body(str, regs, err);
+}
 NOKPROBE_SYMBOL(__die);
 
 /*
@@ -410,6 +421,17 @@ void die(const char *str, struct pt_regs *regs, long err)
 	oops_end(flags, regs, sig);
 }
 
+void die_addr(const char *str, struct pt_regs *regs, long err, long gp_addr)
+{
+	unsigned long flags = oops_begin();
+	int sig = SIGSEGV;
+
+	__die_header(str, regs, err);
+	if (__die_body(str, regs, err))
+		sig = 0;
+	oops_end(flags, regs, sig);
+}
+
 void show_regs(struct pt_regs *regs)
 {
 	show_regs_print_info(KERN_DEFAULT);
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 108ab1e..2afd7d8 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -619,7 +619,14 @@ dotraplinkage void do_general_protection(struct pt_regs *regs, long error_code)
 				 "maybe for address",
 				 gp_addr);
 
-		die(desc, regs, error_code);
+		/*
+		 * KASAN is interested only in the non-canonical case, clear it
+		 * otherwise.
+		 */
+		if (hint != GP_NON_CANONICAL)
+			gp_addr = 0;
+
+		die_addr(desc, regs, error_code, gp_addr);
 		return;
 	}
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/157787323316.30329.2945432496766517547.tip-bot2%40tip-bot2.
