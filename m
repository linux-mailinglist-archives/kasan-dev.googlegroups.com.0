Return-Path: <kasan-dev+bncBCMMDDFSWYCBB4FXX67QMGQEHU2FZ2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id B4262A7BD7F
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:17:38 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2c72e6e51cesf566459fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:17:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772657; cv=pass;
        d=google.com; s=arc-20240605;
        b=BTBGL9yz6GIEc5fiNZ/l78HJ+E21BmtTo/te0QThBy7pjQJlTAYHUeM2FuUlAry9Dz
         +V19VAppiPVegwgPLKcFKY1eGHhV85xVfJUwJLd6WT+wDo3yxVEC3i67wqSFJXohAiH/
         wzq1PiefRrZne97buimWzsHcuU/HU62XMLUaZ0GMiTbpk4EXYcwHnsZ5cNJEwE+i3evb
         N5GmUMiLjH3YhkSWSloRK5HFGZXdQp5xx0sNkmt4SCoMV7Z7GjrcLlz4LERtBpcLxMU5
         YOQ9z6FV0+ObgSt04AimpNP3sknYu5I0b82Zn4WValY+gTZabJq6dx2ycL87zZHHCa6n
         wgsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TykxOcy5QEdcmxmREh7EeohqyZLCDtHX2TyvWzvbg7E=;
        fh=AsjprdslWYmd/2NW9CZ042huHhPSgRpsFe0DBp13wVs=;
        b=gk6EpTDFa/unqDQxwBrpR3SrjHiZfZlWgjRehJu6ANwXuzr3fypVM06pqV97zaP1Gd
         M+Au/xpLejSxL+JXdGM5z9k22kYDf+fDgPczNzu9eCp8y3QJnm19DfhBPysltcFYA7NY
         WyvgU8Vin99qIZ7YnXECMXTptx1fE1/LnvkxgsxJDFfCcmU7+Mr/11GJOc3+jhMHmssF
         7PlWvgRVMh8DUk9MSkf2dPEErWUC2/do6+npkELd3HwRPFGt/DSSs1feXXtGmC4D8jSe
         3lRfaJA7Sw9ZFTGd7ehZWfgxMJrxbiUrWHvsgS5Wu7vFHhWGqP22Ds+tmK4gWgu72R/d
         3jHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NNCjA02e;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772657; x=1744377457; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TykxOcy5QEdcmxmREh7EeohqyZLCDtHX2TyvWzvbg7E=;
        b=Lfq0wPXF/o7kjB+VKLDsb3eF7LJVux7+7mJLXqh10dRxNl+TLxjIk+ZTQIm2B5XD7i
         /RB9sXiq1tg/CAhzI5EENvCug1WmlF9ve5VD2MApP+hxARHBvDbqb1tyYvxiWaO2YEmz
         /xrDHis6M+afW9q6zm5USsNCJzSDWwqiw8Y2dF49fDqlO4jKE8xzgApabCm31Zyaqho9
         BKJjvhVpBWZnGPqxyyRxjx0IZehfFaaHctvP8M/AGSF78dnOuDCc1vHVgC9FXRgKBqF1
         a4JjqWP7SBGO1uSRK8MglwrtZSwAqetgheRtQQxS5KhzXud085edoVrGcvrM44mDzqLX
         UWjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772657; x=1744377457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TykxOcy5QEdcmxmREh7EeohqyZLCDtHX2TyvWzvbg7E=;
        b=wOt9jmdVSLib/yyuSJReAQDGqeKmpttypc3kck64TWOW4zqbl1vOMhLS4993+LjhIO
         I/D75yUPncAUGCYj5tqYCsI57ulHTcfabSDSpdvTL60Fes42Mbzu2VntTlOQM40RtsAm
         M3hGmv+U8tlEDVLVU0ovFkbeaHJLSKAqX20AomTvXf0M24URMGcCYdzR7Fgm2pxkKsH4
         saWQ/zBWq/lSj4IIAMO0julvn2xI0Z/h8/HBE8hJQnJ5oO5Hmxzi5fwgQz+V6SA6sywM
         3Hz4JT1KeEVZyQDUKtTSyeEGQk/Mly3Xbql1sGIhLsboOJnETuMdPk9pHJRNyuBM3AxP
         D7bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSi9HV8zdjtXHowMEkJlZipX5ngZcNPgwLenLozzzopmQQ1hb6/HEOwuqK7f/+dLTr+lEJ9w==@lfdr.de
X-Gm-Message-State: AOJu0YzYmLqZPGlZawBHi5vo/v2fZK1chtsZSmecRg+1x1SZlBeELROd
	LhDpfPQJlFWLlEDWp6GWx83ZOOR7q1RgdXJ7fBvrtsUoHhlRmcQ3
X-Google-Smtp-Source: AGHT+IGQJD5EWCR4etiGsS4vtoLN7sysnrlc3PMjk+xHdJYTXmzSbZ+XvclaiFcXR9LN4fy0BQ5MsQ==
X-Received: by 2002:a05:6870:de14:b0:297:23a8:1e0 with SMTP id 586e51a60fabf-2cc9e08c3a7mr1755925fac.0.1743772657063;
        Fri, 04 Apr 2025 06:17:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI5xBstSbbFHpa3/QwKr402a1nZjTHFYD5qO+VFzEJZlg==
Received: by 2002:a05:6871:d085:b0:2b8:f3e5:a817 with SMTP id
 586e51a60fabf-2cc7ab25535ls618573fac.2.-pod-prod-02-us; Fri, 04 Apr 2025
 06:17:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQ67H3/m5xanON0dvPlrCHSmVkWZi4/K8n+qYN+lLz76/Vjcg7pp4bDo2HgNryW6snXXcdEjDn03M=@googlegroups.com
X-Received: by 2002:a05:6871:630d:b0:2b7:d3f1:dc72 with SMTP id 586e51a60fabf-2cc9e7e1439mr1915892fac.29.1743772655422;
        Fri, 04 Apr 2025 06:17:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772655; cv=none;
        d=google.com; s=arc-20240605;
        b=fcPpF+GTsyXGXbl9HaJ9CWBSpZNOLekjkMpCsVoWG01ANdKt1MMvwWUFflMSztENkH
         Io2DpTsLf/1jip+0aqmzgF4F8S5/b9W7kHE1l69e5al090Ock1iEvuDmokELixj1g4V4
         zTpnAAAU+bAMXMsoHTdBiJhaVTdG+2jGUzCJCyBPBGS7DXoyi+alThUlrW8F+OfiiuVB
         EE8XDNpjNDRXWb6hbD+bH8dz/AgYtCj4NRGMQMp9u/kgJm8pm8W4Ciawzo6TF2iTeHAz
         +bsVxPSWjmi3fVp85TpCyxdF5JG5fXdZ4lQgqtbHXQIQuFCORztG6InvjdXAkiZyRh5m
         Ph8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YmTEjrWSa8coBPFUOPSr23Xq/XeudCw3/a4+DRkDMns=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=GgARrGeJNDts6lZX8KOhEf11saLGMWt1N5x8rtQOmSd7nzp+Y6l5/Gycjly/0oDJmS
         Az2P7YF3OOcKWWKCb6ICun49Xvb52mjB+fEXgFA6kyGZBby4OJIjJVd0na1LZrf3Znqk
         AGHTxk/UQjjx1aS5e+VaJL0bS57inkuG7a1kHpTDS2b4oZ/HE/CFMMUV7pTHUc+81UCW
         72Smq4pvg+bwzbwwqfBqvtfkzBF4dStm3KGpzLf7y1uOgxIaAAFIELTzU0BaXknnFGFQ
         g/sXpRSMwNROhiUlN00I4HPv2tiQvuK4DpJk4PLadBx3lkJBPok/D80qwT02JpEGpqQ6
         krcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NNCjA02e;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2cc845e0d28si186538fac.2.2025.04.04.06.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:17:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: w3gU6DY8TUumHJ7f4fHbLw==
X-CSE-MsgGUID: pQGLUeUtQiaQH9pWdvra8g==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401994"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401994"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:33 -0700
X-CSE-ConnectionGUID: FCqpUyFdSE+x8MZMxgr8BA==
X-CSE-MsgGUID: 2YHQdmbJQX2GJD9jL/iewQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128157352"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:17:18 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: hpa@zytor.com,
	hch@infradead.org,
	nick.desaulniers+lkml@gmail.com,
	kuan-ying.lee@canonical.com,
	masahiroy@kernel.org,
	samuel.holland@sifive.com,
	mingo@redhat.com,
	corbet@lwn.net,
	ryabinin.a.a@gmail.com,
	guoweikang.kernel@gmail.com,
	jpoimboe@kernel.org,
	ardb@kernel.org,
	vincenzo.frascino@arm.com,
	glider@google.com,
	kirill.shutemov@linux.intel.com,
	apopple@nvidia.com,
	samitolvanen@google.com,
	maciej.wieczor-retman@intel.com,
	kaleshsingh@google.com,
	jgross@suse.com,
	andreyknvl@gmail.com,
	scott@os.amperecomputing.com,
	tony.luck@intel.com,
	dvyukov@google.com,
	pasha.tatashin@soleen.com,
	ziy@nvidia.com,
	broonie@kernel.org,
	gatlin.newhouse@gmail.com,
	jackmanb@google.com,
	wangkefeng.wang@huawei.com,
	thiago.bauermann@linaro.org,
	tglx@linutronix.de,
	kees@kernel.org,
	akpm@linux-foundation.org,
	jason.andryuk@amd.com,
	snovitoll@gmail.com,
	xin@zytor.com,
	jan.kiszka@siemens.com,
	bp@alien8.de,
	rppt@kernel.org,
	peterz@infradead.org,
	pankaj.gupta@amd.com,
	thuth@redhat.com,
	andriy.shevchenko@linux.intel.com,
	joel.granados@kernel.org,
	kbingham@kernel.org,
	nicolas@fjasle.eu,
	mark.rutland@arm.com,
	surenb@google.com,
	catalin.marinas@arm.com,
	morbo@google.com,
	justinstitt@google.com,
	ubizjak@gmail.com,
	jhubbard@nvidia.com,
	urezki@gmail.com,
	dave.hansen@linux.intel.com,
	bhe@redhat.com,
	luto@kernel.org,
	baohua@kernel.org,
	nathan@kernel.org,
	will@kernel.org,
	brgerst@gmail.com
Cc: llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	x86@kernel.org
Subject: [PATCH v3 11/14] x86: Handle int3 for inline KASAN reports
Date: Fri,  4 Apr 2025 15:14:15 +0200
Message-ID: <012c84049b853d6853a7d6c887ce0c2323bcd80a.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NNCjA02e;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
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

When a tag mismatch happens in inline software tag-based KASAN on x86 an
int3 instruction is executed and needs proper handling.

Call kasan_report() from the int3 handler and pass down the proper
information from registers - RDI should contain the problematic address
and RAX other metadata.

Also early return from the int3 selftest if inline KASAN is enabled
since it will cause a kernel panic otherwise.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Add this patch to the series.

 arch/x86/kernel/alternative.c |  3 ++
 arch/x86/kernel/traps.c       | 52 +++++++++++++++++++++++++++++++++++
 2 files changed, 55 insertions(+)

diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
index bf82c6f7d690..ba277a25b57f 100644
--- a/arch/x86/kernel/alternative.c
+++ b/arch/x86/kernel/alternative.c
@@ -1979,6 +1979,9 @@ static noinline void __init int3_selftest(void)
 	};
 	unsigned int val = 0;
 
+	if (IS_ENABLED(CONFIG_KASAN_INLINE))
+		return;
+
 	BUG_ON(register_die_notifier(&int3_exception_nb));
 
 	/*
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 9f88b8a78e50..32c81fc2d439 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -16,6 +16,7 @@
 #include <linux/interrupt.h>
 #include <linux/kallsyms.h>
 #include <linux/kmsan.h>
+#include <linux/kasan.h>
 #include <linux/spinlock.h>
 #include <linux/kprobes.h>
 #include <linux/uaccess.h>
@@ -849,6 +850,51 @@ DEFINE_IDTENTRY_ERRORCODE(exc_general_protection)
 	cond_local_irq_disable(regs);
 }
 
+#ifdef CONFIG_KASAN_SW_TAGS
+
+#define KASAN_RAX_RECOVER	0x20
+#define KASAN_RAX_WRITE	0x10
+#define KASAN_RAX_SIZE_MASK	0x0f
+#define KASAN_RAX_SIZE(rax)	(1 << ((rax) & KASAN_RAX_SIZE_MASK))
+
+static bool kasan_handler(struct pt_regs *regs)
+{
+	int metadata = regs->ax;
+	u64 addr = regs->di;
+	u64 pc = regs->ip;
+	bool recover = metadata & KASAN_RAX_RECOVER;
+	bool write = metadata & KASAN_RAX_WRITE;
+	size_t size = KASAN_RAX_SIZE(metadata);
+
+	if (!IS_ENABLED(CONFIG_KASAN_INLINE))
+		return false;
+
+	if (user_mode(regs))
+		return false;
+
+	kasan_report((void *)addr, size, write, pc);
+
+	/*
+	 * The instrumentation allows to control whether we can proceed after
+	 * a crash was detected. This is done by passing the -recover flag to
+	 * the compiler. Disabling recovery allows to generate more compact
+	 * code.
+	 *
+	 * Unfortunately disabling recovery doesn't work for the kernel right
+	 * now. KASAN reporting is disabled in some contexts (for example when
+	 * the allocator accesses slab object metadata; this is controlled by
+	 * current->kasan_depth). All these accesses are detected by the tool,
+	 * even though the reports for them are not printed.
+	 *
+	 * This is something that might be fixed at some point in the future.
+	 */
+	if (!recover)
+		die("Oops - KASAN", regs, 0);
+	return true;
+}
+
+#endif
+
 static bool do_int3(struct pt_regs *regs)
 {
 	int res;
@@ -863,6 +909,12 @@ static bool do_int3(struct pt_regs *regs)
 	if (kprobe_int3_handler(regs))
 		return true;
 #endif
+
+#ifdef CONFIG_KASAN_SW_TAGS
+	if (kasan_handler(regs))
+		return true;
+#endif
+
 	res = notify_die(DIE_INT3, "int3", regs, 0, X86_TRAP_BP, SIGTRAP);
 
 	return res == NOTIFY_STOP;
-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/012c84049b853d6853a7d6c887ce0c2323bcd80a.1743772053.git.maciej.wieczor-retman%40intel.com.
