Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XRZT5QKGQETTR2LPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 76DE227CF59
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:38:51 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id y136sf2079220ooa.14
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:38:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386730; cv=pass;
        d=google.com; s=arc-20160816;
        b=d2Ltd7506tvgTDEFooyg350X2drcfIa9+ps8OM59/onTD9peHlkIGUlxkaOGrBmL8Y
         vzAK9QkzpZaiBNUEtMYCE3L2dInVOGFzZ+aNT7P9PRwyjce+Eo6PSzjfeUGHevAgIZbi
         ZxZej2FkByxqjoGFl1Z4sY7WKxza56oKYsp9DlhFzXZz3h2tbMAeivRCeVD2QUEpZswN
         vgerjRTFMNNhWGc+DEMvKJKrMPjfty+K6WwkVSaHADXzjtC3UclTJ8bmIHVXN285n9Zx
         TDZYEfSSPfNIDai/TVtLEheafpjjoL8EMdWRgzGd2h2gJudcMA5ttY+rg7KCSo4FiKUI
         TXoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sOzix3TVMxHv9IwpAZM33XqpNud/xmV+fkueoN9rE/M=;
        b=paXHzbMTMYYlN7qLi3KwdK8wGkAp3Z7qMF3kWFaF8vxY8uk9kv5+ysGW9SQvJeJCnG
         4ycgCZbIpSLErBni+567TSmpDEFoYrIUo0QPJMNDr2orZbNl5junB9BVf4i/wx6RuXRv
         i9q1h5/lpy/xu9pcNRVDxfGhghyyaBjnZ7DPtY4txnpj55flaCXisDG56yvKsnXt6SRx
         vuuD38jVadYUrmDq9Z+OXl6tWGddWCGQW5K9FpUhiRhnrOEmgR+Dp8AR4XKIaZAOqOCF
         rh2XHiRG1Gt+DnDLcIP0hzvRV/ZIz/KSIVEeYWn69eF0i5vHIlrMDk4v4n3FWSMMk9zz
         wSlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M3qvQTHw;
       spf=pass (google.com: domain of 36thzxwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36ThzXwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sOzix3TVMxHv9IwpAZM33XqpNud/xmV+fkueoN9rE/M=;
        b=nDlu0gIL/9yUrOmRUoEr4wzDDPHUmmCKlhqMuKtAfaH7mGtVewxN4lXI29tpCfcBkg
         GimL73ZA6Q3um2lt7S+Yj/aN3hstwDkk7RX8mo6tOtYyzCrtEx5qtBnoxiw68o/PX6Z0
         u976Ely7naLJAwRqh2QyaMCdHBTHEi4GlZVFUKgqcKcMq/a/8gPLIDuosYdLFA6Br3H1
         KFLrdopfNG7SSmcwdwbld3PRoIGiTgzu7eiy7aNfH/LHrkHo9HefTXDw1NqLn5DEM+jW
         Upijrvkgl18DCuIqodomcAAW40U9X5OuAkumBtIokpC+y8k+sGjUOT4QPpwKoSv22zYz
         7ySA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sOzix3TVMxHv9IwpAZM33XqpNud/xmV+fkueoN9rE/M=;
        b=uCr5wyA1J082TEAQKHLr1KqnU8QmMpEleLcTtj2Xxdmk/pA8DHQAUFrjR/OQY8reOe
         UhiCng5D2SjRScM4XkTnn9wIPQsrVE8A2R1PPgeyDjowK83qSxsljmS4gF5TcvUGqlRj
         /UEljoK20qCdvmIA1SS6DpgKY+pVMHiaO3z1vu6hsUbOQZnVtZhtlRdv5cYTrA7DNMp3
         HYzCVUsa0Dzx9W5CxwvkjVrHUrM8GOOFZxuu64qBSGrcVtagMMtlBDxuOv4IvIFWZcLp
         qgaIDFmgbUDLlqukEhZjigq1tB+u/ouc42/XsbHyUd1Pz5eRAnt4cCaDlgE1SboMtqHn
         Bx6Q==
X-Gm-Message-State: AOAM5317BGvk6OOeBb8LHHfb1Rc4GmFB0mnwk9cxsZgJCHNb87uq4nq2
	UoZnYDOTwTtg2SqUEXrjIgc=
X-Google-Smtp-Source: ABdhPJxcaar1UaovSHzWeFkOtZm48cQjF7JjtIhlanMnpQENI1Khs+gZbqvyimG2YMPYMPHVXYKTfw==
X-Received: by 2002:a9d:6a0e:: with SMTP id g14mr2746422otn.126.1601386730373;
        Tue, 29 Sep 2020 06:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b88b:: with SMTP id i133ls162326oif.10.gmail; Tue, 29
 Sep 2020 06:38:50 -0700 (PDT)
X-Received: by 2002:aca:d4cc:: with SMTP id l195mr2732766oig.16.1601386730020;
        Tue, 29 Sep 2020 06:38:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386730; cv=none;
        d=google.com; s=arc-20160816;
        b=d4uvddUlN8EBj7Os7dJc6r7YXJi+JPE9Y0IeL/Ov0hlu6775rmD9NKW9sEgE7krIdM
         A78wm9iMM4Hr+kLO6wcRgx0EK/PNi+aejAL10l/+bZNnUNlnHPXoyr78yfaDNxIzQvSV
         SmbFdljIRNmQ2W2qJdNxs+s/hxyFdazbDL2oGrQCN9L+zrf0DeAC6dF+jFCOlvMqg7y9
         UlEMN6/FC7R1wFQX4cXov50RiPOLzU3Wxz8OuPsJx37GmVoqdY6r5GFrR0C/8hxnBUjC
         luCzOO+wsq0dDvDFwdpLtcxzvAe1mriwB1D14qDSbPhogzn65MzRF6A6sK/tphT85wtH
         N3XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qLrQI/JwUn36fq2luHZslhJ1uvvVQDF6ByQHZzaen98=;
        b=uClZaKRNEC59pXdV69/LFN3mOW8DXBTputilecKlWNFZ7ezjOEPQSLXjFAFvNKaMNN
         qg4UwAY1WEZi7gu1oS5GlO0L4OKTuoQNJGgSDb7uzY5ciHTvw7QMEwoJ8bz6KhWoUHKE
         C5rwvZ6nH2KffhHB9bnEA7gF8VorD/mraA+GDAyu2im0XxU7fktzKdmDDBhfW4u2xRNM
         pDJs+aO0fsadDJ72rcY0xf8sm/XWNgCK+S68nEXl8u9kAlqqXYVlAQLSEM7jSDev9hkb
         0Zss6kA2JhoMWCpw4HcP0XiSNuKFqf87BTFrip7KHDPkGeqM1RzKWQR8kRHW/Sh6LtRz
         fY0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M3qvQTHw;
       spf=pass (google.com: domain of 36thzxwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36ThzXwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q10si733569oov.2.2020.09.29.06.38.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:38:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36thzxwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id j10so4756107ybl.19
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:38:49 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a5b:d43:: with SMTP id f3mr5632739ybr.46.1601386729429;
 Tue, 29 Sep 2020 06:38:49 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:06 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-4-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 03/11] arm64, kfence: enable KFENCE for ARM64
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=M3qvQTHw;       spf=pass
 (google.com: domain of 36thzxwukcsokrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=36ThzXwUKCSoKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

Add architecture specific implementation details for KFENCE and enable
KFENCE for the arm64 architecture. In particular, this implements the
required interface in <asm/kfence.h>. Currently, the arm64 version does
not yet use a statically allocated memory pool, at the cost of a pointer
load for each is_kfence_address().

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 arch/arm64/Kconfig              |  1 +
 arch/arm64/include/asm/kfence.h | 39 +++++++++++++++++++++++++++++++++
 arch/arm64/mm/fault.c           |  4 ++++
 3 files changed, 44 insertions(+)
 create mode 100644 arch/arm64/include/asm/kfence.h

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 6d232837cbee..1acc6b2877c3 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -132,6 +132,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KFENCE if (!ARM64_16K_PAGES && !ARM64_64K_PAGES)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
new file mode 100644
index 000000000000..608dde80e5ca
--- /dev/null
+++ b/arch/arm64/include/asm/kfence.h
@@ -0,0 +1,39 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+#ifndef __ASM_KFENCE_H
+#define __ASM_KFENCE_H
+
+#include <linux/kfence.h>
+#include <linux/log2.h>
+#include <linux/mm.h>
+
+#include <asm/cacheflush.h>
+
+#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"
+
+/*
+ * FIXME: Support HAVE_ARCH_KFENCE_STATIC_POOL: Use the statically allocated
+ * __kfence_pool, to avoid the extra pointer load for is_kfence_address(). By
+ * default, however, we do not have struct pages for static allocations.
+ */
+
+static inline bool arch_kfence_initialize_pool(void)
+{
+	const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
+	struct page *pages = alloc_pages(GFP_KERNEL, num_pages);
+
+	if (!pages)
+		return false;
+
+	__kfence_pool = page_address(pages);
+	return true;
+}
+
+static inline bool kfence_protect_page(unsigned long addr, bool protect)
+{
+	set_memory_valid(addr, 1, !protect);
+
+	return true;
+}
+
+#endif /* __ASM_KFENCE_H */
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index f07333e86c2f..d5b72ecbeeea 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -10,6 +10,7 @@
 #include <linux/acpi.h>
 #include <linux/bitfield.h>
 #include <linux/extable.h>
+#include <linux/kfence.h>
 #include <linux/signal.h>
 #include <linux/mm.h>
 #include <linux/hardirq.h>
@@ -310,6 +311,9 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (kfence_handle_page_fault(addr))
+		return;
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-4-elver%40google.com.
