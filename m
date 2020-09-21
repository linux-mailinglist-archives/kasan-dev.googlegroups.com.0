Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFGUUL5QKGQECO7FL2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id D3D72272560
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:26:45 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id d15sf13164321ybk.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:26:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694805; cv=pass;
        d=google.com; s=arc-20160816;
        b=kiPteS50WKdwfYV4B8jd+PyVBbtu4WSUeFez8/qPbd6J80pimJyj4mN0gh3RlZkQoy
         SX3KK1P7mgACz6x/6A1MdbpzwKzD5yAIjGJTXD1NqDAyk5nLTMlBA5+bfWeDFI0n/OD+
         MF5ZswaGUbz0Vb6Df+jJRHBz2uE4PJUqTbF8m4lZ3UnaWnDltm2Jd/w8eeXYLS8Pn0Hj
         6rkksKtd+fTvM9blQX3G1WbLS1R1Kfs1376N76RJ7E9n+uYZoWfair7eQN962gfg/GLy
         XGDir3s5Q6UT3OtjylvSi00Yg92xcxHgJNAHd7ijnJCkVl7iyL07TQtH0QaxWXXklDtx
         pMkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=P9CJEI8pT9i4/jo8ydEg1aIVxnufDGQc6+WA6PVQnYw=;
        b=B+TD3Gp80ixNt+gTdH/VHDJ8rb2siQ4wfmZWcR/3fhNzSkKTkDNQTaJrj+68MMexUp
         lGZbPDPtqS1qVykBbITIKFsZAwSOrjOcP2/33ioHYsYn06G7vTlf8263XDdiuCSNHGQo
         nscT3g7lAqP5xJXJukmpUKRfb6DNNSi/jt3yFV8ot/zLYl3fc4WOXAbTzNIV3qZCzplA
         hF/EBR3l8FPWYCz7a9GIAg7m6WuTr1J9yujHc724O4gPV5xwnNLUqegJdMLP7NzkPlkt
         +/cdVF3pAolOxOmHWURn60VdutRQ0QAKJztToTPa8Cxfo0EUovT7N6lq8U30AxxVqB8G
         dvPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CTsRusC0;
       spf=pass (google.com: domain of 3e6poxwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3E6poXwUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=P9CJEI8pT9i4/jo8ydEg1aIVxnufDGQc6+WA6PVQnYw=;
        b=RUpCj570UC5l087OsUahbCkN/Wj/3Ehy/mWDQmdxGLx7UixJ1rGOXhn33JjMShgfzH
         mzcI411YUqCt42shoGodQfLdW+IepuJWCWf9pYpDSe3Oh7L09owL+dzPTzeFQ3hmaudW
         HHX7m6uTIvbc8cKgk2+7hmVmhBSwmxUunDebubJjCMXN3WCRlwQx/wY4AZ1G1JXe5TB8
         NBGP/riFWQP01rMvova4DwMb0CHffAr+ibYzpfQxfVd0PtT8VceDPEiwoD1wcF/F/9Zr
         +iHL/YRkC3ldYeGd877tawNJzJpaGLPLZ1rKcUhG5aFmrbDsHDwfJDL0hK6/rjOwAh5p
         Au3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P9CJEI8pT9i4/jo8ydEg1aIVxnufDGQc6+WA6PVQnYw=;
        b=njSumznVyDOHEbAnCdZxXd2WqNSUOhbGsOxOyNNu1LKUvMdkH5Wzlt3zKbEg4s//tw
         X2xE+GmNS+2YJXn8wyzcKWDhk+lHlAnbMfK9CfbvnBSVHvxDOjBBrRlBdv79L/XUIiVC
         //Uw7inSF03MDzkV3B6Xom6u39FLkU3ECa51VafPdXrULtU+hIyGsGTf5HyKi09R83fc
         Kja3T85TtHq6Lpcilb6t7m5FyE7tBeIt+mY4SsDB7cuLDwR1ogL98uUYKc47QFP6BsCl
         8wzpLTmWEZaGD27lz1iKH0bt+7MMepTcrkevB8oznGEHTNJLOzh5u26QWKrliJErne17
         FR7w==
X-Gm-Message-State: AOAM531DkOtublMcMd0DLmUSRj/GS5mC+EMrJUeL4am4VfaH4OE8jpYc
	Hag4SvGhwOpek3lPLeAvmqU=
X-Google-Smtp-Source: ABdhPJzcpUIx9oh4qbcXAFbXY1xwgWKuGwI3sOU1q4yRVdv+ajRhkOoim4bU8oDgQRsAPfuM0PmE8g==
X-Received: by 2002:a25:6887:: with SMTP id d129mr56459303ybc.434.1600694804835;
        Mon, 21 Sep 2020 06:26:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77c3:: with SMTP id s186ls1145544ybc.0.gmail; Mon, 21
 Sep 2020 06:26:44 -0700 (PDT)
X-Received: by 2002:a25:6041:: with SMTP id u62mr69194064ybb.70.1600694804273;
        Mon, 21 Sep 2020 06:26:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694804; cv=none;
        d=google.com; s=arc-20160816;
        b=iq41f0Cz80ZjmHizQixXc22sZPcxHWXmqZ2n0OeFRI7rW9ejEQ/ctcdzMjksAtjzJ5
         MMZgdqzl3BR34B4Gu4r4ddzu1axtD9d5nrUvVEnZsgM7fOc9tSlVw55aXbdqS4RllcSy
         Uj7h+gzBnzKFGG7v90Z15f+FmmLYDUFXZDjg8wlewW35419uFF64GNlxgkcxK9hpBdOs
         8ZmWh1jBIEyfXAQMTqg0g8z24QW5m/nygKYKw6ILdOQ/2bbsTzt5mJLmy3DXuZCRwKKs
         kFwl3A2sZylIyFJGZ+IJNNORoMAzoGHmlZ5Zg5TlQIGM8Gy+Fd2D6jLH2ecFlf7f+Ug+
         QNEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Ix66qFhKSgSVrZqQyJftp2TjE15R0Twg+sH9CEm53D4=;
        b=NQMGU+g9a5eHCBVjw/IVp3mc94ETKjf4qB3B7JHKSsvN7mNlQnNn+En/7zdMIk/Hti
         1ja7jMfsOAjKspxZd1RArJI842fALTa5rzsF/yAU+UGsjR7k696RvwjBbcdZHdCNscsQ
         CEorfQAn9/2inDTvLQtnlgNcHOyozGP61nNCRrtdjQqbtYffF/glkn3aHc8vOi9HMGnM
         TpBgQqiqBctSGmhXBoSghH+z6TiFqcJVqYNPtivap2TAhnUQ+SUZAZmbTKCM4a6aauuD
         KxXBvFxuJJg8V+ZhF94ZAMWFwakDYGPLQhXKXxdkeOy3dstnK40YxUFHCv3gwTDfj31j
         k74w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CTsRusC0;
       spf=pass (google.com: domain of 3e6poxwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3E6poXwUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id s69si622898ybc.4.2020.09.21.06.26.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e6poxwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e6so12858616qtg.13
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:44 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:4b34:: with SMTP id s20mr30490550qvw.51.1600694803653;
 Mon, 21 Sep 2020 06:26:43 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:04 +0200
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
Message-Id: <20200921132611.1700350-4-elver@google.com>
Mime-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
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
 header.i=@google.com header.s=20161025 header.b=CTsRusC0;       spf=pass
 (google.com: domain of 3e6poxwukcqwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3E6poXwUKCQwqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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
For ARM64, we would like to solicit feedback on what the best option is
to obtain a constant address for __kfence_pool. One option is to declare
a memory range in the memory layout to be dedicated to KFENCE (like is
done for KASAN), however, it is unclear if this is the best available
option. We would like to avoid touching the memory layout.
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-4-elver%40google.com.
