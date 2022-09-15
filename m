Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7P6RSMQMGQEXJMMYTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B2545B9E38
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:37 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id sc31-20020a1709078a1f00b0077ef3eec7d7sf5442962ejc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254397; cv=pass;
        d=google.com; s=arc-20160816;
        b=B+soLJQrlmDu11thZPKbt/Hr7nIRmGyS3/JMCav+9V2f9nIEaMwtvC1B855EBgBYYX
         fbfwOnhwSsGY7PECVoX9IhZCICy/q+F5uYLBP/AHFIrO61y7qFVw+//lhdx42GXUNsah
         Q+lLVJTVnxzmiOkT1R9LJ0JRFDFwMv7AGXBNF9rL4Op5Gyhr37wlnlnPqwPUa+RKRsn5
         Q2FlcDT+Rf3TVltQd1WcHIpl6y+Wx0GEzeYoP+XWPW/ME735MN3t3dvHDSSBrwOYQ97B
         fG/i8s4MDnaCY/f1qzxf2DFqasx7J4KpAV1Z9U3ID6UxHTp/baAodI70PMp87X1vH7L9
         jozw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=KMlsRow11LshkumRafZLtdNuyA2DMYGfQqv/es2UOq4=;
        b=VB+2soIq0CJfGkguaQikoMlc3emPFOv2t/UpvPKqiShwVXTcfgaKyHG+w6t5XE7KIJ
         P/z+/y2SHfy55lIH6lopop+E+9+cHAhY9CgzNKd6vWtDdr1LHMP5OJUh0QFgQBs2sL1G
         mXk8n5gBeQg0Mc6HoEgK5MiRR5cH2BjCfjo5qQvN/S5dBB8ATTtldqkuUrZUeq0zX+BW
         Gh0uL6xyJMuAaHwQPIjAri0EMPbVcf4FPWgS7Kx4e/s/FiOb8Rc5l3xLEKPKXi8esYD9
         2a2BOlaAj5UvxqKvYpEIw4PhiN6WGc8WLnCk2nWj6EDXJpysi60ice0/450pGMwLIh7G
         wFXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BdvNjfu5;
       spf=pass (google.com: domain of 3ez8jywykcaymrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ez8jYwYKCaYMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=KMlsRow11LshkumRafZLtdNuyA2DMYGfQqv/es2UOq4=;
        b=JxJI+S6W3qEBAGiyeDljSS6lM3l8UZUEkqohGqxZzunZGXW53dp5PJKNef8QoumD1p
         POmCyWu4NMMMal5EoDL8zyqzIrNOLc9m05CIkw6Pcofwr2fNTgwXixq3CnCGU48ypib2
         wjI4etR8dAjY/nCA8DHmSQKDxWOcwMRcG5hMsSkaVo0/qu1Alm0AtzR0cck4O5qc7aPH
         sv7t3YxkWuUQSOL69RKRnG99qqV+Wx1uONJ7PQoRNSG7tkR0KxzNvcs4tfwCKhrnau6T
         896vBXVnVvrS/YaLQHRXpI37LQ1802k8qtdIDT9+Ry+pt0swmbzG6NzmlM1IJvcoyfCI
         nutA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=KMlsRow11LshkumRafZLtdNuyA2DMYGfQqv/es2UOq4=;
        b=XzJfJiJ00gxNNwgmrxH7XJlFP21sZisnZHATM/KLPwSuXduLKA5UdQsm5L9npsOlIG
         ZOc1Y0Pm8q4f/Wc2/0ySdVbyUfD1EBjV1A7Dc00+wAP7xDwAwfyTVDPEOT1titdsrk7H
         /dTNg3iwdKm9RHzvbmIiSJknFIkWXWet2Mnf48W6b8hflAg3eXagcpIIzaV2P47Ibp4z
         s1SaLRjVtrcIn+x/6IvHrNiQpkSCGhr9EuAXH2JbV5bZuHiZ9xNF4QLFmTGmZPEPB00Y
         qngTBoFw0fppfsK9EzPKeb9DNmH6Kil9Z9Ff5mp8Nw011AIGg7WYG3NFYts69uvNua9E
         HJlQ==
X-Gm-Message-State: ACrzQf3gSllf0IypOVQ8jvAgrCisG/4axomwURUaL4W/+MZJaoxZza4w
	VUlY1jOp7XyNV0/M6CpYruU=
X-Google-Smtp-Source: AMsMyM7uNFnUn6Ow+TBqGdwtaKiK1NgOCk16gmkqJ1LW5ylMzcqIZVWj66EVxoS/Eym+g90BnaiYlw==
X-Received: by 2002:a17:906:9bdc:b0:77e:1ed1:b12 with SMTP id de28-20020a1709069bdc00b0077e1ed10b12mr285160ejc.661.1663254397293;
        Thu, 15 Sep 2022 08:06:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a444:b0:73d:75ed:a850 with SMTP id
 cb4-20020a170906a44400b0073d75eda850ls2519822ejb.2.-pod-prod-gmail; Thu, 15
 Sep 2022 08:06:36 -0700 (PDT)
X-Received: by 2002:a17:907:2da6:b0:73d:d587:6213 with SMTP id gt38-20020a1709072da600b0073dd5876213mr306874ejc.5.1663254396207;
        Thu, 15 Sep 2022 08:06:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254396; cv=none;
        d=google.com; s=arc-20160816;
        b=iuUwLuwJAzaLUmaekc7M0iigPCVVxzx3aVEr8Jq0NgyjUzjshRHz6ZTMwX6KLoSvIW
         WdRzqKMUrOtagwkal3Ce45g+qh0Eem9uP4V2AXvUtZatga6Fqfm596ko/BqKWY/h7pbY
         Crek61GG1eGqhjNRY3GLBdRAf/5PKeAs8ZGtex2gtmQ5XOsioUizYQM4QSfIoT2OkJYJ
         wJ8dWnbVyVWRTFEU3DMU7ZkUDhntxfeG5UDQ3ePlxZFJF+SZkWyjWhSglNu5ee3irFQD
         4C1GhNlkdskehLvSj0fgEL6kNl0Sa1GddMpra1Iv8w74jU4GIce58mY+zQywVy96GeuM
         HtcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=qWMR0SPZO0jqHHxoNfMsk5w/9uuaYeqiCUk8OeqbWGY=;
        b=eA+Tb3m9PDLTwOwJmFE3SF9uzkjElryN4W1GF+YqChh3bJGqOecJr1Il4pyBt38FEE
         Q2L6+2ssIPS+Mjz+zkaYB2zriMaksAnmXt/49djcOq7kM56ByT8zFguvcdW7wxp/RSuO
         m2xysSb//6lVs+x1WcMBoCDV2Qi1gruC2Q5a0B6pBwlIjVRBuNHBh7VCVrVxnaPuHtGm
         A2364qqiY6pQwOolQUYMtQW8SINyVcXhqzWAExLsGPfh/Q6H4rTO5X3Mr9Xf8IQ0i07x
         v8V5RdAnnu3Jy0rNP4tQJ1gZQAg1RIlZKDFas6HkijvxNarhBPnPxp6SBEHdIGG9Onb3
         XnHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BdvNjfu5;
       spf=pass (google.com: domain of 3ez8jywykcaymrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ez8jYwYKCaYMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c12-20020a056402158c00b0044608a57fbesi551893edv.4.2022.09.15.08.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ez8jywykcaymrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id r11-20020a05640251cb00b004516feb8c09so10387747edd.10
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:36 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:a0e:b0:780:72bb:5ce4 with SMTP id
 bb14-20020a1709070a0e00b0078072bb5ce4mr321825ejc.234.1663254395778; Thu, 15
 Sep 2022 08:06:35 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:17 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-44-glider@google.com>
Subject: [PATCH v7 43/43] x86: kmsan: enable KMSAN builds for x86
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BdvNjfu5;       spf=pass
 (google.com: domain of 3ez8jywykcaymrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ez8jYwYKCaYMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Make KMSAN usable by adding the necessary Kconfig bits.

Also declare x86-specific functions checking address validity
in arch/x86/include/asm/kmsan.h.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v4:
 -- per Marco Elver's request, create arch/x86/include/asm/kmsan.h
    and move arch-specific inline functions there.

Link: https://linux-review.googlesource.com/id/I1d295ce8159ce15faa496d20089d953a919c125e
---
 arch/x86/Kconfig             |  1 +
 arch/x86/include/asm/kmsan.h | 55 ++++++++++++++++++++++++++++++++++++
 2 files changed, 56 insertions(+)
 create mode 100644 arch/x86/include/asm/kmsan.h

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 697da8dae1418..bd9436cd0f29b 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -168,6 +168,7 @@ config X86
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
 	select HAVE_ARCH_KFENCE
+	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS		if MMU
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
diff --git a/arch/x86/include/asm/kmsan.h b/arch/x86/include/asm/kmsan.h
new file mode 100644
index 0000000000000..a790b865d0a68
--- /dev/null
+++ b/arch/x86/include/asm/kmsan.h
@@ -0,0 +1,55 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * x86 KMSAN support.
+ *
+ * Copyright (C) 2022, Google LLC
+ * Author: Alexander Potapenko <glider@google.com>
+ */
+
+#ifndef _ASM_X86_KMSAN_H
+#define _ASM_X86_KMSAN_H
+
+#ifndef MODULE
+
+#include <asm/processor.h>
+#include <linux/mmzone.h>
+
+/*
+ * Taken from arch/x86/mm/physaddr.h to avoid using an instrumented version.
+ */
+static inline bool kmsan_phys_addr_valid(unsigned long addr)
+{
+	if (IS_ENABLED(CONFIG_PHYS_ADDR_T_64BIT))
+		return !(addr >> boot_cpu_data.x86_phys_bits);
+	else
+		return true;
+}
+
+/*
+ * Taken from arch/x86/mm/physaddr.c to avoid using an instrumented version.
+ */
+static inline bool kmsan_virt_addr_valid(void *addr)
+{
+	unsigned long x = (unsigned long)addr;
+	unsigned long y = x - __START_KERNEL_map;
+
+	/* use the carry flag to determine if x was < __START_KERNEL_map */
+	if (unlikely(x > y)) {
+		x = y + phys_base;
+
+		if (y >= KERNEL_IMAGE_SIZE)
+			return false;
+	} else {
+		x = y + (__START_KERNEL_map - PAGE_OFFSET);
+
+		/* carry flag will be set if starting x was >= PAGE_OFFSET */
+		if ((x > y) || !kmsan_phys_addr_valid(x))
+			return false;
+	}
+
+	return pfn_valid(x >> PAGE_SHIFT);
+}
+
+#endif /* !MODULE */
+
+#endif /* _ASM_X86_KMSAN_H */
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-44-glider%40google.com.
