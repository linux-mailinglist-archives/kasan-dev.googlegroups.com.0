Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU4H7SKQMGQEC3H5PAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 50C6956354A
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:24 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id e10-20020a19674a000000b0047f8d95f43csf1205663lfj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685523; cv=pass;
        d=google.com; s=arc-20160816;
        b=uQug3M5NvGbWqEoz29bI4ckOqO8gVoc2Boxqtz3VsyMRvw5X4UAP1IvB5+h6myFoAl
         zcihmDxAVqDqzf5I2AalmR8jXKosL9rWk9lcW6JNc7aO4xTf4xU/45P1vrSvcyp2/l1l
         vhZh8IxcJoPo26O7MvDZMee6qZpB98vamPpPFpZS/oai9ZkGFx6ytlGjcsiSr4u4gv6F
         LDlZa6F4m3pksERLULENpGoHqAbIbPHIkKb7sao/RGc+8DM5jFjE3AcwoAWgnbAHGGFp
         wC0YrIj71/NgOGFOwo848MybtfjnlHJuL7nlR4SEmxUJdDsVWBgmjoroMCmhT8aqgVnX
         ASXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fTnWFbjS+YcnE3vG9KAZm7cdWcIwlKDZmUV50KbkpEE=;
        b=bLVPUdZUdl5+rb/LD4GhBRQ9GxYady+HyzVNLFMw3KRL75IHbnykacRwy8CEtwzf95
         ygJpQp1i8uNwPIdACvI4R2s0JKmtPnup50bavX00KjopWH9ku/6LP4MNMVlKvnCdG6gp
         vmzS514C/iEqMVCTlOcPV6tSS+BmKmN9eoFk7Rm9nDlHQsRKZ//Vedatqdhoaq0SgKDU
         2iE7JBYHrJtMXhVqJZydUDf2ibLA/Lj7RwYYK4wsDwt1oLTZUXrtEUU85qwAEUyQuxhq
         LbS8uIZmPRLfa7WEtFZ75eSGmOqj7hns86E4skIbYwl5VZdJ82MnA9upPar4L+iVwmsf
         U68Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TJFxAn5S;
       spf=pass (google.com: domain of 30qo_ygykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30QO_YgYKCfAYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fTnWFbjS+YcnE3vG9KAZm7cdWcIwlKDZmUV50KbkpEE=;
        b=H2bu5+nAwZ3RPN4m9sJwYoif3Z6+KXeijo3I0ivo8eXLzjym4QcyAs7UZ2Bq5nip8S
         E5aSTBZrg1dXtgiaUjo1on2rFO8GoGJVwKf/ARb4DZ92DtqfXeXyDsVCQq3v377fuAUz
         k99CP23RayWgvRcKEkVkZx3aEmLpkfKB6eOjnz0Dcmz3HHGvYLr/b4YcnV2mnVWIuLjg
         FLoJ0fVqy3nme6H0bOfIIAnTYzk7lFdrynCdWCP4RTZfvsjIwLuZU1rpEccoJXf3g1Vt
         XNBcYap4g+XiRpKLxrInPo9g98L0llJBHaezD72lNV5kkdVt9GZd4tWpM/dLqHXosT/4
         itIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fTnWFbjS+YcnE3vG9KAZm7cdWcIwlKDZmUV50KbkpEE=;
        b=0CwoQPUKTmiDsm+YdmJ+6U11E/xGoppn8G++IyMMnH/rPBfsvn7hgnyZ2N9idFnIjz
         pfUviXQUizs6Fi27Uha1w4Y5aL/5WXvr1IgWpopWgEYzv0krIzpUJHZNie5KHpDZGBhg
         qznPKpyRLLmfhYhrP5OD+tPSm782W6mcC6R41/++fayxozS8t6xat0wIiiTMN/dUmQm9
         X4Qn/eSZez+mKl4wx8wm8UelLqSbQAQogzxsXwIYIcWdJtpI+nApSgP0IomOmebyQtpn
         TDaLJLTtLlJOsU8Qq7w2+IgjdgqDqGq43CkHfwl4E7lKmT6QMog7yDxWxJHap63YBVbe
         WFKw==
X-Gm-Message-State: AJIora9DHioYDg/i1j9aMbp1a534qkMiymBu9UZF0VrYFmV6JFksE7z6
	QPhGf1qOC+cWSFKh5R4vwM0=
X-Google-Smtp-Source: AGRyM1u0Vlf4GWZaDpGjNCbdD3B4uqOQfsIV2Ir9GM18LRJ6kP9D68yQHoPxVIMkR8G622GxUEkjoA==
X-Received: by 2002:a2e:88d3:0:b0:25b:b79e:9501 with SMTP id a19-20020a2e88d3000000b0025bb79e9501mr8366114ljk.315.1656685523608;
        Fri, 01 Jul 2022 07:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls89757lfv.3.gmail; Fri, 01 Jul 2022
 07:25:22 -0700 (PDT)
X-Received: by 2002:a05:6512:b8d:b0:47f:74f0:729b with SMTP id b13-20020a0565120b8d00b0047f74f0729bmr9194800lfv.403.1656685521914;
        Fri, 01 Jul 2022 07:25:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685521; cv=none;
        d=google.com; s=arc-20160816;
        b=U5Q82ZtpbbHKdTboa5/NZYdP7amA49p96bZvjtUqO3RCsPQcKzDVxCGWVjU9owjL3W
         g928f//AneWMmI1cm4RWznef4+CCAvKp5cjpzIk4fEXToX/CvHncPoEFYjhAwtoflf1E
         ex/i9f9p/s+oh4ljrWdUPx+zFoeY78OQqHOjMk2jeJqeiy9SkICCEYoufX8qw/RaDnFw
         lO678tqkHDlnj3DhOhrnPX6UMMaRMf9t3uuauQcFI96SQ1Y3WL51tjNcJN/lBz3aHoJM
         zx9sOsxopE93p3z3g5q1AU3eZKA+TfbXjzFjYYunw1jsph6Tk+75hwEqV/GOVFLcn1ZC
         4lXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=auy4Z9/QbdBH93W7clb5ShO/bvtQNUkdCMoxr4yxtk4=;
        b=BizqBVJs8te5gB5auuoyxzihajz43YwB4cuMXRdRZ+DOLMBXd3ni6rM4TmzjAoObR0
         HV9QE7Mrs2EuN5qDh3/Z2Pi6wTzF2qvpdatq7BzahHti/nRP4dlkR/xcegT12ZZL/jGt
         sMEFns53dI+CX5PXIsJ9FhZ5b+Zr/B2rO4yRsqxJBmO3qebLWjyGrrboXf7iJKnggGpE
         b2Dkgad8fTW++BpsAX09NhgJWByEyUJ7ygXIqR0Xxz6E0et+4wzBR2iUjKqQFi6W2cNb
         lJI+nwYyX3Lu3mJKggrCJ+ps0rLtUD/XXNPkclf49UMzrmzAYLCfI7Ee2E44seeeb9c2
         fH0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TJFxAn5S;
       spf=pass (google.com: domain of 30qo_ygykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30QO_YgYKCfAYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id z14-20020a05651c11ce00b0025a7388680bsi651318ljo.6.2022.07.01.07.25.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30qo_ygykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id x8-20020a056402414800b0042d8498f50aso1888322eda.23
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:21 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:4408:b0:435:9ed2:9be with SMTP id
 y8-20020a056402440800b004359ed209bemr18990092eda.81.1656685521229; Fri, 01
 Jul 2022 07:25:21 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:10 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-46-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 45/45] x86: kmsan: enable KMSAN builds for x86
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TJFxAn5S;       spf=pass
 (google.com: domain of 30qo_ygykcfaydavwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=30QO_YgYKCfAYdaVWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--glider.bounces.google.com;
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
index aadbb16a59f01..d1a601111b277 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -169,6 +169,7 @@ config X86
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-46-glider%40google.com.
