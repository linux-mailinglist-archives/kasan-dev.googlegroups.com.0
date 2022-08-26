Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWOEUOMAMGQEDE2XGNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CF1C5A2A96
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:10:17 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id y14-20020a2eb00e000000b00261caee404dsf664113ljk.4
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:10:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526617; cv=pass;
        d=google.com; s=arc-20160816;
        b=fAPPXPAbPnpStIlG26boT1foainJYHYA2t1TC/aGRgSS5IIfL2hzR8ob7evUrgfhyq
         bpNGNTxePy5kV/M+tPe2i+ACF6548OztzaY1OqxfgLSqUQNztibY41pIqNx18zVHJjCn
         tp94Y4r6YFuPsMaGFrMRZvBI2vUahvndtuv4YVl0ZuluDiH5heFCTp5jY+PLYVdgXO7a
         zRm/gmHrGHeaid3LupNcxb3pEoRZKR4vFOgHoJm4syDUf35sCp3lnOlpvnYxi3oV2B/5
         TX2I48h8LTE03EQpGUOiYfMCvLtNHgZM8s4ooin6QjVgyzBJx/SKVeSwodduC2wN7GjW
         mwCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=04nq+UqeAcBjvZPLb3xd90M50OWbQ2lDdh6uWoW2ClM=;
        b=ZL+vEmgT2EAgp82qHOgP+p7x6VsIyCumW87ZRksZ2F/S2pV2qrhihQf39FBXRbsS+W
         p1RquShkMaEE+7b0NZmqd3ROmmt9CNIsPUoxrwIEFSXrEu13nvQ1/pqTNsaUjvqKLktf
         4rg+d+TCcpIa5yT6uaVCKPYY1fuenXypJ9O3sG1vhlbspnf/9m/9y0gi8rBn03po/gvj
         vTMD8ZH/W1DRRRFlhOKpltfDdvffjq7aj0SLjwZ1G1vEc8sNrt35jd1nbGHA/AP05Bb0
         x5UZM2go+pRQvcHyto31sbkLCG7x6Z44s33fJMhsgQmOzTdV7Z3JMxiIqleScftZil1p
         jU8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q8VLjQ5x;
       spf=pass (google.com: domain of 3v-iiywykcv4che9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3V-IIYwYKCV4CHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=04nq+UqeAcBjvZPLb3xd90M50OWbQ2lDdh6uWoW2ClM=;
        b=o/9agoRqA5yI0Z2bQruMH8Mb37gPRzzyHEXyJReNcHaC3bdK7+D1jixOt54J4kf/WX
         IUj7UP9xk0AFT+UK8UNyCTEeciqzlG8VkmuJUJ2/lE+Icgl/4NChijzGo/RzJtXQDzzJ
         3TRX4IhMmb2KWOseceWUsV+TVKvudwHadlsBhqYMl0s9rgtd7TWR371SG2Dl4Ab4k0kd
         0sniWLPRLRmACfE8Nf9aDxRp8SQqlmeXDXPXt9ttssLNQ3Cs6tyE2z7Cd79m0I6GxfgA
         VpVIBY3EI7BZ9W+pBNoBCfsMaqgdLFEn56Z/4FGfeMbpyJDyLUeLTouVWG4zRzmmvfzr
         4qaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=04nq+UqeAcBjvZPLb3xd90M50OWbQ2lDdh6uWoW2ClM=;
        b=BaYwmKU4hxf4D/7zI+WA8SLBh5ankjsIUQ1+hFaWyiL+bZDhg/Z19nh4wh6WUuF7Pv
         rXSZMFbINcw4sRf1DNy5KNxu9QO/pDd7TYUWlje03bvPFA+fvWOtcEvL3iOSkjE1wyPy
         fh7RAJSTCzf8O/OU8DMvzOrvDfAB8NoaGHJ/iVyqFEnl4Xi8zuZzGgsC46jIgZMYXF81
         Ka/8t/Dz2mhODfk+hNIaEBkAs4p7htI/eC9Y00lP4p8sg/En0KfqlqVlJvNJ3BqwmI3h
         rIH106aCnJG7bnE4ZwktNINZ0lsh/8Mr6MY5ljrp6pyz3p0EjQcwMA5UXtjIpanrc5an
         BJ+A==
X-Gm-Message-State: ACgBeo34b/pAYTZDbiX6dPh1LxYfb5MQ9uSC7fn6Ezr12qCKbw3ErL9B
	rijxEoWx5Y9y9V77SKTplqM=
X-Google-Smtp-Source: AA6agR4DqYdi6sTtnm1U7mpsqte5xMWIWAfF5SOgwu+d2IFaU1WACARRRivZR9ixZMXh2WAm/RNu2A==
X-Received: by 2002:a05:6512:3f91:b0:492:f17d:33d9 with SMTP id x17-20020a0565123f9100b00492f17d33d9mr3001797lfa.73.1661526617216;
        Fri, 26 Aug 2022 08:10:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:995:b0:261:b5e5:82b6 with SMTP id
 b21-20020a05651c099500b00261b5e582b6ls712727ljq.9.-pod-prod-gmail; Fri, 26
 Aug 2022 08:10:16 -0700 (PDT)
X-Received: by 2002:a05:651c:17a0:b0:261:ac0d:6c45 with SMTP id bn32-20020a05651c17a000b00261ac0d6c45mr2441218ljb.225.1661526616233;
        Fri, 26 Aug 2022 08:10:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526616; cv=none;
        d=google.com; s=arc-20160816;
        b=TLU5rSt1B22jPZ42ro30rg7UZa4dUUzO4vW0sojHStkLEAd4fBQi/lhnTrPGuKfJJz
         I41uQ2QEqISr5oCDXPMbOP8fssELblX0NUIOAo+hMCGUP1BOEYZhKS965xIicIHd1IRH
         vPzMFqBaCR6hbYIyqQEQJ2nwDkwTATzKF96ZwGC/8S92K+5I+blfTm5/kD5nc9143G+K
         osQQshePMQo6m7twsvRN6bsIsyHyEITyEdr8tunFvBC2fxGxMnp3BmQYJ7LlT36oX763
         F/1KVCnlbQGJY00z9mw57ORP6DzwPG54W/l+A3OEfIQEvtoMjWg4ft1oDFiVDzJK3Pae
         j1Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fxlXGK8qL+YVfFcW6ClvjL4YS8Ri9qaHIYNR2qoUuzA=;
        b=y4DIFF28JLGoQhInukoHrH0h+BhwD1G3KQu20mo+b1skE8xYn4sHARjUMrapPuep2Z
         Va3YGuDxrWGJq0vN7JYKS80SyWmdcMqGKFv1ioxFZ9bZMIFQxVVy6arKR5KmiuRYYJFR
         C2X9Rx4Q1H+EPFzDHDaV4bkExJ5jUDNI3q4W6Yoq6CfQ4zZYNM0MR6R8F3LbW7x9kKP4
         Gb1KaOrowekaW1UgZKmc7f7AOa7X+Rk+FK3H7aon+O+MAEwrpvrIEf8hbJf7RJSBMNkp
         6F98KV11SbpaLhecgRWnOPoZFa56A8SDsKAG0k144PIByngx2Komb6/XQ9xquQfI1nhJ
         qJSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q8VLjQ5x;
       spf=pass (google.com: domain of 3v-iiywykcv4che9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3V-IIYwYKCV4CHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id i22-20020a2ea376000000b0026187cf0f12si75089ljn.8.2022.08.26.08.10.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:10:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3v-iiywykcv4che9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id k21-20020a2e2415000000b00261e34257b2so674001ljk.0
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:10:16 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a19:e012:0:b0:492:bec1:7f9d with SMTP id
 x18-20020a19e012000000b00492bec17f9dmr2498937lfg.585.1661526615782; Fri, 26
 Aug 2022 08:10:15 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:07 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-45-glider@google.com>
Subject: [PATCH v5 44/44] x86: kmsan: enable KMSAN builds for x86
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
 header.i=@google.com header.s=20210112 header.b=Q8VLjQ5x;       spf=pass
 (google.com: domain of 3v-iiywykcv4che9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3V-IIYwYKCV4CHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-45-glider%40google.com.
