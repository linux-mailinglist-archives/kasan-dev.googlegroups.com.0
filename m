Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFGW26MAMGQEJ3FHVXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id CD0C15AD28F
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:27:01 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id c18-20020a2ebf12000000b0025e5168c246sf2804059ljr.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:27:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380821; cv=pass;
        d=google.com; s=arc-20160816;
        b=PJvFKvsmlbreiyWas8twrIQkbsK1X4rFVIu9UCfGlvNRrzqTclga17EKmxYyZKm7D/
         WeqkhWZOfKtNGw84Mt8v00rekKhZvMndxFi5iI3wkZAlVxedfBuaEFwVPq7NHpLYJi7T
         BmJqlhIdJ3zfUhfvjH6qsdOsKrUg3KtzFm9av/+Xs3YjH/F/jxURgImaoVmnANBGrRzp
         rEgk+MfLJTZJ+jPCiFg8ju3G2VVQ1Fm3k1mh1VEPCI4DHYI+VBkZITQgikIuRLxcRNQQ
         RTKw3FGzrp9Z+DbijxM0UYM4VCYr6ZqN53C18LLdUgnU8PhiVxPWn0B+ChQ6AKK/pW2t
         HrYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=q6VFLoLACrpjHYQSnYNnu38e8PpAsyrk2UDSbekU2IM=;
        b=cHiaaSLpFTN+mLBsF7UJZYHeth336ZuxqPnCmJN0eYDxfSICXRw3LwlG4nWvPmHp6w
         IiB9O0rIm4b1Iv17zZDensLDLqJYtvheUovQjAqZaLHIeKq2bTXFDs/yTHVr2+ZMlFLz
         RnYLK5a+1gbWcr2NsNX9k19YWsHAuuf/Ih9YFzgQGyy4XL3gT2sAvh9MdIpAG0Lep5tx
         goen9xbV9DV1g14WH7V0rsCKDOQrB8kCVVhTz3tMsg2DCB6YGY5mTR94yyjJeHFlIMQm
         Ehcqa0G4TlL2OUsQMzC8uPco3bZwAVywpRaq7v2/bpKchDJZtLFLz2FyM1wPDWKEaJbf
         3OwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MCXD5lbA;
       spf=pass (google.com: domain of 3e-svywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3E-sVYwYKCWAEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=q6VFLoLACrpjHYQSnYNnu38e8PpAsyrk2UDSbekU2IM=;
        b=Jk5r22Pmt0X2MQuZqGW6fCiIhill/loPDw+ymlkssnPpyDdd+1VL2eOvhFbZkok6k6
         N6qSdAD3Yvm4W2dYkOnfm2/e6C3wKCfRveKti49jH+S1cGWdsFLa3iez4VPJ3/xbbdSN
         AbO6tQYrPsV1UcdlW6+StRlDfuIOADO9BrAkm/dNCA8kJOiNtMeHAXdFoxZXkGZVychW
         dNE7btq2FNm2ho/X9DbyMvbvyH+vye/s6Fc0NL5o+4TDA4KrYg+SKUvjedWiKF4STGFa
         6dW2vow2DH59/c0szppYEoHR7AAr2OlVmjdrN9nDIjeMV0ijZqesLd7kzXkckKsSmqDG
         x4TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=q6VFLoLACrpjHYQSnYNnu38e8PpAsyrk2UDSbekU2IM=;
        b=OPPegPeivEZsYOcGRGZSUNfG034qFPaTd8BxTDhYWcKcGlphXWwcsGPrSvB/L3rcYj
         HbCy5SGUxI2u7K83XI3tTpSWxOxeuZXdPssrYkRzvk+W7RU1YNieP6vbp+YizS8WqbIH
         c5w6h2gkBv4F1V/kd0FnDJxikW+iU9fQlpIe2ZFZqhyidFbuMFvoIqaDIO6c2Uhj/EWh
         4wNSxrp8wAhy7dGF+shfAz47ESrahAebg1cse5+/DHGicbpzG9CATuwhoxs7yosfAwe3
         f/PydSVMDndVykONAHjBFZUs3a7oTY+zTxGbIxIDVYPzz9Il6x3hV60+qo5F+HohjJKn
         1eew==
X-Gm-Message-State: ACgBeo0LebWa60asEP0tgzASubr0vEr9ONVU9NCR5su/gkEpQ5PNG0qP
	cN9Azmelts6/tMo/CesnDAI=
X-Google-Smtp-Source: AA6agR7FV8IxqQoI0WREFXBu8deCzNqsRphWrtnuvQByLGC55Y5/aPuOhSewXLBzQTVlPo4WqQeTzA==
X-Received: by 2002:a05:6512:104f:b0:494:736a:8332 with SMTP id c15-20020a056512104f00b00494736a8332mr9881310lfb.683.1662380821127;
        Mon, 05 Sep 2022 05:27:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls4743434lfr.2.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:59 -0700 (PDT)
X-Received: by 2002:a05:6512:1289:b0:492:ca81:9a8 with SMTP id u9-20020a056512128900b00492ca8109a8mr18212883lfs.457.1662380819652;
        Mon, 05 Sep 2022 05:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380819; cv=none;
        d=google.com; s=arc-20160816;
        b=xOqqqe0YbNPklcVoA0KAfTU7HwTG8QVV8rgPV3Df21HNkdlzUHsZ3xROUrgYSXa4W1
         6MX7AWPua6fsO9ob4+BzUzjTsWSLZRIWjwf1uVcIM+u2OAcse8Q1bUhqnBxfuYdkZo/O
         J+2FH+XZ/8gPAiD0BFAUgyqYwmDoaPqvhK/41ReZAjdeD9a2+GgCyN5Abq42LhTkvEoy
         sHV3uyn1wy6f99jn4ihe2MTATTIaoZFrCFxhj5uY4tZExGDq8092H8DR5JV5KwPGhbkr
         DgfziFin5zQH/ltWtct3h1f7LuVTxssZSsGVjidhsLG+f8GqR+2Xd4F0lMYQkp34Zcgq
         ydnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=qWMR0SPZO0jqHHxoNfMsk5w/9uuaYeqiCUk8OeqbWGY=;
        b=klMM7Qyu8qYK7WXOkU+4PbwMHyz2vZaWnxgXDDQlL8+kQ+fDBxfBrP6rgv4YoKGrlh
         pVQKAtd2OfpA+KzmehXzRk+EUYWNt5I79pMRr7ojFxqIsfP0u00YEbtDabvTTCxyJGqw
         lDr57tcbWBP9wZsybN/GifYDyoHh95rG3NRRQvH9NMeyOIm75AXXFfUFRgGjNa5wqD0E
         +g1n+WcvwDeLoAJDpgrA/EWKUeaPfH9bxjGGEXG9V5+85LcLN6BTR6D48xnG7+yMMI6m
         6RsiLEnX2EGsJ+Aiz0YKHCkJD8E0XraAmB8GFTJumShqgb5ovFMx+eDb84OgJh8p9gYx
         Wi0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MCXD5lbA;
       spf=pass (google.com: domain of 3e-svywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3E-sVYwYKCWAEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 4-20020ac25f44000000b0049465aa3228si278555lfz.11.2022.09.05.05.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e-svywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id l19-20020a056402255300b0043df64f9a0fso5759341edb.16
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:59 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:2c74:b0:741:657a:89de with SMTP id
 ib20-20020a1709072c7400b00741657a89demr26824523ejc.58.1662380819269; Mon, 05
 Sep 2022 05:26:59 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:52 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-45-glider@google.com>
Subject: [PATCH v6 44/44] x86: kmsan: enable KMSAN builds for x86
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
 header.i=@google.com header.s=20210112 header.b=MCXD5lbA;       spf=pass
 (google.com: domain of 3e-svywykcwaejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3E-sVYwYKCWAEJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-45-glider%40google.com.
