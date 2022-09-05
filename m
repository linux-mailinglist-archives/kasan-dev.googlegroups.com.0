Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA6W26MAMGQETYDOV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 373925AD273
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:44 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id s6-20020a197706000000b00494771d1bf9sf1836131lfc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380803; cv=pass;
        d=google.com; s=arc-20160816;
        b=olkzxgi4QZ9DoNrqTDQJKMbYEhdWSMC6K9TcPNjKgVee8J9FMCYw0Io0xRQPqHPnRg
         7ST5dYuuN3c1RciHgkW5TXuN+5r55K6HfgjB6kRsKjY0P+7o58rkqmNJ902d4rGeOhkr
         /TwcZ2xc857YNiszgUR1VA2p2DChdFDDqzxJB9RIs0r61Y2VscCOhapz8B+yIgJh2ma4
         Ykf0VWgfLM0jiJ40bdh4j8L6kC1ciMO/yH7vHPp86K/LYf0Aa3gCm4NYGGkcEobXmh1K
         W4jxDQpybBhlkB2cwn2fFMOp8DLcxJ1ZDP6bhnGerPx4p19+KkL/GUCQeFqKshqgDTp1
         SfTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Gd1O3PxczO1pkSqcA4Zb+1lbY+4svHFT5B2EDH9djNU=;
        b=nvSAPzdt9+e98EjDNoLU/3/Ha+XK9soKwWIYtj8dgPmqJeA1HKCa4wAothiKWxsJxo
         Sdo+pHJyLNYQM3B51RpaVOsPBYKlXwAtCZfSa5WaKFb+xUisiQKU32CE9umVlE8BCAn8
         Ep4EZ4JxfzN7Xv+GAiu+dJBrPYlJTPqbsfTESxcusrFfCMRqH41rpRAYRHQbAgqutgyG
         7QntarkpU0K22dsiz+EFjgut5tfruwimQwXw6h1rmYqlC/jvpnpCvhDiWBwMBu6fEvI6
         Y3WYWnyv35WdNQYsV+U83HK4B+Z/PzwpZ5WWknDx9HyCYP236uwzx4n22WbWj17ggIde
         c0wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IiXcuANz;
       spf=pass (google.com: domain of 3ausvywykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3AusVYwYKCU8x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=Gd1O3PxczO1pkSqcA4Zb+1lbY+4svHFT5B2EDH9djNU=;
        b=InZHiHS65ktVigHnAx/9bktfrze8OS4aV3/PYZH75YhRBhYitcbyMIPndnOfTrjf6i
         1RrJYzLKYe3MNRmOAI/pDOI5x2Ff5pM2APkAPxT16q2eILra2MU6GEzcjnba6OS/rFzH
         2Kd/b8gasP78Z4uSs4EBhNCkQqSd0yD8cvbK+GVNz83lpI3EJQFGEoPixTlPHZ6z0FAi
         K4nc9sA7ytbhzAql0GYBEBv1GtkGKk8Rrhfa6adK2yUM8c28S4kdvpFg4WmLrl0mLI8R
         LdUQgyoLE+j6O1RFgqgMU/+q0OOW8H5BKWVqOXQ2+lpFCZ9TyHqI0z1ZkGY3VTwazFQO
         tLOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Gd1O3PxczO1pkSqcA4Zb+1lbY+4svHFT5B2EDH9djNU=;
        b=OZyeYUTPdMngwtczGybKLTe4boo/mzF3jmDvQFpvlQc/jz619KDCAV1oahRvb6wrjh
         e1vQoDzCUFtZ9B6iiFdSfEOd/ZddAj9M4UWYaJnLAyLXIi66WFBByOaY5rxPZDozB/bX
         zb6NivoyBntG7A/un/gZ7HbTGv2Xt6/86ZiW9MDBsDCZzzzglujthrDJVSbu5r+fRAUl
         d4eilJadjxQJ6fs/63sPf4khkYwYdq70QxAGPk9vhm2KUhREdp1jT7D2CXLR3Q5fidkX
         ZSrUh0JtIgJFw0HafYCLu8XQ9GNARnPNydGCClgHS/27jioACs5g5dExOVrJeiS6FjSy
         cEGQ==
X-Gm-Message-State: ACgBeo3EITopA4QpzMsFYCE3ycHNk4QB2kL1N6B6/mQbCYB/LUT0I8sU
	2RxOvab3VUi96mudDaWdB3o=
X-Google-Smtp-Source: AA6agR7u2pDgrG9qLtoRsO4SqOHlhg5v1f1LBmBUIU2XqSlvs0JT7bQbEG0xxBqOTwFDiRZY7GOT1g==
X-Received: by 2002:a05:651c:305:b0:26a:915f:45e8 with SMTP id a5-20020a05651c030500b0026a915f45e8mr158873ljp.6.1662380803695;
        Mon, 05 Sep 2022 05:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1055:b0:25e:58e5:b6d5 with SMTP id
 x21-20020a05651c105500b0025e58e5b6d5ls1564016ljm.1.-pod-prod-gmail; Mon, 05
 Sep 2022 05:26:42 -0700 (PDT)
X-Received: by 2002:a2e:9b98:0:b0:26a:7364:b521 with SMTP id z24-20020a2e9b98000000b0026a7364b521mr811254lji.418.1662380802638;
        Mon, 05 Sep 2022 05:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380802; cv=none;
        d=google.com; s=arc-20160816;
        b=L/Oofr4bXN0tmMaBL0JkupHqJPJU0odPeoNx+OxqPO5c+7M2J9AvWF3LrCYflwLx+B
         EUM8WcUyQnPMBUeGvRef09lA9Nctj2El1Hn2FrZWKXrdOHKwHTPwnM79OKd37rljYiDv
         ooVGrjItA4oh3F8ExpJ37yhSUaYtby9ScEYtm63NDzRb5s/2PLK1YYUk9V/kKPPOa4oI
         tl2H7FYOPM761o7MwyOCxOA3D36UXAazDWwuD99BZlLXMDzstx2YzgtjNzgDZ8tYZQlg
         eJlbipkclEVI4JBkmCqvmyQxnNyfAAVdQKUE+8HTCs8+qBjM70iYoHjC5ks6PROpp8x0
         suKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=UAXLi6hWes4K0I7wTwgH8ix0vMuStYu2bu/++oTzO6o=;
        b=LoQJg1c4gXAozrLU0fAaMsrPlZWExHfk3gmAnoyHyQaEDYooFPdZpT0NfWlvr88/8q
         nijbtNTiiiwAbGN1tSwmHiH5pO5ZOKI8yZBoczLNqym0zHfKQwPN2Hb/rNjWo5fEGxe/
         p+ASvkjV1byzEic3zRHsdP3+mc4lA+mWdFk7bf+T/rX9ck4Axj/IvS2rXooI9XpS/RsQ
         ytKsWRrLLT5UaXesbvkeMNg0pTHDzQVPd2TB7hEai/ClDrLMhHBv3TIfttsJHwkvyg7H
         jRAbUKG5Hpn1xZa3D+yY86RqAFHFqq7JyuMNRlZW8W57ARlskNR0Pfh/g/MebfRq51Lu
         OF5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IiXcuANz;
       spf=pass (google.com: domain of 3ausvywykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3AusVYwYKCU8x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id u9-20020a05651220c900b0048b224551b6si401439lfr.12.2022.09.05.05.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ausvywykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id z6-20020a05640240c600b0043e1d52fd98so5818780edb.22
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:42 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:7d8f:b0:732:9d6c:4373 with SMTP id
 oz15-20020a1709077d8f00b007329d6c4373mr33515704ejc.493.1662380802045; Mon, 05
 Sep 2022 05:26:42 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:46 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-39-glider@google.com>
Subject: [PATCH v6 38/44] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on
 x86, enable it for KASAN/KMSAN
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
 header.i=@google.com header.s=20210112 header.b=IiXcuANz;       spf=pass
 (google.com: domain of 3ausvywykcu8x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3AusVYwYKCU8x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
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

This is needed to allow memory tools like KASAN and KMSAN see the
memory accesses from the checksum code. Without CONFIG_GENERIC_CSUM the
tools can't see memory accesses originating from handwritten assembly
code.
For KASAN it's a question of detecting more bugs, for KMSAN using the C
implementation also helps avoid false positives originating from
seemingly uninitialized checksum values.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/I3e95247be55b1112af59dbba07e8cbf34e50a581
---
 arch/x86/Kconfig                |  4 ++++
 arch/x86/include/asm/checksum.h | 16 ++++++++++------
 arch/x86/lib/Makefile           |  2 ++
 3 files changed, 16 insertions(+), 6 deletions(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index f9920f1341c8d..33f4d4baba079 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -324,6 +324,10 @@ config GENERIC_ISA_DMA
 	def_bool y
 	depends on ISA_DMA_API
 
+config GENERIC_CSUM
+	bool
+	default y if KMSAN || KASAN
+
 config GENERIC_BUG
 	def_bool y
 	depends on BUG
diff --git a/arch/x86/include/asm/checksum.h b/arch/x86/include/asm/checksum.h
index bca625a60186c..6df6ece8a28ec 100644
--- a/arch/x86/include/asm/checksum.h
+++ b/arch/x86/include/asm/checksum.h
@@ -1,9 +1,13 @@
 /* SPDX-License-Identifier: GPL-2.0 */
-#define  _HAVE_ARCH_COPY_AND_CSUM_FROM_USER 1
-#define HAVE_CSUM_COPY_USER
-#define _HAVE_ARCH_CSUM_AND_COPY
-#ifdef CONFIG_X86_32
-# include <asm/checksum_32.h>
+#ifdef CONFIG_GENERIC_CSUM
+# include <asm-generic/checksum.h>
 #else
-# include <asm/checksum_64.h>
+# define  _HAVE_ARCH_COPY_AND_CSUM_FROM_USER 1
+# define HAVE_CSUM_COPY_USER
+# define _HAVE_ARCH_CSUM_AND_COPY
+# ifdef CONFIG_X86_32
+#  include <asm/checksum_32.h>
+# else
+#  include <asm/checksum_64.h>
+# endif
 #endif
diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
index f76747862bd2e..7ba5f61d72735 100644
--- a/arch/x86/lib/Makefile
+++ b/arch/x86/lib/Makefile
@@ -65,7 +65,9 @@ ifneq ($(CONFIG_X86_CMPXCHG64),y)
 endif
 else
         obj-y += iomap_copy_64.o
+ifneq ($(CONFIG_GENERIC_CSUM),y)
         lib-y += csum-partial_64.o csum-copy_64.o csum-wrappers_64.o
+endif
         lib-y += clear_page_64.o copy_page_64.o
         lib-y += memmove_64.o memset_64.o
         lib-y += copy_user_64.o
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-39-glider%40google.com.
