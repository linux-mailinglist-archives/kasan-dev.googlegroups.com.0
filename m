Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSGEUOMAMGQEEQFDQZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 66A985A2A90
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:10:01 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id ay27-20020a05600c1e1b00b003a5bff0df8dsf3857477wmb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:10:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526601; cv=pass;
        d=google.com; s=arc-20160816;
        b=zPqN7eYkAt8TRxncaek2gw8Xcc+2J5ZUAo0mtnSxOeUtb7cFD8w9ned4Hln12yeR69
         2JbcQPV1nQS9Sq9V3pAxlpUVKA9F/jJbAXvQ/g45LbYI6DJHOVDkIginNHkaETWb7T02
         K3MU8mquRKZZbV5vZMfqkx7rZ50zG65tGTIX1xK9+TNp3OVpbnPi49FYkDWV/xhZVzvd
         L92mq3+VW/AJN1dsQyaCPdqd6Hwp+5rmc+t8TGDX+hNRvCj9P41AygZfy4Lbk2dqj+LA
         0R4vRzDj3hJ1ZElm8PELAt6wc4FdMLfTHWT2tjpwqfkVvalIF+hSahvt4WfomXsIVMvQ
         JIGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5rgMv2TnzwogsIgRGOZX6yW9zGUvYWk1RKwKZ6kqr+M=;
        b=0bUSkic2lwiKFJ5FIVXcTmHW2VgP0RqFzag4AnH5zBimgroou0o9WMN1u0E57nvK9q
         jx3MLhZgyNi7CCt4mytVmZUeAq10Rq+ShxHZKpMm34g58pDdnCZLUN1uv+Tw118OZbGA
         H/q/zRbjPONf9d+53niaTinRqpuTRz8SLrqs7JW7TntdHDWSPZYKdB6FvflXIxh6Qlg2
         Q6LX/yyzhXw4yj+X/ljqD3S1P6h4UmP68ZbGzDoaPRZsYr/9d9htbGNXVz2cuQjOp5JY
         ZZpllAs5SKexXqpnbSm0n2cWfnvCqbNYmybvCjfGajv3P4/ntTb50YExhis+BCZM+pE3
         WNZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rllUU8td;
       spf=pass (google.com: domain of 3r-iiywykcu4w1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3R-IIYwYKCU4w1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=5rgMv2TnzwogsIgRGOZX6yW9zGUvYWk1RKwKZ6kqr+M=;
        b=KkJ3Td4JUuFiU2NdDHUcLDOe7KPRSBx/TTyAxMQ+Yzowh2NewO9xRGscL06Fez7qp/
         el2lmCJjenhft5JbMcrxZvqmH0dDvNpF6U1+Leju+J3F8TaSK15FWH3cMNiuPZfFUUb2
         Nssth+sB1djIT1fy0/3y6rR7zJrr+ohsa9hselIEyrJlEYqX9HgmCvWNqZOCLgQwaNKS
         qous3U8JbRSf+iXmPbbDnO2mq5G5KDmUeUYTPg5v6A1YbhH7lkwxu7Jq7A4hBxyL3any
         A8Gp7VYEXD6K2e9SaLZkonc5ukZT+4c5FZD/bsZ4whdpGHsOPH0uCzhvzlqS5bKGiQzS
         fvOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=5rgMv2TnzwogsIgRGOZX6yW9zGUvYWk1RKwKZ6kqr+M=;
        b=ifgYnAX/7GYkossWNxpOwSLAZmVL2dFQjvzAuUFqsc68k25uw3NwjXQ10aT44gGlWI
         0qWtiq7w0uwbzrrtW4wpMrXUL5REOaOiU10bpmvaHB9HowyNwaAokCQ7iL9GU9YLp9r4
         xw5UqxONXvsDm/I728KRioBat6Z1AEWNJHoij7iXLqXiNuywSZG9InLegN+2bZujdPZD
         DSLby9FGcjtM6ioDfjg1ZN7qxk+3WTCpbeyUXdEvTA23XeSh1ci0Wa6387Gb0qzrBp+7
         nLX6k5RGMIJR0OKzZoJyS5cWoBc8q/n2bpCZEhG9CZj9P33q8hAmpO7hlOs5Gd7CcZE+
         4DrA==
X-Gm-Message-State: ACgBeo1cR85AVh2QqtVUHK+slb75tfIQhtalKqilDq7Sjkgd1fBqIw+9
	nVPaJyZIL5+wFMn5XTsSfGY=
X-Google-Smtp-Source: AA6agR5JgZdpjhYDy5xhoZPcjCa4mwTe4Dm6Zoyc+mfmbQYrByuERyKoAvlewfm3Js6dN8zBKogK+Q==
X-Received: by 2002:a5d:6f0b:0:b0:226:458c:269 with SMTP id ay11-20020a5d6f0b000000b00226458c0269mr57719wrb.223.1661526601183;
        Fri, 26 Aug 2022 08:10:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4b1a:0:b0:3a5:2d3d:d97a with SMTP id y26-20020a1c4b1a000000b003a52d3dd97als22584wma.3.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:10:00 -0700 (PDT)
X-Received: by 2002:a7b:ca58:0:b0:3a5:3c1c:6d71 with SMTP id m24-20020a7bca58000000b003a53c1c6d71mr33377wml.118.1661526600192;
        Fri, 26 Aug 2022 08:10:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526600; cv=none;
        d=google.com; s=arc-20160816;
        b=kCmY25OI/BP2G29BPlBMG5Ih0+mq8SOWWKoVBo1KD3PS6qxk+tLVEFHMpqtNJmQP76
         NSwXRXcj6cayvEgMFlOx1DBx3MVtremNasyioeYNJy3f09dxBfVHDGxRQFzXoUrpjjVW
         /q7IYNTBEgw6WsNGh8NX5i+rPt80XNuSyTHwZmTOhBOMDS3yhz5tWPymISJjZuoa2RHK
         QSJ25aJnP4oxr+zYpfmP6Boei0MPo8KnFopMf1z785nzOSIczMOW8Y+QIQEmtbP50UNJ
         OSUKVUei9eYV1LQwTZ2CB+jFQpP4NAXIjEGXwfo3T4yh7H2/tnfMvTFsi4QuVoFdJ2QR
         eOfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=G7zTeV7HivGGK7/AmFGwNvvgE+xYoTaOW1pCL0nph+s=;
        b=jj+Tiq/4q6O64dg/XEPBJVKyZ0qPyl4FkluVxVmw/JYpr3SJX3vF2oAfP8xRiMy1KL
         eSBx4AxwA6DUkyawPp4+VtMauop0nYPSELNvNwZMDBf362beCzgD3vsrgbfG4y1ixSa9
         3KRBbLP0Az3qJXvmt0H/0wqEO+17j/WWDlmxH0u35ZxAuwRsxhU/wH/hF02QJa03vZQM
         Sd0UZy1a+xx7yYtjSlCox6XVPxwV74kFMxWBLD1fZG7+WLcC9RTK2FHSL4V1u8d9MXcA
         YW49YFtSaSne5JUTxyStIj/CYpYaUVun9WRgUsq7AZ2it9p6BTx7l/rICKTqYVr6UIIs
         Lp3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rllUU8td;
       spf=pass (google.com: domain of 3r-iiywykcu4w1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3R-IIYwYKCU4w1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ck9-20020a5d5e89000000b002258b543359si1777wrb.1.2022.08.26.08.10.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:10:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r-iiywykcu4w1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id b13-20020a056402350d00b0043dfc84c533so1235564edd.5
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:10:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:b17:b0:72a:edb8:7529 with SMTP id
 h23-20020a1709070b1700b0072aedb87529mr5717591ejl.749.1661526599889; Fri, 26
 Aug 2022 08:09:59 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:01 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-39-glider@google.com>
Subject: [PATCH v5 38/44] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on
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
 header.i=@google.com header.s=20210112 header.b=rllUU8td;       spf=pass
 (google.com: domain of 3r-iiywykcu4w1ytu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3R-IIYwYKCU4w1ytu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-39-glider%40google.com.
