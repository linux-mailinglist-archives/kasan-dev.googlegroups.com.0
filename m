Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHH6RSMQMGQECA7KJJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B7D5C5B9E01
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:00 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id y22-20020a199156000000b00498f587546csf5619965lfj.14
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254300; cv=pass;
        d=google.com; s=arc-20160816;
        b=0J2QB0hGEswgOukrE33TwMoRAoGv5lXAYE0l3ptyZAJJprG/d32bOzi+3sZLD+zkda
         uxnLInruJpKZH5YQZvW2wpP/K0O2DaZ4AybfSIFDMRmJ8AySdYOJa1OWv5CduPLIh/Ku
         ei/EHHaUt4SOq+GQFQk/6mXeMMr+Fua/XdiqeJkivP7O4ipG/AUclLOOhY58Fr2l7Lq7
         FukAJ2bUAM8SFIu9Q6K09ugE4K3TYdlGbUeNOoNMI8SBxaKvrWw25cu6uBc2yeRLaYFz
         tqEF/bSurRTKHJZAwaJk04tw1QwjNLsVhpju4faP55MOuuCFVPr+sO/L2VAOw3q+LL3X
         wbkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=w0ysOeVC7rrz77WmKMvnF5DgcA9+Dl+eq0Uh0FqPdlo=;
        b=wjhoRR+FVzDP0fMikxmGuHU99SDUUHiFuV2e5ynzpb5Af2/6XQUWsJFNG9aBNBd/nv
         K44IHvEwj6TXN94nNJ54lACFTHwZHgnpJZpdGWTSmrV+vG1mwsIVzMUGQTqo7PlmfPxs
         CJkQbg0Nm9gYXM8VsVTYzOBPOTbiapN2q9/HKvHhaYa5Kg6i4sg5T8dwpHrZR4T3gKxY
         TCrh16ilL4dOHuHDb+U30o7QFarXQsIGu1CfkFTLxSrUKaUN0dsC1i857A6TccVDcSeU
         UOPd5nu0Qreyl+he9zvQ24q2OpRwmHg0PdG2O4aIFwuNlvI/xRyuTt4Us0fy5kaMbfPs
         YRWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bQZcA86h;
       spf=pass (google.com: domain of 3gt8jywykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3GT8jYwYKCUQmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=w0ysOeVC7rrz77WmKMvnF5DgcA9+Dl+eq0Uh0FqPdlo=;
        b=lfdbM9mkP03HaU72MrfENhDhMSoz0xdrMmMFDR9hMqoi7fATjY506uGGgMnnmumHe/
         yGyPM9Xn4g3KbrxYNbvhJZSChNebH+bYQL96JKLiLDMEAVICdOIW9C5NV5n1OyDHK+rI
         S2pE9KvfWmliqKYgC/U0XNuoproIgTg55xSHQ7hiCkVU2/qtsEhcGDiiLFP8UmEXEQZF
         eglw8aHmJ1fEBEiJZ/TFkqw6rxb7ZHpNS0Ms075OSq+lOBVpdoqUiUk9zYZvK7ACiqr6
         MezWR6NmPEo6rminLWWH0T9cxLQscAVQgY2e4C6x3mDHh4EJNdFbX9fVtS2RfRlZjSiO
         pD+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=w0ysOeVC7rrz77WmKMvnF5DgcA9+Dl+eq0Uh0FqPdlo=;
        b=ZA3chvJnbfLyRG+VnRVPHC4KpUnKwjEPxu4lrOar02/Mn6FSbO6H2RYzbb1fAo8Nfs
         Ip8Tlq2T2afZ/yQE5fExtMqS3W4JQhYFy0F1MUsl/f+mYH6ZX0IWA1ajLfsabMgfsWcJ
         R/eDBbz2p/+OOVl2Qrzv4oCDT7WUielKmV3ykpXlumEmwnOhPryjIxu99cqDmrRHntXQ
         E0scYAWo/EuJ2cXHZ5JTazg7MtKndcguPyAjRS825z4rbRb+z0O6Ei1fcxt5DW2+y8vO
         eY9Iw5WrEcaEFfm+X20B6GnBdJw4OaBZ741iqh7yOF5Ldj0ED3qvTqAuJF9s0LEddiyx
         zXfQ==
X-Gm-Message-State: ACrzQf1PQ/RgiK6Cl6U7JBE5SFn10Usti0quVneCx0MGWs3n3HvPjMB0
	hC7y0YFKkfzA5VbQcd/VtNw=
X-Google-Smtp-Source: AMsMyM7SkRh8xjQMmWWIw69RrsWUZ1sN5GWys/Zif0tmtuAgkKfjVZyuyTzyGWEwOVCI0oGs4cpSAA==
X-Received: by 2002:a05:6512:3f01:b0:491:9b9f:a54a with SMTP id y1-20020a0565123f0100b004919b9fa54amr131566lfa.160.1663254300320;
        Thu, 15 Sep 2022 08:05:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:210e:b0:48b:2227:7787 with SMTP id
 q14-20020a056512210e00b0048b22277787ls1227669lfr.3.-pod-prod-gmail; Thu, 15
 Sep 2022 08:04:58 -0700 (PDT)
X-Received: by 2002:a05:6512:3da2:b0:499:d70a:e6bc with SMTP id k34-20020a0565123da200b00499d70ae6bcmr117787lfv.191.1663254298356;
        Thu, 15 Sep 2022 08:04:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254298; cv=none;
        d=google.com; s=arc-20160816;
        b=KtSALF1JbgKq6vbdHFtyiSRXGVfzoQSsEF/rAbPxLkfAf4/VNUKAx5E0XrFb4OTxyq
         8f2c5Fv4nN4GnV1IQwU7VNgaHW2czYfwQ+d91DRwRti3fzl5IP0eVtcgV7TX8HsIowSN
         Wx+3mYRUXc+40Oo5+EcTTn4CMqev9ypQ5xjDf+QIk1Hjr8jN373zB3LJRuxnajdPhoFD
         /fb06M6I6A82G45nh1aRsdpWw1HwAcJ8ICIBdW+pRRY6L6b2HqHwY9a/+oDHH839S+KH
         hbopgEZ/fjpIDkAm1kjtPuUKNvsgiHAUsP6Z/CHB0Kx/DkA+q9JChK2EvpMmizwhO0LM
         JxMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FNkIx/jm8VmVwIUxP0UOjGDN2D7zAcH5S0k2sC/Umx8=;
        b=NhuXH5mBiLDvVUs/LfvIJ3OeEMXhkZQO4+YFkALQgB1244VUSyRifjvQtPif6Aq3Jn
         ElETxBlL0klVLs94f+i2Y9tk2GpIiwCblM59FbMKr+KdTFry+2BnR+SjH8iDhuVquskI
         7zfL9U2xQkNTYfE6lSnFnvKIemgU7HoWZwYNyKBVvJ5n6G9T0sVoqMfWxxQq8mKXn4BO
         3o4OPDJ+4gc2YPwSEq0oEMGsmhyc4UsylxcapKolPbhIl0/nQ3zHKW4Ls333mzUy8KJT
         RY/+dejSeAh0lMfbyRN+lgdQTfMTAHzcwGeCXWu5w+mrpxmt/6Njy8+4CQx84kvPW0gj
         YV8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bQZcA86h;
       spf=pass (google.com: domain of 3gt8jywykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3GT8jYwYKCUQmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id v22-20020a05651203b600b00492ea683e72si545917lfp.2.2022.09.15.08.04.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:04:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gt8jywykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id e15-20020a056402190f00b0044f41e776a0so13137981edz.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:04:58 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a17:907:94c7:b0:780:7ccd:aca7 with SMTP id
 dn7-20020a17090794c700b007807ccdaca7mr323937ejc.136.1663254297632; Thu, 15
 Sep 2022 08:04:57 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:41 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-8-glider@google.com>
Subject: [PATCH v7 07/43] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
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
 header.i=@google.com header.s=20210112 header.b=bQZcA86h;       spf=pass
 (google.com: domain of 3gt8jywykcuqmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3GT8jYwYKCUQmrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
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

__no_sanitize_memory is a function attribute that instructs KMSAN to
skip a function during instrumentation. This is needed to e.g. implement
the noinstr functions.

__no_kmsan_checks is a function attribute that makes KMSAN
ignore the uninitialized values coming from the function's
inputs, and initialize the function's outputs.

Functions marked with this attribute can't be inlined into functions
not marked with it, and vice versa. This behavior is overridden by
__always_inline.

__SANITIZE_MEMORY__ is a macro that's defined iff the file is
instrumented with KMSAN. This is not the same as CONFIG_KMSAN, which is
defined for every file.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
Link: https://linux-review.googlesource.com/id/I004ff0360c918d3cd8b18767ddd1381c6d3281be
---
 include/linux/compiler-clang.h | 23 +++++++++++++++++++++++
 include/linux/compiler-gcc.h   |  6 ++++++
 2 files changed, 29 insertions(+)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index c84fec767445d..4fa0cc4cbd2c8 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -51,6 +51,29 @@
 #define __no_sanitize_undefined
 #endif
 
+#if __has_feature(memory_sanitizer)
+#define __SANITIZE_MEMORY__
+/*
+ * Unlike other sanitizers, KMSAN still inserts code into functions marked with
+ * no_sanitize("kernel-memory"). Using disable_sanitizer_instrumentation
+ * provides the behavior consistent with other __no_sanitize_ attributes,
+ * guaranteeing that __no_sanitize_memory functions remain uninstrumented.
+ */
+#define __no_sanitize_memory __disable_sanitizer_instrumentation
+
+/*
+ * The __no_kmsan_checks attribute ensures that a function does not produce
+ * false positive reports by:
+ *  - initializing all local variables and memory stores in this function;
+ *  - skipping all shadow checks;
+ *  - passing initialized arguments to this function's callees.
+ */
+#define __no_kmsan_checks __attribute__((no_sanitize("kernel-memory")))
+#else
+#define __no_sanitize_memory
+#define __no_kmsan_checks
+#endif
+
 /*
  * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
  * with no_sanitize("coverage"). Prior versions of Clang support coverage
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 9b157b71036f1..f55a37efdb974 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -114,6 +114,12 @@
 #define __SANITIZE_ADDRESS__
 #endif
 
+/*
+ * GCC does not support KMSAN.
+ */
+#define __no_sanitize_memory
+#define __no_kmsan_checks
+
 /*
  * Turn individual warnings and errors on and off locally, depending
  * on version.
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-8-glider%40google.com.
