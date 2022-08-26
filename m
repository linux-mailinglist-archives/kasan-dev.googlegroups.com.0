Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4WDUOMAMGQERTI2ERA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C5C865A2A60
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:34 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id y15-20020a2e7d0f000000b0025ec5be5c22sf659338ljc.16
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526514; cv=pass;
        d=google.com; s=arc-20160816;
        b=07Z9kMUz2uW8Wxwsyc8w+HeOYKQzZ/xAJh+mSuc+R8+j/fwRq5iH7/Dz8rzatZ9aXl
         caSq7+iSrdblue+lA/vA8pUq4lw8ZpGXTDl145NG7y1r07wFTWFSydHf/60VC7Ks/6Fr
         4ByaVxiyV7hNMJG82H8vOwnhXlczDU3lZomV/n3/oTB4s61z+jLbDQ8KbmQROlZ7Goe4
         t0JXb0UgbfJHHIekyi/CYt05TflZMoK+5gXaA+2a5qU+36+LnwGkFgUzxrQc2zVvAim9
         0Nj45pn9t5kfHhwXlIRxKV7hs2LSiyOHiILATSQPywe2IrdzCgkmXt57jKXfyOADZGM/
         bhxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=mvKL7x7nRtvtz/7bSRhnyVCoXUhhtD7Onmw8GaUDse4=;
        b=xARzveBtAmd67b/0DAjUl8qRJD3kQQq9Ge3bw1fK4NcHo3ks3kb/2p+MB4k2ZY6IED
         4eC7dixPHd1bN+z3yhEHa78rOzuRZbLbVjy4hw0Kw23U7Vp8sTc0uJBQrO1oqGvnYrNR
         lwShvEMAkjMBj2Abq9G2wUia7Al51JDXJGKt/7lUlhn/oVDiiCkpBeB2wFrtx9a9H6rV
         I8STAgRXH7QoFFacK0vEjsIDIdCyh4wxybK3QKGayvnvSHFe2JicptwlopOwd250iSEU
         D0ANZ+Jzoyx2/QA6ooOzRAB678CNnuBd72AYHclIjqwUZqthwXkeO+2elUtRKvQBOuS+
         /8Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=c+6A8OMg;
       spf=pass (google.com: domain of 38oeiywykcfudifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=38OEIYwYKCfUdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=mvKL7x7nRtvtz/7bSRhnyVCoXUhhtD7Onmw8GaUDse4=;
        b=C7VU5zcqrqqwiabfYoD4ugG4YBe0kN6/lGQBI9QpBbODSnXx9K89OFEeDRCXO9bZcB
         HnOhE+iPCIC4kR/sZIGekyNzYsqdGoi4bcKTLMXrKLn69sYqhCAcjgmgWfajEiv1EZVZ
         0uFDaTlrs8cPBQq70pCl8xJ38FR/mE3j3CAkvjAiH7fXlhIVrmunxr7OoJFq3C3qlcWu
         oI63v+KM4T+XYj/ZI3Q80nP0EGOn6Vd5/vjfNDyO+tjMmenfu4J/5v7IJn8HQBq/iZgO
         CqWhNK+lKPLTCYt4oN4KVJ0QfwkNfprS/wxH4VPesJgp/OUscNqIffEITg93Szn5lpb0
         sY4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=mvKL7x7nRtvtz/7bSRhnyVCoXUhhtD7Onmw8GaUDse4=;
        b=LsvLBOo4DawQkPkG+2ZHnETAlmHXaz6ecuv5s2AZKv/IEe+gjlNBcHimU3DW2Dmq34
         IHDElhm6kuGx+ESwkHToBhnG83xlW0Z1VxOMkBI2rOsXC0kg5XLBAUSpb9VnnzAVUDx3
         zEHH4kHVOrZB7RfoaJgk7WUxEEwhHK401yI5Q1ctJYoo0LMk+qtbCPnbM74JVGdEnnDX
         ikn4nq2iaTzWP8eIKKaGVmIPMi1bzAa0s2x4bn/utg/wFBxWE6YXjlHB1c2qKFuO6+O8
         dhzhk7iZzP1v1sxBooat82IBKhTICkukKu9p5CIpU7Ka7jrxY4r5/pdMoIH/bHGyaac1
         yFQg==
X-Gm-Message-State: ACgBeo25ToeWWYa3TP5v1JhrIZ3FzvwCXIwwotJEx8BfSp1cGm/OHzGs
	JNsl4cHmLm8cop6vAmCX3Oo=
X-Google-Smtp-Source: AA6agR4OXx6s+zdQZaeVJRWLuOU+r3uqjrAWenXaUp501BK22Gi0SYizAsyNYEYfbUqQVTOlS5fijA==
X-Received: by 2002:a05:6512:3f4:b0:492:f088:45d0 with SMTP id n20-20020a05651203f400b00492f08845d0mr2493625lfq.283.1661526514262;
        Fri, 26 Aug 2022 08:08:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls1143651lfo.1.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:08:33 -0700 (PDT)
X-Received: by 2002:a05:6512:3b21:b0:492:aef6:b5a7 with SMTP id f33-20020a0565123b2100b00492aef6b5a7mr2846590lfv.270.1661526512974;
        Fri, 26 Aug 2022 08:08:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526512; cv=none;
        d=google.com; s=arc-20160816;
        b=bbISkVhCTMtFvbW6cU/goZZ3HI3dpiMUW/ddeCEASJ5MQE9gnGPm0kKaOVyBBM/EJU
         PUyHn5aaKHUi5kwtFdrlWvN3KKvBcbWU7JSV4AmK8DRz3jpEgYpoUGrGsYLehD9V/Aom
         aMOlw6TNSP6+5KopqFm1Wqc/hloAvAk4nAo54excXJosSNz1IlpPbM6lc9Qzff9Cgj5W
         o8P2Sedizl1dcvwFuIEaNu4QoqggrGoW69RaeVe+yUI6/IW3aECxSXsn8wJt117Vf8lO
         3byZCCZqGSsMOEvLuVyBnIM6Ffc1FzfN4PGyx/LSn6hiWCID2ibVizByxvmE6y77r1g0
         S25Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=c5NepUxkZ67sJe7jHUeDkh2lejA2rZ0n/lgzGJfAW+w=;
        b=PHQKQxPY+2YAeZi7ogd2Sg7yj1I3Jy2Qr0qM22xQ9kKc7LIBu1YwsA9KHgn5dEF1Uq
         iTCrA5czIgDm5mMdJiSwIaFIX2judSHVwJwvjU8EKAex6BSICbWfUncCChLHeymY1Dbb
         SRLYETpK/URYC3SWBBkN+zr5BrGKKhqshRPphki9qIwWagXKdotGjlqaONhi9V9QwXT2
         DOgWkYHg4rDpHRzxkiBB1xW9yTW+SLAuPqpPfOFzWks3HfKVrHCVQHlJoOj0ImT0w7xP
         u60GHTmfk4SO6/N93K1e5gvVCTaFSh0kwaugExOyUq9alQ31mlKKSuqocgiJBl6vjjbJ
         bEUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=c+6A8OMg;
       spf=pass (google.com: domain of 38oeiywykcfudifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=38OEIYwYKCfUdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n23-20020a05651203f700b0048b2a291222si62514lfq.6.2022.08.26.08.08.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38oeiywykcfudifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y11-20020a056402270b00b00446a7e4f1bcso1253968edd.1
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:32 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:515:b0:447:780c:39d6 with SMTP id
 m21-20020a056402051500b00447780c39d6mr7244136edv.265.1661526512626; Fri, 26
 Aug 2022 08:08:32 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:30 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-8-glider@google.com>
Subject: [PATCH v5 07/44] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
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
 header.i=@google.com header.s=20210112 header.b=c+6A8OMg;       spf=pass
 (google.com: domain of 38oeiywykcfudifabodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=38OEIYwYKCfUdifabodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--glider.bounces.google.com;
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-8-glider%40google.com.
