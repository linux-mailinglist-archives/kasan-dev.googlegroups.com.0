Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNGEUOMAMGQEDCWCQKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D4C85A2A89
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:42 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id k4-20020a4a3104000000b0044607fa7d05sf921467ooa.21
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526581; cv=pass;
        d=google.com; s=arc-20160816;
        b=GvQ1e/eY6Be9ynJhGly1mR8KKHMb3EunjxBKTXkZy8gT08BdT6Ck67eC0Omstmq+dy
         /GnJmpzZvGlYxx4laW14HVd8v0NCiyEBqPgDpnNrvW2myibGJuRhsA5RmCEn7YXS/TOO
         P29NlSMjnf+Emi7qsCA6/BbgS0s7ufzx5qXv/9d7pU4iTEa3ct2z+h3K4+abCB6Z38MK
         zs1xLRx0iK1PClHR5fk4koCuqshxNB9O4RZ6IRSoMRWfGZP+j/bHXcgJfY4f4a+/Q5Sl
         ZEEetgI/oj5QU0Sgsd/dvfWyoiPz81a0EzESpgBpeZIN6qC2LnxmU0QStTFZWk42X4Zb
         E4mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/eSgUDjYE7S0k+Yi7JrxiF7gnhz3bTMj70W0mu4i818=;
        b=a73bWCazdPmEUgPVYP0y9GsKfqacwtR6r3s3V8YfHIxcLr5ZdGeSbVRGoM6VTayi0J
         9meLGaGXuwSrJZjyen8Q+0qcmEvY2nTQ8daKm/TjJgNF76nq4oOiiuMTIl0r6omj8Y/Z
         xy4vY3elTaLrJszWwNPuDP26UStA3be+kMf0FXJdauru9CN9gieagkydoJPg2Bq16MO6
         UBGV3The3BEgaxdSs/wHPDTd1cOonGDg2UNwvdRzTu7VtwKlR3Z5c37RYIJDdGKM78ih
         wKB3TFPPsEK8IdIjVosKjGD91gfw1mWyqoAuKEI7LNhe0ctHj3SVgJ72YhORK4FMvUZM
         xjEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kOld3GJA;
       spf=pass (google.com: domain of 3m-iiywykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M-IIYwYKCTocheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=/eSgUDjYE7S0k+Yi7JrxiF7gnhz3bTMj70W0mu4i818=;
        b=ghD1tSltNZcXcZfsc4C6ZBqNTcrnTjmNNtrHfoaMIQ/zVc32z1SMSaeRL8D0ukX6U1
         2HtPME9GyJ24LellVQLtLbPJFc6n++uzOR4Q33bQqV2sPfvs+tfaM+Z/tcy+0M/bv3N9
         inRkk37Q66pokzQTv4pSvDQ8FqG+Cf0AQS0qGXpL6zxDHKZlQ2/v/jWfNUKiCvtTOhsq
         GGVAyWMgI2/jZrnwPvpWInERJeEiHcE0wBeN7VdbZildZao9hNDa8ah7mrZl6OCLrIm0
         wl9jhGoSlro8d4rjYD8L8bkjd1SamXeaOj7iYha5cfmsWGESbwvZTJpgGb6ynrdC1CqS
         EdLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=/eSgUDjYE7S0k+Yi7JrxiF7gnhz3bTMj70W0mu4i818=;
        b=m5m4T1wZm4caJJtv0tDHR+MaeSJNy2JCWVamWz3hLgglgJlZwl7RU0T+xr1yG5CghX
         VRQen2RIiPv71wbxreY1sB8EpebXAkoipi4ba4+zklhkmpD5GZRuJhTLH4WMxyQ1Hu/k
         Lo+TAweHlaAUwqgIufoVkDmwVLwRw9KdnnLv3yJEQ2SiThCwFOyiIegsB1pG21fLTTw4
         NhGPotailS2L8WYAufKMCPREULcdgiHY4kPJyAWwcYyFVtLGSVT+c0aAODseD6++e30v
         HGj+YRkWPbzxYfl2raSR8NjRdy0Jy7KedpSyfeS6eh5wc1tp4ZtiRaAfXqsCPpdBmkwK
         z+Ow==
X-Gm-Message-State: ACgBeo3ExA4mf076IB5xWUffqZ+ko2F0q/QJ1e9dpIann8nwUEcBmSvN
	00/5kUdX7X0Q87gdGCG+7jc=
X-Google-Smtp-Source: AA6agR4T7xIwKPDwIQw4GQrC/VTVOVhOSdBJWWVjUIkfF6K+nxqgKi2Mr2RtDI6b9lf33RhRYPbmVA==
X-Received: by 2002:a05:6808:3010:b0:343:f19:d58b with SMTP id ay16-20020a056808301000b003430f19d58bmr1773068oib.282.1661526581007;
        Fri, 26 Aug 2022 08:09:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3810:b0:11e:94fb:39c8 with SMTP id
 y16-20020a056870381000b0011e94fb39c8ls92626oal.1.-pod-prod-gmail; Fri, 26 Aug
 2022 08:09:40 -0700 (PDT)
X-Received: by 2002:a05:6870:890b:b0:11d:dc77:89b with SMTP id i11-20020a056870890b00b0011ddc77089bmr1975257oao.132.1661526580043;
        Fri, 26 Aug 2022 08:09:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526580; cv=none;
        d=google.com; s=arc-20160816;
        b=f0AMF4W5QIUnmTs66gw1Z3Ow1Ysod5ksAIXmBHxIoTJEGplJO8QbR7VZos5HzoocUu
         lm+8chx2yH8bCpidvjw78CXj44IzfPoI66A22h7KHYhU7A+E/ykgtndRMZF2BdpYgqoG
         KwWEJaUkuFWK/Bxcx1k7Ni0B23DHEZ/BhNolIe+IigX+EiEn9+87bIjflp0VM1yYFh+g
         dmRvfLzIHuEuHmXuytwEOTqSpwBJq3KPHBwIx6k6J+L2WQy5U+enC0nLdFN4ojvwDnlr
         PCgeeEQRcvcYqtPKbQ/aMSWgttnltraGG3+GCMteMTxmoBLV1SCQjdl+J+S8j1uymkCu
         KsvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=l4zm1sbHMytNqYdogbjGF6C06dm3yrxkJ0CqfKBvE4Y=;
        b=BNtbx6c5TrRPpmdRlSxHreipJXbLJFXyFCUzAfvRpBny+TdXADEwOSooWAFMn1dCzR
         JHE8LEWOTHlNK3FS4PRTsJMBG6eCcvNDMonzaz5gpx6PBjEVvmr7X2q0DZUSRL4Vtdda
         o7nZoOz1lebuuac/Gep5YhoRwlTtQExbwcsP9drz7jrr1tjJaggpRvUVXid2+IdILtKd
         kK24lzVzlpN8tn1bosjKtovV93veO8vqbHW68bZ75/5tkHElvRd4LVCG52ypUs/WBtgT
         3E5dz6/OwSKzqsFew7yX5Fc1cD+W3XthdvyOmJdlgMxI6ltVm5vCe3UZatJoHbvYaSR8
         lHMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kOld3GJA;
       spf=pass (google.com: domain of 3m-iiywykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M-IIYwYKCTocheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 43-20020a9d082e000000b0061c81be91e8si101339oty.4.2022.08.26.08.09.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m-iiywykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-3360c0f0583so29867337b3.2
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:40 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a81:6e06:0:b0:33b:4e1:dd6e with SMTP id
 j6-20020a816e06000000b0033b04e1dd6emr129882ywc.212.1661526579691; Fri, 26 Aug
 2022 08:09:39 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:54 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-32-glider@google.com>
Subject: [PATCH v5 31/44] security: kmsan: fix interoperability with auto-initialization
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
 header.i=@google.com header.s=20210112 header.b=kOld3GJA;       spf=pass
 (google.com: domain of 3m-iiywykctochezanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3M-IIYwYKCTocheZanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--glider.bounces.google.com;
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

Heap and stack initialization is great, but not when we are trying
uses of uninitialized memory. When the kernel is built with KMSAN,
having kernel memory initialization enabled may introduce false
negatives.

We disable CONFIG_INIT_STACK_ALL_PATTERN and CONFIG_INIT_STACK_ALL_ZERO
under CONFIG_KMSAN, making it impossible to auto-initialize stack
variables in KMSAN builds. We also disable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
and CONFIG_INIT_ON_FREE_DEFAULT_ON to prevent accidental use of heap
auto-initialization.

We however still let the users enable heap auto-initialization at
boot-time (by setting init_on_alloc=1 or init_on_free=1), in which case
a warning is printed.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I86608dd867018683a14ae1870f1928ad925f42e9
---
 mm/page_alloc.c            | 4 ++++
 security/Kconfig.hardening | 4 ++++
 2 files changed, 8 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index b28093e3bb42a..e5eed276ee41d 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -936,6 +936,10 @@ void init_mem_debugging_and_hardening(void)
 	else
 		static_branch_disable(&init_on_free);
 
+	if (IS_ENABLED(CONFIG_KMSAN) &&
+	    (_init_on_alloc_enabled_early || _init_on_free_enabled_early))
+		pr_info("mem auto-init: please make sure init_on_alloc and init_on_free are disabled when running KMSAN\n");
+
 #ifdef CONFIG_DEBUG_PAGEALLOC
 	if (!debug_pagealloc_enabled())
 		return;
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index bd2aabb2c60f9..2739a6776454e 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -106,6 +106,7 @@ choice
 	config INIT_STACK_ALL_PATTERN
 		bool "pattern-init everything (strongest)"
 		depends on CC_HAS_AUTO_VAR_INIT_PATTERN
+		depends on !KMSAN
 		help
 		  Initializes everything on the stack (including padding)
 		  with a specific debug value. This is intended to eliminate
@@ -124,6 +125,7 @@ choice
 	config INIT_STACK_ALL_ZERO
 		bool "zero-init everything (strongest and safest)"
 		depends on CC_HAS_AUTO_VAR_INIT_ZERO
+		depends on !KMSAN
 		help
 		  Initializes everything on the stack (including padding)
 		  with a zero value. This is intended to eliminate all
@@ -218,6 +220,7 @@ config STACKLEAK_RUNTIME_DISABLE
 
 config INIT_ON_ALLOC_DEFAULT_ON
 	bool "Enable heap memory zeroing on allocation by default"
+	depends on !KMSAN
 	help
 	  This has the effect of setting "init_on_alloc=1" on the kernel
 	  command line. This can be disabled with "init_on_alloc=0".
@@ -230,6 +233,7 @@ config INIT_ON_ALLOC_DEFAULT_ON
 
 config INIT_ON_FREE_DEFAULT_ON
 	bool "Enable heap memory zeroing on free by default"
+	depends on !KMSAN
 	help
 	  This has the effect of setting "init_on_free=1" on the kernel
 	  command line. This can be disabled with "init_on_free=0".
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-32-glider%40google.com.
