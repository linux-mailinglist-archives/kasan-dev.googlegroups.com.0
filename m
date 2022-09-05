Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLOV26MAMGQE77E6EIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FF185AD254
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:18 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id h35-20020a0565123ca300b0049465e679a1sf1867603lfv.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380718; cv=pass;
        d=google.com; s=arc-20160816;
        b=VRkgJG9269b6YVHwv3mi6dMRxRyYCC72DvUVpNqZHkce2fN7oGf+GrzqXBV3HlpVtu
         nNtDZAZW4NxWAsXSa1JlaNVEOs6+qgbpW/+viiK+SJTr3eLiFuTJcsPzu5A/SvgmIKVN
         zkvOIc7sq7eTTDRv8rTMYtQ8T64xQkv/IHCWfR5l/v2p63a+lputdHwWI3iz4lAoeRx3
         N6OXR/iMNI1vO+jTO4Vr1oMnIb2EQlshJig3JCc2pUKztaoWKhM8dgbkHZct1jAGzAJU
         YOJ/o2muiZ71QrNmc91lEIz08CXBQ1xTuxKW26X98TxY/xIOGi/HJZVKLTHGdSeji+rt
         Dxug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=E9osVLMMYVDMEDqMOrVDJmEOB+nc4svWQMIUk4Sxomc=;
        b=zfVh3RrVyMMWOdQ6HmxkAUBgjOFpYyEKUjKqJuUcFm73C78a7zeB/isW3WjtFFqQrf
         /LlvY+H17yBOCmjT1gsKyZC9GhLR9qiaJzQcj1XpeCwwk6F7UHRUjjWaVKD42PTBbkJJ
         DCmQvmftLC9D1viXocygnWNTkl1I/W6tNNmsTbJSxx8foH6R4kDaJitTpeBCGr6Z8iVQ
         BIMI+9D7Uy7BVCad+nXHzilI1VHnND/KORXRKiOr/rW4j2u2FxnRrlRyHy8iLsW1Aypi
         vWrNJAfaZgwIbPlcKzV/lLkX0SGAf+No+O0qgzwo6aUHywe3EoIWQ78n8lKjUPxgBSeE
         zyFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K+RIqV9b;
       spf=pass (google.com: domain of 3roovywykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rOoVYwYKCfcfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=E9osVLMMYVDMEDqMOrVDJmEOB+nc4svWQMIUk4Sxomc=;
        b=YOJDnORzcWq0GB6ibOazy4D87+KfhZpRJll+vbMUfh3xOPKj0SrkBAxy56fiWaXPwC
         +RKTbImB4pRa30KXv3f+qEya2RCLhY4nrMA+Rpg4XW3V4jeDfITd4kSP/hQaPNoFbX5U
         GB/gNYoOvirmqzMFztEYyickr5yxLcgnR2WiX/X9OmEyjluStRsfB/5w4IQ0BDfJsQX5
         OuFmhCyJmIFNwFHpoHfJreS09V+A5sHJTbwLTktzoTLK0ailblNbNyAMLywkNoMr6hRm
         +HV5zMU2TOVEovduxnlkSME6fvGWDhYRfas4y5Yd70U0QzoCfPDAZclAXbn6Yqx90fYi
         pYSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=E9osVLMMYVDMEDqMOrVDJmEOB+nc4svWQMIUk4Sxomc=;
        b=HRQ1PvAyKnNTzwwL3EIyat06Q/xdg2uKHr82IP0Nspa33vgCUYhzALkmA/y3q2Zgkr
         +sPzxX12n5DPwrFlxxXA64r4UcNNYGuU4zBI1iL0z0P4j/gvD5tOXcQnFKbhgHArWGyO
         R54s3eb9yYxtibjlBPgb7vqmc380EwAh0O9cs1JX4yjh6tlHZw43Ov+ML9qZ7RaDcwla
         wlyvf1Q1FMqY5PS28Gjk8Wb+EPzrgRr5nHMId8eF/vlhvvr2lHxGpTzNqQqv0FbfH+IU
         ewEfL6Ck7GvPNk1HSh7EauKpVXRud/lEbP+U6RmSFzdugN/oadTtFpsdGT7Y2KB+RAwl
         lKUQ==
X-Gm-Message-State: ACgBeo29ujbXxYHFjECsbeEVIVaZgvO+X6KjQLnAeqPna76tuKG2QvmK
	F8k08secDaYo5G+VJshgji8=
X-Google-Smtp-Source: AA6agR4pBgsq2OiCDVGSkRGlj+gGgRw3xFS2aAZnA203VnUwi9BuCR00aMcggfqrrjFDmOjaZZBNkg==
X-Received: by 2002:a05:651c:305:b0:26a:915f:45e8 with SMTP id a5-20020a05651c030500b0026a915f45e8mr156865ljp.6.1662380718149;
        Mon, 05 Sep 2022 05:25:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1055:b0:25e:58e5:b6d5 with SMTP id
 x21-20020a05651c105500b0025e58e5b6d5ls1563541ljm.1.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:16 -0700 (PDT)
X-Received: by 2002:a2e:8749:0:b0:25e:4357:8ef7 with SMTP id q9-20020a2e8749000000b0025e43578ef7mr15455910ljj.319.1662380716751;
        Mon, 05 Sep 2022 05:25:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380716; cv=none;
        d=google.com; s=arc-20160816;
        b=PfcKm0gw8c3MsH/PiToFsmLJd5EA7NkE/scMzuvJ4T2T4lshPY1oL/75nzI1Bx0UzC
         mUQAWO4IJ+Nxi2PCDczYLzUpJiXZVy2se694Y5LUuHQSqC4v3DtvnKJX56lA08ZvTuHL
         1j+3tH7DLgVTJN+qkivvc77sJo9KkWrSSbdEdYsw66j9olsUTRPZH4toEPmg4GQ/V5Zg
         SVB6xPOU64CiQTukgukHEeROrXVFCPaSk7aLTPFqvLynov3YGo0b3t2lmsNpqTx3QKzX
         6aG8EhPq/xaCPsxT4+jXSrgrpWCO7CN84UWEtDfzon7xWycCOkxf+Xiv5qOpTeYO4LwH
         UThg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FNkIx/jm8VmVwIUxP0UOjGDN2D7zAcH5S0k2sC/Umx8=;
        b=SNN8hO/UwG1j1HMYRQVceLpFp1Yg8K3aI2RxSQMwnz0YD2KIPORrcRjrQCYC/eYqnQ
         GiZyRDUHidsrtiCDn69367pF34ccNmIh0XxcLDkB2rzrdzbx7+OmG+v7exm1m/Z/6dTz
         PBFIPRbkiTwG5gKSdaXkZZIL1bzPkN7ORls8Mo1Xiv4r/+XcXJW9f02bwjcdoex1Xln1
         C1c2axZDmAiTLyedr+4X1CR2GlZYG9M/An5uQTVoK24xhO+fdHhtpEdcFfMo9v+sCxTJ
         zUtdK1m7aNuKZGLz9hRuWXzRxPwgPe1TpZSnE7U4sXaqdrBpGvn92zdMY1AtnlV2VNwQ
         nxhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K+RIqV9b;
       spf=pass (google.com: domain of 3roovywykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rOoVYwYKCfcfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id s11-20020a056512214b00b0049495f5689asi328112lfr.6.2022.09.05.05.25.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3roovywykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id z20-20020a05640235d400b0043e1e74a495so5773644edc.11
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:16 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:2bf9:b0:73d:dd00:9ce8 with SMTP id
 gv57-20020a1709072bf900b0073ddd009ce8mr33496068ejc.151.1662380716059; Mon, 05
 Sep 2022 05:25:16 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:15 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-8-glider@google.com>
Subject: [PATCH v6 07/44] kmsan: introduce __no_sanitize_memory and __no_kmsan_checks
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
 header.i=@google.com header.s=20210112 header.b=K+RIqV9b;       spf=pass
 (google.com: domain of 3roovywykcfcfkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3rOoVYwYKCfcfkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-8-glider%40google.com.
