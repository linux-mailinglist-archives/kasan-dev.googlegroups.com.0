Return-Path: <kasan-dev+bncBCCMH5WKTMGRBN6EUOMAMGQELCOOXJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5841E5A2A8A
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:44 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id hp36-20020a1709073e2400b0073d6bee146asf736964ejc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526584; cv=pass;
        d=google.com; s=arc-20160816;
        b=vj/VFn92BDWcbQSZge90cEoKHaNeETY130Gk0U+KIYn2khwlk2eZMiLjQQeVoO6b45
         LgiXbO0qULHVGQyfYXpqTXSv5W3GvXy5jiA2bKNLSCqh3bhfiQVnGHgVzWck/17m1Cx4
         in1N/jHjzeevUbo2EmH8UNi6sgNDuRsAntmb1/GXELtK+yk3Lyiv7zMD/0IM2vVz54N/
         +dMi8FIzZs9AipMrqFPuP/PMXoehvQeWSvbV/oqbDCoDdxZrwuRExYUseeXpX2CJRva7
         jxxE0s4WM0BRLCPqf9qJJcu9UyYHLXo1w0QNA8TPuC/xxbCdu8CqnRkdHr05wDEiCSNa
         gX7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=eyPXrRL+BuZhKysJNxkatQJQTG/maOayUs5ysJg+WwE=;
        b=uiFmObasjM6hJKZtoSo96el+l/iXfX/MhwVTSrlVftarYYFzsXk/KwkF0vTtpSjR+v
         ZWLIH7CELuAk6iWqzgsYDWHYaH+XARgfvaOylksQTGgpT4xvg3XZbmqi5V/rfYFGrU3e
         C8fT5/SUli2vKJoosFIS1s4aY1UmswOvQN9wbzrvtLNKlGMz9t2kVgL7kY35BTPOKe/4
         U8i/4gwPkeR+2MEsaMY2oPQo3qJuJCPG/k1n7rWFQx5WBxxtSdEBw6VoFvCUrxgFDpEi
         3IEn0Apyln26lrupIsnIqbRUsRzlJSZ9cwv9r6Rf2XBUKfGXXhzbmwj9dIwCzkeGEQIW
         IPKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q2dLT3h7;
       spf=pass (google.com: domain of 3nuiiywykct0fkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NuIIYwYKCT0fkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=eyPXrRL+BuZhKysJNxkatQJQTG/maOayUs5ysJg+WwE=;
        b=E9F1XeJVwmstKWn2epmYkhCrqCpN2eest1Ki1mddmLmj3IeFpKpyTqa71LxIRcSE6a
         WGuEer5/qJ5PiYJvA/SrjC/1QuLGp7m5Kp+IdFhdObp5ea2ojDzRkGhT585GjfmORuk4
         7UtIHuFWWrh7F6oQwcWHjQ7TTY5Qa1JGJ2iGoVvnFVJypXlsVxrjGIHHZqRkj73UdjGQ
         9tGmaCHkRG13p2+r3o1KvRHpiD6yEOWj22AMLC78o6XyFdOH+2lehmALmw2ligXczPfm
         ABMvI/9tfeWyPINONJvVbPKmRaBWxU79YdWnRhkxXxPNQG9c6wBkAjmV0MOFGlJOUUlM
         LGdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=eyPXrRL+BuZhKysJNxkatQJQTG/maOayUs5ysJg+WwE=;
        b=1BdKRGOliZE/huoh+zOslvtK80g3L5/hNSK+oyrAGPxdnJk51+93duRACI7969t5WR
         IsouMEMx2XnHUECxedxSR5sy8lgA0NzBQWSckVJo3mFKS11pvVY4RBT+uNsAQeNzgLTs
         82iTHDBpGO7AIfgkWYeBVJfi9+gphVI8laSbR36Lp9t7/ZDX00rUKzcOJpqj0BzDpGFE
         fKy8p5lZU1v2XhTSX2nLPoN5mi2IsRChO653WppK71N16745cwYAVoxau0os0dZ0iZ3V
         J0hQ/+g2y324S7cqq9+GMH9uSKMCaLnwdFwnZxoLcgOgGakUGNHl+C9SBgKM+6/SN66v
         qQzA==
X-Gm-Message-State: ACgBeo1EX54hgCG5Awp7ZT7jb6GWpPSTmUq4sPXocBm+yJBL3XUY+xJq
	N+rvrhTNytD336sQ7a49xzA=
X-Google-Smtp-Source: AA6agR66LSi2d2zTXEOsIHnYUXpx128YJNbWhBE1In4cTXXjXGCdRfseGtig5khQDzxze9x5wGtGUQ==
X-Received: by 2002:a17:907:2724:b0:73d:7696:cc2f with SMTP id d4-20020a170907272400b0073d7696cc2fmr5808240ejl.678.1661526584059;
        Fri, 26 Aug 2022 08:09:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35c8:b0:448:19d:6ff8 with SMTP id
 z8-20020a05640235c800b00448019d6ff8ls1204673edc.3.-pod-prod-gmail; Fri, 26
 Aug 2022 08:09:43 -0700 (PDT)
X-Received: by 2002:a50:aa82:0:b0:445:dbba:6cb1 with SMTP id q2-20020a50aa82000000b00445dbba6cb1mr7239212edc.267.1661526582937;
        Fri, 26 Aug 2022 08:09:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526582; cv=none;
        d=google.com; s=arc-20160816;
        b=YyRmOMKrSqrDWjXQ2IkKO0rq0M7DMwtamt7rPYR/IybaGTNmDybd7n3zulbpl624tS
         JLfy30vTYcr1NixSWKU17KINudGUyEzK+B11l9eGaNYvaT4GNRQ8J8PdP9r2aVEBRhwH
         cLXBnsGsq5ZIQFSpwBW8acra0OFeX9sGXoJS7jdhLJV6PUadYB8vSB+uJqn0lkD2ziO2
         wDxxLoDQvUrjTWRf6UQexvqPDEakC1jINno+5eitxp8ehHXSJVW2zKYrKDh/ltynDztC
         pfIuVoxAMPvOEqsuuFDKmvmKiV42T/zPde717MeLJ7DqRdt5iADOjDfwVTzIWKP4FV9j
         HIvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=wnBRr6RijpcrZwDY4IvPeedZIJ4FbGOivCI4jGGTq68=;
        b=DZJG5VuNo27lA750WwiG/X3F2jb63CBKudV04NBJ8DMU5lEbL4GIm4A4tHXwwmREEi
         CWhY/p+0e99aCs1e4gPzxkxmcwDtxWawSAN3nLJulFJCSwX8h/vPqyzHeG1xDBe3gin8
         6ysa2ipZn85eXX8VhPFipJVO0CXTWih37iT9mWlIuzFpW548jQuoTxVY7DFFrOrzhx5u
         jNE5ZOOSGeyTjGHnp5xZ68jNftuyAsbZr6GA20rmfPnab03X1v5IDAcx9XyqGOSepWm5
         JcqgfcCAGzR+HG1M/lbaMM6XQtU/dKu61O7flKCYConKZvMeRQZeFya/mN74YY0NawZl
         w/4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q2dLT3h7;
       spf=pass (google.com: domain of 3nuiiywykct0fkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NuIIYwYKCT0fkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id c2-20020a056402120200b00448019f3895si34426edw.2.2022.08.26.08.09.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nuiiywykct0fkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id s3-20020a056402520300b00446f5068565so1236685edd.7
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:42 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:268d:b0:43d:b9d0:9efc with SMTP id
 w13-20020a056402268d00b0043db9d09efcmr7340129edd.92.1661526582428; Fri, 26
 Aug 2022 08:09:42 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:55 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-33-glider@google.com>
Subject: [PATCH v5 32/44] objtool: kmsan: list KMSAN API functions as uaccess-safe
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
 header.i=@google.com header.s=20210112 header.b=Q2dLT3h7;       spf=pass
 (google.com: domain of 3nuiiywykct0fkhcdqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3NuIIYwYKCT0fkhcdqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com;
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

KMSAN inserts API function calls in a lot of places (function entries
and exits, local variables, memory accesses), so they may get called
from the uaccess regions as well.

KMSAN API functions are used to update the metadata (shadow/origin pages)
for kernel memory accesses. The metadata pages for kernel pointers are
also located in the kernel memory, so touching them is not a problem.
For userspace pointers, no metadata is allocated.

If an API function is supposed to read or modify the metadata, it does so
for kernel pointers and ignores userspace pointers.
If an API function is supposed to return a pair of metadata pointers for
the instrumentation to use (like all __msan_metadata_ptr_for_TYPE_SIZE()
functions do), it returns the allocated metadata for kernel pointers and
special dummy buffers residing in the kernel memory for userspace
pointers.

As a result, none of KMSAN API functions perform userspace accesses, but
since they might be called from UACCESS regions they use
user_access_save/restore().

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v3:
 -- updated the patch description

v4:
 -- add kmsan_unpoison_entry_regs()

Link: https://linux-review.googlesource.com/id/I242bc9816273fecad4ea3d977393784396bb3c35
---
 tools/objtool/check.c | 20 ++++++++++++++++++++
 1 file changed, 20 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 91678252a9b67..577dfdca635e8 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1060,6 +1060,26 @@ static const char *uaccess_safe_builtin[] = {
 	"__sanitizer_cov_trace_cmp4",
 	"__sanitizer_cov_trace_cmp8",
 	"__sanitizer_cov_trace_switch",
+	/* KMSAN */
+	"kmsan_copy_to_user",
+	"kmsan_report",
+	"kmsan_unpoison_entry_regs",
+	"kmsan_unpoison_memory",
+	"__msan_chain_origin",
+	"__msan_get_context_state",
+	"__msan_instrument_asm_store",
+	"__msan_metadata_ptr_for_load_1",
+	"__msan_metadata_ptr_for_load_2",
+	"__msan_metadata_ptr_for_load_4",
+	"__msan_metadata_ptr_for_load_8",
+	"__msan_metadata_ptr_for_load_n",
+	"__msan_metadata_ptr_for_store_1",
+	"__msan_metadata_ptr_for_store_2",
+	"__msan_metadata_ptr_for_store_4",
+	"__msan_metadata_ptr_for_store_8",
+	"__msan_metadata_ptr_for_store_n",
+	"__msan_poison_alloca",
+	"__msan_warning",
 	/* UBSAN */
 	"ubsan_type_mismatch_common",
 	"__ubsan_handle_type_mismatch",
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-33-glider%40google.com.
