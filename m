Return-Path: <kasan-dev+bncBCCMH5WKTMGRB76DUOMAMGQED5G2DOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id CAED35A2A66
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:49 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id bf3-20020a17090b0b0300b001fb29d80046sf1204252pjb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526528; cv=pass;
        d=google.com; s=arc-20160816;
        b=LtxWIJelIKIbjeahaaZia0dJf4bHdE4+M0CJ+j2tfHiHyTK/aylOEm/JaOoI3eaR4t
         InSrwpERFM8OwZkNZvySc/G/cv5MqfSeR9Xq5pU7rlCUVjuNNMGKipfsMowVRulAiZDH
         MUlod5+o3DmEGVQQKJXIwr4stXkA4L5VzEdxzofUu2Of4aFrX+KMpgSkf3P2+DS+X2CX
         K7oiNCFuFqQSiJZwlGpZKAQbCzEZbyi2avj5c14X5N4lrYwYzAEHGPO6P2AbjyLlvhs+
         LrDB+t9d5TsiSEHfsygDiD+wVzkM3DqJKXMm4ECozU6eRZ9gJNZWY7GluPahWbG+5uO2
         bhZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gEPwR03aoF4ADLKKAg6Sn7DOHxTSyI+bidJqpC1h3Ns=;
        b=TDuOrvaO4J7QFSTdckMhNn9LlmavCfrToHk8j1svbYy2jW+EfcM+Dhe5Sp/qc0WfwP
         0Rvwt4ZiBzJt1V6Ae6yXXPfmzr60oKy9t98WWivV+G4YmiIGYQUeKe0vnQ1TdXcyzSwR
         WCkyhiK/aYzwA9brTpJJcN7Z4J3zgtSG3Qcz0UfddM8yJj1H2Qx30f5watubjDNBinQw
         K5F8u+Xi5HimHmxTNzh6HClsRgbTj6xuLeBPm8tPb/9UUBXYnjJQd5mqkjIkT0B1gNwk
         SXkvn7sGeoRGHprf6g62ouQUnUhCQCvkZ4tDFrPeXYVEMA6ryJL/eqWvy/XVL2F6BLis
         NzjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XiFqi+Hv;
       spf=pass (google.com: domain of 3_ueiywykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3_uEIYwYKCQUlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=gEPwR03aoF4ADLKKAg6Sn7DOHxTSyI+bidJqpC1h3Ns=;
        b=QhWdRFl+0x2u/WzoHiqwjoy4N2OXx/T9hQ+2xXSt9mH7ydcIp6nHzdxszjAzjwXA6a
         h/qz3ebDmXixJjTyVF05IuH5cGr+o/B9nEwqPQ7D3FiZ2xWMedFWR+nYNPYWwG3zRlxM
         BWcQx1/Ltik0qFxVhKUPcDgvG+YFZOY42puCxNFpnWfvRyhom+muJrNsjijZsNCw+P6h
         /BEt7msEfNnDvpvTc14ilebQybFeLE8MSwKQhaWnktuVb/DxVtvEuyU5aE4C+eLm6zdF
         Jr/0aMRE4I0/OJDmscvyOjby6UyNLNx/BTTCCwgBU6gmUEPcpM1Gumwh2jzGXcxspTdq
         AOJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=gEPwR03aoF4ADLKKAg6Sn7DOHxTSyI+bidJqpC1h3Ns=;
        b=1f3U/BnMMzmAUIEXhRHP/oqwOR4ZV3YyTywn55x6dlJY2JZFK0VmK+BWq2rbHgp/Wm
         LNN73HAO61pSiaplewOXSC7Wb507tBbyK+UHeE5/FcMPLwZPsYGIEoKbxN/1AfsFnXYE
         6k4G/cDysyCOKRseErg8YtEHJgYznc/vAd267NwvpE1VIphRxoBXXgMAhhyuBNHDiKIl
         0PxrKa6ZgzNX3kqw2Ghx+WsD5j7oe2H83Qamej7UP40AxbeWwd/sC8mVgQnW0oQtBshT
         CDM0LUpj+o8htPDLssoCGaK0yy/cNOdd3Tq3e/AH1AYm6m3N/NTvJVPhAUeL7ZekLF/H
         RjlQ==
X-Gm-Message-State: ACgBeo01Zi/jK4NAkC9gDZJiOGKG4Vq3WLdQaH9YGQO5e5EDAF8tBgNb
	GtCIAIyHomPXCAWE/AU8id0=
X-Google-Smtp-Source: AA6agR4caHGAJSoOiJdE/js+DJ/6lxuciMupKzoeKkqZAAgMlcTpaLBAJAbOeDtOzTwTqmfO6PMdrQ==
X-Received: by 2002:a62:188f:0:b0:536:ee23:e3ed with SMTP id 137-20020a62188f000000b00536ee23e3edmr4301854pfy.33.1661526528089;
        Fri, 26 Aug 2022 08:08:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3b87:b0:1f2:da63:2f68 with SMTP id
 pc7-20020a17090b3b8700b001f2da632f68ls1975468pjb.3.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:47 -0700 (PDT)
X-Received: by 2002:a17:90b:1bd0:b0:1fb:740b:c3ba with SMTP id oa16-20020a17090b1bd000b001fb740bc3bamr4684898pjb.61.1661526526939;
        Fri, 26 Aug 2022 08:08:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526526; cv=none;
        d=google.com; s=arc-20160816;
        b=VRI3e+zJ9aAtBGHmaodxbypWNFRDKYoFX57drr1Ld2sbeXr+cvx0R1e1StgeV8cj5+
         2FWqWbiL2vfe2YvoWx9gqLzRJh6OUUuqbF/j7tzi71S0JDwr9R9SaOPCcLjcwbysm4wj
         JG2No3fDsG36cFFq8NJWWgLnDopsanx9Nbk9Swchluqak9bCZHAd0isKmC+TFeTHSMC/
         Mwi6sn5Gvf1Dbpybg2ArEbGrO0OxncCafq4Vw3SM3vTUrBeO5wJyUENaF7/xwtN0OlsJ
         LeB/IfEPW8o0ukMM9p/EBBqKhuPUwS8NEzUlBD6IxG+gnIgs+BtbIoLV/izwOE9OJoP3
         0kjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mLlFYFB/rgc9qqJnOoWYqSqEWYlWfzhxjk78c+cLuAA=;
        b=AsXHnWTMEwE6HQpB1CA7cbfOVk26vhKkwuk7xEJ/eHjFuxCZq3pKrL1iXLBXcwW0Zy
         pw4/Aq85ZpZw7Is3dtU3h04tBPHbEnRdHRZ9AtfZV3Yt6CoRWW0yPKjrNwWrGLRMpof2
         sIJcGXEybNVqh5YVritgk7fBxLYe30b2JAYPJgvUyb+Yyc3GY+3oejEkPQdMA2eRZbSh
         OTe4TZxE50qg+zl6O14ROZC1SnqXMxoyiOAvubiCEqAjFhSImJHASFsolJ93xUs+n4EG
         fwtwzGDTKvZp1gu4PouFjFtSf6yDXjph3W67ARyFH2ZsyRyxmISNTLh9rvHtgWbKo79o
         w+Zg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XiFqi+Hv;
       spf=pass (google.com: domain of 3_ueiywykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3_uEIYwYKCQUlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id n7-20020a170902d2c700b00172bdefe0c4si80001plc.13.2022.08.26.08.08.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_ueiywykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-33dbfb6d2a3so29605097b3.11
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:46 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a0d:f144:0:b0:33d:a554:b9b6 with SMTP id
 a65-20020a0df144000000b0033da554b9b6mr135036ywf.172.1661526526267; Fri, 26
 Aug 2022 08:08:46 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:35 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-13-glider@google.com>
Subject: [PATCH v5 12/44] kmsan: disable instrumentation of unsupported common
 kernel code
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
 header.i=@google.com header.s=20210112 header.b=XiFqi+Hv;       spf=pass
 (google.com: domain of 3_ueiywykcqulqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3_uEIYwYKCQUlqnijwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--glider.bounces.google.com;
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

EFI stub cannot be linked with KMSAN runtime, so we disable
instrumentation for it.

Instrumenting kcov, stackdepot or lockdep leads to infinite recursion
caused by instrumentation hooks calling instrumented code again.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>
---
v4:
 -- This patch was previously part of "kmsan: disable KMSAN
    instrumentation for certain kernel parts", but was split away per
    Mark Rutland's request.

v5:
 -- remove unnecessary comment belonging to another patch

Link: https://linux-review.googlesource.com/id/I41ae706bd3474f074f6a870bfc3f0f90e9c720f7
---
 drivers/firmware/efi/libstub/Makefile | 1 +
 kernel/Makefile                       | 1 +
 kernel/locking/Makefile               | 3 ++-
 lib/Makefile                          | 3 +++
 4 files changed, 7 insertions(+), 1 deletion(-)

diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index d0537573501e9..81432d0c904b1 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -46,6 +46,7 @@ GCOV_PROFILE			:= n
 # Sanitizer runtimes are unavailable and cannot be linked here.
 KASAN_SANITIZE			:= n
 KCSAN_SANITIZE			:= n
+KMSAN_SANITIZE			:= n
 UBSAN_SANITIZE			:= n
 OBJECT_FILES_NON_STANDARD	:= y
 
diff --git a/kernel/Makefile b/kernel/Makefile
index 318789c728d32..d754e0be1176d 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -38,6 +38,7 @@ KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
+KMSAN_SANITIZE_kcov.o := n
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 # Don't instrument error handlers
diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index d51cabf28f382..ea925731fa40f 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -5,8 +5,9 @@ KCOV_INSTRUMENT		:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
-# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
+# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
 KCSAN_SANITIZE_lockdep.o := n
+KMSAN_SANITIZE_lockdep.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
diff --git a/lib/Makefile b/lib/Makefile
index 5927d7fa08063..22c064b61b3be 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -275,6 +275,9 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
 CFLAGS_stackdepot.o += -fno-builtin
 obj-$(CONFIG_STACKDEPOT) += stackdepot.o
 KASAN_SANITIZE_stackdepot.o := n
+# In particular, instrumenting stackdepot.c with KMSAN will result in infinite
+# recursion.
+KMSAN_SANITIZE_stackdepot.o := n
 KCOV_INSTRUMENT_stackdepot.o := n
 
 obj-$(CONFIG_REF_TRACKER) += ref_tracker.o
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-13-glider%40google.com.
