Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUH77OMAMGQELO2BI5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B88F45B575A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 11:45:53 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id e1-20020a2e9841000000b002602ebb584fsf1844862ljj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 02:45:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662975953; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nn6JrlYp60rBE20WXGnF/qsRFtyZY/m/in1fg5ml2xEQSAPii/0NQVGS2crQMsSD2r
         PXto1zLBc7j0ZCZrbXxBHAJkIaxfWy/yphDpzSekQW5gigiFcFtggkNOYUsy+9FOdsSj
         T3qEE6MEaoN30giMzCadJXmFentW+903cSiuXk00zq6biHDHFRMzrJ2PEkHi6dwy9p14
         Lq3VLhVcTbYYlr62XODPTJP+BB2YWNYidRm3UfP3A7aciQZZ9kBfaFTF+KfYC947BIhI
         p3XFHWfif0yrFIe2cVX9WesEOCkrUKe6HASA37VSAPlUUpbO47NJ8AEGWXxAK3wZFlmX
         NoaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=b4UjJLuNNZAT9AxEgIFyH/tAA3MuKTVk0bdtWwxUdhI=;
        b=LLa+dbp0ZI1GhtDtIeltwyFcmiwKBKqXB7JNSwrp0K1vEj1ZbtEqNiiqTexbDZ6ez/
         YUTRoAqini9PaFWTtctdV/70LG4wzmrd4T2rs/Rech+/IR3GvuoFgW9sHNeTQaflmeXp
         gPlz+5pbUFFO45veaQ0oRzYzlWCgrHHCYOQ0DbNEqtZQYprvQ5eZFbCXVzQmtQKBK+/+
         KlFzfYfl6q+vXQYqmZFTfmyL8eo7rG2nQVxFCjhvX4a1sW3hwhTfjbB/5oAkO+v/y1Sx
         GrPMDFZji4rTyhzczWoz6X+zMkOeygoDiIt5ZP1xi75owgtAD9S7eiWFn/Q7vUWZURrI
         UrpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MR5DigsB;
       spf=pass (google.com: domain of 3zv8eywukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3zv8eYwUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date;
        bh=b4UjJLuNNZAT9AxEgIFyH/tAA3MuKTVk0bdtWwxUdhI=;
        b=nKdSLEHP4WMR7r9p3tudmC/0joM00TmBf8+VNxHw55kcFDWYuxZMKHLqEQ29nK3T0n
         CXa8O1FjnCh32ntZjX8X95ALLOaqLLYlIj+jJoINHDvvC9TH1/dqbefyFSEZzrhDH1Ml
         MgQTuKczu1WlJcIS/QJYeni1RLdNEIGMks9763u08wX/MvwCoaicgS8v+e9sNm8vUg43
         ++NL/DrA32sYsfjCBnzBq3lULaoJKfs/McPzuY9wHSDqxpo3/EdogvOFWtlv0wP1EtD3
         6BGQceFWE9MrQ69YXMLCc+0wBDBDHiXThBs4W8ltLvJM7aL1dfIRERA5xOs1nDdccP1h
         gp8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=b4UjJLuNNZAT9AxEgIFyH/tAA3MuKTVk0bdtWwxUdhI=;
        b=0196STSB6noTmexHo6RHZRfvW9jzfNvPTpPkQuhNVJzEwEmLduzvv1eQgqc/i3C5CK
         aG8+5ac9AuikLEC6/dE7xYHzgTBV0Vp63SY5+aNxHOdgW+2IravhAtXvOWMIbM3l/+jX
         H0WhXXWvQfUfYoMQ6KsNyt2wVsovR1jFm9jATafijYCdmqATR0dtA5BPrA6f115BNtFX
         +iavS0C61P7hPy1umf2VOvEkVJSfPxExeM2Vdnb5NCfSDTYS7SV9S9auQwBZCYW9rvlK
         SyEkaCCgmy5XDi2oEArj8uEYE/0DnjEOGtP4HMtngFtdvl5F/UhwYapmu81cIPAhZyGN
         3DAA==
X-Gm-Message-State: ACgBeo3Zfd1Ady1HQBy5eF2nkDpLkkCeonwdzkrm+XGpLyVDxuOo0w45
	fow7DC+oZvhB2CHSafXXv1I=
X-Google-Smtp-Source: AA6agR7ALL0J1LtMxLDK1EHa7YN5AkuSkPfw4m7joDFvOA6D1UYmboX8V9Qu5uOQviIlY6bRUHQHGg==
X-Received: by 2002:ac2:4945:0:b0:498:eb8d:e283 with SMTP id o5-20020ac24945000000b00498eb8de283mr7106126lfi.192.1662975953027;
        Mon, 12 Sep 2022 02:45:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:808f:0:b0:26b:db66:8dd4 with SMTP id i15-20020a2e808f000000b0026bdb668dd4ls455783ljg.8.-pod-prod-gmail;
 Mon, 12 Sep 2022 02:45:51 -0700 (PDT)
X-Received: by 2002:a2e:bf21:0:b0:266:2be3:61e8 with SMTP id c33-20020a2ebf21000000b002662be361e8mr7258875ljr.383.1662975951443;
        Mon, 12 Sep 2022 02:45:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662975951; cv=none;
        d=google.com; s=arc-20160816;
        b=TKZqvDa7nPiwxh3mIAeyy1l4oWsZ0puyOtYcNXEeeSNF/zTcbC6XnwMqqP+H7wpcsn
         eKG3CgqHgv+8YX0Azt5AYLXvEWUgAWUXGRkNNl2YhdcOPGxrIib2J1NJzVYBbQ2D28gK
         JITYhb/sZKnw481JBvQYyyB3hjALhP0eSjfEu9tceoKCL93ix0G5MG195rPXdfOtNvSl
         BigwXsFuiCnmYVGWuYwZpajdaFDKNbRN5J4tWvLMBQe9zhoAcUqeDgB9Cdr7bzl3m8XC
         0dXzrTrgmNdhiwaPOtaSZ7qzHjd96YwphLhkU6usX0jW2IOAWQGiNMAj3qNLgrz61/Xg
         QDxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=jBoH9dZtU8u1abW3Qj3aDrAs7nz5caMLzMPJv+JY2CE=;
        b=GjndkaIKuvGrpWWWie2N8YEulq1CeC0mIN+26q2W/Otx+QSamacA3ejBFndHuJsgjL
         5QcZ/hV8rCeurVRw1PXJZm3zNfZAf7wKpvQzJb3qr2FFo4RTCd2/DmLw8DIR4ZNYEoQ/
         u2O1PC3Ou6KUn5USOaGnURYp4/i48BNQ3+s13PvjpbVMNB6Txb5Ub26pfeUClBYGbyTU
         F09dtyErdN1r9Yf+F+J9hwnwogiGuEkdbDFPCNHx4fW49KRj1Z3qDsq/2G447yWgZYyC
         EoDwsqgyqKFUsFMtS2qVe5U3UpbY7xbzQcMhKx2j740IuxxMNtbxTj6mhUGNJaeP6U1B
         y9sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MR5DigsB;
       spf=pass (google.com: domain of 3zv8eywukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3zv8eYwUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id k15-20020a05651c10af00b00268889719fdsi205080ljn.4.2022.09.12.02.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Sep 2022 02:45:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zv8eywukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id xh12-20020a170906da8c00b007413144e87fso2906022ejb.14
        for <kasan-dev@googlegroups.com>; Mon, 12 Sep 2022 02:45:51 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6402:5002:b0:444:26fd:d341 with SMTP id
 p2-20020a056402500200b0044426fdd341mr21825632eda.351.1662975950998; Mon, 12
 Sep 2022 02:45:50 -0700 (PDT)
Date: Mon, 12 Sep 2022 11:45:40 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220912094541.929856-1-elver@google.com>
Subject: [PATCH v3 1/2] kcsan: Instrument memcpy/memset/memmove with newer Clang
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MR5DigsB;       spf=pass
 (google.com: domain of 3zv8eywukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3zv8eYwUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

With Clang version 16+, -fsanitize=thread will turn
memcpy/memset/memmove calls in instrumented functions into
__tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.

Add these functions to the core KCSAN runtime, so that we (a) catch data
races with mem* functions, and (b) won't run into linker errors with
such newer compilers.

Cc: stable@vger.kernel.org # v5.10+
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Truncate sizes larger than MAX_ENCODABLE_SIZE, so we still set up
  watchpoints on them. Iterating through MAX_ENCODABLE_SIZE blocks may
  result in pathological cases where performance would seriously suffer.
  So let's avoid that for now.
* Just use memcpy/memset/memmove instead of __mem*() functions. Many
  architectures that already support KCSAN don't define them (mips,
  s390), and having both __mem* and mem versions of the functions
  provides little benefit elsewhere; and backporting would become more
  difficult, too. The compiler should not inline them given all
  parameters are non-constants here.

v2:
* Fix for architectures which do not provide their own
  memcpy/memset/memmove and instead use the generic versions in
  lib/string. In this case we'll just alias the __tsan_ variants.
---
 kernel/kcsan/core.c | 50 +++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 50 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index fe12dfe254ec..54d077e1a2dc 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -14,10 +14,12 @@
 #include <linux/init.h>
 #include <linux/kernel.h>
 #include <linux/list.h>
+#include <linux/minmax.h>
 #include <linux/moduleparam.h>
 #include <linux/percpu.h>
 #include <linux/preempt.h>
 #include <linux/sched.h>
+#include <linux/string.h>
 #include <linux/uaccess.h>
 
 #include "encoding.h"
@@ -1308,3 +1310,51 @@ noinline void __tsan_atomic_signal_fence(int memorder)
 	}
 }
 EXPORT_SYMBOL(__tsan_atomic_signal_fence);
+
+#ifdef __HAVE_ARCH_MEMSET
+void *__tsan_memset(void *s, int c, size_t count);
+noinline void *__tsan_memset(void *s, int c, size_t count)
+{
+	/*
+	 * Instead of not setting up watchpoints where accessed size is greater
+	 * than MAX_ENCODABLE_SIZE, truncate checked size to MAX_ENCODABLE_SIZE.
+	 */
+	size_t check_len = min_t(size_t, count, MAX_ENCODABLE_SIZE);
+
+	check_access(s, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	return memset(s, c, count);
+}
+#else
+void *__tsan_memset(void *s, int c, size_t count) __alias(memset);
+#endif
+EXPORT_SYMBOL(__tsan_memset);
+
+#ifdef __HAVE_ARCH_MEMMOVE
+void *__tsan_memmove(void *dst, const void *src, size_t len);
+noinline void *__tsan_memmove(void *dst, const void *src, size_t len)
+{
+	size_t check_len = min_t(size_t, len, MAX_ENCODABLE_SIZE);
+
+	check_access(dst, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, check_len, 0, _RET_IP_);
+	return memmove(dst, src, len);
+}
+#else
+void *__tsan_memmove(void *dst, const void *src, size_t len) __alias(memmove);
+#endif
+EXPORT_SYMBOL(__tsan_memmove);
+
+#ifdef __HAVE_ARCH_MEMCPY
+void *__tsan_memcpy(void *dst, const void *src, size_t len);
+noinline void *__tsan_memcpy(void *dst, const void *src, size_t len)
+{
+	size_t check_len = min_t(size_t, len, MAX_ENCODABLE_SIZE);
+
+	check_access(dst, check_len, KCSAN_ACCESS_WRITE, _RET_IP_);
+	check_access(src, check_len, 0, _RET_IP_);
+	return memcpy(dst, src, len);
+}
+#else
+void *__tsan_memcpy(void *dst, const void *src, size_t len) __alias(memcpy);
+#endif
+EXPORT_SYMBOL(__tsan_memcpy);
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220912094541.929856-1-elver%40google.com.
