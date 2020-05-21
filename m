Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIM5TL3AKGQEJ3G3IKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id BCA801DCF76
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:26 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id 184sf4879887iow.10
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070945; cv=pass;
        d=google.com; s=arc-20160816;
        b=WG4FvVPsOwAGUA5I+vl9E+NWfu6FPtwlHTgFo0mIo9hOq7f29BHoWmLm0o0s300tcD
         56EpoB82m9ql/F68lYV9owk5mdaz54hGvHwSdRmgPXstvrULKGJGK6DjQVmjx9abA4TK
         wk23e1YLJHJdtBr7uh1F4/pNuGZL0VwXeGS1hAnDMqXurWvNMPYY4McPlhk8IlhN7vGZ
         a0nmLhDX4bbyTNV37VC6f8chFt56ji3PtUDzrW6wbmsNFUgCbIioUehrPMYOn5139+cV
         Bf54hYZ/ySXNm89h/i/Rj8qjVnODu7BpQWwXYvx75cUjYeLOJplg2Q5dt4n5yO8EkGSP
         AYbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=MERawGnphyfJQgvGqnyr2BQMOoqh4a5STQRa80KR+PI=;
        b=VBtsDblj/U7/P0OJeKMF8STL0/A/YEKFw4fLHvrXp9imaXe1S/xBtkfCLDJXo6Ytqe
         Jor0r2YpwpcOz0dabkD1M7k8ZBP2dBQ6KO2VIM3qP9ZLcbE9WQIZs5DkL1NmSexUCXtO
         lcKXN+P3Lip7Q6Iv/YrMPYrv21kbxd9Z2zvWdhcEtfAoYaTdCKMNozDQoCHlHXL6Yify
         hZMzHoAYybRt0Jb9q6wdDC9sPi4XV566cNYRXvhpOXnDlmYMl/M5sAL0UB6nBY+xItij
         fHqwkv31b852z08Zmgrgnf/Yiz5kZmeXjDsRovzkOc1t8QuCaJRPyTbUIILV6bZlAOH0
         yuFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jEt1Ln1f;
       spf=pass (google.com: domain of 3oi7gxgukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oI7GXgUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MERawGnphyfJQgvGqnyr2BQMOoqh4a5STQRa80KR+PI=;
        b=FBUfg6/2fTIL2L8dNi7tAMe7kix7NWpxwYDG7mG2eBDo6Sx6yPJoZ2+fI+6TgAUpNj
         G1PDC2jdX2nfLlKei4rTZ/+peD+qc/1L2d+afs71HQUV+CQZjGgyHZAsshcg4+Q/6175
         lPINvOC/R3usyLibPiiKlnkLHI6pWSQrDx1TZCjFyK+e4FdiJSDiGQMTE5vufQX9OnPu
         iNADOc6PFM3yGdSRajgTrY9Tl9Y4tDqTAx8ou4YKSus0ru9DlbBCsuCNuiCOQJJfvr17
         aCnzY20j2kOS2brPEY87ozdOtMrNyB8YdLS+icEuAXQhUb7GneqM5ZN7+asdRRFrLKIN
         L/lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MERawGnphyfJQgvGqnyr2BQMOoqh4a5STQRa80KR+PI=;
        b=V5Bkf4A+HZAeopfQyEu3hH9bODea3JmE4WIQMo2ylSJyKSrbo4fkaaAnI5y44phFIM
         c37En6dCLRjQWGwW/1vdn9mK8fGzdaWDtYzlgrp1hvo/5VpMVIt2gpOb/GwDJ0p5gukA
         pdZHvEha5WSlgzxJZxnzi/MMbwKX6tlv7zBMFIxfxNaKAk0lA/MvpvOp4QdKdzCgEmj4
         J76Cdjv/o1ZFMc5jq0hRN7m9o1dBETWrYpl4QcVvAeoX6aB380nIMl+tOktWmdGjHNUe
         aluyvCeJQnhNr7OFMdyBEnO7JJY7D6Ky28Hmd/enpSKJwh0lJyIY0hbrjjkqZO0wa+j6
         v66g==
X-Gm-Message-State: AOAM533rVQxNng0U8LuS9sFuhe+yYjO3gx9/u+Cg9sl/eNlKDF2Zg3DZ
	7WXxkFdPtm7+xgwpjP3POMI=
X-Google-Smtp-Source: ABdhPJyyND0m5ku9W33rMmVjv2pgBcph1g2PJPhE6ZVKcfms82T69xi+aFbYCByQRv5u3clfCOBw5w==
X-Received: by 2002:a05:6602:1210:: with SMTP id y16mr7808598iot.201.1590070945699;
        Thu, 21 May 2020 07:22:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10ce:: with SMTP id s14ls659794ilj.6.gmail; Thu, 21
 May 2020 07:22:25 -0700 (PDT)
X-Received: by 2002:a05:6e02:52e:: with SMTP id h14mr9010848ils.177.1590070945408;
        Thu, 21 May 2020 07:22:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070945; cv=none;
        d=google.com; s=arc-20160816;
        b=JawAJ6baJI7aGQBPrQE/RFz2b+dmL0AhYMZ8JnQhf6/EPL2zjpw0227hlE15W4ma1i
         0FrxzQ7Ho7rNz8MAKtaoOd+qAad0Hc+SFktMaMYCQTfB4X3EQU2TQ1cAVD04AUSOuvpF
         tJY5fsvnnUIWgpBLz3bZiFQUG97RHEUwANFq/wepHqrl80DEv6uxHU8+XFymx/fIvn+D
         Gt/38rkVjXqbdm+06EfTWh1gjoU/B6iRcH0EUjFJG5Ni/1Cbk79stYXOp3uDfilVFLjH
         quL3ZDfKLivM95ZhN+S87pRr5aomQtBJjs7ZXJBKuTYKpyOOddcDTmbLdwOjOAbg4CEw
         zRqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=KOSbRYBxnt/X3aB2qnjtMZzC3fbLoIePjEhBC+KEIRw=;
        b=bds8TjeVr5yBNN2oG0N28gCL3igsdvMEUhg1jPwAc4tTCxKKnyqHSMo0VZGgkIzCA9
         Ck2x/b7zyHR2UwRl7Q5kRCvB6kZLS41qRMQHTZhJZyXDxFD6eYBkybveM9f58ODP9Q6Y
         4zlBLlkh1QEA46x3Ps0tQOArV7LRdO4hCJTMLdV616mg+l2dQGhX/GpKyks4NxdvkGSJ
         lqtKnXW9md9trQpy6H1a43T2dqSwdM1+3z0LN/ps6ieS3CXVrlJr0oZrHHAfORiTKWVf
         5WA43ltHFtAy/TFnXK91WvdaYmSQbpTTbIDm3bs+/m70bUY61B5RXy8CyQMSvhdoH36B
         fbUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jEt1Ln1f;
       spf=pass (google.com: domain of 3oi7gxgukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oI7GXgUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id s66si310152ild.2.2020.05.21.07.22.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oi7gxgukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id y8so5467525ybn.20
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:25 -0700 (PDT)
X-Received: by 2002:a25:b103:: with SMTP id g3mr15635243ybj.88.1590070944895;
 Thu, 21 May 2020 07:22:24 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:38 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-3-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 02/11] kcsan: Avoid inserting __tsan_func_entry/exit
 if possible
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jEt1Ln1f;       spf=pass
 (google.com: domain of 3oi7gxgukcdm3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3oI7GXgUKCdM3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

To avoid inserting  __tsan_func_{entry,exit}, add option if supported by
compiler. Currently only Clang can be told to not emit calls to these
functions. It is safe to not emit these, since KCSAN does not rely on
them.

Note that, if we disable __tsan_func_{entry,exit}(), we need to disable
tail-call optimization in sanitized compilation units, as otherwise we
may skip frames in the stack trace; in particular when the tail called
function is one of the KCSAN's runtime functions, and a report is
generated, might we miss the function where the actual access occurred.
Since __tsan_func_{entry,exit}() insertion effectively disabled
tail-call optimization, there should be no observable change. [This was
caught and confirmed with kcsan-test & UNWINDER_ORC.]

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 11 ++++++++++-
 1 file changed, 10 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index caf1111a28ae..20337a7ecf54 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -1,6 +1,15 @@
 # SPDX-License-Identifier: GPL-2.0
 ifdef CONFIG_KCSAN
 
-CFLAGS_KCSAN := -fsanitize=thread
+# GCC and Clang accept backend options differently. Do not wrap in cc-option,
+# because Clang accepts "--param" even if it is unused.
+ifdef CONFIG_CC_IS_CLANG
+cc-param = -mllvm -$(1)
+else
+cc-param = --param -$(1)
+endif
+
+CFLAGS_KCSAN := -fsanitize=thread \
+	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-3-elver%40google.com.
