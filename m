Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSWDUCJQMGQEWLOEGAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 890B751040C
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:03 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id m5-20020a2e8705000000b0024f0fca4516sf1801988lji.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991563; cv=pass;
        d=google.com; s=arc-20160816;
        b=mGZBVMdURRYHklkgE9DW7/hQJJ9PwRq0fCG1VYx67z+1wDAZQhYjRy22mEDyN8dLtI
         bj1+G/+HZkHCHU5tBKipFdfVhuGWtk38h/hvFFYoONFqVcoRKAxSD7j4JQalcvTor/Qy
         2q0dJRJKJqOE3PgEhhOMOjWK1JEy3ew4ZQKBvQi1jaohlGiPbOAz/FS7mUGkTi3lozJD
         Yf1YUjAAELjKtr29yMz4BjUIWwfO0uK9abHjsHz3tTBxODlOp7QDOZ1iyIQuCU1+b9+k
         QB7592Ba68N+TwQG0JivPriTmGGPZL01TgPtDfhnPTvNFDTtbqPt6CayN2MZcYBij38h
         ASJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZeMPPCCioSuOUUMLAhL/5+IqkFf2FMYrQ4YOV/0NdGs=;
        b=QDj36zcY1xgs8mK/l446tM25Q6OMQe6psnJPtnsgEPhN8NlIX4kntrXGsOb6icaN9L
         Qgm++IduUJcCEYATQBDPe51ZAiOQTw80LWZrx/v/W0t0csF2sEshVzCEJcbjO12DmNfz
         BJPlXYc8l2zJT85YMlGB7G2nwbRTWjS8YxjmS5sWAK9ePAatVvR/Xf20vPU+UCjG+eWr
         x30OINIuPtP8wMHNTy9jn6el/N6fSLb8Jp6PrWW5KewxXfIlO9hJXJDXL2xv0Wanvfmv
         4VkZCC6C/CxpfKCIQgwZTSNtlpLHFtnuSi4mpUkQi65Sl5DduzNO8UiR83Wvepq+Dt7G
         Uc0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JMsNnrgA;
       spf=pass (google.com: domain of 3ysfoygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ySFoYgYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZeMPPCCioSuOUUMLAhL/5+IqkFf2FMYrQ4YOV/0NdGs=;
        b=W3wuSOZkI+ojL2bmgbqvoK/gHaQd4cOrkEuR1B5Knj1QHmA8h2plcVtITfxTg7LATp
         orqTArUNC3CDF8SOEQOe1vI7i0MaTVu6UtR/6qdyMFqDswznzujg2Xw5PmaG3qRBUGbl
         HMQdoVGNIrPPuKMdKUn85nSCjB0BZnqT2SDTntSJkvIvh56YiucQ9HiB8ocHnbp6Doqu
         rwqdV9TJPCboFLHKDnBhzYTvlGGAPgrxJSvShkwQdEiJrBGhus85FpXBLBvAL1YVVx7n
         kjaG1pd7a2eK9S5C+aAeAg/1YlM0HtMKsXJM8hfaaJFlgIskx5SNa5JmG5Bt+3UYryLX
         J22A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZeMPPCCioSuOUUMLAhL/5+IqkFf2FMYrQ4YOV/0NdGs=;
        b=4KhHbcHIYebwYoTx6+N8bR+YuKjktQM2Nfd3B4qrfgEwfE6B61zyWHbtnW3C/wcSO1
         lj0faJeIKJ/hPUaGPjsNxUtK3OFdKVchBCbVDwHjsfb4PvOjjhQF5jlpKSCTPoZWRZTf
         pS2D7MZkeds2nWZYhOIqOI8QtvnQ7hkOlcHAfy6Cx4Wxpxli9rG29IR7g0DymrdqR55/
         fs2Kd+JD0roflxvFOVALAggk9f+BXXtvTktJM7dk+1MtyrUkqea9zf51NoxaF7ExMmnt
         lqzwxuCSajqgAVjtqVFYnopk5gn3a5TS6R50RLKE9/ntumzSR5CTVihyZ5N1RH+jHei3
         q+MA==
X-Gm-Message-State: AOAM5335scMeNy6fpiXk1gbwPF5KlFhUCHKDSQReeDPJoB7I09cY+GSu
	vgOtxuETIksv3pWUosW1te4=
X-Google-Smtp-Source: ABdhPJyA4V5NC3PRd5SQakH967TXtbUCVosDtkzFdiaM23wQEy6l6cdzTvp3c8F2XopLGuPPPmd0eQ==
X-Received: by 2002:ac2:48a4:0:b0:471:fc7f:b54d with SMTP id u4-20020ac248a4000000b00471fc7fb54dmr11459516lfg.538.1650991563137;
        Tue, 26 Apr 2022 09:46:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2815:b0:471:b373:9bb9 with SMTP id
 cf21-20020a056512281500b00471b3739bb9ls2093277lfb.3.gmail; Tue, 26 Apr 2022
 09:46:02 -0700 (PDT)
X-Received: by 2002:ac2:5d6d:0:b0:46d:f50:7c7 with SMTP id h13-20020ac25d6d000000b0046d0f5007c7mr17317707lft.340.1650991562174;
        Tue, 26 Apr 2022 09:46:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991562; cv=none;
        d=google.com; s=arc-20160816;
        b=ldPD2tr3oIPkn77GaMApgFj35MMRCBraCKQh/8PBXZFjh9EokLZ2lwX6C5AJoQw07V
         pc0LICInufhhVxCAHmQx+liZK+gbnTIMzJl4zm00pnw1Qam8rBcBG5yJTnJm0Yn7QB0h
         mIiGhUZhEZBo7r0kZCnjpoSLxQzpZKGWc9Jhafqp0bVCytjrAdofDvDXI2OON/f1XKCv
         zKmDYjXNLXitVKHVDMcXZFpTYDIUWjc1959YFi6t9/mx+kkQKXB/+LIXf8u0BYWRgh5V
         5Zc7yDmbhC8eqFrklqNvOUr1njNnzqqlQ8d734HeweVFvB2Hz72Y2Ta4h7CU/AwzL0+Q
         pnkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=XLE4dDKZQivTtEUon/Tj4SL+cxx+nqfawlbFCYGovJc=;
        b=uQGmDcUtjkXBrr0hv2RLlfnbviB6XKBdWZkBhXY5BPQ5+70AM2aYftaq+mH1vfZGpX
         v5COntM9Mi+gWOvNK8O3TChAlsdYUX2B8TgUTuN81vj0y2FUAzD3nzKRWVK6081gh9YN
         P1/mEA1+blylF3sf86XgQQeWRCNnwuG6GDK6UPbtQfVUgd6pKv4fW2qPejryHTUwDjJS
         6xxQHYYAFGVbdYsG5lUv1MAOi+Vps0TY0DHSHpG/7AtdPs5Z2sPaKlZMWv0OjgfgzAYq
         t/L21yzVBOCits44Qh9Cc0+6IUcMc5Nns6Vx1tHDN/GHU33hjCfPvdbk1P+a2zIiekp+
         bfew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JMsNnrgA;
       spf=pass (google.com: domain of 3ysfoygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ySFoYgYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id e11-20020ac24e0b000000b0047193d0273asi781530lfr.8.2022.04.26.09.46.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ysfoygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id l24-20020a056402231800b00410f19a3103so10612831eda.5
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:02 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a17:907:3e21:b0:6f3:bd59:1aa0 with SMTP id
 hp33-20020a1709073e2100b006f3bd591aa0mr1461947ejc.682.1650991561485; Tue, 26
 Apr 2022 09:46:01 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:08 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-40-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 39/46] x86: kmsan: skip shadow checks in __switch_to()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=JMsNnrgA;       spf=pass
 (google.com: domain of 3ysfoygykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ySFoYgYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
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

When instrumenting functions, KMSAN obtains the per-task state (mostly
pointers to metadata for function arguments and return values) once per
function at its beginning, using the `current` pointer.

Every time the instrumented function calls another function, this state
(`struct kmsan_context_state`) is updated with shadow/origin data of the
passed and returned values.

When `current` changes in the low-level arch code, instrumented code can
not notice that, and will still refer to the old state, possibly corrupting
it or using stale data. This may result in false positive reports.

To deal with that, we need to apply __no_kmsan_checks to the functions
performing context switching - this will result in skipping all KMSAN
shadow checks and marking newly created values as initialized,
preventing all false positive reports in those functions. False negatives
are still possible, but we expect them to be rare and impersistent.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>

---
v2:
 -- This patch was previously called "kmsan: skip shadow checks in files
    doing context switches". Per Mark Rutland's suggestion, we now only
    skip checks in low-level arch-specific code, as context switches in
    common code should be invisible to KMSAN. We also apply the checks
    to precisely the functions performing the context switch instead of
    the whole file.

Link: https://linux-review.googlesource.com/id/I45e3ed9c5f66ee79b0409d1673d66ae419029bcb

Replace KMSAN_ENABLE_CHECKS_process_64.o with __no_kmsan_checks
---
 arch/x86/kernel/process_64.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/kernel/process_64.c b/arch/x86/kernel/process_64.c
index e459253649be2..9952a4c7e1d20 100644
--- a/arch/x86/kernel/process_64.c
+++ b/arch/x86/kernel/process_64.c
@@ -553,6 +553,7 @@ void compat_start_thread(struct pt_regs *regs, u32 new_ip, u32 new_sp, bool x32)
  * Kprobes not supported here. Set the probe on schedule instead.
  * Function graph tracer not supported too.
  */
+__no_kmsan_checks
 __visible __notrace_funcgraph struct task_struct *
 __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
 {
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-40-glider%40google.com.
