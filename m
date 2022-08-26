Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTWEUOMAMGQE4MFVSCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id EBFEA5A2A92
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:10:06 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id x16-20020a1c7c10000000b003a5cefa5578sf616028wmc.7
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:10:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526606; cv=pass;
        d=google.com; s=arc-20160816;
        b=qBg1qKwMOwjyjt/5AmCvSvsaFotX75QV+YKPsEX6Scs2DsNBLdtKPuKI0iaJq/EZfz
         IKHRs3wUFyLX4BWUh6c/6ngiQcP71CHJkwZ6vU2OJWkvaHxzBHWDb0SnfbTM8xtyl/9N
         ydIm7NYNXhD6VDh4GAhGk/w3cG9PYo4pTxQKcYy3pr3XiHZ34QV0IvUrZZfr1g/YIUyI
         SALLianXYbXh+TnNZNjar2eR6vHVEU9LGs+Ae3CdNPAujpJnkTlUbmsIqpNsRnrIPqFv
         wxY2yN1b2E2C6FNsgDxTi+4Ys4XMmdyBQIJmLSx4PzRLGtfrS5rN569JtlQ7Z9b7oZ1X
         /Ywg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=J44h0pli8+HnD73a/wQpSs1aMsdd6olqedup69ONhKM=;
        b=YNN268TTrvlUoVp7LI5zvQkCAZh8UBYxau+BpLvA2hgpU2PPIct8TSGKX4d5b3Z2/q
         3otDT/3eD/qyhwqJ963ajaL4qnHxiJ2MA9nv/5gAZnOSwIf0xJgI0UMy8bQf4fl//7p5
         RlzWCaf5WCj716Ooz11KeA4AI1zJlTjeznuz/A2sqGgJ4nCTlCiaYH47JWBQgGhCmc06
         ev7KNJcnMD2PNPJOlZ+weN8OkoMjQ7duhXZwppT/mrck+b7rtDs19IBvybWYJ1AjaYx5
         9/mUneKwAtaplpI24PKU5+lZ4pTnI2JurMg4CaSRt3aILbtnAboLLJrUuvtA3Z+IlOSM
         tJNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dLOEePxQ;
       spf=pass (google.com: domain of 3teiiywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TeIIYwYKCVQ274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=J44h0pli8+HnD73a/wQpSs1aMsdd6olqedup69ONhKM=;
        b=f8cMp6gxz6gDwxz5ukxBOXVnI8sfv+dnroFmRqzF/NAQEn9akWQ8LYHX+Ebh0ALlhz
         /tC4P0gZj79cSkmdFC5N5SwYTGqu54Lw1N8//XzHM6UPlmIdjPfowFpkvCScMSZZ/WoK
         eVrVzP3VCUedbl9vPTR5LgT5yzZi4hdJ2P3S/TgwvVftm/gONPYIyDnxcu7XB1HWB3I2
         71Emk7ZA9KQccpFssnBgndyPJsWt2IGn82R+NssisCCCr9U4k/X1C30XRohazpVYIV3k
         UuAwL+GRrdooBTmh44xDaaiOU5PjxUb44wJqk/xU94/wU6z5pwhwRIqA0LqKbFPjgPtF
         N02g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=J44h0pli8+HnD73a/wQpSs1aMsdd6olqedup69ONhKM=;
        b=C5RJ7JveBTZkhQIJ3duL9YPOlAFF5YPRePB5laB8m0i3cRw69El6rsmD7VI6vDA2j3
         GKD3nxRHWxncX7nCiJFueUD6+0oXhN/Nf9z4xnCVUMiXsHnYthHBc+5tKRcB0xivyigZ
         xWeo9ntvXC7j11Zuct2iEWNIxwOIXyGLVjGHHoKwlOqmlXzpFUEwLSno7o0FuU2ccoKG
         iDcr75jZHgK0LYLbL/CRF/pvv2qJgXlbwRHvVe0XhljW098oKZPWEGfvTu60kOCJBfjA
         F5yzoq6IhLYZkyOmWIelZ4U4LM8SGsJ32NYWXoXDTMuTbmw0SnwMg6qT10aWc7eVL7O1
         PtYA==
X-Gm-Message-State: ACgBeo12cSJA/u31Q72WO5evqAAyJ8zwoYP/1GjZyLiuop+CQEFjrVO3
	18QADs6WvBZbRM9IReDJNaw=
X-Google-Smtp-Source: AA6agR4gb9To2BJa16Ta2NOpUf5d01BwJsbmwNskODLOwYmiXx+VitczAPKS/mn/JIUckHxC6H/EAg==
X-Received: by 2002:a5d:52cb:0:b0:21a:3cc5:f5f4 with SMTP id r11-20020a5d52cb000000b0021a3cc5f5f4mr55144wrv.367.1661526606714;
        Fri, 26 Aug 2022 08:10:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d234:0:b0:225:26dd:8b59 with SMTP id k20-20020adfd234000000b0022526dd8b59ls86801wrh.3.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:10:05 -0700 (PDT)
X-Received: by 2002:a5d:47aa:0:b0:225:371b:569d with SMTP id 10-20020a5d47aa000000b00225371b569dmr70145wrb.478.1661526605740;
        Fri, 26 Aug 2022 08:10:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526605; cv=none;
        d=google.com; s=arc-20160816;
        b=fbrII1xoQqo1acNCIf+IabXQOxlXJ19F7mKgxJS4xbLn0HqYz0RTmIJV177CCYgZnG
         xUmddYK8QMzI97GvjkWNcfhg96vsWpMC8A9uWncLQ6dmRkm4HN/iB8X4mGKDd1rVnUV0
         vArUf59l86XxkIi81nRHU1pE4wBrcu/tB9+JIVKrlKbIDAN86AddXjm5FRUIbpKLXkA5
         /DEESkoZG8Z6ikokcyM4Acy1h2oE/d7qrzghszhaZvN6GfgnCDS/pVFhjzSiIoToy5np
         F0rQLvXh9i9sFosvFx83j0fEdAyCYMk/kWxpU3uzTuCT9mUDgH8eBK7PFx6Bo01k0n9L
         U4kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BglHskuQEcyUyCGOJUH508pmeGJAtuUxUacPJvhZbyk=;
        b=tng4ZS42ebV3eNjyqcgeDhAfBSkx5MV2Q+k9DBeMhA3WfI7sVPGAV4JEI2vrG4MU3u
         554Efc6O8lkR9msZuk7rCK1CaMHOj3J7nBBu5Ofamo7LfJxjuYmRsPm5U34lCY4Qctme
         Z+1WAeUCz7KgJf6eFxfgBI6MNqb8y3xJvqZyRGtwGjxZcleto91CW0iN9a8wOd2cn6Y6
         iBQHmNst1pYsSMw/UK+kaDNl5z3vddrFNnRnLmsAWL1Tjd3qoCUptzjTy7B0sShMbxXx
         RkXA3+YBiBJR4UdKboW2PU2pUdLAdDqTzB6suyxvM9w/9Tq610oZ8cETaeIiPcy4aIbp
         jQSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dLOEePxQ;
       spf=pass (google.com: domain of 3teiiywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TeIIYwYKCVQ274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id i15-20020a05600c354f00b003a54f1563c9si150936wmq.0.2022.08.26.08.10.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:10:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3teiiywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v3-20020a1cac03000000b003a7012c430dso1455600wme.3
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:10:05 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a5d:58d6:0:b0:226:cf81:f68d with SMTP id
 o22-20020a5d58d6000000b00226cf81f68dmr60412wrf.131.1661526605261; Fri, 26 Aug
 2022 08:10:05 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:03 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-41-glider@google.com>
Subject: [PATCH v5 40/44] x86: kmsan: don't instrument stack walking functions
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
 header.i=@google.com header.s=20210112 header.b=dLOEePxQ;       spf=pass
 (google.com: domain of 3teiiywykcvq274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3TeIIYwYKCVQ274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
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

Upon function exit, KMSAN marks local variables as uninitialized.
Further function calls may result in the compiler creating the stack
frame where these local variables resided. This results in frame
pointers being marked as uninitialized data, which is normally correct,
because they are not stack-allocated.

However stack unwinding functions are supposed to read and dereference
the frame pointers, in which case KMSAN might be reporting uses of
uninitialized values.

To work around that, we mark update_stack_state(), unwind_next_frame()
and show_trace_log_lvl() with __no_kmsan_checks, preventing all KMSAN
reports inside those functions and making them return initialized
values.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I6550563768fbb08aa60b2a96803675dcba93d802
---
 arch/x86/kernel/dumpstack.c    |  6 ++++++
 arch/x86/kernel/unwind_frame.c | 11 +++++++++++
 2 files changed, 17 insertions(+)

diff --git a/arch/x86/kernel/dumpstack.c b/arch/x86/kernel/dumpstack.c
index afae4dd774951..476eb504084e4 100644
--- a/arch/x86/kernel/dumpstack.c
+++ b/arch/x86/kernel/dumpstack.c
@@ -177,6 +177,12 @@ static void show_regs_if_on_stack(struct stack_info *info, struct pt_regs *regs,
 	}
 }
 
+/*
+ * This function reads pointers from the stack and dereferences them. The
+ * pointers may not have their KMSAN shadow set up properly, which may result
+ * in false positive reports. Disable instrumentation to avoid those.
+ */
+__no_kmsan_checks
 static void show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
 			unsigned long *stack, const char *log_lvl)
 {
diff --git a/arch/x86/kernel/unwind_frame.c b/arch/x86/kernel/unwind_frame.c
index 8e1c50c86e5db..d8ba93778ae32 100644
--- a/arch/x86/kernel/unwind_frame.c
+++ b/arch/x86/kernel/unwind_frame.c
@@ -183,6 +183,16 @@ static struct pt_regs *decode_frame_pointer(unsigned long *bp)
 }
 #endif
 
+/*
+ * While walking the stack, KMSAN may stomp on stale locals from other
+ * functions that were marked as uninitialized upon function exit, and
+ * now hold the call frame information for the current function (e.g. the frame
+ * pointer). Because KMSAN does not specifically mark call frames as
+ * initialized, false positive reports are possible. To prevent such reports,
+ * we mark the functions scanning the stack (here and below) with
+ * __no_kmsan_checks.
+ */
+__no_kmsan_checks
 static bool update_stack_state(struct unwind_state *state,
 			       unsigned long *next_bp)
 {
@@ -250,6 +260,7 @@ static bool update_stack_state(struct unwind_state *state,
 	return true;
 }
 
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct pt_regs *regs;
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-41-glider%40google.com.
