Return-Path: <kasan-dev+bncBAABBUWI3SJAMGQE2TCXVQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E423C4FFF44
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 21:28:18 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id c12-20020a2ebf0c000000b0024af8f2794bsf627678ljr.12
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 12:28:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649878098; cv=pass;
        d=google.com; s=arc-20160816;
        b=GciHt3zKYFwHGosqFP3Ytkj3iVqc3lndl0ERBkHOQIbSX+W5VBVFQm9jMWaFE5YFHR
         P8uIvez12JKV4t5GbubkjTAB5dYhRsVGMn490nhyPKc/NUXltQI6hxweJGTebpBGrBu1
         hfaoPFhzY9TAwpiMY+PWNuwvWza9yJ4WlH9mC2LUajVLJGSM+tvPhgqTvjuuGIC8jzHB
         XVELOE4H6AdL2c8pK8Ut8QVf0uDiom93N9okzJhw8orHqtQ8sw9ANivkrZyfaFsgbZA3
         LQzoztC9Q78Ew5WO7uZ0x1O3sID/kqaw9h4eQ0jGuS/jWS9I/2cu3NOj3D23KIs4Xujo
         CR2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rCrUNBosW7kYEuBftI4DGAAIZz+pccjhxgPzBJLoXXU=;
        b=XqQ+badMvrga71mEQAN2UYeGB5lSqngfkLvEh5HmUCbGYTrwIPMY4DNqCGQPOl2lb/
         Rjs2wMjEt5tEuNK9PnTwHJtGWt+pvYSC384coTM0/ZcZT9PJKlVRex05uqQlvlQVbdlu
         zcg752H1D/cE8yM/cP8h23wXS6Ei3AMS9aIgwvx2Tv9toGztX1Z5/E02IADQ6Cihbqun
         kp/utpK4/P6e2kn/MdZRLkRuuN42UhCIPf9WhXWdYfIf4At9WSG0/jqbQqcX1DqJ9ndB
         HOJgrC6/bouoVuBh9fK2XcdNUb33WC0/84lDTl0c3UrskNQmx9fIFSIu6kq29zwrZdFE
         /tZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gnwkJMKP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rCrUNBosW7kYEuBftI4DGAAIZz+pccjhxgPzBJLoXXU=;
        b=gAmHu3RqGrlJprdQ8cfv4QWSsgo8F+CpAVQJd4/pYRpmQA+3UIToocovJW9/L0B1GG
         6QUO11HujVjVyZ/6It+tLwba6EQAg4R2sGywk/DpbNj6SvKTmNoF/An/0jqSNtc/fgfX
         HsW5VECbi/dAiCEvDpN+IVupwwrwhmMwqcJT4rqs6n9pjJpOH3dDfocR+NNoS9evwlHi
         REKPHqNLaeBlZmpLAiYobo1FxsVStzET3HOoNPKAjZ5+nSdL02qo8YcoVDhuMJXM/Xg/
         KwcBN6QhdSD+BG79tORRnAqYto51jCeFZMMtC+PJCS/9emC5cgKKRMaOSh+WCrAL4VmJ
         wjWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rCrUNBosW7kYEuBftI4DGAAIZz+pccjhxgPzBJLoXXU=;
        b=K16SS6gotAET9Ube9+QKodcpMBAkcw5KB9EowScWNN2y2NJbiTLlFaN+3Pij454MEY
         imqIDEVAwNTktrjkTye3F9R8lgIBimDS8SeepmLBymdTxEwokkY23KdRdregoREEun+L
         mV/q4CUYbem4Ck2oPCSxfpyRio9I8tL/FRUoUQRBIuu6S2+7ntSYLtT9a75Yqb94j0dO
         Va3o90Mb3Q+c2X+W6kq6F9DwhW6AHZUK70mIAR91WwqxeIa+IDxAaPMk+jsJVIL8RGNs
         P6oCDEj2jRKtDuEZyhawhqzFjiklCgB4TReXHu9ztZ37X1wc5yea8qT9a2068pYOOAzM
         qcPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531czhfUhbhZT22BTj/hlSTChRnscVIKW/W9ttYUySuHR/5nz8G6
	846AFOgPZQg+OCI+wpxX3fg=
X-Google-Smtp-Source: ABdhPJxD4eOL6/yY320x1YaidCJO9lIeKf3PW/o7IA6OWU3e0F4HaGrkH7MwlR9uAeRO5oYlZjMMfg==
X-Received: by 2002:a05:6512:683:b0:46b:8e8d:9c44 with SMTP id t3-20020a056512068300b0046b8e8d9c44mr16910092lfe.519.1649878098286;
        Wed, 13 Apr 2022 12:28:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a14:0:b0:24b:627c:97d6 with SMTP id h20-20020a2e3a14000000b0024b627c97d6ls581873lja.5.gmail;
 Wed, 13 Apr 2022 12:28:17 -0700 (PDT)
X-Received: by 2002:a2e:b742:0:b0:24b:6370:1e00 with SMTP id k2-20020a2eb742000000b0024b63701e00mr10008078ljo.71.1649878097405;
        Wed, 13 Apr 2022 12:28:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649878097; cv=none;
        d=google.com; s=arc-20160816;
        b=HN842w2khzIQJzsmfHz0uIjRHK5yD6X4XQDPiIHtcaR0kwczpvmPnBWwdNOZ4YzgkG
         60KnIUKB+AuzRe8RMto4sLwGA/g49BiATBtzyxrnCJRhWG/EgHTp3W83WxRdxvsqJ2gd
         8X/dpU17TNc1wz0JklEL9/GV/8MhNJammdddIzUDR7D4BUt2euCR9s/xkXH+X+vJmx48
         yF5QVDyeu2VIQo1UMZV68Zuk82Mx0F37FFsf6up19PTDP1RQnggKAT8gyeXZK+s0kBlq
         gyY6howEYg0gLJnCuekngxRgKxqxDwqTYiHX3QHGr58qKpt6QBRvQkSrPtqKBNpbvEJC
         KH3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1W/iPGxZZe0dTxtRIT/L4inWkaCNOxDFyHeQ0vhNfa0=;
        b=06c0BZkuTfNSUWYxoSbwNjRJNt6gIDFreO+FifhpDl1//dTLqFpN7WBsx6qx6SzAo4
         GGjgjKxcNatObnpgMHowjaL/P6xxMO53s+bfsQmEGzr2kT8fgbyeBDAUHf9tkf/94oqa
         uQdVX5sfvPS/BC1pj39jtsQ9Ju0FVwVnPWz/jAZeGXJRzy6GpShdqIDXSR2PWB9HLhur
         er2m4nmPsSrP8vcNC3wf38Nc1bALpo+VKqMPeLvL5B0ltU/LPR9eyunNEvlLXEdDB+U0
         +63sNithRWoLp7+NFgiuUVx+QAkxeL8/hc8TupwFJftq3Iq4tvauBPvkqZzMiK08tSz3
         F/kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gnwkJMKP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id l28-20020a056512333c00b0046bbea539dasi265407lfe.10.2022.04.13.12.28.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 13 Apr 2022 12:28:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 2/3] kasan, arm64: implement stack_trace_save_shadow
Date: Wed, 13 Apr 2022 21:26:45 +0200
Message-Id: <78cd352296ceb14da1d0136ff7d0a6818e594ab7.1649877511.git.andreyknvl@google.com>
In-Reply-To: <cover.1649877511.git.andreyknvl@google.com>
References: <cover.1649877511.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=gnwkJMKP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Implement stack_trace_save_shadow() that collects stack traces based on
the Shadow Call Stack (SCS) for arm64 by copiing the frames from SCS.

The implementation is best-effort and thus has limitations.

stack_trace_save_shadow() fully handles task and softirq contexts, which
are both processed on the per-task SCS.

For hardirqs, the support is limited: stack_trace_save_shadow() does not
collect the task part of the stack trace. For KASAN, this is not a problem,
as stack depot only saves the interrupt part of the stack anyway.

Otherwise, stack_trace_save_shadow() also takes a best-effort approach
with a focus on performance. Thus, it:

- Does not try to collect stack traces from other exceptions like SDEI.
- Does not try to recover frames modified by KRETPROBES or by FTRACE.

However, stack_trace_save_shadow() does strip PTR_AUTH tags to avoid
leaking them in stack traces.

The -ENOSYS return value is deliberatly used to match
stack_trace_save_tsk_reliable().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 62 +++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 62 insertions(+)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d9079ec11f31..23b30fa6e270 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -30,6 +30,68 @@
 #include "kasan.h"
 #include "../slab.h"
 
+#ifdef CONFIG_SHADOW_CALL_STACK
+#include <linux/scs.h>
+#include <asm/scs.h>
+
+/*
+ * Collect the stack trace from the Shadow Call Stack in a best-effort manner:
+ *
+ * - Do not collect the task part of the stack trace when in a hardirq.
+ * - Do not collect stack traces from other exception levels like SDEI.
+ * - Do not recover frames modified by KRETPROBES or by FTRACE.
+ *
+ * Note that marking the function with __noscs leads to unnacceptable
+ * performance impact, as helper functions stop being inlined.
+ */
+static inline int stack_trace_save_shadow(unsigned long *store,
+					  unsigned int size)
+{
+	unsigned long *scs_top, *scs_base, *frame;
+	unsigned int len = 0;
+
+	/* Get the SCS base. */
+	if (in_task() || in_serving_softirq()) {
+		/* Softirqs reuse the task SCS area. */
+		scs_base = task_scs(current);
+	} else if (in_hardirq()) {
+		/* Hardirqs use a per-CPU SCS area. */
+		scs_base = *this_cpu_ptr(&irq_shadow_call_stack_ptr);
+	} else {
+		/* Ignore other exception levels. */
+		return 0;
+	}
+
+	/*
+	 * Get the SCS pointer.
+	 *
+	 * Note that this assembly might be placed before the function's
+	 * prologue. In this case, the last stack frame will be lost. This is
+	 * acceptable: the lost frame will correspond to an internal KASAN
+	 * function, which is not relevant to identify the external call site.
+	 */
+	asm volatile("mov %0, x18" : "=&r" (scs_top));
+
+	/* The top SCS slot is empty. */
+	scs_top -= 1;
+
+	for (frame = scs_top; frame >= scs_base; frame--) {
+		if (len >= size)
+			break;
+		/* Do not leak PTR_AUTH tags in stack traces. */
+		store[len++] = ptrauth_strip_insn_pac(*frame);
+	}
+
+	return len;
+}
+#else /* CONFIG_SHADOW_CALL_STACK */
+static inline int stack_trace_save_shadow(unsigned long *store,
+					  unsigned int size)
+{
+	return -ENOSYS;
+}
+#endif /* CONFIG_SHADOW_CALL_STACK */
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78cd352296ceb14da1d0136ff7d0a6818e594ab7.1649877511.git.andreyknvl%40google.com.
