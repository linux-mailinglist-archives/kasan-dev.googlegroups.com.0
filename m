Return-Path: <kasan-dev+bncBCCMH5WKTMGRBREH7SKQMGQEIBOVS6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 94058563542
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:09 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id r132-20020a1c448a000000b003a02a3f0beesf3117199wma.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685509; cv=pass;
        d=google.com; s=arc-20160816;
        b=yf3VOxDqH7dYXEyxCZQHliGHFa9FUFk1mqXTpHLH7nUqXiFlLyLhYSfADscq/crznm
         A49LQH8fWJd06AVJ3pO9Gy/aCN9cckG2r4vEidkr6hB1YZw6tp82CU4FWED/+3M3f6Ec
         oSX1vb2FJBOIjjfFzZvTtmc/L2c6iKS6shAqqwD1KvMK/FLD4zqZeMUWKqPWLWVeYGNZ
         nkMI/DoBooGaCsqunVe9pIJXofntMDFfmT5PfJqjtc+oi1b0VKHbXp+mEdeHTcjrHW7Q
         /+VxDzNxGkNq4oOJJBeIxUrWvlpAQzx642GuQAy+GCaCiruxUilRvwAkiPwOrMZbgVol
         M7kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+UIFSwoFrV5EOvaHRoX20Z3markJcbOIuzYk41qGr4I=;
        b=YWmIlkfocEjFm7h3ofefekgNKQ4C9WVkOTkK4mvPTQj9dACVEog+kuSK2Tpo0WmuiZ
         ChHIk4dtGNIVH2TGALH5Mkgq4oAVJzRxhB/4ASUHU+qDBn0A1iDMuakeRm34fHuKb77k
         2+Vc0zu8rgaa+ip+bcpgYnht1FmomDgoehuToUcIy0uWI7b9LNPtCaUoIks1swpEBwk+
         fPyfUOQtD97N9klVIcG5d/Q8kLydyr9mNb2/o1Ce9S6NLE2IQLACNmBg6k2GYhkeSXHV
         hzY6eiHl50kipDvwjiyL6xPt1LUhC5TVxXbk/foPRjQ7dEeCjnLxDpXysaw3L0glJyRA
         y/5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=m0zQVBcw;
       spf=pass (google.com: domain of 3wwo_ygykceikpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wwO_YgYKCeIKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+UIFSwoFrV5EOvaHRoX20Z3markJcbOIuzYk41qGr4I=;
        b=NmZmTMwwQYMr1y0USfLgV1hTCnZR9m0Kc8PXP3eqeTcd7RSWJQLGFpt2sWmmvojuqf
         ihYtTLYyAoYYrGXVzUvfvZBX0DAAimFSHzdtkw10sWQ0uET17KgbyHfIKXYIdxyAr8OI
         tmosF2nQbZyR2ZWYoGx2qQxlLla//iz1bhJj3ANt+De70+qKG3Ps0Yv0C9Lu/4C56DjK
         WW1vvDedSjh29GM2r7wgX6AzlwBt/fQjrNuP0DENSv/wwDWEm242QZUValuY5zOwTqQa
         PpYcsbX08Q1tqNHIx0bV9/NCkUPZ6iSlTdPmSocEIT3i2vgJoK3TTEJuHatWjsMvmHmA
         t9XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+UIFSwoFrV5EOvaHRoX20Z3markJcbOIuzYk41qGr4I=;
        b=SLYjdR9ojdYkmFptaQByvfRyYP9sIxy8T4ESrHuGfUlaamtxkL9M5nr3vjyZO1TcgW
         qKracoNN1bSs2TW7NBq4bzuFfLqcXAJefGcurCV/3ElVkwJGm+BfWoATnUiA8BxirRRp
         wMWLZX3uHZyvuhqwsSDQSDw6SpKPZ2QsFRsZDcZf6AFUS9j8+X5nsNYDnXh6SfaQFv1T
         AApZRzCLIwzHnzgZMxLLEyMRCN9RN5+Mga5kCuLBVZOU7jSKaaXB925L4JqKkcQ1LDAl
         97XHBCVjSzXNXtPoz2L1LbbPvPB/tTvdERzLbDSX/3edfFXJxAiubIPan2fWYPF92aMu
         3Fpg==
X-Gm-Message-State: AJIora+pGBJ7cxEopa5a5/L+a2XCCyOGPa4/h2CuQWekXrb/9l5cjAIO
	ifGEzU8S5IwGHbrdhwFVzI4=
X-Google-Smtp-Source: AGRyM1vFGDgjYFae2Jo9VkyYtnZHxK6S/1iKolCRKhGKqAfWMlhLdSiUiPKyRd5F2W0ZB1IP65CCFA==
X-Received: by 2002:a5d:6d8f:0:b0:21b:dbb5:fe0e with SMTP id l15-20020a5d6d8f000000b0021bdbb5fe0emr13745266wrs.500.1656685509226;
        Fri, 01 Jul 2022 07:25:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e19:b0:3a0:5669:1a91 with SMTP id
 ay25-20020a05600c1e1900b003a056691a91ls3473480wmb.3.canary-gmail; Fri, 01 Jul
 2022 07:25:08 -0700 (PDT)
X-Received: by 2002:a1c:25c6:0:b0:3a0:3367:1b30 with SMTP id l189-20020a1c25c6000000b003a033671b30mr18724689wml.74.1656685508181;
        Fri, 01 Jul 2022 07:25:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685508; cv=none;
        d=google.com; s=arc-20160816;
        b=tuF1AnaxTc0s0wi2cu4NeyTDwoYmXk0ZFUUWVubxUE7vU2fKZ+Qu7aBuSJVdpNPnb+
         3SkRBozpPl8YUM21qRzNIIMtlkB64igxDql1yLb3KMJY/1kQgKZfI58UwJBkFFQR/X+f
         bU+QAx+QPPeH6VjdHdYrb2jO95lwQ3ojze1S1oSB2/ZmUzArXlQcgzzhFYz5YVPXOIPP
         QUhvfvDqVviLHGh91DArhEYZXkWPzXRpeZDqP87wVtRHdQcZEbli47GY4zUcQA84CdHN
         7y2jkV0X9MTXwTxQ/lfRolPVdAc5/t0pmk5MFn4Kh8L+RJExPhrPVD07WNWfJkaQkFpp
         wBgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=l9HW4hvq2CQJApDpi6peUok9IhcNK11lvxcg04+BYhI=;
        b=jwFh9akm5eKcewp3TSzusJpY9eDVAet9mcdfvCz/eH+Uu6ptoaMg4Zxdx1RAKK3rsi
         MlPiSHbSfKgsE0u+NxEZ9CfXzaiQGFnwWm9eRlCaMrsd5sHKD7Mk6RNFnv5v0G2PgI7k
         x6axYTbg+R41laLl2Oi+zNecf6PsoZHTNooCDwJUdkARfL6j0nlpyqorL1W2/HzcCtYo
         uBsnKb1Mla6nNtN+wQDE/Fs0K6fvnjlySB9m8lsHEFgF9OzKSFon0mUixjdMb0RreniS
         77ZqSyLJTsHy5OhMKRa8JJ9WRFaS+ewvYGObQAIbyIODTkq01Alr7d9BRjooLeJIEUnG
         gWJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=m0zQVBcw;
       spf=pass (google.com: domain of 3wwo_ygykceikpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wwO_YgYKCeIKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 68-20020a1c1947000000b003a050f3073asi202250wmz.4.2022.07.01.07.25.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wwo_ygykceikpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id e5-20020adff345000000b0021b9f00e882so414783wrp.6
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:08 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6000:10c4:b0:21b:8ea4:a27a with SMTP id
 b4-20020a05600010c400b0021b8ea4a27amr14086444wrx.575.1656685507805; Fri, 01
 Jul 2022 07:25:07 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:05 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-41-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 40/45] x86: kmsan: don't instrument stack walking functions
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
 header.i=@google.com header.s=20210112 header.b=m0zQVBcw;       spf=pass
 (google.com: domain of 3wwo_ygykceikpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3wwO_YgYKCeIKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
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
Link: https://linux-review.googlesource.com/id/I7001eaed630277e8d2ddaff1d6f223d54e997a6f
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-41-glider%40google.com.
