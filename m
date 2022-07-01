Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSMH7SKQMGQEWB2ZMWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 3375A563547
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:14 +0200 (CEST)
Received: by mail-ed1-x537.google.com with SMTP id h16-20020a05640250d000b00435bab1a7b4sf1894814edb.10
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685514; cv=pass;
        d=google.com; s=arc-20160816;
        b=NlJmWMVW+U6iMpiz2Tb6hAHXKgPxmj8cZ5NyIVz/TENeGKQH5MLWNp6NLPhRlVmJmJ
         i4UoFB09B9qhUW5m5vCuxdLTdQx5fx8gO23ZHPO7UB4UOUOqWpnHgczVd9TcSAI1WA8u
         euX3myYiEYL4+LeD5MaXTsOE2YxrhF6oRspQoH6P09VEhv+jFaLctRyp7QE9cROS8Goa
         ml/uAhMTPqgC+8RtIQXINcKbu8eYPH1Pl3eCDTrtnXlMRUPorJVBKpzSzUsL6MjGYrQe
         JnLgH11Cc7sKtjIXMTli7t6T50l5F5Z0Yk01wK8yQw3uc8oJxLaWG+4Z0wknLUym32SP
         gnhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=L3YRWmNl+74FMHpy/+VOhCpR4J260hhtYMz6EWlPAd4=;
        b=S2ZUXOYmDl0gEQFKno4CTmBMIKB6uWEt7YQO7KNfOQrToAgsi76VX6J1ozmVcvCIqb
         pdfZ9pPV9mbewlRoQBbEKTXnTmMbgnO3sZ+9J8brY0BI6qftXoAB+zDy97TaG/QBphOz
         JdbvSg5xlcHA2p+nXCBRSuexJhZS1iXxA7BTFkvRjwwP9jwYLFXsJs4RoHddXpCyZJPf
         lE6q659wYe97myv71vF2NR8ET/ONw9TrOfOhpDDeTcQ8s4VK3P1fnYFYl+4/WqPfYwvs
         019+jXGzkD5P5T4pRfbovbs8ctksNqcRndO082Q2Z8TBd0moM+xpKfeauQD5TuipQ6PT
         2L9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tgfjQq+i;
       spf=pass (google.com: domain of 3yao_ygykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3yAO_YgYKCecPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L3YRWmNl+74FMHpy/+VOhCpR4J260hhtYMz6EWlPAd4=;
        b=P3HED1YR/HgBKo44BOVRiYCES8RVtCy1bqFocyvRH02o7abpGFaC3XsSVNg2+a5M6w
         yY4hFU442nqzvgc5Qykli4nRX9dGEYzw7WDVVG6uaGYPCaWNttnI9JzbbnZIi7iNKKz3
         L5KZco4j7/EfFqjVbFyyNNw3/mohXAzbbkN4z5Uo0EUpMn1Ixc49bekwYmLsFYvCyhCk
         g0IWTzGLXliDdYwVkbku0CbPDWBfT5Q2QC8u+ygVrrnprrJe7wEk/5RGHaRuQkusFFdO
         25LrkdoW0YKJmcaQMjEyW8S7iZTFP8VzxT7tskTsi+Y1xzw2lILr5a9yTh4S/yF1kFLi
         PJwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L3YRWmNl+74FMHpy/+VOhCpR4J260hhtYMz6EWlPAd4=;
        b=P7J0Oy7/j5l7nBPhYb/RbLsQM3kzD7E+dV3gMUb85p3h7LBMHn/IFCc8LDC3jMeOXr
         LGXxc+CbA3Jej7hpEnYcSAbF6Xxg55nUvNJhPfcmSMDV+J+u+DCiW+Y5NS9kpbmzXSfS
         9wgb5Lzpu3T3LlSTR+svesshMIAfwr5dUyA2HnCJ4VRAacEoi5ayC46DPU+SpgP8BG5R
         jCU1XLgKA0yus8wOMd+bQRKhdaDRdo+2tnuGMW1faQtbkiVSGStR9z67q3Ukqs96CQBQ
         xdOVMsetWOw9p7cw8rD5XY5WCzT+Nb7R3NX9gsbCT47p78xVnV1o9rX5IfLLLuctMY4U
         6SoQ==
X-Gm-Message-State: AJIora/3No0lcFJ1jOXEhifX35Kk9bal8QDUxC2f09Vam8xqN7jQ54vG
	lUKnslBVnkuiWDZmqvR1Hx0=
X-Google-Smtp-Source: AGRyM1uPpssZk7p93TbPLOEMmnYr7so7XqDJQ7v1d/mKFAMwDisaNN+x/YwntqV7Q/bdq0z0OP5n2w==
X-Received: by 2002:a05:6402:1e88:b0:435:bf05:f0f with SMTP id f8-20020a0564021e8800b00435bf050f0fmr19380214edf.2.1656685514020;
        Fri, 01 Jul 2022 07:25:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c9:b0:435:95a1:8b64 with SMTP id
 x9-20020a05640226c900b0043595a18b64ls372810edd.2.gmail; Fri, 01 Jul 2022
 07:25:13 -0700 (PDT)
X-Received: by 2002:a05:6402:240a:b0:437:d2b6:3dde with SMTP id t10-20020a056402240a00b00437d2b63ddemr19386409eda.62.1656685513210;
        Fri, 01 Jul 2022 07:25:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685513; cv=none;
        d=google.com; s=arc-20160816;
        b=mIq2CYLQpdn6DlPvKkeR6YPhUyxDnHJW0dSZsta44iJkpDdn289SqaYYNHW3MGMw68
         HX+5VR9Z4A2CTv46xblkqY4Hy03s+3qM5r9mDHCLa0H/7c9zBt6QfRuW2W/k2UWfarzQ
         QimfyQE+mOq1i9lJOHx351jKfm6/smJclKz3NGWM+5NXCB+tz3BVxaaQwT2xfoTBOATS
         NHtohoU1IH1lKdu/wzEiGWZM4QLD2o1sEuJds+yVbhRB1NnyKS26/IHgYQVNXXGXfgWY
         wUkije4mGMA/sYX8rgHSqzqgmHQX7WOwxFMspsngU3gmIkphaRXdhHmssuPpSpMZgOJe
         SdYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=NuZxaTt6SuBtelFew5LXxi86pENufXvsmy2qQXyoE6c=;
        b=ihKckqLy68l/sCN5MHxcGzzoLsC5CCcjii9bNiR4cNmaskEHB61RInPYhC6+iy+rUj
         OGul6SmtMmi4Xh+GeSN4Ac2M62NhhiHyOUEeF6LNYuDoZ/WAhW3OQbJ/fsE4yLGWlDnR
         UKW4/6IzWAJbcqd4tO3j76jwjLMHMr/zX3fWs6DoY2m1jbSkxgCmcsInZFoiMHO45vwZ
         nXXjDzx3F2MYsDdq+nqloo/VxFZzJP/UwPPD8ixkLW3uDgxrPvhw7hNfUNvDDn+4ajPQ
         Jfq49/YUMGIzFWetmkE7qa3hi/WHhsc0JzRuFdzIaIn0QFUc3Fe2KK7aXkfCfxcOh9XX
         fXYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tgfjQq+i;
       spf=pass (google.com: domain of 3yao_ygykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3yAO_YgYKCecPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id i24-20020a0564020f1800b004319ce84356si915098eda.4.2022.07.01.07.25.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yao_ygykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id z13-20020a056402274d00b004357fcdd51fso1871651edd.17
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:13 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:907:2704:b0:72a:596f:8b9f with SMTP id
 w4-20020a170907270400b0072a596f8b9fmr9611410ejk.761.1656685512839; Fri, 01
 Jul 2022 07:25:12 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:07 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-43-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 42/45] bpf: kmsan: initialize BPF registers with zeroes
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
 header.i=@google.com header.s=20210112 header.b=tgfjQq+i;       spf=pass
 (google.com: domain of 3yao_ygykcecpurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3yAO_YgYKCecPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
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

When executing BPF programs, certain registers may get passed
uninitialized to helper functions. E.g. when performing a JMP_CALL,
registers BPF_R1-BPF_R5 are always passed to the helper, no matter how
many of them are actually used.

Passing uninitialized values as function parameters is technically
undefined behavior, so we work around it by always initializing the
registers.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I40f39d26232b14816c14ba64a0ea4a8f336f2675
---
 kernel/bpf/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
index 5f6f3f829b368..0ba7dd90a2ab3 100644
--- a/kernel/bpf/core.c
+++ b/kernel/bpf/core.c
@@ -2039,7 +2039,7 @@ static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn)
 static unsigned int PROG_NAME(stack_size)(const void *ctx, const struct bpf_insn *insn) \
 { \
 	u64 stack[stack_size / sizeof(u64)]; \
-	u64 regs[MAX_BPF_EXT_REG]; \
+	u64 regs[MAX_BPF_EXT_REG] = {}; \
 \
 	FP = (u64) (unsigned long) &stack[ARRAY_SIZE(stack)]; \
 	ARG1 = (u64) (unsigned long) ctx; \
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-43-glider%40google.com.
