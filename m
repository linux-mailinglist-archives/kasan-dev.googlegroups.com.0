Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2EDRSLAMGQEBSJ5WFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 6149D565941
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:17 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id g25-20020a2e9e59000000b0025baf0470fesf2800618ljk.8
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947177; cv=pass;
        d=google.com; s=arc-20160816;
        b=H2mHtbCDvI/Kvi+QRVKN44SlzNlKgBTNJXj0TxcifL1gWzgtgS7YoN0Ou8QqqL8fd1
         cpg51jYAYrHGOGQgB50OE/zko8J3oAHhCyw+bPSENkDtYOpEHSeXOE3kpJf1j2Y+NATS
         R3PpikyQjTbfOuX5T+rSmA6LC5ooY+tqbWrGAWlF+kYZejt85z6ir+xXh9c+JxBvHAsv
         BGsFptV84t9XG6H4/0FavDpTjNqWvk47T2+YlqPnOp0giyZksVZEeup5WHR4pI77Ct9w
         NXUtXr+VzAgDtQM940JaAQEmVAw54K42cbKG/+9r7yMr5mQvBDbm2dMJQZz4amUVcsSj
         GCTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Dqf+lk9g87A0GlxnnaAm7MmviYSu+iElmePFsjgDGYQ=;
        b=erarKmNnQLqM/aDtFQNOZrN1acKTy372cU23ouAgQxlr6hgrQbJmOyPXjU5FcjtxHa
         PBAhoOThQS6j9t4/TIqi/72liu0xCUowHhXWegmQsmmx0enlEk55RLGHB9xIP91yDT/l
         rgkKQkt8ZN2tOGtz2gRvVXQP98u2RRzaxobZ/gM44OsWCeCocV1xPsdobt9Wykqs7moi
         mjsUGKuSbfyS+RKlkvzl795NmaF5QHOE8X7bUp0qEQJiis6CgQsEIHCNXSAeAqP5cKHD
         L4WigPduzNQ6ikLcSIi2NsKsKa8JDGLNA6liOErDDzQezRvOmd1qhnwxKiFXMppk3PZF
         dKYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QbMgulhI;
       spf=pass (google.com: domain of 35whdygukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=35wHDYgUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dqf+lk9g87A0GlxnnaAm7MmviYSu+iElmePFsjgDGYQ=;
        b=hBJzDeA7sRq2+F6QVuUoy1A+9peoaQ/sKIYZcMF2plbuBZhg5+biRxbDdMiFAX0024
         07inoVkynMbELZF4HXytQXMiWcchyPjOulhtGKiXl2rKIPtvk+ELfT+8vokqcfj3TClM
         b9tPmtlrQXsGcilPiRwJPcK10uGeeUw98pTIfu5MSFB4OEtMEYTdkMA6mPt/5mAXMeXe
         Ehf93eKRMsHZj2Jeol42R4k45ROujNabmlcPAdX8ac+2vDjfrNoZIp/sFLj+spSW9RtP
         NmouJ55OtV9+I2USR3gGtCH/VOLJkLTGzpqIrWvD6knWPO/Lh86qAyoH4TnUbKVYMu8f
         FE6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dqf+lk9g87A0GlxnnaAm7MmviYSu+iElmePFsjgDGYQ=;
        b=aHzQ11SKo++varBK1pOgtxkUv7lcTAZwgndrMenRyVIVJGowvVYJkwYvw212OjOelB
         VE6dlQHzhRklkZrWISMXQfDRyf/dgJ3DNgzA6wCpPoAql7/hP6C7FGpjdF6Spky/OA6d
         NmjIRHaVHICKReytEKBO++dGzb1VDLcg2CLh88CWDL6Go7I5py79FWwq/cIRSOfIHZMQ
         Vn9DYgLS4wXEqPAplH85BrjYcLhyVRJLzSSu7twKdjOeD1iSJ3Gx8a2oF8GDMe1GR7Vw
         s0Ti34uWhof11CRyN+SQWLMRt/nQ8x+ffJEVwVGcwtlOqhg2687NdvVhDVkDxs5+Kp6P
         oEcA==
X-Gm-Message-State: AJIora+pwTlzKawfewUgNnM74/JVklh8TlnKHUAURvfdre8WaHBwilkp
	dbGWh8kKU3ZdwwUwnwngWKE=
X-Google-Smtp-Source: AGRyM1sLdm27DZ1lKkMg0IJW96xrIz1rtmrR9sIzD2XAIXmZ9TnR1gPIyamIpTg5h+/EThgLK9Q0ZQ==
X-Received: by 2002:a05:6512:114e:b0:47f:5f76:22bb with SMTP id m14-20020a056512114e00b0047f5f7622bbmr19731365lfg.648.1656947176854;
        Mon, 04 Jul 2022 08:06:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls201584lfb.1.gmail; Mon, 04 Jul 2022
 08:06:15 -0700 (PDT)
X-Received: by 2002:a05:6512:224f:b0:47f:5fc4:69d2 with SMTP id i15-20020a056512224f00b0047f5fc469d2mr17613954lfu.567.1656947175485;
        Mon, 04 Jul 2022 08:06:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947175; cv=none;
        d=google.com; s=arc-20160816;
        b=LUF92sWBy9fI6jsQD/Sewt95dW2tb0TX9cuEwv0kyNQem8ZalYG0NOFQRSCZ8z7+v9
         PuuNgAqN4JMPWKyCipU/83zK+x9umXnOVmg1y/VxLOeQh/poOT4zL2CECE1HnQNR8Uek
         VUE8w25XiaBc6NbbrLEphYNBC+uDI4YlFR74WlNp9vndpwlAJndPeJ2cxdJOTXm5bTOK
         TUDas+6E/aWBweSUVEfJt6I31v5F7R5Vi9yxqBQzAM5yKxCuNOMONa9PpVDwW7UpZoZI
         cWCyX0k9fWYGhlclotgZMih6PtLmv9XyJ/qmC+s59F2kqwi0knILhuQbx/VOztJeolfE
         9k9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1aXAa75QFld8JbpbPPEthMJig82bhovg/Ry5+b6na1M=;
        b=hwhJRoJr2wXcKG0WuvDvAleSLuw5sogGlA5qwEDQiXnZ6hNxUglW4L3H/cD/MOZ5qv
         SByTLCfC8H6LivjU1T0jNTEPv6cpAn7mYolw5hoNWgiCdftxbT0ZHPpBRXNoWD8P52q3
         lBC3ZpqaIUESiJufCpo6BCpkTAR0kf22AhElaO7qiJMm9DXzwGFklPfhbnU/KSSTwlm0
         NFnQY816GdQtZITKFSoc348or3R+jOsltrDJODV3BcFTobWbfmAGiYPAW+/PYlsgc3Td
         THD+w02fJRlj8yZFwnkqD04283QO+grfleYa9D7cvRPumuhOq7hLr7JtGSEbCLZsrpq9
         0t8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QbMgulhI;
       spf=pass (google.com: domain of 35whdygukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=35wHDYgUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id k27-20020a2ea27b000000b0025d2c310ccesi23001ljm.2.2022.07.04.08.06.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35whdygukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hq41-20020a1709073f2900b00722e5ad076cso2160002ejc.20
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:15 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a17:906:74d6:b0:722:e521:7343 with SMTP id
 z22-20020a17090674d600b00722e5217343mr28873376ejl.432.1656947175193; Mon, 04
 Jul 2022 08:06:15 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:07 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-8-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 07/14] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QbMgulhI;       spf=pass
 (google.com: domain of 35whdygukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=35wHDYgUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Due to being a __weak function, hw_breakpoint_weight() will cause the
compiler to always emit a call to it. This generates unnecessarily bad
code (register spills etc.) for no good reason; in fact it appears in
profiles of `perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512`:

    ...
    0.70%  [kernel]       [k] hw_breakpoint_weight
    ...

While a small percentage, no architecture defines its own
hw_breakpoint_weight() nor are there users outside hw_breakpoint.c,
which makes the fact it is currently __weak a poor choice.

Change hw_breakpoint_weight()'s definition to follow a similar protocol
to hw_breakpoint_slots(), such that if <asm/hw_breakpoint.h> defines
hw_breakpoint_weight(), we'll use it instead.

The result is that it is inlined and no longer shows up in profiles.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 include/linux/hw_breakpoint.h | 1 -
 kernel/events/hw_breakpoint.c | 4 +++-
 2 files changed, 3 insertions(+), 2 deletions(-)

diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index a3fb846705eb..f319bd26b030 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -80,7 +80,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
 extern int dbg_release_bp_slot(struct perf_event *bp);
 extern int reserve_bp_slot(struct perf_event *bp);
 extern void release_bp_slot(struct perf_event *bp);
-int hw_breakpoint_weight(struct perf_event *bp);
 int arch_reserve_bp_slot(struct perf_event *bp);
 void arch_release_bp_slot(struct perf_event *bp);
 void arch_unregister_hw_breakpoint(struct perf_event *bp);
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 9fb66d358d81..9c9bf17666a5 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -124,10 +124,12 @@ static __init int init_breakpoint_slots(void)
 }
 #endif
 
-__weak int hw_breakpoint_weight(struct perf_event *bp)
+#ifndef hw_breakpoint_weight
+static inline int hw_breakpoint_weight(struct perf_event *bp)
 {
 	return 1;
 }
+#endif
 
 static inline enum bp_type_idx find_slot_idx(u64 bp_type)
 {
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-8-elver%40google.com.
