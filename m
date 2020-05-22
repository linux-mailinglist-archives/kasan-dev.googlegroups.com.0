Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEJT33AKGQE4L7IJGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 15CC01DE14E
	for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 09:52:26 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id w1sf3230278pfw.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 May 2020 00:52:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590133944; cv=pass;
        d=google.com; s=arc-20160816;
        b=ghOCUujrTTPsmzGWs67K2IqziMy+hL7ajaDh9V9Bth16ChaD5ayhxVI10+4vq2lFgj
         p3Cg1GAakH7WSXSiOOmYTmNXdqG59mitCWvjKuqQnBvUJz8L51fBUZGHbhEzT+1uJ3mc
         EQTiW1WYzvJA3z3wPA/7i4KVGbz70sxBFz0ey+O0K0mDL9i12NMekai4i7vXBZLgbMbb
         pP6uY02eP44jdYU/Z2UhbRhI73V/sx9QAGdMiEMNHVDhkBMurBnwrYpsD9U2hln/ezn2
         3ZEBAz3JPDWxzmDjk/GoPGlvIHRWHKZLOpa5uF73RjQhf2GUDLYDb3HLLdUNrxaXFegr
         Rnbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=OdXLiGGMvkOgGS2SeI463HgMIpvXvLAo9Kyd++4Kw2Q=;
        b=RlL1nVcDJKqThbJcKOa7tnumvVoSRTZT2Dyjk3LxSLdFbXP0sa1ZkP732+z4pxLs/P
         N9lkO3AlegNoyY2L8V0fqpShqrB/3h2OkFcai8JIbz2upvPZr84V2bQhDAwq1Fr3qFsl
         7nKsipJSzNdfY6Oo8Wk31mF1TSdnpjFlI6aM5+QEKZXPENhDk6MASnhW067YO2eTPdYs
         NFYkGAL2ifnTE/23ZQ+Pb9JhdFHtiwzLHA7WwJ7SyTgdo0xPpITW0uYZIxoTDplKxJRl
         krp7Y+l3h+gOpuzekPvD4FEovVo1J6U66H2wU9LmazmOtxAf59muuPF1lneTbm9JzZyo
         03XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YyyrLMAu;
       spf=pass (google.com: domain of 3t4thxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3t4THXgUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OdXLiGGMvkOgGS2SeI463HgMIpvXvLAo9Kyd++4Kw2Q=;
        b=dI+/cV9E7MD1zPHIbC60QnvBQKTVsT6hBnEKT13+areKm9Rc4lVKVZ+ewyn2KJJVcK
         O3stJJbmONLsj1gTmyRIg9xffZ++EP+Kys6xt4l8k8fP4demXzfwsC8PLJ3/6bMNHkfZ
         5ZoxLp+FeqlxXlCVI3wR6/ljpN36oayPCe19iBVGWf9Nrv/a1/i2RB0gIey1yH1W2vU8
         yEDYGaeavBToCYcZ7zQKZElaDl0hsjnVad5sDSsTUUI+yMoR2tfdTMk1kuLi2Pc/yv7G
         1VP7X/9Ct/tiLaC7oQoj1fHV01v7UM80P/Kz11gy6A9mmDNJq4Q31RwZOptS/MLyljzt
         1GeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OdXLiGGMvkOgGS2SeI463HgMIpvXvLAo9Kyd++4Kw2Q=;
        b=am+44ck9HzUdm2Js/HGVbcjKVtJXnaKphmydO8LPjTL73BZWFMQEXcstntSC0Nlo6V
         BBAwhMchB6k8XUYmsYiP6UH3eIwtC9I3Z0CuHMFrAHAgoZPP3j65/bVe6Lu3WFc49Acq
         jvTwSBZJG+34yQgYkU49jbwAqrfHtQdC5KK38FjdRlFV04+L66U4l5BrInzip+jQxZRa
         /wKx59JPtkb4B4HekuxpivJINlqblxVdgm/ixw5VPN4iRaEoy+HCy3uPyudVrV86eIeA
         NR6MEQMrEvKsItzt3GQb8cZgUeyhVxvaa4sjiVuOQPfXNcmbEu49IMVtcF1PNxp2n189
         Up5w==
X-Gm-Message-State: AOAM533wrGRro7Lce5VhNDgVxgici271+SgXY7BEqKq0+hytk/8MIJcQ
	uvJjCPBBxm+JCaZ9uB9dJ6c=
X-Google-Smtp-Source: ABdhPJxUpw3TagCFRT3S4qqrjKdgTz2GloA/YJHsMSJOsikbISeH7hwANv5de6+eyk/g86jXnzZ0eg==
X-Received: by 2002:aa7:9f0c:: with SMTP id g12mr2770631pfr.126.1590133944584;
        Fri, 22 May 2020 00:52:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:521f:: with SMTP id g31ls174650pgb.2.gmail; Fri, 22 May
 2020 00:52:24 -0700 (PDT)
X-Received: by 2002:aa7:9532:: with SMTP id c18mr2695507pfp.255.1590133944127;
        Fri, 22 May 2020 00:52:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590133944; cv=none;
        d=google.com; s=arc-20160816;
        b=uwx979EMrss8MPxjyZpPyeXPXP4T8+1R/MSi1Bs+v+r1f1+zxtey7Hth88HhWjAWSH
         aielrTF76npD22qb9xKByHUcUKSmXK1JUjGFcprVlXkubVo0J07UwL/4nm4pE+ZLVqW2
         OHiWeoMH7QAda4MicrYb96ahBu0L0KUBlf7NQNf71DzgpAX/N8qKKN7qPGVH1fEuVyH4
         iGoWoOon3160d9uGQ03MyP6TITzEDJS+sa8JQ5Y0rkxZ83JL32ZZ2xgEmr6X04IfzaSU
         NK7B/CyrSGJMukwFs3YzFd6bdQI5+HTHLQULPEsVoiRfVtbVDo/oEa2KFQ5/c0lLD0pV
         7/nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=V3kv+xBmjrIeYzeByZn2jZ0q0fngGgBM343mBftKcUc=;
        b=u0my6ooXwwcrltxD08XzgR0gYQ0haHUoVWoJzbQWtdnvijyISpGYVlyrUrJ2/pdbqt
         1Z2+nnx5JR4Iy7cBTwSh+Xfk+45LNL/VvWnNHMajBpyRkUHkwAY7DAThljfwZJMWKcZp
         1rYaQwN8bwJspuNUWGzE1BNRnMc56ppl6wn0c88prwW4m2DxAETnFEdLrr1sYGLIMVji
         wQx0jZVvq4J+GMZ2QOR24ZRGiHjxR1bMGqm/vBO+hyx8pDZgBwuuzn8OtXyPpMjURyFK
         vPLEo3c8GPISE2cE2uzMVR4ac6xP5+OTwdrOQ/PVWUW0JRWxhyb6oDmgkl1pSJIrzG5N
         +YoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YyyrLMAu;
       spf=pass (google.com: domain of 3t4thxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3t4THXgUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id e6si875916pjp.3.2020.05.22.00.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 May 2020 00:52:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t4thxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id w6so9958898qvj.4
        for <kasan-dev@googlegroups.com>; Fri, 22 May 2020 00:52:24 -0700 (PDT)
X-Received: by 2002:a0c:eac4:: with SMTP id y4mr2480760qvp.39.1590133943257;
 Fri, 22 May 2020 00:52:23 -0700 (PDT)
Date: Fri, 22 May 2020 09:52:07 +0200
Message-Id: <20200522075207.157349-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc0.183.gde8f92d652-goog
Subject: [PATCH v2] kasan: Disable branch tracing for core runtime
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	aryabinin@virtuozzo.com, akpm@linux-foundation.org, linux-mm@kvack.org, 
	cai@lca.pw, kernel test robot <rong.a.chen@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YyyrLMAu;       spf=pass
 (google.com: domain of 3t4thxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3t4THXgUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

During early boot, while KASAN is not yet initialized, it is possible to
enter reporting code-path and end up in kasan_report(). While
uninitialized, the branch there prevents generating any reports,
however, under certain circumstances when branches are being traced
(TRACE_BRANCH_PROFILING), we may recurse deep enough to cause kernel
reboots without warning.

To prevent similar issues in future, we should disable branch tracing
for the core runtime.

Link: https://lore.kernel.org/lkml/20200517011732.GE24705@shao2-debian/
Reported-by: kernel test robot <rong.a.chen@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove duplicate DISABLE_BRANCH_PROFILING from tags.c as reported by
  Qian Cai.
---
 mm/kasan/Makefile  | 16 ++++++++--------
 mm/kasan/generic.c |  1 -
 mm/kasan/tags.c    |  1 -
 3 files changed, 8 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 434d503a6525..de3121848ddf 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -15,14 +15,14 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
-CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
-CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
 
 obj-$(CONFIG_KASAN) := common.o init.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 56ff8885fe2e..098a7dbaced6 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -15,7 +15,6 @@
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-#define DISABLE_BRANCH_PROFILING
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 25b7734e7013..8a959fdd30e3 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -12,7 +12,6 @@
  */
 
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-#define DISABLE_BRANCH_PROFILING
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
-- 
2.27.0.rc0.183.gde8f92d652-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200522075207.157349-1-elver%40google.com.
