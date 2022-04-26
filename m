Return-Path: <kasan-dev+bncBD52JJ7JXILRB2VNUGJQMGQETFLPBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A230510A80
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 22:32:43 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-2f7c011e3e9sf94278017b3.23
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 13:32:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651005162; cv=pass;
        d=google.com; s=arc-20160816;
        b=kf0IQfqeRcO9ZqraQw59Jfbb8ccgKR9aplQh5jURYzQj7iVW8QoINk0+53hLeTiQb+
         XAPd7T76D2GqwpJcyQV2o2GxgceKz6iQpZaaGxlB/QYMokJ7FniZwJQ/ThhpafI2kyms
         TZ+G7rpejd7CBlpdjZ/IMl8rrMldp7ilm9shumokUgCSzO2LnFpI6mPB8fdobwwBfw4/
         TKkbBwktays2Fz6ESTrBSopvhRQC4+2iz/SlnZkfEcjk1o/OJr+sa6ZOf3WhdqD8OWI8
         npMBt4IAeXUAksiUJkP479G6YGH1V5EjFM3rKH7Q4hjM9fF0DXCgN0M3ReOTm99vUoF6
         f6pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=v8V8dBvneoGDEHgPYkdQho5NpQOZI17NvXTVG9GmehQ=;
        b=amnUhmHv04Lfvy4RD4+zgTzrHCT9t9EUwc8BTIxS2XVbE2b3VpzpaHuUiKho6wu2pN
         n2n3ALdf1XpfQNuJCD6v/6eivwrJakFbDxq511rI2vJrdiOBJ1ztMsGr1IdNvZinNzq5
         roFtSw7K6d9ol5G2mtkjeF43+4dGk7qMJOZoa4Eb3pLoQrjvckX6+JyjJoEPwcPEQsy0
         CiZf3tP5Bg6aFyoQwXQIwmynp4/hiRp9oYYuS+GrDwuNYgMcy8mVAxKh09am0c/X7rO2
         qGThJqYpLiTjmOb3I6T3NAhca8sg0P+8k6TzvqjclX2GBJlNfc7gxbDMLNZnS94xAjiU
         P3XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YHzUgr9Q;
       spf=pass (google.com: domain of 36vzoygmkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=36VZoYgMKCVI9ww08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=v8V8dBvneoGDEHgPYkdQho5NpQOZI17NvXTVG9GmehQ=;
        b=FyZiR+Ew1aKSOxEPszrzM5UqFyMGMMCjSYiV2l2Rw5CucmuVp2y3OkjYMhJ8/lStOo
         DfxYOFD2H/1C4EXP+9SYFQ7nVEJV4zul8ObaRE27lQCZnEEo87NgAhIQ4lYM7aOixBji
         KtiaB6VRHGMqll0Fx0qOeFd0e4ThTWjyNURVX6lTq9goxv1N74ObGWZ2gJ1iRUBLCkai
         SRkXiNWwDh9/wh8UB7EJ8vMNGlaFT/yEKqnhBT3/FaiKarQT1PqM9GbYxYeQzm9YzROF
         NqBnn9Ugbp5HwpNz+jRWwIUiqJzTtWdoJ3GY9nVORjYnNoT8Nhe7Q29R3PuTNIedoVMG
         gYDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=v8V8dBvneoGDEHgPYkdQho5NpQOZI17NvXTVG9GmehQ=;
        b=ZLH4tshLWYiPP1D4IBBd8w5urm3qz2rPv/3o9Ea8UvqK+VsMznL+s9KPlnDzosUC+N
         up/JgHmjlQKc/VL7Q08osfG+vbeRAf70Kn1D98bDPDKsoEXEky6zBYB2m8Av/8COOVHv
         NaMFQEADBhy96MnDem2E9FUgM1H197iyyM0btDOUl++YFR4CWZLCKb0nxtudWt1sqjTc
         ZW/qWBnxxGAIcrK3xTu6zRM8+QW1v1iS0hLVHuBQmZjm0GEk1/HYDKiFJAZALTz8V8mQ
         y1c7XfZbx8ue8+Cmt1GBl0USjdVl562rzeJVVFJApHFYafmqVRzAIX7/UVrXLRLUGOjG
         BI5Q==
X-Gm-Message-State: AOAM532uo66wvcpXd5jeNspuAGDk2HYeDEVQqnmO2QTuxq3lTWyTRyk8
	GkQb5WgCKRQ0mz49KEid+go=
X-Google-Smtp-Source: ABdhPJx3A6aXKE05zQc1HJYUaC5VxL7ENoC/dLyz5N23UF511JgIEVwEvVu8W81NinmrUlpTm2qX2A==
X-Received: by 2002:a25:b9d2:0:b0:628:a85f:953c with SMTP id y18-20020a25b9d2000000b00628a85f953cmr22655451ybj.312.1651005162154;
        Tue, 26 Apr 2022 13:32:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c84:0:b0:645:d47e:683 with SMTP id s126-20020a252c84000000b00645d47e0683ls152381ybs.10.gmail;
 Tue, 26 Apr 2022 13:32:41 -0700 (PDT)
X-Received: by 2002:a25:880e:0:b0:641:2775:7cfe with SMTP id c14-20020a25880e000000b0064127757cfemr23007214ybl.7.1651005161691;
        Tue, 26 Apr 2022 13:32:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651005161; cv=none;
        d=google.com; s=arc-20160816;
        b=ZOaDsSBpEuZXYmjpyvGJi9F+l/evP04s6P6404UH6VBADgBstM2NzA+Q4eNaRT9WlZ
         XBhh0KOrjjlTuvxFFC+r3OticWAaxQLOF63dgdrZmMZupQ/5PHW8LcVPiOg9Hje09mZd
         BezFlfX/41Wf/pOq9CRT16towqICJwhQ0bqp+vyegGa3UFqmHGIL/HGLke9VocbFiXkj
         0Rk45dfQhEWpRXIHJmeZKx8jEuu9/Uh1UQtx6cXyWizJ6gEgdjv9LF46axhbr5cjELKp
         oHcpjxy1uY4OuLQJrY1WTD2GjCFcWKyAFjEBQK14PEg+9DGoAA46IUKR/lE4yKqTFZE4
         mSyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=ZsCBuiiFgRZP4jhvDChuQicSvWa0udH/sRJiHNclKT4=;
        b=TP1e8qFYgNxPLsob5VrsaWYGXPTwHMgi3VunZGU493coDb0xCBD3zvHUc/gxDFoWxT
         4WMESv8VnuPRLgv3KQ8PrRIATrM/QLfnbHaHzhmmj4UOSEnx7OWzEz8o4q9hVZdfPUiZ
         k4FNnvXUXKJonOdeSmIYifWCJ8S/kKOUz+HrMLiJZk1yEZryUIAdanlIMnwVGJfxjR7+
         pGBWAJq9XTekYeSFd9D5tnuwiYTb+f0TKIADXg1nQwe9A+74qU8qVLAjBzqj/obGvQoE
         E6VopAWFfyr0Onslbl413KSMJcAWNj+Hllw1nox57X/St0EqeFQ07oQnInoCQC6m/6te
         a5aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YHzUgr9Q;
       spf=pass (google.com: domain of 36vzoygmkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=36VZoYgMKCVI9ww08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id g186-20020a8120c3000000b002ef4b182f12si2138437ywg.4.2022.04.26.13.32.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 13:32:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36vzoygmkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-2d7eaa730d9so165864357b3.13
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 13:32:41 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:709f:5eff:336a:4109])
 (user=pcc job=sendgmr) by 2002:a05:6902:52:b0:645:bd1:970e with SMTP id
 m18-20020a056902005200b006450bd1970emr22523227ybh.413.1651005161361; Tue, 26
 Apr 2022 13:32:41 -0700 (PDT)
Date: Tue, 26 Apr 2022 13:32:30 -0700
Message-Id: <20220426203231.2107365-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v4 1/2] printk: stop including cache.h from printk.h
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, vbabka@suse.cz, penberg@kernel.org, 
	roman.gushchin@linux.dev, iamjoonsoo.kim@lge.com, rientjes@google.com, 
	Herbert Xu <herbert@gondor.apana.org.au>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Eric Biederman <ebiederm@xmission.com>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YHzUgr9Q;       spf=pass
 (google.com: domain of 36vzoygmkcvi9ww08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=36VZoYgMKCVI9ww08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

An inclusion of cache.h in printk.h was added in 2014 in
commit c28aa1f0a847 ("printk/cache: mark printk_once test variable
__read_mostly") in order to bring in the definition of __read_mostly. The
usage of __read_mostly was later removed in commit 3ec25826ae33 ("printk:
Tie printk_once / printk_deferred_once into .data.once for reset")
which made the inclusion of cache.h unnecessary, so remove it.

We have a small amount of code that depended on the inclusion of cache.h
from printk.h; fix that code to include the appropriate header.

This fixes a circular inclusion on arm64 (linux/printk.h -> linux/cache.h
-> asm/cache.h -> linux/kasan-enabled.h -> linux/static_key.h ->
linux/jump_label.h -> linux/bug.h -> asm/bug.h -> linux/printk.h) that
would otherwise be introduced by the next patch.

Build tested using {allyesconfig,defconfig} x {arm64,x86_64}.

Link: https://linux-review.googlesource.com/id/I8fd51f72c9ef1f2d6afd3b2cbc875aa4792c1fba
Signed-off-by: Peter Collingbourne <pcc@google.com>
---
 arch/arm64/include/asm/mte-kasan.h | 1 +
 arch/arm64/include/asm/percpu.h    | 1 +
 drivers/firmware/smccc/kvm_guest.c | 1 +
 include/linux/printk.h             | 1 -
 4 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index a857bcacf0fe..9f79425fc65a 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -6,6 +6,7 @@
 #define __ASM_MTE_KASAN_H
 
 #include <asm/compiler.h>
+#include <asm/cputype.h>
 #include <asm/mte-def.h>
 
 #ifndef __ASSEMBLY__
diff --git a/arch/arm64/include/asm/percpu.h b/arch/arm64/include/asm/percpu.h
index 8f1661603b78..b9ba19dbdb69 100644
--- a/arch/arm64/include/asm/percpu.h
+++ b/arch/arm64/include/asm/percpu.h
@@ -10,6 +10,7 @@
 #include <asm/alternative.h>
 #include <asm/cmpxchg.h>
 #include <asm/stack_pointer.h>
+#include <asm/sysreg.h>
 
 static inline void set_my_cpu_offset(unsigned long off)
 {
diff --git a/drivers/firmware/smccc/kvm_guest.c b/drivers/firmware/smccc/kvm_guest.c
index 2d3e866decaa..89a68e7eeaa6 100644
--- a/drivers/firmware/smccc/kvm_guest.c
+++ b/drivers/firmware/smccc/kvm_guest.c
@@ -4,6 +4,7 @@
 
 #include <linux/arm-smccc.h>
 #include <linux/bitmap.h>
+#include <linux/cache.h>
 #include <linux/kernel.h>
 #include <linux/string.h>
 
diff --git a/include/linux/printk.h b/include/linux/printk.h
index 1522df223c0f..8e8d74edf121 100644
--- a/include/linux/printk.h
+++ b/include/linux/printk.h
@@ -6,7 +6,6 @@
 #include <linux/init.h>
 #include <linux/kern_levels.h>
 #include <linux/linkage.h>
-#include <linux/cache.h>
 #include <linux/ratelimit_types.h>
 #include <linux/once_lite.h>
 
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426203231.2107365-1-pcc%40google.com.
