Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBYHHZSHQMGQETCRNVGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0562F49EF1E
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 01:08:01 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id mp5-20020a1709071b0500b0069f2ba47b20sf2034647ejc.19
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jan 2022 16:08:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643328480; cv=pass;
        d=google.com; s=arc-20160816;
        b=y7rLjOy6GDVGH4f5Y6WPj+7Y0r2H5d0IEqf7VY06oBLMW3VQlrrRAr3tKcP0eIwc8b
         QlMPq5w+xRrhgkbb7osGnIforj49zKTySmiVNngEjNobdN2T3rmeXJPPbv2Fc8SopqRN
         j0EJ0FFjriSOdM1yHwL3AWe+oYIHc8VtiZdbhzmk/xEeCeCV4BEr/O0K06oK4a3ULJ7F
         6/VAo7oVTYmVS0AtdVCDpBDa/wDaAnWjWqy21E5zA5DrvVHufRsT53FShwDLkZxy0Bgt
         uS/egxQViXGywtrBnpVohKTAHQ7zWMMvt8VOtwlfBGKMXFBh9oP535dtEHe6IkqpymnU
         IncQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=+K7/kqidqBm058VN1jn/scNOp+snLx2xH2b8XpeNqIE=;
        b=Rr6RIYLgtt2h2Zuzw/sFW0KLP+qobatXeJRmTVrput6ZA/jFm2u340GlK05vBRRPir
         sI11MI6iDlf4/ZJxhItsRcmEWmt4uk5LrQtagp2vWC4bNXPe3oZrkmJLZEVXvaZ0DTeq
         Ur3JE8AgDJZ6GoX00Dy22JpE/GR+HXsrkewvEwqpCTzu0mTqvDGqm+7o8eSlEDqJyLfp
         yzJPy/mDwXtqG0dbb6sojdzu1ldEhcPAN/FS4s/FAiJth4PVzBM6GYCGDTEYfFi/BUzW
         WMjX+JWJ10bt5XcVPs2ZIeqFKa3I0T+hCa/cqPdEETexjCipmDhmwEgRJ+XdU+/WCU3S
         8ydQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=psUgohyl;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+K7/kqidqBm058VN1jn/scNOp+snLx2xH2b8XpeNqIE=;
        b=fOGTutBfQJ/fyUBrM9z2zr7Wj791K02OoqeFjoUFiH0d5L2r+gF/DDJCziVvxC0Ray
         HdUTEwtcEfhxJPKYT1Tx95sLse0civrXHJVla/RNyASy6w1lm0Y7chIn8v8JNLV4L/+M
         Tw6EBNo7L1pPXC33K2OOVH8skqQIKS0FzpnEabDOA/Hvo0+Sn2s6xCUM3KI0h9+0c0by
         CYOuK1E5YbA7tYhdPqDiOtq0uGTh+u+ok2Zz6kfSjtujNtMWB8RfVRDwIrwNXfMzCXvb
         aAF/SQOWj4y7QYhU5DOmzwDJL9Hdpz1dSYWEfrXqFQh0bFJ+d0ujxWhlO340sElTQfWi
         Uafw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+K7/kqidqBm058VN1jn/scNOp+snLx2xH2b8XpeNqIE=;
        b=ZFYU1SejFhyKvhr2hV436NVMKWQzL123g9Ft8TY1U5huOFw4uOYZ8DZQW14SbIXfak
         no8kFaDigDA3chf2Xqrm+/GovLCaf1W0ZEwDqyeY89sN8wvc00w24AE1msFJu+gaLQZc
         tPNkYxxIRP7PiNo0j1ZeGNgpE2zFp2bl70MWXibe3g/mWjDrYc8N8whHaujSME7KY+Qi
         cG3MtGM/DADsst+KpJOQWjVc6for6xoDREcXh0MgrIUSmAvzMDodqt4iQIWuzfBeFEdh
         UcQ7FaoYl6yEJFKi32fBqWULTN6Fiq/jgVWnsbX2YJcwOYAq070H2XF2u1TScuyb/oOy
         5iBw==
X-Gm-Message-State: AOAM530YPSNRjPzA5TzSC5apTP6pQ2g0K7hh1DAYELxtsQGxVdgBWboE
	bnArcEifGsKyiB1JTa1VgoI=
X-Google-Smtp-Source: ABdhPJxdDA27CZ5/qHdrwK7uMwBunentbovNHnR0ZCUGL7M4PoCaN4wxUAae2LttUYA4X0vQg+chng==
X-Received: by 2002:a17:907:3ea9:: with SMTP id hs41mr4979663ejc.727.1643328480612;
        Thu, 27 Jan 2022 16:08:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:8a20:: with SMTP id sc32ls3176895ejc.3.gmail; Thu,
 27 Jan 2022 16:07:59 -0800 (PST)
X-Received: by 2002:a17:907:608f:: with SMTP id ht15mr4867573ejc.498.1643328479686;
        Thu, 27 Jan 2022 16:07:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643328479; cv=none;
        d=google.com; s=arc-20160816;
        b=rmA1YTibVasqvnaOVcAQNSIJ9Avb50c2WSPDeVtnuyidAp5lM0zk1Z1QtGlWdylJ0j
         Tn3+nEGwdeaF7x04l0W1X6i+vKyFTMQIv1EhLFTNaRIOOO2aJvddZvsV56Co4bgxtD3k
         QSx/YCeKQLUyIRaPkibAVlWuVgleT0w1xjrU1qpSSEegBZJjniO5RSE5rTP6K8KES+ZZ
         9tvTuyPhNhNF+PfhWeUbX0G40LQfq2yJRHMlmWFGcEZ9dw1nKMqG+JEL1ZlKAM8K/aWC
         aW1GU66MDPEmTUlV9Vje17evnCtSfX7E0oCJIxU2o5UbUOTKYJTre2iwkc7rSKd4z14r
         zkxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=K+UJbVBKe2v11VAhxonJJHgo2MJev+F3zVTIM6Z5XRw=;
        b=OpGvmLnJFQDs3Rc8ozI0WjunjR5eRZZuZrysKBA4WrF0mPbYDJbQskJlA/DE3otxy3
         fjcRyjFrFLboxqxUPQawUYNNrGA9nS38s89hGEHU6bwOopV4rN1RQyTnmryoZ/A5hjZa
         DCgCh4a9H/Vx12d4393ww1YbFcc9d0QxEGSVsJC5KkR3Zk51DQeENybmb+RwELsvpm1H
         503vuccQusXzo0vzH/aajEz8bQ+sPQSnbW3yNOrCTSnnZl8MWOlRSeOrggiyQpVZmKl9
         zCNWLVvaYGOoKKqdFloZ3EAo1yhcODCJjYmL2ft3plLOP1fHM2iyaHjphGXc9iaGFvEF
         /CeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=psUgohyl;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id r25si96752ejz.2.2022.01.27.16.07.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Jan 2022 16:07:59 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id e8so7769474wrc.0
        for <kasan-dev@googlegroups.com>; Thu, 27 Jan 2022 16:07:59 -0800 (PST)
X-Received: by 2002:a05:6000:18af:: with SMTP id b15mr4686186wri.589.1643328479307;
        Thu, 27 Jan 2022 16:07:59 -0800 (PST)
Received: from localhost ([2a02:168:96c5:1:55ed:514f:6ad7:5bcc])
        by smtp.gmail.com with ESMTPSA id x4sm3478297wrp.13.2022.01.27.16.07.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Jan 2022 16:07:58 -0800 (PST)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>,
	linux-kernel@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Eric Dumazet <edumazet@google.com>,
	Jann Horn <jannh@google.com>
Subject: [PATCH v2] x86/csum: Add KASAN/KCSAN instrumentation
Date: Fri, 28 Jan 2022 01:07:52 +0100
Message-Id: <20220128000752.2322591-1-jannh@google.com>
X-Mailer: git-send-email 2.35.0.rc0.227.g00780c9af4-goog
MIME-Version: 1.0
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=psUgohyl;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

In the optimized X86 version of the copy-with-checksum helpers, use
instrument_*() before accessing buffers from assembly code so that KASAN
and KCSAN don't have blind spots there.

Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v2: use instrument_copy_{from,to}_user instead of instrument_{read,write}
        where appropriate (dvyukov)

 arch/x86/lib/csum-partial_64.c  | 3 +++
 arch/x86/lib/csum-wrappers_64.c | 9 +++++++++
 2 files changed, 12 insertions(+)

diff --git a/arch/x86/lib/csum-partial_64.c b/arch/x86/lib/csum-partial_64.c
index 1f8a8f895173..8b0c353cd212 100644
--- a/arch/x86/lib/csum-partial_64.c
+++ b/arch/x86/lib/csum-partial_64.c
@@ -8,6 +8,7 @@
  
 #include <linux/compiler.h>
 #include <linux/export.h>
+#include <linux/instrumented.h>
 #include <asm/checksum.h>
 #include <asm/word-at-a-time.h>
 
@@ -37,6 +38,8 @@ __wsum csum_partial(const void *buff, int len, __wsum sum)
 	u64 temp64 = (__force u64)sum;
 	unsigned odd, result;
 
+	instrument_read(buff, len);
+
 	odd = 1 & (unsigned long) buff;
 	if (unlikely(odd)) {
 		if (unlikely(len == 0))
diff --git a/arch/x86/lib/csum-wrappers_64.c b/arch/x86/lib/csum-wrappers_64.c
index 189344924a2b..c44973b8f255 100644
--- a/arch/x86/lib/csum-wrappers_64.c
+++ b/arch/x86/lib/csum-wrappers_64.c
@@ -6,6 +6,8 @@
  */
 #include <asm/checksum.h>
 #include <linux/export.h>
+#include <linux/in6.h>
+#include <linux/instrumented.h>
 #include <linux/uaccess.h>
 #include <asm/smap.h>
 
@@ -26,6 +28,7 @@ csum_and_copy_from_user(const void __user *src, void *dst, int len)
 	__wsum sum;
 
 	might_sleep();
+	instrument_copy_from_user(dst, src, len);
 	if (!user_access_begin(src, len))
 		return 0;
 	sum = csum_partial_copy_generic((__force const void *)src, dst, len);
@@ -51,6 +54,7 @@ csum_and_copy_to_user(const void *src, void __user *dst, int len)
 	__wsum sum;
 
 	might_sleep();
+	instrument_copy_to_user(dst, src, len);
 	if (!user_access_begin(dst, len))
 		return 0;
 	sum = csum_partial_copy_generic(src, (void __force *)dst, len);
@@ -71,6 +75,8 @@ EXPORT_SYMBOL(csum_and_copy_to_user);
 __wsum
 csum_partial_copy_nocheck(const void *src, void *dst, int len)
 {
+	instrument_write(dst, len);
+	instrument_read(src, len);
 	return csum_partial_copy_generic(src, dst, len);
 }
 EXPORT_SYMBOL(csum_partial_copy_nocheck);
@@ -81,6 +87,9 @@ __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
 {
 	__u64 rest, sum64;
 
+	instrument_read(saddr, sizeof(*saddr));
+	instrument_read(daddr, sizeof(*daddr));
+
 	rest = (__force __u64)htonl(len) + (__force __u64)htons(proto) +
 		(__force __u64)sum;
 

base-commit: 0280e3c58f92b2fe0e8fbbdf8d386449168de4a8
-- 
2.35.0.rc0.227.g00780c9af4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220128000752.2322591-1-jannh%40google.com.
