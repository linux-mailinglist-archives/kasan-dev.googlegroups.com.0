Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD5O6D6QKGQE5G3THXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 396FF2C155D
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:52 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 194sf6506266lfm.22
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162191; cv=pass;
        d=google.com; s=arc-20160816;
        b=aKU2tl5W6do5HcrBoLFnBfTjMK63atKSG7WCX9GwLeT2oRPoVMuLtBP0qa4jFS4lsT
         FgwQntMTu9GJnru0/0dJ3/RouRj8LupsYKTdcfqR4QFDO//W0ohPqOgGFdePfnU98fK8
         H3QzMxbzoXEj1JJtqLZnYdZyiT5c0IOL058R+XMhNqPFK6H8E4paI36s7XT7XsGDIIkl
         QUUPe6D+Rf/HJMfZSiAeWPuoccZ2Mjbm5CFCK0A32WMu4Fk/CFluUJof4JCuSwkYGc5v
         GYAOegOLtRtbZvMV1nQp5nvTPS54XLM+QxRFVViG8Z/9e1lvkSXA+j0Hzr8WF6bUWgyI
         48Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=M84XarbrHlQeyxa1t/hiqnd2BaQaFPbHvmjKilPpa1g=;
        b=v6nYL3NLNtFvUAzGacXRI0oloqBwNAxqayFtaSZd6K65tqc75a+dWspMbIHmTUNaaJ
         iLAL0kJWMZqNs/xZWxPlilFQypU/5odF9Bh9ru6n7696DBlM0k8gs+BvhpxunRQx5uLY
         EKucd78VVA4axkBaeftl59uQWpEE6e6pjHzaE74oJQeof3Ol0H/1FUZs/7kLUCj8ETgb
         ZMfN7zlzLCP1/pOulEE0SsRJuQRsyD2xkYmeRXb2kPHA2UemOZ2ID0E+vNR4yYdJCrgk
         OGdxVzV+p/bJov4l19dBQsGMmLo0A7sWMw+aEv95+5yR7YFA1a8MRnXR1AvQ0nEXK3V6
         /nQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S901JV6O;
       spf=pass (google.com: domain of 3dre8xwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3DRe8XwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=M84XarbrHlQeyxa1t/hiqnd2BaQaFPbHvmjKilPpa1g=;
        b=tOmOblYLH3a9E3ejhSvLiTOrhj9dhf0fK6KZz6NnfsSrLs0PmNn+Q8I66SsgHQ0eHz
         J4MyHRPPSaMCBFf7kqBk7buMUhU6miRgZXGioUJwupCJ9keK3rD8hcoOyW0n2VZ1GbJh
         GKepKu0sTbC0WwRrWWoqKwlahxBAULMxDIA2oPvJ3be1/PXf07rrBElIbkTqid30PISV
         0zGt6cSqg39zfEYCP0p2uY2evOvMK3Ci4/ffrttRVIcu+0nhFVsWrhMtzv5wbkEAw/sL
         35CPJaJoT/vsn5lqMdcZyXsCtAM7/1BxlTWfCdgklH102QGDlloIxwHEcBoin849giK8
         rx2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M84XarbrHlQeyxa1t/hiqnd2BaQaFPbHvmjKilPpa1g=;
        b=jHxt75RKovVzcLR42eK9tnUkJ4WhXOLgrL0ld5SgjwBCyP7I+rQFoHXaxbmySfwhXt
         b7RDNarJi3sLEWyzDPnVNFHHwO85FYohAdcG95eJo28wYLih3mZl7Y+Ql044KSxjR3LV
         DLc5fto3/y0oNIuco6mWIdGvPFOrSxR9JsWtmYBF669K1ui2TFK7i/dtmbNgxEoVdCCo
         Y8tL1Dk/9LOV5NCFv68Tagl1700nX24O9K2RIsL3f/NuVyFPPxyT3pGTwaJR0E4/4ONk
         NpVJnYXX3E3zMXrNXaSQe0uYg6cV/X2X9gdPjBdXdO8cO7OxjFHHaxWwaFXq5IZ1jT6z
         UZwA==
X-Gm-Message-State: AOAM5326o5+JRV0YBUc6ksAHjlT5Rq9bvQpa6szOUGLHKK07TUyO9HVl
	XSVakDXLrr+KToOdMZRZH3Y=
X-Google-Smtp-Source: ABdhPJwtEtMCVRoIJAKHCXqKH4EEMJ4nkdbYGUZ2UEMN+2Xop3UlVyHcqIRoW8lEu1MFGVD7qx1LFw==
X-Received: by 2002:a19:8112:: with SMTP id c18mr302543lfd.455.1606162191812;
        Mon, 23 Nov 2020 12:09:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:914c:: with SMTP id q12ls2349503ljg.8.gmail; Mon, 23 Nov
 2020 12:09:51 -0800 (PST)
X-Received: by 2002:a2e:8e6c:: with SMTP id t12mr423121ljk.441.1606162190919;
        Mon, 23 Nov 2020 12:09:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162190; cv=none;
        d=google.com; s=arc-20160816;
        b=u5ZXMHxzHBj9lie862qeyDB0PYhaQ6TukVW/aJiExK2Y8PZPVdUkfasfgDCOxgJox6
         4mRxrEsXsBvj7lufyb9vH0gffriWvldb2Ng478ibzUEwuE0BcVCK+soq7L4ea79L4641
         EVxzYvowMx92oxFgQyl/5sbhosfwZgKrFAwBiA7XV4UeVEO0Xsov51CbGzpdQTvmm+1k
         Mq9SDOqz+3Erorypebv2Xu6mApkDsRlvDr15zkeQFgOSnkJevoujGkbyiWaFSogWz6oH
         GljKLBKbyaF4Znpiy+xLZ84tw8H9yCvUAasCB5mkW9mx4DsNNiTgopxTfcHfsrC64De3
         YMZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=rfxkb1rbWhlJP1u/zeppHvBMeszJmW3VoX+v06hDfPQ=;
        b=0n2izkguV4hrun7QPhDqU9RKsU812eOMmDbKDGvL82SO8aVB3nRrJ/jveZ8stGdwJK
         H7ahdCR5D0ZbONtKygKgx2FfVxxy5yAN/bfxw+YK7q8IHrQJhelpG2t+ZZ+xoO5IWx2J
         +8wsaDWF5Ddbgsv1nt7KqewSakEvCojLPLfIThYhjAgaFgKXUUsIiQfuq0t/j8qQwl/8
         06lG7nvl7jIjWyFhMnXOv30HFBQZGOAIbb6ix30IY4GF7gQwrcqxx3GRIBOGNE/i5kxb
         Rn4YZQfUqfMkL2FFrAx3hEFb+4w1bBMn0iBv6a+z5Y+tUh/iXzAEUFBKXoTml2ODPjeV
         jqtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S901JV6O;
       spf=pass (google.com: domain of 3dre8xwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3DRe8XwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id o13si432633lfo.5.2020.11.23.12.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dre8xwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id g18so1426478eje.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:50 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:c0d1:: with SMTP id
 bn17mr1284452ejb.114.1606162189982; Mon, 23 Nov 2020 12:09:49 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:59 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <9d84bfaaf8fabe0fc89f913c9e420a30bd31a260.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 35/42] kasan, x86, s390: update undef CONFIG_KASAN
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S901JV6O;       spf=pass
 (google.com: domain of 3dre8xwokctamzpdqkwzhxsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3DRe8XwoKCTAMZPdQkWZhXSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

With the intoduction of hardware tag-based KASAN some kernel checks of
this kind:

  ifdef CONFIG_KASAN

will be updated to:

  if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
that isn't linked with KASAN runtime and shouldn't have any KASAN
annotations.

Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Vasily Gorbik <gor@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
---
 arch/s390/boot/string.c         | 1 +
 arch/x86/boot/compressed/misc.h | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index b11e8108773a..faccb33b462c 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -3,6 +3,7 @@
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 #include "../lib/string.c"
 
 int strncmp(const char *cs, const char *ct, size_t count)
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index d9a631c5973c..901ea5ebec22 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -12,6 +12,7 @@
 #undef CONFIG_PARAVIRT_XXL
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 
 /* cpu_feature_enabled() cannot be used this early */
 #define USE_EARLY_PGTABLE_L5
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9d84bfaaf8fabe0fc89f913c9e420a30bd31a260.1606161801.git.andreyknvl%40google.com.
