Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQWE3H5QKGQEGIYW35I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EF84280B1A
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:12:03 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 23sf56256lfy.15
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:12:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593923; cv=pass;
        d=google.com; s=arc-20160816;
        b=PA9j4cSxR4fMCR0Bm2PYuheTG7rbE+A+QNVRypU53hJQe8PNRK0NRxwy/Pa5KMSqkL
         MiXiY3Pec6ny2nMMxEF/gOkPeGmsvtlo4okqSs+R5rF3240nl4hDDZnOMXWXkJcX83jy
         aNkxzgvE678kSUu33o5gJwZ0OXDOUWceXbaw18Vsu9opdhD/Ygus+aJUqgBwINdcmTwN
         bBhEMTqN41jFphk8jPtHb/58hS6jv6pNVtpriBoBPCEXlobCVKBq5tuMv9x3H11mdDnk
         3CMrT2UFNENO2ejFdvnF5cYffDqMWbQ2RIBTXYAwkoD/IBvAKlUKOMyIvH8Mkf29OUbj
         OKbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=AS5C+iTdD7K0X39EgZqCEUJWJXf5UBqp0EAExf2xutg=;
        b=LvYHN/4/6Fr3jMhikvXcAFPlHK5DHVVtKg4/i/ncmSihk7j3dTJ4Mkjqih2Gn5XED5
         a8sSZ7gQq3gTwLvZMyZtLPUCy2jQ+SMTiDyvR8oE967R1UOdSMr8xink43C5RPryVTNb
         7zipX/D4XpG7K+DbSXkwHg6QVRP4TbivelIqqArovHmueg16h7DPDmThZxBr2g6LtXBX
         3COh1ghL4B9DMJHj76iEfs457veRZi4OPuWJnu8lGY1kkCjUMYFy/yAvfqzdroj9S5f2
         I0G2XJ7/EwE7TGSGr9kO/5dSEcCnK+mr2ILwXfA6ayXnqf3OY8pY4r3H3GFgYrAtOt7X
         zN6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Z/TzKhjp";
       spf=pass (google.com: domain of 3qwj2xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QWJ2XwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AS5C+iTdD7K0X39EgZqCEUJWJXf5UBqp0EAExf2xutg=;
        b=NO6C9FE8yW5CTTYhDdj6eQdtgzwr+D4XmC7k/g6c9jQHS8dnv19dFzcRWF1yZSOY2H
         juxGYkEd5RjGyGEQXUlt1hD46n+8t2CtUeTF3SXupc01w2bqH9NC4lpdLxF49rSGiLNR
         dnDYaAdUojg0Q/zn3uxypfM4ELAsuJ0hp/pnbyXmnzayaIMJZU3oXoQagNtuUClaYIW2
         PJrYEpcJ2me2cYoMT1JohzjtOfo9V6lQ4XIqTAzrYu7UTHqcu4BmiknnhRXF7h92xpbA
         f7tupRJxqqJQ5A8yTp9C8vsED11tVPdhUpkANu6hNTb3TAh+YXGdJR7HKV7mXR96PdIa
         urmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AS5C+iTdD7K0X39EgZqCEUJWJXf5UBqp0EAExf2xutg=;
        b=i5G5phaUgWlTGtKMx8d4dOPgWnnlrYO0IEbUS1aJo+59LgfsYBZE8NpF2i9NKX1MGH
         GL1qy5VqYCd2HOCS35LN7Y4/tRJIg1UOEhAFfMJCGqaxIoNxmLMsgvJ18ykqh7CrYYXD
         dBIS7GvvacUZg1TN98bLMzZ6/2oWE3VsFAlzJrinp9p/LK4Do0V1GlDSH2Q+tT8bEKEL
         5giDZq/gWxQ4DTKL6+uackY40bc7D1nbdSg3/PHN2y2jhvnNYR75UFTSQmDL6z7mVNUU
         v7O0L23AYECS4kNnie36CHcd9ui67CnxDnK0JpWj1gRnUxPCliFnvV4GONxj4M0mNCGM
         1CzQ==
X-Gm-Message-State: AOAM530mKPzaaN+K03ln0ig65MwEsAHORD/RuM0KWBCIfMKEaRqTIKhQ
	ndMa4xs8+WqPWpqBeVCr198=
X-Google-Smtp-Source: ABdhPJzOC+7XPR5j4yh9FcG7YG1tiRNFN0HxTQUQwUQTOIIq6OiCbQYpLExl7seyZWY/PNCPZQTpBg==
X-Received: by 2002:a19:c154:: with SMTP id r81mr3461296lff.424.1601593922860;
        Thu, 01 Oct 2020 16:12:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9a93:: with SMTP id p19ls1066348lji.7.gmail; Thu, 01 Oct
 2020 16:12:01 -0700 (PDT)
X-Received: by 2002:a05:651c:124b:: with SMTP id h11mr3249397ljh.172.1601593921826;
        Thu, 01 Oct 2020 16:12:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593921; cv=none;
        d=google.com; s=arc-20160816;
        b=vwgUTZSOqOeoQTuyOiVi8MMhqTb/PmuTGRYTogDXuRJZTGRXCzmplp1ADMKLNI3iDf
         1lu+wJB9+6zd0xho0SMu9rpFlQcFi3VeGJCpbOxxoToqwDxCy/wSvJxBcJvl9QK2/fWO
         0CoX4OGz459L0AQQIDy3edgrhWQaKSPcRGyf1imJFnux8SCtalGSQDIQacRvI4PsYYRV
         Y87g9li1bI87og7olJTT6rczrj9t7hzi8byE3YyctZpEk6CLq1ZbwWJFVcAZ5EOg2K4m
         zg8OjS7SpsBMbMX1F9RPAjD+T5KXV9IWAxobY5TZ7TFxrepN0ayy0bcZPcAOhH/9ikJ2
         lvig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hpJpWYgCbJqCacKELcaZY87V3j8i77+2ePhmmcYZBwE=;
        b=oAEDVQ0SqBvrS767QNfDe2aGcAkXrIErK3AWD69uQirWCeaxJq8bN6SHpgHWeGHcFE
         Mu8sEP34G26byxoNsZflla+Otuisl375g7OMLMV+sOF3xRIGFplAaytSFPdBnHPi6LM5
         sRh66Hyf9vieH5vNntFFZKcSjEKKSIRm+WIQpyGULyiZHotbVyuGhrNxv2wIyscvFBrL
         QoCMPaQ1rfZMURDOrmnXzdy3pRusz/HC5wjLdcIXAfXO9As8rXa02mQ9IQ9YT0i+PNdE
         BolrxLcjbBspz54FAddWwjCowHAV6HYL8L1qYwOdtZt1DkOni2MET+6xjsitksXeAlPY
         wZsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Z/TzKhjp";
       spf=pass (google.com: domain of 3qwj2xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QWJ2XwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id j75si224353lfj.5.2020.10.01.16.12.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:12:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qwj2xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id t8so39359wmj.6
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:12:01 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:22c5:: with SMTP id
 5mr2354008wmg.34.1601593921173; Thu, 01 Oct 2020 16:12:01 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:33 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <2f2c30b9793bd5da7601043c9027d1b87ccb2e8e.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 32/39] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Z/TzKhjp";       spf=pass
 (google.com: domain of 3qwj2xwokceacpftgampxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QWJ2XwoKCeACPFTGaMPXNIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 9c73f324e3ce..cf03640c8874 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-kasan.h>
+#define KASAN_GRANULE_SIZE	MTE_GRANULE_SIZE
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 #define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2f2c30b9793bd5da7601043c9027d1b87ccb2e8e.1601593784.git.andreyknvl%40google.com.
