Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKECRX6QKGQEMT5VDIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 404E12A736F
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:49 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id f28sf142994lfq.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534568; cv=pass;
        d=google.com; s=arc-20160816;
        b=hH4IGJ9X43Fhj6GIwxpcp6FPV1T8qX7vbeuIEMwedlW6S9kDXuCo8JOdPcMcGYn457
         S0c31hM2vymDXy7Id88ThRji6VW33sQV7HQ0CgOZVnJm4NYXMbTRYygDsgqIi79dGG/v
         HkvwAJ05HxYfj1qLrb8aKzQKWw6w8j9/SRfkYsphtSlLk8FruyorIqjV0XzlAad+FSs2
         1ii9nBAA9yXhSCXA0jvFv6E8D0gw4JKLBUVdMjESUpzU4+L7mSEdh3HWs2BYY4IUl0W9
         H7O/u4gPlQV1SGc1FKsSLS8tFRM9EGTpxPvSIv3DOebIGZTznKQo/XDkTU6EWE9cBmxB
         NNHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Q9M+5tn3aoQxzGoF9E265Ua8Oxpd6G7ZFvxTUMfATew=;
        b=k5a5cZoOg7cEMIckaldQQv/Gh4bntlvW3JME6XyV3Wm1mW8c3zGvWs6EXaUII+TS+i
         aBHDODoQtIYNwoierMk0I4rsFzywHyQAyWH72G31sDS5JTSwnkfAIn+ixvPE+lLAYeRl
         OQmVx4vSeHIpgY9t1iOgdTH6aG592gnRg6kdENSeMybsylyZmiTnPUio3TugRONwy+HF
         gmDqT64Zpx5/eJArGW5ksoXD0Dvm8f5JOlbxLdVPXLAZ/l7EvwRJa558hHS014XrvqnS
         yuGAwhOBgIkrgyPOBEvzrG/HO9sDxPC0B1W9/VAKExovvkNzLxPcLJPLX/Nlqr0+d8Zw
         naGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o1BHF1EV;
       spf=pass (google.com: domain of 3j0gjxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3J0GjXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Q9M+5tn3aoQxzGoF9E265Ua8Oxpd6G7ZFvxTUMfATew=;
        b=VwjbuDMwNAaQcMcXt0LrnDkZtwACv9c1ebYH748xw6rN/lP4V+q28YaxtbW0AI9+xM
         vQePnTgMzPKRyZnknL4RwrI+frqfdReXNcVL3vjYyBoW0RIBxgIPiyrYV6bXpcPu2w++
         2msgrnJ34mMT6PThi743cFJWFXQS90YcGgBmQj6wQ4Rq3azDbxtbkARJr56sNjruvUcp
         yEujp7WbCa2dTCgpqOOFDdalp2ypeiSNkbVEeqZjwM4yV5EW0/TkPkyFnKuld5PSTmHS
         Hrg4UYrSFf3oOxWnOFYqCZd4+9Rkv7zxzrWXR1iZsqqJQGZswkh8WEWnnmBwIFcvL4NU
         WBGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q9M+5tn3aoQxzGoF9E265Ua8Oxpd6G7ZFvxTUMfATew=;
        b=i6MEwxXY0Kc6v9J2ED0GhNx8uWkrzmGaLRc1ndgTqrIPAIVOw9+jpDItS8Sz6tKWmv
         oE24iyGj0irwpDbID0aHrUXxiTNfb3ghhuiHri9cEwMu4wJcmu94jWpa/ptHf+IKLicg
         Bsdgr8JcvHNdu+R5CpOC/cuostOL2naHMSlKTJpB/uV6EsqvO8VyZF8geSzf19XvZUvO
         dZf4JX0SlBjHgy5jqLz/YGEwIidfx5H5/EPwCG2YT2n+BnjaK0SHHD7wbmRJPtFlKaXz
         QN3mfiYHX1kjSZnIKUIYyuSn/igfkpgOyPCRX7QO0ylw2UIOkxOb9aj9cnPf3GB9paTW
         Zb6A==
X-Gm-Message-State: AOAM531v5XDlWywiY4QoyWk0dRA+bYcHZvbz5Yg2jFwPWE1EuEmxUG0V
	3tRFSDlYyvwV56Aw9blerdQ=
X-Google-Smtp-Source: ABdhPJzj0g8G+0REZbJvtlQVQNpzz6jaJax2W+4m3p243t6mXOEQv0Gl9a3kwk/Sa5ejhsoeJusXWg==
X-Received: by 2002:a19:80cd:: with SMTP id b196mr90445lfd.118.1604534568837;
        Wed, 04 Nov 2020 16:02:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2023:: with SMTP id s3ls2305776lfs.0.gmail; Wed, 04
 Nov 2020 16:02:48 -0800 (PST)
X-Received: by 2002:a19:58d:: with SMTP id 135mr67219lff.139.1604534567978;
        Wed, 04 Nov 2020 16:02:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534567; cv=none;
        d=google.com; s=arc-20160816;
        b=yUmnUnPaj+7LmXoEC1KimbxwOi2R/XyC5O3Bv1pRSkNI6AzTWU7T/mX8F+5wsrpTGt
         B20hpbCPYYPcRfSIXcu91432f6ytywZJBVBLE//akwjHyc6SWWD++4TMV44rLgM+NPEt
         jFycl4xYVrBbIleBnmIyx8NL+echZMFeWqPbkjnGa6dX4nNhis2pw44vb8pIdMZpl1jN
         pn/L+0GkZh/NcjeDZ9rpu6z8uVNRyPXSyqNNtttL2f6R057Z6fDbnZyRPGUSM8Pj5eFy
         Tp4lPAbA/Mr5k/boWu3s0aKxA9qYOYiZm14cPIQFR5yHab4lJTp7aOtwfAo6qfCTxeu/
         YDZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=z6j3WUTg8MpmEPLYdtLimxVBLIkxxjwsBk3bJk+FZ/c=;
        b=HI6EonRbd1Go+ehYTehMEWMJO4YZ0waRGf2hvB/EcxIn7215xnXqlJEtRG5A9Zh1uL
         NL6okw5BXfAK39+O+3AauAOyMp2gM4l1xkEaGZn+n8inxXHamM082R3ZRwEVtgOizt1x
         RQStzlJslNgdSHVzYDIkhkWLU36I9S7CuJNnLssSOxB1+FFkB+JAG411cDZwKBT9euFO
         p9padhAQ4zfGj15nme68LjO7negLytM+19F6uJfAMnLmyrUXqj6zJ4JWklAtwK32gsWA
         MCQ6mGB5MyLswv+BF7Jf1chIULMM+NAszZV+p6tDUF3RGclVeejLHN7UanHR1yaQTrij
         0+xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o1BHF1EV;
       spf=pass (google.com: domain of 3j0gjxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3J0GjXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id y11si111220lfg.7.2020.11.04.16.02.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3j0gjxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o81so2155wma.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:47 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:a315:: with SMTP id
 c21mr514082wrb.272.1604534567466; Wed, 04 Nov 2020 16:02:47 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:15 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <dbd82cbb24bf5875b465e0d75568916edb8b92ea.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 05/20] kasan: allow VMAP_STACK for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=o1BHF1EV;       spf=pass
 (google.com: domain of 3j0gjxwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3J0GjXwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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

Even though hardware tag-based mode currently doesn't support checking
vmalloc allocations, it doesn't use shadow memory and works with
VMAP_STACK as is. Change VMAP_STACK definition accordingly.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
---
 arch/Kconfig | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 56b6ccc0e32d..7e7d14fae568 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -914,16 +914,16 @@ config VMAP_STACK
 	default y
 	bool "Use a virtually-mapped stack"
 	depends on HAVE_ARCH_VMAP_STACK
-	depends on !KASAN || KASAN_VMALLOC
+	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
 	help
 	  Enable this if you want the use virtually-mapped kernel stacks
 	  with guard pages.  This causes kernel stack overflows to be
 	  caught immediately rather than causing difficult-to-diagnose
 	  corruption.
 
-	  To use this with KASAN, the architecture must support backing
-	  virtual mappings with real shadow memory, and KASAN_VMALLOC must
-	  be enabled.
+	  To use this with software KASAN modes, the architecture must support
+	  backing virtual mappings with real shadow memory, and KASAN_VMALLOC
+	  must be enabled.
 
 config ARCH_OPTIONAL_KERNEL_RWX
 	def_bool n
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dbd82cbb24bf5875b465e0d75568916edb8b92ea.1604534322.git.andreyknvl%40google.com.
