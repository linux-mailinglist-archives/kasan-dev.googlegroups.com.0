Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLENXT6QKGQEWGRJLYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8583B2B283C
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:28 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id a19sf4012030wmb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306028; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQFfOI4NpAdz9Q/HuUTDR/brq75fN7uAsN3QwaCAOE4a324Y81dtwDEBvOuUbjBTW0
         EwNOpF7+mGHN7pQr9zk5lGlOvmw1h6SvS64gP24YciFusEVeSUG1pk8vPN67RvrazcBe
         hJBWCFkgeWfwGyOdCxTZfmWz5ji5xF5lMsGpGufGNlz0KYTjSV7skZudvsrMSNfZlR+N
         4jBjH+iwx2e5f+cGbMoMxKulHyo8W/jpnvLBxuemPq4H1KiSyXrtnUwy9/r77GWh80Uu
         8qsiwGDOJelVVwvMmo284osy77TEQYEYsCwPm/GiLbm25gVKZvGUrbLRj157nrormv5c
         7DzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4Hrv0Ii8DtX30e/vpaBX4eZj7kRKxIh5q7k37RkfiCo=;
        b=C8Yrzqd8rPO3C44zGGiyOD6XxZPQJzTIX5aRa2n6j5+GJGhrOEw2Q4e8ryCqk3FhGU
         wr6UgwPcEQzh/eicCLDzTo20ckx/XzXYK16KFLLmV0omw2DswahYNVXRNYMsS/BlTGtn
         q+zSorZfWen7ryKxJ66FYh5QnrzBCP13Vr9cHCcl3od3fFepk42oZDZGIQD6Noxikuvc
         3ThQj7UdZh1H1Z+jbRrJw66seUxRkX4H5jFqTC3aIKaMCRG/N5sORbN2pR5WX1We7Kmg
         seo3zEMFXjCEnAcyyhHav2JILvB03H/bJhzMV8SD25XaVk46RPqksdUFeNkdw+dJr2hW
         8o3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n+QZ43qt;
       spf=pass (google.com: domain of 3qwavxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3qwavXwoKCXgWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4Hrv0Ii8DtX30e/vpaBX4eZj7kRKxIh5q7k37RkfiCo=;
        b=NffsSj8CO4YNXAGHuhBRlU3yTlrHiRAtz0//FhVG5fC/YCcicaECuUGV+3MDsYtXHC
         r8glbolaYFfF39Eei6fJKm3J30ZVJjTUjiTehQ8DKVxjgsTLLGPBFKZjnzcC2C98N67l
         EylFxj+Zsowl/EsiiMUyAJvvjp1ug2UEaZAz0XKBPlqriHScowfqh/9/GJHpjHT/+Zdo
         8xAFzjBgWtMX81u9oLJ+Q/R9kJm0IJFy22K5gkuZar3O60A6vLsJCG0kcSYSyQs4kTOm
         gyonHjXIHmKS5z2szzwoak6XMaYutth52oySfBJCuPPF1vm2w6KS7IHYleEGF/wVIv6i
         Ggfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Hrv0Ii8DtX30e/vpaBX4eZj7kRKxIh5q7k37RkfiCo=;
        b=MvNxt25bFM+LYzEK4YLhp84reXSk4L+V5Mk1c9oZqEAJr2Dc3utML6e0NQiUEyFfG1
         8t6/Dw6dlUaIF6YTQGtbAvkWd2sWM2GVujEqEhU7La8IB3D80lWb0NP8tZxCJBEp7g4Y
         7zttu5YD4Mz34d5a4B2L8D5tg540KoIlv6nSl7AzXNQWGqO6u36ufmKlgjQ+jHppwIV9
         OgtDDJlWSY2qKI+vBmjyXRgw/xncarQGAGPHaj7lIVM1JTdiw28kmZtDrtu2Wyh5VjQq
         IAkpjgvxPrTXWSyPfcEYhCEcsJUm/G+Bf7lM/a/AR7JaNqsI375TRjByY+XuWDZhShry
         Edhw==
X-Gm-Message-State: AOAM5321bPsdsx5VMKaBnaWOn0IlFdcV7CZC/q/dOOymQ7eJFek8IZqb
	klkyiiPMUfA5FtR7JoGr6P4=
X-Google-Smtp-Source: ABdhPJzHJzIKk/zT06xmVyeoJscA+3haE41PmiBZOTXDY4dhNo+c3tUq9DzgUd6TsgLcFVCuIT1T0Q==
X-Received: by 2002:a1c:3d54:: with SMTP id k81mr4729910wma.144.1605306028339;
        Fri, 13 Nov 2020 14:20:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1bc1:: with SMTP id b184ls3726630wmb.1.canary-gmail;
 Fri, 13 Nov 2020 14:20:27 -0800 (PST)
X-Received: by 2002:a7b:c3d2:: with SMTP id t18mr4691755wmj.112.1605306027479;
        Fri, 13 Nov 2020 14:20:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306027; cv=none;
        d=google.com; s=arc-20160816;
        b=JrIOiIAUvwWPQPboqJUcGfQ77fgSMkmcHbxlfPXTi6LHv7P+q1EtBET2MtshDSMY4Q
         YI5BDvQjAENOCHZWOANdSBpXmKVkyMe0Xd2aiv1DkwPz5cUO/4ei2lwqX3DaUCE2OD6n
         OUUwavcm4dFZsG+lK/fRKpvP+cskvehaG7zG1zkhS1oCRoNgh/jAN/aCQI9Hrwkl7y8q
         gOqjvVv/295nElBXbBYhAWjDM92nL+eWcW57Y1b16S4JsWLDyRlC5KnjUiVv2UQt4Wi7
         XRK7gwuuUVuVjIvrLkTa5knmIIDnMwHZx8jJ/FQS+bGIns3jO1LA95lcRuv6SarJJLvT
         saCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=240iZR3W5frW7OjJkRyo/pFDEniTKiELI7K8tAXDIKI=;
        b=v74/+opqrPq5kz32tiq2uAqR4U1bJjznzbrmrC/n4FfcmB3Z+Lbq1cUXkV8wwm/VkS
         vc7iXGhYAnCpNmFzhy9VTqMOa0wfwvSauArn1xnWuA1jxDEpr5wl0OhOwcQ6QiVqDf3o
         B5PQeImmKBB8cqyLM8qVJud1p8SEqC67hrb0Fl6IK4GudV1KMpusOmFDnJfANcK1MFSd
         srWTaXHB/czcyLxKzh7vjhyyzL/uAjd/36aAjwO1/BPJ9G6hdn2MaqDsagBNy/zEBVIQ
         UttsQ16rXqpbiDOMEu3Hi3wB2BHzzDoav6HgOgNlHum/a8WFb80FbKemSiL3V4kc7yoN
         h71g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n+QZ43qt;
       spf=pass (google.com: domain of 3qwavxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3qwavXwoKCXgWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i3si319730wra.1.2020.11.13.14.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qwavxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id d1so5557644edz.14
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:27 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:b043:: with SMTP id
 bj3mr4104115ejb.543.1605306027092; Fri, 13 Nov 2020 14:20:27 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:55 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <89bf275f233121fc0ad695693a072872d4deda5d.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 05/19] kasan: allow VMAP_STACK for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=n+QZ43qt;       spf=pass
 (google.com: domain of 3qwavxwokcxgwjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3qwavXwoKCXgWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
---
 arch/Kconfig | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 9ebdab3d0ca2..546869c3269d 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -921,16 +921,16 @@ config VMAP_STACK
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/89bf275f233121fc0ad695693a072872d4deda5d.1605305978.git.andreyknvl%40google.com.
