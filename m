Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBEMXT6QKGQEQH7DCBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 99F092B282D
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:40 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id m3sf85711eja.9
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305860; cv=pass;
        d=google.com; s=arc-20160816;
        b=dYGxXdq2ZIdqln7mJRywky+OWxCX+iFofa7AYRvtLIxSvOcyxYKK+KjTitQANdgliG
         kPc9iY4UgqO9lwTlJodqyssSck2vmdsTj9Si2FE/PmjhxnS9EL85eHiMXO82S0ou3Sqs
         xO33EXz+HGmow/5hbCqU91LlSBwO8b21qvhD0CX2FdP5dTlsD+fHizMLBZrUGOnh7RW+
         d8bZjjnpB2FvNPQ0/New0FjTyCQitwY8I6mTF+f/E12F0y6nQJLM0R2eej/Diptf9Hz5
         +JRzLLZoc6z7heXzr7+RNeJ7EiYwEaboV6SPiIkviYLWFvef6Yl9fP0O5az/rZYoS1DB
         NloA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=W1hRFRErEjXBEU/wM9O+S/uVSfubSVlKlawwIENN2mc=;
        b=oAmpL27+ja8gDiATc8ZSuMU8jGh6Bgh/nHA9AskkMmlYgZjHmnb8++s+nKGIdGg6dv
         ApxgxHBE/y+GqiHiUUi7Jbf9tLdplohenk8/LecC5TnpF0+u7qSf4713ZImIC6iDe4rZ
         BYCJPuMhtfYxb+ny+ssmtR3LOan7NDOKVEGcJu/3mp+p8WBc+cfUldeLQ+yUQMIznfM9
         4miMAWjg53LOiR2Zuk1TQGcXrCm9fMCu1CMQe9BZtGBhUUq6OL8LyotMeQbRWUVk+ip/
         LfOVMHo47QDv7SqCs2sL4gcBFtxEf6WfCQRzwYIg5YWHWWa2QIVs72u27C4wNgf6dsdP
         yurw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TaaWdO3Z;
       spf=pass (google.com: domain of 3awavxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AwavXwoKCc4u7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=W1hRFRErEjXBEU/wM9O+S/uVSfubSVlKlawwIENN2mc=;
        b=tWQ8VInBvkkakH0QdwQqZiAdacb4ZfBufbV2CbDnDjNx3VwVu7fy6XvM9EtFzpliRz
         2WLmRyN2nsmWYI9V7ZFO1SqwHZw7yWbDnVyIGxkUFvpQ51sQDpghUBXFkeXp60i/IC/7
         ohloABSXWl+HKGLTRdHnxg6GTID9bokovOAbutNzPLJbSspF7pmaxPxRE1orNd+RVWVM
         oJBVfL5wEhhnNf8K5N6o0DfnUewJdbqeAAbIHgq7pC6Npebz3zjs8d4r3DTsSDGg2mPr
         telgOxi2eUXou2z8vHI5XqJh1op4q9K9jO7Hh7GVr0hSDPx1i4qTBfAI7K3BdMFDk8L0
         nWsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W1hRFRErEjXBEU/wM9O+S/uVSfubSVlKlawwIENN2mc=;
        b=i2rZHi5TUDARh0ZflANkhghL6+t/O0cPDR45XbfvMmu1Oz3La11Ox4Kd+qLdnaXtmb
         0Ha3WetWjFkw7pzdjwwn2HgvqnUrRlSuSrZaRhyvjD+Dn65L3URiU5a0onrZPw2tDQ4y
         hnuPz1Yngli2zOTwWtkERUk9yTlfT+coT52edsH3Ku795FW46SFH1CmZYaoFYd92hDxH
         Gi6cD7mmfmYsjHINq7g7KEjGjxdDva42GtdpFL/DOHCdUh6BGBlhz39py3eUu3NkDXnU
         zK4aw9jc4q348eTugHlrw8s7zSi+yzIAr/xuSXgw+fo8uFa6nWp5HoyVr7RuxuFRJAW7
         ocYg==
X-Gm-Message-State: AOAM533dDxyV52BIP5LYD9WLbWVJEodXcx5a4JD5ga8Z8/vjzdSF5XwN
	aA4E6bTN+ME7PN3UrhloDyM=
X-Google-Smtp-Source: ABdhPJwiPyM29xnFbFDDAiOkAleAFyBE1HJ7U5MXQJZG1P6zqbjOGVY2Vv21JaoKD74hUBh0ckJGNA==
X-Received: by 2002:a50:9e29:: with SMTP id z38mr4939241ede.220.1605305860399;
        Fri, 13 Nov 2020 14:17:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c050:: with SMTP id bm16ls442975ejb.6.gmail; Fri, 13
 Nov 2020 14:17:39 -0800 (PST)
X-Received: by 2002:a17:906:2a4b:: with SMTP id k11mr4329323eje.467.1605305859627;
        Fri, 13 Nov 2020 14:17:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305859; cv=none;
        d=google.com; s=arc-20160816;
        b=whDii5g14b6GCQu71A73GULos3j87ZwRRtOQVMY1PYAD8NQaHGvf03Rxq8c2QwLCL3
         mVQGUHNwkVU61fDPSOMwR0BAhx6nYQt96jHDWd9tWa1YSfnL/RpPMsaGSqIpsaeDyC6P
         GataUVhNoCgbhoGygeHpdD0NvNjJTnb6r+8L2cPQm077ae/9Y88KI+PQOWSZUvD5vN6+
         rVc8n3ViQr2Xfh4Zd0Hll4Rr6Gclf3eIqtzceZDZ4Pi1kO+XxLW8KxN0j7sCuvTkz/Cc
         re0/gYECDeIYbpWzmKDRL/1uXDHl0qwb6hf3xDOeOls4EV4xqptgDYjHHfKvkqaSceeG
         Gt1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=oVadbN3NqpY7ZnHAx+kB6EDsExDJuzGfxhHAguhdwUM=;
        b=TGodPOwuoLzYJt/K1AjfIgB1/Csn0MeekBqupSgTnhOIvHTcc/4332d5BG4vmOkVcf
         RvObDvurMP8QDXPhHdcgXPCay0lg5vsElNBGdssDtL1jk1VQxx7sghgomtBvvNhj8mHm
         WP3E8X/g7SX4xCGylInYZwH6mE7PdqgugdnZxrzdcssqKAy1RVhyg/CBEu8GvO4aOcYN
         eGyszwVnQFxwfx8rlScgU3ix8ldN7dcvSCf3ZD7II+Vr73oKM9/EMu+AzfS9Mx1f4S2f
         F/EIPjJgZO14dfZS284gdGxEcLtEDPidH4PBYzblhh4BCmWenprHL/wRosXW2XmdBn5A
         Pt5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TaaWdO3Z;
       spf=pass (google.com: domain of 3awavxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AwavXwoKCc4u7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id l11si314345edi.3.2020.11.13.14.17.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3awavxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 14so4718340wmg.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:ebc6:: with SMTP id
 v6mr5701672wrn.427.1605305859268; Fri, 13 Nov 2020 14:17:39 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:03 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <cb21c3e3100b37b4250cb35e109b1513fc8aaf70.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 35/42] kasan, x86, s390: update undef CONFIG_KASAN
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
 header.i=@google.com header.s=20161025 header.b=TaaWdO3Z;       spf=pass
 (google.com: domain of 3awavxwokcc4u7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AwavXwoKCc4u7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb21c3e3100b37b4250cb35e109b1513fc8aaf70.1605305705.git.andreyknvl%40google.com.
