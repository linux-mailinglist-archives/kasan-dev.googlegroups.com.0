Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBOGWT5QKGQEO7NHA7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id A662D277BE4
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:49 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id l22sf311517lji.23
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987909; cv=pass;
        d=google.com; s=arc-20160816;
        b=HJqWyebsD7vr0KV6VlKKpM3sRgXYd5aDaJedF1gl45W67dQk/vaf/4LoJSPIxEuser
         IG7817swuCtQhsVuNBYZXFJCiAjEFZY78f1YTuV8sG4a6eIzqqxEXRmXRDHk4TmGus8u
         YUDIiIjHiDyg0MqAxhBHUck2PP6SVcRyRAXXVRw4H8TYs8aRPN8U4bzH73KGkwQ+T3jm
         +mJCE12aVe6TeANInBVs8h64JVvd1JpQps2THIluM5IctxERsUx4ftcjqkSDk2DLYUAh
         3Nc3esxrFhF+YcuE6t86zPiroC02yAWwyTrYiUvzggbGExQy4xqCThkfr7w7YBDCfW6Y
         mMLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=DHS1Pgw5hg9UfHK5Yq7PTQ/VO7hKE5EXmzqrnUtpY20=;
        b=cDT1x/RxikqQEVtVjoQUYCGAQHt/mJ8xllVsax5eP9W8Ev6Wc+2coorR10V/SeByTO
         yJfId87xR7AQxx0UdyAapXNIdXgSrrVw0xB7LPaO1h4TnC8+UNcuXxdlNzPmyU6wzwwL
         DZ6FXzKcTTrvXbs/lzaNf/sUK99xhEV+PcxkVnNZn/r74rza+5JPkQ+466+hScw4euKg
         /k9LDH/6W9g+6YWLMibzL0iLrxRGEfpQpeY+aXYJx4udLvbOX2YAPQEwwPpl3p5LO73J
         frlRq9CxP1bqDc0JLnqfI5fRWpiAdAvUHufQbY9Ubag/KpZ8BrD5kMK4obrSSxjA4+WR
         lWJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XMZR6S1c;
       spf=pass (google.com: domain of 3ayntxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AyNtXwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DHS1Pgw5hg9UfHK5Yq7PTQ/VO7hKE5EXmzqrnUtpY20=;
        b=r7TrQVBqgVlJNvRyvndVOhYTQ8ZdI8YkNRFPO4MnEFhUt+t3EOafHhQRpJ9pnT6O0+
         RtYSjLSFW2X8GeppGw4SG8PPM4XTTH8u58W9DZHkaaohXZcU5F1HTaySosA3lxBaEsxx
         s0qdGyWRetqHnzr4QMYA7sNdm4GI0oElDEOkscCXOh8/NU/YoBO38nYz4GyFWfAd0dXq
         5BIpoEmyJ5Btg1x4+UWyYPa/mBoIkTfPt2niRUcYb2Fc7xPct3MuMTveUYzdxsxX+MDk
         HUDc82yuIaCAYfw4q8y8R1ZXBkGmr2bXss5eP5rWrP7ZP4dCZAvuBZJAvbyhnCuIlxSc
         U4Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DHS1Pgw5hg9UfHK5Yq7PTQ/VO7hKE5EXmzqrnUtpY20=;
        b=hddVEU4U4uEMKHJpucqlOlsNd500PMWFBZ8YNAsWgr9f2LvHBydXzKJyCytYMElCii
         Du+dm4Gj49VgqE9MhPgyHAGYjAEAAUTWYuoR6TQxMgPVPLA+KE0ug7yXKXJE2wMW08Wo
         SuzaqB3afh9OwOsD8CHeHWZkP4cumgWkE9iFyaCdH/3KJrJ1O9kaW2hX4hbVHf33JwPs
         Hctzlyfu/6vnICM3UTUCstr4F8OWsNBQS2gxNNK15/FA8rFXJ1K+ItfmXBGp2Z8YMpOC
         wFK7mYb7wWbcOdn+eDRsj1CbTnXIOiivq7pqm4j3j2Chmtew/IImzce2Mv+5JItPYnZ0
         8qGQ==
X-Gm-Message-State: AOAM5304+vhwJwBfOlBi5fliptl/1KPPJv9lF6Au4NbIjAsmnSJf4si9
	EUri0CHyO4D81zn3o/u/Xbc=
X-Google-Smtp-Source: ABdhPJzTQ23EudJW0BvOn1dfXusWD0P+wn6HRBQPTscFqR8Bofmew1Cg7vswqug9mDQjcEYhHEL5Yw==
X-Received: by 2002:a05:6512:5cd:: with SMTP id o13mr373984lfo.171.1600987909264;
        Thu, 24 Sep 2020 15:51:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls256537lff.0.gmail; Thu, 24 Sep
 2020 15:51:48 -0700 (PDT)
X-Received: by 2002:a19:8ad4:: with SMTP id m203mr368664lfd.183.1600987908279;
        Thu, 24 Sep 2020 15:51:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987908; cv=none;
        d=google.com; s=arc-20160816;
        b=qwb2RIScuHs6A4R21ST7zhy1ikLV4dSIsEQfvvJJMGmeX4TL3Z2RtM4UQ3Ch3VdKXx
         Rg1MpU6LGrb8vP5odCETOzSLo8PvF2p+vfj/q0w/zUWEcEsc6w1F+GS4026jrZEWnbjU
         9MMJMNSmntnbo6mLXQxE83L7BVxy0BN8/xNw9TCmsDpzImMkP+UB8CLnUVn9KklfaxXm
         cGKN/vqC6TPd2mut5FeLqZe94mo2mljdAkQkUjfkD8d78Fijg9Zc8p7vpCz60q+dz72w
         1FV4x3yOXsn/t5QJ25Q0h0o2Rws69kKclNqOnPbKhdfqs8nb4p+XaHeBj2GmmctOcL2f
         m0Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=CfInn+EsKhB4L8Pe7ugZJV/aGs/bMMxN4WZ/9r1ElOU=;
        b=cNA51N1cP2mWdQWx67QRmYcxLj+aFXU+IRoSRUqwLDLq2BAaZxORfAR0JNX55cQ2Pp
         gIHn0UUdZUvjv9RaXK8zDqfgVMl+YC+WaN/Gy+/RaegBlPVcilcg5TuBajJnUCRM3ubn
         J+nwy9A19YfUvwxxBpQlG+yHnfGhUu9mLIZwiRzPYivx/kY3en26I8Ol3bFotRy5n124
         V25y6mAARbN+bZXQgCEZj9NhTECnkfvtVN5YTI8qMqORvWt2+71FJfxo3M0MFUDMVtMf
         tIkn8yyj2w7ukVWH/QKG55VolXW+Z1iXTUVvuTZaemPv2IvQV7+hTE+mxA9AlRnOEgxV
         nZ7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XMZR6S1c;
       spf=pass (google.com: domain of 3ayntxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AyNtXwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id f12si22664lfs.1.2020.09.24.15.51.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ayntxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id t8so273764wmj.6
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:48 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:c5:: with SMTP id
 u5mr864994wmm.14.1600987907480; Thu, 24 Sep 2020 15:51:47 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:30 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <878fb755aed45104a44f2737d4244c14fdd1b9cd.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 23/39] arm64: Enable armv8.5-a asm-arch option
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
 header.i=@google.com header.s=20161025 header.b=XMZR6S1c;       spf=pass
 (google.com: domain of 3ayntxwokcf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3AyNtXwoKCf4gtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) which
is an armv8.5-a architecture extension.

Enable the correct asm option when the compiler supports it in order to
allow the usage of ALTERNATIVE()s with MTE instructions.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I172e15e4c189f073e4c14a10276b276092e76536
---
 arch/arm64/Kconfig  | 4 ++++
 arch/arm64/Makefile | 5 +++++
 2 files changed, 9 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e875db8e1c86..192544fcd1a5 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1600,6 +1600,9 @@ endmenu
 
 menu "ARMv8.5 architectural features"
 
+config AS_HAS_ARMV8_5
+	def_bool $(cc-option,-Wa$(comma)-march=armv8.5-a)
+
 config ARM64_BTI
 	bool "Branch Target Identification support"
 	default y
@@ -1676,6 +1679,7 @@ config ARM64_MTE
 	bool "Memory Tagging Extension support"
 	default y
 	depends on ARM64_AS_HAS_MTE && ARM64_TAGGED_ADDR_ABI
+	depends on AS_HAS_ARMV8_5
 	select ARCH_USES_HIGH_VMA_FLAGS
 	help
 	  Memory Tagging (part of the ARMv8.5 Extensions) provides
diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
index 130569f90c54..afcd61f7d2b0 100644
--- a/arch/arm64/Makefile
+++ b/arch/arm64/Makefile
@@ -94,6 +94,11 @@ ifeq ($(CONFIG_AS_HAS_ARMV8_4), y)
 asm-arch := armv8.4-a
 endif
 
+ifeq ($(CONFIG_AS_HAS_ARMV8_5), y)
+# make sure to pass the newest target architecture to -march.
+asm-arch := armv8.5-a
+endif
+
 ifdef asm-arch
 KBUILD_CFLAGS	+= -Wa,-march=$(asm-arch) \
 		   -DARM64_ASM_ARCH='"$(asm-arch)"'
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878fb755aed45104a44f2737d4244c14fdd1b9cd.1600987622.git.andreyknvl%40google.com.
