Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOVAVT6QKGQE2QWLQPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 540FD2AE2D0
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:11 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id f4sf56329ote.15
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046330; cv=pass;
        d=google.com; s=arc-20160816;
        b=LMUpnjbGOK0dktEgqlFBmamiz79pYU6RHaUTSWY/vA+9AjuUPydXTjfbhuPaRiXDh8
         Z5gPL4HRdJSvHsydk6ixgXJGYGEpoRe8IpBqQVNjfGEGMv2ZKPlIOE1zww9TJ69QsXYE
         VntxaDJgYwBwWvpAFy+Zfm9EiLkyB4BKDSNJGE8ibYr0TD6GDzBoUg98Ubos+r6ZHk1q
         5wRnu2QlHK6TQP2k/IphRZZKw1/Hcm61dtD4Zk7Tfeio8e0rVXwvl6jp48LqQDIvmEgK
         B6Ue80S3y0bOg0RJIXDOWQY217jvxwVCvGXPELScHCh+Am4hHErzCr4/Vc1u6NxD/7oT
         zmyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LTPy7r5qqjb2vJ8nOWXpSXTknE9VDkFqyFgDGaBwGAo=;
        b=ShzbXm0kRmkngyT9stMo9GZxwtDsdziaeeKeavIVwehFp3uSi52CwgBxCKs8p/7gxU
         1/cquyRH0QGAQun+LDuNvvvMJrYTvxfFsFHNuY/W4HZDi+H3VE6cSC0SgqrJyc9hW6pA
         gCgyG3jtNBnTGA/z0T8ehVTVLADnDNhzjh6GA85fhsdkpLV3wBkDqkqD/KeOBaqEDtHX
         9Hq95dS2SKGvAPDrjmbg6L36wRLEzwfKCKigVGZiCV4iqOAwfG8TUG+nGsor8AAkbte6
         rsxw4KSIOxZ8Wa3PfSOhTfta2mzVzPXrhivNacnI3iTS9J1u6w/kbctDBbQCe1tFlZBA
         3Y/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HzxJDWjp;
       spf=pass (google.com: domain of 3orcrxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ORCrXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LTPy7r5qqjb2vJ8nOWXpSXTknE9VDkFqyFgDGaBwGAo=;
        b=sdg4XtaPBSkhg+XJ9bgFSNcF38RbBb9/UdaU+zYkEOFMWao6LNBOhx7Rt4aEbrsaMQ
         ouVxRTjrgix2bPQj0JD2X6ApnPIkPYki3BCjHmIDGbpDcb/RmzMhOr1eECyBplN6GeSk
         zBD+a7+cd0/8zOB4CkOVLMSFDmsZ64a+t3EGwv95NWj/qum9eqZlTIaP/4YTFynnv/HO
         irw7iHCUIJYRM8/UsVw6oNVkMi9sSZgsBrhAhBBDjJq99TBd1694hkdvJZ/MH0EwzXQL
         PqNKLq1xHhOSXbn1M2y81sH4evFniWC2UmommuPrmqxiSUTK0R7MdgdYyP8mGzW7mY8o
         kmWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LTPy7r5qqjb2vJ8nOWXpSXTknE9VDkFqyFgDGaBwGAo=;
        b=ZNnv6bjqnSO9ftMqLZYuLYdkozalpjXu/goUfUMeo1bImbw9mtpTMfUx2gsmczXUnk
         6VzYB0DDPffbdcYPfc9jthG4e1z4pGFYyJ+UN2nL7DDqBVzhDJMGRuQmx8Agru230RHH
         gUoeT01qqt1SlPORZ5BZKKpTolJ/ANZv9wGaFYr3xBQgXnrtaW4kSsWQXp8z+IlUu669
         YW4qYlbgIphyD8954HiVXXjGcPSs1l9Jw0WL8LSENXIM1xy9UDjvD2fJJERcZywz3f7j
         C6bU+AEYV/GBdjsiWHCLmrswRsnoZ+zT0pd6hlSapVV1CNMyLZ5zZFxVU0bHwhlGY7B9
         THTQ==
X-Gm-Message-State: AOAM533kfHzAy5AW5D1h2z6YlwE6DJKFWZiCXDWXkaYtqNr2SiXZnrYY
	Xk5AmdL6AkZfhdVfZAp9Q8g=
X-Google-Smtp-Source: ABdhPJwDf2QOZmBIHAn0N7W+NXgCb586LKdmyUYKZX3DHpIKBmH0kOa+wfQj0FwmBGp1FujOYbOcrA==
X-Received: by 2002:a9d:27e8:: with SMTP id c95mr15556185otb.262.1605046330143;
        Tue, 10 Nov 2020 14:12:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5f11:: with SMTP id f17ls3433157oti.6.gmail; Tue, 10 Nov
 2020 14:12:09 -0800 (PST)
X-Received: by 2002:a9d:4c92:: with SMTP id m18mr5895466otf.248.1605046329793;
        Tue, 10 Nov 2020 14:12:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046329; cv=none;
        d=google.com; s=arc-20160816;
        b=RehRYa8IRpzHyFqpnanobFlUEbydSQkh9dt8etIYjK+ZZVDc4JGbd7UQYxSWHWQFCG
         PVFMbBTWyiHFuKnGBltGQFptc9Y3X3KV2bKF6lpssjeAd1Cik+xUa4PX9s0IkIeA9zfl
         KG3na04P6Lq9yya3n2MP3fRwpxt7poybRgyn9EGeLOl5dgsmwSKD2SiOv7C1XUXm343/
         EWtG2YVtdyb9pui+mXapGuTZLTCtq1spNb6oU3CwobPxlci1P6IfvOYv7cccX5mGPXow
         +9+ECuNizU6c0SjevMKTQcoBuQAjwu2q+iLDkJ0U4ds+gdjPUSN0oUOCi201n1njN+54
         asWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d0luRNisG3KRkUWIJpA+kozZ7VZYZZ7aV9TEVeCXzwc=;
        b=i9Kni89waLrxf4PSiUZw7zP3MRYog4vtiOfQM+kT28MYRDFfR+gyRxuFqe9W8eOp4x
         1HUu9xrjBuEOtER0o8qFqEIv5IiqZ/3lVpXf0iGXczf+26SO3yk7ptKkRImlMw1yW+AT
         ZmAlyuiaFQsCfSHMM+vPQaDDcAAUFMtao8sfizOSVuGXbmItVysv3Q1SiJjcVZ4p1CFc
         2xxqCXEw+kBh1eAFTo7RMsF6l1MTnTYx82FPNr1D9htZC47V1On136/GkZCaXXpbtZYQ
         FXWg0oGgGOfOBaXv3BUSyQoj7AtWeq/IFDqLM2q7t5h3BLi08D8QguBtE6mdNu017Twy
         8iEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HzxJDWjp;
       spf=pass (google.com: domain of 3orcrxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ORCrXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id e206si6478oob.2.2020.11.10.14.12.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3orcrxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s5so71286qvm.0
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:09 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:90e4:: with SMTP id
 p91mr20380986qvp.61.1605046329251; Tue, 10 Nov 2020 14:12:09 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:23 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <e7f69b87c86266c3671ec137f56e7740890155d3.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 26/44] arm64: Enable armv8.5-a asm-arch option
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HzxJDWjp;       spf=pass
 (google.com: domain of 3orcrxwokcqokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3ORCrXwoKCQokxn1o8ux5vqyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I172e15e4c189f073e4c14a10276b276092e76536
---
 arch/arm64/Kconfig  | 4 ++++
 arch/arm64/Makefile | 5 +++++
 2 files changed, 9 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 25ead11074bf..c84a0e6b4650 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1591,6 +1591,9 @@ endmenu
 
 menu "ARMv8.5 architectural features"
 
+config AS_HAS_ARMV8_5
+	def_bool $(cc-option,-Wa$(comma)-march=armv8.5-a)
+
 config ARM64_BTI
 	bool "Branch Target Identification support"
 	default y
@@ -1665,6 +1668,7 @@ config ARM64_MTE
 	bool "Memory Tagging Extension support"
 	default y
 	depends on ARM64_AS_HAS_MTE && ARM64_TAGGED_ADDR_ABI
+	depends on AS_HAS_ARMV8_5
 	select ARCH_USES_HIGH_VMA_FLAGS
 	help
 	  Memory Tagging (part of the ARMv8.5 Extensions) provides
diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
index 5789c2d18d43..50ad9cbccb51 100644
--- a/arch/arm64/Makefile
+++ b/arch/arm64/Makefile
@@ -100,6 +100,11 @@ ifeq ($(CONFIG_AS_HAS_ARMV8_4), y)
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e7f69b87c86266c3671ec137f56e7740890155d3.1605046192.git.andreyknvl%40google.com.
