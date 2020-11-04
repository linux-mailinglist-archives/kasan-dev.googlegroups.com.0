Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKXORT6QKGQE2LSEQDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C15622A7137
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:10 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id f28sf100104lfq.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532010; cv=pass;
        d=google.com; s=arc-20160816;
        b=YczAAKhtJPolzAY/TefQMrGlGgC3+y+Oebevireedk9+5ZDbw4Zp2RjTzBke9BAIaG
         h0CMJyK+SRn6+KqAxiShgbnpnPxaeTFMLE0Y13mYb/knDdfaK7K3eVd1tvNGICx5LT58
         AbJarUusbB8oUXToCYK1P1m7A81g+Iitre+eYib2aRDgHhWc0US7ataIs2Vjq2tZCJEp
         dcDcOtuDCJYu4p90aWlZPjohQ8MOg/ZZvmQ0asxhb66DkKWllnN38sMpienvyVsf/VBh
         43miEOw5wVa6DQzxIAnPVbXkQKu7QsMnA5MnsA/DVmnhx5ySC8FNyqmil67rR+Zp+nRS
         Hx/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=UGSZx0+JDALq2JR/dNRo2U9sooix+G/DjvaVz6YxkLg=;
        b=S+fHyI24xbQmyOtYh987qm6ZMY9A5+NWLhBWlfn+vrgj80bgp/3/jv8LM5gYPmuzhK
         BXprHOTQscrQgJTPscwbk0qAAjmOP6UVY4EnBgy7sRyaxec6/zjVR02R3lTDMoWJZi+V
         Jmal0pXgJFpbg69XFqk+gvbkMWcKRwtNZt2nePAjvQZHJrJzVuPDP4RGd2kvcAyJRPNR
         VZpGSRXJM9AJu8uy9/3R/w8zfQlOahSLA6ppjh2lM63pj85fKD1f5bpvqIz1zM2Xclq1
         u/cTg4IQe1xhT2qVhOAgSFyyFwvrC4/3Sx7YLl94e6ASfkeRur08pses4b6Hp4mplFk7
         m+Jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p5M7LSLa;
       spf=pass (google.com: domain of 3kdejxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KDejXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UGSZx0+JDALq2JR/dNRo2U9sooix+G/DjvaVz6YxkLg=;
        b=QXXpu7Vz/rafeDu7j/MahGgv2709bwbvMeVNxDOxxcfSBk+2/YuliKW559Z3HMq/09
         HlFUYjqqxx4CM0K4d0i/RVo1x6OXg33JEAi+sZhQqYOAGqD7o1uY7yIJaCi+wZT90l7Y
         LsZs4xiHEskmyNfDoE9g2ppDl9O7IyhbmqObQuojtP90WZschHbqnx5v5DaIWM3k2iqX
         FEgezYdmtNtZ0PI2r+OU+Z9U6Nie8jYGvn8qmGdDhYEqtT6eXan/hfub0qLOp+CNGehI
         Aoy7XGDuNb+q/DNons2QkVOke0aRVwbAvwBKuDQtJ27UCeVL8pHivpavD6UPNdahFAdb
         Qa/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UGSZx0+JDALq2JR/dNRo2U9sooix+G/DjvaVz6YxkLg=;
        b=iOZ21TYhdf6OG+wFbcpfq4Hf7KbwQsJfEwAHwb+ThDqGk8oFIe2HeAxPSCZzcnBC/N
         K7ox7sQ5epaL7I8t0//KgAPEOEfmv+Pjd6y8LNfzPE54DU4c859CalkBlOujO5G+o63l
         +07lk/FQ041O+dmuLPMzO5xFQj3lL/5Tx3AyhDxvjHyWZl1cnQS3qQhymxZzUQuJPIX6
         RdU5vOxw5AB7pIowo7CYcQY6RlMU9oAPXVbGdiTPKeqT2i51ESiSEuNn8p/aUBq4jjFv
         2Q7Av5FhdgN3DKBBAGqZl+0/xiEnwmPvqrRTZrJkFawY4tLTahOUuZKdKyWYaGFqsWbM
         Ml8A==
X-Gm-Message-State: AOAM5317Ogsxs8ZDT/taz72huIOFIDBCHku4g5MPOrxmOZlI6XjmREcO
	2uSsUnvE4BFIx0x0cxq6CE4=
X-Google-Smtp-Source: ABdhPJxR/PpHtBS6oCL+nRo2nr0qT44imzLKi/8d/ocvFKi12VjwcdkH0WS/sep8GR0RB40oVfPTCw==
X-Received: by 2002:ac2:5102:: with SMTP id q2mr15299lfb.391.1604532010370;
        Wed, 04 Nov 2020 15:20:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls644775lfa.2.gmail; Wed, 04 Nov
 2020 15:20:09 -0800 (PST)
X-Received: by 2002:a19:8b8b:: with SMTP id n133mr32602lfd.202.1604532009480;
        Wed, 04 Nov 2020 15:20:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532009; cv=none;
        d=google.com; s=arc-20160816;
        b=yOhz6otFTx+MXg+MrlqkclRRB4Pd9hjdxSEm08kkC3E4tkrf01YEd6VJS9KUzjs3Au
         z+Be4FhUkGZZffx9THsDVXd4EETn1sa3qQ8ZLPOCGSRFIf1CbTDAmA3mi+LqN7bfKyXf
         UI9tFP2/VhUcXpQpjRRnASqmcskrYhQFUawMIVOQP9kV1/g/4MyEbpthbz0ypvJruQzV
         xxQHtn4qUF8AouluCB9ypY88uroRl7WDjNxtQOkNmr24LiVXZSo1aFBOaxiJDIiebKik
         YVWc7fsyqfHUKqWha4W6XQPSFV1EDqrjNUutbaU3ZYTGc6goJfSUmAuv8zf2uaEUaNSe
         fpZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=FlydYZzkHHsNkirizC6EMfUHVnYCnfRojTwu8q88f10=;
        b=Ev+amFXRIObchXqLvWsjqA582Pi/GRnNwwpSkm83hLqPaT738o/e4GYMZvTn/lFMFm
         kkkoMfQVMjXwOCDUS6uIcHYTobRoaZcIRh2cWUkkPhK2m2hPQLGT0Q370Hg7yrj13M9V
         RLbqh8wweWgbVUiMa69xrPqQmGrYPEmXkjcFzLPaQCpGVgOLk3S+1or/4X+DD5nG1c5p
         c749HYLl1oJPBMEFFBH5o2f3n9WXxfvN3Tttd8CFdrLzWou+bkBBDARsCKjv5f1hb/iV
         S+/VF1+x43B0CHDY1xKmaCa2uZW6PR0TvizxyuMkNqbKE7jbif5VOneB7z1KRu8HWQYr
         843A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p5M7LSLa;
       spf=pass (google.com: domain of 3kdejxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KDejXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v24si116686lfo.5.2020.11.04.15.20.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kdejxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h8so45179wrt.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:09 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c937:: with SMTP id
 h23mr66523wml.19.1604532008922; Wed, 04 Nov 2020 15:20:08 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:41 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <c370778bd2f6b4810eaa2ba72cb3583fe05e1183.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 26/43] arm64: Enable armv8.5-a asm-arch option
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
 header.i=@google.com header.s=20161025 header.b=p5M7LSLa;       spf=pass
 (google.com: domain of 3kdejxwokcscdqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3KDejXwoKCScDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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
index d58b4dcc6d44..cebbd07ba27c 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c370778bd2f6b4810eaa2ba72cb3583fe05e1183.1604531793.git.andreyknvl%40google.com.
