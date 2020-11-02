Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDW4QD6QKGQES3U5IIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A98462A2EF1
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:31 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id e6sf2398790vkb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333070; cv=pass;
        d=google.com; s=arc-20160816;
        b=D2MVC04smwqgzFW2/ksUqocce86yJleGgITCwjpoDyE6ZuvlvagGYqJHttfsTUdT7k
         tVs17g3qy/C0cf13j9J3h6vHd9DQQyy88/xZ+v6/Qgi7aRdEV+ky2K+RGWW93iatdgU6
         b1le17yO+A6VfoUwEtEZ8ATWno7if1Vggr+1x7xIEC92zP5SqrGZWm8DLEVWKpO1jsVO
         qtAyYraPSWd5IG3N1D9cCUvoIddHq7Zitu3fYb+Db7NpXNWuP2ubU7prci8uadAzuG4v
         N/SHOnCsTW7jcVldi4V4pVa3yN/YrVmYGwdqAug2Ht2rxIiBzoOP9cGQ+8syBIwva7Hh
         SG7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FK2AZzn4zWm61viz+MxXTKzW6glqr6eJyT4dHqkan/Y=;
        b=y3o+c5k9nnxKr9EXphKbrNDVF8auhV7OY4PMPzfeMuTR0+kPVKtlQxgmVMk/lszdrM
         O26elWSBnndQuHdqs3bh8M7St8Hei+cTD2jN46z/0XmW04+v0YyC27b/ul/rcEA42tTS
         ZZfZdL5WDdYIzzW0ByhreBTF3faruhbGWr977z3I1MADkoWOVlMuxizKuiPm6K9VBcfO
         mg/tKfWH8MbpyNX4d7aJwOsQeLzjtYH4N+d8so2wIWiUDgKQ5OstgyLeAm2QXC74offR
         8PI0lXixUvZuy1EdTBaaUekbHfatkjvGcNx1rOtRPufUUs/DSiQLSejKVXgZ/7HsG6Jj
         l2Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eTQoB5Zg;
       spf=pass (google.com: domain of 3ds6gxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3DS6gXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FK2AZzn4zWm61viz+MxXTKzW6glqr6eJyT4dHqkan/Y=;
        b=SVp1cq5gJx3NVwTEDcUlP5yz8v8CqEzHlcYL+RKboiN9uI6/1vabT4RklG1chYdnRE
         haX10Nf6xXT6kh6RX1jTXb02rtAm7KnImbKKSx06jopGpeoJImgkAb5kPosy/2bXa8d3
         ufQNkCJ9g1RKdDF+1BQP2g27uYzmFlOIfn2NI//f+wnzBKssNd5D1ZmsDe178hIlKs2y
         ljbonTSGU8R4Q712UykP7UmuCnXaZfP3pbnzOIJ3VizTzXELZTFEFENieezmffMHlP26
         A0waaiR/453eiG6gdCONaiMgRu9S6IvUIo6JRHSFgUvttaQBv0no/WwTH8u2oSkMIrsy
         OlOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FK2AZzn4zWm61viz+MxXTKzW6glqr6eJyT4dHqkan/Y=;
        b=oB1J+FZuvatecAU4PNYnznlqdd8hTe2Mx+Ymw4pUcFJ+kWXjubpqYxhhV7kq4h9XTM
         7IttBJ4MAZ7VcUNjefjVvUXjqGLUO4mzc+jnPtiSHdGruhyFAy2DC5Dy2G9hwpYi1d+v
         ybp2sii5TAXP+YGujAsfbp5VqaALfFsKLVXFdC9nZE1xUzS9oAo6Gi+dSPVmUP7FALJK
         1xu3TlOsbr4Q43uz5O75yvkPyfh++R0w7ve4I7Ly/b4AddqOZx8h5Htgys6v/V4DGChr
         vVFe822rVUCu5d2aaBiNfN0oliZrZfLuAaS38UM2ggOqb3b6zvHYkUwNqUsY9xye6tzH
         /MNA==
X-Gm-Message-State: AOAM5307ZPQX91ne78RtZoNvEET3RatggNo4/jbl7/6hZetQfrdp+Ghm
	mZepQRVOyahDDpf1qxpxlIc=
X-Google-Smtp-Source: ABdhPJzUz9xwGu44/IQCLdWSVU0Uzh898CpHqAVqJNh2DkFGCRkt3P5xgXUUiZuf3oaHT0fa6McjVA==
X-Received: by 2002:a05:6102:4b6:: with SMTP id r22mr5193354vsa.10.1604333070398;
        Mon, 02 Nov 2020 08:04:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4515:: with SMTP id s21ls724998vka.11.gmail; Mon, 02 Nov
 2020 08:04:30 -0800 (PST)
X-Received: by 2002:a1f:3655:: with SMTP id d82mr13800810vka.22.1604333069882;
        Mon, 02 Nov 2020 08:04:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333069; cv=none;
        d=google.com; s=arc-20160816;
        b=aUIWoiN+FM73oW+FqxyNCfNyH0y1toPPlGpq3fpwk6SVrNWgJZqxbjyjEVcNiF1Vws
         oN5bq5Rz0Mu3Uyy8orGE1OSl8jublVq8c4PL4yyrKuIq03sOJUA+9WbDvhD48+E2mDQl
         7pv6RomRoP8Jh+ZiCN6UjnSrcJLAonh7g473rEZeVp6XOS678LTA3Jf31y8tuQYlvS7A
         LcL1I+vYeYmsEOAzbdyijO4nEYH5pCSV4+LhFgCsQVeR//jp3Qze/+r/qs53euWVJNHL
         9OuFpmmcf8QOQXKLQMeeEzVkzU65UGNVBFzwxDFPy7fQ6WXenS6m5B7yuRv4lAE0MQaP
         hgIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=m6E33oJg1cT4FLFX7kYbKRuylbP2hj1k0453+DytozM=;
        b=xv/QWqqCBv9YohNRpJOsWmOqqo0Lc2A/vxeMEi+cCeYk7bOOM8G5/jDalk5VTySi4M
         ixmxNW7EVfeEAXgXRvU/Iy5n8Zh/ziG6YRtj1Eo9cvDgPlh35Bx9tpxFlTVh3F7HusqQ
         a/rfpfT4hemHMOSY/2Zm5TTmoSgvBy9oMQt0rlDc6lIB5t3RsPcaqEpu+yMRUFs3Uy8f
         m20+QQ+M/VQcaI9zvYfTlSyddrC7l569z0OECpkAPnibEosuBM5+2FdD1q2HPo6Upu6F
         jFXUepaiMZcc99AXlBSDYXCMAN5wbHJeZgwPpev4Ba+856unPJaepVE0nDEEEfmIJOcG
         w/Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eTQoB5Zg;
       spf=pass (google.com: domain of 3ds6gxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3DS6gXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id n1si489445vsr.2.2020.11.02.08.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ds6gxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id q18so5678046qke.9
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:127:: with SMTP id
 w7mr7030495qvs.3.1604333069499; Mon, 02 Nov 2020 08:04:29 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:41 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <d9ec144c1150de0cb5d69e8f204cf559af0ae2d0.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 01/41] arm64: Enable armv8.5-a asm-arch option
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eTQoB5Zg;       spf=pass
 (google.com: domain of 3ds6gxwokcewobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3DS6gXwoKCewObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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
index 1d466addb078..fddb48d35f0f 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9ec144c1150de0cb5d69e8f204cf559af0ae2d0.1604333009.git.andreyknvl%40google.com.
