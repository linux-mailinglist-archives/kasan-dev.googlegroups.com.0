Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPW6QT5QKGQEPNUT5WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E80D126AF53
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:16:46 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id f18sf1698612wrv.19
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:16:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204606; cv=pass;
        d=google.com; s=arc-20160816;
        b=xbMBHcvcI5sK+KmeAWKS5PybBrPNYw7gyQ6FxrjHjVXQuacqkBWCHlyajMF4kCVg5H
         QhRB0+4gYIWJ46WS+WwlqO522f+5hfllOqg/IcOwGPeOP5iRFMVmFEXCfFLA8JJ7DOyM
         XOvhoXTDHeEVwIo3a/CUtL8uVbc9EC5XzG0h4KRd/1X9b9BAc675K2cnzv7GagUuoxem
         20iSkmE08hYcrw0iGzYm70o1dNPu6oX7Q8mCysE2BauoFk7ssyiwa9doG0gkg+uC0UKV
         3aUB/d8nwDi0AAFunm+DdfsJPU4+tvBazhZcArt8xjn1/i5KnIuoD5oVkS2qn4SGtd74
         MJuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=RVrnNFWNWEKyIu3lnZXrLLay3eXp8QNmHJ4UkYUSXnU=;
        b=NRbfd7mCCMa5Kghmkr/43FEZd3wPIjiZkiY4w1qbM+L5V9o5w5pcUxiFCOKdzZC2jj
         aV6g3kX+1R96CHz8UQaPM1H+KWW+zXM9OxooL5whWdxswPeHhA+JUs6ymv7am1h9s/t5
         33UCF/TCfdo0scGstgkN/ilYFc8UxfMSGZ6uzoMTOn++IdsBXytxqUAnqjIpSVPFyUnm
         5UhPngKiZ8hMepZqEzF0+DMM6ZImcHdpJoB0Cw/Iee+8si5L02FESMX1Ow1oexCCSTpG
         sEmBahwgoZe1PVGi9TAD7uP+vLdDTN/A5r5OSXADI+g1i59qEnPaYn2OBe38I9Tc99Fs
         n8+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X1oFaYJ3;
       spf=pass (google.com: domain of 3pc9hxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PC9hXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RVrnNFWNWEKyIu3lnZXrLLay3eXp8QNmHJ4UkYUSXnU=;
        b=lK+6hq7A2IhmgVazYRTUWGXpqddbHLptc/osAABk+J6lSzTqZpEwcHW6/yVuopyFUl
         W7ev0cmt6UniOOGydhF2YrZpEYalnVT85jSIBeWXMqSDNVD5ocsLSE94tXR8VZWgQ9zC
         Ug1/Q1tb/EvqH2rpJhivkRgZ3PwxZ8gAmxBmDSTQvWt6j7h2I2KL23RiCrTQKk3nmwXU
         X3bsvIevJ7Jg+kF/u44/BkcTAcN+j+4TQXLxBzmhMp/7O/aiqd6Gcijp/rCuaoaKbsLt
         Xle7CJlKWQGpnyJ/JIfrl9+eTAsmjhPuMU46hIVEVA6LEp6ewnUrvdlDZkUEx6e7KgpP
         eO0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RVrnNFWNWEKyIu3lnZXrLLay3eXp8QNmHJ4UkYUSXnU=;
        b=ssv4ulgeWHFyGILIPtEvo+0bgd+DKjVmJqS7eAgNpc5/sO2vJ/BPxIwRcvV8MUXrH2
         gYBbK3zUm/AwG/5ceTDOgasi6pddb4OgL6+DOCddcbngAgnMlPaBivYvhC21yrlZWcag
         UFhUAfBmBeNHNd4y5KKGQDgoDCpzW7vYPdXwAZrw8r04AvjQzUGIO+lhQwSa8Wnpg67H
         wkEA8Oi2JIJKvl7eNfrPdx05kVRkQoH6DtQ2ffQb12J1vz8P0UZIng2LsCSEPF/k/6pw
         QBUmlTOY+4EywYzl7YD5EO/RYQBYYY269ZfHiWoiT3Ee/JDZRJWdWcTJkJCpKKiz+w3l
         6kdQ==
X-Gm-Message-State: AOAM5315ApVveQTdWUFA/u9r9tYvzUP7Vok0B/GGC1pxp+Me5YvB7gQp
	jKlAVpqEaA2SKdXtF4f6m6w=
X-Google-Smtp-Source: ABdhPJyqHtE3cDy+3K43XK5JsM22RWIn/7KF3WZwNl7r2gsFAGz7SmOFALykCMSNcbO4tcCyzY2lIw==
X-Received: by 2002:a05:6000:110b:: with SMTP id z11mr24263819wrw.426.1600204606665;
        Tue, 15 Sep 2020 14:16:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c768:: with SMTP id x8ls99912wmk.2.gmail; Tue, 15 Sep
 2020 14:16:45 -0700 (PDT)
X-Received: by 2002:a1c:9d07:: with SMTP id g7mr1319543wme.144.1600204605821;
        Tue, 15 Sep 2020 14:16:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204605; cv=none;
        d=google.com; s=arc-20160816;
        b=ChFox5NL7bg+XdMB2NiNlbSe6eo7hjpSb43j0H531De7kToYB+0kiDxRNhIaLKs0Sq
         jWkhyBfo7YjBl7o1g09OVKpZvAbi7rrGlYBoKnrcKu3cI+8fsxdBSS+HxFZ0abS7uQsa
         VhVReuWVD/BuZVOyms7KwMh3PAIyn/noGu6Hx6/Z6LaPWcPTcDSeEGLu85/RthjqNsGk
         EJ5ILkgcCJYJlD/m5hgDfS2DS6YM+KogMi13orVSBuO7HBFj2lROzIAVN2dhniNnuqKs
         KX+dGqmSQjACWM6lLnFejwvkYT7B8Gf7EZFvt9RxsAXGvcs24QSjAfIgVsSxyz6CTj7l
         gevg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BdONTOcHhT5ryTedju+DUoHznOnFqEEPqO/13OyviNc=;
        b=rRf9REFLt7DQsVFiMu5cMtqOC/qIIxMhIf9oU/a8QBitVDB9EFn0YSQrldsW4EXZj3
         Om5uzCe/p73pXI4hVzAEey4zENMyVr4qCXYl/1SRqr7hkxA7VcDrecvlkKsaBC9qtpVr
         ecpxCZXo+Wmv5P5B1BXDPW1aFTkkLndG3K81i3Hj3AEikCHIietx679Gki6IOnPNEpsb
         fbRcYJltPBLwQ99bVcO+VkMh+N4giu6/uCJfGgmYf9cJODFoQd6pzob6eZLvf1tvMeqv
         950udtN5uwjAGrVTqoD+QeFmklAV0RjQqgM2soR2lEGAXg/SLebgrHiNJqR6LZV7nDhH
         AA8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X1oFaYJ3;
       spf=pass (google.com: domain of 3pc9hxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PC9hXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id k14si407079wrx.1.2020.09.15.14.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:16:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pc9hxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l9so1687437wrq.20
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:16:45 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4709:: with SMTP id
 y9mr23509475wrq.59.1600204604330; Tue, 15 Sep 2020 14:16:44 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:15:51 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <af8284f93dc3c1a51a2db0d3784bf71bb5f348cd.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 09/37] kasan: don't duplicate config dependencies
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
 header.i=@google.com header.s=20161025 header.b=X1oFaYJ3;       spf=pass
 (google.com: domain of 3pc9hxwokcse7kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PC9hXwoKCSE7KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
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

Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
those to KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 11 +++--------
 1 file changed, 3 insertions(+), 8 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index e1d55331b618..b4cf6c519d71 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -24,6 +24,9 @@ menuconfig KASAN
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	select SLUB_DEBUG if SLUB
+	select CONSTRUCTORS
+	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
@@ -46,10 +49,6 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
 
@@ -70,10 +69,6 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/af8284f93dc3c1a51a2db0d3784bf71bb5f348cd.1600204505.git.andreyknvl%40google.com.
