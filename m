Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSEASP6AKGQE3SRFPZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 24A9F28C2DA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:44:57 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id s21sf7128156edi.6
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:44:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535497; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFhTWlsIzNy2RD1Xt5mTFQDHoC5O40gUIE4khcxgPrUmn6leLVOptq6m4DTzBv/0li
         USHBi0S0A730yVVP1sn9mL1076YCHhSZ32f7XRi6IYhNwjkY/3ODJKEvuGim+qDrY7wu
         Ub+HtwoWv9ExawzQ/8bKcPdGDG21P51mgWu6ZeTyhfKUAwczSjgQi62n9TEBwAtmVcvQ
         fkvTefnKGR4o4ezkP7N9WklI2Bxbf9N0K4oXVMbV82F937ijUiHhHjGbLYjS2YXE+qz8
         6CHw+/7HJLWNqpMHt/o+qrTWZXI5ConUPidf+7uYXm5etwm2+fpMaeba3VEhVk0SXRxh
         tgNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0H6nQ0+sU1G6yQkYx0bUFls8kb/3hbYPUH//+/it5pI=;
        b=HFKZAxx2lFW+uO1DybGeqreDGLYcsZfm2dTVFGTKvG7qvyYbdTZ9+rjTXEPcm0xQkO
         oU3lb5NU5kzf1dMQTYANFKPAkSNzUlPasbtMu4dvIoNC2zI96hKlbhwNGCN/1ZbvouP/
         rKBLmMzx0QZbasvEKLgZC2EyNKb6+A3JMZhJV+1WfcHalyU1UxbGvMwFzBV0pxDrlj6M
         ZX5pJv6HW8mSNamVkXXlJmAS8lzFL/bnAbdiG9bj9gWJODGwSjIPNy5wiKrnLUVpvcNl
         xOSm84Jir7BDiUZm4h8Q5qUsFBEWwvzkejtYgKZTV7UydVY/5TDnwFU4mP5v5TYTLYES
         h/EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VScTU+0p;
       spf=pass (google.com: domain of 3r8cexwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3R8CEXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0H6nQ0+sU1G6yQkYx0bUFls8kb/3hbYPUH//+/it5pI=;
        b=Ks/Gcioj7hAfF3bMMVKG7jy1jqYYzNAvqwJMAou6GAmb0QPJ1a0KQflVCqgotszFeF
         MMnunp2yZfKCHqyWtRCX0Fp50pjImGiFmutdzlFp3hrUxMPvUcrV+rH3kMdsBGvLKRXb
         AuROCit5dD+0EFrrSq6bloJDHRtfkCpeSsZ52AawR5hpHbt2RGwtr2Bal1BJfK/dhui5
         1WwjrnC2eqYR57HruYVXmvYNyk+HHkp8Wj++IDJKwxJBRe1PCU+zF7MShRsicKokdlza
         ydqiV8w5B91PqBskei+HpSe04nEnOONm/Cr6lonxs3eQyJRb7HTBLNkCbNPfpX6Hzz7X
         Uc3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0H6nQ0+sU1G6yQkYx0bUFls8kb/3hbYPUH//+/it5pI=;
        b=D0x2x3AXvw0aEyDeljjnLp2sO66hv6w4mb5L8PEyruR3KxDXcPHQcxUL0CjQXeL9pC
         5KmBtBy3V2TgiscEe9fN0q2tUpevI5YMa4WcT/VlK4ub4RufYXwKAGd6yQQ0sULvXSnI
         XEcm/c0SYEHjCD7PIjawXGtGHrsks52dy4QZsf4EsL9uVGunisI1mxMieAKC84ZSSlX4
         8+d/hxUwb6CmSaee3i0mUwzRMIHuw2QPPjBgNh6N2hlbmdb5s4YqDGtPBDQkdZr/wQQ+
         F6PvD18sKEKanBcqitpb5yAy6HVA+eYG0dEZaDyGP8D7QhDmLp/0VZtFqoOurRXUivFz
         fMSw==
X-Gm-Message-State: AOAM532/p+HnJpo8K3PeXjHdZy26iFLlB0Tlb+Uw9AqPu3yZVx+LyT3r
	+lV9gW/7kn/IbAq4hMr1H/A=
X-Google-Smtp-Source: ABdhPJzQ4nclwc1/i16evN33f1mImQ9JMkxi9IjuAmnp4QSsuw5hFAyOhljpzEkesIODpmnSq4OmiA==
X-Received: by 2002:a05:6402:b0e:: with SMTP id bm14mr17027112edb.259.1602535496865;
        Mon, 12 Oct 2020 13:44:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:848:: with SMTP id f8ls2343554ejd.4.gmail; Mon, 12
 Oct 2020 13:44:56 -0700 (PDT)
X-Received: by 2002:a17:906:453:: with SMTP id e19mr31060761eja.391.1602535495979;
        Mon, 12 Oct 2020 13:44:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535495; cv=none;
        d=google.com; s=arc-20160816;
        b=roRStcsYdYtEUhdy/DY1XNy1h3FgeZcKFfvjSqRpn0pdvwMmT9P+dOxN9tzNvdNTHG
         1ebcX5uN9IR1NZHCxtGzO4h39E6D1oF0H0/Cu29KDm88GTUyZUQRbb8AMEP5kwCJS7MX
         x1AsFrTqTeUqlHUvVCBpKWCci3G4k8ymntL1Aaryfp0pomnwe+wFQ8uEp5PUbYDhR47g
         Y1AdxTUTtxGXWf+8lIuy5TzPYM4YiaJs1tofAPzbu28Syg0TaTAORiN4KhCHPCp/WBIR
         yOyKwq6fBXEMCT7LyuKujiO7C0lfKtPXG9/eM6PB50T+5ypxdBxhQ287Mlk9u5F7x4Oy
         qxVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DmclJkDR4Qm5lsb7ydlGYlEQZpzVsyh6HqffasVR3Wo=;
        b=jgu6y959OXtowsYjka636ZfRrmnYGCLeT1PvA/H82QvZCL6TSnR2sOzN4VdDz2RpUQ
         RXijHwf6ZKew6lQqnP3w0C5lOOFBHvr/jVKZvBVfvupXWhzPyBrW253Mk/qgh1OTSuzE
         W/fQX9sQ5tmtuTA11ZDqh9oqDUC5l3gWflrw4HncyWNijbAnhfxLWHe8kXqOGnJ1QZuP
         c4R0ZCigY2EwKNNeeeD1pFrJinwn3AjEe5wgXN0wWdtyaLJGPWyOM2XJ+sKy2w9WI5Rc
         wB5xSXO7Ac8yy7HglRtS2ZjCj6IQg8+4oGXqLqtGIYk9gGyDWSyRnxaJwMDJrLvxgAw4
         tlAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VScTU+0p;
       spf=pass (google.com: domain of 3r8cexwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3R8CEXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id n11si141437edi.1.2020.10.12.13.44.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:44:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r8cexwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id k14so9097867wrd.6
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:44:55 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:5344:: with SMTP id
 t4mr12260918wrv.267.1602535495668; Mon, 12 Oct 2020 13:44:55 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:07 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <f861d02845a596328fa98faba825e06d712c88bf.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 01/40] arm64: Enable armv8.5-a asm-arch option
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
 header.i=@google.com header.s=20161025 header.b=VScTU+0p;       spf=pass
 (google.com: domain of 3r8cexwokcdw8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3R8CEXwoKCdw8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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
index e7450fbd0aa7..f27297ac70bf 100644
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f861d02845a596328fa98faba825e06d712c88bf.1602535397.git.andreyknvl%40google.com.
