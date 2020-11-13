Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2MLXT6QKGQEJMNY6VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id B7E372B281A
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:14 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id x23sf3210923vkx.1
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305833; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zo/hIFVEU63pdpesXJkf8R/iZMBRFwindZjQdBgIX1Q9wemqh75LbXexLGeeWFCVnE
         wd5xGZe74xzxmFVBGyP+FQ+FyohRglKLKlKocdKnqZF4H2y7Re1s7lwbGr/CFIG20Hk7
         5PlGCXhukpQD/MUkBEZuOF0VsAkATMqXg6ull26kNxFAerO9ob1ExGhtRZjFybP5vnCf
         OMDViiciHdZcfV4gdsix7fbw9WHNHDYrO28f8WIR2456AYXV1FkyRUrWlOMg8QeFSqzs
         mjC4LIrYGbRyMMg44zZyrWTdsgZenBDkPyHoSuungxF+SYwK07IsWu/GD35I8aljRPPh
         LuPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=aR6foFTM7yZYpBr8Qp6be6nAKCpCDrkiFQV2xST3Ni0=;
        b=M73VGG/mURxjju9ytNXTMcO4lIdXwU4qIs3foz8R8cpPOB1roWb5CljypadS7Cy1JK
         3fHqflyUFs9P9yjb6YwmE7UkqIzOilDrTmyTHwpeHWgLbvU90YFiVy0+2TkfpLYr6/AI
         boRf/R1kLg8s+FbMizAoKsVGUv1+2KjS9IlkYbSq6MbdX9ycDOsDkb2uI2lanHbEKIRx
         L2po3aEXc4caq65a+X895OkTyw0DgNBDlRPVNdSlyQt1ZTzkR1EQzAd+d0qof+lKk/IE
         oGafQaG0dlEAqZZwTyOAaDL8GXX9DaNLYUUvroYjsU1cOqwn+Eto5y2BBJFlZxdQ+6JN
         L7iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oZGcT35L;
       spf=pass (google.com: domain of 36awvxwokcbmtgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=36AWvXwoKCbMTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aR6foFTM7yZYpBr8Qp6be6nAKCpCDrkiFQV2xST3Ni0=;
        b=V6GCabhe91/q4YyIYAPFuqA+9T1bLCKbiW0m3wjkKYiWLJBIEWfOyGXx31yy5zJ63y
         MrNaerMm3ru7jWoe/JxeLvHypKDS6cx4AJLcilN1sy4y//A2O4D2uHI54zzYXt35x582
         XojDsbMPhwa8Hpby5HouDHV+phOq4DtvqOaT3gknQl7iWTm+Ncq8F3oN6mDHXjWqnPTl
         zZlTvcJgYvzE4oJ2YAVgWVSc0G9IrIwFslKL68BFVc6PdbHd3aV3AoZUPBmDSDQgVxPl
         jQR8nuwFh35oyPhbx5xwIKpZyzcBEeOP/Sh9DQmvhJ14ysycuRkUfz3B8jWgyIcwGCaU
         rlxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aR6foFTM7yZYpBr8Qp6be6nAKCpCDrkiFQV2xST3Ni0=;
        b=EV11zlVvw+r+aV4QU6f49pgWUkl6Wo8jTFsWNZVM74ichc6u61AxceqeGP/xuldncX
         WXJ2vh71wR8JYMZOU/WbGRjL+cMa8Za3MgPE+az4TTOL3W+S8qE4YPAKBsg+oMxzfwVZ
         U59Z3e8Pmpm/z8iNbtU//86WrBjzG7DkO7F9egPXMSWdssq2nwaO7AiJRMZfny33RU8u
         Yd6YVKkYPVDZo9GZ6YQjxi2it0468OksyvvWrIHWOmp3RhwX8lC8+YCPCRd4CO19sIfT
         HT27S79/jqqNXHx85e1w0zRNa2MyI4ZgBfli5yvJPP7eTtD6Dk2R4WSrOFXjLkkrx4JA
         7vNA==
X-Gm-Message-State: AOAM532F8cYikbvJmad/17umNzTxVaSdWZ2nne1jxH4PuYdeqTsn0EPc
	PgLDGZWFGo4ymygdueXRRK8=
X-Google-Smtp-Source: ABdhPJwdrTMk58VyMjx1wBXxEhJtAO551d2VuvkE3WqaBY6Gopi0F/VV8WC9Vt1MFwfUlPU7in1kcw==
X-Received: by 2002:ab0:6dd1:: with SMTP id r17mr3045031uaf.108.1605305833832;
        Fri, 13 Nov 2020 14:17:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f905:: with SMTP id t5ls1103741vsq.0.gmail; Fri, 13 Nov
 2020 14:17:13 -0800 (PST)
X-Received: by 2002:a05:6102:5b:: with SMTP id k27mr3231133vsp.11.1605305833374;
        Fri, 13 Nov 2020 14:17:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305833; cv=none;
        d=google.com; s=arc-20160816;
        b=aZUXyrKIaZvjppM5F0WZHeC8YGPw3yu26dY+zUUwqVDTs051oUZzx2VN8Fr/FKJQ/a
         TpGMLIxhBsD9bWj6v6PRFRdAKDh5uY8VzqXKMzrEnEEdJqvDZ12hnRujhKQCs0+hgcwW
         j9JUqdg2Feo6uI3zpAiPWSyXZT77pb7wC45uRkTTdiEIaePruA06NXrQskcBSwi0lX38
         AfKLHbUaYNZrn9XNUJ/rYE59aFGfzEv1VdX37FvDCKEYrXz5RKGZ1R6anzdAgpsVnwYO
         atKS3lqqahbfpxzIWLEA42MqXYsoGruFvKIIaCQ+WkhAmuhbkt9lTzXLz5/1ESPQ1WPQ
         E+6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NFGGXUBjg1FkirXtdz4QA+03+4XYK9SoCEIWQ/Car4Y=;
        b=wOJ3crM7TV6YfNLr5pm1TtiZnHe510MwveK9uX414Ei1Di88YlydU/kXNNxs8bJFHC
         Hx4fXHyuybT4dlq9V9QrPEl/ejzoPwfJutGGKI+uIz+q9GRVcoym+M3nsm6w1+Z9bEhT
         LZFe1dmaMt6MWb19M22cvZUMcUp4hWyVo+tnEDbTLde77bTtOoXJL+HEhZEVlgQNIk2W
         QMNVX+2EkIFTkCNUDOQA65NZ6DibWdW3X2FeKC7bGFfpUQGIL++BLkXYz2Wk140CJf68
         q+GgEC4SvGuIX5499r07611mSacvXeIP/dDzWW76CGLb7tXzPLYi2kEtGAz8/RVodez9
         Euvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oZGcT35L;
       spf=pass (google.com: domain of 36awvxwokcbmtgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=36AWvXwoKCbMTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id k3si978139vkg.3.2020.11.13.14.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 36awvxwokcbmtgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id x85so7609718qka.14
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:13 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ab8f:: with SMTP id
 j15mr2391938qvb.54.1605305832937; Fri, 13 Nov 2020 14:17:12 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:52 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <ba9dc492214fea3a88e05544bb0697b3237e743e.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 24/42] arm64: Enable armv8.5-a asm-arch option
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
 header.i=@google.com header.s=20161025 header.b=oZGcT35L;       spf=pass
 (google.com: domain of 36awvxwokcbmtgwkxrdgoezhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=36AWvXwoKCbMTgWkXrdgoeZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--andreyknvl.bounces.google.com;
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
index c999da4f2bdd..b7d1f1a5705d 100644
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba9dc492214fea3a88e05544bb0697b3237e743e.1605305705.git.andreyknvl%40google.com.
