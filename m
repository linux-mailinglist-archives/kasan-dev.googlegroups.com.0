Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUVO5T6AKGQEBBALEHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9011C29F4DC
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:11 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id r83sf1538828oia.19
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999570; cv=pass;
        d=google.com; s=arc-20160816;
        b=jvffeHnxJx079YgdjOFstQ2BwQzEjG8Bof41K4lyq4kI5pWZCr49WzpdH5LK/pk45P
         hiu8tOUIPcbOzURWkTExiXz8F5mP/v5D1FJd6bTR4m7wsUv5+1ORejEsu35CWnG46pgL
         jpBuNvKB3ojQ8BANfQa5/4n9dI1VBQBgRe2u45FbMY+TS7yrUaWgGv+QuiB9RQo9RPYk
         +rSTQqaWxLhMKQAXCLC8GTuhWcickV1qzBRGJj0msNV7S7drhZ70VGlOph4lShOMK2VD
         hmcI+S4LwE9D1PISu+KucGhoCxj4oRkTIjcslecC3EsO97S0bqxjOWwuCdybLpjaY7ke
         WleA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=86FiOeZ5mE6bNHu8Tq9fO+5frKacF0x5aQ+pwnyL6mE=;
        b=otfnyoC0mUlAWw907+R1o4El9iKmc1tDCc4RjzEyWKo+Z/uZ1YzTZ8W3dqtu2MULqj
         eVHQualvekfNMZVYqqo7AEsgKJeK1pbbFysB3zFbxP++hr5QWQ45hyZoDYRSw8jhi7Ml
         LsNqBOBy/Q3c5UU991o1j6jssBKyKh4Kjzib/KbeTtn7aziS4tAezTtGlSo2SZtyX/ZT
         bbL0f372A2tLvove3jy6IidXPA7ukrA0uFrLjY/C9lkjCtyLO72zerbOzh6rNCtTOW/a
         y/+sJpMm/Tz4A743GsXVy/N4R0zhKwLSzZJZRsYGLkVgMerNKXtfBPMHXNdmTpHe+AdX
         Vzow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gGdqNoDG;
       spf=pass (google.com: domain of 3urebxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3URebXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=86FiOeZ5mE6bNHu8Tq9fO+5frKacF0x5aQ+pwnyL6mE=;
        b=EWWQAzIyHElX2GSr2157D0NeYGLlEBg9TkChUytPUMmJK5LnohRTLg4TwNzW8kxHJE
         Y1rYByxf0DwJrS613GCh1dHOW5F97o2QuqWczn6eyE7H9wszAQSUcyZQsDfkFHuvD4L3
         6TZcV5iRZV6FeQMUFkJ9YqpH6V6x1Uz+Xe91XHGlpSo4WzLg/XID34/fM398p9kNdpt3
         x+y/Sl7w4Mrf7YAlmdFhSItgSaRibW55rFrP5tpA6SwcNv90MF5iyFmkd+CUb9cpGZUN
         aYBgfHkicdZHHDTk0wizskBgpzjCeRShG0lee+ebZLBDysOM/LXT7DSeKCQBkQrM8GJ+
         y1xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=86FiOeZ5mE6bNHu8Tq9fO+5frKacF0x5aQ+pwnyL6mE=;
        b=HqCCE8On2IYDjDn1INdOKv22p1PZN9Ef8JiAKMsuTU5EkTidrkzUCHwZHP8xL6nuhc
         NRkNLMoEsoWdMTKUnVebfeJqHgM8EPriEgbrA0s33MBhNw5muxtQ3TINPptv2H/n5OYf
         tn60d/d7HwNIc01EDjNLA/ZsHpwiCN2DDpBqyIjGS5DqhmtnW577oEnwgi+teV1B0K8p
         XP9o14sZNIkKyCEEZdXMU9zEM7yUKQi+E0DhU4Qey7++qoQiMgTB3jXy1nZRXKUWQ80l
         4onLjs9fV8Gra1td9OwhjDc/oWPcZroViH+prMfJImBb5CUqVzw37zjD4FC1MLwHUOpC
         CBbw==
X-Gm-Message-State: AOAM530Cu/3xJ6Hckioj1/oiIQ++9dJREa3BJhsCNcbSCiHIEq92Q1ux
	W2JYRiN3Fm85D/jS4Y1fuEk=
X-Google-Smtp-Source: ABdhPJxhRnnhvmcmVUkLBMC4Vxp6l6rF/MH7hPUO5zkWhxS7LMjABlyYN1snJVtNTEXklWfob5RozQ==
X-Received: by 2002:a9d:2c62:: with SMTP id f89mr4215096otb.38.1603999570557;
        Thu, 29 Oct 2020 12:26:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6b81:: with SMTP id b1ls988633otq.8.gmail; Thu, 29 Oct
 2020 12:26:10 -0700 (PDT)
X-Received: by 2002:a9d:5910:: with SMTP id t16mr4709056oth.155.1603999570181;
        Thu, 29 Oct 2020 12:26:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999570; cv=none;
        d=google.com; s=arc-20160816;
        b=nP3BM6S1yrHppgJsfvV7VgQoM+ptjtGnVoigwswrZIcu1tzX1BC2N3gX1lJbo2KiZJ
         X7fPXXRn3zmKfn70AIxztjgDLZZKM+cayU4M1D2xyrWr2GZdY0FBly9iN5iMFF7mxg6m
         NOnzg/nsyXODZa41EfFHINLr5SY3uGh6UUhEWUJ2wU+4Af6cOZse9lhuBKpxEgz4Mb2r
         BdP7NOpe9FohcKqEmIUBx3cS3yvNAI9tvMh9wbqj/onYAWf7882cdvjP/ypIEP1DINnA
         1L1mC7mof9bVD+RjEdMiC/GXYKJXXFc2WVNiS4PEGvRO57hdypJCt3ogJ255w3luQkNK
         PgnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=E3nLeu64H5OkoX6I7J0ZTAruHDRmKSNURPLcLoePP7U=;
        b=jkjMtqjYzqvkQPsVkLz9WhSDHcpjZ73wCudINWlQhyBd4pg7TsvoS8AOHHkcF35CtI
         gJfSwYHfgYmdXkpgSoSOnX1BwaY5m6EsXJRnZsjIM/2y0xUWzgxZvahb7D1mU49xlO5G
         qwM+GBRBrY2yKK9zgYf+asBCGqpqsUwAV7V8DRmBzTe+wlRrym7LZzwe2KMU8IwzvpzO
         Qk7sb5ikEChK2ZdbfIzCmH1WAeINnW4yHv4+50FcdTVz5gqQB5x+nwPz3k0NXPnzy/30
         3OZtwNho+22drplJ9LI/yBoF88VKGeWBbxIPKNOWILUcsiyO7iNi2DvbjrXsBM9W4Fxe
         Dlbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gGdqNoDG;
       spf=pass (google.com: domain of 3urebxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3URebXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id q10si326824oov.2.2020.10.29.12.26.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3urebxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id d124so2457789qke.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:10 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:43c6:: with SMTP id
 o6mr5668120qvs.53.1603999569614; Thu, 29 Oct 2020 12:26:09 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:22 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <15c4e9480d957318797d39d0ac1aae08f9efcb18.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 01/40] arm64: Enable armv8.5-a asm-arch option
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
 header.i=@google.com header.s=20161025 header.b=gGdqNoDG;       spf=pass
 (google.com: domain of 3urebxwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3URebXwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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
index f858c352f72a..9f13ab297b7a 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1571,6 +1571,9 @@ endmenu
 
 menu "ARMv8.5 architectural features"
 
+config AS_HAS_ARMV8_5
+	def_bool $(cc-option,-Wa$(comma)-march=armv8.5-a)
+
 config ARM64_BTI
 	bool "Branch Target Identification support"
 	default y
@@ -1645,6 +1648,7 @@ config ARM64_MTE
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/15c4e9480d957318797d39d0ac1aae08f9efcb18.1603999489.git.andreyknvl%40google.com.
