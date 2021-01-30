Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXE522AAMGQEF5JT46A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E00E3096E7
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 17:52:45 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id w5sf8250602qts.9
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 08:52:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612025564; cv=pass;
        d=google.com; s=arc-20160816;
        b=owTFOLk7AZ6MgGQKjHcmP7PzwNQaKaoEUKQp7lRqBygxeQ+1m5yIb8VNtvST0MS7sF
         4ESEE8ENLsN7M7I6blSQQit9SoaWihKgkY89tJ2WaJbgHGmGDTpiqyGgp665Hn9L+jE8
         Pke3Gif/rx3qXlwPWDUV4R8QC7bHHgvzG/IfHal96EAWtY0MPAQFzIT1AGlPkzO+8ruu
         Sf45OvdHmMRh/WVSEMYjAvTU7bxlBXIiUKrTgy1nnZbSr1JXrhcbIMFfRN0/ooGLGC5U
         8uT+elxXM329HaLuetSYHiUlht8hxx0bIYkZFgaBk8DVKPow3q6BuU2GEGZKApOd6wBA
         6QLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JHnGxZbpHnBR9q96NL4uLu2MCSZKzcwGsj73XrHDzT4=;
        b=y5FMg3rVVtFXKRAYp/5LTLnGPFI2ugtPbpT9QawLtb5lKdXdPMuZ5hqj1UgcAPHD78
         39sun5fGdggFF0Oo55QgdrNV3Ha6M9lt+ZqNAHH89zCzaLaxIo6Q8dsrFKKknQsNce/7
         1Xf0kXzNx8hGw3/3oUs7AQuLUG/h1NrEw1EQgfhgscItHCNdJ3EKJXhT5vtw/86a0SPM
         7SNy3K502GUo9x2mobjXLZXdND4nFFEbxB+tFiZGSgIfPwpAewpGpJ2JI6tkMrRHZxZM
         O+ordCFFacnAz1c86KmICG7O4Q74OwAdZ+N8yXYrEg1Zd4/1TJCYh0nWtbLIyXceLzeJ
         ogzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JHnGxZbpHnBR9q96NL4uLu2MCSZKzcwGsj73XrHDzT4=;
        b=MoeocNNgk7JzGn67f2mQTjEYzvzFtJwyb9jMU8Ebk1XZCtSoB4xTUV3I6+S7Lge3lH
         WULvCbxwoPE7D57hYSizU2JxESXluxqBy5UP3cpDOahaN0j7nZOL7ac3t7mofYWCsjYm
         Bx/dhp3gsvRA+UxA8w7VloOBDW5G500tgW26/Jo/5hzq2Le3Kz/fV3BnpiM3gobxIv2t
         parRrndlDtEYjVbqi8DexDuPIEwnRahiC3ba5D+2887AbJ+aCLMW9FrNG4hvgh+vkTR9
         AcBK2cD2aoyoVF5jl9iTGQKBIEHo0HPi8vWW2dwk3kBFfppWQooeXX6RzB9ugZ9DXPKe
         FNqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JHnGxZbpHnBR9q96NL4uLu2MCSZKzcwGsj73XrHDzT4=;
        b=LU4IQ1ilWzQClIfdYQ7vNeqMzRyoL8Hr5D66EkO5ZZAhU+uOPqCXBhllab2KZ5wA5i
         rnvRV4aa1x9mPek1q+V4YA3OMgAVkYISOY61WvzgmlzE6qLh7c85cPDOjGZ3Th5GezT4
         DZI09aWG0PJcRGmGbbh9Ln5E0/Z1pJSf0tzk//GqJDCBr+kW4IeNcS3+ryaek1+cXwOI
         9W9c7W0H2N/XEiEZQhMmODGSbfyOKApgd6vw9T/oXA+Uvc+NJv+MQYXgdCBR5Cv8ByLS
         e/nJTay/Ai5Augau9g6NcHqKMfIc5Jr8bMh4Ryn2fxl1I25eTDeUbLbb/rdd5jaxjgA7
         44pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GdcBN4dcJTcwIbvnNFW12fO86NUHNlkklkVgArwPWNlqd8fP6
	klnI/24ypYdSsV/pag1HojM=
X-Google-Smtp-Source: ABdhPJxaE6jqzlPTj+b+BLFiA/VBdZHR13reyqxyaSdj4oaHfFE58PImJkl1IbEaxjce21FXL2d1uw==
X-Received: by 2002:a37:9c05:: with SMTP id f5mr9042736qke.189.1612025564479;
        Sat, 30 Jan 2021 08:52:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fa4f:: with SMTP id k15ls3075129qvo.7.gmail; Sat, 30 Jan
 2021 08:52:44 -0800 (PST)
X-Received: by 2002:a0c:f143:: with SMTP id y3mr8892235qvl.62.1612025564143;
        Sat, 30 Jan 2021 08:52:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612025564; cv=none;
        d=google.com; s=arc-20160816;
        b=fniIsSrYL1NnMfJtskc/EqwyN9bYVeHqs+lcoWcNZalc2WvSO+6iLTWNjngQNd/+R2
         NggGbeYOAVl7fFNYZKiEMVXzAti8VO9ktPZMOESLvPr8mWCzJ/sOs7lgmEd3q8R/M9kL
         uS45B17ITtlp1fp/GbwZK9cRfd/YkvFZ2I3rV7sMrvHgu+nUHlfvxKOkmwChu9117S+/
         EIumr4eVdEOnR+e0JxmkGxIxyu/W3PSk8pOPBmae9YigpNVv/wEA4C0zxMWICrd1gx5q
         3wKwKuYuihOrDvma7+wCIC2lUPjG+uuWErqCNWQwUSb4OeA5JGn/o6jdUslIzEtPNtO0
         Wycg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=qaTy6Kc9+vmp27LroyuCn6a55xdy5dd3XEGJoZzAxL8=;
        b=CKSmuFKGHXIGGxwcQaNmOAGmr8vnbT+hB1xuoVJKpY7gSHn0SFbq9oekf/nOPOfL+M
         LzLVVHSNZdSBrEgWEma7v1sV/d8uYGGGfMxVVfnoE8rMNMpIu/O20Fj/SnwYD7kTDlxr
         /qBme8XBKrono1o9FvgxdcboQQ7f2DR1KEoAmESZnaOBjsWJ1+3ivEASGH91K2We1dKA
         LenvDLdjd6ggBkQw93kQh9rd/ijgCxmEwv7SBhQ3/i/y+HAOmhRKDW0DqWX+vixQDmI1
         sQcXvF9xTCqmazigP0qG6kZFHGr+DgrNWOJ7+GTBjnbnBDVJ5m7Sks+kg4JMrQnOM5BJ
         pEFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g51si636462qtc.4.2021.01.30.08.52.43
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 08:52:44 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5D229106F;
	Sat, 30 Jan 2021 08:52:43 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7088F3F73D;
	Sat, 30 Jan 2021 08:52:41 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v11 1/5] arm64: mte: Add asynchronous mode support
Date: Sat, 30 Jan 2021 16:52:21 +0000
Message-Id: <20210130165225.54047-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210130165225.54047-1-vincenzo.frascino@arm.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

MTE provides an asynchronous mode for detecting tag exceptions. In
particular instead of triggering a fault the arm64 core updates a
register which is checked by the kernel after the asynchronous tag
check fault has occurred.

Add support for MTE asynchronous mode.

The exception handling mechanism will be added with a future patch.

Note: KASAN HW activates async mode via kasan.mode kernel parameter.
The default mode is set to synchronous.
The code that verifies the status of TFSR_EL1 will be added with a
future patch.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  3 ++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 23 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 71a6e36cfe85..8ef409d4a18c 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,7 +231,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3748d5bb88c0..8ad981069afb 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,7 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
-void mte_enable_kernel(void);
+void mte_enable_kernel_sync(void);
+void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
 
 void mte_set_report_once(bool state);
@@ -55,7 +56,11 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel_sync(void)
+{
+}
+
+static inline void mte_enable_kernel_async(void)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index c63b3d7a3cd9..92078e1eb627 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -153,11 +153,23 @@ void mte_init_tags(u64 max_tag)
 	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
 }
 
-void mte_enable_kernel(void)
+static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 {
 	/* Enable MTE Sync Mode for EL1. */
-	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
 	isb();
+
+	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
+}
+
+void mte_enable_kernel_sync(void)
+{
+	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
+}
+
+void mte_enable_kernel_async(void)
+{
+	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210130165225.54047-2-vincenzo.frascino%40arm.com.
