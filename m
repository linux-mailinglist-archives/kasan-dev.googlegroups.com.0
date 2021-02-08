Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBRG2QWAQMGQEIEIN7HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AE4B313A2E
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:37 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id w79sf277571oie.7
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803396; cv=pass;
        d=google.com; s=arc-20160816;
        b=DetC1bJM15IHipRSzG6Xhw2Mrtfn/MMZxawy0+vmxIl9FHvg628cNdxWopaaXL1pyv
         4WadtvhcPLIdRbFyzN0k+J8PW5YBZGp9edFyUe2TGxC3Z5AGyjOuPx+u+fY2BrhoivJD
         Jsa2Zlg7YAkI4cRRDZOnaY6KaL8EkQtbH1QW3w8EBndcT27zsVd0F7YR1Snb+75DtFJ2
         Mjq/5UQEZaOajOBCKz37rqDMhF7HOeh/BBAXNE6D9xGlZPs6OwN7EdzQcVLxHGUBDnZq
         TxouZuvsQVvsJx7Nt/YgDc8OfC5KqWBrdF/GSNDL9vO2Neo8wR2d8Seh6dKMs8tqv4R7
         XQ3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MvZEMIEsSgRRiDbkIdU6EtGkzSGNAIAw26XZY+AkJ5c=;
        b=cK3NiaTCdvgdfeVFZjUCaq3sL6EtB0T5SzFE1PYqAHvCwhh1cGHz+XlQ9qw4w9jF82
         nvML8yYEdPuviStfv+0BzbN1BCIQaqd9dobnTDlsEjAHyyak6p5V+niRnZnGIn+Si4tS
         QiDntEDmB6Ggz1o1rGN++ecPSQBLeMPYHVvYcRhX+ieMo+2l/rnTYeyPGl5Sk/YDTNNm
         a2pfiWRL+9SPjSYUurHLmvERjm7ViHkcOsTRj9vG1XmaWIdPq3SYJbrBcSR4kV2VTLvX
         T9Q11e1RlctLEYZiNttlomekja7eKLqiVoze1eVHxbHAIUl2uL/ci7eHmRiUEQxh4SEU
         ddVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MvZEMIEsSgRRiDbkIdU6EtGkzSGNAIAw26XZY+AkJ5c=;
        b=e0jGWZaqzYB+Bl3M5XIorH8UduoVrLcHPBtGpghXnOtSFHiBLZ59iCxHA6kJFW6B42
         PNwgavuR3FGfXYf4D9ky3SxHo/WBfGXV7HhuEhj8xdQM5zLg2K304ynqxThb/HlHNJaF
         CQrlSXqeRI6nVGmBt0shlLHFwLpKHry3ExwjAO/p91UUB8Q4Iz5qHsjPYkSL5toPX6FZ
         1WBzuukukRWsOr0WHvH9g5esu7wHD96YRR9xZNyGVtrsV9MsaIvwREljfXerBOvTgw+Z
         1NhGllQUSZKz7QM8rQv1ML53PMMos8o5yaPq3hIHhjjEWT6DPBPOfYJeUdYE7F4TSump
         vtpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MvZEMIEsSgRRiDbkIdU6EtGkzSGNAIAw26XZY+AkJ5c=;
        b=ZCtcqSUyYhIwjkF4HhhRCLzAbq1xKdbkrHOzublMHeg1TAd3+RlH6GR9koCSnoMv+g
         vTiTiw3gKCwyigMvq4LrRrohgFsaYEJUAjE1I7Tr4mopZCMX5oF4uJpsBQCmTi4JDxRg
         iam7GtKOyfWD+u8ac5SGpylXMa2fFHYYqu+8dCGqSBcplfYZpX5YnJHXF5q2Xzxg9SKQ
         IMasZBXgW8oF4IS5t+epWg9iJWKcU8x2N3wWSJtSwZrCkUCaw0poymO5tdz+u181ou4N
         iMYFvKcw/o2fW6Yw23gy1Ya6aj4N/tI6+qZeAyqrX+6z0xwuq/MEPVkNEnv/9M8itFwt
         o4Rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310hXbrmhXDsVu74pfTvAKxX9B0k7fvkCIWA11cs0WHFLS384CI
	FceqtONJMGgG5DrGBWfPq50=
X-Google-Smtp-Source: ABdhPJyQzFVJbWiY5Nm21z9l9J+VnP63lJbux1+uHisaF51QIM5ArHb+I1iIkW4NHZgZpH5d34bLxg==
X-Received: by 2002:aca:220e:: with SMTP id b14mr10499334oic.130.1612803396554;
        Mon, 08 Feb 2021 08:56:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:10d0:: with SMTP id s16ls2950226ois.7.gmail; Mon,
 08 Feb 2021 08:56:36 -0800 (PST)
X-Received: by 2002:aca:b6c1:: with SMTP id g184mr12047516oif.47.1612803396167;
        Mon, 08 Feb 2021 08:56:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803396; cv=none;
        d=google.com; s=arc-20160816;
        b=osdyEBtEm89Dt+nN57RrhXhRmLKhkT3uTdJu4WTMzjMPB2tDKG0zjE/Eblzr3XlIgb
         ijvJO2+OIbLWjp3PyDq8DBZOcH+vQ2HMnCGWq8vPg6W2bUQdRXpLpCYYHjNCryzt61UQ
         NkJLSpEHbF+S/EAB1WKJrOeNGrFtYWVqq1R2tSOWqEq2et5yFCm87zaJtv0yDzvcabfp
         NJqVp7sg+PmgrbHGgzRckgd8qAq6MUXn6Iu6uTETYsr//o9Bnj+N+a5w5TNyiXUrN+lq
         jqie8B5JnBq98b0qlsJwi6XftzdBz1ga7dkFmgi7JoC8iKjlDiIQaEEF9ERlIgAKzL0Z
         /Ogw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=RA7SSvbYOUX0tk211UpbrVnWsgFJBgVil5+7gTC/1T8=;
        b=NHgBwCEJZRg6lXJrOGTjLrtQCJpWWUyflQyEcB/LBH6FX0mNATFAk4hNnQsVa03biU
         kfS9l8Lxtu8UDABK7McQUTgeTrZjf1cPmpABF+sDiwA+lF2tj4WU6g8o9jItU87EK29Z
         4XBW1sEt5FitSvbTznB3Mvz8BDxIIMm3e/MwdLoR2Tw7wmQ4tKRX1e62qUoCFy/CyFDL
         /4UCNbb5N0gteMdXKAWao4EWxXBJSS2dXE3k2K53XLTLHKRGN8XJ5GB/1F+tvwHtzZu7
         Ms/lXE4Yc+YsjsmCgm61l95yixaDNI5kLEkStk06IqI0wh1vTpUk5nTKBjiOhjZXQFRi
         aeiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f20si310545oiw.1.2021.02.08.08.56.36
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E15F511B3;
	Mon,  8 Feb 2021 08:56:35 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0BCE13F719;
	Mon,  8 Feb 2021 08:56:33 -0800 (PST)
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
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v12 4/7] arm64: mte: Enable TCO in functions that can read beyond buffer limits
Date: Mon,  8 Feb 2021 16:56:14 +0000
Message-Id: <20210208165617.9977-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210208165617.9977-1-vincenzo.frascino@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
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

load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
read passed some buffer limits which may include some MTE granule with a
different tag.

When MTE async mode is enable, the load operation crosses the boundaries
and the next granule has a different tag the PE sets the TFSR_EL1.TF1 bit
as if an asynchronous tag fault is happened.

Enable Tag Check Override (TCO) in these functions  before the load and
disable it afterwards to prevent this to happen.

Note: The same condition can be hit in MTE sync mode but we deal with it
through the exception handling.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reported-by: Branislav Rankov <Branislav.Rankov@arm.com>
Tested-by: Branislav Rankov <Branislav.Rankov@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/uaccess.h        | 19 +++++++++++++++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++++
 arch/arm64/kernel/mte.c                 | 10 ++++++++++
 3 files changed, 33 insertions(+)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 0deb88467111..f43d78aee593 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -188,6 +188,21 @@ static inline void __uaccess_enable_tco(void)
 				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
 }
 
+/* Whether the MTE asynchronous mode is enabled. */
+DECLARE_STATIC_KEY_FALSE(mte_async_mode);
+
+static inline void __uaccess_disable_tco_async(void)
+{
+	if (static_branch_unlikely(&mte_async_mode))
+		 __uaccess_disable_tco();
+}
+
+static inline void __uaccess_enable_tco_async(void)
+{
+	if (static_branch_unlikely(&mte_async_mode))
+		__uaccess_enable_tco();
+}
+
 static inline void uaccess_disable_privileged(void)
 {
 	__uaccess_disable_tco();
@@ -307,8 +322,10 @@ do {									\
 do {									\
 	int __gkn_err = 0;						\
 									\
+	__uaccess_enable_tco_async();					\
 	__raw_get_mem("ldr", *((type *)(dst)),				\
 		      (__force type *)(src), __gkn_err);		\
+	__uaccess_disable_tco_async();					\
 	if (unlikely(__gkn_err))					\
 		goto err_label;						\
 } while (0)
@@ -379,9 +396,11 @@ do {									\
 #define __put_kernel_nofault(dst, src, type, err_label)			\
 do {									\
 	int __pkn_err = 0;						\
+	__uaccess_enable_tco_async();					\
 									\
 	__raw_put_mem("str", *((type *)(src)),				\
 		      (__force type *)(dst), __pkn_err);		\
+	__uaccess_disable_tco_async();					\
 	if (unlikely(__pkn_err))					\
 		goto err_label;						\
 } while(0)
diff --git a/arch/arm64/include/asm/word-at-a-time.h b/arch/arm64/include/asm/word-at-a-time.h
index 3333950b5909..c62d9fa791aa 100644
--- a/arch/arm64/include/asm/word-at-a-time.h
+++ b/arch/arm64/include/asm/word-at-a-time.h
@@ -55,6 +55,8 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 {
 	unsigned long ret, offset;
 
+	__uaccess_enable_tco_async();
+
 	/* Load word from unaligned pointer addr */
 	asm(
 	"1:	ldr	%0, %3\n"
@@ -76,6 +78,8 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 	: "=&r" (ret), "=&r" (offset)
 	: "r" (addr), "Q" (*(unsigned long *)addr));
 
+	__uaccess_disable_tco_async();
+
 	return ret;
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 92078e1eb627..60531afc706e 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -27,6 +27,10 @@ u64 gcr_kernel_excl __ro_after_init;
 
 static bool report_fault_once = true;
 
+/* Whether the MTE asynchronous mode is enabled. */
+DEFINE_STATIC_KEY_FALSE(mte_async_mode);
+EXPORT_SYMBOL_GPL(mte_async_mode);
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -170,6 +174,12 @@ void mte_enable_kernel_sync(void)
 void mte_enable_kernel_async(void)
 {
 	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
+
+	/*
+	 * This function is called on each active smp core, we do not
+	 * to take cpu_hotplug_lock again.
+	 */
+	static_branch_enable_cpuslocked(&mte_async_mode);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-5-vincenzo.frascino%40arm.com.
