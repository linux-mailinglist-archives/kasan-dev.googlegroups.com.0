Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBC43TGBAMGQEAKBQFPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 13F0633131D
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:15:09 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id q17sf3796031pfh.16
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:15:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220107; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqyKKw2aGu32TH/eAzQ/Dg1A18kPJdF0SUoM3v56QiOC/Mc8NhW1RLW051bNNgf/eO
         NSo7HQeN+UpW4Yv54aNu5+KgkCxugacv/q8Uo9h7aGxYcNXWglc+IeigVTUXOoVOibPK
         yuBdFGYTF/yq8aHt/byTr3z7RwSCXMmVvZ4N28zMy4ByOhCqIm7umzaq7TdxKsQ3zRCo
         7M+tA2SiVVzwr9hJZ2m0g8EfuiWryhWoUOZ+7Jy7TatnmDHEqT+bn8wrP6ErnNJZzXdp
         aVN+BhrqqjqdOVdLQ2lh5o4jX5EUhP58KGGgTXDiEtXkndf+eT97ZPGpDr7N0NLgAQBs
         d2Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pCxPrW4EltV797qhM7/efdg+kqPnMiXtfKpxArgKMEE=;
        b=DFxQf+8Z9CcT3ducgDAUAvlXvfFeNanaTavckMAXcSsocut8RV/NH6Pi/xLQimNp8d
         3Zky6SHDKrzhtYGhMJDQFQMYkNt/ngHE7FuKGbftC6ZW81IKonVPvnLRN1bA9sj/w7HO
         fKSs3X7O7STTk52MefGIW2RktGYfPkrA7pjQhE2w417AoOlf3ZbfiGRYJYuzvxe9+Wz2
         IIJ/YPG3UGC2YuAzYtMVyd1XdHSwq8vqunyLx92qFK5pydqp7i9iY5ZixIvNE6E7q/e/
         bphQXpHUioK0XIjcwrGsfFhNOnyDdHHk8roVZSVkb5HGVSzJ9CUAXW61dnbXLHOduvKA
         i37A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pCxPrW4EltV797qhM7/efdg+kqPnMiXtfKpxArgKMEE=;
        b=IXVdl/qRcECUbUah6hnTqKzI4dwUzL0nQx8jxeY2U6zzDbA6y+TCk9VwNzFTG16XX0
         ZLu5Xjy2WeRpl1diMDB8/jTyJ/7+LYWWCE3nnb5KNTVWgIpNgL8AQNGW2vwkLVRJ1K3T
         NE9HOTS5l7ZBHRa5Kay2sJ2Ltj/Dg3DqbE55XyqkNY/bmPPc7odXGXDD8MKbu4wi4dm/
         /WWhcfZ5vDqKZOz4PEA0qpqskhZ5I5sc3kV00C1lMDy5jCB1Qfjz/KBGvNK6Wf6oVoYB
         Dw3LQGFcJz1o3GmhnaPtQ229YqSWtbXJRbPfoEt5QG5CpEQiy3iuZsKE7TMZeKmeCSGX
         Idtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pCxPrW4EltV797qhM7/efdg+kqPnMiXtfKpxArgKMEE=;
        b=O8NhEYSDn80YigLjSSt8kWGSch0yD1cCQDbkxcIaTOZVYj4dIgFfYIZXEgwWgMsdoh
         BXufEQ2EbqBlVwabiIbM+IxHMh/V4YSNt+wC3qr6lPXZWXHyO86apUR9EPsOjI1JW46/
         gamPzDWOqyPO/oFHov+yPH4xR4EASHS53gVknk6bt6bLJukaHYrMvHmSCNa5f7wGgWMb
         HCIHNHbAdP3+ZsVdJqgeFfnLvPiuOAo5ZExJF+ImwNYsMYE0FhEDtm8WsJcXmWCg4lfi
         pUmLY3OBpBTHR33J3ggmLZrMxqLYR0e73JwJh5/+yxQgVKy9DwgawF8WmiRjr6zhCuzX
         WNgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Nm1Vp715Aug18cZI/It40NoEOiG6Hx2Ktn/m5K2rtuST1U7AN
	cRgcY45oy2+ClTm3EMiFCXM=
X-Google-Smtp-Source: ABdhPJyN1AueusOSNXc1h/n7z6/Sw2U4rwDx7D4xWDHhuR0ACO3LL0uvCjpVrn1MBXyKqqqjSRsqOw==
X-Received: by 2002:a17:90b:515:: with SMTP id r21mr25386123pjz.42.1615220107737;
        Mon, 08 Mar 2021 08:15:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:f212:: with SMTP id m18ls1860689pfh.11.gmail; Mon, 08
 Mar 2021 08:15:07 -0800 (PST)
X-Received: by 2002:a63:704:: with SMTP id 4mr20955706pgh.411.1615220107262;
        Mon, 08 Mar 2021 08:15:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220107; cv=none;
        d=google.com; s=arc-20160816;
        b=Ln6J7yuKoFjyaRLzuJy8Txi+CvhTiZZRxMnCzULSVKnd522+tsqznSfpvMdcqLGG8I
         6evtLlgU1Pv8TzSCyxsMy2My7LAzgOHueGPlMgGMinvP0ClEsWyuQpKRhSjwpv7t4iKR
         pp8THWm87AECjjQkMnq2drboR5bqt/6+ArRb1CseBc2XJOZ/RCP5gekNLtze9cZY/oMV
         mJjNrq+KupI+AlOFoyNc+h02IlbgzAO0e7tNU7uDoN6SqsnaoX5A4Tlo9KfSE1QVullO
         6P4ounvCwShC0/D36L25wwd5pWSkkOSBQ8hxGcnYgOpahX5IwFb+6V80vDk+aLWf94nQ
         iSxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=B5otvFYPRumouNpRYjjKnGJbSpjGZY7+AWkXcair4fk=;
        b=J9bQpv2MNSV1ICDGnnOxTK5yjn6NEIvYGwWEVack/03PFP0troNWrseIuxzFk138y7
         DriYqjoAqNkXEM4WG8QODg5Q9Octb6mJaRkFScvBKF+pLZixzSNQzzHbRwO+6DeZSxZw
         uBH+YINUB7EI7jNpEUXVVm0bhjMRg5lqefaNwCufRrKmUjg64UX9FgHRpDWHCUoEuXZF
         l9YpqCxyQ7JjzpMynlofJAIRfd17I0GWYDt4LaxH+ztspD2wUdnBsrAtzaY4KiowIOTb
         cT/wd1TIJXF0KhyMvSuTEODjU0Gg0tApPn79vVsVpTBNg5Ds+jOGflVaCNp2Mkv/5yd9
         j8LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e7si645716pfi.1.2021.03.08.08.15.06
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:15:06 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 76DA0113E;
	Mon,  8 Mar 2021 08:15:05 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8FBAD3F73C;
	Mon,  8 Mar 2021 08:15:03 -0800 (PST)
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
Subject: [PATCH v14 5/8] arm64: mte: Enable TCO in functions that can read beyond buffer limits
Date: Mon,  8 Mar 2021 16:14:31 +0000
Message-Id: <20210308161434.33424-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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
In the current implementation, mte_async_mode flag is set only at boot
time but in future kasan might acquire some runtime features that
that change the mode dynamically, hence we disable it when sync mode is
selected for future proof.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reported-by: Branislav Rankov <Branislav.Rankov@arm.com>
Tested-by: Branislav Rankov <Branislav.Rankov@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/uaccess.h        | 24 ++++++++++++++++++++++++
 arch/arm64/include/asm/word-at-a-time.h |  4 ++++
 arch/arm64/kernel/mte.c                 | 22 ++++++++++++++++++++++
 3 files changed, 50 insertions(+)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 0deb88467111..a857f8f82aeb 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -188,6 +188,26 @@ static inline void __uaccess_enable_tco(void)
 				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
 }
 
+/* Whether the MTE asynchronous mode is enabled. */
+DECLARE_STATIC_KEY_FALSE(mte_async_mode);
+
+/*
+ * These functions disable tag checking only if in MTE async mode
+ * since the sync mode generates exceptions synchronously and the
+ * nofault or load_unaligned_zeropad can handle them.
+ */
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
@@ -307,8 +327,10 @@ do {									\
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
@@ -380,8 +402,10 @@ do {									\
 do {									\
 	int __pkn_err = 0;						\
 									\
+	__uaccess_enable_tco_async();					\
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
index fa755cf94e01..1ad9be4c8376 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -26,6 +26,10 @@ u64 gcr_kernel_excl __ro_after_init;
 
 static bool report_fault_once = true;
 
+/* Whether the MTE asynchronous mode is enabled. */
+DEFINE_STATIC_KEY_FALSE(mte_async_mode);
+EXPORT_SYMBOL_GPL(mte_async_mode);
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -118,12 +122,30 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 
 void mte_enable_kernel_sync(void)
 {
+	/*
+	 * Make sure we enter this function when no PE has set
+	 * async mode previously.
+	 */
+	WARN_ONCE(static_key_enabled(&mte_async_mode),
+			"MTE async mode enabled system wide!");
+
 	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
 }
 
 void mte_enable_kernel_async(void)
 {
 	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
+
+	/*
+	 * MTE async mode is set system wide by the first PE that
+	 * executes this function.
+	 *
+	 * Note: If in future KASAN acquires a runtime switching
+	 * mode in between sync and async, this strategy needs
+	 * to be reviewed.
+	 */
+	if (!static_branch_unlikely(&mte_async_mode))
+		static_branch_enable(&mte_async_mode);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-6-vincenzo.frascino%40arm.com.
