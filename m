Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6MQ7SEQMGQE73TXWPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id D0CF5408639
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:14:49 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id bi9-20020a170906a24900b005c74b30ff24sf3306043ejb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 01:14:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631520889; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9uKe0Zbba/OSUMI5NZkUVgwl2x79gDXAGEUbnZi9vQIC+GS8vwXhl1BP1feUFiaNe
         4xI22avmW+jlhYVnKZYPn0xivACjIa95aIaf5ZUrK8TCbxUj6BRKqKxn2JsHxB6R+36S
         VZCa7zTz2r8V9/mtSiqACMnfzmefO09l/aI6sVQc+a+/oM9ErPITXJcMzKWHe8osO3UY
         HyzOWB2eSPXRl2hbeMJO8/ChWrX0wWDwBT+wS7kOe6GmHp+DASpeSvIU8rbEm7mBC8FF
         TKP+0CERERJydof+lakImvS6Ro0oZ5DxkmeL6HhY6L9Gas5CdzP240PYj0upY6YbOcFP
         TtRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hDM8bHUMApbDZGOCd9SUL9rUQ3SzN8N25PKoY5htmKI=;
        b=mDPIBFWtVnu4UomYNOFecEYc6InkQyeJwi7iyO0gSN8kSpj6z3r/4O5r8nqjkZXOL4
         0P/Ap2JZuDuonTeTa16+fnx/Rgpquar8lnr428yw4XVEE+pRlMgSgQBUkvrAbQn1X61c
         q3KT8dDiu9y4TfvH3vc7jkLS7eJAqJySEbalerKwvuJ/MtQ7mYQGBjlr2JBHnYf8bIdZ
         iwnEnmz/p1kSq5LcTij1OvSgmjYQV+vgPvSB6A6abrpNPAwNf2EsLodWiKvRyqcNOc5P
         bLwiYR35KvOz+HBKuMhuumS5TiaSOT45w6HPO2EVT8yBAMh6TOFfIfPhO4sFsr+p3jQ+
         sqdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hDM8bHUMApbDZGOCd9SUL9rUQ3SzN8N25PKoY5htmKI=;
        b=M8aDh3C4W2SJ8Vk8givd0rLPZTOvTcM65J5fmHtl6N2DzaJbLqq1uRdoqdaQYpUPsz
         L8NV30O+xMNTLXLQfsYNqq01Wn1xnNNirKHPMWlPWkdMu2eo6Z45KZXJ9f6mCzJgQT2g
         h2IGD0BiZNmPANg3HD7yFu6RKN97VIq9BoyFJ3kykhvbxKIcX1k8+p0WkZC9442HICLB
         isWJ5WYhOGfQ8cEXloKixmCZFOlrRJORhYZFnlxqg7aqjfdYo21siYnc5ew76oqtsl+j
         48zeFtI/rg3Jf6MvG/TA4idq7mVw8awyBN/sD9ruxtF2kkuDh5kOpW73XojemkPjHTKq
         FiLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hDM8bHUMApbDZGOCd9SUL9rUQ3SzN8N25PKoY5htmKI=;
        b=qfFgymdCWxWYJ6VJ1DBJB9+58JYIXVylO6rnJU4wdl8pK9exHggRuWOoCQ7RA0lkLM
         3XCT/sbGJ76XdbqXXvqbbEC5GLpj4ltxeFx49t/7vrF67V5DdbomZSkP9rygxEzbnSPh
         7aRObVimsrkcxYOrctix99WdQdRmrIWAoUSrut3Jgyk5uqTewP7RlovENRlSJGkxKME9
         4NVMQJp9cwoT8Mukf2FeBp5++GrphCI56O75hDLQGE1oNH7ZcEgZJC/aBKWhJKxoSe38
         F9VuB2V2w+S2q8mPZAuLRCZpg02HF1/qq57JP+6q69w82B0W/Ggho/nxIxeWvE7/OQH/
         NAgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329EExeCl1eWf3b0vENTSjETZqc3+sEXN6EfUEFIPwbw3VI+9xr
	YMVW+nMpuTyjvg7L4ztr1ho=
X-Google-Smtp-Source: ABdhPJzVJ8tlY4VRQLTtTuvaNs+GbpnvlEBhUCJDESHec959zD76+/KbJs5nkJO9UNWuks9l5hI6oQ==
X-Received: by 2002:a05:6402:268f:: with SMTP id w15mr11960194edd.186.1631520889555;
        Mon, 13 Sep 2021 01:14:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5941:: with SMTP id g1ls2404164ejr.10.gmail; Mon, 13
 Sep 2021 01:14:48 -0700 (PDT)
X-Received: by 2002:a17:907:20cb:: with SMTP id qq11mr11049290ejb.488.1631520888710;
        Mon, 13 Sep 2021 01:14:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631520888; cv=none;
        d=google.com; s=arc-20160816;
        b=Q1Q4OqlnAajLZBgCfYw0akqzHcyI084h7MM+JhDjktWtWV/926VECzmisRu62DA+Wb
         bSoEtgO0XDFtyirob7+H9uingcJr+QxN4Z7gXhmpICD9U3vbrsE/iV9q2TbMccSoDwBj
         EDl/YJQRNUknAhU3uY/5chb36qAIUpZ/x+7UN6ATojOSzjnpAIv4I2/nKvcIYUjztB/5
         Spag3/rjGI9LNvyjhOSYBjsP/zCsDfLSKH5T0mMBcV3aAUYZvi6MupdQtN0dsGqz43l8
         Ln7il+m7qZezJW7macDdOl2hv6FiqlHFhjhrp9a8vXLh1MteyDMVgUyAmnjTXsh4D9Fq
         W2YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=M5PzcZIacf1B3cCC//js2k24DhfED83mTjpeYXL0fmI=;
        b=C4iatPPbhdUGS9mpzW4DDLqPtxyKHUoaV5HIQTLlrswL7Ua0TWf03jz1D/UMGKEXrk
         kK6xEWJJQlX+uoOWBA0S9QOWdv3Qngm+llfImHSrhbv9Yic8t7dd1xNcmSkyuyQOChaJ
         FQIaepXMoxyBLyCexUXUVydN6REfW5c8JGfGP/CymX+Q/OHAidQO8X+HjlfF8SNPVGbD
         mzB6AdX5ZUjnY9Dl1kCou+K3rXZM3k9wiGMd7usAtk5sHRaxkfrOXy7plt2XBv3O/tm8
         RFzYZP/vY782BmOJJvp70mOjfSTzBm/P+q5ujnvzuTxR3pQusvR/Ihgo1vb2omEpZTuz
         h6/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w12si894016edj.5.2021.09.13.01.14.48
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Sep 2021 01:14:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E3BE0101E;
	Mon, 13 Sep 2021 01:14:47 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0E76F3F5A1;
	Mon, 13 Sep 2021 01:14:45 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH 4/5] arm64: mte: Add asymmetric mode support
Date: Mon, 13 Sep 2021 09:14:23 +0100
Message-Id: <20210913081424.48613-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20210913081424.48613-1-vincenzo.frascino@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
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

MTE provides an asymmetric mode for detecting tag exceptions. In
particular, when such a mode is present, the CPU triggers a fault
on a tag mismatch during a load operation and asynchronously updates
a register when a tag mismatch is detected during a store operation.

Add support for MTE asymmetric mode.

Note: If the CPU does not support MTE asymmetric mode the kernel falls
back on synchronous mode which is the default for kasan=on.

Cc: Will Deacon <will@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h |  5 +++++
 arch/arm64/kernel/mte.c            | 26 ++++++++++++++++++++++++++
 3 files changed, 32 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index f1745a843414..1b9a1e242612 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -243,6 +243,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
+#define arch_enable_tagging_asymm()		mte_enable_kernel_asymm()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 22420e1f8c03..478b9bcf69ad 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -130,6 +130,7 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
 
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
+void mte_enable_kernel_asymm(void);
 
 #else /* CONFIG_ARM64_MTE */
 
@@ -161,6 +162,10 @@ static inline void mte_enable_kernel_async(void)
 {
 }
 
+static inline void mte_enable_kernel_asymm(void)
+{
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 9d314a3bad3b..ef5484ecb2da 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -137,6 +137,32 @@ void mte_enable_kernel_async(void)
 	if (!system_uses_mte_async_mode())
 		static_branch_enable(&mte_async_mode);
 }
+
+void mte_enable_kernel_asymm(void)
+{
+	if (cpus_have_cap(ARM64_MTE_ASYMM)) {
+		__mte_enable_kernel("asymmetric", SCTLR_ELx_TCF_ASYMM);
+
+		/*
+		 * MTE asymm mode behaves as async mode for store
+		 * operations. The mode is set system wide by the
+		 * first PE that executes this function.
+		 *
+		 * Note: If in future KASAN acquires a runtime switching
+		 * mode in between sync and async, this strategy needs
+		 * to be reviewed.
+		 */
+		if (!system_uses_mte_async_mode())
+			static_branch_enable(&mte_async_mode);
+	} else {
+		/*
+		 * If the CPU does not support MTE asymmetric mode the
+		 * kernel falls back on synchronous mode which is the
+		 * default for kasan=on.
+		 */
+		mte_enable_kernel_sync();
+	}
+}
 #endif
 
 #ifdef CONFIG_KASAN_HW_TAGS
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913081424.48613-5-vincenzo.frascino%40arm.com.
