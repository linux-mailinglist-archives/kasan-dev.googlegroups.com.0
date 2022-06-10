Return-Path: <kasan-dev+bncBDDL3KWR4EBRBFWDRWKQMGQEAKYSPAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C601546954
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 17:21:59 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id i19-20020a056512225300b0047db7f89e9esf557679lfu.14
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 08:21:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654874519; cv=pass;
        d=google.com; s=arc-20160816;
        b=pOhhSu/TA8aQ/5b9cldqtio9jdXWCWJAVbi/F+IC4Ft/rzrADmQEbIor4H1bRSV4d5
         GG1A+2nwUH9Ol2U/YgkBQyjDllAPyLK1Ea/qm32FIB+DNTZauwOsPTS52JTx7jCxa4DP
         lnue6Aku2Y7HO3e0JVowVcEyy3XPokjviq/sGksP1WuWy0o6zoR6bLa91I9PinLNAyfd
         lhs82OezYnPojVG7HS8QlErOdWmxYCbbq8YHVvv4q44g1bfusHVStzt9BHSDcAvnyOBc
         U/ltoMZ4mvCugbGmWThY8N++HNpKPQwRUJ08CDOvOiEZ2ghXcJtLHVUpzHnsNtSuaMrS
         IfKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Fbxdu3bczd7bRiIPOVc23IoTgREuUhJUxBZhttC4fUg=;
        b=gIW37Zlraaj6cu0WUoenaEx9fdIpKQ7wOIauvoTXKbrtGd4QPEEs+LcC4M90+5vFsP
         NsVbfQlyt3NtDpa1PqKaeyuTiBKpf/9TK4w5nmWoLPBGgCQhiRF8eU1r3y7baVmC2wUC
         4/Q22IpM4nMgNVm5yL2k2sFhgsw61jtH4BgZTO69TnRnCm7xDBCRBVVBT/waXZgCw0lc
         TdoCpf0uXeeN+qAf+FyG13Mn/qGCqf3lhMWIn7pCevwD7BCeHYNDf1wmN/e6nt/5t/9i
         l3vjH6lBpi7XmKcgDpOA/w/bVnt6oAOv500VbqKLW+qBWTH2OLf/1ZiL1iHg3pUgMAHw
         opPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fbxdu3bczd7bRiIPOVc23IoTgREuUhJUxBZhttC4fUg=;
        b=Km93nzWMKYyxsmDgDBvf8TO1LtQ0Rt9I8EX0g79+zCq7CV9ZGguVV52+sqm/DOYeUG
         UJI3VnQ1sTHdzVp+msuYtmDslCNCaLQK8LqMIrjg/tArClCckgDLsMlbV9YCIfl8/fHv
         idxYxNsAhZ2XReM3Foz3zJ7G3XFuai6O7+SZlyNZxZrRT6UP6J4alwP28ScQ3GMsnm0O
         ZU3RG2kTkfqYJaMGreF3H1hkNedT5Rh51gv9KE3Z4TeqdRRmkfo52p/mYZUF973GnD/n
         J8rtJYZNDxW/HSdT8gvGhI43rQAyVeJM/vQPTu2bgXPdFSOyNkD6XHwPhfhCjBMESxt+
         AJMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fbxdu3bczd7bRiIPOVc23IoTgREuUhJUxBZhttC4fUg=;
        b=qDjfyL3eu3x9x3eAuL4T4u1/enKhho7gZdBw1mSRrDFJxY695UXJaCp9SvZ25Hwi7z
         CmxCYeadHSrQS6t17KPJRGz96PxuTPr3P03sbcj63eePqoYhaDHtV+Q5UskTfqkUJFvx
         fuqc5b/tYoHYt5+jDTqN1XxHFz1eYF6WAyiF1VErecUl51RseVIUp2zdlHRBqLXw27zh
         E3/7bhsKpsbNH3PGqQQjoPjdkMGfej6hJXh7BhfakovMTLcZ1+vOfkz22IClWv4mEMnU
         YC4bfnWGyFn3X29luCYVnl7c0Qld2Kjmn0N+5x+t79XkfmlL/qR7nU22vHE0EkoSxd83
         YoGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532K8E8VR4QXE34jHNd7RYvqUHkR+NOFN4X28q5O4FVAFYQcs7uD
	5DvV0EUy8isWdBOSkVCr/LM=
X-Google-Smtp-Source: ABdhPJxZEp3XVDQkJHoedsGlPFN/QFdzKd4Oj2e4gm+IzPRd3j6OYyBNMqmJas9eyM0sfwBV3+GK1Q==
X-Received: by 2002:a05:6512:3991:b0:479:2e05:2ee4 with SMTP id j17-20020a056512399100b004792e052ee4mr19987617lfu.64.1654874518601;
        Fri, 10 Jun 2022 08:21:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls217780lfu.0.gmail; Fri, 10 Jun 2022
 08:21:57 -0700 (PDT)
X-Received: by 2002:ac2:43c3:0:b0:479:1630:c6ed with SMTP id u3-20020ac243c3000000b004791630c6edmr23533928lfl.406.1654874517119;
        Fri, 10 Jun 2022 08:21:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654874517; cv=none;
        d=google.com; s=arc-20160816;
        b=pcEAfhx7PXskuGDNAslEHVuz7wFILdm0DJvQ65y0gdXfOuDCtsy+0wOAjccpZ04uTx
         +wB/Ptfkzjrz08MtGQ2OCuExAOudw5WtwVwW8eIZNR3F9AjyZ51CMEL7lg4qhSemyfq9
         h7a3tbutg6Tdrn99ZheoF7S77ezX70zY1eKhBFr7kgYq4ti0O3MZcuLV/7JjNJx21mCv
         yOEuDHcLMVTxR42ofqGZgq+KXypDNk9ph1c5K2XhdHHBxzDcXPDxQUHoUhU5QoaNcL0/
         OoYqTR6SiXiARQCh7/jqsdH+sQ3RlspS8GMpwjGAomtVfhH0XqwfsDZGlpnKTUjMTt03
         yg6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ul5Rkg2DHPiOb0XL6MyXI3hFMrCX85Gv29rAxP0lAWg=;
        b=c4HomWFD67HtHT/GQpv0zlnYRGjzQJw2SBoZiLWDmI595MvUxhxDTSC/Qs/o6ch+WB
         kQSLTFKjhROeNAySXIbXh066/RWEZmWDexz5gdTUDRYlV3Il0dM/C+HArjx6UX1Izpm+
         NIivHJ53AyLBGWEpvTraJ6L7RIfaA1j8HtLSGFsfkkPpac6NEq/vwfYvxkChePVhFVz0
         zGtFqIYJvGNuFC3Z7/taLo2tc6jISz+sFnh0cjRQcwnA4UvH7oquNgefuj1Cpe/FK86C
         PMWg3oKzC3bF7YaTsFyj/LMUOz20GeyjgUe79f8Ii/Ghr3Z5F1yoePvn5Zb0joidNG6l
         MBaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id f41-20020a0565123b2900b00479071ed831si1275105lfv.11.2022.06.10.08.21.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jun 2022 08:21:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 27FC5B835F8;
	Fri, 10 Jun 2022 15:21:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 20B78C34114;
	Fri, 10 Jun 2022 15:21:52 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v2 4/4] arm64: kasan: Revert "arm64: mte: reset the page tag in page->flags"
Date: Fri, 10 Jun 2022 16:21:41 +0100
Message-Id: <20220610152141.2148929-5-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220610152141.2148929-1-catalin.marinas@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

This reverts commit e5b8d9218951e59df986f627ec93569a0d22149b.

Pages mapped in user-space with PROT_MTE have the allocation tags either
zeroed or copied/restored to some user values. In order for the kernel
to access such pages via page_address(), resetting the tag in
page->flags was necessary. This tag resetting was deferred to
set_pte_at() -> mte_sync_page_tags() but it can race with another CPU
reading the flags (via page_to_virt()):

P0 (mte_sync_page_tags):	P1 (memcpy from virt_to_page):
				  Rflags!=0xff
  Wflags=0xff
  DMB (doesn't help)
  Wtags=0
				  Rtags=0   // fault

Since now the post_alloc_hook() function resets the page->flags tag when
unpoisoning is skipped for user pages (including the __GFP_ZEROTAGS
case), revert the arm64 commit calling page_kasan_tag_reset().

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>
---
 arch/arm64/kernel/hibernate.c | 5 -----
 arch/arm64/kernel/mte.c       | 9 ---------
 arch/arm64/mm/copypage.c      | 9 ---------
 arch/arm64/mm/mteswap.c       | 9 ---------
 4 files changed, 32 deletions(-)

diff --git a/arch/arm64/kernel/hibernate.c b/arch/arm64/kernel/hibernate.c
index 2e248342476e..af5df48ba915 100644
--- a/arch/arm64/kernel/hibernate.c
+++ b/arch/arm64/kernel/hibernate.c
@@ -300,11 +300,6 @@ static void swsusp_mte_restore_tags(void)
 		unsigned long pfn = xa_state.xa_index;
 		struct page *page = pfn_to_online_page(pfn);
 
-		/*
-		 * It is not required to invoke page_kasan_tag_reset(page)
-		 * at this point since the tags stored in page->flags are
-		 * already restored.
-		 */
 		mte_restore_page_tags(page_address(page), tags);
 
 		mte_free_tag_storage(tags);
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 57b30bcf9f21..7ba4d6fd1f72 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -48,15 +48,6 @@ static void mte_sync_page_tags(struct page *page, pte_t old_pte,
 	if (!pte_is_tagged)
 		return;
 
-	page_kasan_tag_reset(page);
-	/*
-	 * We need smp_wmb() in between setting the flags and clearing the
-	 * tags because if another thread reads page->flags and builds a
-	 * tagged address out of it, there is an actual dependency to the
-	 * memory access, but on the current thread we do not guarantee that
-	 * the new page->flags are visible before the tags were updated.
-	 */
-	smp_wmb();
 	mte_clear_page_tags(page_address(page));
 }
 
diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 0dea80bf6de4..24913271e898 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -23,15 +23,6 @@ void copy_highpage(struct page *to, struct page *from)
 
 	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
 		set_bit(PG_mte_tagged, &to->flags);
-		page_kasan_tag_reset(to);
-		/*
-		 * We need smp_wmb() in between setting the flags and clearing the
-		 * tags because if another thread reads page->flags and builds a
-		 * tagged address out of it, there is an actual dependency to the
-		 * memory access, but on the current thread we do not guarantee that
-		 * the new page->flags are visible before the tags were updated.
-		 */
-		smp_wmb();
 		mte_copy_page_tags(kto, kfrom);
 	}
 }
diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
index a9e50e930484..4334dec93bd4 100644
--- a/arch/arm64/mm/mteswap.c
+++ b/arch/arm64/mm/mteswap.c
@@ -53,15 +53,6 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
 	if (!tags)
 		return false;
 
-	page_kasan_tag_reset(page);
-	/*
-	 * We need smp_wmb() in between setting the flags and clearing the
-	 * tags because if another thread reads page->flags and builds a
-	 * tagged address out of it, there is an actual dependency to the
-	 * memory access, but on the current thread we do not guarantee that
-	 * the new page->flags are visible before the tags were updated.
-	 */
-	smp_wmb();
 	mte_restore_page_tags(page_address(page), tags);
 
 	return true;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220610152141.2148929-5-catalin.marinas%40arm.com.
