Return-Path: <kasan-dev+bncBD52JJ7JXILRBKXUSCRQMGQERUD2TSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B79B705D10
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 04:21:32 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-ba8338f20bdsf148906276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 19:21:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684290091; cv=pass;
        d=google.com; s=arc-20160816;
        b=uT8Kt7g4P7M5e4YM5OmZk2Wc8uIJT44f0UiSXuDI5Egn4I0d9wd+lBwgvkMAK1s8jR
         e1UHhdQqCS4iV9QJ0VV/nee3Rk4eO9inlSCOHSbLVc9Y6oYHQXdhSglwKyM6DFZ1oVqF
         M1f+U399W6IT+UJBT4at3IXjldjyg9sFfjkb4MD7uJimd1+DiuR2WQfY98iE72ldDXth
         XteN1uqa/GiiL122QRmiH5LsVM8GjPXO4egklV9ffq41fhRqdRsb3tqlSbUSvMAK9aBF
         r1ZsvFo0VQYLK1Tp+4XYCC0jM50uASXDo8hYTi7Yf0Zpx0zlNbxPQnAGEGsJJfvHJkUq
         vfxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=KJu38qMoztyvOFg72fFT/yqXdC+AWojLcw2V7FTpOxM=;
        b=Qt9W7pA/ObwcSd0RXcM7O1Rgx5jCUIxZx/wT6nhEdfwppVxTFQqwnO9xStCvmVMFmq
         VpBoNgG49uGrhbJNARZ55wQkMuBh6/GTj7lWnZfnhhH9ei1Gk5VHAIuH/adfIEkXk+et
         afWrVvsLBfZqj13HTASxaiHo19DkVlAbEq2KHWb1cpTwOPozwtCTL4BSpd8PbsnmHNu7
         Mzn+YE+1mZ4qlbw+LJ6j+3ZiKyD1X9QJ4xNJ9mq8mK8hu2u/tjavHTQqgxjWCFyzBg4v
         po8T9rgYAuWhaCloomPEJMOmjCRfChcMHizc595T22M2a8qEO321HNVYGbejfrwyMl6G
         7t8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=nS7ih6tl;
       spf=pass (google.com: domain of 3ktpkzamkcvgf226ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3KTpkZAMKCVgF226EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684290091; x=1686882091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KJu38qMoztyvOFg72fFT/yqXdC+AWojLcw2V7FTpOxM=;
        b=AfuvBXWriHIvKeceosVn9/VnUt8MA++Ond8PW/s0U1cW2Hoj6F83BANzgfPuEgkGPi
         ydK5exMAci6SN0aQBIhylGPw1f8ZG4/TbFLNZaEoUYaxhpCu4CXCSq0q0KC+pVosDRr8
         iHADtC6nIl+K2CKxGrH6xqj6thWb9vPZmBCuKvWjlVDbZY09SpRun30XtQ4T/DzFqBFp
         Rjw8PicsZIMFN9OQmPFaojXISZf6xJuDm8kbg4SkeIFvQps8SXDkegemS8VtLoIoCKBr
         JnsE4RpS6v0ifXT1+780dPUgMqEWEnqbMlZmhVuDjeBKBk4PWAC7DH00FDWkpvqKiSzj
         MbpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684290091; x=1686882091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KJu38qMoztyvOFg72fFT/yqXdC+AWojLcw2V7FTpOxM=;
        b=T3KpCbqU1eHGYAOF1siGAUJzfiXYOQuhVtBTCrJgYQk74duG0Sv0rXdy46sJqbzXOb
         5uAFVbD9CLLb03hmjL/onYf8sn0SvkHiNB5utyrz3SjdPdmIwlCxESCJq3vaD8Kd8bh1
         lL3TJp5Udc1t7egarX7qmU5lD2tnRlo3uytXLuAS6KD1OcaN/OL+kkwzpzO99zbl9ctt
         iswLDbHWCl6Pj7oynEpj4vmT7gjNA8nDA91zAXvqa3LrB/9DBQ2MV3PLi54yVRth7MNX
         bsxbv8G8aJyYNH5mgSaxXNTQllKYS/i5iLgmhtS0P1SkMaAAEt0RO0wwxOyTpp+eEPmg
         cwiA==
X-Gm-Message-State: AC+VfDyC4KWIBDvdKzgHwj8qR885mUnwsbwz410VsMWd2NA0ZQJANVmW
	99ZdyvMCPyhciHTcNINcDak=
X-Google-Smtp-Source: ACHHUZ5p46KBREaWjrti/xtoXbwi+XUIVUwrflb/6GnBpA7AmnoxvzIowoPorwkc5Ts+gXDP94rL4A==
X-Received: by 2002:a5b:58f:0:b0:b8f:32c4:5cc4 with SMTP id l15-20020a5b058f000000b00b8f32c45cc4mr24798548ybp.4.1684290090841;
        Tue, 16 May 2023 19:21:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:5d0:0:b0:b92:4a72:d990 with SMTP id w16-20020a5b05d0000000b00b924a72d990ls8142500ybp.6.-pod-prod-gmail;
 Tue, 16 May 2023 19:21:30 -0700 (PDT)
X-Received: by 2002:a25:ca83:0:b0:ba8:32d9:eace with SMTP id a125-20020a25ca83000000b00ba832d9eacemr3184178ybg.16.1684290090227;
        Tue, 16 May 2023 19:21:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684290090; cv=none;
        d=google.com; s=arc-20160816;
        b=yd93sRe/LzDdOWM5IbwHlK5gn49Sl+y9m7BslS69er+fjXRAq43CToek+PnEDSF3KG
         xMGszhJ8OEidC3B2u9+OqIBliMNdDzRY/aXnvpnV+8t0VMaQf/lGgNBe+QG1rliUgTQ+
         v/FKWEn0vCiQ9cN8XggJo47DpLmbWZmMcVPIttx4ZM4nRN18AhOhQDOZZwWNw+rQmMBJ
         wh9t6SW4qJpzQZtMSdti0csUMhblq7Ij4DAtr+cB3moQkMU5XWXnTbT2IKvOqU2MHa2V
         O5C+WuiQs1cSV5UkbTz6smPpGdQW2I7Y90pjd0Kuc9Q4ldMfXU290IvyCwV/bEpA+0J/
         D39w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rrlZpn5lxQz0wYWidXhNS5k4qYdBDD7AOOGwfPiDsdQ=;
        b=g9XM/BT8cfnYF87tjAuqoiUKgnuK6ulxFqHL5LOTl++MLR7xezbEFHfOjMYliFFbUP
         fR2zG4jD+k6GHBm+AjnElWGrGfk0xOUD6VENWXNV8IbxHszg6OccMTCogE6MashD+qMu
         /0IwkdpmD3SDpBI5GqEPC1H/E/XOP5+1rzDvncizWPEgI9ltjRRfiagfdZ2QlHyPZPp4
         lLKX4hwgmV2MOSV4wUmYIS2H+392ElxVcvyfzso9LAbMuzAn8CtXaVTXO0bE0b7scVED
         4fb56cjzw2tp8dSVq+yKlUNTW/o56efuIxAVbKQ+J5Luy2/X/bAqgEXknegK5tK7rpyC
         B8jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=nS7ih6tl;
       spf=pass (google.com: domain of 3ktpkzamkcvgf226ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3KTpkZAMKCVgF226EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id ck12-20020a05690218cc00b00ba778438c17si50294ybb.0.2023.05.16.19.21.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 19:21:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ktpkzamkcvgf226ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-559d35837bbso2535057b3.3
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 19:21:30 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:b3a7:7c59:b96b:adaa])
 (user=pcc job=sendgmr) by 2002:a81:ae54:0:b0:559:f89f:bc81 with SMTP id
 g20-20020a81ae54000000b00559f89fbc81mr23166501ywk.6.1684290089941; Tue, 16
 May 2023 19:21:29 -0700 (PDT)
Date: Tue, 16 May 2023 19:21:13 -0700
In-Reply-To: <20230517022115.3033604-1-pcc@google.com>
Message-Id: <20230517022115.3033604-4-pcc@google.com>
Mime-Version: 1.0
References: <20230517022115.3033604-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH v3 3/3] arm64: mte: Simplify swap tag restoration logic
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Peter Collingbourne <pcc@google.com>, 
	"=?UTF-8?q?Qun-wei=20Lin=20=28=E6=9E=97=E7=BE=A4=E5=B4=B4=29?=" <Qun-wei.Lin@mediatek.com>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	"surenb@google.com" <surenb@google.com>, "david@redhat.com" <david@redhat.com>, 
	"=?UTF-8?q?Chinwen=20Chang=20=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=" <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"=?UTF-8?q?Kuan-Ying=20Lee=20=28=E6=9D=8E=E5=86=A0=E7=A9=8E=29?=" <Kuan-Ying.Lee@mediatek.com>, 
	"=?UTF-8?q?Casper=20Li=20=28=E6=9D=8E=E4=B8=AD=E6=A6=AE=29?=" <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=nS7ih6tl;       spf=pass
 (google.com: domain of 3ktpkzamkcvgf226ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3KTpkZAMKCVgF226EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

As a result of the previous two patches, there are no circumstances
in which a swapped-in page is installed in a page table without first
having arch_swap_restore() called on it. Therefore, we no longer need
the logic in set_pte_at() that restores the tags, so remove it.

Because we can now rely on the page being locked, we no longer need to
handle the case where a page is having its tags restored by multiple tasks
concurrently, so we can slightly simplify the logic in mte_restore_tags().

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I8ad54476f3b2d0144ccd8ce0c1d7a2963e5ff6f3
---
v3:
- Rebased onto arm64/for-next/fixes, which already has a fix
  for the issue previously tagged, therefore removed Fixes:
  tag

 arch/arm64/include/asm/mte.h     |  4 ++--
 arch/arm64/include/asm/pgtable.h | 14 ++----------
 arch/arm64/kernel/mte.c          | 37 ++++++--------------------------
 arch/arm64/mm/mteswap.c          |  7 +++---
 4 files changed, 14 insertions(+), 48 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index c028afb1cd0b..4cedbaa16f41 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -90,7 +90,7 @@ static inline bool try_page_mte_tagging(struct page *page)
 }
 
 void mte_zero_clear_page_tags(void *addr);
-void mte_sync_tags(pte_t old_pte, pte_t pte);
+void mte_sync_tags(pte_t pte);
 void mte_copy_page_tags(void *kto, const void *kfrom);
 void mte_thread_init_user(void);
 void mte_thread_switch(struct task_struct *next);
@@ -122,7 +122,7 @@ static inline bool try_page_mte_tagging(struct page *page)
 static inline void mte_zero_clear_page_tags(void *addr)
 {
 }
-static inline void mte_sync_tags(pte_t old_pte, pte_t pte)
+static inline void mte_sync_tags(pte_t pte)
 {
 }
 static inline void mte_copy_page_tags(void *kto, const void *kfrom)
diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
index 0bd18de9fd97..e8a252e62b12 100644
--- a/arch/arm64/include/asm/pgtable.h
+++ b/arch/arm64/include/asm/pgtable.h
@@ -337,18 +337,8 @@ static inline void __set_pte_at(struct mm_struct *mm, unsigned long addr,
 	 * don't expose tags (instruction fetches don't check tags).
 	 */
 	if (system_supports_mte() && pte_access_permitted(pte, false) &&
-	    !pte_special(pte)) {
-		pte_t old_pte = READ_ONCE(*ptep);
-		/*
-		 * We only need to synchronise if the new PTE has tags enabled
-		 * or if swapping in (in which case another mapping may have
-		 * set tags in the past even if this PTE isn't tagged).
-		 * (!pte_none() && !pte_present()) is an open coded version of
-		 * is_swap_pte()
-		 */
-		if (pte_tagged(pte) || (!pte_none(old_pte) && !pte_present(old_pte)))
-			mte_sync_tags(old_pte, pte);
-	}
+	    !pte_special(pte) && pte_tagged(pte))
+		mte_sync_tags(pte);
 
 	__check_safe_pte_update(mm, ptep, pte);
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 7e89968bd282..c40728046fed 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -35,41 +35,18 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
 EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
 #endif
 
-static void mte_sync_page_tags(struct page *page, pte_t old_pte,
-			       bool check_swap, bool pte_is_tagged)
-{
-	if (check_swap && is_swap_pte(old_pte)) {
-		swp_entry_t entry = pte_to_swp_entry(old_pte);
-
-		if (!non_swap_entry(entry))
-			mte_restore_tags(entry, page);
-	}
-
-	if (!pte_is_tagged)
-		return;
-
-	if (try_page_mte_tagging(page)) {
-		mte_clear_page_tags(page_address(page));
-		set_page_mte_tagged(page);
-	}
-}
-
-void mte_sync_tags(pte_t old_pte, pte_t pte)
+void mte_sync_tags(pte_t pte)
 {
 	struct page *page = pte_page(pte);
 	long i, nr_pages = compound_nr(page);
-	bool check_swap = nr_pages == 1;
-	bool pte_is_tagged = pte_tagged(pte);
-
-	/* Early out if there's nothing to do */
-	if (!check_swap && !pte_is_tagged)
-		return;
 
 	/* if PG_mte_tagged is set, tags have already been initialised */
-	for (i = 0; i < nr_pages; i++, page++)
-		if (!page_mte_tagged(page))
-			mte_sync_page_tags(page, old_pte, check_swap,
-					   pte_is_tagged);
+	for (i = 0; i < nr_pages; i++, page++) {
+		if (try_page_mte_tagging(page)) {
+			mte_clear_page_tags(page_address(page));
+			set_page_mte_tagged(page);
+		}
+	}
 
 	/* ensure the tags are visible before the PTE is set */
 	smp_wmb();
diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
index cd508ba80ab1..3a78bf1b1364 100644
--- a/arch/arm64/mm/mteswap.c
+++ b/arch/arm64/mm/mteswap.c
@@ -53,10 +53,9 @@ void mte_restore_tags(swp_entry_t entry, struct page *page)
 	if (!tags)
 		return;
 
-	if (try_page_mte_tagging(page)) {
-		mte_restore_page_tags(page_address(page), tags);
-		set_page_mte_tagged(page);
-	}
+	WARN_ON_ONCE(!try_page_mte_tagging(page));
+	mte_restore_page_tags(page_address(page), tags);
+	set_page_mte_tagged(page);
 }
 
 void mte_invalidate_tags(int type, pgoff_t offset)
-- 
2.40.1.606.ga4b1b128d6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230517022115.3033604-4-pcc%40google.com.
