Return-Path: <kasan-dev+bncBD52JJ7JXILRB3WXRORQMGQEYOTTO7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 75572704372
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 04:35:27 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-7577727a00esf153606485a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 19:35:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684204526; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7Qi8G3nDNVMW8VyLCEyUNP+dUVoKv+zowMzTQVqNYfqcNBz2v6Mh8SAe1jEKp4ocl
         X/Er4EuHdVSikILJQ6zVJPgmLv1F4kfP0Unj44Clu8Xhp8elhrU/DGXjBEaqQTNIh3bY
         kdbHEu3Egbnl/ExgpIAvW5fxLkt06SEff5rP2Q6P/u6nr8qXZQabwvImXeI8FW0IZ4Q9
         pmWZpqaGUBF99bAzZul60i38YsK5e4Gxkc1dmryoGQd7qiFjq8HMItZbnFXrrE3jMW/5
         nQkAWR03AcW35Hw3+4hkwQpDZOlJV8wFpiUOrhI+RIR1O51BboN1bzPqnC/sND+Ri7LY
         67sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VbN7zhk49xHaVNGZpsQ2yWBzvVPB4+HohAUlMIrSzjQ=;
        b=NN3UllQoay7dsm2oU3mfF5znueitfu0NF+YDtj2DRqfA5vwXcjFHgrxGoDMKKmP/Q8
         L26Er16YfW+f/TtlUdlUNn51GGxXnLKf1LlyHiIyHPnDCc/5gQYFtKrIszlw2hVu1zOB
         pBkuZasxACNQRAdxJyGVrjMelq3omzmVd/hMCeSvH8WuRwoYXlKkWO7dwNnfKPDczjHX
         i2ogQ0Aiywwx/cD1u7x/UhDAhcqmxeY7y4YUgNcERZuOvdqbNzxfYYfbtXvRs0UQuPER
         oWxCIEL1Vtj/04nwjr5tLLLBlHoDthJJGoRc9xc9OYgc35B+/OdmE/vkVJsAZgiWOwtI
         Zm+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=vKfIPmvX;
       spf=pass (google.com: domain of 37etizamkcxonaaemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37etiZAMKCXonaaemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684204526; x=1686796526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VbN7zhk49xHaVNGZpsQ2yWBzvVPB4+HohAUlMIrSzjQ=;
        b=nArHE0R62f1GGZAK2tPUoSYnpKZrE2mm88kWBY7ZKMocCU8/klEHV1aHFZRQIHhE0j
         UvWtb4MFhlWso7rR4lMb/V2SEdpy3GJZgTe88uLZGolh59nKce3gzO1VGJnO9VWZy0EX
         TDyengnkri1Hu2RL00H7OSWXZDj2zlPEwit+DcB4pKuiuvvlrICcMb4iBfySlChyyBwx
         d40wpvaoPYzErfKXqWfAupOnGwoQW7H8EItTrHdtRrbZtu4EvFJnlmh2nFDO7DmpObzx
         oTDYK1kedcwSnIz1T3XnPnoK9gJ5FohIKmTBYHS0gKAF/3nSDwEYlW3K4/vE7yR+JR3z
         TYrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684204526; x=1686796526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VbN7zhk49xHaVNGZpsQ2yWBzvVPB4+HohAUlMIrSzjQ=;
        b=RSoenA3JlaAqbwQuxx8klmoVPOFdlDEgPxe2Dt6K9fDxQAHYSPJw6L/vSbrBtAFB3q
         Bk7PKJexRjTSVUd6+CzYUEhL5LeNZQlT/lJaIgQoaDX7ZHtq5ukonThphcEQQVkK+5fu
         Ne3cyFlFlGkjXZbTSADBbXe3pIF1Fn6OQy6jLSmoztfw+DRVd07UmlPPO7D0iZJckY/T
         E02yjy86LbEs4eQcyvVAKHPx+9a4OVc4NiA66JxcV6RE3pFLKHYodPackyXct31yZmp5
         MuPBs5i38vRwdtBO8WP9s1+SOhksnrxW2iivQKkzucCGvA4wRB8SL7cwpA5BrplNNULF
         d5pg==
X-Gm-Message-State: AC+VfDz1CxkrCWM+hu86K4vwWagX54t7yOQk0LBS+DsEWWstnmAN76Z/
	8Vqf3HCpvXgWWr/6jo06GwQ=
X-Google-Smtp-Source: ACHHUZ6PrxCxaHubuef70M466150/hSD3i9bEoBufZRPIHBnFwK5p8Yp598uIVXLg6p8m38azv1Nmg==
X-Received: by 2002:a05:620a:2451:b0:759:1a0f:dc91 with SMTP id h17-20020a05620a245100b007591a0fdc91mr4295594qkn.7.1684204526191;
        Mon, 15 May 2023 19:35:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:459e:b0:61b:5dbe:d03a with SMTP id
 op30-20020a056214459e00b0061b5dbed03als23317757qvb.7.-pod-prod-gmail; Mon, 15
 May 2023 19:35:25 -0700 (PDT)
X-Received: by 2002:a05:6214:2305:b0:61b:5bcd:db57 with SMTP id gc5-20020a056214230500b0061b5bcddb57mr56228904qvb.48.1684204525532;
        Mon, 15 May 2023 19:35:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684204525; cv=none;
        d=google.com; s=arc-20160816;
        b=PNwqpoxrIyd5bHOBjQE84YZTWwKWPhUne7ZorHVpuCDSzazhVumEAnyT/9KQFu79I8
         A+0MtII7/4nJBZU2ktvKQxyHrfSrH+IDK4b3MBay6QueOMaSDNRoWDXvPQf5WoQ9UeOe
         /qas3b7cjK1vwl0iWionBqcww9m8Fqt4zT+wnMqOARh5sfk4m1YOy4E+6mwTUwF6I4+N
         nqdHoUVBGi77gQ0hLsAw2JP2Ld8qknc60XY8eVGuv/8fUGSlfG5f+w3/jpTA3GG6dylW
         0LyJypPROMAIdCW3CZI6daWT0e2e0oehGjVuBr3bepWqQWC5BgeUOT5CmEarXp8ofCum
         pBVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PFB1dkpGULUqWzGVGpWTfZD/wGkLnLUL2yYSj9UHJe8=;
        b=SrBcQfTyDzDY5Glivhqr5p3eEk9kQ9XhzuCBLP31I56J80LxTecnqrby9TiSt6dVUl
         sodEkb/TIVaR3QNJMYs/EqG9R891OlR3x7gMTXTWIokveGUE8KnA8f3TJ03ewPJBm3Rx
         LJMWSkGOv1e9kv3CWw2PZz4dQQtv+H+DxOBE5ljAm+vgUQA0SGcW/HS2RHWe3cjjTU9C
         voTaqN08G+xPVuqp67x8pNO3d1bfELVB3RmkRV2ghcUIQJ/47dc02H7nmXmHLTYmFfY2
         3mfzJGB9Fc8155IqqyLbNBBVweviDKwJG/8GjAZ50VerkgssK4bzn7E7zeqm2G3IhNGq
         Lo2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=vKfIPmvX;
       spf=pass (google.com: domain of 37etizamkcxonaaemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37etiZAMKCXonaaemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id dz8-20020ad45888000000b00621120c5026si1286794qvb.2.2023.05.15.19.35.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 May 2023 19:35:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37etizamkcxonaaemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-ba8217b3d30so185624276.2
        for <kasan-dev@googlegroups.com>; Mon, 15 May 2023 19:35:25 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:c825:9c0b:b4be:8ee4])
 (user=pcc job=sendgmr) by 2002:a25:dc43:0:b0:ba1:6f1b:8905 with SMTP id
 y64-20020a25dc43000000b00ba16f1b8905mr21936003ybe.4.1684204525241; Mon, 15
 May 2023 19:35:25 -0700 (PDT)
Date: Mon, 15 May 2023 19:35:13 -0700
In-Reply-To: <20230516023514.2643054-1-pcc@google.com>
Message-Id: <20230516023514.2643054-3-pcc@google.com>
Mime-Version: 1.0
References: <20230516023514.2643054-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH v2 2/2] arm64: mte: Simplify swap tag restoration logic and
 fix uninitialized tag issue
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
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=vKfIPmvX;       spf=pass
 (google.com: domain of 37etizamkcxonaaemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=37etiZAMKCXonaaemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--pcc.bounces.google.com;
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

This patch also fixes an issue where a page can have PG_mte_tagged set
with uninitialized tags. The issue is that the mte_sync_page_tags()
function sets PG_mte_tagged if it initializes page tags. Then we
return to mte_sync_tags(), which sets PG_mte_tagged again. At best,
this is redundant. However, it is possible for mte_sync_page_tags()
to return without having initialized tags for the page, i.e. in the
case where check_swap is true (non-compound page), is_swap_pte(old_pte)
is false and pte_is_tagged is false. So at worst, we set PG_mte_tagged
on a page with uninitialized tags. This can happen if, for example,
page migration causes a PTE for an untagged page to be replaced. If the
userspace program subsequently uses mprotect() to enable PROT_MTE for
that page, the uninitialized tags will be exposed to userspace.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I8ad54476f3b2d0144ccd8ce0c1d7a2963e5ff6f3
Fixes: e059853d14ca ("arm64: mte: Fix/clarify the PG_mte_tagged semantics")
Cc: <stable@vger.kernel.org> # 6.1
---
The Fixes: tag (and the commit message in general) are written assuming
that this patch is landed in a maintainer tree instead of
"arm64: mte: Do not set PG_mte_tagged if tags were not initialized".

 arch/arm64/include/asm/mte.h     |  4 ++--
 arch/arm64/include/asm/pgtable.h | 14 ++------------
 arch/arm64/kernel/mte.c          | 32 +++-----------------------------
 arch/arm64/mm/mteswap.c          |  7 +++----
 4 files changed, 10 insertions(+), 47 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 20dd06d70af5..dfea486a6a85 100644
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
index b6ba466e2e8a..efdf48392026 100644
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
index f5bcb0dc6267..c40728046fed 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -35,41 +35,15 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
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
 	for (i = 0; i < nr_pages; i++, page++) {
-		if (!page_mte_tagged(page)) {
-			mte_sync_page_tags(page, old_pte, check_swap,
-					   pte_is_tagged);
+		if (try_page_mte_tagging(page)) {
+			mte_clear_page_tags(page_address(page));
 			set_page_mte_tagged(page);
 		}
 	}
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230516023514.2643054-3-pcc%40google.com.
