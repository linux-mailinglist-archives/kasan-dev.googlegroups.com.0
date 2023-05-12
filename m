Return-Path: <kasan-dev+bncBD52JJ7JXILRBHFF7ORAMGQE4LBOY6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 34D287012D6
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 01:58:22 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id ada2fe7eead31-4348c88959dsf2136596137.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 16:58:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683935901; cv=pass;
        d=google.com; s=arc-20160816;
        b=uFVwppkUISPyvKSkwWa26xoYHwwr8py2s0r2LVrHFGVg5RxMlRJOngr1sAPN5BgDWO
         Gk7g+LzhCnIRd+w1siz5Ls7zcECw0A+ueyZPLC8/2urr7GvetGoWv63M56UFWDT9e64O
         BUg8t++bCMdMQOgongyZXiIafujyvqO5YF0etlpnSRf6EX//3y3GxsI5SVOsoiZl3Ld6
         Z0UmQfcWVonXdBu9vwpZ9Z/1/J+/4/J8azHIsnEZEM3TTdJrvjckhexqsg9N74TP0Qxe
         gr7VNH7NwtMJe2v4nN+8siLtn9BudCRfY+ju5gYSUAonpXftzod7a+FQSAGPzn4BNtsZ
         m8ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=AZ9o26rSXSx/t5dowCYz0607o8LaSkO0t0G7U+uoIso=;
        b=wq+Y54rkwPt4YPjMKjjxaEBMdxA5pGDJxW+SFl5vbhguCueJMRrRzpH3tsVl8otWpy
         K/fHSxB+wUznwjcAAwwvm6Pa3z8tYltpGEwU6+hx8umGftmfLjn9UOo1l7o+nF1q2gUo
         V+GW3mg6z0xS4Tr8SR5QXfXXmPC6zfkMYzKG9OwluoTH4kWdH5FvNaYim1OoDaBZw00j
         sZAFYwAvKugtgaJuIyvUkvsU5DjpdXodRvvzRfgxrbCT3KY4a+QYGhsCF3Akd0ZSvkTj
         +2WCn+68JB4cMcqCzpMfcXmsOewKkxwebTlo621Nfum36Ajf27129Rq4keEJzHAytRk6
         HOJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=RfEuSDTL;
       spf=pass (google.com: domain of 3m9jezamkceqviimuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3m9JeZAMKCeQVIIMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683935901; x=1686527901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AZ9o26rSXSx/t5dowCYz0607o8LaSkO0t0G7U+uoIso=;
        b=G5autMjYA6DNbfLkKQooxObNEfuSHHUu0yZdsY8WHb1qtjEOJlTPT7nKBPpTlU+zud
         wKCMIZicleLDMwWLy+KHHDCZNXVLqyD8k/k4qVaLbJP/GvQx4l2LMMHtGjCbS8KyN2TM
         zGfxK/ttFUSO0xObmB7hnoMK3RyvXCIaSdDHI7YATHkfjTlZjDPbRKmOsNETXPlioADB
         m/fMcGcI1Pe0tAYiB5gqlOFkhWmJzGoyoTw3H32L+RVKhA9pJ9nQn1r1vO/pl8xXpYhp
         ZqAMbpjoxQSAJST8piLODrwbuol2JbqjKxEfYz53E7nD7ojWkh8n8MuA0/6VDPSJoz4d
         PeEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683935901; x=1686527901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AZ9o26rSXSx/t5dowCYz0607o8LaSkO0t0G7U+uoIso=;
        b=i3qAQgz7dVq5zgxmiRW7owoDxHTLp9anJAigYtz+KoW2AfOR/9tmn3HafZ9LrE+t4v
         ueJNRttra2FpW9fdvu4ykgiJTNt44ZTNgPZL2Wm81dVCLaiifuTGIWrboXkDSa1aPTSo
         k9z+yo0NgIwq3j09cYcYQp0N/zZlDWUhO2/uyidX1a0Fj0/aiMDd3uJ2pgCrXUH6NgK1
         DBRG7bGLgluNL9NTMC4845QGG3FihbbAkwZnDiZ6m3sQ9Hnh1QbAXSFcK3s8ATrmw1f5
         LdrskHEdypqyMAaFauXjlmkHadXvfgBDXQ4D741UvTOsmpcUxZbwLtoq2AZxHPPc44sF
         6UWQ==
X-Gm-Message-State: AC+VfDx0UPu/jjwmpFeA9YLetWaZQyjpjCZAzIcHtCkcb4G0Y8V3Sy9z
	hQu4e50ej9BiY7AouFzD89Q=
X-Google-Smtp-Source: ACHHUZ4+AK+aINwn88aGiufWW9S0D5YwgQMND9FZJK70APHhu0SBcSba43u+Heai+XSrm6YMdMee5w==
X-Received: by 2002:a67:c306:0:b0:42c:6c77:d113 with SMTP id r6-20020a67c306000000b0042c6c77d113mr14687714vsj.5.1683935901002;
        Fri, 12 May 2023 16:58:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:d88:b0:43c:4909:450 with SMTP id
 bc8-20020a0561220d8800b0043c49090450ls4620087vkb.9.-pod-prod-gmail; Fri, 12
 May 2023 16:58:20 -0700 (PDT)
X-Received: by 2002:a1f:66c2:0:b0:43f:e949:758f with SMTP id a185-20020a1f66c2000000b0043fe949758fmr9908612vkc.4.1683935900280;
        Fri, 12 May 2023 16:58:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683935900; cv=none;
        d=google.com; s=arc-20160816;
        b=xkZkDW0a4Q9TFSXo+XKC/Cx3/Demg8XorRorQv8TrKkkwUj1VbNKnX1PcJTQbbCDGr
         V6K/7zMNQuvuhK7OctzEVv7LucZx8XZtFkuj3P6sM8WHf3RrgmmQvdwfTToov/BwClXa
         0xpx0+eqHLLrHX5B21Npp7kXFoL4gn37Jyh25/X1KrYSGa72l2HtDCZGGLu3XIpsjpN3
         BqONoYh7hn+2SkOWA4iYwxFHuW5MceIc4tNgNDLRv80vjAMPY45FBeR0eIBpd8wqLeVs
         Q7YXCek9E3Jv+2aljrD5wc+7hc67v8SkFhTiJMOWIK7IRCHa/BLthr4kGhjN/jQlKFiD
         egjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PFB1dkpGULUqWzGVGpWTfZD/wGkLnLUL2yYSj9UHJe8=;
        b=GzKPzcZY6ad1lgdxXiNOtHhFht9kgK5HjOq8RSQVt+BXULMyS/xoluZ7wxN7dfuNCC
         JriK7/BaEnE7Lw+qhqBcDhGTjP7K+Hwk+pTtCqSKUu9rV9ceNN1BQ1NLy0ISu97Wk3yG
         BZ2R3jUW5HKl1PoGQ0/fAqK0YqCMeAKMuAVM1Jsh9WRsiCD+LMAgTRnxKHlY7cDTa7/c
         DAWSTV64JtWcXUUqr5DTqmC32/k6Vwt3pkKQawY3JpxMqCkZUWH5gCqYWp5vT2ojkgSx
         GxWsB6YlchAdpiXdorUe+EYPQCuCdijHMlG2gdvx5sQXPtSJc80cHp6fkgiUNJpncebn
         eXrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=RfEuSDTL;
       spf=pass (google.com: domain of 3m9jezamkceqviimuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3m9JeZAMKCeQVIIMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x54a.google.com (mail-pg1-x54a.google.com. [2607:f8b0:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n28-20020a05612213bc00b0044f89ac0658si1277174vkp.0.2023.05.12.16.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 16:58:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m9jezamkceqviimuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) client-ip=2607:f8b0:4864:20::54a;
Received: by mail-pg1-x54a.google.com with SMTP id 41be03b00d2f7-52c3f0b1703so9900790a12.1
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 16:58:20 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:ff6:108b:739d:6a1c])
 (user=pcc job=sendgmr) by 2002:a63:151:0:b0:52c:6149:f6be with SMTP id
 78-20020a630151000000b0052c6149f6bemr7437419pgb.4.1683935899323; Fri, 12 May
 2023 16:58:19 -0700 (PDT)
Date: Fri, 12 May 2023 16:57:52 -0700
In-Reply-To: <20230512235755.1589034-1-pcc@google.com>
Message-Id: <20230512235755.1589034-4-pcc@google.com>
Mime-Version: 1.0
References: <20230512235755.1589034-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH 3/3] arm64: mte: Simplify swap tag restoration logic and fix
 uninitialized tag issue
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
 header.i=@google.com header.s=20221208 header.b=RfEuSDTL;       spf=pass
 (google.com: domain of 3m9jezamkceqviimuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=3m9JeZAMKCeQVIIMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--pcc.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512235755.1589034-4-pcc%40google.com.
