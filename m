Return-Path: <kasan-dev+bncBD52JJ7JXILRBK4YWCRQMGQE34J3B5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 97B1C70CFB0
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 02:43:25 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-5654242df11sf2860407b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 17:43:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684802604; cv=pass;
        d=google.com; s=arc-20160816;
        b=tH76KPYKzI5xeqq3uO8hZoC2jyXw+S0qokypc0NYW0U5jRRsWw4jEOPFWmqqYLPQHe
         8BXdCPSrTHoRrPRHr7buxGmhd6NQzS9EkqHOcympyvik7LacWlTiDybwn2bkiVDFl9Yo
         84eUhOIrlX8k86AJRzAQbM9/kr6K37/MSonvq5lTFEd8BLpfDmrviCgFQnVohOYAVbuY
         sRlu99PSIVeKtuKFr+5bDQeQcS4FCOTkeZt/7vYwhw0IfbLReAGSMjsgF1jDw2bq7Uv7
         Fk4J0yt1UOhpBzQgASOcDVgccMm+uLghOjU6IoRjgTfVK4sPsS5/pSf0IbiVAGlQVeWF
         i5VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=BlHrTwyxgYWDGzRlTyiSnyVYDiMYiyzsjG/LlTObCto=;
        b=YxUKuL479KE+hrK0UkDwI8afuF20wf/jp2U4iqizsJyiDfj3iLd72yx//94YTYfrLm
         Dcc+JCIj2DOisNQFNE0aeIlK3QaXOznaBi6T7YczW7isS4teMiBE+3Gfy65vSVK3/T2M
         c5rFLwxVcYYVrbWkXGHgZ0qVpANpR5r8CFtUZAuGwraCKbzsX4zH4/w8hk67nWjKBiNL
         eMvVGOkPE7pklxwVzcvknZ7Mpfw6REYckxErARlFUKAR11kjQnKjA8DWAQbX5WKrhOft
         xBgSxSbekBUD5PWJHidqJfindBwuDlYqj1UqnMMOZpiDF59qWqwe6SJR6zwuL1SbnwbF
         nvvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=XY4gva+E;
       spf=pass (google.com: domain of 3kwxszamkcr4j66aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3KwxsZAMKCR4J66AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684802604; x=1687394604;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BlHrTwyxgYWDGzRlTyiSnyVYDiMYiyzsjG/LlTObCto=;
        b=L3EWX6Sq6CrGNYCCQ03MJtGk0F3rkqDcTmAbNRT6G4vlHx8rFDn44pRLnrNRqX49nS
         uTUl+XKDtUSBbZ5ZH6VFcubQQ9ZxrBC4OtpBkQ/sBpa6pAIG20Z7CQuxbBJm/1c/ObV8
         Ks/hscsi5eAWg7OA4Zye78YOxqKScG7aGh8P0vidrbfzdLDwBJct+L+LX9OEJ38MYWPT
         OjegusZRMYhkB2wCNdAxOuC5esfy5qi9D729HawZPwlXQMF/vsM1xAjWK3xRQuKhLu9v
         P9EUt2KmCeDOevpoqiIto2/vuFoIoVPdJBqDhWajwWMmUml3NHUfo64pm3m6FUvefqWr
         LLdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684802604; x=1687394604;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BlHrTwyxgYWDGzRlTyiSnyVYDiMYiyzsjG/LlTObCto=;
        b=Sf99DX+/iX0Zt2n+7/iCkMwiRQgJ7bI0xgLNzvtdTKbyJcJskFgvOjHXEK9tZJ++LQ
         Bfj46SXWCBM3raol9GXR9N+Qri2SO6qRpGr9+DoBQArWQk5q6cwaQBNRVNf+kj7Gji3I
         AOZpuAB3F2YL9V6dpvdcMo8Vh1wVBgtevL0mtZaSQrTx5+I1Mt4E10u6Cz2LohqasKJy
         kO72NPLYlPNlD2azvErEmgrlgSOkxBXDCGFSZVyBHNAP8S7WZgxapzXa5cl6s+hKvoMJ
         /WO+hGOQfKq02N/8WlQ3soXNXtI0N2JS7FheLJWsa8gpWrGuC0WhVxVfu03OZM3Vox5L
         IL5w==
X-Gm-Message-State: AC+VfDyBRgqwvRVUVl/KGaC3aoL+M85eozb/Zq2gIsRLji2BLO0h8Aqb
	QswoeU/3zzkFCn1ginKOqOI=
X-Google-Smtp-Source: ACHHUZ4P5oRiTloQ4nBKFLZT7xNs7mFcVJqowf63GfwC+uYwm6GDVwETeTQvD2XScT5SuQnM9DdOjA==
X-Received: by 2002:a81:b147:0:b0:54c:2409:c306 with SMTP id p68-20020a81b147000000b0054c2409c306mr7062970ywh.6.1684802604061;
        Mon, 22 May 2023 17:43:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9382:0:b0:ba8:14dc:b584 with SMTP id a2-20020a259382000000b00ba814dcb584ls1424310ybm.1.-pod-prod-08-us;
 Mon, 22 May 2023 17:43:23 -0700 (PDT)
X-Received: by 2002:a25:ae92:0:b0:ba8:58f1:6179 with SMTP id b18-20020a25ae92000000b00ba858f16179mr14474343ybj.30.1684802603433;
        Mon, 22 May 2023 17:43:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684802603; cv=none;
        d=google.com; s=arc-20160816;
        b=cD8/RGoaHgYxDqGep+CIW3VsclRtRFVEx7PzynkyxmhjL6SghmmwkqgUhIAZCRcNpL
         QJhi9doxrqqktW+LgD1KzpDDeU2jVoqtefjJWYaub5p6aNZ1i8jqgzlgk1Q+L4Qijd/P
         L+eWgLeD+E/INVL5xAJ32Zurz+o0HWrSNRFRzIkW+p5RvoAFu7arUlZOLdIsNmv5VxB7
         KDgYiJNFF979hUJTJzdPQjbuvRsEMm2tRNrND6+qyo8/CLgMl06C1kJSXBVlaxhZI4/E
         hn8rz2TvyJXyawSXzK46OojJ1Z31A3mzNBO0nGuDrzCxx65zQq+/e+ZnqNkArfJEW6Tt
         xjrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=EOtAXf5wuxpOrHzLJXv+xvDvcqfWad6caZwbz93V+KE=;
        b=nFLr5ofhX9cPBza6sbyfbGimcj0DVnhEYHZJCXve4HMDHsvF8hdT3WbsVO6/YkvJbW
         VufZDZHXGfwqQb4W5LVkrh4MRDwEbvnZhKDogBgT/agQm4/OQ3cJ7LbER23lFPKTmYBO
         WOPZEiJceby1O6cEOvJ4Ebc24LXqTwMw+aVK6zI0FiS9CjX1a0Tw55awApybtD86/9Ns
         P1XhzfCuYvVDQcJfvRIkgp6wI6wKRNngQmJtKcdq+dS6Kh2h8ZFa6WRlEOpETL7SmUxK
         tLn1XYaSmCA/aB8nJ6BDBt2eS2UL0W8qcINheN+LLXgj57gjlFem+UfZ6T0Hx6htl/Qx
         CCrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=XY4gva+E;
       spf=pass (google.com: domain of 3kwxszamkcr4j66aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3KwxsZAMKCR4J66AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id f186-20020a251fc3000000b00ba6a57f8334si484448ybf.1.2023.05.22.17.43.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 May 2023 17:43:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kwxszamkcr4j66aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-ba81b37d9d2so12214283276.3
        for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 17:43:23 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:3d33:90fe:6f02:afdd])
 (user=pcc job=sendgmr) by 2002:a25:fe08:0:b0:ba7:8099:c5f2 with SMTP id
 k8-20020a25fe08000000b00ba78099c5f2mr5220235ybe.8.1684802603205; Mon, 22 May
 2023 17:43:23 -0700 (PDT)
Date: Mon, 22 May 2023 17:43:10 -0700
In-Reply-To: <20230523004312.1807357-1-pcc@google.com>
Message-Id: <20230523004312.1807357-4-pcc@google.com>
Mime-Version: 1.0
References: <20230523004312.1807357-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.698.g37aff9b760-goog
Subject: [PATCH v4 3/3] arm64: mte: Simplify swap tag restoration logic
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
 header.i=@google.com header.s=20221208 header.b=XY4gva+E;       spf=pass
 (google.com: domain of 3kwxszamkcr4j66aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3KwxsZAMKCR4J66AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--pcc.bounces.google.com;
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

Signed-off-by: Peter Collingbourne <pcc@google.com>
Link: https://linux-review.googlesource.com/id/I8ad54476f3b2d0144ccd8ce0c1d7a2963e5ff6f3
Reviewed-by: Steven Price <steven.price@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
v4:
- Rebased onto v6.4-rc3
- Reverted change to arch/arm64/mm/mteswap.c; this change was not
  valid because swapcache pages can have arch_swap_restore() called
  on them multiple times

v3:
- Rebased onto arm64/for-next/fixes, which already has a fix
  for the issue previously tagged, therefore removed Fixes:
  tag

 arch/arm64/include/asm/mte.h     |  4 ++--
 arch/arm64/include/asm/pgtable.h | 14 ++----------
 arch/arm64/kernel/mte.c          | 37 ++++++--------------------------
 3 files changed, 11 insertions(+), 44 deletions(-)

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
-- 
2.40.1.698.g37aff9b760-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230523004312.1807357-4-pcc%40google.com.
