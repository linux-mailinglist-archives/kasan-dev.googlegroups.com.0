Return-Path: <kasan-dev+bncBCT4XGV33UIBBIX23KTAMGQEYPFRPIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id F1368779AE5
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Aug 2023 00:58:43 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-64189040afasf22004656d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 15:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691794722; cv=pass;
        d=google.com; s=arc-20160816;
        b=qr4uNSk0gz7hx2zYjxILJSb1A/9d+66RWmhPStYc8vuCG4KlADNaaKTNjj7f/Fm4M2
         oJ7ducRuwOJ060gXmHqr60zqoWWzSnonVj20v+KAzbbeCeKEAIjBIvHIJONznwfYyGrD
         i0HA17Dj7182L3i5uFz+38ElNWLS/8DZNInL0K318DIFRUN9cvtu11uIDMp/reQOmMB4
         tVqZ/SQY+3ywQgIjPMW2tf8aafhwvTKX6/kLpT7klXS4PTiShDe4vtSmUBqEdIiul74f
         qxnjHo7DdIKaCtah4mpLBm3hDJ8l6XMfvKd9GyY/X75OMBbA6yIsscNvW8GM43qp+tlc
         ocsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :message-id:subject:from:to:date:mime-version:sender:dkim-signature;
        bh=OlRoOkF4vgDASFYfvNkezcAtc8yYQlFuNwD0TlsDK1k=;
        fh=0jO1JOzt27HyKkrjcL5NMcwM8KGfmM7wNTpPS5AH8Ow=;
        b=aUR1Rzffj26YIYHHfeDBrwr/h46LI1oYwGl/knLYOplfU9U+Bfs/cla/zPTBFI7ctk
         Szf1Y16C+lxJ7meJEInuP9b0kR+T5L2pld7TONquc5HvsgUJsoEeNgjofYj0Qku1v5Zj
         AIRnuXiSIa2zNa7wGEr+vZRw9HvfDw3eDhr1Ye2sBcPG9HC5oJPbPeWqW6CQ5WDdDmIB
         ZJkxrqqLSTF8JmgbGWMDShkIH0zO7O/rTw42rzuhCqeEvBX8ORILRE6wM0divCVyD7Q9
         cBQj44X5QYoFNwTPWBjHtverHkSTnNoMJ8EWB5LenkklKSoNU7Mt70CzcVEc+QkRHc15
         xAqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=yLpwDXkc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691794722; x=1692399522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OlRoOkF4vgDASFYfvNkezcAtc8yYQlFuNwD0TlsDK1k=;
        b=EW++lqCwj5bOxXKtRzdhDKgmsf/plW+AQaLWMahydO1+F2euqtVEZSnHM5bK3meRNW
         E03vdVqBVpW1xE/uP44v7Cdwvoc44uKvK0hpiPEYhOjpp6cs4csDrHmsksSWoUhnJoar
         fkDw7j3MR0atXyR0/hm5nVen/O4l1NyUAYmzpCl7JDKiJnahEEVG3k1QVL5pe6y6BWTG
         jX/exalX16rcG6rqtnYOM3OM4DndSF4hRuOhyC2YwYi58HEezHn/yUIti5OZaMFoiUjU
         +w2X04AJ0jwbBjKQXH6DfynRCYcm/Z4p5TlO7bQILjTfcdAoz8tGQq3AMW7yeR81aW13
         RRBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691794722; x=1692399522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OlRoOkF4vgDASFYfvNkezcAtc8yYQlFuNwD0TlsDK1k=;
        b=a2B76eor2sMC9oRk+ens9azJV0AXgioFVLg2Uej1PbPrE3VYO1FO+yItnRgsviN7xH
         IhnGZ4WQNSkiROSB2kXK0LxSrnfcRQAFkMid/h41l9IBsCc9VhHN+YUJQ8aMjAGcK8vN
         jVfp+LB/KwP6b8QzuzEa7vEKKPUdsxZ/S/5ZyzNwWlX37gcM3A7OcXGpngYeLa3srmtT
         9z8/oLd99MUwMgd5Pjzk8A4Ga/XfUORODCwt6TzUal0wI293WEMU8peM5TGqjp9WHhFG
         mdj6z3U6g8wflPIbNHAbQOXdZVoUZFfIBdGoXiOv8BVnaZOtaTa71j2B6wiAVJr4Sney
         tN6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxvej8Y+UiwkyD5QxPNyXFoSs1Rux2+gkDjcEILuoM74T7qpEnv
	djAG27DUMpiia6zJlOw0Nwc=
X-Google-Smtp-Source: AGHT+IFKVOebqe7OBgpNKvWyrHUrM4JMup4TUta9cxROe653RWR8ddeBuPzhagM+L5nwZWMUNhqbHw==
X-Received: by 2002:ac8:598a:0:b0:403:a814:ef4d with SMTP id e10-20020ac8598a000000b00403a814ef4dmr4538628qte.49.1691794722650;
        Fri, 11 Aug 2023 15:58:42 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4513:0:b0:408:d946:ba72 with SMTP id q19-20020ac84513000000b00408d946ba72ls3274766qtn.1.-pod-prod-07-us;
 Fri, 11 Aug 2023 15:58:41 -0700 (PDT)
X-Received: by 2002:a1f:bf50:0:b0:486:4b43:b94a with SMTP id p77-20020a1fbf50000000b004864b43b94amr3663409vkf.6.1691794721268;
        Fri, 11 Aug 2023 15:58:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691794721; cv=none;
        d=google.com; s=arc-20160816;
        b=OAWGq14IVY0JMnygQ+9J4LG2/cQpq2MwBvwoyq27+zeHBlaJQ3naT0uuCkQCiOQsDo
         ngKpzD8hP8d/RKUdG3EaX5iABcmNGSNe/Or4dFsQyqLn7m2T5MBY9lroVBkDHyHQcpAY
         kGfjiRdPLcXTImUE4+K20ahqvQX1Aa/PD3AHG0o0x2dURWxkDZFg5T/rjHdN3udP7RVK
         LbRT1NXod5oJzswMrq5LUkxISALBQzx3+ek3xcC98Z+chWWJiO/7sMojY8LggoTPJ8fG
         ysHw9id3xhEhEK6EQFbCSkfxWQ8+bvshqiV6WNzP67ezOgFuday6X5FlgMFfUc/ChQ9S
         pzNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=2rsmMel9185PBL1fTWx/H7qgV/L1RxMTkI8oKqLpMr4=;
        fh=0jO1JOzt27HyKkrjcL5NMcwM8KGfmM7wNTpPS5AH8Ow=;
        b=KLUM6dKhh6ch4K600KSBUAAY8sURh8qAZOYsupz/oeR6bLUrT9gI3vtzqV8e/y0+cf
         2wNAbWnHF60TP8+UcxcDkNt0Q35U43C0mw7RCawJpHsRStX1tJGRolbrwhLjFyGTFRsK
         3S4XiKUJnQGZSiBGeUr+xLW07qN7Ej/IAsxJU6TOIU+QD+lb1jhWRUtlwvDNUa2/B61f
         4jM0NPAn94VWsmHpecVXl4kvwl5DToKyaawmqHx8AuWzA3HOwu4vW4nj4wfrHsJe3nhc
         xApziTw5ZfytkN3VYEqkho0MdAg4TFQhTWNhOf6Wb3x2lWO/5Gd/Ve3r9ipfNcLsse9E
         bzYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=yLpwDXkc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ce7-20020a056122410700b004867f388b06si885507vkb.0.2023.08.11.15.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Aug 2023 15:58:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BBD48672B1;
	Fri, 11 Aug 2023 22:58:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1B230C433C8;
	Fri, 11 Aug 2023 22:58:39 +0000 (UTC)
Date: Fri, 11 Aug 2023 15:58:38 -0700
To: mm-commits@vger.kernel.org,ying.huang@intel.com,will@kernel.org,vincenzo.frascino@arm.com,surenb@google.com,steven.price@arm.com,qun-wei.lin@mediatek.com,Kuan-Ying.Lee@mediatek.com,kasan-dev@googlegroups.com,gregkh@linuxfoundation.org,eugenis@google.com,david@redhat.com,chinwen.chang@mediatek.com,catalin.marinas@arm.com,alexandru.elisei@arm.com,pcc@google.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] arm64-mte-simplify-swap-tag-restoration-logic.patch removed from -mm tree
Message-Id: <20230811225839.1B230C433C8@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=yLpwDXkc;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
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


The quilt patch titled
     Subject: arm64: mte: simplify swap tag restoration logic
has been removed from the -mm tree.  Its filename was
     arm64-mte-simplify-swap-tag-restoration-logic.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Peter Collingbourne <pcc@google.com>
Subject: arm64: mte: simplify swap tag restoration logic
Date: Mon, 22 May 2023 17:43:10 -0700

As a result of the patches "mm: Call arch_swap_restore() from
do_swap_page()" and "mm: Call arch_swap_restore() from unuse_pte()", there
are no circumstances in which a swapped-in page is installed in a page
table without first having arch_swap_restore() called on it.  Therefore,
we no longer need the logic in set_pte_at() that restores the tags, so
remove it.

Link: https://lkml.kernel.org/r/20230523004312.1807357-4-pcc@google.com
Link: https://linux-review.googlesource.com/id/I8ad54476f3b2d0144ccd8ce0c1d=
7a2963e5ff6f3
Signed-off-by: Peter Collingbourne <pcc@google.com>
Reviewed-by: Steven Price <steven.price@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Alexandru Elisei <alexandru.elisei@arm.com>
Cc: Chinwen Chang <chinwen.chang@mediatek.com>
Cc: David Hildenbrand <david@redhat.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: kasan-dev@googlegroups.com
Cc: kasan-dev <kasan-dev@googlegroups.com>
Cc: "Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)" <Kuan-Ying.Lee@mediatek.c=
om>
Cc: Qun-Wei Lin <qun-wei.lin@mediatek.com>
Cc: Suren Baghdasaryan <surenb@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: "Huang, Ying" <ying.huang@intel.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 arch/arm64/include/asm/mte.h     |    4 +--
 arch/arm64/include/asm/pgtable.h |   14 +---------
 arch/arm64/kernel/mte.c          |   37 +++++------------------------
 3 files changed, 11 insertions(+), 44 deletions(-)

--- a/arch/arm64/include/asm/mte.h~arm64-mte-simplify-swap-tag-restoration-=
logic
+++ a/arch/arm64/include/asm/mte.h
@@ -90,7 +90,7 @@ static inline bool try_page_mte_tagging(
 }
=20
 void mte_zero_clear_page_tags(void *addr);
-void mte_sync_tags(pte_t old_pte, pte_t pte);
+void mte_sync_tags(pte_t pte);
 void mte_copy_page_tags(void *kto, const void *kfrom);
 void mte_thread_init_user(void);
 void mte_thread_switch(struct task_struct *next);
@@ -122,7 +122,7 @@ static inline bool try_page_mte_tagging(
 static inline void mte_zero_clear_page_tags(void *addr)
 {
 }
-static inline void mte_sync_tags(pte_t old_pte, pte_t pte)
+static inline void mte_sync_tags(pte_t pte)
 {
 }
 static inline void mte_copy_page_tags(void *kto, const void *kfrom)
--- a/arch/arm64/include/asm/pgtable.h~arm64-mte-simplify-swap-tag-restorat=
ion-logic
+++ a/arch/arm64/include/asm/pgtable.h
@@ -337,18 +337,8 @@ static inline void __set_pte_at(struct m
 	 * don't expose tags (instruction fetches don't check tags).
 	 */
 	if (system_supports_mte() && pte_access_permitted(pte, false) &&
-	    !pte_special(pte)) {
-		pte_t old_pte =3D READ_ONCE(*ptep);
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
=20
 	__check_safe_pte_update(mm, ptep, pte);
=20
--- a/arch/arm64/kernel/mte.c~arm64-mte-simplify-swap-tag-restoration-logic
+++ a/arch/arm64/kernel/mte.c
@@ -35,41 +35,18 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asy
 EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
 #endif
=20
-static void mte_sync_page_tags(struct page *page, pte_t old_pte,
-			       bool check_swap, bool pte_is_tagged)
-{
-	if (check_swap && is_swap_pte(old_pte)) {
-		swp_entry_t entry =3D pte_to_swp_entry(old_pte);
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
 	struct page *page =3D pte_page(pte);
 	long i, nr_pages =3D compound_nr(page);
-	bool check_swap =3D nr_pages =3D=3D 1;
-	bool pte_is_tagged =3D pte_tagged(pte);
-
-	/* Early out if there's nothing to do */
-	if (!check_swap && !pte_is_tagged)
-		return;
=20
 	/* if PG_mte_tagged is set, tags have already been initialised */
-	for (i =3D 0; i < nr_pages; i++, page++)
-		if (!page_mte_tagged(page))
-			mte_sync_page_tags(page, old_pte, check_swap,
-					   pte_is_tagged);
+	for (i =3D 0; i < nr_pages; i++, page++) {
+		if (try_page_mte_tagging(page)) {
+			mte_clear_page_tags(page_address(page));
+			set_page_mte_tagged(page);
+		}
+	}
=20
 	/* ensure the tags are visible before the PTE is set */
 	smp_wmb();
_

Patches currently in -mm which might be from pcc@google.com are


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230811225839.1B230C433C8%40smtp.kernel.org.
