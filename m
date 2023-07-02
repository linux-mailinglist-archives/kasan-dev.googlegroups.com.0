Return-Path: <kasan-dev+bncBCT4XGV33UIBBDVDQ6SQMGQEVKDFVWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 08BDE745067
	for <lists+kasan-dev@lfdr.de>; Sun,  2 Jul 2023 21:35:45 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-66700a28586sf3901528b3a.2
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Jul 2023 12:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688326543; cv=pass;
        d=google.com; s=arc-20160816;
        b=hZ+9jxqvuXSVzAFStKCLNd41OgMHMT3lGzQlskoNTr4XHwP2g5crQHaIEnCI0RGJWH
         1zKNB22etL0iJKcApT2umuh5QMmTPNCt9C5eUkiW2XyMssKLFASnYlg/nVFRyQaccjbw
         /FaDdSe+2DiSbg2TAgAPyt4SoHEA2dl/TCEc3jpswoYOfB3RvtP55ZXs+9ZNZYK0hM09
         K8DXJszU/NtgEkSYHVG9IP2E8x6SPsOnynTbcpjkwZV9Uw/Up8jXkmCKY1mcZPjiDVds
         AtomOZz9Qa4vDd2w/RkG7Mwkee6KsBkFkqdazCzG3B7VSOM0/5WS5xESbd9B47aCJ9f8
         2joA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :message-id:subject:from:to:date:mime-version:sender:dkim-signature;
        bh=LiiS8Lt56N2TpXjFkjKNhlrqdTgeiHfJxnbgsl7w8ak=;
        fh=0jO1JOzt27HyKkrjcL5NMcwM8KGfmM7wNTpPS5AH8Ow=;
        b=uhPkOlrYg7tv3OiOJ37za04jp7Sir4eVZHl7jD6HSfl8Ch+WcPuOpb3Od8fS6vRM0v
         stS77YwKLuCia/4A5i1oa9ot3G4dJ7Z0LWMxMytPTZufKlBD60KGNZ2N+vSu0/GxW+qW
         uCO50hjpnbWfwl4TcUm/a/d4+n+6RnLe025//1yfTz0sqR5gttoLMtUqpjXLtFHEfjki
         SEZc0w5quiYXJkOfKsE00ZFJJmBwURoCiCyj7D8HY85kT5U69hdOPuXYt/+ekBnjy74r
         1J8olHBRGA9dCYVUza6LnOodsu3I5GujmDTw7oGwgxee+If6AjUvC1sE+Onq7B0qnza1
         ltQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=q64ERIYy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688326543; x=1690918543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LiiS8Lt56N2TpXjFkjKNhlrqdTgeiHfJxnbgsl7w8ak=;
        b=HVdhEDxyK99ec59944XkDQxIevB281i1o4neCkKEyWJZxcHA7GgGyVK+u9Gs8zkUH1
         KlPNBUk1+DM5q4CPcU+PaakErR2xF70sWjxSjJhu0zYdtOjdvjTYZyq2W1qc7cYfY3oD
         7m7bGaEeT8d22/rAsrLE1uWwMjpLq0cpyjZCVeK1osZ0udICd280ogEUvsfJVyXqXuN0
         5z4ZfXD0NeRlze0FPWfV96i7WRqwRFNX80VtBZewnBTVdAeQ3+ehxRcH/aFfRZM6Myxx
         058WJuXMc7iG2Og/V7VBfHXPERg1bQ1BwvZUSca2aZn++txGaq82pnDrmp81l50axPsO
         sveg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688326543; x=1690918543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LiiS8Lt56N2TpXjFkjKNhlrqdTgeiHfJxnbgsl7w8ak=;
        b=IkTUdbREMHa9WYwtrv8UN+NHCuFUxTMjpmr65nAMDPSxHInHkR/VLF92P5DS9YJ2dM
         +7xbzDMsNsscmC6fcadLxCQtnslbzRCPImf88fGZ3Yp63/kyoDqNNm0NPG9palz69tOQ
         EI+5n2ey7uNMvD2cqxJ9psmB4RXXPye5DEONfRLG3Gp+pWP2c+1d/6YlmJJ5BXB00wq2
         /FYOjHKkl4e2eS9DIzEXQCpU3O6r+a7MCcgTsaXvNxUNxQEKJEmiSzofK3UTdxRqJo0g
         LwfvZV0afJBIxN0foC+lL6+urSmGecVodOmehjLcMlWVCM7Vj/8tqBOkU/+CWb62F0y5
         vd1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwhhyF//OdU5mijnCbBKUJYynsEbOEvtPvpyw4Izana+/ssmjlf
	shg5vrRPDw+nERAx6wFVWAo=
X-Google-Smtp-Source: ACHHUZ5ekqbOMU3Eap2jbelnnr0NTgmotVfomYmzFdHxhIFZCHYHRxKh+inZ3j6A/E1WuEb0yfKUXQ==
X-Received: by 2002:a05:6a20:1612:b0:124:eea9:668d with SMTP id l18-20020a056a20161200b00124eea9668dmr9374473pzj.40.1688326543044;
        Sun, 02 Jul 2023 12:35:43 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:82c9:0:b0:666:ec56:e7e6 with SMTP id w192-20020a6282c9000000b00666ec56e7e6ls2071409pfd.0.-pod-prod-09-us;
 Sun, 02 Jul 2023 12:35:42 -0700 (PDT)
X-Received: by 2002:a17:90a:2f64:b0:262:b3f8:6ae with SMTP id s91-20020a17090a2f6400b00262b3f806aemr7491369pjd.46.1688326541986;
        Sun, 02 Jul 2023 12:35:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688326541; cv=none;
        d=google.com; s=arc-20160816;
        b=cFDjrR/7rEt5vIakQdhn/ARSdltadpP4HLkRRN48+/2s3nl1R9/RuyasWliERkggCn
         wGXVCFBK774Y8WZa7dWpAsphSbqkyXUq8oOlAf4Aksr0jOOKvLq0uRnLJG+IxI4nU9Og
         D5ojp0mQUiY+9bWUDqIjF/w7UVxvRQw1BlXd9am+mywcWCiwhQW4yN6zQ1nKxKTW7AA3
         bSpKavobpLykoeMxr5SXUFLn7r8fzbRdwWqzh7LYm/pqnrZG1fP7h+6uhbh7hwUSk6+m
         DVmDHHlxIhR1ZuodA2bFZ8wm5NXUWpUHZbs46VUwVLLVRNRrODQydS8xYewR8gdRVyPD
         Fa7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=h1C08NG3j655r8wa3bXmO4VSiFO4/xDc/jB4sWe/KV0=;
        fh=0jO1JOzt27HyKkrjcL5NMcwM8KGfmM7wNTpPS5AH8Ow=;
        b=EOYUVP//xjQ4FgFWkwRKbk02aNj6XvfPWsnCiS5+W7cU1ymY5NtHMY9z/aeOXqcnOl
         jAbVe6RlxeYUeFVNSsEBD9HcPa1/Z7RoCNmFcSmB8660QsonK7/9N1zotlgswnV8jKi3
         4allvz+JwCc0OoRFmZpNEsD0vFRUymLWLJs9LSPBs5rUBDhjRdsXOOlQ1Qr+VjjgyHu+
         nB/OALMqHQ3fHEWRX++x7eIvTDhrsPGRYY+9RR3rCz6iTR3rhkuNqFWlfE/EtdOpL8AE
         /m/Y4Z2oeeXczWu+K5HQArlpF4ukLmeLRdorf0PFY2U/JqY/pBQ3P874Ph6wavBtYQ8r
         odYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=q64ERIYy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id lk8-20020a17090b33c800b0025679987800si223914pjb.3.2023.07.02.12.35.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 Jul 2023 12:35:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3F90860C7F;
	Sun,  2 Jul 2023 19:35:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 94D58C433C7;
	Sun,  2 Jul 2023 19:35:40 +0000 (UTC)
Date: Sun, 02 Jul 2023 12:35:39 -0700
To: mm-commits@vger.kernel.org,ying.huang@intel.com,will@kernel.org,vincenzo.frascino@arm.com,surenb@google.com,steven.price@arm.com,qun-wei.lin@mediatek.com,Kuan-Ying.Lee@mediatek.com,kasan-dev@googlegroups.com,gregkh@linuxfoundation.org,eugenis@google.com,david@redhat.com,chinwen.chang@mediatek.com,catalin.marinas@arm.com,alexandru.elisei@arm.com,pcc@google.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + arm64-mte-simplify-swap-tag-restoration-logic.patch added to mm-unstable branch
Message-Id: <20230702193540.94D58C433C7@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=q64ERIYy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The patch titled
     Subject: arm64: mte: simplify swap tag restoration logic
has been added to the -mm mm-unstable branch.  Its filename is
     arm64-mte-simplify-swap-tag-restoration-logic.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/p=
atches/arm64-mte-simplify-swap-tag-restoration-logic.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing=
 your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

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

mm-call-arch_swap_restore-from-do_swap_page.patch
mm-call-arch_swap_restore-from-unuse_pte.patch
arm64-mte-simplify-swap-tag-restoration-logic.patch

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230702193540.94D58C433C7%40smtp.kernel.org.
