Return-Path: <kasan-dev+bncBDDL3KWR4EBRB56JR6KAMGQESB6EXXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6364552AA11
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 20:10:08 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id bt27-20020a056512261b00b004779fd292b1sf1477884lfb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 11:10:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652810999; cv=pass;
        d=google.com; s=arc-20160816;
        b=KjFhdi9ylVI11s4hQFRVsqHI7bWJhRh4VJOMf0ha7egy+C7nKdw1DKxMRx321+miCR
         r3cqD7cp/prP2ejuh3sJhaoTl8zRXoXMdiw9RBkt2NbA3dEKWPwrcW7foH7FcYr4iXUW
         bmhXC2Gyeb1Nyun193S6CZajzHagwcCAFJ052mlmALKiWBDe8ew5xG2jJ9AzJJ9UuoCF
         na3jU8rYeOfsvQdOI7sq4qc67d1yv02sHJ+YfkBoaCAr0g+q61vMKS0fqtJcDyldrtZ6
         GUyx4/1YlG+i2DsjOVPQgrDfwdyFHtELUaOTEMXskUDO1NRn7jE4g5IWWmjJNFcj/K5V
         9dcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=g6lXn3dQ6k6hwMTqnE42i4ooSswgWCuMjmGMe8x4spE=;
        b=r952dEkKymLqen5mhz5DMtgPGTfC0ceRQFpA8f4KQQQof9NJlmtzmo033+3HiUqJy3
         StxEhJMmCP04lWWwBy29OrmsibqDgpsUAKC+/7s6e1X35HyGovNSmT7mVKJw6MUn+jrO
         /pe8cmjPZ1MAY7KOGUCXHktZCOMAwaMxOr/KvYk7ZOfFuacsGFuUw/YYhVjj/8kAnfut
         1TZDCq/WCLSX8iDCeIZNazZfyfr70iahMlF0MbbdtaFkl28Fg0hgeX6DxGY8Ul7ocWhz
         CyMvO5UFxoWyDh52IwRaI0tYsx1XvWgz9i3OgFZcF/PY5kItwRY3oShE2YAas1foL5NH
         XkvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g6lXn3dQ6k6hwMTqnE42i4ooSswgWCuMjmGMe8x4spE=;
        b=dVBePWH2vPHTBpurvuVIc0aayK/T6nVxljGlOkRZ9bZgkQOUoxSPN/j181TP8+o6tN
         JjH2j87L7/6+ExInMeyR9yxVwRKsg6f4wBIkq/bQ6OjuqB0WFYL/WdojXwZsOYyuD0+1
         kjwd4lhJZU/Dn8eAIJM8zCJmaABns+V/vIynucbskkqqHOFU7NIXlxOoV4vGu2jafwgV
         a527chAMAxZVq1RsfPf2iJuIY/ifEpmpJinI8m7LO6iIWlLHm+wU4d4YyTGiABMNOdY0
         u5dN6YqvKeFaz/UyPkkX9c/mve06uLEUty4Ax1SrDvZRzf4dTaEkl1hFG00nAKUZZD+L
         4yeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g6lXn3dQ6k6hwMTqnE42i4ooSswgWCuMjmGMe8x4spE=;
        b=O+//smtiJ2//gsK7Ts7HP4DasNveBISfZYnRVFM9Zz/Ttp+M3t6VX4mIA9coj3esC9
         BqHgm7uS/3Vv+66liltysXbhBhNk7/4gJpUDKFr/7uDqCpWhmv9AbdFHz4ZAaN2V17/+
         zMPNGZogjniQfzva0Oau78XfPxDMP5/8ho9r2S6RPEjAo4EP3UEVR2PFAE/xPcb7NpPH
         7dbueGzaqjzBQoFKOVGPkV1XDytcngYUvBe+Qur+4shWMFT40NFRX/83jhzLsTOV3xFK
         g9JhjqBPknCFpc3ogJsPHRfS87cPBnzt3qVtSnzHS2QLdfWY9aAvrjpPrtim7V2yFxEC
         zTdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533qD3G5f+CzWtBOmDI60CjlylH0ySM4SuAJ5Cd0VB7fSyr67pCr
	OsyTar+kTzi3v+ntCJY/fPA=
X-Google-Smtp-Source: ABdhPJwzo5Ggrx9MA7FuWoJwnAbH28F3o/ji0gdmSg4wD8sZD/nHGVhSL1JOVQy2/6j5cjpa05TNNw==
X-Received: by 2002:a05:6512:ace:b0:473:ba5b:8e06 with SMTP id n14-20020a0565120ace00b00473ba5b8e06mr17398411lfu.614.1652810999262;
        Tue, 17 May 2022 11:09:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:b0:477:a45c:ee09 with SMTP id
 f14-20020a0565123b0e00b00477a45cee09ls2324167lfv.3.gmail; Tue, 17 May 2022
 11:09:57 -0700 (PDT)
X-Received: by 2002:ac2:5509:0:b0:477:b18a:b5b5 with SMTP id j9-20020ac25509000000b00477b18ab5b5mr1368299lfk.297.1652810997758;
        Tue, 17 May 2022 11:09:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652810997; cv=none;
        d=google.com; s=arc-20160816;
        b=f9h5dogkiBua7mAnKH/h9nQHEe50/73l7+ftgydU4jl0NWI/nMb96ZK0tbYezCkEN4
         +aQCartMNTXnI/RjpLytiARsiZbbPrOQ0PYkKJR8MZIBQySj7djUsnFXAf3uG5kYpBB7
         q7H31kv/u/q6lUoxdxFjw0UY2SBGZ6SSphHvFX6n8Y5KHndm1+arnYh1Dxh2nnTTT/ry
         Uo0I+ffcAuKXEoBv/LVRikAMsQFVRpHaTlzQty0sBcxOMRtMMJGp42WVSZ4W05HD55EE
         JQnLpkk1Hl/1Dhj9Mf6HAiMihnGlwuRyjNx1qsyKkGH2g2NO01pbHE3Z7JOyTRr9qChD
         JPuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=07/Hd8eKhjPACAgazg3Z5WAvEpjmJLkOjYMTeB2iw5k=;
        b=Af3s3JZyVM+pqWrjI/b5lVUoc860mz+qAKFG3rQh6ZciR5qdKCr/x8lKX/ZTs9iDq5
         n54whqdmik+sc9o3qN89VpP6dTzt1Glos/C3ln6rV4NncdojmnAO2A8LKEsEbXQxaQk1
         ilkkRoUYbTnj6T9d7D9RMCHjJ/PmxTBRt6q5NIUPCVogBt0Hv6NTThQxqAdJWYGv1Nlp
         Iu7s/QG07UNm616S+oVZSRuxMDXLNEzexDUyhCCF0i+ZIyBfDG4YoVftC0ge8mF9oejm
         7arN7zYpnmAo8HZyULkPzx5nzWgnO5ptXfu87K8BUgwzkyDFNc+TTm8KLTMJtdZy0cQd
         hrJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id t17-20020a2e4611000000b0024eee872899si21207lja.0.2022.05.17.11.09.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 11:09:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 3A6C9B81B75;
	Tue, 17 May 2022 18:09:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 393FFC36AE2;
	Tue, 17 May 2022 18:09:54 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH 3/3] arm64: kasan: Revert "arm64: mte: reset the page tag in page->flags"
Date: Tue, 17 May 2022 19:09:45 +0100
Message-Id: <20220517180945.756303-4-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220517180945.756303-1-catalin.marinas@arm.com>
References: <20220517180945.756303-1-catalin.marinas@arm.com>
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On a system with MTE and KASAN_HW_TAGS enabled, when a page is allocated
kasan_unpoison_pages() sets a random tag and saves it in page->flags.
page_to_virt() re-creates the correct tagged pointer.

If such page is mapped in user-space with PROT_MTE, the architecture
code will set the tag to 0 and a subsequent page_to_virt() dereference
will fault. The reverted commit aimed to fix this by resetting the tag
in page->flags so that it is 0xff (match-all, not faulting). However,
setting the tags and flags can race with another CPU reading the flags
(page_to_virt()) and barriers can't help:

P0 (mte_sync_page_tags):	P1 (memcpy from virt_to_page):
				  Rflags!=0xff
  Wflags=0xff
  DMB (doesn't help)
  Wtags=0
				  Rtags=0   // fault

Since clearing the flags in the arch code doesn't help, revert the patch
altogether. In addition, remove the page_kasan_tag_reset() call in
tag_clear_highpage() since the core kasan code should take care of
resetting the page tag.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>
---
 arch/arm64/kernel/hibernate.c | 5 -----
 arch/arm64/kernel/mte.c       | 9 ---------
 arch/arm64/mm/copypage.c      | 9 ---------
 arch/arm64/mm/fault.c         | 1 -
 arch/arm64/mm/mteswap.c       | 9 ---------
 5 files changed, 33 deletions(-)

diff --git a/arch/arm64/kernel/hibernate.c b/arch/arm64/kernel/hibernate.c
index 6328308be272..7754ef328657 100644
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
index 78b3e0f8e997..90994aca54f3 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -47,15 +47,6 @@ static void mte_sync_page_tags(struct page *page, pte_t old_pte,
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
index b5447e53cd73..70a71f38b6a9 100644
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
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 77341b160aca..f2f21cd6d43f 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -926,6 +926,5 @@ struct page *alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
 void tag_clear_highpage(struct page *page)
 {
 	mte_zero_clear_page_tags(page_address(page));
-	page_kasan_tag_reset(page);
 	set_bit(PG_mte_tagged, &page->flags);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220517180945.756303-4-catalin.marinas%40arm.com.
