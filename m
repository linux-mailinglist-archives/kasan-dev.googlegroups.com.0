Return-Path: <kasan-dev+bncBD52JJ7JXILRBGFF7ORAMGQEOIABT4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 466427012D4
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 01:58:18 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-763c3442563sf689772239f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 16:58:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683935897; cv=pass;
        d=google.com; s=arc-20160816;
        b=XSomZTcLYVgWSpGdw98v54wuprhUhtMjS0YYBqMrHaI0X2MtESp3RAFl6bVsY8iivZ
         uzlJzA13/wMcMXpTaUABWVTFMQ/bnZirIzOrUIUMwRioTU5i1uf3V7K+v7o9TVaKNfMC
         Q/zNWxKv11LcBlIU5YdW6aNLLYYbz1+I02d3fLUQ0mjMwtL2C+TjlDo/wZ2zGQ4QqM7K
         Wq1lUlOijppdPqAdiPDI1oqz7IvSVI6VgVl4Lho3RzWTrOAF+Seqi9hlI8e3Cue0qPes
         qNo505IeLFaa4Gv4QTRvmmfm4Uf/vE1rTlxETGmKloALcBktq5EQgpgse4gn2mnBEWGZ
         7PIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=EAKvNJP+QBmW02zk8DVx8K9rEsKn4xacDcfjWy1qYz4=;
        b=n2Z4gI/4ife+pCGC3dadpd47qOBIHs0QA15z7oZFlgt3Ropi/o9z8N9JVz3eWhOfYN
         G5eiLJdt2TrvrNSmxlkhWXINTgdIQ6VjnvIrUh8KGfjuVpZPv7yaY+qsZFb6447BISTj
         jgTlRTvQah8qvNiNNZNFwc9k1FEyl8xHc4gGr7RiiRDgd7Y5nc7gI/jGUdbZ1EFLwdpY
         m2H8OKYE9fYkEvzEfzdQCnU7poTz3h5p8YUTP7GhLr2dVvBZeQEZtbHK5sb6sMOoyYhe
         eQU5a8x1LU6hrC8E0WysKXRimMTXsSyHIs78cOa2yMV6TqvkLmBrEjsO5EzW2349fpg2
         U0Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="f5hclik/";
       spf=pass (google.com: domain of 3ltjezamkcd8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ltJeZAMKCd8QDDHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683935897; x=1686527897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=EAKvNJP+QBmW02zk8DVx8K9rEsKn4xacDcfjWy1qYz4=;
        b=szQuf8VfBIFyW99uN3uKi/VJDmjpUdXBsogtiraC3ofIxHTCppNthnE6lUF7QTIQd7
         zBteTDeGKftZUQM7YoWFr38vyso5arKxMGmf8/0lMoqodqhJa9XztwwoUA4g8/zw2o2+
         VkabP5MQgKdpyLjPiyIWhdwkVhEpD7rzltm1uciVRs/JfByUmenif+4RP48f2gfpDQxq
         vrLFGqno1W0e+MFSADjB45aglEqYAB4VU5iWZyOYWH+rcUeni/TWZkIi7NydS76RQ2Zx
         TE8V8zyzLIK1U2xScVou8t/rICrGlacY/5myhg8KRYw510C0/+8sZovniHN6gOJGp/yQ
         LaZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683935897; x=1686527897;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:references:mime-version:message-id:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EAKvNJP+QBmW02zk8DVx8K9rEsKn4xacDcfjWy1qYz4=;
        b=XLugWaXHK8L3+DQj2n2CSp5+pIlznuZTiCaK4SMuSJz+au86H6MNLacMPW9sWpMNKy
         tQudtLSi71mxe5uOajfNPqi67S15zZw7sRLc+S9k0XeM1OwWioC67xuzZLwjW1DmFkhF
         aClk9d3PBc09u1cu3GFp4P8YldMd/g28OqxnTqnRPoRqa16BwhrGjm540YCrToNcAhQ8
         sEnioZmIF64qboPxDYuOafiXYA0Kjk0bGLZsVNYmspFCT1MSmeJyNt993HuKMpSpkpCP
         r9mECDO6lPH0ZHRpviybW7vjyGH+yoXqkmEZ1QBOks76yQZT57oCyaNatLyrPE0TiLQK
         m+xg==
X-Gm-Message-State: AC+VfDzldU411X2+S1eKpOcw4XgUnHNOQbBgreisE6TqWofj6DEF6Qmk
	uqHYTUwqutqYJ1XartSx0R4=
X-Google-Smtp-Source: ACHHUZ6IMMW8mZhiPOunnnHvxGSlQfIz7zACGw5hZzf84/nXNwaJJPXg1xiziG0aOkMAD9usozsYqg==
X-Received: by 2002:a02:b0c2:0:b0:416:1d9f:9887 with SMTP id w2-20020a02b0c2000000b004161d9f9887mr7000193jah.3.1683935896828;
        Fri, 12 May 2023 16:58:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1043:b0:32e:2d9d:f290 with SMTP id
 p3-20020a056e02104300b0032e2d9df290ls2102426ilj.1.-pod-prod-07-us; Fri, 12
 May 2023 16:58:15 -0700 (PDT)
X-Received: by 2002:a92:c806:0:b0:334:7796:f90c with SMTP id v6-20020a92c806000000b003347796f90cmr16886499iln.18.1683935895336;
        Fri, 12 May 2023 16:58:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683935895; cv=none;
        d=google.com; s=arc-20160816;
        b=OuhyPojOkBN7kZKEuUpou2+8ZI0OM8gd9jYjlt45j2esZ6k1TwUMdzer06BWvxBYDs
         lF03sziHuIBOss1WHG3tfPglKi3/HrB52sFPcwU2MCHKOclV3s8LlDBXGCJPX3X0qt9p
         /Be4ME9cKxzjQ6EB+pmUdtxbhYOaJ1riNAEUgHPv8Hm0K3CBhzwmJ8wtH5sHBEJ7SPzC
         JRQnZxtgrOsjrAZvAZmMz+wQbVR7+Pd3X5ZEeL1o2MgNZsXcum21Lm/2qHZgosmZnkRi
         Wv91mNpnbYyMWFr2j9zL9mBuasnVI/q7+My/nT4cLTlkJLhFxvcYjNRlLsB0ZSLClekN
         s0Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LVFc+Brp/nv5bcVUuCiFrcDkBMn4WnVlAUQLAdw9K1k=;
        b=k+6jKZPz7saikQf7hpDlONPqymLI4p0bpwTZnsdB/l3GoxuBtJ/XTrpRueF7bjDkkM
         xB5wauZpMjMaiNYwz1wjEVMpnIg7Qh5FVDMt4tNbtkb5fQAyHToyZ5N2xykE6ISHhTDD
         PL85dRr1nwlOHjgRX9S1EelDWtDtxm2Z7WCvFN16HCMScAVpG3vccuXf1ul5NcWnjctz
         mESwg9U6MkraGj5HhKuTaubu/ai/qcm/gZf2vW/mh3CuSl5hRjXKr//hNI3yzZJnN1tS
         dbMJOU1SPR4RRYQ0Y8Jwvhko4H4uqzhzEVNVlC2oNHkvbmAqVZ1rDREnnwipSAgwM4Om
         5wxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="f5hclik/";
       spf=pass (google.com: domain of 3ltjezamkcd8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ltJeZAMKCd8QDDHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id ee24-20020a056638293800b0040fa7700d64si1475308jab.4.2023.05.12.16.58.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 16:58:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ltjezamkcd8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-559d8e22306so189871567b3.1
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 16:58:15 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:ff6:108b:739d:6a1c])
 (user=pcc job=sendgmr) by 2002:a81:b285:0:b0:559:f1b0:6eb with SMTP id
 q127-20020a81b285000000b00559f1b006ebmr16091480ywh.4.1683935894947; Fri, 12
 May 2023 16:58:14 -0700 (PDT)
Date: Fri, 12 May 2023 16:57:50 -0700
In-Reply-To: <20230512235755.1589034-1-pcc@google.com>
Message-Id: <20230512235755.1589034-2-pcc@google.com>
Mime-Version: 1.0
References: <20230512235755.1589034-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH 1/3] mm: Move arch_do_swap_page() call to before swap_free()
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
 header.i=@google.com header.s=20221208 header.b="f5hclik/";       spf=pass
 (google.com: domain of 3ltjezamkcd8qddhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3ltJeZAMKCd8QDDHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--pcc.bounces.google.com;
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

Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
the call to swap_free() before the call to set_pte_at(), which meant that
the MTE tags could end up being freed before set_pte_at() had a chance
to restore them. One other possibility was to hook arch_do_swap_page(),
but this had a number of problems:

- The call to the hook was also after swap_free().

- The call to the hook was after the call to set_pte_at(), so there was a
  racy window where uninitialized metadata may be exposed to userspace.
  This likely also affects SPARC ADI, which implements this hook to
  restore tags.

- As a result of commit 1eba86c096e3 ("mm: change page type prior to
  adding page table entry"), we were also passing the new PTE as the
  oldpte argument, preventing the hook from knowing the swap index.

Fix all of these problems by moving the arch_do_swap_page() call before
the call to free_page(), and ensuring that we do not set orig_pte until
after the call.

Signed-off-by: Peter Collingbourne <pcc@google.com>
Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61020c510678965
Cc: <stable@vger.kernel.org> # 6.1
Fixes: ca827d55ebaa ("mm, swap: Add infrastructure for saving page metadata on swap")
Fixes: 1eba86c096e3 ("mm: change page type prior to adding page table entry")
---
 mm/memory.c | 26 +++++++++++++-------------
 1 file changed, 13 insertions(+), 13 deletions(-)

diff --git a/mm/memory.c b/mm/memory.c
index 01a23ad48a04..83268d287ff1 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -3914,19 +3914,7 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
 		}
 	}
 
-	/*
-	 * Remove the swap entry and conditionally try to free up the swapcache.
-	 * We're already holding a reference on the page but haven't mapped it
-	 * yet.
-	 */
-	swap_free(entry);
-	if (should_try_to_free_swap(folio, vma, vmf->flags))
-		folio_free_swap(folio);
-
-	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
-	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
 	pte = mk_pte(page, vma->vm_page_prot);
-
 	/*
 	 * Same logic as in do_wp_page(); however, optimize for pages that are
 	 * certainly not shared either because we just allocated them without
@@ -3946,8 +3934,21 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
 		pte = pte_mksoft_dirty(pte);
 	if (pte_swp_uffd_wp(vmf->orig_pte))
 		pte = pte_mkuffd_wp(pte);
+	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
 	vmf->orig_pte = pte;
 
+	/*
+	 * Remove the swap entry and conditionally try to free up the swapcache.
+	 * We're already holding a reference on the page but haven't mapped it
+	 * yet.
+	 */
+	swap_free(entry);
+	if (should_try_to_free_swap(folio, vma, vmf->flags))
+		folio_free_swap(folio);
+
+	inc_mm_counter(vma->vm_mm, MM_ANONPAGES);
+	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
+
 	/* ksm created a completely new copy */
 	if (unlikely(folio != swapcache && swapcache)) {
 		page_add_new_anon_rmap(page, vma, vmf->address);
@@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
 	VM_BUG_ON(!folio_test_anon(folio) ||
 			(pte_write(pte) && !PageAnonExclusive(page)));
 	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
-	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
 
 	folio_unlock(folio);
 	if (folio != swapcache && swapcache) {
-- 
2.40.1.606.ga4b1b128d6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230512235755.1589034-2-pcc%40google.com.
