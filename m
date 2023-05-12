Return-Path: <kasan-dev+bncBD52JJ7JXILRBGVF7ORAMGQE4JSGA4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FD6F7012D5
	for <lists+kasan-dev@lfdr.de>; Sat, 13 May 2023 01:58:20 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1925e331932sf6868704fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 16:58:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683935898; cv=pass;
        d=google.com; s=arc-20160816;
        b=drLDyW0ACSbbyFfNH9ZfUajh9/3efkABSTeLsFF3IxMDGzbM6xxfsRlAyA+BFkqX08
         4BrX+WZzQ0+gWfl2KgLAcJNTMC9apMy9vmqH4ErVv2uiQS9QHaFygef1Z0bfnq4q4Pzu
         VtYTBKolSVlcP1KgjxWYjZcxp3jRJoJuECsa8tTId2QwTZ6Nqh2HAnoPSk4VbN+0NSMZ
         QfqKlKoqKxx2O0tLV9YFo3SOrUiyCSvZJqMygXLOksESPqXIuZQaSqjhzWeboRxb23TK
         mAqzZ9Q8InfpWLKcOgri6mAMSuIF7Ko0j8IIaMJDgCPMNOBM8d+THpOIx5qKQY/hv1dS
         w3Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nx2rmOyqgfaAlq4voEn+4OB7GJ2hSNXX5FUdmdemuwI=;
        b=Ie0wTaYAnn+hLwB/vlpTl8geY65a5bMmGkThexTi2v63bfaSDmNHRVxK2ByFAXXDuC
         oMZow7+fCnmVr0bXOP34Q8xLCP0R6nG+O8K4icZPQuhBeWvDguXqXwpCCG51qzTsv5hH
         Q0XzPaBWWJgxfg0EjXz/rCCFFoE4qa39u66q1urMMC3/X79suhgummtNTgmCrd6JVhOI
         AcjZ1J8OG0Anq8zvWcobXQOHaOPz1/w7a3KJT4M69dDGUwTcthW7DhI8enYM2HRVBup6
         DmpcK8YLVsHpbVqVv+1n06z+p7tlLh1Wm0cAMTPvKJegkfxmXDRioUqw0S+dDw01aYpk
         59Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=xk2Ibde3;
       spf=pass (google.com: domain of 3mdjezamkceitggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3mdJeZAMKCeITGGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683935898; x=1686527898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nx2rmOyqgfaAlq4voEn+4OB7GJ2hSNXX5FUdmdemuwI=;
        b=p9tYu7ch8aFJHesMYkCwoHHFz15zdteHm1hTGJsEuyCjVZXaOZuN/QcleSe6UTYvw2
         yXMLDjinHOdzj2F8L3tvius8BkDPMHNEbtbTsnGzg4/MKy38NybB+xq0MW/ShJoSuLLz
         8GTyQMicBBjiIC8ZRKJwbmQX/WYLlRxhLoFlpT822czOnGwj0qZxVu54LJUhTTC8JEQA
         8hGhiCtplWKRmrsgCUkmDX0fZdgD/u7NmfDVwdh8yEOvIS+KjNTb+MisxrV5LYlI9z4X
         mMl2AYB9Z1QtmSZB29Mpi+LfPEaSrrTddTxE9Z8jBpZ61g9+5aU346DpS2iNgjpudRUS
         W/NQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683935898; x=1686527898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=nx2rmOyqgfaAlq4voEn+4OB7GJ2hSNXX5FUdmdemuwI=;
        b=NIf4EdtT/cd46AfWhld8ilwn/ehrXaio4A5Fk/me2UbE5P1JFzrUTB2h9Qjs2qbgrA
         XgCvaxyHJemXwnYAvWA2u0/u5blDbu4aJiTX6hukQnvQyZGbnniy+lDPv7lDTvF6K10a
         Dt1GZcsZ3qgUbE7kDX8vB/feQZXro/ABxs1XUAbsRyvI3fqNuign9E/E4VG3lJYTrNwV
         TOJlmeJfCLZRBbdTFI8SzmF38kI1dJ+jeks5sfx0f8vpE4TkuBoCCv2HyiPzB5y9lnmt
         xDmLHgR4yFIsKJEDAfRlM9bLMaSldnOkRUY7ZgJLbDGj+nJZK2M4VGYCSGfcMh/wuwvZ
         rIsg==
X-Gm-Message-State: AC+VfDzzynXXS+kp/U3BepQMSWTn7rOvAJdCfGpjg7MVgA1x5LR+7zB7
	v9JNUTHZOjdGqnXpQt5KMRo=
X-Google-Smtp-Source: ACHHUZ6EwwbUxxnu0clMRbZx5q1LvJhR7CR2X3rXQqZ6cXiyvyYGY9EfUJrLqbXeuBhTE0YAkd9oxg==
X-Received: by 2002:a05:6870:bb0f:b0:192:7333:5afd with SMTP id nw15-20020a056870bb0f00b0019273335afdmr10359968oab.7.1683935898540;
        Fri, 12 May 2023 16:58:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6714:b0:187:ff84:efc2 with SMTP id
 gb20-20020a056870671400b00187ff84efc2ls7407775oab.10.-pod-prod-gmail; Fri, 12
 May 2023 16:58:17 -0700 (PDT)
X-Received: by 2002:a05:6870:3a32:b0:18b:1df9:92ba with SMTP id du50-20020a0568703a3200b0018b1df992bamr12867738oab.1.1683935897496;
        Fri, 12 May 2023 16:58:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683935897; cv=none;
        d=google.com; s=arc-20160816;
        b=Wl5/PGg/EYhtKhJbMHsyDRYsk3Ut3I88y1Ribwme9JMD7d8g08lB2Et1ezsJj+8wBw
         3ieC2WoJjJ5ITnQ9lcPEsBAT9AHI3RVZmKjbrXL3TaQ+LqpV8hnRo5aI8hKxLpq+ssMS
         qsqy0MyNYbkn9NR4wrprkVN1SStlT1Bd5DNWxwU8/L4QBWB2xsOtWwVRB5ZmnIlzUEds
         mZ75SzyJMW1ET9E+m14wVq90cRRvdqC5Np0g0z3o63QWcOA/yHi+gB7AK1sigEihBWPM
         zfMSjj5BWAZhXT+fF3pW9IqFcfNj0LZb+aM/hwN5+O4R8L/afU4H+ieCwAyEv3iNa7vs
         wFSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=XwMV83qzB00xUe1xka9Kex2X8Ec2jkmSilor+2INk6I=;
        b=JzL1QoemUy/OXX9e70G56BaToVWyrv7HbfXwJ/sayeodyN6f3+5uNEBZAxw4xeF1wI
         Y1o4LB8VL74/h3oQP6CAeHBEwo9pfJ25zeZ5ffgJdudqm7omD/rrMXSH6PlA7JccK15k
         HtVV9affgOhiFYrUI8X/lQ2lZ2/vuObchO6EWX93wGqdLmavR3sq5p4r08mq+b/2LhHU
         +12Qu0vPSCerVz+89QCb3qmPopHIJxzXBQN2L3Wy+eSzuCTwJerkaYraM5BA9QKF4eSS
         gXbrGQ3fCQ4Njqdp0DpxDD1gGj3jFfN73/wzO6IEa6Qs40xivClUyDRKpu21JwfCnrSy
         Djmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=xk2Ibde3;
       spf=pass (google.com: domain of 3mdjezamkceitggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3mdJeZAMKCeITGGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id bq20-20020a056830389400b006ac8e0f88b7si215561otb.2.2023.05.12.16.58.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 16:58:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mdjezamkceitggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-b9a75194eebso13020305276.1
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 16:58:17 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2d3:205:ff6:108b:739d:6a1c])
 (user=pcc job=sendgmr) by 2002:a25:d18a:0:b0:ba7:29a9:a471 with SMTP id
 i132-20020a25d18a000000b00ba729a9a471mr1565248ybg.0.1683935897117; Fri, 12
 May 2023 16:58:17 -0700 (PDT)
Date: Fri, 12 May 2023 16:57:51 -0700
In-Reply-To: <20230512235755.1589034-1-pcc@google.com>
Message-Id: <20230512235755.1589034-3-pcc@google.com>
Mime-Version: 1.0
References: <20230512235755.1589034-1-pcc@google.com>
X-Mailer: git-send-email 2.40.1.606.ga4b1b128d6-goog
Subject: [PATCH 2/3] mm: Call arch_swap_restore() from arch_do_swap_page() and
 deprecate the latter
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=xk2Ibde3;       spf=pass
 (google.com: domain of 3mdjezamkceitggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3mdJeZAMKCeITGGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--pcc.bounces.google.com;
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

The previous patch made it possible for MTE to restore tags before they
are freed by hooking arch_do_swap_page().

However, the arch_do_swap_page() hook API is incompatible with swap
restoration in circumstances where we do not have an mm or a vma,
such as swapoff with swapped out shmem, and I expect that ADI will
currently fail to restore tags in these circumstances. This implies that
arch-specific metadata stores ought to be indexed by swap index, as MTE
does, rather than by mm and vma, as ADI does, and we should discourage
hooking arch_do_swap_page(), preferring to hook arch_swap_restore()
instead, as MTE already does.

Therefore, instead of directly hooking arch_do_swap_page() for
MTE, deprecate that hook, change its default implementation to call
arch_swap_restore() and rely on the existing implementation of the latter
for MTE.

Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
Link: https://linux-review.googlesource.com/id/Id2f1ad76eaf606ae210e1d2dd0b=
7fe287e5f7d87
Signed-off-by: Peter Collingbourne <pcc@google.com>
Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@mediate=
k.com>
Link: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d434.=
camel@mediatek.com/
Cc: <stable@vger.kernel.org> # 6.1
---
 include/linux/pgtable.h | 26 +++++++++++++-------------
 1 file changed, 13 insertions(+), 13 deletions(-)

diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index c63cd44777ec..fc0259cf60fb 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -740,6 +740,12 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
 	set_pgd(pgdp, pgd); \
 })
=20
+#ifndef __HAVE_ARCH_SWAP_RESTORE
+static inline void arch_swap_restore(swp_entry_t entry, struct folio *foli=
o)
+{
+}
+#endif
+
 #ifndef __HAVE_ARCH_DO_SWAP_PAGE
 /*
  * Some architectures support metadata associated with a page. When a
@@ -748,14 +754,14 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
  * processors support an ADI (Application Data Integrity) tag for the
  * page as metadata for the page. arch_do_swap_page() can restore this
  * metadata when a page is swapped back in.
+ *
+ * This hook is deprecated. Architectures should hook arch_swap_restore()
+ * instead, because this hook is not called on all code paths that can
+ * swap in a page, particularly those where mm and vma are not available
+ * (e.g. swapoff for shmem pages).
  */
-static inline void arch_do_swap_page(struct mm_struct *mm,
-				     struct vm_area_struct *vma,
-				     unsigned long addr,
-				     pte_t pte, pte_t oldpte)
-{
-
-}
+#define arch_do_swap_page(mm, vma, addr, pte, oldpte) \
+	arch_swap_restore(pte_to_swp_entry(oldpte), page_folio(pte_page(pte)))
 #endif
=20
 #ifndef __HAVE_ARCH_UNMAP_ONE
@@ -798,12 +804,6 @@ static inline void arch_swap_invalidate_area(int type)
 }
 #endif
=20
-#ifndef __HAVE_ARCH_SWAP_RESTORE
-static inline void arch_swap_restore(swp_entry_t entry, struct folio *foli=
o)
-{
-}
-#endif
-
 #ifndef __HAVE_ARCH_PGD_OFFSET_GATE
 #define pgd_offset_gate(mm, addr)	pgd_offset(mm, addr)
 #endif
--=20
2.40.1.606.ga4b1b128d6-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230512235755.1589034-3-pcc%40google.com.
