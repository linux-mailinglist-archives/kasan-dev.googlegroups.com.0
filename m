Return-Path: <kasan-dev+bncBCT4XGV33UIBBC5DQ6SQMGQEZRKKIBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E160745066
	for <lists+kasan-dev@lfdr.de>; Sun,  2 Jul 2023 21:35:42 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1b0271d3228sf4116532fac.1
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Jul 2023 12:35:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688326540; cv=pass;
        d=google.com; s=arc-20160816;
        b=bsEfJ8KWDXPVttji3//tqrffWYxb5GMyFIUfLOpGX4s1ofVIoc4HELNcbxQUJ30518
         4mCSczbc3LPwJdph+FJ44cb4rDKIwg9mxfUnxuZbaDciMsi6jsoDXT96fyNMMG0ueArB
         J1h2rrCoLnt3YbKLm0dlk9hL4Mfdj6WB4joc5nKm6M0tSsqesexoF4CPJnUA1/gYu+Ml
         jdC4tpB20q0Sn2jFgtXsXuaB6x7izx/5f+5CuvYkIzyVMuK0KyjZvjfmMix/zZ23c79P
         4w9eVOVhrzZX0AfeGn5qTqc38Lzx+Fj7NC8ODiK1yqM6ou/Sm4zoSjmqhqz8hI6l8FP/
         fjzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :message-id:subject:from:to:date:mime-version:sender:dkim-signature;
        bh=laXMSFy3OgZKVpx7OdvROWohaOz5QEB4uhjiZSwRbIY=;
        fh=0jO1JOzt27HyKkrjcL5NMcwM8KGfmM7wNTpPS5AH8Ow=;
        b=tOcd8zT9TllsSEzA1j5riDG5gEjd47NCx12X6Z8nzL7OX+zcdlpIvuujSbg/1uzbiL
         zQb3KU1wFIDYPsffj+FKwJClqSflz1/5DXIeGZy116xfIOMWRClUBAKejrbR2d300hRc
         ZC3h2CNUgfOgcZsaTWGzpeGQt5RCMljTH4ZTtAdCkaQ48wMGyMTIHkAy23wdZ92XXJVo
         qPUsQgST6MFKi9XHmLL9akxqQKjuYHD+yIcTeGsDPwWUOFRc74FXctJ8citOvLjJ+w4h
         PdIqvFZJYZ93aPoX5QCeG7NNe6LHw+Coqszdfk7RFbWd2Cw+C9RbtOqATevH0fbsA14i
         DBzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=jQo9kxVd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688326540; x=1690918540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=laXMSFy3OgZKVpx7OdvROWohaOz5QEB4uhjiZSwRbIY=;
        b=MZK9lKpm08v+JOgdbgPvbe76wfQHVhVzuIrRQ+S/lL1fyhayb2lYhlpgIwRYtjqeC3
         0haeN2l3YgYlBH1UXooMAySx6Wpz2NLI8Cpa3q1/6qLi6ov91ELV7s4uavwiMnTE/NjG
         INAOFnCMh/pMorrOAatUGvy/jTsBALIiQ1xijfqqdyWxqabxCG5MVvB0ETjgsjcfDdlv
         99jo3R0LGXS5EvPkMdODCznoShCnHgArekiKdwNgwgMUBQ0ySLC5U35DFqkbc09bDVjx
         5eMP75VSCnRkacnrMdNfDH8jWOCVWgkgHLhoot2WjcubE13aWEoFtxLkNrqT6Qikb2n7
         OJ8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688326540; x=1690918540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=laXMSFy3OgZKVpx7OdvROWohaOz5QEB4uhjiZSwRbIY=;
        b=FWH2pl8A24ww6Al781ZXUa+B22pqKEAFBTLo0KwHqbzaQoSbLzxVi5oKvQ1rxF225r
         rVeZ5NYmQq8kGHOmFJ46tdEvgbaJRwjnWus7hiMI3+MSCdOH/PHxVFP0PNS+5i9tzQ0d
         wjthccqLGxL+lGZ93xmfDE6tgzmTzmlQ3hssyRflywxDBgGActpNjz1AUaUCuKdRsE6x
         lBTPzgJDx3331DBlrd1GNF7p5R3Ek38ynML8Z2tpEGFCmkQlERzaMYF6ujCKAo2yE7tO
         Jcjdo/M2aVr3h2kbql3zY/K7AF15UIdnDJNcE0e8YHAixg2UvH8qaxSz0LWkScG5BLGg
         37eA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaY6fT5OW4izkf8zxmQ2KWgL5Rq+abm3E2NobQjrJy4DgNdoMRw
	l2x/7u6HfX8V7o8C/CQeKvc=
X-Google-Smtp-Source: ACHHUZ7/oUWkNv57RMtw7ic0hff6KWtjJ9+VHJJQOywKp+cROeyHLH55oI4JPj3XUxBwSPI9ZaiDyw==
X-Received: by 2002:a05:6871:4094:b0:1b0:4d44:8155 with SMTP id kz20-20020a056871409400b001b04d448155mr7868793oab.47.1688326539224;
        Sun, 02 Jul 2023 12:35:39 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:60f:b0:1b3:a2b3:6b5d with SMTP id
 w15-20020a056871060f00b001b3a2b36b5dls228886oan.1.-pod-prod-08-us; Sun, 02
 Jul 2023 12:35:38 -0700 (PDT)
X-Received: by 2002:a05:6871:438e:b0:1b0:21ef:6e1a with SMTP id lv14-20020a056871438e00b001b021ef6e1amr6577395oab.40.1688326538045;
        Sun, 02 Jul 2023 12:35:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688326538; cv=none;
        d=google.com; s=arc-20160816;
        b=AozLCpcJAUwBt4L3ibqnNpSK/EJdSe1ZF0npOooqT9bYh2EntPzTCGJDSikh21P00A
         WaCsPCZftd1RQIzA2wny2B4vOLCKz8N+H+PWcaLceiJhaVGAfDD0xae0UPP2eOIs5jEd
         z+hOUwvTEBpK1KPcDw0NOL+YtVKTilU99sR0YoSIEa09Bx2oQNiz6NUVp69wHbp7VWk7
         T5xd4qB5aW+apVuFU3L+gcqfewDiingPfxAgNOo9FVBuI/zMVALXiCiGva+5ztw9e/lf
         q18360Y3mQTesxcdYli2O1hUdwAtf0Cz73vFzCYbYJCdSHFAee6RcUVjFFpS/2SG0JDd
         1RTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=0L3IUWKASuQlz96nG61A1rA3jQH89BuTkwBBdfy2QrU=;
        fh=Yf7qH99iLNw9gvVXWo+YSfZkuqKx4nsWax9TRSYHEg4=;
        b=bLRzHI+gUwR3TlEetXtjbR1/F9N2VM3Y9M7gJMMAqJP4CbKwSTACJY7wJ+RxmSMZVp
         I+i7Aryoh8nXY5tPMBvSJWXf+fDXheWuDJdrpN7CbKmaiTYTet6ord1jbNoh077I6msl
         Pw1CeYO5Djtrr6OfTMMvNen2VhXiHC8nCNKeY2oakL6jlf5OoSPKj+PK+aWzlFzMffcS
         LmOinCzWkX69ZKNWrxXeqXmwp6ne2khYqwOLe/b6JXHvTc+xCfpNVIA8SGsfes0alEJJ
         8qERJ1GGfyriRvWCGlWQYnt3thitjtoxYD77HS9LwcVseeFJaBLP2uFAze+MOWw4RsuZ
         JpOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=jQo9kxVd;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ga8-20020a056870ee0800b001b39eee00b5si107986oab.3.2023.07.02.12.35.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 Jul 2023 12:35:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B6F7560B45;
	Sun,  2 Jul 2023 19:35:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 17933C433C7;
	Sun,  2 Jul 2023 19:35:37 +0000 (UTC)
Date: Sun, 02 Jul 2023 12:35:36 -0700
To: mm-commits@vger.kernel.org,ying.huang@intel.com,will@kernel.org,vincenzo.frascino@arm.com,surenb@google.com,steven.price@arm.com,qun-wei.lin@mediatek.com,Kuan-Ying.Lee@mediatek.com,kasan-dev@googlegroups.com,gregkh@linuxfoundation.org,eugenis@google.com,david@redhat.com,chinwen.chang@mediatek.com,catalin.marinas@arm.com,alexandru.elisei@arm.com,pcc@google.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + mm-call-arch_swap_restore-from-unuse_pte.patch added to mm-unstable branch
Message-Id: <20230702193537.17933C433C7@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=jQo9kxVd;
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
     Subject: mm: call arch_swap_restore() from unuse_pte()
has been added to the -mm mm-unstable branch.  Its filename is
     mm-call-arch_swap_restore-from-unuse_pte.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/p=
atches/mm-call-arch_swap_restore-from-unuse_pte.patch

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
Subject: mm: call arch_swap_restore() from unuse_pte()
Date: Mon, 22 May 2023 17:43:09 -0700

We would like to move away from requiring architectures to restore
metadata from swap in the set_pte_at() implementation, as this is not only
error-prone but adds complexity to the arch-specific code.  This requires
us to call arch_swap_restore() before calling swap_free() whenever pages
are restored from swap.  We are currently doing so everywhere except in
unuse_pte(); do so there as well.

Link: https://lkml.kernel.org/r/20230523004312.1807357-3-pcc@google.com
Link: https://linux-review.googlesource.com/id/I68276653e612d64cde271ce1b5a=
99ae05d6bbc4f
Signed-off-by: Peter Collingbourne <pcc@google.com>
Suggested-by: David Hildenbrand <david@redhat.com>
Acked-by: David Hildenbrand <david@redhat.com>
Acked-by: "Huang, Ying" <ying.huang@intel.com>
Reviewed-by: Steven Price <steven.price@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Alexandru Elisei <alexandru.elisei@arm.com>
Cc: Chinwen Chang <chinwen.chang@mediatek.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Cc: "Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)" <Kuan-Ying.Lee@mediatek.c=
om>
Cc: Qun-Wei Lin <qun-wei.lin@mediatek.com>
Cc: Suren Baghdasaryan <surenb@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/swapfile.c |    7 +++++++
 1 file changed, 7 insertions(+)

--- a/mm/swapfile.c~mm-call-arch_swap_restore-from-unuse_pte
+++ a/mm/swapfile.c
@@ -1778,6 +1778,13 @@ static int unuse_pte(struct vm_area_stru
 		goto setpte;
 	}
=20
+	/*
+	 * Some architectures may have to restore extra metadata to the page
+	 * when reading from swap. This metadata may be indexed by swap entry
+	 * so this must be called before swap_free().
+	 */
+	arch_swap_restore(entry, page_folio(page));
+
 	/* See do_swap_page() */
 	BUG_ON(!PageAnon(page) && PageMappedToDisk(page));
 	BUG_ON(PageAnon(page) && PageAnonExclusive(page));
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
kasan-dev/20230702193537.17933C433C7%40smtp.kernel.org.
