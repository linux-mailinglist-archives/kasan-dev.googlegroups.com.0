Return-Path: <kasan-dev+bncBDDL3KWR4EBRBDODRWKQMGQEH474RFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 65C75546951
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 17:21:50 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id i129-20020aca3b87000000b0032e75128546sf10880834oia.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 08:21:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654874509; cv=pass;
        d=google.com; s=arc-20160816;
        b=eyCch7ej/bs6Evuxh+pCNBRPlOiMTp3a+ELgBf/jACu19oJfqkxy92FufH+jy01ZcN
         J9/57PN0cKjKiJUUzNBO8jgE0aTSAD+s/yFvs7OxTVnKxvmeU6QZycSBwQ3lIK8pTlMr
         rqwapN4HcS5+HTfZmSsIDUvSzrNubkUDQqBntY0PoevR1ebxTQP+0+kmCfAp5YYFZSUu
         DBgDoC3iYeJRnzqmiHcVZA8XhPz4nGNimM4bAbZOaDziidG/d1/QEUwLH0vdIvLD+GDO
         vNEjzrxLtbArhOPsY35lOxjbTBQxDrJKDEDCcABazCFPqS+uanb4Yc81Y/1BdQk/984r
         JZjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4kZcOKs874DnepCe4g5sg2hxbpH4PsVyyJRdjg75SlE=;
        b=uxpiGjPwf87Jjn/+4VQ6XTe3Eqv2WDHxWuIRlWOjyDdmcX+gCLz/uMYHbEvLh3YOSM
         kTx/Vff1QB3OX7rROQ736tuS99JVAcP9jzjLWr3KddPC15YEhWe5v+PcLORIQYOY2W0e
         FT2Be7MfhNi1FOPnoCm90btHNdK6Sw6ZS8wQ8GGMU5Cd8G5TKhn2MN0kmS1kH/wAlZD9
         xiVtRRRozG0l28o3LD3kNhLxa+eZZvSqDGVP0wY5w0cdh0kxp//BVAk4C4mdfCF+erdm
         aV7mnjSCf3ZJL9Bcg9zP6sVj7v9prZf4wbUzUtuMjnOwhIsMpO49SklJC2RTmj/iYU+o
         lZCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4kZcOKs874DnepCe4g5sg2hxbpH4PsVyyJRdjg75SlE=;
        b=sJwKMTUpOlMG2yVG2XW1hEjXy9OTVbPc6mFyD5J1PET3c36eqpPIDq1WD+3fJfmB/b
         foYWtOlMRDp4k1jIJTWopMAaT8SW249g7bkkIF/6aNiRGWN61tWbaz46/Thu//QOm/Yv
         2KhiqF8EdKNjC+1BIv92K331r04KMwcxFNSDIR02dl6UAQ03ZHn4J3gCEKsGGwXSeTD5
         hP4VeIENZpESJ01dJ1LAkomtrH5DvAcsAchIOAErR1R99wPycYvSMtPJX+mrYDbYhJBi
         39Dj0gnoMLThRVQTcxRCZ0gvj1AHOe7OmVzhonRxBbgKzjDa4SAQkjn8aUdpDBO4ueLt
         2bhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4kZcOKs874DnepCe4g5sg2hxbpH4PsVyyJRdjg75SlE=;
        b=Ejy2TbEgEhjB929yEZJVzi0wABknogG+sd2tGzOZI+dPUe+KX0b49kpo4cmtEh2g5L
         M1AolrO/1vfYzOVXsQztdmhmV0q/6uyPhHIXGynKCL7Hg9Ww7YLuy6McvD+GPeJYRBqS
         xjY9m5xr1MWHjotiE6vqmzieE0Hzt9h7R2Ju5wZbHYfZ4lSNs/b9htB2HmBaFSqDkBO3
         NNT3mCb31p1RuKmfuq7yxP2bho9xw84nEXgVHPmy899EsUOrHglaNU+MgYo0gSekhr/F
         KRCTlQAnVNWwrBfCTMbwZd0Dzg4brOEF+N/4BjD37n0zVt4H5fuYRBcD8ozqI6HIHqqu
         DNLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531kIkJBMv0VhrzOhwCViV+5sulCrEqJ86kdgDxlMNgfUM8EauM7
	8I+HfdxxV//9YWa44mgz1VA=
X-Google-Smtp-Source: ABdhPJxpZLDBixSFrGm/Fmh2Ip9We4Xc2kRebrhXBKuouOLUHW/SUgJd57GKVH5NLzsq/+riax7sdw==
X-Received: by 2002:aca:32d7:0:b0:32b:4437:baf0 with SMTP id y206-20020aca32d7000000b0032b4437baf0mr188867oiy.204.1654874509240;
        Fri, 10 Jun 2022 08:21:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d78a:b0:f3:426e:e97a with SMTP id
 bd10-20020a056870d78a00b000f3426ee97als8820788oab.2.gmail; Fri, 10 Jun 2022
 08:21:48 -0700 (PDT)
X-Received: by 2002:a05:6870:418a:b0:fe:4ac3:a0a4 with SMTP id y10-20020a056870418a00b000fe4ac3a0a4mr197546oac.48.1654874508871;
        Fri, 10 Jun 2022 08:21:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654874508; cv=none;
        d=google.com; s=arc-20160816;
        b=M3K+azuvRtNHb9T+E6kck318FbXN5lK6zXJB0dnCHkkLPQ+BZg4PyQDUi1YsnLxtJg
         MpIzrLYerqpGWQv/Q8jOr3pVKQrPPqnLEXSicOORaK4aNtbR6Gdk9qGC9Z+uVvEwXUMC
         IJ8kDbHrdXVprEVNh6OnRKs7GA65Q6e0QhU720oO/d+lVw2M8EaFVjLhnz6EAtkgormi
         Npgt8yB41JNsW2avU4pMb8AH8VVf3QiZ1SjXvwAft+yA0j4r0eUZv4mzQxIWZEn+/gaR
         M6igvj6JujySiJxOdxNN+qfVYGwzbMo43AbmZXj4pm5gPuCLXoCfxOz0poXyJK0Mmbvw
         XN4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=lgMgeWhztOHyVi3SUORGBw5VvBKlP0XC/a7AJMMixY8=;
        b=NJHl/0njq5VvxHQ99AW9P/7hPhLFzbxq7+O0+6U1EL706Y5O0VfRuCxszKDgAGzLrm
         tdlaR5+mcSMr0Rh2UMig2nCDS9T0j1yJtacbyH3r90/Y10/qCZzvaGbG22rNPeBhmWv9
         3cndXjZkEicMhio8HxrAhOlzkcHgL+hiw6PXa2WKmtgyxOrH7s76STKU0C5zQ40V+eqJ
         +UnASOMnKTXhkqoBU6X62yZgmWWrHYX+T+i8z7zRz4WglVvldO6np0ctp+8JEOzaczIb
         HwFs5TbAitVFfLmIHM/0D89p46pQOCVh1dh5n7vErYdVqqJsHGIsKYiIHHEFWu3EUNRe
         kiug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ed47-20020a056870b7af00b000f5d73c60c3si2479410oab.3.2022.06.10.08.21.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jun 2022 08:21:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AACE361F8A;
	Fri, 10 Jun 2022 15:21:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 41782C3411E;
	Fri, 10 Jun 2022 15:21:46 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v2 1/4] mm: kasan: Ensure the tags are visible before the tag in page->flags
Date: Fri, 10 Jun 2022 16:21:38 +0100
Message-Id: <20220610152141.2148929-2-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220610152141.2148929-1-catalin.marinas@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
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

__kasan_unpoison_pages() colours the memory with a random tag and stores
it in page->flags in order to re-create the tagged pointer via
page_to_virt() later. When the tag from the page->flags is read, ensure
that the in-memory tags are already visible by re-ordering the
page_kasan_tag_set() after kasan_unpoison(). The former already has
barriers in place through try_cmpxchg(). On the reader side, the order
is ensured by the address dependency between page->flags and the memory
access.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/common.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c40c0e7b3b5f..78be2beb7453 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -108,9 +108,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
 		return;
 
 	tag = kasan_random_tag();
+	kasan_unpoison(set_tag(page_address(page), tag),
+		       PAGE_SIZE << order, init);
 	for (i = 0; i < (1 << order); i++)
 		page_kasan_tag_set(page + i, tag);
-	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
 }
 
 void __kasan_poison_pages(struct page *page, unsigned int order, bool init)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220610152141.2148929-2-catalin.marinas%40arm.com.
