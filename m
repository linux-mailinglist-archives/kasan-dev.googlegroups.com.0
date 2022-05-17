Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4OJR6KAMGQEELR653I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1938F52AA10
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 20:10:05 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id z11-20020a17090a468b00b001dc792e8660sf1754317pjf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 11:10:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652810993; cv=pass;
        d=google.com; s=arc-20160816;
        b=DCs77siHCYCfj0I5re5xTOhMDkR/2E0GtJLfEf2N/Jt1ZdIM+oHd1V+COWqGwT/XOi
         ZE2FhWj58Z58Qs3hSnX2hgPdLslqtT3Ni/nlBaJQC0ufGBa4vmgcQVNVceVi66n9mL37
         1jHa5Hsw1o4CedqBe8gngISNsCyB4OVt0D3JR4C3nR/9wC9fDqwxNgSEcm69XczAYfh3
         f3r0OujFwovW4zaHSgJ7ddQNNe/434WoPrP/crrf3Og/IV9lP38Di8DPsyc7VZO1PUfO
         4YzqVN24QJZJep5ca/Zk62KTOY7te1hqIEAA31nqyw5lEgh2odgOotgQ8BN3RsTuuTqS
         nFsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tj56s2LqchYdJEkVxQMS48Q+zrt6/lXciQd4KXpF2dY=;
        b=I9xR0+2nTTCsqanqastQgbyG66q0j013J8jvvXl4sUcsUvpFpz/eB4cCevVzQjbnUy
         DO+zTge0ylr5rGCSXtAIn7PIHJ/fpEVRxalSKk3vIOpZUyNG/4x61rC3uCI5mEmQO0K4
         92gXBmqmeWkCdn7oopJxEgheK1WPVwDn2sx1oDQdmt3xWa0FM091S1E3qozRvcvGvKMa
         6Vg3ApJ9oFvG5hPQSETT8EpO+RgwkaQ+woT1pcAxt6fuU5VRiyd6WPiL51ThIU84V8BL
         iDjEgPE6/E2lhdelnJX1SnSL1PV42hM0sGDSMaTPEber6MyBcUnkkxKTkzdSR7Jl0gPc
         H+8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tj56s2LqchYdJEkVxQMS48Q+zrt6/lXciQd4KXpF2dY=;
        b=dBMnAiWlCiTbBJ4qF0X9y9WILF7zV1acXLS969ZfMdHIBCWrZRQoJT2BUU8OE3y/YL
         aicRFgpVUh9qiP0H6HNvxbNZT+uItViX4yNUzNFCZ1RgkNyk373G0wHA+zaEotGNyREQ
         W2j44qSpY9uAR79CRGnmeVMUDdhYuQbPlp9OhcK/1a9cbYhcNnpVsduFPCPqOJFZnPgM
         eUd34ilo/VoY0hvfaLKZAFM1MCjEIFrIAsN+8qxTU4lLnIW5rCDZK7mokQ7kg7DJeoqq
         zX8R/JGtee3/omRYDe2gaDeophohh2L9l284W6hnVidN3XMU+RKG/mJU02sQ2Z2Qt1ps
         eUjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tj56s2LqchYdJEkVxQMS48Q+zrt6/lXciQd4KXpF2dY=;
        b=iUzsETTX7C11NRXZ3bo4+fVXkrCmTb8helNIR0ZCkZPBldKaPH+yYVuo+rf2jdoKWW
         /oYuZiIjiHVsF0OpVMtAXSoGjFeeZiEf0QNfP7N3YHRx0XCzr6tERoJP62pk+PqNj6tv
         /OH3MtvouP73YlJy/ZaBHRFBv0wS44LBNDHWjpSOBhQZQNWSWmZl0gGTsRpTG7AyVKJX
         fF4eM6RanU/cierreBwVN6qqWDk9eaPlFfaGde9rPiU1XyCbNAro148rVIArFmYMGMJZ
         Pk6CxfD78PQFFeD6AbmCA20Af5vA7WlDIye8S8Nlu9xQQlQ2p6prWrpnudCUVeSs0gd7
         uJLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ghMi7zRfrRyr42is9snYkJhQhvxwHf9TmpfYVOLQh9Lfd6VoI
	vP8PhcpnJ3AWnQqprb11jLg=
X-Google-Smtp-Source: ABdhPJyg7flP7Dj4F5inA/ZVpTCznsOURxkuWV8qehsx5KY6HOvvHJEu3QX683vFcNkcG44dcZ5ebw==
X-Received: by 2002:a63:85c6:0:b0:3ab:4545:e29e with SMTP id u189-20020a6385c6000000b003ab4545e29emr19836932pgd.573.1652810993657;
        Tue, 17 May 2022 11:09:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a8d:b0:1dc:36cb:7c55 with SMTP id
 lp13-20020a17090b4a8d00b001dc36cb7c55ls2091663pjb.2.canary-gmail; Tue, 17 May
 2022 11:09:52 -0700 (PDT)
X-Received: by 2002:a17:903:124a:b0:154:c7a4:9375 with SMTP id u10-20020a170903124a00b00154c7a49375mr23628976plh.0.1652810992860;
        Tue, 17 May 2022 11:09:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652810992; cv=none;
        d=google.com; s=arc-20160816;
        b=zLJclFUSIGYi85VYdztd9jIg5vX1ZJOregiAVrbWTyztXBFenZijP7u1svM/Ce8NJp
         Lgj90sTNxZTxT6l+PwdlskmatqZudZZo2ARZr4zg0lzTpPUbJxe5dYKyZWKSyhGOqnSq
         jzONEAga8K6djAzaiw0FwGxjrbQy068hy8yRHcyVtn/IkZ5Jb6TJRDnEiPlSpxcq4S6Z
         k9CqC/1NbFaU9C2/rJ+NtXuTxIKzbPzM/xcVqOZroTZH/TqZhVuZZVLZmMe8Ap0fAarq
         35OSA96izYNml9vwCXh9oTu0ZX3gaASz3bny42mY5lHYHFno+XlSxqJrDuFY8GTnW1/J
         V+oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=MvTRkwd2rodA8qPH7aRiiTXvAXkuPsDdaX3QRlFyBJw=;
        b=azWOu4nsnnIF3aaZdhyfhxVNYD3H/0Sxdw8eJAL+Y6ju9AkWRZXfmS851jHLsnUah1
         /Hz1VaLOBCMJoc7tDgv3Y2sBijzYrXnRFz44QgxKXsfqSTRPu7mQkgGeo9xcNVlqX0Vv
         lGM2NdPVmp5Hkw0kmTe1dh/sMUxtH5A1MjVMaoibtYtNGtlzCtY1+LV8sQPFpPsw9NQy
         YbNg22hOiaaBMizeygYZC87tqC9KUXRTiJiGyKyo4AHslysac3J3kfDfeJ8hw2PPzW15
         6jktnYbaRWQDo+CYOvPKGq6t7/iwLRtznbBFdZJOqG/9HBHqKUxNHbNpbPbTjb/n9u+l
         orIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z2-20020a6553c2000000b003c1fd25c98esi912953pgr.1.2022.05.17.11.09.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 11:09:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 58FAE614F1;
	Tue, 17 May 2022 18:09:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1BDB7C34118;
	Tue, 17 May 2022 18:09:49 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH 1/3] mm: kasan: Ensure the tags are visible before the tag in page->flags
Date: Tue, 17 May 2022 19:09:43 +0100
Message-Id: <20220517180945.756303-2-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220517180945.756303-1-catalin.marinas@arm.com>
References: <20220517180945.756303-1-catalin.marinas@arm.com>
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/common.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d9079ec11f31..f6b8dc4f354b 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220517180945.756303-2-catalin.marinas%40arm.com.
