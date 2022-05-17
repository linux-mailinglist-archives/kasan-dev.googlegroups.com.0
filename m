Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4WJR6KAMGQEGYPT2KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id D5EE052AA0F
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 20:10:03 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id t1-20020a056602140100b0065393cc1dc3sf12900116iov.5
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 11:10:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652810994; cv=pass;
        d=google.com; s=arc-20160816;
        b=xgyMvGlHl/C/CWlP+1vbCdrJm7Vdy9RGsee3lFQoWVMGVFjBfbVgJoibvD80wN2leY
         mX0gjy5FoXRueG6aa5ddFavCWAOPlBcnTRgDp8XySfkfxgGADNQRvEwHg548blkUjvza
         MoDBAxFZZq5pg8l3zjqbdQeDfHKpXzyVAM4GGS3dOtpe2eaKXUuehshcnyBdm0LvGhIL
         0kY36WbVkoWwfId+P+xhNSyI6D55OFcnYRMWsrZiBJ/tRvWXw+ChiPteb43zZvY1qpZh
         JeyGFqPAS5GR38B6kh5E/3/As2MI+tE5uAZzGs+lVmkIYDGQHNXkM5lsyeTNzRwyMU6o
         DgEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cRT+SduYLsk8dF/xHtNvMkZASsDbLeVTz//8CusGkrM=;
        b=LGVATx7Gs9oV0oXBXJ/Esy0YStdjylXpDE9tlIrgfrAKbB6N8EAAOPB/H7kSJnA2Vr
         391NzAR3Ayt6Qputphen9cwNC0E9Cu+OCvWOLdaJfZwpxk0En/S7VqgjELOh+0xAN32S
         HT6VMykAn28Z97CAZ2YOHpStW5hgw1747QBelnba3wvvbHra6i4DtCqAY8iaVw4HOmPO
         SQKsFk5ac1H8iPsqqFrVLHcsts4UJN/i083CtY5Jquj5lS+i5HOh8ByrG5WHkLaWOU0H
         mJTuJuKMZGRSnRhyKNBHrtOHTjNqtNuUOUYgzQtYmi87zfik2tGagtBuU0zjGrYz5auo
         XF9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cRT+SduYLsk8dF/xHtNvMkZASsDbLeVTz//8CusGkrM=;
        b=VdFNIed+MPZG/wD92FMo782sbw64Yi6PHiOc92wWKSyHH9GlXPSIuBWVC4hBIWMdVs
         v1CwelUdvdkWITFoBBAYlg1DFrLScFIkjO0pffg4QrHc9nmISY7rUNLuv0AU9yNewyiW
         S+drbgZkbl3gexxcaLtH4d5vWrTz4QBPM9t5POGSEXi5c1arILkQ6hjCM2IcvsysyIHO
         yQAt7PlIqZ7T8qfQyY1CZSSz8qahunkcUqCUJvOgljAnGVziPP+26/XYgB1sfgcADPsa
         Rdz+cY2fkBHCPdSU752OkV7gTAPdFbAG2Krvm2uyb7cfrwUdkzE51bVqd3ItVltcKdUv
         uKDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cRT+SduYLsk8dF/xHtNvMkZASsDbLeVTz//8CusGkrM=;
        b=xe8IZlNLAyq+BVRRcgMEFKIs3qLRLMLhFOZ6eAEPSXeRcydQKG+F5vKeC013IbUpnt
         6QHGp8723LTgy7QAYbUf61xZHBbOflq3HHvmFUYczvBBWej7dAnctE28JoqvI0oBUzAE
         DVCuxEZkttQhJHFD6Ok98kM4TJlQsVJwUKRt95NspNKgTsIWx4dbpiAsRV5S8O28o3Dm
         UbgCMf/cZB/nmTrtHcWwDF1XN+BspieLTWvexUn/hHx1FWNp9RaFRz4oP34vxMiWkJEX
         cf2dZTanrwWCiu5SY/Wn3Nn+ou9KMplOIeHu9nkmA/4Gy/lAREXq/60Aftu6y1REgpSL
         YrMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DT5QRgrh1NSGOVCnFLQIJ9h12ZBm9D/5+rWdFefzcvQtWf9He
	9iBLzCbIgJNVZxegOaUr6AY=
X-Google-Smtp-Source: ABdhPJyK0jvzjwlzljqzm4e7TDlxJOD03Gp5TrWum5h8hooF8xnFHTHZbEz5DowbdoE6rGR5OOke7g==
X-Received: by 2002:a05:6638:4388:b0:32e:6882:8f14 with SMTP id bo8-20020a056638438800b0032e68828f14mr238688jab.65.1652810994444;
        Tue, 17 May 2022 11:09:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1395:b0:32b:85e8:b3a with SMTP id
 w21-20020a056638139500b0032b85e80b3als3346291jad.7.gmail; Tue, 17 May 2022
 11:09:54 -0700 (PDT)
X-Received: by 2002:a05:6638:19cd:b0:32e:1b95:e56b with SMTP id bi13-20020a05663819cd00b0032e1b95e56bmr7907015jab.0.1652810993976;
        Tue, 17 May 2022 11:09:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652810993; cv=none;
        d=google.com; s=arc-20160816;
        b=rHGVugXkb90n2NkB7tvk2FGjQkWqnNypI1LpiJME2EOv3Rf47IaLjb2ivCmXt0cICD
         qD3pSpHnq8MMDNMw+A/LdmfU+7mEnIKjPlHI9YJUZM4MH2f1QCGNPc6gnCEEkTYQq+Ff
         R39+1p3QgOHZKuy519XTPATrNPnIydx9ZGSED2AbsSr9ddU68EesovFp0HNdkM4CeRfg
         v7lmPzgWOJ67phi8MuSty0Kg+JbrQx07SbjFpGf+r7EXYJheDLx0lMUA6/dZS5KSr32r
         GSrGricfGf+eSjYA30nXOQxMC1V/PMOznzANC1skE6jY/rofVwpcIrJ6dm0P85rZWG63
         5ueA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=cOkIJTTQJM7cT+gDfccYdYq59kqQBH1CwoD+bKFMdsg=;
        b=N+mitBEpUd3yoGIJghA/R5ARAfy2LGSxOAZowza7rJeIVLjMhVqHz+Cx3nZBNj0rZc
         xunUJTEdx4PwpUKJNWBpoCUkIU375uGtM5lmn+Np326uFnPBfY5gG/w9ZHue2tNHNnQy
         YUovgmb12HYUpnmphbkFhCofQCJusv3kA/Tq0J0luagUWtpqqqMzTCrSqcV4nD0SsfIo
         1Niy2y/xWwx96K9jGScvu2tWUCfcwJTvvNicEcLX0ZKuedSQpXfPTBDkHMow2DOrBETb
         ZjNQk2pl6TmZ+5jmuAdP//0dsAR2cjAhIFyQSB/IRbbbrHFj/mQYyTKbtAWFBJkBMVCj
         AJpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d4-20020a6b4f04000000b006495f98f57asi122589iob.1.2022.05.17.11.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 11:09:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 8451FCE1BD4;
	Tue, 17 May 2022 18:09:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 04ADBC34100;
	Tue, 17 May 2022 18:09:47 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and page->flags
Date: Tue, 17 May 2022 19:09:42 +0100
Message-Id: <20220517180945.756303-1-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:40e1:4800::1
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

Hi,

That's more of an RFC to get a discussion started. I plan to eventually
apply the third patch reverting the page_kasan_tag_reset() calls under
arch/arm64 since they don't cover all cases (the race is rare and we
haven't hit anything yet but it's possible).

On a system with MTE and KASAN_HW_TAGS enabled, when a page is allocated
kasan_unpoison_pages() sets a random tag and saves it in page->flags so
that page_to_virt() re-creates the correct tagged pointer. We need to
ensure that the in-memory tags are visible before setting the
page->flags:

P0 (__kasan_unpoison_range):	P1 (access via virt_to_page):
  Wtags=x			  Rflags=x
    |				    |
    | DMB			    | address dependency
    V				    V
  Wflags=x			  Rtags=x

The first patch changes the order of page unpoisoning with the tag
storing in page->flags. page_kasan_tag_set() has the right barriers
through try_cmpxchg().

If such page is mapped in user-space with PROT_MTE, the architecture
code will set the tag to 0 and a subsequent page_to_virt() dereference
will fault. We currently try to fix this by resetting the tag in
page->flags so that it is 0xff (match-all, not faulting). However,
setting the tags and flags can race with another CPU reading the flags
(page_to_virt()) and barriers can't help, e.g.:

P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
                                  Rflags!=0xff
  Wflags=0xff
  DMB (doesn't help)
  Wtags=0
                                  Rtags=0   // fault

Since clearing the flags in the arch code doesn't work, try to do this
at page allocation time by a new flag added to GFP_USER. Could we
instead add __GFP_SKIP_KASAN_UNPOISON rather than a new flag?

Thanks.

Catalin Marinas (3):
  mm: kasan: Ensure the tags are visible before the tag in page->flags
  mm: kasan: Reset the tag on pages intended for user
  arm64: kasan: Revert "arm64: mte: reset the page tag in page->flags"

 arch/arm64/kernel/hibernate.c |  5 -----
 arch/arm64/kernel/mte.c       |  9 ---------
 arch/arm64/mm/copypage.c      |  9 ---------
 arch/arm64/mm/fault.c         |  1 -
 arch/arm64/mm/mteswap.c       |  9 ---------
 include/linux/gfp.h           | 10 +++++++---
 mm/kasan/common.c             |  3 ++-
 mm/page_alloc.c               |  9 ++++++---
 8 files changed, 15 insertions(+), 40 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220517180945.756303-1-catalin.marinas%40arm.com.
