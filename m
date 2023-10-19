Return-Path: <kasan-dev+bncBAABB4EUYWUQMGQEENGRLQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id D071D7CFDC5
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 17:25:37 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-41b806be30asf918241cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 08:25:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697729136; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kuhj3VzcpVAMj7qEgCgxzjS58k6FnG/FFgQ/ZjauFF1l+p9fa9wNhvaNVv8T3Y7Ebe
         4j97MNReDWHUQiJ5dlnAHoq77ShwB4GHiEsVpb2kgMUh5LCq2NU1YC0dRY0xhPa1Iimt
         5dTtjBBzXouE3CB/mr5bJ5n7HhiQJA6evN4N3lzIkTCFj9dflq09ISTTkUV/hv3/tnxV
         BgAe4jQlql9h0yPHP+M3OeiGXxysOpxo7Ljfhqhie1u/ax18xkXXPxwdw4v/C47cmZ5D
         OXswnC5QmhLHbYsKX18RAgg3q5PBQ2JCV6fbRKoDfWftmncGupwC5GMYCaH/7oLGP09w
         7NbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :date:cc:from:subject:sender:dkim-signature;
        bh=/Kfvjk2Qq4vsSN+PCmlPxV3WZh2W+i98uZGWAi/oVFg=;
        fh=Qz0GlNUUQOP041c42I/KGDZUvrAj0vfqrGHwltwnOFU=;
        b=gvoXjsXaxm0JsozOd7WjzyEPTCa995bq4FFai0JLc6O/xcJ7uGuBbQw7FjmJGmdjUA
         9FDxIhUeT3dHI4SHVryB9qbg0bxK/LGN7V01qFJZVHXTetkB+tS5XPpPd+6pDGkkdVgH
         d3yCchiyizVoAJzwvpOzI9dvV9eEFuqtMCfyXvZKfLw/DKxj6BdOMaB5xbPBrT69jQqG
         PnCUni/TwbiTNR2aOyBhz834316o+oD7A7zOhMUQsdhDR1dM3ql/N+qnzLVaNjVzqR0u
         5pAsgonqADZx0XSCI2snXYBsarGI+fOFDz626BmM6LwIf2HHthoOi+6u7Xk58S+ShFA0
         3Wdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="s/A5u5nu";
       spf=pass (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697729136; x=1698333936; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:date:cc:from
         :subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/Kfvjk2Qq4vsSN+PCmlPxV3WZh2W+i98uZGWAi/oVFg=;
        b=HExJtWe9sigN5nsicH9nB1jJjh3jrBqCuwUilFNVB6RqqEQU1nVREd/piMC78O2Het
         I3vA4zvO0DfFLw5GZpNyK3z7HeYazJDwaSGDAnj+o6dJm/EvtLtxeJudmWTEPWnOit8c
         0UON/ZTAMgYNGlhdVkyle6/fn6tlOFZM4LTPnMUhDstlNHdnWGh1yQ4XS8Gd+TSC1Wi0
         IjLjk+JouRhtNU84DApV/caZZhjKQyeaJkEBYSJfQhpgowqRCoGRp4v2FrKmasLEyv70
         RdvHgGrkIMzQU2FNRZfDxcR2SN12jkSkhhLzHPKScAql2G2+igJhv7xjcOmPtuaqQnby
         wJeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697729136; x=1698333936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:date:cc:from:subject:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/Kfvjk2Qq4vsSN+PCmlPxV3WZh2W+i98uZGWAi/oVFg=;
        b=fzPOLWkI5eEWX5ULFB/bzkDqGnO3bsGGNBbY8cMWkFTkhjuSbZUbKfjjffWvn8b8Rk
         666O5+H1jDjeirHw7YRr+x1lrFsGj5Nl08uFwfWd4tIIj3QX8LsYFLBtBxUOzLppOlv9
         cr73zT7ogub/bS8acUKOl54RHMoBqkMbX68pFi8skRXqRSEaImKTXxGtwIM71sA7xwNu
         DDGmB6P5OSjpk0G8g/6IzsgWgdu8bKxm8KmJyvhoVRHzFc6kLRM4E4+Be09HZ/U3RMtv
         XIqf0M5QASmCrpvQMLLxOECXH1CxNTvu8o/Q0WK9RYvRzZkN5IOavOKCyT9B9vVobQjI
         aAhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw6J5S3yY5tnHTqEWd0dMpn75wEn89NPBE2AU+61kX9sp/wFWCa
	pfzccNMq7EAjHP8qh2O8BaI=
X-Google-Smtp-Source: AGHT+IFAHcY1x5t67uheLDlB/H5lpAnIjalvV0rabm3ZeyBJe0AK0mQikIVio8pALlsVxe4+pGiNrQ==
X-Received: by 2002:a05:622a:7619:b0:41c:ba55:e3bb with SMTP id kg25-20020a05622a761900b0041cba55e3bbmr245636qtb.1.1697729136577;
        Thu, 19 Oct 2023 08:25:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:9a8:b0:65b:e4f:d22c with SMTP id
 du8-20020a05621409a800b0065b0e4fd22cls1160qvb.1.-pod-prod-01-us; Thu, 19 Oct
 2023 08:25:35 -0700 (PDT)
X-Received: by 2002:a67:c210:0:b0:440:a8c8:f34 with SMTP id i16-20020a67c210000000b00440a8c80f34mr2509062vsj.3.1697729135501;
        Thu, 19 Oct 2023 08:25:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697729135; cv=none;
        d=google.com; s=arc-20160816;
        b=ThNlRXNO1sPga/n1Ki14xhEi0UgpjyRcsY0JeEgNPMVA2uSfjE/mknzpUWUBUdd4fo
         N3UADMiQFFR8yb5SOyZ947EFBJOhMkVlRzIPrfrkeAp8kBUV/GXBtDWSt4TcOBxl+/Ol
         jG0ZRMQqNA0lerKbrE6Ly1nr69Dq/amNPrQP23NmYNl8bXp06sTX0SIUut1BCLsMSTz2
         9Lp9+h9MgPFClJifapjK4HTWTH3mmo57OtGZbfnp/a46q5N+E+s34p22eEo/fjMAW6DC
         r/2huurMDVx8eq1Z5Wy5X5VWriixsZ4THSFQZMMHvjtnHTly9D5byeb99wgkQq34Wfl5
         keMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id:date
         :cc:from:subject:dkim-signature;
        bh=cX5aZ6mOEQDrOawUDAzp6GCxq09mE7rC9ZDBEzG04KU=;
        fh=Qz0GlNUUQOP041c42I/KGDZUvrAj0vfqrGHwltwnOFU=;
        b=UMDT3fngHP365/xwdQqV1QkJJy8aSWt3wPsQ0fUCGI0bwcy4EdLwITBw8NxZBc+ra8
         q1vCl7efWEmGv7Y6afW0kjgi0r1uayUx10YQn9Y++4wxUKfmO5jNcck24re+DxawRray
         HOWToPPvb/jue+CiXGXrEqGgY7iVFWNsyAwvmsJf3y4+uOTYX8/LgEB4FkDs+aOJKOcM
         PpecOOOc1KEBD+lmZHBtvzSd6J+kalu4xC5MGdOXctV1wWDzHEinrzMm97UlLgok+2BF
         /7aQDh2KTE1W/uJ83osXT21fj/r9Q9Hw6Ooqjkz/B/Ss1ppF4jdMFsabZ0/84rkLqAv/
         Ittg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="s/A5u5nu";
       spf=pass (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id gw19-20020a056102669300b0045258d13d6esi632768vsb.2.2023.10.19.08.25.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Oct 2023 08:25:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 3A255B828A4;
	Thu, 19 Oct 2023 15:25:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B5754C433C7;
	Thu, 19 Oct 2023 15:25:32 +0000 (UTC)
Subject: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
From: Chuck Lever <cel@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
 Chuck Lever <chuck.lever@oracle.com>, Robin Murphy <robin.murphy@arm.com>,
 Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
 linux-rdma@vger.kernel.org, Jens Axboe <axboe@kernel.dk>,
 kasan-dev@googlegroups.com, David Howells <dhowells@redhat.com>,
 iommu@lists.linux.dev, Christoph Hellwig <hch@lst.de>
Date: Thu, 19 Oct 2023 11:25:31 -0400
Message-ID: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
User-Agent: StGit/1.5
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cel@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="s/A5u5nu";       spf=pass
 (google.com: domain of cel@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=cel@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

The SunRPC stack manages pages (and eventually, folios) via an
array of struct biovec items within struct xdr_buf. We have not
fully committed to replacing the struct page array in xdr_buf
because, although the socket API supports biovec arrays, the RDMA
stack uses struct scatterlist rather than struct biovec.

This (incomplete) series explores what it might look like if the
RDMA core API could support struct biovec array arguments. The
series compiles on x86, but I haven't tested it further. I'm posting
early in hopes of starting further discussion.

Are there other upper layer API consumers, besides SunRPC, who might
prefer the use of biovec over scatterlist?

Besides handling folios as well as single pages in bv_page, what
other work might be needed in the DMA layer?

What RDMA core APIs should be converted? IMO a DMA mapping and
registration API for biovecs would be needed. Maybe RDMA Read and
Write too?

---

Chuck Lever (9):
      dma-debug: Fix a typo in a debugging eye-catcher
      bvec: Add bio_vec fields to manage DMA mapping
      dma-debug: Add dma_debug_ helpers for mapping bio_vec arrays
      mm: kmsan: Add support for DMA mapping bio_vec arrays
      dma-direct: Support direct mapping bio_vec arrays
      DMA-API: Add dma_sync_bvecs_for_cpu() and dma_sync_bvecs_for_device()
      DMA: Add dma_map_bvecs_attrs()
      iommu/dma: Support DMA-mapping a bio_vec array
      RDMA: Add helpers for DMA-mapping an array of bio_vecs


 drivers/iommu/dma-iommu.c   | 368 ++++++++++++++++++++++++++++++++++++
 drivers/iommu/iommu.c       |  58 ++++++
 include/linux/bvec.h        | 143 ++++++++++++++
 include/linux/dma-map-ops.h |   8 +
 include/linux/dma-mapping.h |   9 +
 include/linux/iommu.h       |   4 +
 include/linux/kmsan.h       |  20 ++
 include/rdma/ib_verbs.h     |  29 +++
 kernel/dma/debug.c          | 165 +++++++++++++++-
 kernel/dma/debug.h          |  38 ++++
 kernel/dma/direct.c         |  92 +++++++++
 kernel/dma/direct.h         |  17 ++
 kernel/dma/mapping.c        |  93 +++++++++
 mm/kmsan/hooks.c            |  13 ++
 14 files changed, 1056 insertions(+), 1 deletion(-)

--
Chuck Lever

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/169772852492.5232.17148564580779995849.stgit%40klimt.1015granger.net.
