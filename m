Return-Path: <kasan-dev+bncBCRPLTWR6QDBBU5L63CQMGQE5RZIXPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id ADE7FB47BCD
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Sep 2025 16:25:25 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-88709bc9a60sf419845739f.2
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Sep 2025 07:25:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757255124; cv=pass;
        d=google.com; s=arc-20240605;
        b=gFououxi86d03HQuqSXxKgasHpb4uYRWoiXn1p5mJWA8fOXzuyX4nji4XEsRrUvoft
         8EhJ7JA3nl9/24oE8AvWi+bAae8/SWlGqSg9tG9NdNJVTnYRmmdE1nnALaaGA1DO/qs6
         6nwsXO+3OdsaNRAoCQ8o6ZflbUmcIrg8PWNKQqYH6rRbv5StMToeQS+bTiKBptoOrKwT
         ekgQoPNcyaMyMrMhtNfZRk+S6+pyc0kaOY1U7WCcZfBaF2TgBV5HdJR9upQMsZHL0iii
         sYqd6ir530h35YAcvhTT1nHVGf6io1Zuw4UJFcMfW/7e1cop492TSRYS9UyGS4YUU3HF
         Dngw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:mail-followup-to:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature;
        bh=+hiLTQytYkF+NUqvW+EDOcIYR8+vJ+S+Wyr8Oy3PpBw=;
        fh=JTtEl+y+jPMPmxHquYJyZBmGL5KiBH4QHWPL03hfo1o=;
        b=PomuNv4KsTLIGPW6sOg5r3hOhNvyg3w0L2mdfjH0/GT67WUD/4+HllkDlL14cFJu27
         L0ZjwFJMUxZCLnOn572ZRhPg36tHaz758GGnDrLg5dWd9Ui1djgnSyCT3EJq5r3nzt61
         aXmNiU5IEbbLxrMvWBr+1kj9lQh7jjbluirZeOFI8811sxpVaKUNbs5F969LWFs1x5xj
         yU5toe1GsUKEtZ1neBbn0mvV7WMZJVOcFIVPCATDoFZlXx+ulrmtmhPgUiGmuLYBTe9e
         ja1AG1OIM8MqJ2o094TIoFcVdzsFjGTb7IidVw8MA2NVaFhdCKdN8glX4TQoNZnkTZXD
         jhow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sakamocchi.jp header.s=fm1 header.b=LxAEL1hA;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=gkkyoHxl;
       spf=pass (google.com: domain of o-takashi@sakamocchi.jp designates 103.168.172.154 as permitted sender) smtp.mailfrom=o-takashi@sakamocchi.jp;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=sakamocchi.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757255124; x=1757859924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :mail-followup-to:message-id:subject:cc:to:from:date:feedback-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+hiLTQytYkF+NUqvW+EDOcIYR8+vJ+S+Wyr8Oy3PpBw=;
        b=VpeVDH1UqQx8kcpI2oYsAnyfJxTzhzrw+imKEEMHpk1sQp0msk5/2jK3f6cxj6qpFm
         yAOTtJUWS6QzvD6d3KEgVsGC0j/G5Z2XL9jT/5pQvT4aBR0YUXlkxY6KvZLOrotYQrDn
         SKTxPAol+7wHRTvA0yRlt4qKWdSLLmLPb/MSJyrr0SfLDfC+UGS3p8dnzj58H5IcCJ+a
         SwyRzee1ak96dOPGwPmdFFwtOM8bZlVjTq5sFdmOlYPkoyLBLgJmyMuiXptZnIZU9Qxr
         Q2FAPIzPYkfW15eg54htHkG7L5GHXxNyqW32SEMBIkH/01WVI4py4FZAXC4pXhxDfv3n
         glXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757255124; x=1757859924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:mail-followup-to:message-id
         :subject:cc:to:from:date:feedback-id:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+hiLTQytYkF+NUqvW+EDOcIYR8+vJ+S+Wyr8Oy3PpBw=;
        b=nBySFDWxBom0UiJkD9Vudq7jmtvAtOfj5DkiggVTLdIrhV2kGjtF0RO5J0TQ/VrOfZ
         UkoiocWKLeyVwu6xbp7wLU3F22i4aqj1+lN9a6euLs014nfBZsoMCx8mOHCmI6dEqAdN
         L8aDuUI2Bh3+VCreYcJLPM9xCuMhbC5Br3WqvWu819P+gc2oZO0kI23IwnY/GFoQNtC7
         W23HGgOKmO4dHYEwwY41hGZsJNkQtZ0EPTSwNiIOGwdfPhUVWM2L/l7yWboy+wHdKgLu
         qHUWQrbzFfQ+z42hxwF6FbHIV/301XuWX35EQh1hYK61s8bcGc8XoGM6Wv28pnbUmN7s
         N+tQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtn1d2ycoOGFI7zebFSasZqX3k93nZ0y+zG/Hqns9C7Oeg8fLjT0tZwougtAEGDUjQiJf3yg==@lfdr.de
X-Gm-Message-State: AOJu0YwHnH63YfuWD0z8191wkxs6l7qfCRjlHkvCJt0qaFt2t1LRM9bA
	6HGjS5Pwy8KiUT2ulx7yjeb8BmW/cNeIydH0CSg1kuC1GPHjyCfQrheC
X-Google-Smtp-Source: AGHT+IFoIevdlavZr/6WNe8NRcgweHT754XAW8KQoMQScZXHhIZDXZ6Zu6ZnZENzF6nTo/siDSWGVg==
X-Received: by 2002:a05:6e02:2164:b0:3f6:690f:f30d with SMTP id e9e14a558f8ab-3fd8e98cf8emr80607615ab.10.1757255123914;
        Sun, 07 Sep 2025 07:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdvSS/fKxy156iHZrN+ThgIyepl4FXDoxQKcWCISuyT7w==
Received: by 2002:a05:6e02:b2f:b0:3ec:3033:7fb2 with SMTP id
 e9e14a558f8ab-3f8a4da942dls19837165ab.0.-pod-prod-09-us; Sun, 07 Sep 2025
 07:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmE77BKn6V2+5xTc9upPuCr9TRe0RF4MiBKVMdTfTnKQzyjp+ZvJcXX/GTSL7D//l+A0BIbk8h84g=@googlegroups.com
X-Received: by 2002:a05:6e02:2146:b0:3f1:f2:1a47 with SMTP id e9e14a558f8ab-3fd97eaf9dcmr75422135ab.31.1757255122706;
        Sun, 07 Sep 2025 07:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757255122; cv=none;
        d=google.com; s=arc-20240605;
        b=S34U8+pzmvMLqE7Pjt/CSK8MYXPUjaxxpo20UD3dY6HPNKfYV9z4DdVwnSdqwqFmU2
         LKsXlVK2k/qLWdasyHIM/QWNZqztID6s+TE0tqAh5AVSYkQjV/tZ3UsokMk37cJX+jJZ
         zbatHDt0VnwE7sQ8bNtoiUCJsvg+pHHHvQSuFw+ZLq9sIXSiMsARSxPoK59pdAe/zPCL
         W4+ZRuNXyA2m+1oPcKGRvjt92pGYPFvJWuZ2pY4Qj2QMMxTiF+TkJjSPETiPA+mjyrV4
         AgdOWi2F98Jj8TFxArdM/WA9PXKguVb8qyys8Nti7xUs2ufqdO4k5NzYmxXStLGFEx85
         BYcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:mail-followup-to
         :message-id:subject:cc:to:from:date:feedback-id:dkim-signature
         :dkim-signature;
        bh=G/EPaorfj+fFyTEHaVMF0Aq5nU/5YHn8ZldlmV9nSRU=;
        fh=Em3yvq2zMsfyYtekL77bXM163wy++1f+rgqYXqx5CqE=;
        b=kU2RnoeI/ZtJcTqIiDcNoHx5yugtwXFGbDnIq1zkH6YQjzYNPfphaCFe8PDzHLBkhc
         tI3MM2djEj2Kw38TMiAjncLNoXOk+fTARBszwVgi0WzJrwOJsmO2BQGrqWSYxPZcdKc8
         K3BU/wPHmPrLdxNmZsqcqrzLpK4X666zjpvX2rlEJ8fUC2PSyB6K6wusvzBYc25aSwLR
         GWLG9E9jVVQDiDWva2PDZyf9C3nVgySIvOOOBZktFYdE3LZSvEnz4gSKctSCveI8bz3a
         fFT7hg+8qiiClhPzj5jY3ObrQqUX1Ion5BWLR9sd6RCzpkpK7zmJhne9z9u4V7acmvzx
         5RUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sakamocchi.jp header.s=fm1 header.b=LxAEL1hA;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=gkkyoHxl;
       spf=pass (google.com: domain of o-takashi@sakamocchi.jp designates 103.168.172.154 as permitted sender) smtp.mailfrom=o-takashi@sakamocchi.jp;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=sakamocchi.jp
Received: from fhigh-a3-smtp.messagingengine.com (fhigh-a3-smtp.messagingengine.com. [103.168.172.154])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-51021bb2ab8si595986173.4.2025.09.07.07.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 Sep 2025 07:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of o-takashi@sakamocchi.jp designates 103.168.172.154 as permitted sender) client-ip=103.168.172.154;
Received: from phl-compute-04.internal (phl-compute-04.internal [10.202.2.44])
	by mailfhigh.phl.internal (Postfix) with ESMTP id C2941140003F;
	Sun,  7 Sep 2025 10:25:21 -0400 (EDT)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-04.internal (MEProxy); Sun, 07 Sep 2025 10:25:21 -0400
X-ME-Sender: <xms:zpW9aHBBt0nmuBo9smDJ2pyc66XAz51H2zLxPIL-bKuIIirEqr75FQ>
    <xme:zpW9aP5GM0Oa9oXSpXiYSqnaKLnHMrts9xFSY3EInc6RNC_Ob2dxgDJB8d83jBdim
    fy3XXGQESbNHiHsUNQ>
X-ME-Received: <xmr:zpW9aNLIKTgt7t1RechOqALMeiJc4jvDTVIeA0j8Y6R9TLQOMTuGJFNVHgmJLi83Qw1w6W0IAc1sMtpcdOdKwHPv5EDXH_yn>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtdeggddugeekkecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpuffrtefokffrpgfnqfghnecuuegr
    ihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenucfjug
    hrpeffhffvvefukfggtggujgesthdtredttddtvdenucfhrhhomhepvfgrkhgrshhhihcu
    ufgrkhgrmhhothhouceoohdqthgrkhgrshhhihesshgrkhgrmhhotggthhhirdhjpheqne
    cuggftrfgrthhtvghrnhepveehudehueekveelteevkeevkeeiudfgtdeivdehjeetffdt
    vdeukeekheeitdetnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilh
    hfrhhomhepohdqthgrkhgrshhhihesshgrkhgrmhhotggthhhirdhjphdpnhgspghrtghp
    thhtohepfeeipdhmohguvgepshhmthhpohhuthdprhgtphhtthhopehjghhgsehnvhhiug
    hirgdrtghomhdprhgtphhtthhopehmrdhsiiihphhrohifshhkihesshgrmhhsuhhnghdr
    tghomhdprhgtphhtthhopegrsgguihgvlhdrjhgrnhhulhhguhgvsehgmhgrihhlrdgtoh
    hmpdhrtghpthhtohepghhlihguvghrsehgohhoghhlvgdrtghomhdprhgtphhtthhopegr
    lhgvgidrghgrhihnohhrsehgmhgrihhlrdgtohhmpdhrtghpthhtoheprghkphhmsehlih
    hnuhigqdhfohhunhgurghtihhonhdrohhrghdprhgtphhtthhopehhtghhsehlshhtrdgu
    vgdprhgtphhtthhopegurghkrheskhgvrhhnvghlrdhorhhgpdhrtghpthhtohepihhomh
    hmuheslhhishhtshdrlhhinhhugidruggvvh
X-ME-Proxy: <xmx:zpW9aESQOTluGcoqM_cunEP_CQ11Qvxrpy5aGTfr1MzqwvK2MTzWog>
    <xmx:zpW9aFHJqGCH6u0UWGJG3VtNOeC2T8wJ8cwxckTphVMd0qLeV964DA>
    <xmx:zpW9aNpr-peDJ1nPk1kSevLyeyufAy3XpVeJTpuplknDlKhO7wcF7A>
    <xmx:zpW9aLNxtTkNoAukVHmomnYFXm7ah-6QwcR2-dfdjXXF-bo6zSTB0A>
    <xmx:0ZW9aEVsvUTTHZprT5gFlKyXEiCBT6fpdOnxgCny8ixcqLiQ3QkTgVqI>
Feedback-ID: ie8e14432:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Sun,
 7 Sep 2025 10:25:11 -0400 (EDT)
Date: Sun, 7 Sep 2025 23:25:09 +0900
From: Takashi Sakamoto <o-takashi@sakamocchi.jp>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,	virtualization@lists.linux.dev,
 Will Deacon <will@kernel.org>,	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250907142509.GA507575@workstation.local>
Mail-Followup-To: Jason Gunthorpe <jgg@nvidia.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,	virtualization@lists.linux.dev,
 Will Deacon <will@kernel.org>,	xen-devel@lists.xenproject.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250905174324.GI616306@nvidia.com>
X-Original-Sender: o-takashi@sakamocchi.jp
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sakamocchi.jp header.s=fm1 header.b=LxAEL1hA;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=gkkyoHxl;       spf=pass
 (google.com: domain of o-takashi@sakamocchi.jp designates 103.168.172.154 as
 permitted sender) smtp.mailfrom=o-takashi@sakamocchi.jp;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=sakamocchi.jp
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

I'm a present maintainer of Linux FireWire subsystem, and recent years
have been working to modernize the subsystem.

On Fri, Sep 05, 2025 at 14:43:24PM -0300, Jason Gunthorpe wrote:
> There is only one user I found of alloc_pages:
>
> drivers/firewire/ohci.c:                ctx->pages[i] = dma_alloc_pages(dev, PAGE_SIZE, &dma_addr,
>
> And it deliberately uses page->private:
>
>		set_page_private(ctx->pages[i], dma_addr);
>
> So it is correct to use the struct page API.

I've already realized it, and it is in my TODO list to use modern
alternative APIs to replace it (but not yet). If you know some
candidates for this purpose, it is really helpful to accomplish it.


Regards

Takashi Sakamoto

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250907142509.GA507575%40workstation.local.
