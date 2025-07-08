Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBYETWTBQMGQE7HEFYMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FBF3AFCA12
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 14:06:59 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-74ce2491c0fsf6467094b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 05:06:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751976417; cv=pass;
        d=google.com; s=arc-20240605;
        b=NxnkN2KNFjnPKOWcKtZHxFOPjw0LcQtFoN+8TePZ13tZ6AAb7K8brheBLhu0Dxw6zX
         enmNqnNeAJveaRUY5mtS4d0xHYTdckLuWAgUFgKWbY1R7F+iKGv2ZBU9VMX4l3H5bKGc
         HG0KkIcDKxJH+Qh14fxpog1W21s4XQjAtAT45cyv8wqUht2yOcj16HdCzK3LgHJS1bwq
         oIFIiN1KofkyOPZcfaYnRh8KrjrN1xHp3N8IT2oFy2073w1R7xIR2Yns3cQ7tIIl0mQZ
         cNIvVjCD4vjfngJNTG0M35ubloFWG2suD1GEtPSnltvKjxXxyaAOovKjsqLLqxtu12Ek
         OK9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=OA0yk6nMTrp1M77NN/dkiwDy0DDRHQRsWFhYtGT60zo=;
        fh=X6QmD7ra2pz4l26ma4b56VVr2VjP2MF/hXgDmkaRNGo=;
        b=I8O5vx+SEH7/h5uGYzvo5owRbV8aEoOUf4D6biT/UjBk+IcTG/oAHdrqNsXLEPgT8w
         e47ValjRM9WZsCxz4g2WpIdU0ASp6BZRT+qweRoenR1Prk/nXnCBQVd7jSd1avMjPZd4
         VYeeK5KM7j0TS0n8nsrg/oP/Z6vFm+pfljLpCTCeZsaY80MJVxf2i8gf/Hc6LbJl1Oq1
         V7dS93U1m2uEa1vqQdUwa8m1hQ6yvMeaztj14j6bKtqFI2MX/cOCqewSRLZXBl1WK/is
         RJoMsyHvC4uyGWBxnOXnZtaHX1b0t/QK82khPAaU4hWu/pRdg05iId+3kfpW55i/c/tL
         nL7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s4Ol3iwJ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751976417; x=1752581217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=OA0yk6nMTrp1M77NN/dkiwDy0DDRHQRsWFhYtGT60zo=;
        b=JuoBzYNQGtkdkwqL81G27327JI0jxsy829284+vqHAzpBnhVX4Arq5IQc5MRQyU9JJ
         RFDQU+m9L8Qcqt3Bez85aYHtF1Zn07+rXdtFNQa20sHmL5laQ1DGxtRTeo1zilDiAqZl
         BdqkfKmT5FSElLvGPUShHUCi3uv/JUea2i10EXlH2HUbQ3CUZ9OWBSkZB7l30MWgKTPn
         iLyQaAOLsj/tqhtGuACbY4MhCuXqOytY3lfzSszsGxW0lpHPnkaS5eZs17Tk+bOzT8wc
         DI3kmj/iP0xWwmvYuv0mvPlOQEyqPYsY5BAMaIvpZo+j8EEKwE3Jv62hyC/kTQJ9pcsS
         mYxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751976417; x=1752581217;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OA0yk6nMTrp1M77NN/dkiwDy0DDRHQRsWFhYtGT60zo=;
        b=XzFhbOt4PGr1fFObao2I6KpEXYMzKnwTd8sFRACNsOjFbHGYXqpFm9zP329liPs9Cy
         Z/IB4F+QMH3U5rBDMY2e6am4G1gMYlvmp7XRTqlKnvXzq1dubWV37XBNniqm0E9twqYU
         RhdlSXV7HC4siRbnLTtdJvoBU7NDzgbDhwiLoEyY5Bcqw2aHz0DBunuPy7ogU5Y9biO2
         hNcQcg5PLqjZWNT/u1StLJCq1WbG8CuONHwFD75FwkDk1D9jSIUGUtXM5Es3ds9/NcEC
         wWFJDl2IRX0FXXMeLo1K1eAfJw9PMGVHtBL2JZdqj3oMMf8RZr89+EdtqHLNQ3z8LiDR
         P7WQ==
X-Forwarded-Encrypted: i=2; AJvYcCWMRSCYPGN6Uvjzz0qdKKamM1XEZQFbh5qHV4TlP5yinIzZEP5dpdcfsuiV5gCp1zpU+152VQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywd/Kfhid5efWgDAJ2McpV+yRHGjgnznsHio6AQNqowsZEDDJiE
	a2/DRY3lo9meNIaRs0YVfBScx+EiKrs1Z72Og055gWGyBGzRTTu+Kf6q
X-Google-Smtp-Source: AGHT+IHM0/h1QBwdtlhnUymiXOFUpt0rmPHopxg8bwOrVa/y3nonucKrtNr5wigfISE17IHm1SEEEg==
X-Received: by 2002:a05:6a00:bd93:b0:748:e772:f952 with SMTP id d2e1a72fcca58-74d249a681fmr3815460b3a.17.1751976417226;
        Tue, 08 Jul 2025 05:06:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZem8kORiSrNXar4T+stil2q3meTj5/i1djYFb0Bj1Qy1Q==
Received: by 2002:a05:6a00:a1f:b0:736:61f7:1482 with SMTP id
 d2e1a72fcca58-74ceb5e7390ls3764200b3a.0.-pod-prod-03-us; Tue, 08 Jul 2025
 05:06:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVm8O16H5ECzErYlaHMZC6PrOBiWNrF7bG9sCAmiDcOm5BDlaV2EvMAAfpTK+FuPAqEFMMOclgAV2c=@googlegroups.com
X-Received: by 2002:a05:6a00:84b:b0:748:e150:ac77 with SMTP id d2e1a72fcca58-74d249e55a4mr3797575b3a.22.1751976415253;
        Tue, 08 Jul 2025 05:06:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751976415; cv=none;
        d=google.com; s=arc-20240605;
        b=BEwT4a48vJBf3sVZv3fzIJGQYTgtEu7t5o/oAhkVmBveMOkWhrHV3bGMsJgcZDZqxF
         7y1gOTnlMz7dNW+iYywc8MQCO+vLgeSUSRIWnuGVPqbSeyg+2WBqFLQwpV5CkCLBFERW
         Sfq3zX3m9nxnySEW91tY1hu0uiZScyic/7t3YbbmoQR+l2mLMP/I8+qYuGVd7e+xqJEs
         NswA84I5ArkKgGnbadHmEp5Y6qGsIjYXfoq7wJEO2h58aBiI3QtixfdR2fxgx2Iv9KdE
         LWhWK9UER1ysGbRIR/QdrkO8CS1Rfk6mZ3g9uPRbf47/7LK7IAAMMUHF4/eUy/rJ8Us0
         VcNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=rViczFoCFQtwcNKraNBrnlXHpBXf2oyXrvi9VNukGlc=;
        fh=grh+l/l01Tfuw88bd6pzQP8VTuOQOiDQnVZvsS9R1x4=;
        b=iVRjD52XmbxA2wKOXCUY9Lq1AMtEmtECd8uaoGBSewUSO1N0z2SitUG4glp/VOimUX
         5FhiyJmc9TkBG32es1OK9CJVz6Fe5rmO0ueEFPt55b3T1qfd6g7wz8wq/9HKLR6uM6qz
         m+9HvAWxPeqnzqzTODGyvAf58G5AAz5J1dJVr2SU6aPuDkCt9g9O3mCI/Fb9uH/WsiJG
         U4AMpIjcXl99DbfuEAs2OCorsWHNfZWmssv5lkbhLhEOkX3HPPHvjPoqAm1W7FAixNqp
         28utTuBjKfmfLHUXU7InnB26txnAOTJVBXBuYzuofYlOm55o1B7Wsd7LJTsB8G7pfZxv
         e/IA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s4Ol3iwJ;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b38ee2aea68si722335a12.0.2025.07.08.05.06.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Jul 2025 05:06:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id F40AF61482;
	Tue,  8 Jul 2025 12:06:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0BD93C4CEED;
	Tue,  8 Jul 2025 12:06:53 +0000 (UTC)
Date: Tue, 8 Jul 2025 15:06:47 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>, Joerg Roedel <joro@8bytes.org>,
	Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org,
	Jason Gunthorpe <jgg@ziepe.ca>
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <20250708120647.GG592765@unreal>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
 <20250708110007.GF592765@unreal>
 <261f2417-78a9-45b8-bcec-7e36421a243c@samsung.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <261f2417-78a9-45b8-bcec-7e36421a243c@samsung.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=s4Ol3iwJ;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

On Tue, Jul 08, 2025 at 01:45:20PM +0200, Marek Szyprowski wrote:
> On 08.07.2025 13:00, Leon Romanovsky wrote:
> > On Tue, Jul 08, 2025 at 12:27:09PM +0200, Marek Szyprowski wrote:
> >> On 30.06.2025 15:38, Christoph Hellwig wrote:
> >>> On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
> >>>>> Thanks for this rework! I assume that the next step is to add map_p=
hys
> >>>>> callback also to the dma_map_ops and teach various dma-mapping prov=
iders
> >>>>> to use it to avoid more phys-to-page-to-phys conversions.
> >>>> Probably Christoph will say yes, however I personally don't see any
> >>>> benefit in this. Maybe I wrong here, but all existing .map_page()
> >>>> implementation platforms don't support p2p anyway. They won't benefi=
t
> >>>> from this such conversion.
> >>> I think that conversion should eventually happen, and rather sooner t=
han
> >>> later.
> >> Agreed.
> >>
> >> Applied patches 1-7 to my dma-mapping-next branch. Let me know if one
> >> needs a stable branch with it.
> > Thanks a lot, I don't think that stable branch is needed. Realistically
> > speaking, my VFIO DMA work won't be merged this cycle, We are in -rc5,
> > it is complete rewrite from RFC version and touches pci-p2p code (to
> > remove dependency on struct page) in addition to VFIO, so it will take
> > time.
> >
> > Regarding, last patch (hmm), it will be great if you can take it.
> > We didn't touch anything in hmm.c this cycle and have no plans to send =
PR.
> > It can safely go through your tree.
>=20
> Okay, then I would like to get an explicit ack from J=C3=A9r=C3=B4me for =
this.

Jerome is not active in HMM world for a long time already.
HMM tree is managed by us (RDMA) https://git.kernel.org/pub/scm/linux/kerne=
l/git/rdma/rdma.git/log/?h=3Dhmm
=E2=9E=9C  kernel git:(m/dmabuf-vfio) git log --merges mm/hmm.c
...
Pull HMM updates from Jason Gunthorpe:
...

https://web.git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/com=
mit/?id=3D58ba80c4740212c29a1cf9b48f588e60a7612209
+hmm		git	git://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma.git#hmm

We just never bothered to reflect current situation in MAINTAINERS file.

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250708120647.GG592765%40unreal.
