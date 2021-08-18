Return-Path: <kasan-dev+bncBDN6TT4BRQPRBPXX6KEAMGQERBCULUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B08C3EFE31
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 09:50:23 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id l14-20020a67ba0e0000b02902c10effe47fsf301444vsn.17
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 00:50:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629273022; cv=pass;
        d=google.com; s=arc-20160816;
        b=yUuvnJINu5r2pZNYKgZ9TtkJTNCLaF8NcP94MKx9H/1gnYIxjCrILc28XADrOb7WFL
         ZFvVOhDtYM6PJ3xsSl0KRhADzHPGCZleLm4SOquhoNosXk9rKBQvox4t+7I8uPWSKDUX
         5/ygqX3Y0Yl44RHlv6cBaQFyi7tx82QyUAAPlWkNT5xtJgwIifaFkbVBcXEW0emTyHZq
         9cd3oYHk5KbM6pzm3p35L4BJl50yTSUW40Ffp+OLchKiIbeo3M4Q1hVdNvtUkIb/prZJ
         PIMuMi+ymZasgSGMGN2y9KYHI+GULsVt9RS1blaUTi6ucCI1Ynr0p/ofO51je4vASYBQ
         wCMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type:message-id:date
         :subject:cc:to:from:dkim-filter:mime-version:sender:dkim-signature;
        bh=gMqc0upsKZIAXVbbsm+q1woGdOaoW81R7EWTDTHwY7I=;
        b=bfroSwL1UzOu4YJnjutDyqYKygspYLOTh/gDDsyq00BlB4tOfQwhwwvt8zQnwDoTvK
         GoG3fqDywmHyjOy6bXdiTbV6djSs6QnZtbCeywh47HR2Pfs7O2G+tgEZtk0k0zyp6c+9
         hOwn4WzUQs5h+AmC0dZFlzhbPHDzNVxPiLBwSXwzl5zPE7KMN2F/rFYZL70AbW3fCSuM
         3dzrinSBgdLxUsMCEJeOTBUJQ2LhulGiBCYaOaGkqfd0Zp4qXt2cSttZ/FGQh0MU99VT
         HmbdNUzZ7QQfIq+LFfqghenEI8eSdV/830CdFK24nFAsqdrXUvVwGxECxyEIZYG44qEn
         BPWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=indZTeAG;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:dkim-filter:from:to:cc:subject:date:message-id
         :cms-type:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gMqc0upsKZIAXVbbsm+q1woGdOaoW81R7EWTDTHwY7I=;
        b=RXTk2Ea0tsQ8PFiZm6NUbfvtqxR28gE4SP6b2hpMZVdd7ALd7JU73N4b7zSjfObOfI
         q15eK0917Dzb3naN+c4TpHcPOLhZp3iBFIFvpJTSySJeQ8SVBP6hz9yVyU0rv5zQlw5l
         646nBmzyhMh9qVIEFOfCAg/vueXIHwHvTUw3LPF2grCW1gv3qCM2dtNQ0M6+jkdLB4q6
         znaEsrRJF8XV+fUuyiokeL/7TOt1UwUy1vilFjQ2MsGbtFDw9EOyAN4VibmHP6M25b3O
         Y+xEhH7rabSc5vQ2zmeDK4QZNnucYnWOt3sU1gygfSGR+H5O9zOpQ9l9YSlBZCUprow+
         xs1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:dkim-filter:from:to:cc
         :subject:date:message-id:cms-type:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gMqc0upsKZIAXVbbsm+q1woGdOaoW81R7EWTDTHwY7I=;
        b=ejK5p1wphcmmwBNLUs61r2rY/Bx2m9R6quukgiRW+Pao1PlqtzNIlSuu2qFXM7BQ8E
         7AMUUcvik5hGat7ttijYS9j8J5WRjHqMEeYYIzZuW5Qq+LyOocjZh1FPgLyZKiL6NsLQ
         wtShlRrNcMuFx5wtdY/komhiJMxtLsv0vThFrfvJWgjzc1h8AOcNrMpSJmvbOZddZZL+
         WbLWL+52vD8+qaJBG01VK6R/TUYUSUn9vTfxOJsA0PxUwNiip/TsrGkbnQx1ZfdrR+hR
         xzU7BaOYlud3jd3Pgh5xt9gqGD6gIchnvMZH4OIXmcx2ZSoV8fcmQoO3hBAwm6M1Afmy
         3aqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zCvBn+mkJ76RrnpUR2BkdHkt23s5jqK0d+4LBJ5c+PJlsBnd1
	9d5oIdQldnoa9UwP8pRpyB8=
X-Google-Smtp-Source: ABdhPJzXWvg9SL0FJlgulVnfzfYKiRw78uuwrEbdFdljSmUea3WKPpMo0vWqMzotBJUCpcqWqIgB0w==
X-Received: by 2002:a1f:3213:: with SMTP id y19mr5874248vky.13.1629273022343;
        Wed, 18 Aug 2021 00:50:22 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ac0b:: with SMTP id v11ls189025vse.6.gmail; Wed, 18 Aug
 2021 00:50:21 -0700 (PDT)
X-Received: by 2002:a67:f551:: with SMTP id z17mr6373770vsn.17.1629273021863;
        Wed, 18 Aug 2021 00:50:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629273021; cv=none;
        d=google.com; s=arc-20160816;
        b=cCBaqiVWbsIs80/zP/l9QCrlxBQ4ROgJQKcXRUzhnGqWg45chhMBHY8yt7WQQB2TuW
         LXwo00UVSCQWJXLswPyrkfnkrtkV3/niZ5mIU3fSL5yEAOtpxPKcgtNGOyo9eGyI2aXC
         igCYY3YY/2kAlbBB1ZtDJHnE82PT2h3flfP1Ngc9P6FY8Wuk5L52uGoLHpD4rDWYFPUK
         knjbcwPzz1xPtTMBnjgTKwLEFIFU/hsqoH70FEH5Y6pASxDdb4WoJydHQwRA2/0Acswv
         K/5J64YpwNP1eRTiYV3h2NRXXySR+pKMSFSPcAwiEF3aR52MAca+1eW6rLaPvt9okFEz
         nppg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:message-id:date:subject:cc:to:from
         :dkim-signature:dkim-filter;
        bh=M9QkWflZWhzJ8C4UH0KXV/Xs5kR42oPIJsd+pOc8ukY=;
        b=W0QRJ8vfmvowYx0mSwYnoyEB6KOZYBjqjszs0EhGqYy/1t2Aiv16ImsW5RpCTn2kYR
         tgOXTY5e+CW1hWxzQLjXOUG/7snOaaj/bwFAE+vlEk9Vxigdnoj1YAa/BS+Y3c2sUsxx
         KT8FkRziwQRnoYFIQzqmlLH0z7Qobr8UGT1XO7I0DVMXFNjotNzq1pk+YzbqbNgwZEQA
         cXskHSZVb6aoSftmpq3lsgejrU/RDSUTk6w0QNQITZJ9xihP5uBbXKMrj/x5eq/C2PWr
         TTHyzMyJCMKq1MFhYfmIvjSoeG3DD3CJ6+Yu1u7nLm9YJKFWuMnphywutpUaYPAdvYWR
         +bag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=indZTeAG;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.samsung.com (mailout2.samsung.com. [203.254.224.25])
        by gmr-mx.google.com with ESMTPS id z25si348291uae.0.2021.08.18.00.50.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 Aug 2021 00:50:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) client-ip=203.254.224.25;
Received: from epcas5p4.samsung.com (unknown [182.195.41.42])
	by mailout2.samsung.com (KnoxPortal) with ESMTP id 20210818075018epoutp0245efd49eaeb28a22d387eef33f30d532~cVy2ipOSA0819108191epoutp02U
	for <kasan-dev@googlegroups.com>; Wed, 18 Aug 2021 07:50:18 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.samsung.com 20210818075018epoutp0245efd49eaeb28a22d387eef33f30d532~cVy2ipOSA0819108191epoutp02U
Received: from epsmges5p1new.samsung.com (unknown [182.195.42.73]) by
	epcas5p1.samsung.com (KnoxPortal) with ESMTP id
	20210818075017epcas5p17c8978ebda5ba5e27ed6b8d0d0b8f7af~cVy1cbJkX0231402314epcas5p1q;
	Wed, 18 Aug 2021 07:50:17 +0000 (GMT)
Received: from epcas5p2.samsung.com ( [182.195.41.40]) by
	epsmges5p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	37.4F.40257.9BBBC116; Wed, 18 Aug 2021 16:50:17 +0900 (KST)
Received: from epsmtrp2.samsung.com (unknown [182.195.40.14]) by
	epcas5p4.samsung.com (KnoxPortal) with ESMTPA id
	20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a~cVU7kK0KC2682326823epcas5p4w;
	Wed, 18 Aug 2021 07:16:02 +0000 (GMT)
Received: from epsmgms1p1new.samsung.com (unknown [182.195.42.41]) by
	epsmtrp2.samsung.com (KnoxPortal) with ESMTP id
	20210818071602epsmtrp24cf8c22343093d9852b6140df47a26fc~cVU7jB2ba0816408164epsmtrp2D;
	Wed, 18 Aug 2021 07:16:02 +0000 (GMT)
X-AuditID: b6c32a49-ed1ff70000019d41-ae-611cbbb9017f
Received: from epsmtip2.samsung.com ( [182.195.34.31]) by
	epsmgms1p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	D0.EF.08394.2B3BC116; Wed, 18 Aug 2021 16:16:02 +0900 (KST)
Received: from localhost.localdomain (unknown [107.109.224.44]) by
	epsmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210818071559epsmtip2108c951d98b4365cb1f7f4385e4d91b9~cVU4xyQ8L2341823418epsmtip2g;
	Wed, 18 Aug 2021 07:15:59 +0000 (GMT)
From: Maninder Singh <maninder1.s@samsung.com>
To: linux@armlinux.org.uk, catalin.marinas@arm.com, will@kernel.org,
	mark.rutland@arm.com, joey.gouly@arm.com, maz@kernel.org, pcc@google.com,
	amit.kachhap@arm.com, ryabinin.a.a@gmail.com, dvyukov@google.com,
	akpm@linux-foundation.org
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, v.narang@samsung.com, a.sahrawat@samsung.com,
	Maninder Singh <maninder1.s@samsung.com>
Subject: [PATCH 1/1] exception/stackdepot: add irqentry section in case of
 STACKDEPOT
Date: Wed, 18 Aug 2021 12:45:43 +0530
Message-Id: <1629270943-9304-1-git-send-email-maninder1.s@samsung.com>
X-Mailer: git-send-email 2.7.4
X-Brightmail-Tracker: H4sIAAAAAAAAA0VSe0gTYQDnu7vdzsXqXKO+pvawh2XlNIo+InuA5SlJIVHR+6hrWm6tnZb2
	oKUhbWmltkw3a5RZmaZNM6cZNK1lgihDl6TZw8rsoaYE0ZPtFv33e36/j4+PwmVWkYJK1CRz
	Og2bFExKiJrGObPn2+sD2XDbmSDUXs8hS0UZic4P1YrQYEkWQOdeZYrRaEYmhm6868WQ7U2n
	CLnqLCRymBoAarycSaBr7nYM2S3NInS2200i591qHDmaiwA62b1ohT9TdqkMMK7OdpyxF/aI
	Gasthbmf00wytlIDyTy5+INgqoqPM2eqSwEzYpu8TrJZsnQ3l5R4kNMpl+2UJDQ97QTadFlq
	/s3XhB44xhkBRUF6Iaz8mWgEEkpG1wNY8d0lFshXAPMeP8MF8g3AwZJfpBH4eRvWd899qQYA
	TZZWTCCjAPab33pTJB0GS+vuEx5DTg8BWNWR763g9AMAWzuyCM/6eHojbBse64EEPRMWte3w
	dKX0avjh0x3f2mTY1WrwXgPSBRT83ZiLC0YUbHp42hcaDwec1WIBK+DIlwZSKJwGsMDi8rVv
	AWjrd4uE1HL4MUOPeZZxeg6sqFMKchA0Pb2NeTBOj4XZP/owQZfC2kv/8Ex4sqvSd0wAHBke
	JoSXZGBx+VSPLKO3wRfXW/FzIKjw/4AVgFIwidPyahXHL9JGaLhDYTyr5lM0qrBd+9U24P1E
	oTG1oOflUJgDYBRwAEjhwXJpCKVgZdLdbNphTrd/hy4lieMdIIAigidKt64JYGW0ik3m9nGc
	ltP9czHKT6HHTkUc4DRRI9NLTmXlhBwtezxpU3Fm/uifUVVC4DaNfZ3+WJ9se/c0oonLvVpw
	wvy+Rx89EBVdGN8sl1cuaVrb8Ssj9Y2Z35iurHrSVs7Me+vMXlpDy78n14ZevqvckHpt3gmD
	n3igKHBqlDaSiF7fG3NvS3F15Hbj4T0riwL0ufZdg4trutdfeWg5Juo/b9gZHyo2m6pU6avi
	yseZxnxu6ZOvWTBsVF44qOCPA1H6hNyQyL603ot5sRPqugYfPQo35RjytWm80xo9d6vFFZv6
	U6qehW7GO6e4pTcOzVDHvTC/8l+9MLztyBQYsznlSvjyxg8W+/S97uwWDi3Tt/CbYoMJPoGN
	CMV1PPsXZhRjELMDAAA=
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrGLMWRmVeSWpSXmKPExsWy7bCSvO6mzTKJBjNOS1lc3J1qMWf9GjaL
	KR92sFq8X9bDaDHhYRu7xZfmNiaLFc/uM1lsenyN1eLyrjlsFoem7mW0ODy/jcVi6fWLTBY7
	55xktei/c53N4vjWLcwWh07OZbRouWPqIOixZt4aRo/L1y4ye+ycdZfdY8GmUo89E0+yeWxa
	1cnmcWLGbxaPzUvqPfq2rGL0+LxJLoArissmJTUnsyy1SN8ugSvjyKlrjAVNQhXTVz5iaWA8
	xN/FyMkhIWAiseDZbXYQW0hgN6PEtWYriLi0xM9/71kgbGGJlf+eA9VwAdV8YpQ48a0VLMEm
	oCexatceFpCEiMA/RokzR+YzgzjMAkcYJa5sP8kGUiUsECox59Rrxi5GDg4WAVWJuRfiQcK8
	Am4SL99sZIPYICdx81wn8wRGngWMDKsYJVMLinPTc4sNCwzzUsv1ihNzi0vz0vWS83M3MYKD
	WktzB+P2VR/0DjEycTAeYpTgYFYS4VXnkEoU4k1JrKxKLcqPLyrNSS0+xCjNwaIkznuh62S8
	kEB6YklqdmpqQWoRTJaJg1OqgWlVRuv2kHl12zn2rvViu7Jk3hN1nyfnb4o9uV2Xnn7vn3TI
	NDmt5Y+rfgs4bjh+NTf/qsTXNyxNamdOb7xkJWpzcKc1a++RU5PjPa1N26ecPffOhPVNULlL
	Ia+YlclXyS8uOl+kVJ7oMbdODkph53zjxXdlomrM0v6/r2qrSrf7yH82Y7ZZIrIm+sH7bpdO
	BsFNFhpTjwby9L2alpDsP3dNaYxguufMOxMyF0XeDw8+xVqyqG/yv5dsxR8ccn1zHZp8tWVb
	P8sIz664wpHIufXAkq7rCkwN3pqrW8pYX4m/Obvg898jHkdO+Xk23q/Qn8vcZdZwmYer02SR
	6Mq1S865mdXYfN/OXHRnF0NurBJLcUaioRZzUXEiAO+3Lu7ZAgAA
X-CMS-MailID: 20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-Sendblock-Type: REQ_APPROVE
CMS-TYPE: 105P
X-CMS-RootMailID: 20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a
References: <CGME20210818071602epcas5p4fecf459638312c95c5d5aaa29e7e983a@epcas5p4.samsung.com>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=indZTeAG;       spf=pass
 (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as
 permitted sender) smtp.mailfrom=maninder1.s@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

As of now if CONFIG_FUNCTION_GRAPH_TRACER is disabled some functions
like gic_handle_irq will not be added in irqentry text section.

which leads to adding more stacks in stackdepot as frames below IRQ
will not be filtered with filter_irq_stack() function.

checked with debug interface for satckdepot:
https://lkml.org/lkml/2017/11/22/242

e.g. (ARM)
stack count 23188 backtrace
 prep_new_page+0x14c/0x160
 get_page_from_freelist+0x1258/0x1350
...
 __handle_domain_irq+0x1ac/0x4ac
 gic_handle_irq+0x44/0x80
 __irq_svc+0x5c/0x98
 __slab_alloc.constprop.0+0x84/0xac
 __kmalloc+0x31c/0x340
 sf_malloc+0x14/0x18

and for same _irq_svc there were 25000 calls which was causing
memory pressure of 2MB more on satckdepot, which will keep increasing.

Before patch memory consumption on ARM target after 2 hours:
Memory consumed by Stackdepot:3600 KB

After change:
============
Memory consumed by Stackdepot:1744 KB

 prep_new_page+0x14c/0x160
 get_page_from_freelist+0x2e4/0x1350
...
 __handle_domain_irq+0x1ac/0x4ac
 gic_handle_irq+0x44/0x80

^^^^^ no frames below this.

Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
Signed-off-by: Vaneet Narang <v.narang@samsung.com>
---
 arch/arm/include/asm/exception.h   | 2 +-
 arch/arm64/include/asm/exception.h | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/arm/include/asm/exception.h b/arch/arm/include/asm/exception.h
index 58e039a851af..3f4534cccc0f 100644
--- a/arch/arm/include/asm/exception.h
+++ b/arch/arm/include/asm/exception.h
@@ -10,7 +10,7 @@
 
 #include <linux/interrupt.h>
 
-#ifdef CONFIG_FUNCTION_GRAPH_TRACER
+#if defined(CONFIG_FUNCTION_GRAPH_TRACER) || defined(CONFIG_STACKDEPOT)
 #define __exception_irq_entry	__irq_entry
 #else
 #define __exception_irq_entry
diff --git a/arch/arm64/include/asm/exception.h b/arch/arm64/include/asm/exception.h
index 339477dca551..ef2581b63405 100644
--- a/arch/arm64/include/asm/exception.h
+++ b/arch/arm64/include/asm/exception.h
@@ -13,7 +13,7 @@
 
 #include <linux/interrupt.h>
 
-#ifdef CONFIG_FUNCTION_GRAPH_TRACER
+#if defined(CONFIG_FUNCTION_GRAPH_TRACER) || defined(CONFIG_STACKDEPOT)
 #define __exception_irq_entry	__irq_entry
 #else
 #define __exception_irq_entry	__kprobes
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1629270943-9304-1-git-send-email-maninder1.s%40samsung.com.
