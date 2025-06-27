Return-Path: <kasan-dev+bncBDG6PF6SSYDRBL6A7LBAMGQE5EU6FXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 23962AEB925
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 15:44:20 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3a4fabcafecsf1050233f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 06:44:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751031857; cv=pass;
        d=google.com; s=arc-20240605;
        b=RQpSbKnPwILGHUI9B4S5YYjgyE9jLruUQfAZJ3iwDIV7Yqg1kfBRx9IN5Luin3GVJ1
         z1jIrPnxXQWA7BOMpwnLO2Snl8StYlgdUGVSkEWntz3elHVYYoTX0Yi8TY0W0ZR8brq4
         REoRQt1tjY0i4jUt6dhA6/yg4Xc98sPYpx+H0xJ6z5/31IsP6h/KzqTE9aU3wloqrobz
         uEGxiGAcIxpT8ewl0qcTzJz/T9jF4bKJTBdFJjDgJS9j7YXvN2JhjzFzgds4uwR/w4xA
         DGioCUSoLao7nY9f8T99D4op09y+X5Dqct4Q8JL6IdD6T0b5e42MnuOBLdvx6SnCxw4y
         WsPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=rUvWXu/y84kNDBe5oJXCg6w2AdhTJ7ZYEqO4T7mYzVE=;
        fh=pIX+uhr5qqJGn4t/cfso2UOfmL6SgXwdnH/hv7lf4Gg=;
        b=PWlt5KRpPk+q4L/P3a2dmW48MZAP3X0mmid4Ktj5CakQT16AIaJKEnEvKyf/VGb6+o
         iRYmU0S0qTZgVzTyoJ5cs8XXfEoZaYfXngqN/FJkbwnGPYQSOBbmCUUIP+Z9KXwAtzJv
         LFZBLA4efl/L8tSCVkfGLH7ByX8CXvx36io7jzkb6TMyxMylKRJu4UHFBPvKb0AfcCb+
         AwCs2sIiGMcMO+gYiXdhOUODEHVqlYUj2Nizm5LkBeTyYIMzs5ynSo0eF7KtehGxKjfF
         TPKkV/bdVlCi1HeteKBk0InK18yF/+wosShhzLz7LGNtEgaQs1nsodWO5ld69wF0fiDT
         QSmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=WhvmDKIT;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751031857; x=1751636657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rUvWXu/y84kNDBe5oJXCg6w2AdhTJ7ZYEqO4T7mYzVE=;
        b=vJFG9Z4EgHAnwKxJ4NC0/lNGft7LVj5TFugaOrOLwmyTRYb4kpdYrIH/z0FGKOCt/E
         VFHURtDtdfGTUlSzOJa6bRbr9B+3x7cDrrewLHDSsn5Vp/kQNt6dQZfHw+W7TJDWx+vK
         I4BAALju6L1O/HFD+UP31Yb7oeESk/JGP8QH7D59/1CT5hD216cZU7VU2qnJxzwMJ7JI
         AStVCvqZjxFy0UHo/RVQQ7LUVDKo8IxVgkyEBaFfWqsRIKcJxXCluhE/jpo26Pf1x6rk
         7zwTJTF96KAvT4vhZES7DiouWCmJJghawc9r2CarMmrWWqUpYGfqZ87JiZ16QrpGr9Ad
         me4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751031857; x=1751636657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rUvWXu/y84kNDBe5oJXCg6w2AdhTJ7ZYEqO4T7mYzVE=;
        b=Bivf2/J0XcCpGMTGYQQ0NyGsp4UBCoBi5dajJ/2zvzU0B7AjzzrZQ4DfGgHllPJXUg
         nZKEGZNonp2n0r87nBS3Bf0w+9lirYRyRNNGsI4boim8r2F40RqLzw7tgQiv4T5p1H67
         /B7V4XO8w4s7CIoTciHPmqNfRps/LBuezpf+7tpZxUYKSqss73WKcgwPIgvlxjpfYpmF
         b/Z4GvgdQabu2KNmzCyantXkNsgoxY+Y8DUGAGrPr6OtxRQpowzRkX9t/iITzwTWXziH
         2Uu01OnWAxrg4xEkxd5wTTGflBFadmdmGoOnh4LJj96X8VTTw6pvtmuew/+hqGoL6nQI
         /4Sg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXt5SMhSOFR21EtbbkwS9Texh9s+RnjXtJ7g5n+redqlynVJbmepAUQPeySB3zzEz1w7ZQeDw==@lfdr.de
X-Gm-Message-State: AOJu0YwoO6T8kWlMLAbGVl34nmxgwbjCXTuHHYrrlWx7RTN5UGlC4hfn
	bw2zb6Ow14wJPZPsgSATjwqpUVXOrza5HGmx8xRbn8PjV1G+U8KOdLlQ
X-Google-Smtp-Source: AGHT+IHrD2zVRCQ/EBFp4zMzGC5bMsV/wHRMJ7eKJhWgRf+w1RIMkQbZmGCxopEC8mGU+uBcwOg08Q==
X-Received: by 2002:a5d:5f55:0:b0:3a4:edf5:b942 with SMTP id ffacd0b85a97d-3a90b8c9779mr3684694f8f.57.1751031855969;
        Fri, 27 Jun 2025 06:44:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfQK13uXPtRNcXtSr3y3uohdwKY2dA5kEazqBWS9xwsoQ==
Received: by 2002:a05:6000:2905:b0:3a3:5e77:439d with SMTP id
 ffacd0b85a97d-3a6f328a8c8ls1029492f8f.2.-pod-prod-01-eu; Fri, 27 Jun 2025
 06:44:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQivTH90uEVZmjED5xDPcFR6uO50Wr3ec4jAHOTPssnag0RJLyhUSbe/fplUOO+PlHmrXAQXkbKVE=@googlegroups.com
X-Received: by 2002:adf:a150:0:b0:3a6:f2da:7fe5 with SMTP id ffacd0b85a97d-3a90b6df1c7mr2394361f8f.55.1751031853050;
        Fri, 27 Jun 2025 06:44:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751031853; cv=none;
        d=google.com; s=arc-20240605;
        b=kV0aYOuGeX5yoT4b1LyeQxac3wSHn9a6B7GF1Nu+l3XvKPIutGpSTIBNyg4/T9vz+P
         r3UWPs2v+5v9TjnxwB3ef/2EA+Ecu6ZdHwuCy/68ogsxQLD9p/XQe7bby5TMb1jQ0uee
         3mK7oTZMZfiIy4wskoY0N9c7HKY1FxnAiyZ3NPg1NQQgU0jlvfpO83bH9TUiWHsj0DMv
         ATvWOQb0mmx9zI/Iq8t2Qmq59xZzf5TfZJq5Uffpcupch5TYggtOhZaCD/Cp3btO9S9X
         1L+NzpQCo0yhIRSX+Qve5Bl5T7TpN6jg71VUus9hdJTTN/U9vZ+hNr7Rg66FjO1AuzEQ
         GNqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=XkLT3H6zpZxdqKr2mL/WBFZuhTWHNBcRcJJv1Mo/N0Y=;
        fh=t482abZ30FL9W5nP0QbFE8h85nSpVAld8hbHkKUygdc=;
        b=Yw3DD8Wm2l7OsAvwglWex8Aprty7by0psB8hY/EPUK2IhI7JFq1XuO5VXKHW8QT7JC
         JcwGq6gtASn9Rd0N4Gk242SKwT/iPTYNwdzeGyTHCbyS6y2rr73v7XYI/nB4wQOTOJag
         Q/BGbSVZQ69rq1GmjkCaiKQuBTqFmB+/GJVfoFL2toDlbjZka5tMiYD5t/uhaU4ZxMml
         EeCRf9l4X/vnEQk4TuhMzU1thywiQ5MW1rjR7EYo2xDhOEmjq3U62TPVCABw7S6ZzJLI
         QjXx8zykQdHOjSlGZEK9Dmh056mu6JOUJixwHSfhBzRGm65x4Tr/n+3mU7cuEXsP59YE
         w+QA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=WhvmDKIT;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a88c80e014si151237f8f.1.2025.06.27.06.44.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 27 Jun 2025 06:44:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250627134412euoutp01e60564ff7ed6ad6bbc42d2985678c16a~M6jFUba2R0614706147euoutp01k
	for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 13:44:12 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250627134412euoutp01e60564ff7ed6ad6bbc42d2985678c16a~M6jFUba2R0614706147euoutp01k
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250627134412eucas1p153bc3e4a1c0897bca604e6864667b66d~M6jEutC8v1155611556eucas1p1O;
	Fri, 27 Jun 2025 13:44:12 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250627134410eusmtip109d5d74275daabf2f21b42eb7440b88b~M6jDFXzcn2675526755eusmtip1I;
	Fri, 27 Jun 2025 13:44:10 +0000 (GMT)
Message-ID: <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
Date: Fri, 27 Jun 2025 15:44:10 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
To: Leon Romanovsky <leon@kernel.org>
Cc: Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Robin Murphy <robin.murphy@arm.com>, Joerg
	Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>, "Michael S.
	Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, Xuan Zhuo
 <xuanzhuo@linux.alibaba.com>, =?UTF-8?Q?Eugenio_P=C3=A9rez?=
 <eperezma@redhat.com>, Alexander Potapenko <glider@google.com>, Marco Elver
 <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Masami Hiramatsu
 <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 =?UTF-8?B?SsOpcsO0bWUgR2xpc3Nl?= <jglisse@redhat.com>, Andrew Morton
 <akpm@linux-foundation.org>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 iommu@lists.linux.dev, virtualization@lists.linux.dev,
 kasan-dev@googlegroups.com, linux-trace-kernel@vger.kernel.org,
 linux-mm@kvack.org, Jason Gunthorpe <jgg@ziepe.ca>
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <cover.1750854543.git.leon@kernel.org>
X-CMS-MailID: 20250627134412eucas1p153bc3e4a1c0897bca604e6864667b66d
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
X-EPHeader: CA
X-CMS-RootMailID: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
	<cover.1750854543.git.leon@kernel.org>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=WhvmDKIT;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as
 permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;       dmarc=pass
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

On 25.06.2025 15:18, Leon Romanovsky wrote:
> This series refactors the DMA mapping to use physical addresses
> as the primary interface instead of page+offset parameters. This
> change aligns the DMA API with the underlying hardware reality where
> DMA operations work with physical addresses, not page structures.
>
> The series consists of 8 patches that progressively convert the DMA
> mapping infrastructure from page-based to physical address-based APIs:
>
> The series maintains backward compatibility by keeping the old
> page-based API as wrapper functions around the new physical
> address-based implementations.

Thanks for this rework! I assume that the next step is to add map_phys 
callback also to the dma_map_ops and teach various dma-mapping providers 
to use it to avoid more phys-to-page-to-phys conversions.

I only wonder if this newly introduced dma_map_phys()/dma_unmap_phys() 
API is also suitable for the recently discussed PCI P2P DMA? While 
adding a new API maybe we should take this into account? My main concern 
is the lack of the source phys addr passed to the dma_unmap_phys() 
function and I'm aware that this might complicate a bit code conversion 
from old dma_map/unmap_page() API.

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/35df6f2a-0010-41fe-b490-f52693fe4778%40samsung.com.
