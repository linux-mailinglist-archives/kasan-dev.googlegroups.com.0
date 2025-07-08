Return-Path: <kasan-dev+bncBDG6PF6SSYDRBWEJWTBQMGQETHWIN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C595EAFC9D0
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 13:45:29 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-553b5884201sf2129789e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 04:45:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751975129; cv=pass;
        d=google.com; s=arc-20240605;
        b=K3i++bg/yD+o1P9VVhll/lORmXrk0XAhNqWE/xTXX0Wyz4vsijR/S9HQDA7a7E/yjy
         2E/g8g2mSg9yLlrBm5fiTW1QqXytmsaXAgAQlWco/fPxKYSx/WdDzHGQ3yehoNRPWpJw
         MBOCl+DRw9ihihvj8bzxGcYnevYY/g74dWuAHDQ9jUI4w0fMB4Jv0OAy+kUzuRR2+lKE
         AoNV2VCMkv25ZKGuKxnnJQZOWokrRwd1AGlJRohaJvn+zP5t6/h6ggWXLwC+n0TRvAbv
         pJrIyMYTLgguVOWqd3NU1gL0tHAKds9p6yAd75ZBrigGD2U0EaFRldxyrvONkMFL87zQ
         FO+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter:sender
         :dkim-signature;
        bh=uKugO34P9RLWmG/OjbmNXWReGZc3xg0A1FDM46jiXd0=;
        fh=8RwRTBMt1BJRHXzVlVpMeQnVHe8I6oH90VM2t2QCS00=;
        b=ScOxQkjZ642MUjDaPX3LdeLY0/CYOOJMA369Bo42F/dh2jZ304YHsnr1gRAxSiR2zY
         hcsUO7RXL094rsC5b2Bew1H5WXBRVSZ5KT83+jrpVxt9gGCWKEu4rCjre0Xy61lOVbxG
         S0o7tHqJesCnc5SOBjmVADZzde8h9s6N6sZyzraMi077bYhIDxkfQ/m0xaUUOT46ABrl
         i0XwrOVyYUkwKF5CMePR+ew4KlhYtCoz/zBzzyPI144bns7DR2OJgCnkuVuoi55bOLeV
         11ZswYDEi09HwFJptArCZyKxKbSMkLs+5U5XWqC6ehin+WDIsC8tH5fVGj7VjER/SKrz
         m6Aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=hTSmuD7o;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751975129; x=1752579929; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:content-transfer-encoding:in-reply-to
         :from:content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uKugO34P9RLWmG/OjbmNXWReGZc3xg0A1FDM46jiXd0=;
        b=s+Tb0dWJxB73rtKiYXEmoC8hLmGmQMJ1Oshz5n2z5LnPeotycABEQmYCKBFNQfLaTN
         UeylMlINZ3a7zl5z8qiGVOUwsUGtl6+Bqs5ziMK9XmjPuZ9VWwSLX0oi/rU1E4FGKTcl
         zvHqf7JZ+evGYRDT7VauUcn4Ve4y6mjrIxY1kubzJQodxH9xmb5GERMTo7HQjRSuS4+t
         QG4Hao3tkxZWKJ4Wt+sg18N/707tNIINF7zBhUoC63M8BHbFeTy+L5kVZxfo/TVc63iP
         9w4+tsfR5IRL0f5O59biVd6XCY9LrAruDJoK9E/520h62Nei1ZBfu/hKBwkIJvlhhrCc
         aNrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751975129; x=1752579929;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uKugO34P9RLWmG/OjbmNXWReGZc3xg0A1FDM46jiXd0=;
        b=MsA7LWKgyu+oMDrRbd01AG7+trtQamXmwbH+8FvPkusPzjmPI/YEfBa+SdvVqDuWJ6
         O81vicfDO8RDzyltPJf2gOkT4OjH2yaJZH69v/ONWcxJQAiENI7FZsdv2C5r46DDQRkI
         EN/M6h19BKPUyOtzhmgBRzyWZYl+VpZ1ewsO4Haj9JBi8wOeeaxq8gOzwvTICio1zUCd
         N6gA3Rkt0xOlggwge5uNMXeT+GRG2UO9IgpBDLrxDjJ1Wv5s6M3ioSaz6SJTn1poU9+Z
         P5tCf85s0W1PB3+d1k1hvdCyoAu/1kQjCTToTTy1hN/hdkh+T97s7XhuMXv1Q9XPgxY8
         pzag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU23/DNrp9zrzO5x64ftb1GjXkCZ46zeeRc3rVFVIJ6rpVlqrkirahK8VVlCg+DFzh59QSPSw==@lfdr.de
X-Gm-Message-State: AOJu0YwRDjvmGGxAYbOe+GJh8ivBnOCGYngfvLGbhXMNsASRC3Zz89B6
	/6B5XQWkyrCBB0IfzhBSFFR9UvEWImUpX4MlI0iLfxwoEjC9wZKzZGst
X-Google-Smtp-Source: AGHT+IG9WaBeWhbNgAuVgucnPZJ06cWyS3b6AfXLY+4Y0nxuqr4w0OFoZh2SIE2yfXp145vrhux4SA==
X-Received: by 2002:a05:6512:1101:b0:553:341f:12a3 with SMTP id 2adb3069b0e04-556ddb9641cmr4520143e87.39.1751975128658;
        Tue, 08 Jul 2025 04:45:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfZq5THaupZKZhXqChXirZX/q73CDTFtHUlzLbNP2iVqQ==
Received: by 2002:a05:6512:6406:b0:550:e048:74ff with SMTP id
 2adb3069b0e04-557cf739fb5ls1050930e87.0.-pod-prod-06-eu; Tue, 08 Jul 2025
 04:45:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWDSMbpwo9kWG+/lHJRiIsRXwTUlzKHWJyaovFniWS/OA9VwhqKsVHU/lXBioOfQfsym/7PpfyosNs=@googlegroups.com
X-Received: by 2002:a05:6512:3186:b0:554:e7f2:d759 with SMTP id 2adb3069b0e04-556dd6bbaabmr4645239e87.28.1751975125864;
        Tue, 08 Jul 2025 04:45:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751975125; cv=none;
        d=google.com; s=arc-20240605;
        b=aBkhqzedLPhNyEcGZSXE03bOQYFoSs2oNvA1c/MEPESvw9ywSKXR9E69ndgsfxJ75x
         rr5ANGQ5hRg8u3QgoDIT3xOnbTawiKGVmqSY0fKAs0C+rnmTvHhf1iNhlNjUITw7duZC
         Oh47M0UuSV6dzZ9CuShDgmRht/Ib2eImQJDZj6h8zOPwRWG4d9Wkq8iUxI9W/HphouUp
         +qmohre4vDRo26bUU7Kbgqt9E/QQMtyoGZfkQG+bg7ZRBmq6hNuEvKrK/Tci2389b6G7
         TIh3CDPj4+CXAKt1riWN7Ewq0wEeR3x0/KOqRnyEM+MuzH6HLY1GtkK0d0jHZyj60fVK
         gfOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=1ym+ZPwSAJBlUJTRBRpHOrnxcWfoWCspHKNp3aF96Zc=;
        fh=t482abZ30FL9W5nP0QbFE8h85nSpVAld8hbHkKUygdc=;
        b=fgB3E1l5EXn+9voKbEXWetCPdM4Vk+TilZ9vvtJPvKXIsCRa/eBHpohdQGAmdlqmK8
         2emoSCy0W4rfaekTcKSFjOS3RCrTVdt007u5J6Dki3y6g6AA58uo5XfYY06jKGpUwmD5
         uWb0x4fMGY7M/JZ1ogtyUJW0O+UsUwwHjPgx7ZAQ8rraUx1oEorJ+3e7Qq6IhPaVAt1U
         Nl1OO1XnEJ1ylPzLcXyR7yvY6dBPpUx1Eu9GpO5BtfRzKCyqfFhIzLpDZhLeuekWOizH
         XaVZamf+WlJZYUgab/WnaWD+q9VVYKMEOvWbH/ndqhIjDgTxXtVIiS0ocMDAknw2DyXD
         JsTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=hTSmuD7o;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-556f597f74fsi219056e87.11.2025.07.08.04.45.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Jul 2025 04:45:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p1.samsung.com (unknown [182.198.249.206])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250708114524euoutp010ae64b598e52525bf01b0021244245d1~QRBfXtleD2349923499euoutp01j
	for <kasan-dev@googlegroups.com>; Tue,  8 Jul 2025 11:45:24 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250708114524euoutp010ae64b598e52525bf01b0021244245d1~QRBfXtleD2349923499euoutp01j
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20250708114523eucas1p2d8771c6a0d017b9bb67a6528e7582617~QRBe5i9Re1494914949eucas1p2S;
	Tue,  8 Jul 2025 11:45:23 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250708114521eusmtip2651e660db53304d0ed855a7d7f6ea665~QRBcy78Hv2034520345eusmtip2O;
	Tue,  8 Jul 2025 11:45:21 +0000 (GMT)
Message-ID: <261f2417-78a9-45b8-bcec-7e36421a243c@samsung.com>
Date: Tue, 8 Jul 2025 13:45:20 +0200
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
In-Reply-To: <20250708110007.GF592765@unreal>
Content-Transfer-Encoding: quoted-printable
X-CMS-MailID: 20250708114523eucas1p2d8771c6a0d017b9bb67a6528e7582617
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
X-EPHeader: CA
X-CMS-RootMailID: 20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
	<cover.1750854543.git.leon@kernel.org>
	<35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
	<20250627170213.GL17401@unreal> <20250630133839.GA26981@lst.de>
	<69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
	<20250708110007.GF592765@unreal>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=hTSmuD7o;       spf=pass
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

On 08.07.2025 13:00, Leon Romanovsky wrote:
> On Tue, Jul 08, 2025 at 12:27:09PM +0200, Marek Szyprowski wrote:
>> On 30.06.2025 15:38, Christoph Hellwig wrote:
>>> On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
>>>>> Thanks for this rework! I assume that the next step is to add map_phy=
s
>>>>> callback also to the dma_map_ops and teach various dma-mapping provid=
ers
>>>>> to use it to avoid more phys-to-page-to-phys conversions.
>>>> Probably Christoph will say yes, however I personally don't see any
>>>> benefit in this. Maybe I wrong here, but all existing .map_page()
>>>> implementation platforms don't support p2p anyway. They won't benefit
>>>> from this such conversion.
>>> I think that conversion should eventually happen, and rather sooner tha=
n
>>> later.
>> Agreed.
>>
>> Applied patches 1-7 to my dma-mapping-next branch. Let me know if one
>> needs a stable branch with it.
> Thanks a lot, I don't think that stable branch is needed. Realistically
> speaking, my VFIO DMA work won't be merged this cycle, We are in -rc5,
> it is complete rewrite from RFC version and touches pci-p2p code (to
> remove dependency on struct page) in addition to VFIO, so it will take
> time.
>
> Regarding, last patch (hmm), it will be great if you can take it.
> We didn't touch anything in hmm.c this cycle and have no plans to send PR=
.
> It can safely go through your tree.

Okay, then I would like to get an explicit ack from J=C3=A9r=C3=B4me for th=
is.

>> Leon, it would be great if You could also prepare an incremental patch
>> adding map_phys callback to the dma_maps_ops, so the individual
>> arch-specific dma-mapping providers can be then converted (or simplified
>> in many cases) too.
> Sure, will do.

Thanks!

Best regards
--=20
Marek Szyprowski, PhD
Samsung R&D Institute Poland

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
61f2417-78a9-45b8-bcec-7e36421a243c%40samsung.com.
