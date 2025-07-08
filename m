Return-Path: <kasan-dev+bncBDG6PF6SSYDRB7VKWTBQMGQEGBT3UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A8AD4AFCB0B
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 14:56:32 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-32b2de6033bsf26166931fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 05:56:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751979392; cv=pass;
        d=google.com; s=arc-20240605;
        b=CQiM2DpjsE3gxUBaNhdp09WWyzd8DRRMgfpONJyTwUgHgx1uObGivXQBzErUvTKu8S
         UdTmTjAXVuaFcyRNJ8ygtTmga1kUPnLj3xzqH9ljbjZ/AsbCoIZwx56xAB34ff5JEmkF
         s8XuyRgjuukdPXTAtsI/L1Sq9Vpy03XW1ZwftPQrMNmv6+58rPk0BGPJAuvOB3WQjopU
         M9qcttoulZ7l9bu5gxko42NIcj4E36F4jr4OACOvtSG2qst7WiFwUufP3o7Y66lFmbCS
         +i7ZFCWcRfZ+pXNSenVS2RFHNjfbJF3O/j9s4gDZtyLIR2iB8TDGsqlhsap6l4Mz6XJm
         QOeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter:sender
         :dkim-signature;
        bh=NwXC5i8tmVYlBApy7UjCkUK0GfvTNph7QFmlxLAFVrg=;
        fh=2t7OiFsULakdxFBT3gipNXbyH4zn+Oo0hW3rYRZ0Xf8=;
        b=BJjmVn2PIi9DtFjWHrXw6ZR3r8s57ErAYuPQ6QCGqG36VApnKoges5pd60seoPthcQ
         I8kYibGwlJc6CK97Wj4RQjjm4S79bSGKliJQDiixRpMIX4qdE4Qdhc3Ym74RanJJkIoO
         16yaHGMmEAWaz+6AGEi1aqvolYb1RoKXsED9ChfcKOfZVovJ/tzsoERWghnSskqvHejc
         4KMJxM8re9v0PGXhr9Ltuy+6Klg34bKjBTqNeLuj6D4jCKena5VX0qoHFWfAbabgM0kS
         NOr0/zDIqFoeEf7fCIv4VLG4n097jQQEczEh88lfEcsZY7oPd6T0NPjC3z+q2H18u15u
         +SWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=rUMpLiKt;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751979392; x=1752584192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:content-transfer-encoding:in-reply-to
         :from:content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NwXC5i8tmVYlBApy7UjCkUK0GfvTNph7QFmlxLAFVrg=;
        b=MxrtntbV1NLlYA/9B5Vn9Xb5nAdLwr2pLkHqh3LeZ6jsK4/dUJo/ikZ7YDzNjtQai6
         DgnVq48/nXaa0Mn4ZpcxYFG+MjMStjbDyvPUt+3ljIfLE3zszfJeTgk3hep1HswCFr3k
         NkBzQwA57JsqGhsB7enElOJUbqgmOHh9HkYy1sxzhr4ELAG5a3m7YOi0CG+dbpS8CQ1J
         NQePFvkD54qfTkjEkjD3iT3Mt3ksxIURRHqVYY6yhcTlOW289UbOsTITbQ0kyWBdetnR
         hjtmIzr1leubV5FQVj/6t3Usqj5j1TUXoEjVB7GREnRSz1uSkPQsRNWffAWKm7vVth1w
         uzgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751979392; x=1752584192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :content-transfer-encoding:in-reply-to:from:content-language:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-filter
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NwXC5i8tmVYlBApy7UjCkUK0GfvTNph7QFmlxLAFVrg=;
        b=Dh9W0PZIVHDKyRY+3W8e9XzyjTRuuG2nCvJ11QcjQuY0ugHYY9j73G2XzapQ9SXW8E
         csrSHPG5RDT4w7yasfh8GRXaIZzV246a7SbWkNaW4PrGi4yH0NW02jawfUYLahHUbAoy
         NztV7yHG/HyBel4E4WSX4Zahs7bPPoKssI2TAMV3oL+JOhbYdE6IGhdXRRiUYtJ3SlTS
         ifloNIcrtCqfIoxJQPBjHCkHYYLymyVaMWsg/eeMbxQsrD99amRsXoTdebryHEbCxV+8
         5q5JsoeIO80YKEwJB/6+nwH83CRXqEOaxWBTWxeXvnResovTvOYDy2X5BT2WlT/iWjae
         NhBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRQ1jvQU+5WFMSnx3aXX5faW66UA0f56g9ZULfhK/BI8MaPzPXEKXKyRwj9ZP4+O5YvFgTSQ==@lfdr.de
X-Gm-Message-State: AOJu0YxUgbFEHEB0wXenVHzj2U0gmbPZLRSG+/ProwBdNjQt9xwnoOsy
	lAmpqnmNXkqlD5L0luT4xhINJEC/9oShw+oHvQCpSi+mLYMHykBIzszf
X-Google-Smtp-Source: AGHT+IHpbCb18DNr/dDFWjfimDwPAL5mW4jX4hlYIMdosTb/EUGqv1+PdCl3Wtuli+X5lBAqfmIrAA==
X-Received: by 2002:a05:651c:214c:b0:32b:968d:1fe4 with SMTP id 38308e7fff4ca-32f39b3ebadmr5492001fa.14.1751979391522;
        Tue, 08 Jul 2025 05:56:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcd1PMj5vYXOKLBe3Ujrfna2G2B6ce0dLewbB6KJLj/Kw==
Received: by 2002:a05:651c:418c:b0:32a:7f90:fd84 with SMTP id
 38308e7fff4ca-32f1166ee3cls5405781fa.2.-pod-prod-00-eu; Tue, 08 Jul 2025
 05:56:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4+t4tEr2IQZRM38jzME7TJp4AkxScHS+GP+NpdH8jJ4ZgV84OsFzoNB9fP1G/C2/aFjKZFTU2zkA=@googlegroups.com
X-Received: by 2002:a05:651c:31ca:10b0:32e:aaa0:e68c with SMTP id 38308e7fff4ca-32f39b64900mr7084891fa.19.1751979388354;
        Tue, 08 Jul 2025 05:56:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751979388; cv=none;
        d=google.com; s=arc-20240605;
        b=BRH7VYLqeMUesotj1v7RDvxMU5E9ZaU2ksKabbHxeIpwLzimmIfzer+SS2mWkDrk3M
         N2J3r6PXuoec5JG6fyKFaUbox0tz8dgWa6oqio4gkUBJoivkx2SaIWCLIdcLvnw5ubip
         B9tYPtANsLByuuYwCbxn1gRXXA8N8wu9jz2zxlvLPfSG2jsVSgKv9PFw7avsRCwLn72k
         CPCiXGilbdY6fU+tZJZtvKTWW1LC53lizWQsiR7UoisrM0Xx3zAZrI53wa/HIhz5ktxv
         PCSoVN5tG0usza6hedScFk8jAdMG00oeT2BYu2dNPQ6y7tTKZ9i0ZmDASjSS03MO/R2p
         hIMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=7/XLYR0OqGT6q8wsQL9awTM8RahowyCK2kF3Lml5n78=;
        fh=t482abZ30FL9W5nP0QbFE8h85nSpVAld8hbHkKUygdc=;
        b=fMKooZTKqVv7PqaEXBz7krI+5h5W3zZVqrbfx0T8/tC81LiurRPi62rcJWbgTmjBQ4
         o2yZc4HViNFEyyLc3J5KGSxQjOxnfFJZxbJnugF103+5aKeugF6bEMvTXLQiC2ZBJEQe
         ICCLbGrmpMdn2F7G8gA1laXwD6gVaSSWkr1H8ON9t5JwmFPXMudsL7aHeRnhu4miDxVu
         bTY+x0PkSSpDbcDKC1zHmY9ewKAnened8l/NhkpUt0/XeHCp7zx2ZObPuXJmfdMp+wHd
         BRP/HiPnRg1CKjMjfK6cvOAVOKzs9i3EhIM01AiX7rdOw8ZpkAAKXQ2wL6dTWkYgNY95
         C1SA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=rUMpLiKt;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32e1b1de8f8si2735261fa.4.2025.07.08.05.56.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Jul 2025 05:56:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p1.samsung.com (unknown [182.198.249.206])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250708125626euoutp01432592edb15e5d64840a98a3982d09ea~QR-g-qQDh0994609946euoutp01G
	for <kasan-dev@googlegroups.com>; Tue,  8 Jul 2025 12:56:26 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250708125626euoutp01432592edb15e5d64840a98a3982d09ea~QR-g-qQDh0994609946euoutp01G
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250708125626eucas1p10fea4e2440d7273510ca606b8c879240~QR-go19vo0583905839eucas1p1z;
	Tue,  8 Jul 2025 12:56:26 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250708125622eusmtip2e8d499202aebc1a18605d526cd72bbdc~QR-dBQdu70489204892eusmtip2-;
	Tue,  8 Jul 2025 12:56:22 +0000 (GMT)
Message-ID: <39d43309-9f34-48bc-a9ad-108c607ba175@samsung.com>
Date: Tue, 8 Jul 2025 14:56:21 +0200
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
In-Reply-To: <20250708120647.GG592765@unreal>
Content-Transfer-Encoding: quoted-printable
X-CMS-MailID: 20250708125626eucas1p10fea4e2440d7273510ca606b8c879240
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
	<261f2417-78a9-45b8-bcec-7e36421a243c@samsung.com>
	<20250708120647.GG592765@unreal>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=rUMpLiKt;       spf=pass
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

On 08.07.2025 14:06, Leon Romanovsky wrote:
> On Tue, Jul 08, 2025 at 01:45:20PM +0200, Marek Szyprowski wrote:
>> On 08.07.2025 13:00, Leon Romanovsky wrote:
>>> On Tue, Jul 08, 2025 at 12:27:09PM +0200, Marek Szyprowski wrote:
>>>> On 30.06.2025 15:38, Christoph Hellwig wrote:
>>>>> On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
>>>>>>> Thanks for this rework! I assume that the next step is to add map_p=
hys
>>>>>>> callback also to the dma_map_ops and teach various dma-mapping prov=
iders
>>>>>>> to use it to avoid more phys-to-page-to-phys conversions.
>>>>>> Probably Christoph will say yes, however I personally don't see any
>>>>>> benefit in this. Maybe I wrong here, but all existing .map_page()
>>>>>> implementation platforms don't support p2p anyway. They won't benefi=
t
>>>>>> from this such conversion.
>>>>> I think that conversion should eventually happen, and rather sooner t=
han
>>>>> later.
>>>> Agreed.
>>>>
>>>> Applied patches 1-7 to my dma-mapping-next branch. Let me know if one
>>>> needs a stable branch with it.
>>> Thanks a lot, I don't think that stable branch is needed. Realistically
>>> speaking, my VFIO DMA work won't be merged this cycle, We are in -rc5,
>>> it is complete rewrite from RFC version and touches pci-p2p code (to
>>> remove dependency on struct page) in addition to VFIO, so it will take
>>> time.
>>>
>>> Regarding, last patch (hmm), it will be great if you can take it.
>>> We didn't touch anything in hmm.c this cycle and have no plans to send =
PR.
>>> It can safely go through your tree.
>> Okay, then I would like to get an explicit ack from J=C3=A9r=C3=B4me for=
 this.
> Jerome is not active in HMM world for a long time already.
> HMM tree is managed by us (RDMA) https://git.kernel.org/pub/scm/linux/ker=
nel/git/rdma/rdma.git/log/?h=3Dhmm
> =E2=9E=9C  kernel git:(m/dmabuf-vfio) git log --merges mm/hmm.c
> ...
> Pull HMM updates from Jason Gunthorpe:
> ...
>
> https://web.git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/c=
ommit/?id=3D58ba80c4740212c29a1cf9b48f588e60a7612209
> +hmm		git	git://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma.git#hmm
>
> We just never bothered to reflect current situation in MAINTAINERS file.

Maybe this is the time to update it :)

I was just a bit confused that no-one commented the HMM patch, but if=20
You maintain it, then this is okay.

Best regards
--=20
Marek Szyprowski, PhD
Samsung R&D Institute Poland

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
9d43309-9f34-48bc-a9ad-108c607ba175%40samsung.com.
