Return-Path: <kasan-dev+bncBDG6PF6SSYDRB4X7WTBQMGQECSFMEGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 42ECEAFCFDB
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 17:57:42 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-32b3ce96f8dsf22284581fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 08:57:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751990259; cv=pass;
        d=google.com; s=arc-20240605;
        b=gOixNsDAdjSKBhQ3mu1AKeGcoXOKfvXmKtPSu4p8WGa8Cls+ou7jEiu84n9bMqa87b
         3AUozQXAdkrXKBr6zeb835oriA/be/pRcczs/IeJzAZ/iYK5+01paXQfglgCmvbPsnal
         jB4jm5Azx7mCZOvZY8nJNecN78zls+i29tLnT5w37jvRk8R+iW7nHHHQF98uHId//J7c
         V13EkTAGz0TANeAENwOUvj1HB0WuWkQBagkyDmQsbw//hGSdDQ/k+/jozHDDRB6R6cKO
         ImOnTl1+42cCtUBstPhv9436sR5NTxcNapqe0b1xOvqH3LjxdDmS9LR5h4jtkErovyp+
         PQ+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references
         :content-transfer-encoding:in-reply-to:content-language:cc:to:from
         :subject:user-agent:mime-version:date:message-id:dkim-filter:sender
         :dkim-signature;
        bh=esdTQMH0hTB+0IIB5txeTdG2CqDDRg2BREONrfAimXk=;
        fh=kit7M58khv1Wn88oDP5JEUDh4/eqdP//jP4gS8LCJHc=;
        b=D2LcuSdsNrLrJFOzU6BY5dumtfx7+eDt6+i6yZDtJnvqejEm3PNTVH8UwBzlFkVVKA
         yfSl4lsQqZjVm0kk83XhngsKOWfJ8sQFXevp9pG/rv2/kjwiXJFdl1wGC3ibzhNXCZT+
         AR1gcuT2pM2LgADeGki0wPx4YD5QatqlMBZE1gMpW5vPcez3oAAKKVinMhkCcFBGzDF9
         TPi3RvD9B532dX2/2ZScE0r0Fu0oUiB0quDY66JNqIzU2yBFk9Kqy5xdyfXE2xrvdj2U
         Bp4SZGSZ0J0JsYn/AfghhzEzIXZG/joI2otOMMgE0YVGdGRL5k/5ItsxrotUhTnNRcov
         1TOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=PAX9aPjm;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751990259; x=1752595059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:content-transfer-encoding:in-reply-to
         :content-language:cc:to:from:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=esdTQMH0hTB+0IIB5txeTdG2CqDDRg2BREONrfAimXk=;
        b=MII+Yq6pFlEIFNp1E3OWpg3xUnx16RGKxgmBU6gLuL284aPwfBxWhiP6GQQMEkQdqc
         HM90SCr3O1zwjSVMbx/AKnDgPs63lh0DfrWwTz+VOqT78S5ux0Tuen2ebDrIogLT4Byf
         /YvHlLn8QwsyirP0MOE2t1Zc8bmVWUOUdTmUfnl5lQefRhcIpZ0eLLICcF4XPz/FhH4r
         QUuKBhV5WcltFbvstO2eZdG55WuwcHCJ3vYeXfYOZcVwfnsPqELTS+gthtreE6nbG9MO
         ZxpIZi2SD1hi7NvYNYT4bNjcuzMCC+Wpya+2N0+HPC8r3zv4UiT3s1cizVQLIkT5ZgPy
         rumA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751990259; x=1752595059;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :content-transfer-encoding:in-reply-to:content-language:cc:to:from
         :subject:user-agent:mime-version:date:message-id:dkim-filter
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=esdTQMH0hTB+0IIB5txeTdG2CqDDRg2BREONrfAimXk=;
        b=SWZKTRQQe15s8fDrUz5zNKhcsxcypgmB66IK1eTRfAd9QAHSlvdfAJY54xP62cHAO8
         S3NF/r9v1lGeJN9qNo3UX1m5tMjFPNaRr5OnPMSev7qUAK9AfjQo3oklzB7G0dKYRvgx
         +hb7uY1ax+rZRAecXMRk8iQoKlxmDZ1Myy+XQ11k7m+hDHAnoK79doIEH8n/6R9JEjvB
         k2CmD10O+jluj2SX0q6JXVxqYI4j7/RlIjwDIRKBU9HwoVg5Jj/ZN1k5i8w5JXvKeLHK
         XEUZMwV/t3xbKVfBdyQa4Uw6YQL8UnaPkTwQZ8lSBnM/zcq4/LxOm1ZT0QH5Gn8aSIPQ
         WlNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWTgd4i1Jhl1fNHwnIHCgnwZm7M6kcTOiqETbh6eS++hx9d4MWoeyhaM5ZFkpHCq2dOpjmZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw9XiuXVJmwP1TCY8Lniav7KPyL/qUCfyaRrxAyPujxuJJg5qpD
	b2zEU+VPVICsY9NoSKaoHJ2ImUx7ZsHOdOKIgdenRYoL0dFQieJfWIEk
X-Google-Smtp-Source: AGHT+IERPSQKZ/KjJD07TW2zTeR0aWNQhUZv0kJppi1WmskY7O2jYP0itA5X+K0aXHeArFpHT+mZ9g==
X-Received: by 2002:a2e:a585:0:b0:32a:7122:58d8 with SMTP id 38308e7fff4ca-32f00c6703amr67202621fa.8.1751990258948;
        Tue, 08 Jul 2025 08:57:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZecnQvAu7oEpeV0Kgfe7D3RHuLxj+srF3fOrFXU+b0djA==
Received: by 2002:a05:651c:31d3:b0:32a:6004:f724 with SMTP id
 38308e7fff4ca-32f11248ca5ls9075321fa.0.-pod-prod-08-eu; Tue, 08 Jul 2025
 08:57:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWg0sp38iGDDaGjOb8Z42yw4q12/xqr+LdY8JSuEtYc1ojpxxzgi6C2eXMLM5+oIJ0peVcIjv+I3es=@googlegroups.com
X-Received: by 2002:a05:6512:a94:b0:553:2927:985f with SMTP id 2adb3069b0e04-557a132c260mr4580301e87.5.1751990255893;
        Tue, 08 Jul 2025 08:57:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751990255; cv=none;
        d=google.com; s=arc-20240605;
        b=SMZOq3P0NYRhjT5yHshZBsuLY9k0MVdtnmV79B/SzQUpOwcATwqa6+h41NgI/EzajG
         MiryBODkgYPaC0mnC7MMHoT7EcvENNiwUP1GqsfpvGpdfTY8/SOXYdZv07vFVn24G0+K
         ZC8sBPdGiNdAREu/76QfjjFJ1LIBECcrlIlDRZZ6uOl5t/fVlYe4O+5uVy5ffab5ZT5t
         D8wy8uhJt6SmN/8QcTVoT6AXgA31msGDBf+dqxDXaHQmnVeEr3jIzMc+eFyAwOA0u1Z2
         BVBuL0Xh7G+OsAw8rH8wt7mihc5sLutNT6x/0z9VZPMAHt5f+LARSnLMztYpZ2TIc9T7
         eWiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:content-language
         :cc:to:from:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-filter;
        bh=uyab8dr49wEubYW85hrXKyGCcYl1OC56FE0kAT8DEIc=;
        fh=t482abZ30FL9W5nP0QbFE8h85nSpVAld8hbHkKUygdc=;
        b=FcIV9p3fcEolyhFfyXnaPjs236m0QxZdsL1csjKm8KbbJJYyUcw+TeHggl8Ppibm0h
         Z9p6BKXIlTWHzwVzVx9iYdVHOiLXm6buEQ4HskbYdcRYPIN1cHwCZuH0rjoSqti8+mw2
         GPDk6fJhb1usioTPotsNDevvtqLiLff0gkWstveLfhnxqNhnS1xvODx9Y1r7DQgl2Y76
         DgjM3/yivOPEOq9pWUKPOb/eB64Zt/TNfFeLK0UOf+LQ13gtlolDMrLVO10VszYaN0IT
         ZPfKd0OuxNyQXpI9DE5cYgK529LA0drwiSPY+57pB66wFm5CsHnNwSpZ9Er770hvnB69
         wx3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=PAX9aPjm;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5563844fff3si378914e87.8.2025.07.08.08.57.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Jul 2025 08:57:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250708155734euoutp01da75c85e37db8b8fb67978584a3e8bf2~QUdqsJdcO2034620346euoutp01M
	for <kasan-dev@googlegroups.com>; Tue,  8 Jul 2025 15:57:34 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250708155734euoutp01da75c85e37db8b8fb67978584a3e8bf2~QUdqsJdcO2034620346euoutp01M
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250708155734eucas1p1407185657d9833058c6b35d11e1d0b01~QUdqUADk60849108491eucas1p1v;
	Tue,  8 Jul 2025 15:57:34 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250708155731eusmtip2162f9813a1cd05daa31b4d62d2bead82~QUdnRS2nc2073620736eusmtip2d;
	Tue,  8 Jul 2025 15:57:30 +0000 (GMT)
Message-ID: <b542bfa3-d680-4952-98fe-0a44ae3bddd7@samsung.com>
Date: Tue, 8 Jul 2025 17:57:30 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
From: Marek Szyprowski <m.szyprowski@samsung.com>
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
In-Reply-To: <39d43309-9f34-48bc-a9ad-108c607ba175@samsung.com>
Content-Transfer-Encoding: quoted-printable
X-CMS-MailID: 20250708155734eucas1p1407185657d9833058c6b35d11e1d0b01
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
	<39d43309-9f34-48bc-a9ad-108c607ba175@samsung.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=PAX9aPjm;       spf=pass
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

On 08.07.2025 14:56, Marek Szyprowski wrote:
> On 08.07.2025 14:06, Leon Romanovsky wrote:
>> On Tue, Jul 08, 2025 at 01:45:20PM +0200, Marek Szyprowski wrote:
>>> On 08.07.2025 13:00, Leon Romanovsky wrote:
>>>> On Tue, Jul 08, 2025 at 12:27:09PM +0200, Marek Szyprowski wrote:
>>>>> On 30.06.2025 15:38, Christoph Hellwig wrote:
>>>>>> On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
>>>>>>>> Thanks for this rework! I assume that the next step is to add=20
>>>>>>>> map_phys
>>>>>>>> callback also to the dma_map_ops and teach various dma-mapping=20
>>>>>>>> providers
>>>>>>>> to use it to avoid more phys-to-page-to-phys conversions.
>>>>>>> Probably Christoph will say yes, however I personally don't see any
>>>>>>> benefit in this. Maybe I wrong here, but all existing .map_page()
>>>>>>> implementation platforms don't support p2p anyway. They won't=20
>>>>>>> benefit
>>>>>>> from this such conversion.
>>>>>> I think that conversion should eventually happen, and rather=20
>>>>>> sooner than
>>>>>> later.
>>>>> Agreed.
>>>>>
>>>>> Applied patches 1-7 to my dma-mapping-next branch. Let me know if one
>>>>> needs a stable branch with it.
>>>> Thanks a lot, I don't think that stable branch is needed.=20
>>>> Realistically
>>>> speaking, my VFIO DMA work won't be merged this cycle, We are in -rc5,
>>>> it is complete rewrite from RFC version and touches pci-p2p code (to
>>>> remove dependency on struct page) in addition to VFIO, so it will take
>>>> time.
>>>>
>>>> Regarding, last patch (hmm), it will be great if you can take it.
>>>> We didn't touch anything in hmm.c this cycle and have no plans to=20
>>>> send PR.
>>>> It can safely go through your tree.
>>> Okay, then I would like to get an explicit ack from J=C3=A9r=C3=B4me fo=
r this.
>> Jerome is not active in HMM world for a long time already.
>> HMM tree is managed by us (RDMA)=20
>> https://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma.git/log/?h=3Dh=
mm
>> =E2=9E=9C=C2=A0 kernel git:(m/dmabuf-vfio) git log --merges mm/hmm.c
>> ...
>> Pull HMM updates from Jason Gunthorpe:
>> ...
>>
>> https://web.git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/=
commit/?id=3D58ba80c4740212c29a1cf9b48f588e60a7612209=20
>>
>> +hmm=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 git=20
>> git://git.kernel.org/pub/scm/linux/kernel/git/rdma/rdma.git#hmm
>>
>> We just never bothered to reflect current situation in MAINTAINERS file.
>
> Maybe this is the time to update it :)
>
> I was just a bit confused that no-one commented the HMM patch, but if=20
> You maintain it, then this is okay.


I've applied the last patch to dma-mapping-for-next branch.


Best regards
--=20
Marek Szyprowski, PhD
Samsung R&D Institute Poland

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
542bfa3-d680-4952-98fe-0a44ae3bddd7%40samsung.com.
