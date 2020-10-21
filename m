Return-Path: <kasan-dev+bncBC27HSOJ44LBBMWLYL6AKGQEKC3BNYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 87DB5295407
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 23:18:42 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id i26sf1994802edv.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 14:18:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603315122; cv=pass;
        d=google.com; s=arc-20160816;
        b=MoqGXk+Rc1i4qpyq2/kT0yFCnud3j2deyIz5tttrEdBMLI/8n8FARuf02fLx0YrIma
         OjooN1N50qVPJKT0vaQa6SNI3KVyxPm2bOQyKP0GN4PbRM1dqZKZdzvkTqvfWbyNE+6o
         /FlNQcxUc72bmMSCmy8XyL8jcpuSNBiiSiUYjZX/A8ROOnCm4l/vDCrAy75hNWI0iO6e
         BXk3ZvvBWu6anYz5wAptg6T3D3qiGvZmFvigdFoKiQfgifvOJ3/xKilx4DH5vdQ/gk44
         arXPLk1/zFdbfatXtcw5Wx/fYlAQdTTg+1Nm5QtE6NHXaeGjFMVsbibKZ7x+HJremSl5
         0fkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=E/PZSwMMWNFx3mo2O6BJXOG6mRa/l8qzus7D3knU6wM=;
        b=NgPsUmPjOGSFVHuVdL46N4zPbVlYn+qdY7AZuqA/ewaP+pD73RMCYPFoSdFAG0sUPy
         NDnirmAX2r2Uu1YKCQJ47K9JFdM3uPV4wW/psPN5HC3WUjODdq2xhQYRwkWD8Y9Hqjnx
         7on6ABU1M9fa0zbNbkNYEedXKmzZsD7vz9lWpyZ2rK7lTYbkGs0KklmLnrXoOUoZA0hy
         8+rA9yoyTUObKNSm/+VPQ5hE8e9OGEa92lwJTwzN78XccNlcpSNFn71Ryyn5l5mpn/lM
         9HEDtJ3SRNgadckdJAxF6pDUbQipjgmAUf62qOD0YBDCQL9fetmP2wzcExTkOJ4eUYgH
         Gtrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E/PZSwMMWNFx3mo2O6BJXOG6mRa/l8qzus7D3knU6wM=;
        b=jy7ygmx+qfMDphr9oxF2emv/NiVYhRVZE7eQ8wo6jhIBS+Z9nYNhp5bt33veCts7Yv
         or2sdZA9KJ0bExDK3dtr3fzehOo3c/IA2KSHrgrff71yuOvrVrRK/pQns3GdOtZZGNZg
         bjmvDHsKcED2gNmQLQJSf38leUiOA6TO6A+YuZnbwvqT/J5Mmq6oXumbYdP/X5K6qJLQ
         Ng1iP6WYVcDTZ2mbITkadUeIv70ixjZkwrBfkfqJ1hKnPKpBeXCSBl0lWf8mOc57KlSw
         +VaTll3eP/YKnlyEzMBqNVIEQjYwUIYQa1+lnNSyPaIe5WY//6LDZIaEfd6T9y3UGe4Z
         adoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E/PZSwMMWNFx3mo2O6BJXOG6mRa/l8qzus7D3knU6wM=;
        b=nEPhyx2zTkgyNHtjrLFZQhxFLq+QPweaoHcyUIleOOub0YjHJpv3//J5lpJw/RvT4q
         Y5J3rUTKkHqDesVfRZ9u2T38TFfPlpnvVH9jUdF7OWYGMa4xTYRL3qeOd++m4r5eu3cf
         chBEeTMj4Lw/BdyS5J7eKRoZ7Pa2jASJBCsnWyFMlDtprRZpOIJXbU5qMzFnX3hAdSc4
         9GB77/ODcGP9u5iFdNIsfvlf3SEW1muM7kW+Rvv3i49OejuUkEy1qasskGYk3CmlZnQi
         mpQMGKAKH3t4/zuTcCoCeQmfTd6fuWqIvStNcWOKFpzbhkkH3iZvSjfbzGRIxme+4fpA
         3Btw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532BBJfpWr9ZogqiRpZqd+q7snwtyKWR+1v2LQk3TBkoG/8/P4WS
	FOAxD/+kNPJT+qVGkPFDTgQ=
X-Google-Smtp-Source: ABdhPJyGOAd1+wRXW71P4KQSHGWyB4AbXXJHQqaRNzcbs/AWiBKPvSeEhCBioNCfnnF/VHEiMJJ3mw==
X-Received: by 2002:a05:6402:1c8f:: with SMTP id cy15mr4996343edb.335.1603315122249;
        Wed, 21 Oct 2020 14:18:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c04e:: with SMTP id k14ls963440edo.1.gmail; Wed, 21 Oct
 2020 14:18:41 -0700 (PDT)
X-Received: by 2002:a50:871d:: with SMTP id i29mr5030909edb.300.1603315121357;
        Wed, 21 Oct 2020 14:18:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603315121; cv=none;
        d=google.com; s=arc-20160816;
        b=XaCiaySyTyjuQ6BTDgwUqXVY3BGSbaEt4YC7NhTaZk0OGpaOwgTds3rVgbUYf0CBOk
         dvK8OTcBAgiE4IviZX4jM+Tryyje8nZDZxjL1vcxA+qa5mC+qJMOt9+ZL3KWiYwsv9dN
         MSkoO+XfMOKV5m7f43Dfl30LHoCs2y8mGNog5zvfdjN2nxRFJmcJANJGjNcscR93XUsE
         OtQu9u4t2Yzmsghl+a7opPcJMnDTsumlSssSJa0rzFfQAzOVKHQF9nhLKYalDlGxpcjg
         vyHo7nASTD38rUC47V4NZq6pFuYUfRqC2o5AwHIKDZz6pUBFSGRPQSwDSNlta8Ehp5Oh
         MWVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=8DRXNUWl7maY2ClnWcpsvuqalXaMcmL8Q1HX55i2wIs=;
        b=Fix6yKDkdq8JJ/VEb3PAg1vJrdBgEXPatkkKtnEaEE5tNScqN96BgYFhBrFA069WUZ
         MWkYyzuxGKIf7mCfGjMQZfdZIyNWnQV9PFlvYYt3VN4QdWOcHBD4nvARWsO07utnOddm
         c0kAoHIrwfRZSfQf6Dtd8+skzee+mbKRbmc0mVIMCGPcfZSDTF6CFEkFe9KhKL+QMBJi
         yc0G0hYGQilbRdOrNYI9JYC09c8j7xsOPvAWAuPYJrXWKVJuZvIouRiwWHshHeSLDgkt
         oAqBK75DYB0jDk2P4IWmOi/XtCO4RNGtIBdLMQzO/xL4AAbeT0PNkuklKtvmiG7Vdy5n
         spNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [207.82.80.151])
        by gmr-mx.google.com with ESMTPS id ba3si96602edb.2.2020.10.21.14.18.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Oct 2020 14:18:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) client-ip=207.82.80.151;
Received: from AcuMS.aculab.com (156.67.243.126 [156.67.243.126]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-190-mJ-rMIRbOpWxzbbz5YLg0w-1; Wed, 21 Oct 2020 22:18:39 +0100
X-MC-Unique: mJ-rMIRbOpWxzbbz5YLg0w-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) with Microsoft SMTP
 Server (TLS) id 15.0.1347.2; Wed, 21 Oct 2020 22:18:38 +0100
Received: from AcuMS.Aculab.com ([fe80::43c:695e:880f:8750]) by
 AcuMS.aculab.com ([fe80::43c:695e:880f:8750%12]) with mapi id 15.00.1347.000;
 Wed, 21 Oct 2020 22:18:38 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Ard Biesheuvel' <ardb@kernel.org>, Joe Perches <joe@perches.com>
CC: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, "X86
 ML" <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Miguel Ojeda
	<miguel.ojeda.sandonis@gmail.com>, Marco Elver <elver@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Andrew
 Morton <akpm@linux-foundation.org>, Nick Desaulniers
	<ndesaulniers@google.com>, Linux Kernel Mailing List
	<linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, "Linux Crypto Mailing List"
	<linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Subject: RE: [PATCH -next] treewide: Remove stringification from __alias macro
 definition
Thread-Topic: [PATCH -next] treewide: Remove stringification from __alias
 macro definition
Thread-Index: AQHWp9zKqfE0UY1ZpUePerljMWlMOqmijyIw
Date: Wed, 21 Oct 2020 21:18:38 +0000
Message-ID: <1f487127202a49c09bc5db4fd95ec247@AcuMS.aculab.com>
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
 <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com>
In-Reply-To: <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Ard Biesheuvel
> Sent: 21 October 2020 20:03
> 
> On Wed, 21 Oct 2020 at 20:58, Joe Perches <joe@perches.com> wrote:
> >
> > Like the __section macro, the __alias macro uses
> > macro # stringification to create quotes around
> > the section name used in the __attribute__.
> >
> > Remove the stringification and add quotes or a
> > stringification to the uses instead.
> >
> 
> Why?

It allows the section name be made up of two concatenated strings.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1f487127202a49c09bc5db4fd95ec247%40AcuMS.aculab.com.
