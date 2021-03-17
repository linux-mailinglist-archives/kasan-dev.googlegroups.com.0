Return-Path: <kasan-dev+bncBC27HSOJ44LBB4XWY6BAMGQEPUQBRCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BC8733F0B0
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 13:52:02 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id h14sf15160400ejg.7
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 05:52:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615985522; cv=pass;
        d=google.com; s=arc-20160816;
        b=bnfvi1wpf681tQn5nwye49jV6H/7XKxUOg0r/lXNRVs9Uw1ZDDxjSkDX8T8z5tpc79
         2aEE52r8shlo+frROoEEfV9i6e3jdhW8ViiuYXdnZFY/TFgIwO8pIjfju9MXOYzpruBj
         PRp2ucpJk8TT6KV5++09ePzhjDuKeh+XV1ZA9LuCPpb4SusoKMlBcnqNVN8acthdRRB8
         jvK/Q6vMWlalxZHq4Itj676UyZkjpSqC4+Cqypn+akvQcV4+nDh9Opna7FzATGPvd0f3
         WxeLcYPel4GtE+p6lmDxrFtetrMCs2DeVxC+igTNNN0CjGECZLPOiCuj0cnnxpOC1Olm
         PsVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=dJ/DXBneUEhGBS9Nqp7dH/kvI6eJm2Ht0+RVUIxbbd8=;
        b=N5h21OpiaI525tkw6FgPIkDsuirxZG/rPKV5iJPFtJout35cmbS278SlgBfyKSJzeY
         SydXva9GILxa57SdrCLuMLElrD+A8VRuRV6lLgswXjlBq1WaY/o+ExiiUlTXzOKo4jTa
         Ap7wPJW6EhsFxJjhEkinikJCT73j46T2ILj+/9f6bwLhUO2v1ARuSNKhB/GWg7FWSN7J
         zKUB+clnzz3WekFbwezqwGXGi/m8yLrCoHdCILzXfKzKtTfFo8cP5xenZsAE9BNXJgjE
         4geFNCyI8UgffSwvJA3E+iRqTtG/SMVOzkxGu+6ssc/G6qpckRZKUkksVhNeWSegsBQc
         vGww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dJ/DXBneUEhGBS9Nqp7dH/kvI6eJm2Ht0+RVUIxbbd8=;
        b=Uhuhs4w/r02Znp8dGMHCRHMVLq2w6PvaAfk3LZt/IkIkHJvWfMaQhZGSa/OiK67snG
         KQWJJ8aWlxvt0CJaLyNbeeTf3+0URv3/nyuTvQ85VrznHm7TV5aElfpqRJiSuwufva08
         xlpxA3vTl95zAdLDBPW3wKklWbUTEjYY5krAE0YCkUxBINzXUpdxj7wl/rDKHIPBOWxR
         eSCM4W7B1MQBqdIuwUlQH+izx4mj9gvWZRUQVAb3wYKyH1e3EBzOMBr46LvTJg35EMIq
         KFoCo/xoXmyb42HDQc2I/AUtLGokdeCmkV9DlUWI4tVwokeZapBi9BB2EYJZjj9V0AJ3
         kfsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dJ/DXBneUEhGBS9Nqp7dH/kvI6eJm2Ht0+RVUIxbbd8=;
        b=V+Bf4GYrxnDTfJ1hhvTb+97N0z0Ak54rMTo5h5FGGVAKNoC68zgyM/nBcawKx+dZBz
         muQYlQnGsikh4b525ywm+TDcHhX3bHvFfvk09QNx7TAsc4nsZHNzo5DPDbIyvjSC6nSn
         mjwwKb8nXHchsyc8v7tHgR4pDw2ryTgwdyczzcuWIvxJjhwiobArX9ryXhl+VYB0Ub+g
         wHCZDQo3Tl5dTkX+Z+IYqguXG1sQLHK8rfW4u6f7UUMe+B3ZA/fS51rc7pOLUmyEDzmN
         emRo8RW5Eh3vFKGU4lHXe9bbzyFBsiSRWHcb7uTNjkok8TGjTM9mNFISwdnJBAX0uXOG
         6B2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IGINlWkeKqIhPsqVHv/OUJrjCqBsgXG6bezV0xtoTYcj1xHw+
	sov6mdFl3IlXtxZNiTLGjJ4=
X-Google-Smtp-Source: ABdhPJx/D2l0KSVK2wovHlaIiN3XHE5q3eCbWKxhsg5QduNuLyTRO2UZWT6Dr9tD2SA5P2EZc4bLug==
X-Received: by 2002:a05:6402:31b7:: with SMTP id dj23mr42445842edb.245.1615985522193;
        Wed, 17 Mar 2021 05:52:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d788:: with SMTP id s8ls1066071edq.1.gmail; Wed, 17 Mar
 2021 05:52:01 -0700 (PDT)
X-Received: by 2002:aa7:c386:: with SMTP id k6mr41322831edq.224.1615985521371;
        Wed, 17 Mar 2021 05:52:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615985521; cv=none;
        d=google.com; s=arc-20160816;
        b=mwkBMBbQAX3sXrfmghiOiValTFfK1/EJezDLHX7jOtL5h4rvNI2dgOErzX6FDzwNE4
         T9c+NCaWcQsZAz2Fo4vMiyLGsTcM/uIrmP0Cmlg/kp04dEEJoKNu9qh1QYG6r4OSvJn6
         2rt9UGlDxJl56jQ3ODs+ijtJR25L4lvY70nqXyJ8GjK4q51blHpc8OZDLBRLgLRcVVRC
         6gQd+1QSLa81Zj8rpvLfZ1gOUllSAm0S0+bU6myDrcebVrsMLFMlOP/IAzmoTKmmID+V
         L6Ct5s6ZpTkMZ1yymFHaYxNcFACDC8duGNeHec1oRRFK8D1xHNBDTOZZXrSJJEeRVYi5
         6yLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=XzQ3ogMEbvs6s681u+dD6RqehYEHSgnhCAEWhqWdvTg=;
        b=ZKtDCBLBc31I2RJuWc2fXF5FhH1QL/5CCe4AV+KMbsagQ6ty/P2LbM8AtG/z8RuNcz
         j9H1uGDPfQxXrFW02N/WglHo+QTePS15c3PLRCdF4rpcRPjSB6c1c10/eAyr2y8WjO3y
         vDwblTvmwqF622s8mZEo2fibVvQ3cb0JbpbHStAmztls2YRryZrGqqlYvpcpgkNcbFCn
         kAqwMYYcRwcMvmUCeUWc9JdBQPQs2bCWxg5Kwi5eW7X6DEgRg+vj0SoQkWJ9A43zf/gh
         3yalvOU00JrI1qboZ7paxcM9nJsPq8hQtfKz37DNaBDDCpsiyMhl8Q2ouBfrbqf+5VJc
         rjbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.85.151])
        by gmr-mx.google.com with ESMTPS id w5si712932edv.1.2021.03.17.05.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Mar 2021 05:52:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as permitted sender) client-ip=185.58.85.151;
Received: from AcuMS.aculab.com (156.67.243.126 [156.67.243.126]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-178-ED19Hj86PCuP2PKcO90fAQ-1; Wed, 17 Mar 2021 12:51:59 +0000
X-MC-Unique: ED19Hj86PCuP2PKcO90fAQ-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) with Microsoft SMTP
 Server (TLS) id 15.0.1497.2; Wed, 17 Mar 2021 12:51:58 +0000
Received: from AcuMS.Aculab.com ([fe80::994c:f5c2:35d6:9b65]) by
 AcuMS.aculab.com ([fe80::994c:f5c2:35d6:9b65%12]) with mapi id
 15.00.1497.012; Wed, 17 Mar 2021 12:51:58 +0000
From: David Laight <David.Laight@ACULAB.COM>
To: 'Christophe Leroy' <christophe.leroy@csgroup.eu>, Segher Boessenkool
	<segher@kernel.crashing.org>
CC: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov
	<dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, Jann Horn
	<jannh@google.com>, LKML <linux-kernel@vger.kernel.org>, "Linux Memory
 Management List" <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: RE: [PATCH mm] kfence: fix printk format for ptrdiff_t
Thread-Topic: [PATCH mm] kfence: fix printk format for ptrdiff_t
Thread-Index: AQHXGnrjHw0GM4Y/B0GSBDFCMZ5+u6qIIzEw
Date: Wed, 17 Mar 2021 12:51:58 +0000
Message-ID: <6d4b370dc76543f2ba8ad7c6dcdfc7af@AcuMS.aculab.com>
References: <20210303121157.3430807-1-elver@google.com>
 <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com>
 <c1fea2e6-4acf-1fff-07ff-1b430169f22f@csgroup.eu>
 <20210316153320.GF16691@gate.crashing.org>
 <3f624e5b-567d-70f9-322f-e721b2df508b@csgroup.eu>
In-Reply-To: <3f624e5b-567d-70f9-322f-e721b2df508b@csgroup.eu>
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
 (google.com: domain of david.laight@aculab.com designates 185.58.85.151 as
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

From: Christophe Leroy
> Sent: 16 March 2021 15:41
...
> >> include/linux/types.h:typedef __kernel_ptrdiff_t	ptrdiff_t;
> >>
> >> And get:
> >>
> >>    CC      mm/kfence/report.o
> >> In file included from ./include/linux/printk.h:7,
> >>                   from ./include/linux/kernel.h:16,
> >>                   from mm/kfence/report.c:10:
> >> mm/kfence/report.c: In function 'kfence_report_error':
> >> ./include/linux/kern_levels.h:5:18: warning: format '%td' expects argument
> >> of type 'ptrdiff_t', but argument 6 has type 'long int' [-Wformat=]
> >
> > This is declared as
> >          const ptrdiff_t object_index = meta ? meta - kfence_metadata : -1;
> > so maybe something with that goes wrong?  What happens if you delete the
> > (useless) "const" here?

The obvious thing to try is changing it to 'int'.
That will break 64bit builds, but if it fixes the 32bit one
it will tell you what type gcc is expecting.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d4b370dc76543f2ba8ad7c6dcdfc7af%40AcuMS.aculab.com.
