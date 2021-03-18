Return-Path: <kasan-dev+bncBC27HSOJ44LBB7FTZSBAMGQEGHYE36A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EB5F340195
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 10:14:37 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id x10sf13577830lfu.22
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 02:14:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616058876; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cep5Be4XqNc1e9Hi3aRUgfCdyryFw1WvJ3/HvB/oS4e43BOmojGxS0dL0UCMpUIgV/
         E1j8huk6TGeoc9ZdUO1r7OJj74cHu2nbsBSbeDAbiY3oed6IN86di5s0C23Sp42TG/9r
         KuUC2EF9NEZsxU6mmBMiUArW/aEkCB0AA6xV6Gt455JLlrMMaX3uP8Rs6cEOgfDOJhld
         2NV75xGkJnONzwyy7bi7wjsqYilZckIFtf/8XSj/vl4niZFIh6S2PJBMyjKrZd3iOF4z
         vokKgd7gBT/EsQurnqN/UWAJfAq+saYHuxER46xjmT5PEgP9tG7bX044ttVIxS/ulX8F
         yaMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:sender:dkim-signature;
        bh=+NqXw8CWncrRhRGR36Xfwe1Wldojgpku/EVu3trT+Us=;
        b=LA7BK3N+FHgdQeQG7B6fVgCag3d4LdELBQo9PtdVO28vleTr1isHpjyWXgFyub96iM
         UIrRVzSSHOo/LIIAMeR6M1Nw0Q7gq7Gi7oWYXV+aZqjCbtMBXppm7lzHnkpJzTClbsqH
         xw6W437UkMH7sWPwyEiXOjaIcFdBknLvoczpQZ6cwE4ONPebQMzsdDldvRELpEDVjJdv
         zFFupElnqAn7RZ6l64kG6iXYL1pW5RNRYcLZbtk+pdf3p68dUz4UJGr17JOWZRRM9ppB
         egbUkeP87v/BDqQWrF3LE+JHEX44/uPeIisqI+rZjFX1fYiky2ZlgDDXT0hxeOrNSOe0
         6pJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+NqXw8CWncrRhRGR36Xfwe1Wldojgpku/EVu3trT+Us=;
        b=I2dNM4HeN2MO7hO9v8C78J6LTg1o2vVel7U6JMxNaMIfKrndIAXQ1gsfDEuAyTz1Wo
         J5EZbbOpjALmbYQ50DTqJIfF4NuRoKAErf5xrJON9MqOBxbGEjhX4lys6QJKyjBYJyZq
         zk+k7BcsZytcmwe1KeLMp2biMPpbnZELSHgWu/CaL+XcQZTr7upQL0DdDXM+hxfspWbt
         Rtaqc0b8TamhXIinKko99RVFjQkh+UwKd/qimLVuUu08OnjNt65+/RwwhthSTv5J64bV
         qRt7FyrRt4io4xnXosI2p9GZ7q/KkXW/R9YDw6ZuedqB4C2i49LwIMMJtFXgk5c0AMBo
         TNYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+NqXw8CWncrRhRGR36Xfwe1Wldojgpku/EVu3trT+Us=;
        b=h2l+QGTNWCvwzF9fgePUh3Ud/JWY/QnIclvtGYQcL16mnmPl2mu6oz4mkIz44pvT4G
         vnvxJQw5orzL22U18kc4w/6MbaiCycQrh1h6wPK0D5YQVq5vOfCjWhSu65T18bIguGa3
         igC93YfB27/bPwVmx29Vp/WSH++dS+U7Nd7awgSKXoBhVSkz8nzqiatbGUroB7honZu+
         NCGzqW/7iyh0T+fBRFmGsV1D42LM8di+0nMoPoFvOBQx3EaJ/dXx5P+Og5LdQQc5LtS+
         gFbvFCE5zlEytUBqQ58vizrLPdms8ZB7qOnezCDpLKEF4gFBi2dJDh+e/vlsiOTaeb2u
         AR0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Lq8VkLaS1GvjKTP9MLT87q05HfjzESWMQ2TWpOZo4cV2NS07V
	UZjiZHr/yuTTFn52p1t+Q3s=
X-Google-Smtp-Source: ABdhPJy9xNkg6LTVhCrQ2/UGmzF+K/a8HwKh2IuRdpc0ID5ala59i7vBMSacrFgKmMjdS4p8HOY8HA==
X-Received: by 2002:a2e:91c2:: with SMTP id u2mr4839187ljg.301.1616058876628;
        Thu, 18 Mar 2021 02:14:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls404617lfo.0.gmail; Thu, 18 Mar
 2021 02:14:35 -0700 (PDT)
X-Received: by 2002:ac2:4d8e:: with SMTP id g14mr4838412lfe.572.1616058875556;
        Thu, 18 Mar 2021 02:14:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616058875; cv=none;
        d=google.com; s=arc-20160816;
        b=CvmrXyP/ddW4wDyMfv0qRkfRZMq82d1uHVZU6odWSbyC+HneFt9BrpiFPJsLukBJfL
         LYdBs8LlZ9MIBectoOR7LhpXqwii7XNgWvTzN+WdZv7ITaykPU+4MTvhiXgw3tYl8Z58
         //urXI4ACbB5kqh+c5/9QdMHPvKOJ/mJn4Hkp0p061e8U2UWjNPsqy3Xy97A5TGzvfWj
         zyuAReIffY5uPKYxFqWsccqVh/hI101VgxBcua3llcoAhxljA1FVWzK/FlLuqPGyDm65
         ISMDCrbHJ0qzY2jBRi+6GaXzYq5dtZG9AF1iri2OFj3FVG6FH1WLQ9t+5izK/ydZcFzi
         rdPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=vmD8RKy4CrDFVpL1qMNDau2NcdumoWakq8QNwUCrr8A=;
        b=NsfQi8gl3IhV4ALOO6ICUK3aWgfSQ+eTmHsrdAzpd3ZNHMl/pVuX/jflP74HogxZCZ
         zsut80CULIxcIPtcx9UL2CyeMSpSgh0ovs3D2OpLLvxj65L7xrmXmS27j2rALfAmU1fv
         H/9X9XItucjuus6deQaVo3twkHGeNgb8aJappyv7pa61NzpgTL1ugy3OJ4dImkh7qh0r
         iQXnBEEAb0tCOophc50aRoT3f3axQHI5GtvLKt5Uz9SNufPS/Kq7J/+nT5b1cAO+Xo/4
         Lp8DRoGXd4GmiTiLb4dD3CdD5a1whz3upssMMwgn6GQc/LuAMhSMoU1Ve/1ehdQGACnN
         iMYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [207.82.80.151])
        by gmr-mx.google.com with ESMTPS id z5si38091ljj.5.2021.03.18.02.14.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Mar 2021 02:14:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) client-ip=207.82.80.151;
Received: from AcuMS.aculab.com (156.67.243.126 [156.67.243.126]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mtapsc-6-HB0JS3AuOO2RQEe5DAakJQ-1; Thu, 18 Mar 2021 09:14:31 +0000
X-MC-Unique: HB0JS3AuOO2RQEe5DAakJQ-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) with Microsoft SMTP
 Server (TLS) id 15.0.1497.2; Thu, 18 Mar 2021 09:14:27 +0000
Received: from AcuMS.Aculab.com ([fe80::994c:f5c2:35d6:9b65]) by
 AcuMS.aculab.com ([fe80::994c:f5c2:35d6:9b65%12]) with mapi id
 15.00.1497.012; Thu, 18 Mar 2021 09:14:27 +0000
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
Thread-Index: AQHXGnrjHw0GM4Y/B0GSBDFCMZ5+u6qIIzEwgABPpACAAQUwQA==
Date: Thu, 18 Mar 2021 09:14:27 +0000
Message-ID: <4f7becfe2b6e4263be83b5ee461b5732@AcuMS.aculab.com>
References: <20210303121157.3430807-1-elver@google.com>
 <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com>
 <c1fea2e6-4acf-1fff-07ff-1b430169f22f@csgroup.eu>
 <20210316153320.GF16691@gate.crashing.org>
 <3f624e5b-567d-70f9-322f-e721b2df508b@csgroup.eu>
 <6d4b370dc76543f2ba8ad7c6dcdfc7af@AcuMS.aculab.com>
 <001a139e-d4fa-2fd7-348f-173392210dfd@csgroup.eu>
In-Reply-To: <001a139e-d4fa-2fd7-348f-173392210dfd@csgroup.eu>
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
Content-Transfer-Encoding: quoted-printable
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

From: Christophe Leroy
> Sent: 17 March 2021 17:35
>=20
> Le 17/03/2021 =C3=A0 13:51, David Laight a =C3=A9crit=C2=A0:
> > From: Christophe Leroy
> >> Sent: 16 March 2021 15:41
> > ...
> >>>> include/linux/types.h:typedef __kernel_ptrdiff_t	ptrdiff_t;
> >>>>
> >>>> And get:
> >>>>
> >>>>     CC      mm/kfence/report.o
> >>>> In file included from ./include/linux/printk.h:7,
> >>>>                    from ./include/linux/kernel.h:16,
> >>>>                    from mm/kfence/report.c:10:
> >>>> mm/kfence/report.c: In function 'kfence_report_error':
> >>>> ./include/linux/kern_levels.h:5:18: warning: format '%td' expects ar=
gument
> >>>> of type 'ptrdiff_t', but argument 6 has type 'long int' [-Wformat=3D=
]
> >>>
> >>> This is declared as
> >>>           const ptrdiff_t object_index =3D meta ? meta - kfence_metad=
ata : -1;
> >>> so maybe something with that goes wrong?  What happens if you delete =
the
> >>> (useless) "const" here?
> >
> > The obvious thing to try is changing it to 'int'.
> > That will break 64bit builds, but if it fixes the 32bit one
> > it will tell you what type gcc is expecting.
> >
>=20
> Yes, if defining 'object_index' as int, gcc is happy.
> If removing the powerpc re-definition of ptrdiff_t typedef in
> https://elixir.bootlin.com/linux/v5.12-rc3/source/arch/powerpc/include/ua=
pi/asm/posix_types.h , it
> works great as well.
>=20
> So seems like gcc doesn't take into account the typedef behind ptrdiff_t,=
 it just expects it to be
> int on 32 bits ?

gcc never cares how ptrdiff_t (or any of the related types) is defined
it requires int or long for the format depending on the architecture.
The error message will say ptrdiff_t or size_t (etc) - but that is just
in the error message.

So the ppc32 uapi definition of __kernel_ptrdiff_t is wrong.
However it is probably set in stone.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1=
PT, UK
Registration No: 1397386 (Wales)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4f7becfe2b6e4263be83b5ee461b5732%40AcuMS.aculab.com.
