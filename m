Return-Path: <kasan-dev+bncBC27HSOJ44LBBFGNRWFAMGQEJA53FII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id DE22640DE60
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 17:45:25 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id q22-20020a63e956000000b002524787adb1sf5589649pgj.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 08:45:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631807124; cv=pass;
        d=google.com; s=arc-20160816;
        b=0bgUxdkwqwLMtN4hbOp+G5TGa0vp266DUkk2QAtZSmmF+oiRnS80qtFnZhFzNhG5s4
         4J5h/4aLTWjczFf2h93VI/QC+KeAb5oDxL7Wl3J1QuUiAzz4D7cr+nFe9xyp3lW6MQyG
         O4tRlC1hN2rw5QJBLot/9KqHur/JPSB8zDMVtswSXaClL2Ksih0zS+B1L8R2vg4Xx3ha
         ihe2KyXXRlXEiPVR5jU1oGXp0dhvSmltpoXENV15T4kYlpIXm71uiD89erLVS5SiS5HD
         erDaexPMSrNxfqNFVk7goSjoaEMSZwDNnDNS2iDz+kEJMsKy6bpRTIW5NCB010Ffanls
         FfrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:sender:dkim-signature;
        bh=R0WJxpQRD9Q3o/+Xn6ZisXML/mkk3LgKyx5NSeOgDfw=;
        b=FWokAojLXl/5IgA7i41pQHAfP8c2PFbLWz5jlshhLhmmF72u+3HbOMigB1fht+JpD4
         piwWN1fSLyoVDiFt2oO56wHNk4BwiZBP5R87GA/dwjq11CQGMG8xd7xYjVETwZww4UpA
         NcwauzV7XaCr5BC84rh/mIKVCYncuhi2zGr5vjCNqaFHQ+OoGeR9GS4yMIIsl48xbGRu
         yJaQgpIuTnnFeETgzRGCoLce57rFIK7JRRqDdIbs928bf3hakoR+o/dJVDerKoVyjCAv
         zXNjhSKM/0QrgjJSVyEi5yJffQSbS0f8eLqA7IAwR+KxdQQtL3MHLGu09O9AGJg+3zrF
         55sQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R0WJxpQRD9Q3o/+Xn6ZisXML/mkk3LgKyx5NSeOgDfw=;
        b=DQrc4LYouKi/GXCHXvg0TUSYTNs5cxgYP35JcSzoyd49ePfWXPF4klz19rRi3PImCp
         jBPSj9mfpTzAWpg1umxrK/RWEP6/GJuoTXWPmvEH1SNM00SbRWYEd7VXVx1fwRmxt7Se
         UdJe9uwe2IyvDayBrOrc2nGj7BGcgSo9h6PKRVHagdUOGSwVgn9jJ4yNcQTvhfSoVtXO
         KAmyDRQ3GwbME09NAeSqeMs8jS6cPuMeKdggnYLFHMr/8NnYZlnevj9fVudbmzMe+td9
         WbbSDgCKlJhyvIkAK8y8uhBPsMH0qnkFVlauoDGcUl+FidShHW8HnZiJ54hevEgqqM3p
         uRdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=R0WJxpQRD9Q3o/+Xn6ZisXML/mkk3LgKyx5NSeOgDfw=;
        b=18lMrVP4c4LkWJX53wq13ggKnx9WB9QgNvaSDOhEUAtDwTu7NJjVvsOSuDYPLhi6qx
         eXlf8uS+a383b5XovdSgfcW5i1nstCqxWzAyHSoH1iKJhwPD7c/tjA6EOjM5f/X4DGgD
         wQBOLpuHjIVO0Kt7A2TMhNK+bwSWwDPDYYWzmrXGNl3TVXqwOEGwkhGNw8+cR+0ZcVNt
         EJRVLL9CYkfK9YCatQMfZxFUtOtb+eI2wsFRxpFSC7ljp56EHBX2LnErdklspBcLOUEJ
         ggTeSHl46i41qcJHgkPmM2uylvp2d0aoGe7wizIXCed7nCpSdJazxIIGo32n+v1bSdU7
         Q8fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530T0tlFUkrRpWzQnB5RyZPX3BwVHrT84hgF6NpensI9klnomAiz
	DzfsLnaGJ2T7xr1Db2N+wwM=
X-Google-Smtp-Source: ABdhPJwBbt7bfjEY2TBA5Ond+eGNHgRu+qsM9sIDSKGJbUG/OVWzaVhoVzJrulwpzBLSe2ebyERT0g==
X-Received: by 2002:a17:90a:1a52:: with SMTP id 18mr15758189pjl.43.1631807124625;
        Thu, 16 Sep 2021 08:45:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:520c:: with SMTP id o12ls1738162pgp.6.gmail; Thu, 16 Sep
 2021 08:45:24 -0700 (PDT)
X-Received: by 2002:aa7:825a:0:b0:43e:124e:5c1e with SMTP id e26-20020aa7825a000000b0043e124e5c1emr5804952pfn.76.1631807123965;
        Thu, 16 Sep 2021 08:45:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631807123; cv=none;
        d=google.com; s=arc-20160816;
        b=RfiCguFZInjpm797B6Z7I7LjYqgl4uhcEuf0tWWyz3O/E8WlEbTuvZp9tlXd6NSibc
         JcMrx0XtH7xhyydQG5joHbZv/41X35b8RLzDjzNWmCWvNPAVU5uhgQBAD2NCm9oFibJ1
         jlKH5uZo+aTd71qfPBU4b6815UcY1OwfK05oNR7cMn0AoBNOUKUHHNR4HEHtpbofW3b/
         6vbTHElCz93yNrvCkYGJwVDZOg2Ph1AIpKCgikrxvRYy5/l30+Dapl/09wc68BawmxdU
         UT8HAwNskYtgNVDnAe4H0MZroVDt5kI7jzGcXu0Kqp3qKQjWV/gJ37aVPU3uWE6xWfA1
         Zezw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=x373u+HnYlvTxtTs67xHGzLNYvHOi01YHMTrM5pKsXI=;
        b=WFqUZShN+i9Pv0n/WzvIuRUMxdLUkvS+X/E9F0neZMJ+ME13Eoeybww3hmTw0bN2dr
         cIAfSaNGWncq7uwLKS0gGBb/pc1leOTausqqOh7VNoqud1Yw2ltf7Rers0KcCpx6M2zb
         3tHuSIAk7PrkclOKhZyIf5C+J/oi94py2ekOybFWVVxdS5TIaMrneWrXbTG0SHDCQ/at
         ZGuEvXT7mdisUdQD9sKi0+QhLtcwp/gKjWh+5FVpsK2ARpXe7oeZC65PQErTySFN/UEW
         ES4S9C6dW8l9QEYPObAuaJEVTGe44VnxZ3I33RjZwLs2OOcqtCJ57HjUM3G+72gN32NC
         LFrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id m9si353425pgl.4.2021.09.16.08.45.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Sep 2021 08:45:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-73-hC-drbRkMRy1ELWZmsZWpA-1; Thu, 16 Sep 2021 16:45:17 +0100
X-MC-Unique: hC-drbRkMRy1ELWZmsZWpA-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) with Microsoft SMTP
 Server (TLS) id 15.0.1497.23; Thu, 16 Sep 2021 16:45:16 +0100
Received: from AcuMS.Aculab.com ([fe80::994c:f5c2:35d6:9b65]) by
 AcuMS.aculab.com ([fe80::994c:f5c2:35d6:9b65%12]) with mapi id
 15.00.1497.023; Thu, 16 Sep 2021 16:45:16 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Kefeng Wang' <wangkefeng.wang@huawei.com>, Marco Elver
	<elver@google.com>, "akpm@linux-foundation.org" <akpm@linux-foundation.org>
CC: "glider@google.com" <glider@google.com>, "dvyukov@google.com"
	<dvyukov@google.com>, "jannh@google.com" <jannh@google.com>,
	"mark.rutland@arm.com" <mark.rutland@arm.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "hdanton@sina.com"
	<hdanton@sina.com>
Subject: RE: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
Thread-Topic: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
Thread-Index: AQHXqpka6XGQNXcc7UiTXkG8ZB1Ri6umzYQg
Date: Thu, 16 Sep 2021 15:45:16 +0000
Message-ID: <858909f98f33478891056a840ad68b9f@AcuMS.aculab.com>
References: <20210421105132.3965998-1-elver@google.com>
 <20210421105132.3965998-3-elver@google.com>
 <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com>
 <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
In-Reply-To: <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
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
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
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

From: Kefeng Wang
> Sent: 16 September 2021 02:21
>=20
> We found kfence_test will fails=C2=A0 on ARM64 with this patch with/witho=
ut
> CONFIG_DETECT_HUNG_TASK,
>=20
> Any thought ?
>=20
...
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Enable static key, and await allocat=
ion to happen. */
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static_branch_enable(&kfence_allocation=
_key);
> >> =C2=A0 -=C2=A0=C2=A0=C2=A0 wait_event_timeout(allocation_wait, atomic_=
read(&kfence_allocation_gate), HZ);
> >> +=C2=A0=C2=A0=C2=A0 if (sysctl_hung_task_timeout_secs) {
> >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
> >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * During low activit=
y with no allocations we might wait a
> >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * while; let's avoid=
 the hung task warning.
> >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
> >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 wait_event_timeout(allocat=
ion_wait, atomic_read(&kfence_allocation_gate),
> >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 sysctl_hung_task_timeout_secs * HZ =
/ 2);
> >> +=C2=A0=C2=A0=C2=A0 } else {
> >> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 wait_event(allocation_wait=
, atomic_read(&kfence_allocation_gate));
> >> +=C2=A0=C2=A0=C2=A0 }
> >> =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Disable static key and reset =
timer. */
> >> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 static_branch_disable(&kfence_allocatio=
n_key);

It has replaced a wait_event_timeout() with a wait_event().

That probably isn't intended.
Although I'd expect their to be some test for the wait being
signalled or timing out.

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
kasan-dev/858909f98f33478891056a840ad68b9f%40AcuMS.aculab.com.
