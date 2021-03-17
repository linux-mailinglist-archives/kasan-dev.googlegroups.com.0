Return-Path: <kasan-dev+bncBDLKPY4HVQKBBL74ZCBAMGQEHDX76LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B110E33F72E
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 18:36:48 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id a22sf15351467ljq.4
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 10:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616002608; cv=pass;
        d=google.com; s=arc-20160816;
        b=uX1e3EabJ16AvEZcGZpLZEtNzrnW9MKet62FdT+1AIuudQkcpPqwSyJxpHZO3HN1J3
         jSbF6YjMF10WmuuUBXCbSMvNhunpbl8nvoq1u7sXAyr9Ubf2iuyw2ec67vuaTAzUVzkn
         aTYCGZPrnLKQQAFIVo9p0qKqT2T1TsIR8adSpfGR4yz8YMQP366DN/Snm9wPKboIsZ0q
         ivhxyEJN1YVBbCFSY/vG9EyvaPE4evcjlmqQoSs4HBB1AvKaIS5teiWttoGzw0gJXnd9
         L6NNiVq3eHRGONh/t7ktgNALiaD0t4KvhlSklIaUHaa1RTiCpCQTBvi9EQAP95fpA1MS
         0NEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=HdRwE3FAuhzWHMqlmlZ3VXvWKHIPhQXkHROFVf2yVyk=;
        b=Fj2LgEAdUlr7aeEAMNtTj0ZK1DwU+sHfltDyW6EjQZGSxsbqIwNzsmYwAP8coqDgU0
         tcCKjO2/f/xDnZuzaPQp12hmWSDl2x1LIz8M70Yr8TNlpeIMOUYvujFE0WI5RDR8/QnM
         9IrtmhlpSLmzla15RfHLahGKj3qWqp7XcHtL+cSotuNPVux9IxkT2bF1rX2VIp6ee1Ef
         5u7uRjtIKCz8v6Puq/ObOoESu8xeDFZtSU1UCk/EHdxOueURgEg667C1KYXVeqZnSbdL
         rNH61alzhjlrD20pkeiJh77/SrH9Kv26MP1B5IOjyMVj8FUwpaHGHteRY0jhnSartzWg
         437g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HdRwE3FAuhzWHMqlmlZ3VXvWKHIPhQXkHROFVf2yVyk=;
        b=RWa6xhc5aRX5P0RNp48Xum7OcYvCSKHfKZ77EwfTAYnkCKdY+sgi63zZL9pqX4jeb4
         qsZClrZweiJb28bYbkVrOlgLZFfbKOthYpHrGFwQs2XQw2gxJ07IVMtz7Dup7eU0IGHS
         EqXd/cm1Xj1H06Gz95gZrgxA1706Nw/3e2cvV1ZVOskOQqz5CvAcMYzD/mYX+eDTB/vg
         jq+vfiIlKIathdN3+hzK2CAzBfyhudtQNF2RkpPK84ucNqokXs8eYpfX5AKqK5Nq68Y3
         hMzTAnlmZof/vGDsVQUfjgQ3NpCEWVix6PWReAFIdtXbqqTjLFU9Z1EYCr1rxZ/w02KY
         qmsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HdRwE3FAuhzWHMqlmlZ3VXvWKHIPhQXkHROFVf2yVyk=;
        b=uCiEVw0jEwe0uQ6xdBScr1ory24Jcif5rppTn+t+ntJygUa6lK/3FK6z2Y2l7o4t8J
         aYC303cl/eRS6l+nyLPAA9USOdEDyv8AQGs2Cqlmvz4eIOwl/rfdpDw9jLOf0vGlx6dK
         VIFv9b8nl4XA7ANSokvesi9z8lN0Bv4fpHNMZRhOSz8cU9HBkNLTSTNZ9BO7ckng+GU1
         VtSIDKSMCyJzi9VPoiQkekDAH65dA+n8e9LEE3lV3qRH8EeEb5XMmPivbB5+Kn6aOr45
         PsP97PpdcCGpXMZbD0ZyUlBbksduiLND+4OCcNJhl7vHOg2ZnEcQEh3vWoLJpgwOmQyU
         8q+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308LEoavTCUt7lLEP3x1vEAY+kfEX2POdSF/5dFjPT9LeLRL5c8
	lCRIkEOdrJgL9iI2FCIGTJQ=
X-Google-Smtp-Source: ABdhPJyYqlEyQfNINz69LGBItPBGKKYp7wSwhhlMFurzd9vPelSbkpn8GkpDI7lmonElXnW3ANwkpA==
X-Received: by 2002:ac2:5449:: with SMTP id d9mr2799205lfn.172.1616002608158;
        Wed, 17 Mar 2021 10:36:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a409:: with SMTP id p9ls5119014ljn.0.gmail; Wed, 17 Mar
 2021 10:36:47 -0700 (PDT)
X-Received: by 2002:a2e:8111:: with SMTP id d17mr2994940ljg.337.1616002607133;
        Wed, 17 Mar 2021 10:36:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616002607; cv=none;
        d=google.com; s=arc-20160816;
        b=A0NEr11B8f895JtlwmDnYDFOQays3JvOHwS0ah5ejGjizSX2H29eQMyW/DlwA+Pbx4
         c3TcQHB2z3pxkztG9ijkdEyDvaBuUnMWOmnENoc5NiNfRBtl7AgZ8Sfdz9pcesaHTqPs
         QH+b3PLd+8TRfz6q9Q+u4m6Q+cocxaK45nGEsLtqkWGJ6tZ1CL8pl4LCKboFtHOT0LmL
         ZjTZs7QCibb/MG01sljrIDVQ7MMDLvi2EIOYuJv4QYvM6GmQQgSFqi8p8nXpbQnK3SYu
         s/oz9/JDG6yqdKLAki3YwKzqH/vBHjcCou6J8fgzTQyPleSwz7SHWhgO5UVL2tk7OGFz
         sDyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=AzTEWxmNmU3hbpnceWVIAg+pttmNO9Y+1+/03Y2x+fE=;
        b=Ww6qJw+Fr7nHw9blCftWX0cOfKw5oRhKoIwARc44vYF63OiM4HILIB5URBE/QERIw7
         EyX2lwOcNH06fIvNWF1sl9aXx+amqZ5IcRUaIvEyEmJdnnge3BB6YM3yA63wYnqIzZO6
         CnozMM+v+3BZqmzNh7AO9+ZER+h4NbmkSR4ip4PeV0V4CS+nFfLFrxJBqXdbK1QDl6C/
         /I5g3aIUGXrQi8VBGuZbhXiJh2x+kN4Poaup7vNw2aXYlw1hjWNkRWfZ28l8P/7s/MaI
         nCwlV50AOvglCL1VETF8VdOrmO5CHWpfilT8tAxorYwnRZ84NwLFMTx31jTDmtj/4dLD
         uO4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id z2si777869ljm.0.2021.03.17.10.36.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Mar 2021 10:36:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4F0y583vFpzB09Zd;
	Wed, 17 Mar 2021 18:36:44 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id v-2_sLTpHPTF; Wed, 17 Mar 2021 18:36:44 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4F0y582RpmzB09Zb;
	Wed, 17 Mar 2021 18:36:44 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 213F28B866;
	Wed, 17 Mar 2021 18:36:46 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ARYtUs8FK9Ly; Wed, 17 Mar 2021 18:36:46 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 5F7D28B865;
	Wed, 17 Mar 2021 18:36:45 +0100 (CET)
Subject: Re: [PATCH mm] kfence: fix printk format for ptrdiff_t
To: David Laight <David.Laight@ACULAB.COM>,
 Segher Boessenkool <segher@kernel.crashing.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Dmitriy Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@google.com>, Jann Horn <jannh@google.com>,
 LKML <linux-kernel@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20210303121157.3430807-1-elver@google.com>
 <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com>
 <c1fea2e6-4acf-1fff-07ff-1b430169f22f@csgroup.eu>
 <20210316153320.GF16691@gate.crashing.org>
 <3f624e5b-567d-70f9-322f-e721b2df508b@csgroup.eu>
 <6d4b370dc76543f2ba8ad7c6dcdfc7af@AcuMS.aculab.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <001a139e-d4fa-2fd7-348f-173392210dfd@csgroup.eu>
Date: Wed, 17 Mar 2021 18:35:18 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <6d4b370dc76543f2ba8ad7c6dcdfc7af@AcuMS.aculab.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 17/03/2021 =C3=A0 13:51, David Laight a =C3=A9crit=C2=A0:
> From: Christophe Leroy
>> Sent: 16 March 2021 15:41
> ...
>>>> include/linux/types.h:typedef __kernel_ptrdiff_t	ptrdiff_t;
>>>>
>>>> And get:
>>>>
>>>>     CC      mm/kfence/report.o
>>>> In file included from ./include/linux/printk.h:7,
>>>>                    from ./include/linux/kernel.h:16,
>>>>                    from mm/kfence/report.c:10:
>>>> mm/kfence/report.c: In function 'kfence_report_error':
>>>> ./include/linux/kern_levels.h:5:18: warning: format '%td' expects argu=
ment
>>>> of type 'ptrdiff_t', but argument 6 has type 'long int' [-Wformat=3D]
>>>
>>> This is declared as
>>>           const ptrdiff_t object_index =3D meta ? meta - kfence_metadat=
a : -1;
>>> so maybe something with that goes wrong?  What happens if you delete th=
e
>>> (useless) "const" here?
>=20
> The obvious thing to try is changing it to 'int'.
> That will break 64bit builds, but if it fixes the 32bit one
> it will tell you what type gcc is expecting.
>=20

Yes, if defining 'object_index' as int, gcc is happy.
If removing the powerpc re-definition of ptrdiff_t typedef in=20
https://elixir.bootlin.com/linux/v5.12-rc3/source/arch/powerpc/include/uapi=
/asm/posix_types.h , it=20
works great as well.

So seems like gcc doesn't take into account the typedef behind ptrdiff_t, i=
t just expects it to be=20
int on 32 bits ?

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/001a139e-d4fa-2fd7-348f-173392210dfd%40csgroup.eu.
