Return-Path: <kasan-dev+bncBDLKPY4HVQKBBKV7ZSBAMGQENL55FPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CDA8340239
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 10:38:51 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id d16sf16093170lja.12
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 02:38:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616060330; cv=pass;
        d=google.com; s=arc-20160816;
        b=LzShFuuHQMLOUTeCBOV/9gA32BLNbV4ejtng8ZSQyU5PEf1ZnIJ7o845JGkobO/OO1
         flTi72u3JOQQkLuGXjiDvlayyVGKLX52oDUFIvWWm3zYWJN005Uchzr0Yul8tqKFMhHz
         qbc/VIF8HB8pfASC82kR5/auSu+B1LYFXitU81RrTtuxDIoCefjnXS4Z/Q9+WS1RxRua
         uDtaTflMkoamwEFC1LtG0GudZ4WCqjfVmeFh19vxFGpZJms0KRqGGnF4nMbI8hzJv2R0
         J3SB9trO2Dq5pfd+//zz6WvhZ6C8hDo62nhg1jAY/HOoDN3/WQ/FE5PPaUEKb9mNxh5J
         NRzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=/0HeIvuPxlaNH4QRLZX78jdrHz4E6wLQBr1BXnYweEQ=;
        b=eAVIIKIVoH371zHFV1qSoZ4Z0W3xuQd4/dhzOPQDXil69gqR9Dwf5YaISirT5XfoLk
         XsbauTJwet46biUi9M4hv8EqeKUN7+He19bSz1HjocT1g3RoZHmIwx7YcCSOj/M2+3cu
         xWahAH1AL5vHSwFMPU+50vQ20Fck0NmU2jaLxMBxEbayh1T5pCUY1mD5pKrXGn7f6Myf
         ifQizZN4DPO6cfjqHMMqaiAa8Z6q/+6DU3t23j/hmhUjQ8QimUhCoMLBhevlUgVGHO/E
         r9kGde1l6EkK4X/S4HVte+2aAQOqW0OUTbQYUkYnixPB8MPSMdMvfId+IhAGjMFD8fLl
         ZFoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/0HeIvuPxlaNH4QRLZX78jdrHz4E6wLQBr1BXnYweEQ=;
        b=e3fDyp6/ZgTMu93EdGgj9Sy4ny3qE3LHOi242FjN2s9Ekir3RnihyHAe/kBCpMbS7R
         6XfZufhuhU340dXzm+fIRKgr5S8KVBHHXAdjT9aJJpv//HnJJ1KdumhK64aor3uoaTJV
         8ryEVAvnXai0rIjcichWKWfxezj/w/CkreqIOSWpGj+mQNJgfIcCv7wHtjvVaRL0FTRa
         QdJcrNYcrEVIO7TVWfrgdjxQQF7NRK7WDx8Nvo2VKer0mr+EFyoJ3COTwkTFbeosCvco
         TvVCJlCG85VP3bc80KKu+C/Mqq64cP/BDaHHYRH5jie6TcAGKkysPrNf4J0czHubtpeD
         B5lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/0HeIvuPxlaNH4QRLZX78jdrHz4E6wLQBr1BXnYweEQ=;
        b=fS5OgUFBQ/qDFjdds1LZtovNMufCF7c2U/ATLoHEUuG/afGPI3Gcym7tN1JbRqW6JQ
         vMB19Wffg9kD07LIFSmNvkI1Hqe2+Mrv8R9upk29jph4WBfrIf9nSc2w3GJAumyWFZpf
         NOf03Yyk6AV78QIXh+gcT0jrTD1zpU/sU/rLajgsUJ/vtXpuF6/jT1hDLnTj6Mnu889v
         DJepYwbXZriDQGUlG3iXc1FwCv26n2t9rTd/cymdFtQ4lbiCmzMg0AZZENMuWYRKW1qp
         wzlA9Wl5BevRYHC19goDJ5vjXPAxQ+g0wprQjlZyl50cMI2Hh32bqe+rG2GRozAZleN7
         +9QQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Htc4nPksEoHwTxSyHLMri5I0IN/wgvQ09y6c5cV3TPvMLrTjG
	E+gWhrBl0aW+1NW6rnB2Wlc=
X-Google-Smtp-Source: ABdhPJxj0xCv3+71ETKyZ9yfp/cIPOykQtL1KsHnOhFsLjyNHuW+BFosdZ662BftDlxHiadCz/yiKw==
X-Received: by 2002:a05:6512:11cc:: with SMTP id h12mr1336272lfr.567.1616060330669;
        Thu, 18 Mar 2021 02:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc23:: with SMTP id b35ls199173ljf.7.gmail; Thu, 18 Mar
 2021 02:38:49 -0700 (PDT)
X-Received: by 2002:a2e:88cc:: with SMTP id a12mr4722237ljk.402.1616060329397;
        Thu, 18 Mar 2021 02:38:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616060329; cv=none;
        d=google.com; s=arc-20160816;
        b=orFtaEV8qz6GX/kJwnrHwq+BpwSTzOToDgX5xkhCcv8gQPN6yxbaVkjwYuMyHycGJ+
         QmJbwKh/RtFgSWnSjmnb6/2BJ+JJ8mdaJwt2M0BhDdmtCp6jpLWYFDa5vXIgJor/3Oy1
         a+2rne8u12g5sz9z0OlyCeLSs71PRQ7UwuIYJXUh17Dzu2rZfUSdvLWDtrlabdOYUTpL
         NE0iInVWgGhqOGxmlwhuMpWEs32ecc+EB8a4jIjAcqoVbFy4dEm8DjSguknhH+FzjxbN
         bKNpu36lX3Cf8TjZKl5B9gEXdjtpvM8J4Cn0VYbM+RewKlU8JxjgDbjJ4vkfsd9Ch5YR
         odjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=9UaQ/q9qxJhPNgHrYAwfdQCEMy+e3tMoj2NQfRnvREc=;
        b=QwzwSATE/zWdTJxltJXLTbEwB57hlfLGMKDJjzgAkNGL+vrSCJLQj0+Ff2GJBN0tGG
         Yd9FkKqTrh2AWXP1tgKWLnv5PC1FiFqJRC+dnd8MeLkRZbcUtLVnoOygMD17ExURFzOO
         BoJh5BbOhZtW8m0X2bu1PmAt7koF4vaZ4w6Icthpfm8rdujeflk+mOtitZ2mSv/84ous
         u5J7DEvqp1EuCzBJFNuM+Dg5Egrrai28vfSiVyRFrRKxhyzAXDACOfDeCVoUpIV3e+fV
         HZ2dUlhIpSNTIQkLlMXqsVnm5HE9wydmpFlxU6gCJ/9qhtpb4t1imDfVND4uEQMsjPlG
         mpVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id o10si81733lfg.12.2021.03.18.02.38.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Mar 2021 02:38:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4F1MRB6KJyz9twcf;
	Thu, 18 Mar 2021 10:38:46 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id Y-YcfSLncL4O; Thu, 18 Mar 2021 10:38:46 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4F1MRB4pdHz9twcd;
	Thu, 18 Mar 2021 10:38:46 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BEB3E8B8C9;
	Thu, 18 Mar 2021 10:38:47 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id feJZioXZgfgZ; Thu, 18 Mar 2021 10:38:47 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1693B8B881;
	Thu, 18 Mar 2021 10:38:47 +0100 (CET)
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
 <001a139e-d4fa-2fd7-348f-173392210dfd@csgroup.eu>
 <4f7becfe2b6e4263be83b5ee461b5732@AcuMS.aculab.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <e4577151-bc73-5033-a9ed-114dd0c1aaaf@csgroup.eu>
Date: Thu, 18 Mar 2021 10:38:43 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <4f7becfe2b6e4263be83b5ee461b5732@AcuMS.aculab.com>
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



Le 18/03/2021 =C3=A0 10:14, David Laight a =C3=A9crit=C2=A0:
> From: Christophe Leroy
>> Sent: 17 March 2021 17:35
>>
>> Le 17/03/2021 =C3=A0 13:51, David Laight a =C3=A9crit=C2=A0:
>>> From: Christophe Leroy
>>>> Sent: 16 March 2021 15:41
>>> ...
>>>>>> include/linux/types.h:typedef __kernel_ptrdiff_t	ptrdiff_t;
>>>>>>
>>>>>> And get:
>>>>>>
>>>>>>      CC      mm/kfence/report.o
>>>>>> In file included from ./include/linux/printk.h:7,
>>>>>>                     from ./include/linux/kernel.h:16,
>>>>>>                     from mm/kfence/report.c:10:
>>>>>> mm/kfence/report.c: In function 'kfence_report_error':
>>>>>> ./include/linux/kern_levels.h:5:18: warning: format '%td' expects ar=
gument
>>>>>> of type 'ptrdiff_t', but argument 6 has type 'long int' [-Wformat=3D=
]
>>>>>
>>>>> This is declared as
>>>>>            const ptrdiff_t object_index =3D meta ? meta - kfence_meta=
data : -1;
>>>>> so maybe something with that goes wrong?  What happens if you delete =
the
>>>>> (useless) "const" here?
>>>
>>> The obvious thing to try is changing it to 'int'.
>>> That will break 64bit builds, but if it fixes the 32bit one
>>> it will tell you what type gcc is expecting.
>>>
>>
>> Yes, if defining 'object_index' as int, gcc is happy.
>> If removing the powerpc re-definition of ptrdiff_t typedef in
>> https://elixir.bootlin.com/linux/v5.12-rc3/source/arch/powerpc/include/u=
api/asm/posix_types.h , it
>> works great as well.
>>
>> So seems like gcc doesn't take into account the typedef behind ptrdiff_t=
, it just expects it to be
>> int on 32 bits ?
>=20
> gcc never cares how ptrdiff_t (or any of the related types) is defined
> it requires int or long for the format depending on the architecture.
> The error message will say ptrdiff_t or size_t (etc) - but that is just
> in the error message.
>=20
> So the ppc32 uapi definition of __kernel_ptrdiff_t is wrong.
> However it is probably set in stone.
>=20

Yes it seems to be wrong. It was changed by commit d27dfd3887 ("Import pre2=
.0.8"), so that's long=20
time ago. Before that it was an 'int' for ppc32.

gcc provides ptrdiff_t in stddef.h via __PTRDIFF_TYPE__
gcc defined __PTRDIFF_TYPE__ as 'int' at build time.

Should we fix it in arch/powerpc/include/uapi/asm/posix_types.h ? Anyway 'l=
ong' and 'int' makes no=20
functionnal difference on 32 bits so there should be no impact for users if=
 any.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e4577151-bc73-5033-a9ed-114dd0c1aaaf%40csgroup.eu.
