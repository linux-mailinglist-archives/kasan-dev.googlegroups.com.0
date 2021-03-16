Return-Path: <kasan-dev+bncBDLKPY4HVQKBBEVDYOBAMGQEVW5A22Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id BB34433D7D1
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 16:41:06 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id m23sf11841113wrh.7
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 08:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615909266; cv=pass;
        d=google.com; s=arc-20160816;
        b=XgZ14x3aSgb+OlqpvxciPullnDPUEFtwIccjqszJDjKT6K5veJ+UN1wh2LbzcQyaxi
         HUh3n497VjUbux5OXqt6USsqCeSf3zMg6KXdx6llBaWv76xe1qUJzcI8ndxng064F4VL
         DqtiqevWRHyHSUVMYF22+d/XuqmHpWlH/VOIf2ymwjrh7ZrzyV6z03JOpqvE2M/Uv/ln
         QIsJ9ISBtOK27VOtfdJdTm0FUhRfsm1ToUWJS8PVUyi3HAkZk+8CO1eFdNEB/+Gi3OKZ
         Ye3UCqyV8/DvY+4A3GdAYhh1LF/p/S3C6ypRS56QP0t96lVvctmx5+KkSnnGdH/6YiwA
         Y4zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=OJX4S9Yxzb92/NoXJN5RhSViMmVb0g/UthwbBFSv7go=;
        b=K4R4g8WiBlWRXN0XWcZxYIsLaZ/t/itHHTUR8cLcjdfbvkkPMyd/i758qnRbkWATRv
         KHe3PcZYpjvcZiWsYjO7HawSE3emsbKc82dKHzMjQ42bq1NG37Fc6wrAZRz/+VXU+7aT
         N1I83AuPs9Py+xN2UOKyXWvGhhu/6R99Hu9KhCwjdTb8DfipNE+pCd2L/CfeCrJUrxBR
         LbIVi6QsXcrSeaefGM2gMEStlA5i4ay4aH/w4KJy9sKKTlr7I9JmKksf1H+7nRE7CSpX
         xpVUWYsbPeYLJaD4X3kz4RsqJXGXn/mDonRNw2nbVirxXpmgUzzRAFwH4FiSuj3c7yB8
         fT1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OJX4S9Yxzb92/NoXJN5RhSViMmVb0g/UthwbBFSv7go=;
        b=IPhbddmUDB5bdTVwjk94spsrKx4E+Pnzs2W+MWX2/Z2mNmy8pC98ublEvkBzWbD991
         A2Ge8a5E7sS4ksf2dLhNtWe31lUwC0OVyfignyOmGI5zDVFNj9SUvJnxy0LVaGCh/Jhy
         QMWHw/RzcSS5k8MgAJ+k4jtcCOFzpF4+7jz2k0ilHPyf0ee37Ip/jadXc1GxH7gjk57O
         fsIxXYb/IxM5JfpyWg61Trmv/WqiPtrxrLVQqqWJk8F5e3A8oGXNDnPbQIzJIYig94Im
         uaKKgiEJo7e+Q21iO2ytRzyVcbVjUr2HUGKHMVnPdgEUJFm2KX3NsjtimgsfRXpNlfS/
         geDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OJX4S9Yxzb92/NoXJN5RhSViMmVb0g/UthwbBFSv7go=;
        b=Pb3BQd1RYLoFQ5gaRr9dGCzCNRiFLsyu7gDxjeU9W2nOOV1LzkJ2y8QB+rZMu4O2xc
         5tPWL8XHVuF5NMemHjO3ucAwryLhagQfVI04uZL5+2ZjpfGiccgzpO7fBZ++zHYaZrEG
         btK+f6VlXChxfvoNcOiBcJKhYpAFBbBRZGdtwoDfJMUW4pZeGeL1iqX9f+mG4dOAdyKZ
         voyCOwYAHNKfRX5nLf4jcoNQcPlU9FzsCB/RR6S0/YwruQq5HvBYQGZCBvzxOUbMCCwI
         5L0CAbPFKH9pES9DTwLEZj8Q7+3TLeGDh2Wxmg+yMwT8NeOYbBH1boGGgeAP7DUrxo+B
         c3DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/4TlmGqbbUoDTHcPwderJV6q13oTFCCr3+7WhIHIvS3G6iFj4
	u667b9xw9TMu0Xpm5KhsHUk=
X-Google-Smtp-Source: ABdhPJw2Pn9vRNp0OsV+25WjRSAskNfGlK1fylClJHVE7InQMYg1PhgjtXGWJmA53gyNI33Mv8Gy5w==
X-Received: by 2002:a1c:bdc2:: with SMTP id n185mr264433wmf.128.1615909266539;
        Tue, 16 Mar 2021 08:41:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1986:: with SMTP id t6ls2189081wmq.1.gmail; Tue, 16
 Mar 2021 08:41:05 -0700 (PDT)
X-Received: by 2002:a1c:1f04:: with SMTP id f4mr284598wmf.12.1615909265673;
        Tue, 16 Mar 2021 08:41:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615909265; cv=none;
        d=google.com; s=arc-20160816;
        b=XNh9jHwi2rpBigrptsPf6mg9ZZXcHjDYz/1b3gqZaseJukYV6GTv78fgT3Xe+Bfgl2
         sihn55d3jYg8ZZt+1Qzm9XrOQWGTYeY8CNlFHG01U94w2YafZV9VZgDDHJCIWoJbzBs8
         MDQoMZJU+QtDOJ5fq68hktv3tEvPUextuHmzMV+30A25MX8baBFE5KVxVhJDkFwhdrQb
         4F+FHUG1nQSWmYes99J3qOZL+edKuMuX3UbGUcpNmhrJvCKMRiw4HFb/2F1iiqdLkbfi
         cM8h6AvNJs8ua4t8yjDtu1xdtoNs2VFLrh/iRmHbmWeRrCxOiQvIsgBzLUv08YNndLOg
         b3CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Lw/trWAsWdql0Ew17J4oyBvFrsw1fdHkFOfSE8nCD1s=;
        b=KjLULoMH5Y8msa74nsqCLEv990Z7ivmnPgcZzq7Zalbyx8/8gpBnV8oGFgxMhk7cG+
         mYjKqvSQ0E5B2qUXPvTgcRfDL55Q6g2Eczax5/YYlad6DHB1EpseoCds2pgam/EfZ6EW
         lvhbfmOxQggKPiZ8kGzZDIRtoDzzTx5MAtmNCbR7QJ0sUk3/xYGe+zQMC7JDi3XetORw
         rDMwmwrXHZ3EyGpR+nXWRQyM7CxFegul9WgmPbPMOIlSdqhyEmrp61gyOsJ1ruqzxgUV
         iBoUlLWYpFB2rn+uf+ndJl0+Xo9rsUG/y60tAlukcPVYtmztIguU4lDZuouQyAO0HQOP
         52UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id z202si543500wmc.0.2021.03.16.08.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Mar 2021 08:41:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4F0HZ74Q2Mz9v0XB;
	Tue, 16 Mar 2021 16:41:03 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id k0D1psiW6rox; Tue, 16 Mar 2021 16:41:03 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4F0HZ73LcGz9v0X9;
	Tue, 16 Mar 2021 16:41:03 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 065CF8B7E1;
	Tue, 16 Mar 2021 16:41:05 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id zQauc1oIXtG0; Tue, 16 Mar 2021 16:41:04 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6D29C8B7E6;
	Tue, 16 Mar 2021 16:41:04 +0100 (CET)
Subject: Re: [PATCH mm] kfence: fix printk format for ptrdiff_t
To: Segher Boessenkool <segher@kernel.crashing.org>
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
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <3f624e5b-567d-70f9-322f-e721b2df508b@csgroup.eu>
Date: Tue, 16 Mar 2021 16:40:56 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.0
MIME-Version: 1.0
In-Reply-To: <20210316153320.GF16691@gate.crashing.org>
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



Le 16/03/2021 =C3=A0 16:33, Segher Boessenkool a =C3=A9crit=C2=A0:
> On Tue, Mar 16, 2021 at 09:32:32AM +0100, Christophe Leroy wrote:
>> +segher
>=20
> I cannot see through the wood of #defines here, sorry.
>=20
>> Still a problem.
>>
>> I don't understand, gcc bug ?
>=20
> Rule #1: If you do not understand what is happening, it is not a
> compiler bug.  I'm not saying that it isn't, just that it is much more
> likely something else.
>=20
>> The offending argument is 'const ptrdiff_t object_index'
>>
>> We have:
>>
>> arch/powerpc/include/uapi/asm/posix_types.h:typedef long=09
>> __kernel_ptrdiff_t;
>=20
> So this is a 64-bit build.

No it's 32 bits. The code in posix-types.h is

#ifdef __powerpc64__
...
#else
...
typedef long		__kernel_ptrdiff_t;


>=20
>> include/linux/types.h:typedef __kernel_ptrdiff_t	ptrdiff_t;
>>
>> And get:
>>
>>    CC      mm/kfence/report.o
>> In file included from ./include/linux/printk.h:7,
>>                   from ./include/linux/kernel.h:16,
>>                   from mm/kfence/report.c:10:
>> mm/kfence/report.c: In function 'kfence_report_error':
>> ./include/linux/kern_levels.h:5:18: warning: format '%td' expects argume=
nt
>> of type 'ptrdiff_t', but argument 6 has type 'long int' [-Wformat=3D]
>=20
> This is declared as
>          const ptrdiff_t object_index =3D meta ? meta - kfence_metadata :=
 -1;
> so maybe something with that goes wrong?  What happens if you delete the
> (useless) "const" here?

No change.

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3f624e5b-567d-70f9-322f-e721b2df508b%40csgroup.eu.
