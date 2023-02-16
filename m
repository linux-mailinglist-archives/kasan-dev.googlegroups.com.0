Return-Path: <kasan-dev+bncBAABBD7WXKPQMGQEVTPIKRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C07B69A24E
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 00:24:01 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id z8-20020a92d6c8000000b0031570404cf1sf2299017ilp.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 15:24:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676589839; cv=pass;
        d=google.com; s=arc-20160816;
        b=jBYrO2QNY9/JZx2C7soH/UcmMa0P2uTEZ079C3gsFKnMieKc7p41LSQEYMr1080uIV
         zetVzuwq7337Dxsg5T+vyGNak5hJDeuAV6QsLC4pwnCuCaHHV54F57k7GoNJbPf59tjM
         V+ESEGg6E04uUaZoMgg1UhwIImjWdBN62xI3n1p0hQOOS7cX+3a4cruCv5pMvsWQAbzC
         tg8yI6i+PYpX0gd9lcw8fN3IIbfKCA0Vbji2LP0/rLBctg4UicPOM/t/g9dtfcZSTrbD
         kLW0LG3qTAxKAD+AYvqFMllD5n781u79+1ZGxtkX0CSk6HROUUzaUnEYLPQRI/p0OUqR
         AvmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:to:references:message-id:cc:date
         :in-reply-to:from:subject:sender:dkim-signature;
        bh=pyR4e1hZDNHUXYkloQYWfSfrcVCKsPGQFbBcrP1zGyQ=;
        b=lAyeRSKIV4y2EqGH/mK3pQVj9njPP8y3EHZwDbfIVkm6deAlSiQifeGuLS05ThRRrz
         eTek0HdUXJYhdbfP5ul8/ENYfHkmOd1LkPY9XMQYOvsG5eBmby7R1NToHLMnvbP19KyS
         zNOiBAgGegCVVWrtTQVweTWMSe9ZBWz6yd6rEMzBO/tw9OAVAcPzUichBbEdooCFrxZd
         Ma5VB7rTcllf6Ea41SPCFLg/zOp92Y7IKmfhedGDL5RGND7JySPrMwo1vF4HWQ3FeIPu
         ipbK72RQBj2ppCvGlktgjqsdMHUdRlJebJelio1A5Jm0Vo/2m9C/1T6fEHwMXmv6O+EE
         Xl5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oNcbgnk+;
       spf=pass (google.com: domain of rmclure@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rmclure@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:to
         :references:message-id:cc:date:in-reply-to:from:subject:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pyR4e1hZDNHUXYkloQYWfSfrcVCKsPGQFbBcrP1zGyQ=;
        b=lSAEPzxoH28uosOUybmEtwmQQVSUnPCg3f4gKDsxTejbDEY5JxSVxVa7/me3FOpDvC
         JFMRr4ySwO8D49CxquNhql5XtVmsTt885jDp7AbicqHqseH3KtwTGR/ZWvAHQd9/EAGe
         1vf9G3oMY2Lxtj60zuvncvSUzbuhVc0YlfeodxDpDMiTpF47k2FgiCdqrKD678UYOMIB
         H2oTeo74eaxiof0RdU7kt1G9vs5uV8P5qjm7QaZP5fmT7lrUqVKy+mEROvpQ9o6UiTzo
         s+zLTts6gRkU1t6Q8TccKOKH/UViEH3vQNN0+JqIqFUV+trJzex986/X2klY2KXqmO++
         BlkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:to:references:message-id:cc:date
         :in-reply-to:from:subject:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pyR4e1hZDNHUXYkloQYWfSfrcVCKsPGQFbBcrP1zGyQ=;
        b=UYFVhyM5zhoqCUS5Ds+Y3Ml7OmZM+R6wjkXtlne2vJbQtqx95Ew6pqhPxzrGCx/BKK
         sWZuNviS8KNyyQNH99ZFzv9FEqTzZTmaZjjy6PWJxfEwiQES9bOkjAj++wlmIS29USn/
         VDwgbSoFnLMsq+1DgWZZUFeTVBzRF3/Mb5XX11CeGpLeTOpF4XBdywm5ZWpfdLnnD04F
         CTsGej5x5QHvHbcKkmunYb/y+TgGVvNPzv7Vp+2ezsmPfrsVA6HyZfPR1i//aD7YxfBw
         JjDPovlaQhNttmTD4yiBwoTsjsyoumXIr9cDug2ueb2e7GKaul1HQQxhWjwzje8nMF//
         bDOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXey90UlNyqPowaVRn7365KZRVU74nhAjfb5/gHcxPB1Ic2bjma
	rNt1gV5u8uudCJXhvJFnIyU=
X-Google-Smtp-Source: AK7set8BAH/LPQVXXxJXtAngadzy9ME04inIJFLcDEL/XVqoK97CMgCkrFqdaG487uEfbz3XlXAQQA==
X-Received: by 2002:a05:6638:3897:b0:3b6:e879:2746 with SMTP id b23-20020a056638389700b003b6e8792746mr2992960jav.4.1676589839420;
        Thu, 16 Feb 2023 15:23:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1193:b0:314:10d2:cf32 with SMTP id
 y19-20020a056e02119300b0031410d2cf32ls1254404ili.7.-pod-prod-gmail; Thu, 16
 Feb 2023 15:23:59 -0800 (PST)
X-Received: by 2002:a05:6e02:154f:b0:311:137e:83c6 with SMTP id j15-20020a056e02154f00b00311137e83c6mr6862251ilu.22.1676589838942;
        Thu, 16 Feb 2023 15:23:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676589838; cv=none;
        d=google.com; s=arc-20160816;
        b=BhAIFu0KzOYoMwvKreBpOoxl32YcEa4q8A6JaK9pengFXCYOWPXYxTtYIG9wfQ+lXv
         gAIpzcU3UW9G5GiIWp7FGWoE1o4NSB1+wgqjmTNGt2FiWENPDwBJP1AqmMYqLAwdywxP
         18OXLH97ZRfmbCe03eVEihZicEKYjUnht5VkQrN8XFEdmdo9v3vgdjqHno2kPZZhe7le
         53Wz22W9sq8QpymQtK18Vl4ROBee82FpUAmZmTe6tXjT1rEru4is32OhfAtHKcc8CmEX
         QJVvbn4ARKkrf3sU0a/e3FFuHoL3e+qVnAuHt8SefFD7d476OJrDoPr9WmzHnQBU/Aiu
         VF9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:to:references:message-id:cc
         :date:in-reply-to:from:subject:dkim-signature;
        bh=WcVW/aeSMtX332lAWfno4lAAkIXtiaglwu4yU4RuTlY=;
        b=C5t8xe4utTvqkw0dRtBjDqKbRjdpTs4nAWblEL1+PxHI1D/iNxh+VUc+9o9CxynUuo
         ffTDvmEOJ7hr/VRwTPNao8WmdUACWanS0ote1dMCFC2+rQspQtf3W+z1hvk906pO19nX
         VkDGslkgVFaeRArp6CxnPBQ7WMu6CjUQEUuoWTLtjwUrwICaeSbIIcVg+/U01SKX7Jy+
         wt8CbkQIizcvNJavW7hpTjoHoouAjv9hM479saacNHuHSvYokumIHXj3YvkU24VmoVUc
         4dhyfJXx92plttKpq2+VXIfTnSN70YudZ2YwsnFSVkO6PyTuTMsmg16GbmeiHs+VfXKT
         TMnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oNcbgnk+;
       spf=pass (google.com: domain of rmclure@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=rmclure@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id q2-20020a92c002000000b0031538deaabbsi234521ild.5.2023.02.16.15.23.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Feb 2023 15:23:58 -0800 (PST)
Received-SPF: pass (google.com: domain of rmclure@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098410.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 31GNCUFm007237;
	Thu, 16 Feb 2023 23:23:55 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3nswxur66h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Feb 2023 23:23:55 +0000
Received: from m0098410.ppops.net (m0098410.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 31GNFQcS018415;
	Thu, 16 Feb 2023 23:23:55 GMT
Received: from ppma04fra.de.ibm.com (6a.4a.5195.ip4.static.sl-reverse.com [149.81.74.106])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3nswxur65w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Feb 2023 23:23:54 +0000
Received: from pps.filterd (ppma04fra.de.ibm.com [127.0.0.1])
	by ppma04fra.de.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 31GHOGmc022562;
	Thu, 16 Feb 2023 23:23:52 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma04fra.de.ibm.com (PPS) with ESMTPS id 3np2n6dd7v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Feb 2023 23:23:52 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 31GNNof741419228
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 16 Feb 2023 23:23:50 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 12DA72004B;
	Thu, 16 Feb 2023 23:23:50 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0D88D20040;
	Thu, 16 Feb 2023 23:23:49 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 16 Feb 2023 23:23:49 +0000 (GMT)
Received: from smtpclient.apple (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 4AA65600A5;
	Fri, 17 Feb 2023 10:23:47 +1100 (AEDT)
Content-Type: text/plain; charset="UTF-8"
Subject: Re: [PATCH 1/2] kcsan: xtensa: Add atomic builtin stubs for 32-bit
 systems
From: Rohan McLure <rmclure@linux.ibm.com>
In-Reply-To: <Y+3kwmFhWilN2OaE@elver.google.com>
Date: Fri, 17 Feb 2023 10:23:37 +1100
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Max Filippov <jcmvbkbc@gmail.com>,
        "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
        Dmitry Vyukov <dvyukov@google.com>
Message-Id: <BD87DB92-9BE9-4145-AAAE-F947DA4EF7FD@linux.ibm.com>
References: <20230216050938.2188488-1-rmclure@linux.ibm.com>
 <42e62369-8dd0-cbfc-855d-7ad18e518cee@csgroup.eu>
 <Y+3kwmFhWilN2OaE@elver.google.com>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3731.400.51.1.1)
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: GekkrYdHog4pLala9GAJcHwQnvoRdTUn
X-Proofpoint-ORIG-GUID: 1B7vN6wjGsbzGTiyS85nSqhUW6E26uuf
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.219,Aquarius:18.0.930,Hydra:6.0.562,FMLib:17.11.170.22
 definitions=2023-02-16_16,2023-02-16_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1011 bulkscore=0
 spamscore=0 lowpriorityscore=0 mlxscore=0 phishscore=0 impostorscore=0
 priorityscore=1501 adultscore=0 malwarescore=0 suspectscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2212070000 definitions=main-2302160198
X-Original-Sender: rmclure@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oNcbgnk+;       spf=pass (google.com:
 domain of rmclure@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=rmclure@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE
 dis=NONE) header.from=ibm.com
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

> On 16 Feb 2023, at 7:09 pm, Marco Elver <elver@google.com> wrote:
>=20
> On Thu, Feb 16, 2023 at 07:12AM +0000, Christophe Leroy wrote:
>>=20
>>=20
>> Le 16/02/2023 =C3=A0 06:09, Rohan McLure a =C3=A9crit :
>>> KCSAN instruments calls to atomic builtins, and will in turn call these
>>> builtins itself. As such, architectures supporting KCSAN must have
>>> compiler support for these atomic primitives.
>>>=20
>>> Since 32-bit systems are unlikely to have 64-bit compiler builtins,
>>> provide a stub for each missing builtin, and use BUG() to assert
>>> unreachability.
>>>=20
>>> In commit 725aea873261 ("xtensa: enable KCSAN"), xtensa implements thes=
e
>>> locally. Move these definitions to be accessible to all 32-bit
>>> architectures that do not provide the necessary builtins, with opt in
>>> for PowerPC and xtensa.
>>>=20
>>> Signed-off-by: Rohan McLure <rmclure@linux.ibm.com>
>>> Reviewed-by: Max Filippov <jcmvbkbc@gmail.com>
>>=20
>> This series should also be addressed to KCSAN Maintainers, shouldn't it =
?
>>=20
>> KCSAN
>> M: Marco Elver <elver@google.com>
>> R: Dmitry Vyukov <dvyukov@google.com>
>> L: kasan-dev@googlegroups.com
>> S: Maintained
>> F: Documentation/dev-tools/kcsan.rst
>> F: include/linux/kcsan*.h
>> F: kernel/kcsan/
>> F: lib/Kconfig.kcsan
>> F: scripts/Makefile.kcsan
>>=20
>>=20
>>> ---
>>> Previously issued as a part of a patch series adding KCSAN support to
>>> 64-bit.
>>> Link: https://lore.kernel.org/linuxppc-dev/167646486000.1421441.1007005=
9569986228558.b4-ty@ellerman.id.au/T/#t
>>> v1: Remove __has_builtin check, as gcc is not obligated to inline
>>> builtins detected using this check, but instead is permitted to supply
>>> them in libatomic:
>>> Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D108734
>>> Instead, opt-in PPC32 and xtensa.
>>> ---
>>>  arch/xtensa/lib/Makefile                              | 1 -
>>>  kernel/kcsan/Makefile                                 | 2 ++
>>>  arch/xtensa/lib/kcsan-stubs.c =3D> kernel/kcsan/stubs.c | 0
>>>  3 files changed, 2 insertions(+), 1 deletion(-)
>>>  rename arch/xtensa/lib/kcsan-stubs.c =3D> kernel/kcsan/stubs.c (100%)
>>>=20
>>> diff --git a/arch/xtensa/lib/Makefile b/arch/xtensa/lib/Makefile
>>> index 7ecef0519a27..d69356dc97df 100644
>>> --- a/arch/xtensa/lib/Makefile
>>> +++ b/arch/xtensa/lib/Makefile
>>> @@ -8,5 +8,4 @@ lib-y +=3D memcopy.o memset.o checksum.o \
>>>      divsi3.o udivsi3.o modsi3.o umodsi3.o mulsi3.o umulsidi3.o \
>>>      usercopy.o strncpy_user.o strnlen_user.o
>>>  lib-$(CONFIG_PCI) +=3D pci-auto.o
>>> -lib-$(CONFIG_KCSAN) +=3D kcsan-stubs.o
>>>  KCSAN_SANITIZE_kcsan-stubs.o :=3D n
>>> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
>>> index 8cf70f068d92..86dd713d8855 100644
>>> --- a/kernel/kcsan/Makefile
>>> +++ b/kernel/kcsan/Makefile
>>> @@ -12,6 +12,8 @@ CFLAGS_core.o :=3D $(call cc-option,-fno-conserve-sta=
ck) \
>>>   -fno-stack-protector -DDISABLE_BRANCH_PROFILING
>>>=20
>>>  obj-y :=3D core.o debugfs.o report.o
>>> +obj-$(CONFIG_PPC32) +=3D stubs.o
>>> +obj-$(CONFIG_XTENSA) +=3D stubs.o
>>=20
>> Not sure it is acceptable to do it that way.
>>=20
>> There should likely be something like a CONFIG_ARCH_WANTS_KCSAN_STUBS in=
=20
>> KCSAN's Kconfig then PPC32 and XTENSA should select it.
>=20
> The longer I think about it, since these stubs all BUG() anyway, perhaps
> we ought to just avoid them altogether. If you delete all the stubs from
> ppc and xtensa, but do this:
>=20
> | diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> | index 54d077e1a2dc..8169d6dadd0e 100644
> | --- a/kernel/kcsan/core.c
> | +++ b/kernel/kcsan/core.c
> | @@ -1261,7 +1261,9 @@ static __always_inline void kcsan_atomic_builtin_=
memorder(int memorder)
> |  DEFINE_TSAN_ATOMIC_OPS(8);
> |  DEFINE_TSAN_ATOMIC_OPS(16);
> |  DEFINE_TSAN_ATOMIC_OPS(32);
> | +#ifdef CONFIG_64BIT
> |  DEFINE_TSAN_ATOMIC_OPS(64);
> | +#endif
> | =20
> |  void __tsan_atomic_thread_fence(int memorder);
> |  void __tsan_atomic_thread_fence(int memorder)
>=20
> Does that work?

This makes much more sense. Rather than assume that kcsan is the only
consumer of __atomic_*_8, and stubbing accordingly, we should just
remove its mention from relevant sub-archs.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/BD87DB92-9BE9-4145-AAAE-F947DA4EF7FD%40linux.ibm.com.
