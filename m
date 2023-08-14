Return-Path: <kasan-dev+bncBAABBGGT5CTAMGQE3ZOQ5GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 4855B77B989
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 15:18:18 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1bde8160f8bsf12845705ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 06:18:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692019096; cv=pass;
        d=google.com; s=arc-20160816;
        b=udmdopN48Qq/QJVtwihb9xrxQ/cLrH8Dazf0Fwu9AU8cRTyfsTaaG9CjtzBsAX54B2
         7TjBqhhaS51EICfxSpbOaMfvD3bVdqfHwuJzfGT3YWlKEZBWgWJdZXtT3Mh8bBl4w4b/
         ft/4HTawd/3ubqtM9feFsfjm8x+agClQKqanksyTmdChX+Fv7rkDFSpy+RQ2eb2jlX9s
         JifXlRUovLTUaL8H//jrNLcaefjHdFaGnshhKh5JMvaZsEmIQUuy3OTNoLu4N1Pa3AW4
         Ftb48wwCFSUKWlQL7wtQoEqBVKnH1A/bf/v8cwFPFnXDTBayLyE3JpqyW54rU5fjzv2W
         7vFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ZWU6P8aThl7hdMWYiOXasala4m4SqwFz0T1DqUKuzQo=;
        fh=cNj4+sEwHTCsbOqHNet+QnLeafJ2N9QqIMtjVwe7lAo=;
        b=WbR5t1oSPco81PD3p4uSeDiobDHFTCqrblQg2DzX63EbiM26GlYzLsAtaDgPxjg/9l
         iNh8SZZliSbGvnN7/Vrng2JdpLbgztEBymbgpKlBpEi4LnC+FaAX2Gszpk8TvFQdkJsX
         t8WKEpMfQbHjiaU6n+8gEfqeYWHu0q3ex1lXV16lAANlr1uQ65vrThqheqXIiKYv3UDI
         a5Wuu/pQAXT8fCNIK4BGij7A7L6kM7wyyFFFB5sfDtMGmS0KRHV6R12ALnFbOBz0ITbO
         dvt0UM2HZfdd+mbF4r+qNDCvQP22YwhX97CreGGX0bkbznOVWk+37KIwMxhZdMl5igKb
         paug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JBfIPnCW;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692019096; x=1692623896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZWU6P8aThl7hdMWYiOXasala4m4SqwFz0T1DqUKuzQo=;
        b=Nvz5OSO8twejUeBFdy43E4CFN/ol5GvYsdaAMto2Vji9pSlmtWHAkS0p0xTIQ7k538
         4dKtcsdC1ShAN0bAZZ4VZHccspnDzCv7DcKlUIhJH+LUyaLWnH17bOIstGPdVR4rDeV4
         LkOitHcGy8EMQfvUH7hFfKmsMOgjfdBoKNX/1lnriTFnyqbUOQ7xlam3p0Ac0+99yi65
         klsckSLI072xKlgOR2x2GnAnfntTIoBLCqSjmOoepki2MhFH6fGNyaGQ1X7G7c51Z5Rh
         lVgwEu8HJ9Ulaxx80ghCChLnRNwcMJzXrMTwQKscxO/HlyIxZNBgoUXkAyvJL/b7SaDa
         85Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692019096; x=1692623896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZWU6P8aThl7hdMWYiOXasala4m4SqwFz0T1DqUKuzQo=;
        b=j/k9PHNhEjmX+b+9phpYaVWeTgSV4DekOcXganBAy5/cX8frITQhOmhUEgqtPdC6c+
         njro/trJ95qJneuMKSZ8b/++kefACRAgU9veke2V5M7fC45eZG/vfjXNIn2CybpSd7Mo
         J7dHgILx9woPb+VHHmPHUH2hhIfsCvgrkUzQZ7iQLhftytbMXAdVIUBcfycSuVM3kbjD
         WLR0x0PeeE0hsyNCIVALuerzuyBXRIafNlv+DZ4L0SRl7vZ0K8yL+BS9aJnpDnAY+obT
         8kNppI7FhF7ckRT2E/ksJuJZrrXWt+eUdKwpY5QJpaC5HboQI2QHgWb2+2KBUZQ/y91o
         D++w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwKY53SFMiHvK7x632f7hCTcLNLKHvhPHJkAtyb2h6WysmTig+j
	wLbeWxhpfVyStXCARwEEHug=
X-Google-Smtp-Source: AGHT+IE50rf7lUM30ajk6U15MOJTa6YZMcI7005eIZMszdCKoXs/l201cvYey5uszLbtan4hIbUW8A==
X-Received: by 2002:a17:902:d715:b0:1b8:8223:8bdd with SMTP id w21-20020a170902d71500b001b882238bddmr8928933ply.59.1692019096375;
        Mon, 14 Aug 2023 06:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:650e:b0:1bb:99e1:88fb with SMTP id
 b14-20020a170902650e00b001bb99e188fbls4203111plk.1.-pod-prod-06-us; Mon, 14
 Aug 2023 06:18:15 -0700 (PDT)
X-Received: by 2002:a17:902:cec6:b0:1bc:39c9:c883 with SMTP id d6-20020a170902cec600b001bc39c9c883mr12117416plg.65.1692019095441;
        Mon, 14 Aug 2023 06:18:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692019095; cv=none;
        d=google.com; s=arc-20160816;
        b=bCnUbRZ0tRVqzu6lax9DjPO13cLq3moiPRRjGG5rx9sOLKm+gMcEJYFV/uDBXMmLKs
         qEbeBqmbIOM0w+xNsvrfMZ9LMqRCgyuvYNBwXo518U3fYWnU+7ZD1RRVZM7i7zaujFyM
         B7RYMg7Cp+c+gvcF+qqd/BQK4kzMZeHtbOWOEBI4lMFEXD+u1ARUo3DTMWUwCKhE/NqS
         U4iD8Q+/AaxqsmrjNR5QaAL3sxLkQhGnwCOZmwvO6D877fvv8nwX5k1i5d7iIKUB2Oe3
         2J6Z/AJVVzLnel6uiIWGvIyFFqDkk17IufV28PDPWR3bPUFdrngndtYmKcEO8ZIibjpd
         ABFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Z2gThLguoQ+HT2qJOdr1jOuqOoSlIbLuQagclRCXl0k=;
        fh=cNj4+sEwHTCsbOqHNet+QnLeafJ2N9QqIMtjVwe7lAo=;
        b=IEHusn71aoojRfdd+2MZEm8KDAmpw3errOaavbHk5SqG4HZCum4WAS7L4ohoKirNim
         rpEicTo770JcyeJvffZ88f+eHCK0bz9J65qobXxmB4qcoVX0auL44E9zqMQadvjj6sDg
         PHyNEYGPXE6/HtU4kozyNDQFhFbsRaY5DEp9K7vKSdz/cp3Jn+FSsvjSRCHwzGB0ru2+
         s88dMhc9m6/AkruC+9PcT/iMEzNQwvyAhSiKe3EktoBjEGMcV9zWSzpRsiql2gZZ7DnV
         T7SiW1++BSbuuHt+KzthAjFoRM9skMiUnX0K9agmimfrlRZBEoehnn+zle1PnePxxNCO
         G9yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JBfIPnCW;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id w13-20020a170902ca0d00b001bbcd26568asi561189pld.12.2023.08.14.06.18.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 06:18:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 37EDCwNX026797;
	Mon, 14 Aug 2023 13:18:14 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sfmr80bs3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Aug 2023 13:18:14 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 37EDEIMt031708;
	Mon, 14 Aug 2023 13:18:13 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sfmr80brn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Aug 2023 13:18:13 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 37EBwR2P001119;
	Mon, 14 Aug 2023 13:18:13 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3semsxvtgu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Aug 2023 13:18:13 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 37EDIAmg23266046
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 14 Aug 2023 13:18:10 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 027242004D;
	Mon, 14 Aug 2023 13:18:10 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2A57F2004F;
	Mon, 14 Aug 2023 13:18:09 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.86.49])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 14 Aug 2023 13:18:09 +0000 (GMT)
Date: Mon, 14 Aug 2023 15:18:07 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Heiko Carstens <hca@linux.ibm.com>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        Gerald Schaefer <gerald.schaefer@linux.ibm.com>,
        Vineeth Vijayan <vneethv@linux.ibm.com>, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] s390/mm: Make virt_to_pfn() a static inline
Message-ID: <ZNopjyWTodocYyVb@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20230811-virt-to-phys-s390-v1-1-b661426ca9cd@linaro.org>
 <ZNY7PvtP0jI1/xF1@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
 <CACRpkda2H_Ls7FT-GPkM2HLci0rLomwcP+Y5e7CJgXtT2NxJqA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACRpkda2H_Ls7FT-GPkM2HLci0rLomwcP+Y5e7CJgXtT2NxJqA@mail.gmail.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: X9JgCslSai8tvP4KXXQVZ3y95aC1RmIS
X-Proofpoint-ORIG-GUID: -wjJXnzDNSjmCIH8y9vuZJtm71vX4PFC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.267,Aquarius:18.0.957,Hydra:6.0.591,FMLib:17.11.176.26
 definitions=2023-08-14_09,2023-08-10_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 suspectscore=0
 mlxscore=0 spamscore=0 lowpriorityscore=0 mlxlogscore=999 phishscore=0
 priorityscore=1501 malwarescore=0 impostorscore=0 adultscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2306200000
 definitions=main-2308140121
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=JBfIPnCW;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

On Fri, Aug 11, 2023 at 07:49:01PM +0200, Linus Walleij wrote:
> On Fri, Aug 11, 2023 at 3:44=E2=80=AFPM Alexander Gordeev
> <agordeev@linux.ibm.com> wrote:
>=20
> > Funnily enough, except drivers/s390/char/vmcp.c none of affected
> > code pieces below is an offender. But anyway, to me it looks like
> > a nice improvement.
>=20
> I'm puzzled, vmcp.c is a char * so actually not an offender
> (I am trying to push a version without casting to the compile farm),
> the rest are unsigned long passed to the function which now
> (after my change) has const void * as argument?
>=20
> Example:
>=20
> > > @@ -90,7 +90,7 @@ static long cmm_alloc_pages(long nr, long *counter,
>=20
> unsigned long addr;
>=20
> > > +             diag10_range(virt_to_pfn((void *)addr), 1);

I only tried to say that these pieces weren't offenders before
you patch and turned ones after. But that seems like what your
commit message says.

> Yours,
> Linus Walleij

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZNopjyWTodocYyVb%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.co=
m.
