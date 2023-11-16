Return-Path: <kasan-dev+bncBCM3H26GVIOBB56W26VAMGQE27QBHUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D8D97EDE40
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 11:14:17 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-5a7af53bde4sf9557247b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 02:14:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700129656; cv=pass;
        d=google.com; s=arc-20160816;
        b=n356LKQpeb0kB3eq2QqO6+ftwHoxPHMgVV8Tjm75lHpzn9NEpp4LuMA2jp4XerJMaB
         afS/7/KkbPwoQFgqSkESqB0J+tF3YWP+lIM7t14XPj6vjOxAtezBlljN/LIS0Yt1lxGx
         bSZZXMhXkRj2RC/NeqsmbVnfuJWral+neXCHwRxDee8PQ/oH40bsIEUWPn/DbCrv1kiQ
         V9ZINje3j5gZx0AJJrbsjpDoQmq3oSaWxMgYQXefUiGjN3q1F8T8OOM0p0LEgY9CwhAf
         4WvxZuAqTfj33kpEPl7pYn0inoVgtSOvNkzZtmN3gxgZWndkbSJChBf/Rbb7Earkt6AY
         LBFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:user-agent:references:in-reply-to:date:cc
         :to:from:subject:message-id:sender:dkim-signature;
        bh=JcHPDZdMNQD5qTlx8Y148rdDjoeEFfNC/2EYcVwIEXQ=;
        fh=DRu6qs0R2xKQX+9GuRjR62JGLrpnTaOE1wQSzv/gHhk=;
        b=NVYyon96NJY0okvdeGh38Jd4+g2xv7tOpq1qrH2sZVCm+qkCXrHPtOYGIeE6iQw4pd
         cESMCWt7dD6qQpIEvk8V/UVT1HbFpT3amYAQymsHrC4LtF0hxmvqlLPLIYM8wucQEDU4
         TuESpJLogyfcmZhDhqDwi+orDyyNfuRcrb4wj8470jFfYYxrn8Dr2EMVLXpkr6h//HI/
         tMm76b4bZHQjGiSTWl0RShXRL0Mxi8vLadSgUCcZoS/bHa/C8dRy5EqUKhOOeNvITA0b
         gmBJ72wjSUg8dlZY6sbnsgrd9jxODzXyZdc9a1qMmo9dtlE+gLa2UlOK+c0J89A1XVom
         F1cQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NAtPmPLZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700129656; x=1700734456; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:user-agent
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JcHPDZdMNQD5qTlx8Y148rdDjoeEFfNC/2EYcVwIEXQ=;
        b=i5o5Bl4a4SRnHfMB0WZFSchiYIAQDyVnqnxh8BUeA+/dCI5ZrIc5wWWrYRL1sPozl/
         /nfnPGjQGAWQVcUUF0b70rKNwXcqleM1CV9ttSJrWMYf7I2OLVmXA43Fsz2KRsRgBcGH
         U+gkSoZhpiSxR5g62jXrlKbAvTN346F0fIEhg3JueW8YhqN5bsaZU8IoeZGVbzzE3vXv
         7QGhR3lKfoNwPA+eEYV/bJqVd5it5TvyFtYjccCP4CBphkNJ/d3GreGzHGO78WsC4PRD
         4TgYYlK88FXiZUTSYsQjjwdpLkvfmcnU+PJx+6s2jyO7qUJkLlP8B2nEOIlh6qICR7D9
         OEOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700129656; x=1700734456;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:user-agent:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JcHPDZdMNQD5qTlx8Y148rdDjoeEFfNC/2EYcVwIEXQ=;
        b=DQQjYoADjA9UW6nPvXvtIQMcx5RkIhXkc63AgByZF/n3qgJO899pzKk3tBX1q8cNXZ
         cNGFfr80EKMCV0dYrABy5SIKG8/CMfmAGAqS2xj0weja874DhtAkaPRuTw+Nnroloy0k
         +s4l56v3uqGub74ZypDcAYt+nDsal4wk99QXcMJQhAyTL9y9uqk+WR6gwM9WQwp/G2jy
         V3ZHhFZa8K2D6b1ykwuAU0tp4EQvTXbRsQ6Hp17cG6O02XBD8TRpERAPOnoqabOgJ539
         5/j7nj+8kwnf+AB7EoQwA4rCh9IvC7KRa40LU2Cad/hcndilhnRTdcjbYCtyDYu6WsZI
         CVOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyE/A96VUVp9Xu8YpvmGnsIMrn5KKmqevKVvzXxz5Cx5mezKJ2y
	sj5D1pT0CW0nRwROwAv4aFM=
X-Google-Smtp-Source: AGHT+IFxpU81wQSLzuPrCnKLtwljVcb3d3TLDlMZmyoywl1c7D3kuNSyou0prxb+vxAzzJ1/uKRaKw==
X-Received: by 2002:a25:cb10:0:b0:d9a:fd65:f97f with SMTP id b16-20020a25cb10000000b00d9afd65f97fmr16342678ybg.17.1700129655779;
        Thu, 16 Nov 2023 02:14:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7614:0:b0:da0:33b3:b1b5 with SMTP id r20-20020a257614000000b00da033b3b1b5ls970943ybc.0.-pod-prod-08-us;
 Thu, 16 Nov 2023 02:14:15 -0800 (PST)
X-Received: by 2002:a81:6ec3:0:b0:583:741c:5fe6 with SMTP id j186-20020a816ec3000000b00583741c5fe6mr12923419ywc.52.1700129654942;
        Thu, 16 Nov 2023 02:14:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700129654; cv=none;
        d=google.com; s=arc-20160816;
        b=Sf6JMqulsr5cFVUR2Pq1XjcR5EcoCMdK1zuCgjEPVLDToZj/EO+TA+JrdbaneG5Kxv
         A1+wUU4tNGJ7cut5vwOF3t+NLuarfYWAThT6umlOEFqhSEuRkcchcphmfT3MhYZ4rS1O
         qDYZ6u5ozgroToAHZcUfNQh0pq7uFmSE0bZVynBcuPFtVRMDkHHevMFZgoD1XdHnQZfD
         guitHeeLmQNtrbwjJWCpsdO3H9BDcXVYd970m71I/yuNEDoi1XAtrHt9xo+DV0M0SR2C
         dV56edH/kq9/ee69gi0yzLaueMMje6hiIEU7O/X+31sVw79+rRTN3geEZ0u4krAUriGI
         e4Gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=Ak1+5JgdIAueV3yIEUMqcop5dQmaB4mQXKLM2e0aWDE=;
        fh=DRu6qs0R2xKQX+9GuRjR62JGLrpnTaOE1wQSzv/gHhk=;
        b=UQcc/gHsr9W9NFqGHIScEUp48BMHLxsXpZ1C1/+6AhaRe2CLaruRuySY/YJgG/ICz3
         eC8LyJsf0k+ChoYkW6GPp/CaZA7ON9Em0qE4apKVkFK5Pzv2zflhUDKxQqFiy1mrgF4D
         5kFadgcK9PFcLh+zmaOzsz4lzELXFZLssgfsEC9gDEn5yST+DKtgIZ5ByMhPHHD6WF9h
         t3HyovDAekVEBY7ObZrjjcavkXpzSclnJ5xp8sTk/faFf36+UQ+YTZPW0nBcDr6JLOqy
         CikChHGEG5JFNrfFSlJq+P3bGgS1idlY0+W0XKX9gSWZRPgkSkJAvtNWIOc5oM+jMwGD
         9s+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NAtPmPLZ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ge24-20020a05622a5c9800b00417048548c7si1900764qtb.2.2023.11.16.02.14.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Nov 2023 02:14:14 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AGAAM17023971;
	Thu, 16 Nov 2023 10:13:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udh3b02ns-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 10:13:45 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AGAB0vB024892;
	Thu, 16 Nov 2023 10:13:45 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udh3b02n9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 10:13:45 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AG8Xiqe000447;
	Thu, 16 Nov 2023 10:13:44 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uanekwr7a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 10:13:44 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AGADf5f19333700
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 16 Nov 2023 10:13:41 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 29C552008A;
	Thu, 16 Nov 2023 10:13:41 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C2E9E2008D;
	Thu, 16 Nov 2023 10:13:39 +0000 (GMT)
Received: from [9.179.9.51] (unknown [9.179.9.51])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 16 Nov 2023 10:13:39 +0000 (GMT)
Message-ID: <7c222eff6c1baaa7647a9aa43a1ef19de9670230.camel@linux.ibm.com>
Subject: Re: [PATCH 00/32] kmsan: Enable on s390
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Andrew Morton
 <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>,
        David
 Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco
 Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka
 Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily
 Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>,
        Christian
 Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov
 <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Thu, 16 Nov 2023 11:13:39 +0100
In-Reply-To: <CAG_fn=U+X=EE9SSb61E=QDReBXn6PGiX4gJnMfNKsTwQ6saKcA@mail.gmail.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
	 <CAG_fn=U+X=EE9SSb61E=QDReBXn6PGiX4gJnMfNKsTwQ6saKcA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: RSDRhI5h1HCfVYThrCR4RyNJd2bxpB6O
X-Proofpoint-GUID: JioNNmrH-KbF_Zczl6SxNj_OhO0okpXb
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-16_07,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 malwarescore=0
 lowpriorityscore=0 phishscore=0 mlxscore=0 spamscore=0 priorityscore=1501
 impostorscore=0 mlxlogscore=549 adultscore=0 clxscore=1015 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311160080
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=NAtPmPLZ;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Thu, 2023-11-16 at 09:42 +0100, Alexander Potapenko wrote:
> On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
om>
> wrote:
> >=20
> > Hi,
> >=20
> > This series provides the minimal support for Kernel Memory
> > Sanitizer on
> > s390. Kernel Memory Sanitizer is clang-only instrumentation for
> > finding
> > accesses to uninitialized memory. The clang support for s390 has
> > already
> > been merged [1].
> >=20
> > With this series, I can successfully boot s390 defconfig and
> > debug_defconfig with kmsan.panic=3D1. The tool found one real
> > s390-specific bug (fixed in master).
> >=20
> > Best regards,
> > Ilya
>=20
> Hi Ilya,
>=20
> This is really impressive!
> Can you please share some instructions on how to run KMSAN in QEMU?
> I've never touched s390, but I'm assuming it should be possible?

I developed this natively (without cross-compilation or emulation,
just KVM), but I just gave the following a try on x86_64 and had some
success:

$ make LLVM=3D1 ARCH=3Ds390 O=3D../linux-build-s390x-cross CC=3Dclang-18
LD=3Ds390x-linux-gnu-ld OBJCOPY=3Ds390x-linux-gnu-objcopy debug_defconfig

$ make LLVM=3D1 ARCH=3Ds390 O=3D../linux-build-s390x-cross CC=3Dclang-18
LD=3Ds390x-linux-gnu-ld OBJCOPY=3Ds390x-linux-gnu-objcopy menuconfig

$ make LLVM=3D1 ARCH=3Ds390 O=3D../linux-build-s390x-cross CC=3Dclang-18
LD=3Ds390x-linux-gnu-ld OBJCOPY=3Ds390x-linux-gnu-objcopy -j24

$ qemu-system-s390x -M accel=3Dtcg -smp 2 -m 4G -kernel ../linux-build-
s390x-cross/arch/s390/boot/bzImage -nographic -append 'root=3D/dev/vda1
rw console=3DttyS1 nokaslr earlyprintk cio_ignore=3Dall kmsan.panic=3D1' -
object rng-random,filename=3D/dev/urandom,id=3Drng0 -device virtio-rng-
ccw,rng=3Drng0

It's also possible to get a free s390 machine at [1].

[1] https://linuxone.cloud.marist.edu/oss

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7c222eff6c1baaa7647a9aa43a1ef19de9670230.camel%40linux.ibm.com.
