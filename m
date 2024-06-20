Return-Path: <kasan-dev+bncBCM3H26GVIOBBU5A2CZQMGQE2MJVDKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E971910264
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 13:20:11 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id ada2fe7eead31-48ef279a1dfsf2104967137.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 04:20:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718882410; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ex6BbyhFfpUfpUYvvT/ln69HYgZzW9REgejWsLHazlnbqKQPxBjgBNR5QtB+7hYsCu
         UPyQAkgQFqmali36HFy26rzI+W4iBYwx1+OBA+ALxqY+CY7L/7UBTaIuI3U/rC0NCTny
         VWVrH6hmYtmO5tasX/3GAiEeHx3QBoFFCdeW0T6cYNlJvGN9qUxbBaC5A5VB5T0X7L28
         /aM2aQzKM+AzxvSJ/ZN/+bxqDsDKi4Q6/VfHHaLqHPiUHTi4Om0PZEvQU7VG2dlzyJQU
         Z2E19ug+4c8trc+DpQswAVP85xpgT41voRbJAUqDSybIq1XAktygA+09RHg93Yd5ErYv
         ki7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=DB+T0Sdnv8wo88XlAZzi7uljCT6sLiUMsrPLzCPm3AI=;
        fh=Glj9MTmBmBFsFGkVnBuoLMxUX5IgZx1aamG3JMcqLz8=;
        b=BsCfJAjYnLqqR6XGGpgKQzkMMmsIzgc0S2xOPQ0RToYJxEPMbBqjjA7Ic6ioTglgKT
         ZPMaNFcNdWD/4wlvWUqmFu/8uHbV5PN/sBMdfKG5kkc+oYQ2asWUNbF/iyWSu2sifffm
         NDQS1sojkYaWpuDbRaamf2lGteoVH+88d5/E0mcQUaUBPTR3ucBMsuViNX1s2IIGI5pw
         egvacnKYZ//5GCzHDMG4wf1ADswqh5WPKvb/gP9g0Nsm/QK6ZHzmc+OnhanBpMKxG1up
         bS+cWvvY5niC5ferQHRdbKO+UKtrsA906prDV5V9DcUZfae1/GzBWQ30U8uYCgY8CIGR
         4D/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sco1L1Qu;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718882410; x=1719487210; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DB+T0Sdnv8wo88XlAZzi7uljCT6sLiUMsrPLzCPm3AI=;
        b=tRKqxAUUv3Cso6m7D6CFtIPOc9nJW1zjUaixo5PwmENVIsczHoMCHDKIHnC62cSwQz
         HqK15UVUSYMyUXasnilGucncRUohITlyb1pRs/Feb/jm6WNkkAYUVP1Rw9JZkFZ0KqGI
         gx/ENJqsOh8hqN3VlLkflQu7Et6p22bicXLCNCAAfVoLem9K2HQVVzU1iscFy0Z+upf+
         S/Aa9wKDu49kBSjr57XrZbAAFTJfSNx7ld8QFTbsBICipOrhXDRwuUOFohSmJ10H4TLo
         vWZH0adnMT1R+OsUmokphooV5c8Aq+Q5oipr3uGGS3kAo8CvUJ0nQZuCu23Lj/zIVs2t
         GqSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718882410; x=1719487210;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DB+T0Sdnv8wo88XlAZzi7uljCT6sLiUMsrPLzCPm3AI=;
        b=EaHXy6IFBlQ7EWYeKrxasnVvBGD7OAXFdKeRKYZcPIHlZcUuBjGRBqjlveU3thkqJ/
         Oe0rRY0Yq3p5Rcyhu3a1QuFYrAej8QqAL9VnIjiRy9+RheAkfpz1EuPsojRRXTCLFzhh
         dlPAhc4oYkHdpf87D1YsEqlaIwfjLCNEgykxpjI/e8kFK9VW1RrTxPy4HHa0l/834fwc
         vrAZBim4i/ELbtIEY4fKFLM9IytDtCKpE7ibflu5cRgMViGuuEyC4hkb//wg2czhkIl5
         MBbgHns6U41Ca1y9kNCro0oFjOYCGZ75LAsABwPcJrI0G9lXm024JH7jrrgGMEJefCFZ
         4mow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+YgVm5ldoLPhFmQd2dzIychFtV5JNl4NDeZcIrUHE7jLdwrj9H+DzRSOkLK/kg/MYHd70E989ZQpCqvxHoqxJpTzFOPlX+Q==
X-Gm-Message-State: AOJu0Yw5tsUYCCPCXYN8B7k7qciVHzEDgc9RUAmas4Rg2aW/Wob1M17q
	j0vEF7bDjJapO5qLCIyt5G1+bzI+aMnaRJbYZW4iLZIVipU4ICmW
X-Google-Smtp-Source: AGHT+IFCACIK7uXpcA7Fl9NZoRfwTs35lZu6wICLqermlwTqx+IVFwQBBcNAMLMuSAaaxM73pQjo0w==
X-Received: by 2002:a05:6870:6586:b0:259:8b41:7aa1 with SMTP id 586e51a60fabf-25c9413f95bmr2469624fac.27.1718882388044;
        Thu, 20 Jun 2024 04:19:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:60e:b0:251:cbd:f69f with SMTP id
 586e51a60fabf-25cb5f3ea71ls27751fac.2.-pod-prod-00-us; Thu, 20 Jun 2024
 04:19:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWE6HG/SfuLjvIofIX0jxwZ7uEwB1XSoWMq1YeWdgRPv6X5Vk0B3kyBXAFfv3fPvZ6Mrl3IBzBpD/JpakYKZGiZSvT5w6D1dcRkAQ==
X-Received: by 2002:a05:6808:1401:b0:3d2:3216:9125 with SMTP id 5614622812f47-3d50f11cdf2mr4001511b6e.19.1718882387288;
        Thu, 20 Jun 2024 04:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718882387; cv=none;
        d=google.com; s=arc-20160816;
        b=QyEEqfT69M88/y1AHqAKviuoVEFEQ6SIR12mZBxVaJoehgQDRt1QVwt+IBdrexze1Q
         JPsYSnFUfUg9b12RxXMv5mcNf/EnNOPVVI/cjYXz2c0s78nLI0L3eOlLP8jZEJnXHfPi
         ML3s3CT6q6B4SW78uM39g8D/2K3v5BBRXe6vRrqHUyoQfl/jJ0QofQ2MfRMUfTJBstyE
         6x6jI/gai7hT45fjBQl2PH2U9ilrbCTVNJNodp41G0hUMkOApYpReqrqrAt35VW/Tv6D
         FZnDjPWY07bjliORINTwRkehm7MBfrSeu58j+CimkLp+mq7fTbAHt8yAiOps+/CWNk1k
         6caA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=YZXiRJkZp+S7FTPMS+D2ZuQxPKOUSyTFYbKHne7ZT5o=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=sjCMzDnDPxyqyLU//lBcgGYXw48MCh4gEXZqH5uriqlEfvH6Aj+POh2/smUYRYyq8K
         VCCW9iiMJ8mVPUcijRtecwCpmiQRM7y8oCwK9F52nX3RSh0sdk1OuQk0g+cx/WwZqSi5
         0dyfF7vxIXwFMNswh5A50B793rGMSs+NzCwwSEqWnXekJCFNr6uoPBW9zLm3mDikkdAk
         up8+M5m5rsNha7hw65aY3xeRQN3ABGVt4brlTl0MAud/JI9h5zFqZom3RkgnD8jQa7B6
         uh5dRIJdabFvXupH+FJJ6gPiOPalbrpTHPG8tVHYfDWbc8wjKz15MgrZR1BpeB/j3eZN
         s3fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sco1L1Qu;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2477c736csi713617b6e.5.2024.06.20.04.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 04:19:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KALHcM006405;
	Thu, 20 Jun 2024 11:19:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvhtw88ww-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 11:19:40 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45KBJek8028469;
	Thu, 20 Jun 2024 11:19:40 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvhtw88ws-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 11:19:40 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KB7Xek009425;
	Thu, 20 Jun 2024 11:19:39 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgn53a7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 11:19:38 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45KBJXvd57016618
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 20 Jun 2024 11:19:35 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6EA3F2004D;
	Thu, 20 Jun 2024 11:19:33 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CDB2220040;
	Thu, 20 Jun 2024 11:19:32 +0000 (GMT)
Received: from [9.155.200.166] (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 20 Jun 2024 11:19:32 +0000 (GMT)
Message-ID: <aaef3e0fe22ad9074de84717f36f316204ae088c.camel@linux.ibm.com>
Subject: Re: [PATCH v5 33/37] s390/uaccess: Add KMSAN support to put_user()
 and get_user()
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Andrew Morton
 <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>,
        David
 Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami
 Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven
 Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil
 Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Thu, 20 Jun 2024 13:19:32 +0200
In-Reply-To: <CAG_fn=V8Tt28LE9FtoYkos=5XG4zP_tDP1mF1COfEhAMg2ULqQ@mail.gmail.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
	 <20240619154530.163232-34-iii@linux.ibm.com>
	 <CAG_fn=V8Tt28LE9FtoYkos=5XG4zP_tDP1mF1COfEhAMg2ULqQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: IrkS3GjvPqTFqcgU2dJPG6AOUTabmxFK
X-Proofpoint-GUID: QnnWeFxfRe5FVGujes4q0S_lbJThwNlL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_07,2024-06-20_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 clxscore=1015
 suspectscore=0 adultscore=0 spamscore=0 mlxscore=0 lowpriorityscore=0
 mlxlogscore=807 phishscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406200074
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sco1L1Qu;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

On Thu, 2024-06-20 at 10:36 +0200, Alexander Potapenko wrote:
> On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
om>
> wrote:
> >=20
> > put_user() uses inline assembly with precise constraints, so Clang
> > is
> > in principle capable of instrumenting it automatically.
> > Unfortunately,
> > one of the constraints contains a dereferenced user pointer, and
> > Clang
> > does not currently distinguish user and kernel pointers. Therefore
> > KMSAN attempts to access shadow for user pointers, which is not a
> > right
> > thing to do.
>=20
> By the way, how does this problem manifest?
> I was expecting KMSAN to generate dummy shadow accesses in this case,
> and reading/writing 1-8 bytes from dummy shadow shouldn't be a
> problem.
>=20
> (On the other hand, not inlining the get_user/put_user functions is
> probably still faster than retrieving the dummy shadow, so I'm fine
> either way)

We have two problems here: not only clang can't distinguish user and
kernel pointers, the KMSAN runtime - which is supposed to clean that
up - can't do that either due to overlapping kernel and user address
spaces on s390. So the instrumentation ultimately tries to access the
real shadow.

I forgot what the consequences of that were exactly, so I reverted the
patch and now I get:

Unable to handle kernel pointer dereference in virtual kernel address
space
Failing address: 000003fed25fa000 TEID: 000003fed25fa403
Fault in home space mode while using kernel ASCE.
AS:0000000005a70007 R3:00000000824d8007 S:0000000000000020=20
Oops: 0010 ilc:2 [#1] SMP=20
Modules linked in:
CPU: 3 PID: 1 Comm: init Tainted: G    B            N 6.10.0-rc4-
g8aadb00f495e #11
Hardware name: IBM 3931 A01 704 (KVM/Linux)
Krnl PSW : 0704c00180000000 000003ffe288975a (memset+0x3a/0xa0)
           R:0 T:1 IO:1 EX:1 Key:0 M:1 W:0 P:0 AS:3 CC:0 PM:0 RI:0 EA:3
Krnl GPRS: 0000000000000000 000003fed25fa180 000003fed25fa180
000003ffe28897a6
           0000000000000007 000003ffe0000000 0000000000000000
000002ee06e68190
           000002ee06f19000 000003fed25fa180 000003ffd25fa180
000003ffd25fa180
           0000000000000008 0000000000000000 000003ffe17262e0
0000037ee000f730
Krnl Code: 000003ffe288974c: 41101100           la      %r1,256(%r1)
           000003ffe2889750: a737fffb           brctg =20
%r3,000003ffe2889746
          #000003ffe2889754: c03000000029       larl  =20
%r3,000003ffe28897a6
          >000003ffe288975a: 44403000           ex      %r4,0(%r3)
           000003ffe288975e: 07fe               bcr     15,%r14
           000003ffe2889760: a74f0001           cghi    %r4,1
           000003ffe2889764: b9040012           lgr     %r1,%r2
           000003ffe2889768: a784001c           brc   =20
8,000003ffe28897a0
Call Trace:
 [<000003ffe288975a>] memset+0x3a/0xa0=20
([<000003ffe17262bc>] kmsan_internal_set_shadow_origin+0x21c/0x3a0)
 [<000003ffe1725fb6>] kmsan_internal_unpoison_memory+0x26/0x30=20
 [<000003ffe1c1c646>] create_elf_tables+0x13c6/0x2620=20
 [<000003ffe1c0ebaa>] load_elf_binary+0x50da/0x68f0 =20
 [<000003ffe18c41fc>] bprm_execve+0x201c/0x2f40=20
 [<000003ffe18bff9a>] kernel_execve+0x2cda/0x2d00=20
 [<000003ffe49b745a>] kernel_init+0x9ba/0x1630=20
 [<000003ffe000cd5c>] __ret_from_fork+0xbc/0x180=20
 [<000003ffe4a1907a>] ret_from_fork+0xa/0x30=20
Last Breaking-Event-Address:
 [<000003ffe2889742>] memset+0x22/0xa0
Kernel panic - not syncing: Fatal exception: panic_on_oops

So is_bad_asm_addr() returned false for a userspace address.
Why? Because it happened to collide with the kernel modules area:
precisely the effect of overlapping.

VMALLOC_START: 0x37ee0000000
VMALLOC_END:   0x3a960000000
MODULES_VADDR: 0x3ff60000000
Address:       0x3ffd157a580
MODULES_END:   0x3ffe0000000

Now the question is, why do we crash when accessing shadow for modules?
I'll need to investigate, this does not look normal. But even if that
worked, we clearly wouldn't want userspace accesses to pollute module
shadow, so I think we need this patch in its current form.

[...]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/aaef3e0fe22ad9074de84717f36f316204ae088c.camel%40linux.ibm.com.
