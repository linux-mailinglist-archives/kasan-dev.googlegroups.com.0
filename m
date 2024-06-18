Return-Path: <kasan-dev+bncBCM3H26GVIOBBANMYWZQMGQE6LYWS7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id DB2AA90C571
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 11:40:18 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-631282b19afsf95307427b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 02:40:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718703618; cv=pass;
        d=google.com; s=arc-20160816;
        b=yXNkjCs/53zIXCIyv4udGuRSIhnT/rpiTUKdRBDowuNPE6QIGEFR+yKaqJ/yJO+lJu
         BTQYlfnqinaMI+XpgoYNTCrC85mKmfOhEPQhyYz+gXep23qoGXInkauQmN1U4cHWlHNd
         QnufbvezgYi5bT0F4uldHWwnc6NHu7uNljVvEWOo8DK2DDojaSmivZbwhZ5Cjhg+ECzT
         2RW8OZczhAp3QMAjxLyH535/yNG4cT63ORw2qNn6C5PB5/iZ2T5Ox2Xysdjh7DgKuuml
         8EW/iZQ8yJWOBNvh721YFTG831bYNvett3d6h60tC0agI11DnOqYmN6JWxys24l4jf+/
         xVEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=HvDwHc4QsBdJh7cB3nrcS0lv8TzZq5Go439EP/ob+Og=;
        fh=5SdRj6e4aAMJi5NZUB9kC30iCWeWZALIUKrTAnB96hU=;
        b=yC8vCrYRWyWjlwnbF/WGLAdl/aTbZDEeCq6s8Ysr91Src9XKyIp8oGAlq6NXf7dPAI
         Z9zfw4NIdK5CLlwN9yFGPG2ldTPdyLlrBFo0DT4kse/rnOB205B4ve+D48Yn8k7ma3jn
         oVmamzMZzN0p4J/Fhiud0flSyBFYOwoW0tHL+Hm7wmRaim6JtG3quaXDQzOmyuHOkBGH
         USOMeFK1QGiRZNAOhArIPUhYTwCPHvod0krWEIJL+SBVcIKqHyuUchE2zWJUK+B1KRHQ
         Oxu5hAu4r8KpDimCejhaSKJ/jeRQw65JrJ/hNvT8hN5IrgUOaQwaY2dA4n0WpMZ3hDPu
         521g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BIhZ1Ocb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718703618; x=1719308418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HvDwHc4QsBdJh7cB3nrcS0lv8TzZq5Go439EP/ob+Og=;
        b=bszs5LPuCQefE4xiZMbLjro5IteKs4OLzn5c9THbbTjynDWVHf79R9c+hFhdWVsS/Y
         a6frRxSkVWzKC1NiOU2O0f2LaHqTLTywtT1NGniDBgNja+ezg+QMdmTJihN6DEOiinEI
         2SVgDLYiRhUO+eu7h+sbajju+x+u+6in1YbSh+vcIega6ORkSl2i9cTh8LSql9FDGkqN
         k4yTjUfvvzmTp1RGpNAn/iHlF6NuaPJQYs6r7ArlS3aEC1OtyhDRwsLfMTzC9VNTMx7e
         Uz6Vsw8qcCaXbo03TOgF9eurAQ9lmzCD0gmKrziHDKsOD+CBYM+Osbysao2qOWJntvOJ
         vieQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718703618; x=1719308418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HvDwHc4QsBdJh7cB3nrcS0lv8TzZq5Go439EP/ob+Og=;
        b=cZ7QYxy8WO0rzWnb7SVappSIeQ2c60t3eJn4ANMMwbmxf4l9gb9B9pxTOiYrVDkhJF
         +Sl9BNmErzrJwwlzTB0bz3disY60TcGvAQT7A3jYk0fn9hANJl7U+R04A8QoCznAYyNs
         l5y1r6fpi4PufONpV20GKWYqWED6CkNS/VffgvQ2p+W44roZjF2JrPlRdzO7gvFMt4IH
         IKGJZZlr4nYczbFFBjKhuV2BA/Iw8VGzRJlh2Xz20w3qqvBmujhLCuNbHd2Pvz75MP6F
         H47ZmMzRpx3AcQ/lVv6/1A4jFpStDvSp1gl3ee0EpcMk3QPxKOImjIfvkj/5waXMRUMb
         vk6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQlA05OpDzFq4lNU5/blMGT//YA53HRqeoqUMGmqev85TzXcqlOTpRb9AFWDxTQUiVJioUNV3xKM9tBrZHfMY0naj3bE1Wqg==
X-Gm-Message-State: AOJu0YynQw7cwDCkqkPqIttEHTBr9Pl2nMPac5UphrpnJWHdP4eZd9r1
	iXnYtxQjilDcWOsAN7iNON1/EkIwAmEbC0MouhYTulZmsuPxmsmH
X-Google-Smtp-Source: AGHT+IEvH0W1rO/2/SpNXL4Yt18IwSywh34eY/LyzW4LAsrHl1ruyf6Hy7bN7lHoTBhgEjyKpNQSLg==
X-Received: by 2002:a0d:ea53:0:b0:61b:3345:a349 with SMTP id 00721157ae682-63222263dd5mr108999767b3.3.1718703617677;
        Tue, 18 Jun 2024 02:40:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3108:b0:6b0:94b8:6230 with SMTP id
 6a1803df08f44-6b2a338575dls74857666d6.0.-pod-prod-05-us; Tue, 18 Jun 2024
 02:40:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWzq2Mo0D0Fy1BXXAxuLRIVgeBgfimAIX8GfEIvvCLykV72X64XxhJF46K3uMema9dh/+eoEyFbu9+KOzvncuMiCAfDe6bNGxKYg==
X-Received: by 2002:a67:cd9a:0:b0:48c:4e31:4e25 with SMTP id ada2fe7eead31-48dae34bccdmr12188967137.19.1718703616904;
        Tue, 18 Jun 2024 02:40:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718703616; cv=none;
        d=google.com; s=arc-20160816;
        b=PFnKp/oQoh7ZFdvnK9Ks3VSCXIOzUV+8oY5NYLqeIiV59D4f/VReeXhuMYrTMWrv8o
         x0yYDov9+FOsy+PmfBeCb4A6P6SLoJ7IqkbGMJ5iLF1ux1fUZebBVbcy3rZulXbep51U
         4YsNaNDDJhVrr2Y5ACeXwFC/3vm1/LsQAmLdXIxmjSIebCsgYMtXxBrbyk9oUN3EXfRA
         wvDGPpP5DJx+0c2kAWKecQrHGcSKgcYNqCpkMb2Sywf9uAJLZN3nAw7nObWLB/uK5W+A
         j3fr/N8h81cktCqke8SiYqLuyRhrWeSIdFg0Ep65y7MSI28aA68LuCF7UvFZ+M02Havu
         NyPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=xrN9vq4AlQ0IUbRyd0kzdxskUPIOH4+XnL8qioJfPM8=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=NHMILgzkaG6oGfbCQU+uwYiVZ80voAH1/VL1vESGvY4OEnpeEug9kWYGvxFU74ee+u
         fmlPZv+YpRz03HvqbkbiPUSoDPV+OJBkBZpxt4yJrw61xah7Uw86kSbAQJgr5Nau31IA
         kwmXcogKbZHNoBR/BwSh908QhGk9ZgNLbJWUVDSUzSlIDIuFYtTQ9KXpphDZV5/i6d6R
         qEJyOLjeia+YKQUBkGBJoLwJ5pNKrtT9pE3t+7HF1wrTRYHo1L/YqN5m1QCidF7Q/4mQ
         ySMemfi0ro8xI6peN50UK6Au6+5SYnEusV2dPMfOq6wXOGMBKdAXYTKoO90HmSbR0dRf
         uasA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BIhZ1Ocb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48da44b6bcbsi442851137.2.2024.06.18.02.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jun 2024 02:40:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45I9Teee031846;
	Tue, 18 Jun 2024 09:40:13 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yu7n10132-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 18 Jun 2024 09:40:12 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45I9eCFE015571;
	Tue, 18 Jun 2024 09:40:12 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yu7n1012w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 18 Jun 2024 09:40:12 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45I85rg5009478;
	Tue, 18 Jun 2024 09:40:11 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmhcqy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 18 Jun 2024 09:40:10 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45I9e0rE15598024
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 18 Jun 2024 09:40:02 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 70A3A20040;
	Tue, 18 Jun 2024 09:40:00 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E805F20043;
	Tue, 18 Jun 2024 09:39:58 +0000 (GMT)
Received: from [127.0.0.1] (unknown [9.152.108.100])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 18 Jun 2024 09:39:58 +0000 (GMT)
Message-ID: <e91768f518876ec9b53ffa8069b798107434d0dd.camel@linux.ibm.com>
Subject: Re: [PATCH v4 32/35] s390/uaccess: Add KMSAN support to put_user()
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
Date: Tue, 18 Jun 2024 11:39:58 +0200
In-Reply-To: <CAG_fn=X6wHfmGsVgdqwms_Hk1CQAZ6M5623WyatjVp=Uk-z9pQ@mail.gmail.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
	 <20240613153924.961511-33-iii@linux.ibm.com>
	 <CAG_fn=X6wHfmGsVgdqwms_Hk1CQAZ6M5623WyatjVp=Uk-z9pQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Jp0hTpySQMny5R80hPYVyQCEnz4JWM64
X-Proofpoint-ORIG-GUID: uCa4rbUV_oOAJ2HiNOsTtujCNAg45x37
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-18_02,2024-06-17_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 adultscore=0 lowpriorityscore=0 phishscore=0 suspectscore=0 spamscore=0
 mlxlogscore=821 mlxscore=0 bulkscore=0 priorityscore=1501 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406180069
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=BIhZ1Ocb;       spf=pass (google.com:
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

On Tue, 2024-06-18 at 11:24 +0200, Alexander Potapenko wrote:
> On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
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
> >=20
> > An obvious fix to add __no_sanitize_memory to __put_user_fn() does
> > not
> > work, since it's __always_inline. And __always_inline cannot be
> > removed
> > due to the __put_user_bad() trick.
> >=20
> > A different obvious fix of using the "a" instead of the "+Q"
> > constraint
> > degrades the code quality, which is very important here, since it's
> > a
> > hot path.
> >=20
> > Instead, repurpose the __put_user_asm() macro to define
> > __put_user_{char,short,int,long}_noinstr() functions and mark them
> > with
> > __no_sanitize_memory. For the non-KMSAN builds make them
> > __always_inline in order to keep the generated code quality. Also
> > define __put_user_{char,short,int,long}() functions, which call the
> > aforementioned ones and which *are* instrumented, because they call
> > KMSAN hooks, which may be implemented as macros.
>=20
> I am not really familiar with s390 assembly, but I think you still
> need to call kmsan_copy_to_user() and kmsan_copy_from_user() to
> properly initialize the copied data and report infoleaks.
> Would it be possible to insert calls to linux/instrumented.h hooks
> into uaccess functions?

Aren't the existing instrument_get_user() / instrument_put_user() calls
sufficient?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e91768f518876ec9b53ffa8069b798107434d0dd.camel%40linux.ibm.com.
