Return-Path: <kasan-dev+bncBCM3H26GVIOBBM6IZSVQMGQEVW5TIBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7547980A52C
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 15:12:05 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1d0af632728sf999765ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 06:12:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702044724; cv=pass;
        d=google.com; s=arc-20160816;
        b=TWtZxD4bqDIbn0AwO0GNdSgjKagERwkjNweRG0bLx4+njVU2w+U/808tvBT5z3UNdl
         RNCr6r7fslqvJtKRUqdwj5TaBIr3b41tx+vYV+4UAXlBqZUzm9T8aQrvvYKvZ9I3EWht
         p0nkSSux5GnRu5ac7g3QWycvNzoQfqFC43l0Sau18xobPMMOjlJbVGV/c1oujvW1U8Or
         3LFN7GXXEtwKbomqdPbWv5/C5uB1q7MecPrQE3GDloeusZnoCQUtLk9KJQtADDOFPLyc
         7IwzjvYp4WeFVqvCefUjJOIPvkBwZ1VWu8Wk5Wr8fKZ2RKiMD30priqd8AV6pzYD+nLz
         UGmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=BMILtlu84n/xFFgb1AxY7d/g1A+z2VYlPRlJIUSADv8=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=WS996ucMylZ0Dp3Du4+lA8IcVpnlZvJ5i40hkLnSAo8cAUX0Kt0rcihHe/408vU4lo
         Zn/XB+zyk3YBXBxrfYsatxSvUlWnbPuZ0z++cdZuOoGBdxtZ61R8+k2I3VsVfPq9UXa2
         l7ZhD9tCHvHOm7hPnoFGYoI4qhcwly2hSKWIjgIqyggu7ncM8PT9puhLNY909KQJPJxJ
         w7ARI8uk42RrveMrfNnY/1MJNcBkW7U9O4G+vdtqyZhR6skxQwA8wG0Xcrb2Gl9jCsSZ
         QMoSc+w4RntN2nLO8jlhMqCjutVP5u0BvOukXInc84ROV5363Ns4DjzddSRqAKdz7aDv
         iwlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=eGWDd3WI;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702044724; x=1702649524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BMILtlu84n/xFFgb1AxY7d/g1A+z2VYlPRlJIUSADv8=;
        b=HFG6pexJA6Bl2brVpwgngs6GOmsWxI1tlgzdYQ1uJ1KDuS/O6h274WrfQxMJE1g3fw
         3GRkvkmWWeTwhYqQKZWG1ucIejMWIQa5fP9O+DI9RXDk15L9RLUJxgl20YFoi4KNNZ8p
         3GnxmHaPg6NusW1MWU3VyVBIlseK90vcrCLddRG2RyzoaXgVpAG+BEuEQZNb2KMYgp4w
         Ugqs72kmxIX21kUXlb3o6JyTtn9XZJnzhj1QCfT/e1ntOxQeCFbj+IuYNlJZpbSo9rVT
         KwJ3jAYXYrWBmG/H8Gq/A5L3O30dxhtigkX9kFMnPOMokw1xhhLjUB5O+flytdimcrn5
         8H7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702044724; x=1702649524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BMILtlu84n/xFFgb1AxY7d/g1A+z2VYlPRlJIUSADv8=;
        b=Ct74YQ+D6zsJ8ubcrL+ZTwUpFxKWKL2GqFS65NM0R3fFtLIAv7vorrAykGt++aV8bW
         wSw2gf442lXvAJgBOIyHnOQKEp5vuuO0GLL7ud3hgdACB+B1b3MlWd0MZ62LfSODyt82
         mCkhvDykiTSqDiR7iZWI4KoJ6lkwQyXpSmdnnCmA8MyZnPzqspY/K+JBHHmZcTOzSKO2
         yGQJjfwhlN99H06Ch4c9VmWvNpnWmS4u01hRUV/0xh1daRLqF4eU7XyKlyNnxWn2UU5q
         zHzn3EJx7TwZUZ0JFS/3/k1mG8tbV4qislQ7S81rtJVPSmteqKsF5my34Nyjn8gjQE4e
         drsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyiKUGaQcDcWOOyXaf05vvUNvCcPdBeIex1Fywfw95kgO4OygP3
	sh/O9KXC0YA0WBIWF4QNamM=
X-Google-Smtp-Source: AGHT+IHHZ1ZvDyhFTPf/1u8zNk1poguN0fG8YRq/OOe0ecV1GOB6tIkHni20Eq13SIex16y/XNceLw==
X-Received: by 2002:a17:902:e541:b0:1d0:cdaf:6c92 with SMTP id n1-20020a170902e54100b001d0cdaf6c92mr120606plf.26.1702044723719;
        Fri, 08 Dec 2023 06:12:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b286:b0:1d0:9a73:2fd0 with SMTP id
 u6-20020a170902b28600b001d09a732fd0ls17721plr.2.-pod-prod-01-us; Fri, 08 Dec
 2023 06:12:02 -0800 (PST)
X-Received: by 2002:a17:902:7612:b0:1cc:5378:6a56 with SMTP id k18-20020a170902761200b001cc53786a56mr60679pll.48.1702044722567;
        Fri, 08 Dec 2023 06:12:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702044722; cv=none;
        d=google.com; s=arc-20160816;
        b=fxe8QW44b/38/JX5BzvhkUKBBOnARNwD5V9/aNUcNg0F5+0EbP5N1l1kLlVdPkjECY
         CZh9RfRGWEYmQ/K7YgxXMl6hp1PH7A1yq5hlheVI/sVFAhTmUEdfPmsu1wos4bEJGA0x
         PZwvbSAZWyFK6WE+idar9K2krJ+XV7ub2KV6IDPN/2VLcTgAswEmiKhVGc8LaRovFXlu
         /4g8ImFfYUa6b7f9u4KtuyKEqCYW1T5WbBI6udJjPeRmZaJYgQW5JLP38jliHIjt1e8q
         7vQo+b+GgtblFj44uO3kdMrKnL6AODPCQYGj+EPKPOyGXvRGeh9q6ORUyk5GDcT8AwIV
         AbLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=pjb+6VN84nea2uIjeiseJx3tuY2waiFgw1F0aqU0WUc=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=xcVqGNUtd/9aMN/twCvfFRO1cTsM4gesiGY34ZxM1acnykF2HQ2ZdGuqZk8NrWGdY3
         WUXodB03t2zph8gbhly2VKIx9SY9YZcbDwP+ZeQIiWRVj0PlVvcIqmWRVCTqNRBIKfH5
         Y+j0TYarCv3yl/DJnftNqOIMJlPpZ4xL5OFo5gVZDDYO0zMMj8eaajmrz49vExLdpcZV
         rOtguqM1lYDsd++QEO76kD8TFVuUVSOWGgpGpCdYXll6a0Af0NJtbgrDZOjR7Udk9FxV
         ZTvYlVpdeJPSnyy13bJznLuG4pUqAnR2T5bB1de/Ws0gKEYeIK+Q0EuqEVoYZmtPXOye
         661A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=eGWDd3WI;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 17-20020a170902c21100b001d045f1d86asi130428pll.9.2023.12.08.06.12.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Dec 2023 06:12:02 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3B8DKRqj015375;
	Fri, 8 Dec 2023 14:11:59 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uv0cu81a5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 08 Dec 2023 14:11:58 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3B8EBvMb024578;
	Fri, 8 Dec 2023 14:11:57 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uv0cu80cj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 08 Dec 2023 14:11:57 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3B8DNTP9027021;
	Fri, 8 Dec 2023 14:07:12 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3utav39vds-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 08 Dec 2023 14:07:12 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3B8E79bX35062116
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 8 Dec 2023 14:07:09 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 851C020040;
	Fri,  8 Dec 2023 14:07:09 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 94BE320043;
	Fri,  8 Dec 2023 14:07:08 +0000 (GMT)
Received: from [9.171.76.38] (unknown [9.171.76.38])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri,  8 Dec 2023 14:07:08 +0000 (GMT)
Message-ID: <69e7bc8e8c8a38c429a793e991e0509cb97a53e1.camel@linux.ibm.com>
Subject: Re: [PATCH v2 13/33] kmsan: Introduce memset_no_sanitize_memory()
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
Date: Fri, 08 Dec 2023 15:07:08 +0100
In-Reply-To: <CAG_fn=Vaj3hTRAMxUwofpSMPhFBOizDOWR_An-V9qLNQv-suYw@mail.gmail.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-14-iii@linux.ibm.com>
	 <CAG_fn=Vaj3hTRAMxUwofpSMPhFBOizDOWR_An-V9qLNQv-suYw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: mSCq_lYucee2O1CVB9SBy2svcmxdcZAg
X-Proofpoint-ORIG-GUID: WlHzW7-H3uATOo0XFfgqaql_BSNz1z1A
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-08_09,2023-12-07_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501 mlxscore=0
 mlxlogscore=999 spamscore=0 clxscore=1015 phishscore=0 suspectscore=0
 impostorscore=0 bulkscore=0 lowpriorityscore=0 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312080117
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=eGWDd3WI;       spf=pass (google.com:
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

On Fri, 2023-12-08 at 14:48 +0100, Alexander Potapenko wrote:
> On Tue, Nov 21, 2023 at 11:06=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.=
com>
> wrote:
> >=20
> > Add a wrapper for memset() that prevents unpoisoning.
>=20
> We have __memset() already, won't it work for this case?

A problem with __memset() is that, at least for me, it always ends
up being a call. There is a use case where we need to write only 1
byte, so I thought that introducing a call there (when compiling
without KMSAN) would be unacceptable.

> On the other hand, I am not sure you want to preserve the redzone in
> its previous state (unless it's known to be poisoned).

That's exactly the problem with unpoisoning: it removes the distinction
between a new allocation and a UAF.

> You might consider explicitly unpoisoning the redzone instead.

That was my first attempt, but it resulted in test failures due to the
above.

> ...
>=20
> > +__no_sanitize_memory
> > +static inline void *memset_no_sanitize_memory(void *s, int c,
> > size_t n)
> > +{
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return memset(s, c, n);
> > +}
>=20
> I think depending on the compiler optimizations this might end up
> being a call to normal memset, that would still change the shadow
> bytes.

Interesting, do you have some specific scenario in mind? I vaguely
remember that in the past there were cases when sanitizer annotations
were lost after inlining, but I thought they were sorted out?

And, in any case, if this were to happen, would not it be considered a
compiler bug that needs fixing there, and not in the kernel?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/69e7bc8e8c8a38c429a793e991e0509cb97a53e1.camel%40linux.ibm.com.
