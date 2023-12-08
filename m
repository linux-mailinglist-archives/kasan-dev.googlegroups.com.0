Return-Path: <kasan-dev+bncBCM3H26GVIOBBM6JZSVQMGQEX7SN74Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D001880A535
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 15:14:12 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-58e2b7e4f94sf2309510eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 06:14:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702044851; cv=pass;
        d=google.com; s=arc-20160816;
        b=YHzFvD81RVzZu8ZArt0aXIxJZyX/9Kzh25LIdPqAcvJ2Ch16X0EFWxaenpTilhikFA
         TV3pPP+46FwKnSwFul6Y/CHkos9d4ovDyS2bBufGfPY2zUfsgdmWFceHK4N6Ut8LvgAY
         EYceMgtu/Gk4KWvBGX8KiEu84d5asKENvDhCxW+wVonLqH6U/Ty5Pnxj3ETJExx6yN0M
         eRFUq5wYfBDQiHMU7cZDu58UpntWOEY8dH73RLX3AQ8Id23u+Ec2tt/u5hlch4WvMgqE
         H/eD6PKHHesrYzw5tJZJviXSgtQT6a6lXysd8e2aHAy4IbjCCqjf1HnfFhrgXje8k6H5
         OXhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=Y/XVq2U5XuLZnzVr23amBjIrV2DoZWo6dU8MCr6n8H0=;
        fh=wGDOQlDrnKfwUTwnTjCIEkCzzSI03tkPyQed+a2bPsE=;
        b=OhXoJA6X3SRblWYtyWvg5TERiXkvWhFMz9rsWCcmYdo2k+C1yXYDGoU+CRqFGL/iwo
         VeAvdJtIpuR+ozzeHH0aWZxs3Xa+mjJEnHwX3LFBDjfI3xpo6psh9xj/+3tOHMzWftVh
         cfAFc6gggffKE/0OV/A+v5V67m7w9j7QgLMxrgEK43U1GBxQL7990++mrOyyum4B2J2z
         EzjRcPT+hKcHcGvF9VOV+Q+UveEYonSnA6GkN0D2BSmVlzWbU98hOEXI/ASjbWinIBeK
         nlfQN0YdoZTwurlW6ivkgg2J/JsKS4LEJK8qVLHatbu5oa8ciySjR97vTsfZxTSqwYHZ
         DGsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DED7RfPS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702044851; x=1702649651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y/XVq2U5XuLZnzVr23amBjIrV2DoZWo6dU8MCr6n8H0=;
        b=Gd4ROKQBeEZnra03sPPWSDjQ/veam6ZGGfGuBAlmz4Py0hPGBUFlpsz9W7ObsaZ6N+
         FSUn073LcO3tSeEXYaG3tV37HNl8VdHMvrhllfLoDNqREzou9A3r0ygH/uQo30++YQLX
         7ftofnXinx6qpcdnnhc0hYKSRnCObfWjey1icFXATM0VDLFMKhjo5Qx9p+OriWPZbSUd
         9IJPqg8VDnObGmIP4gl7esILWXZDadgnH8YCV37b10fivdGXuPR3aBW2juoD0/z52Uwg
         8hoH+eiyuNiPhENND+QDIlIQ/sUt3hc7sIPlyBgQ5X85FNMkZUU+YE4iHq4UnnUSnMWY
         SMfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702044851; x=1702649651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y/XVq2U5XuLZnzVr23amBjIrV2DoZWo6dU8MCr6n8H0=;
        b=ma1WEZJw9VUZ93xZIbVNA8nEdEs5nwdpJgEOnlV6w+l/eg71P3oCM4GXTgDKTydc1+
         JvHS1We4lsd3c/9u8fJ1TxUb7aFIe0nj3f6FgqWD5JetLBQxlnomfLzKmM6VGceiosAi
         q/em03nJ7YqcEKZOInRRf5fZy2OI5T0JMAbOL1TiEEGGdEOQ7QNt8yu1bai6FLFW3hX0
         cjFvDmQb92iisdSv47d2bA5r6l7UlEe/qUCtHkhYDd261pJ788L9jK+yu5uF1OTPPONL
         04FyWUnJPrT5h2xq6B6YLoiuPnxPhlHPmTVteqsJ7sqT73WD0VLY8SI0TGwMASIV9cZj
         Th0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YycknRzvbh9fFczemNtoTVwRVONhdzHRbWtSoA4AXlJUIoXounV
	bfI4LO61h7DRUhp++iOy3ek=
X-Google-Smtp-Source: AGHT+IGXwXzI512zr9YN7oV4zmiWRMI89LbNkJM95BwVZhSiG2zQ5WFfNCwX69frJbyNAfXj6i/PQA==
X-Received: by 2002:a4a:9d5e:0:b0:590:930b:cfc7 with SMTP id f30-20020a4a9d5e000000b00590930bcfc7mr104320ook.18.1702044851608;
        Fri, 08 Dec 2023 06:14:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1612:b0:58d:d4e0:4e with SMTP id
 bb18-20020a056820161200b0058dd4e0004els3660133oob.2.-pod-prod-09-us; Fri, 08
 Dec 2023 06:14:11 -0800 (PST)
X-Received: by 2002:a9d:7d84:0:b0:6d8:7ee8:29b8 with SMTP id j4-20020a9d7d84000000b006d87ee829b8mr93666otn.8.1702044850845;
        Fri, 08 Dec 2023 06:14:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702044850; cv=none;
        d=google.com; s=arc-20160816;
        b=jQJlA/AB6eISGsWA3oN0XSDJDk4y95Pt66f8Y4lYZiz3nS/t6j3+48oYkxTC6sdr/r
         rkAdFilidem9QLPvpAIIDk8jr3ysTBpNMvAL+riuloGA1zYd+lA+V/D3raziXr09btds
         oBXyH4FgN+rdfIpl7ryF1dW8FpiXmhLvwM+lZzHUtDRU2E4UGFWjRrL0Ekd6ZfV4qxcq
         SJDDHKq/5SlEAuo7svY+PH0PZ02XcBh8cBL61yamir7O8VkXWoBHRCRqGbsoJA7VllPK
         xAXYixBOTwjt22I7CYv+Uq9tJzN7evNEHVR/aCBk2BVpgBWhQXLnkNWOG/TwakCpOwHu
         AALg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=3G7Rfp1wGPTrFcOUcQ8bqn3AoifuA4aNkt4dozPC+NA=;
        fh=wGDOQlDrnKfwUTwnTjCIEkCzzSI03tkPyQed+a2bPsE=;
        b=g6wmi+QEvtKf4XH7m2Ap4zYDa/nLMpjCe9wgqI7B+RSGvRtVl5wzS6BQpBycMJvtcI
         0hM9sNjsr/qtx7ixQlN1XWOddMFIqXnlDz5DVWadlFhhtzNlG4cr4IWxJWnce0hE+YO6
         Gj/FUxSam4kbj6muOHSC+oDHb3iwyQSrNtbJk9nFyZz3Mdu1HF9o1p7CEzkn03htaAdz
         fGP4ioTYBb/zmwVa55u0U5aoVR0eekYFLSUt9hZyhHz8V6y1FEkydr0aTz3pcQghzvvN
         s1wjIYiFXvOnQkEduvKpq8ObloCTKDR0h4RXCnauDU4V647sYohLyBjSntOxhuUC5mf9
         +BnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DED7RfPS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id j27-20020a0561023e1b00b00466025e2258si485447vsv.2.2023.12.08.06.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Dec 2023 06:14:10 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3B8DIRoF002996;
	Fri, 8 Dec 2023 14:14:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uv3p3hwpu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 08 Dec 2023 14:14:07 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3B8DIWuA003552;
	Fri, 8 Dec 2023 14:14:06 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uv3p3hwpe-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 08 Dec 2023 14:14:06 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3B8DY3dY027096;
	Fri, 8 Dec 2023 14:14:05 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3utav39wbt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 08 Dec 2023 14:14:05 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3B8EE2PY7471714
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 8 Dec 2023 14:14:03 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D6F0D2004B;
	Fri,  8 Dec 2023 14:14:02 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8C55A20040;
	Fri,  8 Dec 2023 14:14:01 +0000 (GMT)
Received: from [9.171.76.38] (unknown [9.171.76.38])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri,  8 Dec 2023 14:14:01 +0000 (GMT)
Message-ID: <4f0eb4b4d4f6830f39555dc8a35f6ff88d6f8e63.camel@linux.ibm.com>
Subject: Re: [PATCH v2 19/33] lib/zlib: Unpoison DFLTCC output buffers
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
 <svens@linux.ibm.com>,
        Mikhail Zaslonko <zaslonko@linux.ibm.com>
Date: Fri, 08 Dec 2023 15:14:01 +0100
In-Reply-To: <CAG_fn=WiT7C2QMCwq_nBg9FXZrJ2-mSyJuM1uVz_3Mag8xBHJg@mail.gmail.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-20-iii@linux.ibm.com>
	 <CAG_fn=WiT7C2QMCwq_nBg9FXZrJ2-mSyJuM1uVz_3Mag8xBHJg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: hoRrnOaWeMBzUuRaToAfGaqdk4G_1Fq_
X-Proofpoint-ORIG-GUID: Q-kY3HiQsqOVFy02f6bQ466_FlOXn4Ht
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-08_09,2023-12-07_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 mlxscore=0 spamscore=0 adultscore=0 phishscore=0 bulkscore=0
 suspectscore=0 malwarescore=0 mlxlogscore=774 lowpriorityscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312080117
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=DED7RfPS;       spf=pass (google.com:
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

On Fri, 2023-12-08 at 14:32 +0100, Alexander Potapenko wrote:
> On Tue, Nov 21, 2023 at 11:07=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.=
com>
> wrote:
> >=20
> > The constraints of the DFLTCC inline assembly are not precise: they
> > do not communicate the size of the output buffers to the compiler,
> > so
> > it cannot automatically instrument it.
>=20
> KMSAN usually does a poor job instrumenting inline assembly.
> Wouldn't be it better to switch to pure C ZLIB implementation, making
> ZLIB_DFLTCC depend on !KMSAN?

Normally I would agree, but the kernel DFLTCC code base is synced with
the zlib-ng code base to the extent that it uses the zlib-ng code style
instead of the kernel code style, and MSAN annotations are already a
part of the zlib-ng code base. So I would prefer to keep them for
consistency.

The code is also somewhat tricky in the are of buffer management, so I
find it beneficial to have it checked for uninitialized memory
accesses.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4f0eb4b4d4f6830f39555dc8a35f6ff88d6f8e63.camel%40linux.ibm.com.
