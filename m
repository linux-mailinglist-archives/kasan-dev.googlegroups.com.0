Return-Path: <kasan-dev+bncBCM3H26GVIOBB76C2GZQMGQE7DXGB3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E8057910E05
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 19:06:09 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-6f18f1ec8d8sf1094501a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 10:06:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718903168; cv=pass;
        d=google.com; s=arc-20160816;
        b=LzXLVmxRlt3A+2vbwSvzJz7+Ky2lkJyxkpEfhRXEW/MlSKr9NzPTamnLln5hDGshZ5
         G2xHMOPHpnu0PDb5NiJSWYOsmuzvrfwGKvur55+KC6EN1MhgjVwr+ZjzOHBpBKyNnSQD
         5F/htqnyd2vNVWXQ15tSYTX2PJwxwvVnBbp5bL7+Sw86NYGhZO2KS5GU//EkZaxVRR+V
         hSnzxaGtBmcUuB6HW9CYH4+Ows5d61tRz2NvFtRW0lUfZXABhK+V5OP6v8IJsJdk6Pfl
         mUdjnKIjvhrtNC/Wxt0VpvkQ/HI0wD5RdPQmCmdwaBf9kfB0rd/Dn6CRMbNaIkTmQLAn
         rEdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=OK9VvFxu4c3TwmkxejECior/QRMzranqL67Dhc/tSFg=;
        fh=6ubqvxa6j4jikyFbAEiZzar3RJNwBOIX8w+OVJmtq9g=;
        b=m97e65OOKY6wYkY2IDKDRwjSohsnJm+BfICh7g2g6+0uhmhoXKXF19NmtI3u36NnAd
         J3/VhzzM1Gi+o2dHRulpyVVK7ETsOQDa6wgVF6YRFhV2YvZdQk06Wa6TaGRjZa3Nbtx3
         3qv/LnbEXIFggOElJSOLvp4eZienBoEX3xLhQQyja9mtrbyjX/jnJDcaeKDcPidhZjem
         AT5PDxdgrVRSbv0fJM0JG13sq84S+dzHIae8AKd1ML+aWbVLn2qUJRV5bJe2tggxLUzE
         7lO7mAvk9sYYQ02Pu9MHcFlRzBRT9NujlUjZQHG/UOcQDfXWG5MbSL/rY1hcvmd6S32V
         LTaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WpEf61lL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718903168; x=1719507968; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OK9VvFxu4c3TwmkxejECior/QRMzranqL67Dhc/tSFg=;
        b=gAgmUVXvJndY+OUPsxKDy7YgvI7TOkg/WxLByDT6yF16qIpSXIa/JKsXIkuTTuXFji
         t8r3/3MDmaE12bGrBCZXFLzS/RDK+0PE8hsH1mlaOyzwGVIUYmEFEBokv5sinXo9mJ/l
         yEqckMjMh+767hz5zvnXtdP+4vIaqxdP8wjmsGGyqXz+okqQkZx80YU3Wdd6DU53sA5T
         1nLuw2Wxz0V69gy/iZL76dHRtAeT9H/gUHmnguUPGLtnXKmnbdYDHc+TKylFHruaoU0/
         meKXClB0uwFTnZie1TSrIUvAB3JY9UnCyqEPMwSWopjwMwKeib9Md7EcQ5u8NkSvTAks
         Wfdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718903168; x=1719507968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OK9VvFxu4c3TwmkxejECior/QRMzranqL67Dhc/tSFg=;
        b=OENTxrWHNZKosVymY29XqvyRfB8p42OJ/STB1Xdb1N91gsFJwAVXhvMXW1nS84jdWJ
         hHG+jGP55lgC4Bd498+5vW+uEGo8LbtySA0XlmGMmOQJDnFcTlAUQ6+YU5eHsXtfbsVc
         NYaQVqubysknijemBFb/nj0YMtARGUrKFOvzj5UkOeqEdl1GEV+E6LeJHoTNaAbgDLLK
         pS8bhx4CTiU7H+lpUM3fGy5mCGi0uoYf1zDC2y9V8oZiID0TzwaVYWUA/5pphVZZe8+W
         iDzFe6reMw107plwwoc1VbaG95F3ti2qMfv9Mr+7o2KtNx1SzY0jox8+B4OPPNWGEkwq
         M7Nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQ9Cx5Ws0ETIdyUbxLxm47pRlmppKxy9JqMRpFde3fdgvRYBp0UcgwfMDzX5tBgXSN3gnJ7aJxxmSQp42Rp8uaxVURNNhMfg==
X-Gm-Message-State: AOJu0Yz04KlCRHv6Hze9lv7fFRvvWPprwDJwllZ0uRKVcCfSj5jC1Vk8
	vxIcuSAAY/A7nPYAwjQ2mBn8dvqDITq/ip8qvz4cIA8GTRbLi7wN
X-Google-Smtp-Source: AGHT+IGWQ/p6wYhof/+nsce3d2fRsSaFaq18xwv1O0uBg+XGSztOlqm+q/VJME5hsQQwKU30USws0g==
X-Received: by 2002:a05:6a20:6da9:b0:1b8:593e:ff1e with SMTP id adf61e73a8af0-1bcbb5cd3e1mr5240606637.34.1718903167742;
        Thu, 20 Jun 2024 10:06:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d11:b0:702:6c74:677 with SMTP id
 d2e1a72fcca58-70640c7d569ls648424b3a.0.-pod-prod-04-us; Thu, 20 Jun 2024
 10:06:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3bmg2lXajyP9mMtAC2EUb7iejTM6jjWJr+okoGvuR/SXGHtW2EMiZsWiGeGbvON+Hlw2r/xUaPFQZHrJEzeYROvBxuVnkSmCx9g==
X-Received: by 2002:a62:f845:0:b0:704:2f2b:a2bd with SMTP id d2e1a72fcca58-70629cef07emr5573198b3a.27.1718903166275;
        Thu, 20 Jun 2024 10:06:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718903166; cv=none;
        d=google.com; s=arc-20160816;
        b=WFgrG33BCKoeMMeoc8GA0HWflojl34pb9wsYLE6cM/9iiq6nDCRXtDwwFhq0yafljm
         PZ6p3GT3OxBZawOgEfWYDpD30P6GXkXONGNRjMMbelJ/4qJdiZBsP6ciSILwB6BvkHsr
         lGbrIvn24LFD+RGmO+BtwYNucHEG7dDrBzItUUdb3kDLUWBy90BD1JJI4+jvpflAheE+
         XFlmwhSS2DfjJygRjQE+/TIhr/Jf6NYaUPPmQ2Aw6hrZgrjSEjfeDc2XTvt7/LshoMJW
         4/ywp9zlt7w2qF4XtnSkBMW+kYo9Uoxj3Yz/rgOhoxeK2e498d9mekb+pXPCy7mkctEf
         b2AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=aZefvX2i2zdaaemPAMbUWZ55XJ/KZi7qSCtrnSRv/hs=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=nUq/0+Oe3OObm2CsV5ZDHrmtiAp4ZSPuiyMJ/w3D/XufwKdr/8PnkdDBlFo0BlIuSJ
         SZMXYfmh9CguXqax/vwwg8MmBLuKdzBXNuJkt3a1CtmLA4z+qzTOMmwedj73PPMwiZ71
         DTf0RlanwvR6wj0EU3LVQm2ko+bFwFnekc8RQlaOoICnEPhZZeuz189F2eQF1W7UlLp0
         /zA3iXT1JiQAkp264upN5384atA7vjXTfeHVn2bPayWHO98A1f4DYKntTUPmDBJ6sVJs
         vnD9wKPd7iglrNZjld5vMEZjjo+G9xoD72bNa+XCBioB+mOOwbEJzyBVBd2accMFupBI
         fqHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WpEf61lL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705ccbb1c94si661694b3a.5.2024.06.20.10.06.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 10:06:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KGw4nC024890;
	Thu, 20 Jun 2024 17:06:01 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvqymr31b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 17:06:01 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45KH60lE006975;
	Thu, 20 Jun 2024 17:06:00 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvqymr316-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 17:06:00 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KFOWgb019670;
	Thu, 20 Jun 2024 17:05:59 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysnp1re64-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 17:05:58 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45KH5qkU42205492
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 20 Jun 2024 17:05:54 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B54F220043;
	Thu, 20 Jun 2024 17:05:52 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 464A820069;
	Thu, 20 Jun 2024 17:05:51 +0000 (GMT)
Received: from [127.0.0.1] (unknown [9.152.108.100])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 20 Jun 2024 17:05:51 +0000 (GMT)
Message-ID: <2fe48485c7181b4fe3a39882f495babebadad595.camel@linux.ibm.com>
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
Date: Thu, 20 Jun 2024 19:05:50 +0200
In-Reply-To: <aaef3e0fe22ad9074de84717f36f316204ae088c.camel@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
	 <20240619154530.163232-34-iii@linux.ibm.com>
	 <CAG_fn=V8Tt28LE9FtoYkos=5XG4zP_tDP1mF1COfEhAMg2ULqQ@mail.gmail.com>
	 <aaef3e0fe22ad9074de84717f36f316204ae088c.camel@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: j17PtW7VvRI5cDmaVdbvQOn8NhUFba9g
X-Proofpoint-ORIG-GUID: CB6tpAHI_NWQszkbL50NdGp2bn9CzjB5
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_08,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 mlxlogscore=668 clxscore=1015 phishscore=0 adultscore=0 priorityscore=1501
 spamscore=0 malwarescore=0 suspectscore=0 mlxscore=0 bulkscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406200122
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WpEf61lL;       spf=pass (google.com:
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

On Thu, 2024-06-20 at 13:19 +0200, Ilya Leoshkevich wrote:
> On Thu, 2024-06-20 at 10:36 +0200, Alexander Potapenko wrote:
> > On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich
> > <iii@linux.ibm.com>
> > wrote:
> > >=20
> > > put_user() uses inline assembly with precise constraints, so
> > > Clang
> > > is
> > > in principle capable of instrumenting it automatically.
> > > Unfortunately,
> > > one of the constraints contains a dereferenced user pointer, and
> > > Clang
> > > does not currently distinguish user and kernel pointers.
> > > Therefore
> > > KMSAN attempts to access shadow for user pointers, which is not a
> > > right
> > > thing to do.
> >=20
> > By the way, how does this problem manifest?
> > I was expecting KMSAN to generate dummy shadow accesses in this
> > case,
> > and reading/writing 1-8 bytes from dummy shadow shouldn't be a
> > problem.
> >=20
> > (On the other hand, not inlining the get_user/put_user functions is
> > probably still faster than retrieving the dummy shadow, so I'm fine
> > either way)
>=20
> We have two problems here: not only clang can't distinguish user and
> kernel pointers, the KMSAN runtime - which is supposed to clean that
> up - can't do that either due to overlapping kernel and user address
> spaces on s390. So the instrumentation ultimately tries to access the
> real shadow.
>=20
> I forgot what the consequences of that were exactly, so I reverted
> the
> patch and now I get:
>=20
> Unable to handle kernel pointer dereference in virtual kernel address
> space
> Failing address: 000003fed25fa000 TEID: 000003fed25fa403
> Fault in home space mode while using kernel ASCE.
> AS:0000000005a70007 R3:00000000824d8007 S:0000000000000020=20
> Oops: 0010 ilc:2 [#1] SMP=20
> Modules linked in:
> CPU: 3 PID: 1 Comm: init Tainted: G=C2=A0=C2=A0=C2=A0 B=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 N 6.10.0-rc4-
> g8aadb00f495e #11
> Hardware name: IBM 3931 A01 704 (KVM/Linux)
> Krnl PSW : 0704c00180000000 000003ffe288975a (memset+0x3a/0xa0)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 R:0 T:1 IO:1=
 EX:1 Key:0 M:1 W:0 P:0 AS:3 CC:0 PM:0 RI:0
> EA:3
> Krnl GPRS: 0000000000000000 000003fed25fa180 000003fed25fa180
> 000003ffe28897a6
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000000000000=
0007 000003ffe0000000 0000000000000000
> 000002ee06e68190
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000002ee06f1=
9000 000003fed25fa180 000003ffd25fa180
> 000003ffd25fa180
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000000000000=
0008 0000000000000000 000003ffe17262e0
> 0000037ee000f730
> Krnl Code: 000003ffe288974c: 41101100=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 la=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 %r1,256(%r1)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000003ffe288=
9750: a737fffb=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
brctg=C2=A0=20
> %r3,000003ffe2889746
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 #000003ffe2889754:=
 c03000000029=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 larl=C2=A0=C2=A0=20
> %r3,000003ffe28897a6
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 >000003ffe288975a:=
 44403000=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ex=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 %r4,0(%r3)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000003ffe288=
975e: 07fe=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 bcr=C2=A0=C2=A0=C2=A0=C2=A0 15,%r14
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000003ffe288=
9760: a74f0001=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
cghi=C2=A0=C2=A0=C2=A0 %r4,1
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000003ffe288=
9764: b9040012=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
lgr=C2=A0=C2=A0=C2=A0=C2=A0 %r1,%r2
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 000003ffe288=
9768: a784001c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =
brc=C2=A0=C2=A0=C2=A0=20
> 8,000003ffe28897a0
> Call Trace:
> =C2=A0[<000003ffe288975a>] memset+0x3a/0xa0=20
> ([<000003ffe17262bc>] kmsan_internal_set_shadow_origin+0x21c/0x3a0)
> =C2=A0[<000003ffe1725fb6>] kmsan_internal_unpoison_memory+0x26/0x30=20
> =C2=A0[<000003ffe1c1c646>] create_elf_tables+0x13c6/0x2620=20
> =C2=A0[<000003ffe1c0ebaa>] load_elf_binary+0x50da/0x68f0=C2=A0=20
> =C2=A0[<000003ffe18c41fc>] bprm_execve+0x201c/0x2f40=20
> =C2=A0[<000003ffe18bff9a>] kernel_execve+0x2cda/0x2d00=20
> =C2=A0[<000003ffe49b745a>] kernel_init+0x9ba/0x1630=20
> =C2=A0[<000003ffe000cd5c>] __ret_from_fork+0xbc/0x180=20
> =C2=A0[<000003ffe4a1907a>] ret_from_fork+0xa/0x30=20
> Last Breaking-Event-Address:
> =C2=A0[<000003ffe2889742>] memset+0x22/0xa0
> Kernel panic - not syncing: Fatal exception: panic_on_oops
>=20
> So is_bad_asm_addr() returned false for a userspace address.
> Why? Because it happened to collide with the kernel modules area:
> precisely the effect of overlapping.
>=20
> VMALLOC_START: 0x37ee0000000
> VMALLOC_END:=C2=A0=C2=A0 0x3a960000000
> MODULES_VADDR: 0x3ff60000000
> Address:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 0x3ffd157a580
> MODULES_END:=C2=A0=C2=A0 0x3ffe0000000
>=20
> Now the question is, why do we crash when accessing shadow for
> modules?

So, Alexander G. and I have figured it out. KMSAN maps vmalloc/modules
metadata lazily - when the corresponding memory is allocated. Here we
have a completely random address that did not come from a prior
vmalloc()/execmem_alloc(), so the corresponding metadata pages are
missing.

We could probably detect this situation and perform the lazy
initialization in this case as well, but I don't know if it's worth the
effort.

> I'll need to investigate, this does not look normal. But even if that
> worked, we clearly wouldn't want userspace accesses to pollute module
> shadow, so I think we need this patch in its current form.
>=20
> [...]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2fe48485c7181b4fe3a39882f495babebadad595.camel%40linux.ibm.com.
