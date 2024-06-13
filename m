Return-Path: <kasan-dev+bncBCM3H26GVIOBB54IV2ZQMGQEQCV57FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FD1C907FC9
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 01:44:57 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-dfe71fc2ab1sf2692057276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 16:44:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718322296; cv=pass;
        d=google.com; s=arc-20160816;
        b=AxoH9qEl9Yr2d/nWqDkUwmF7czOAisaz6w2M36qd2H27bN4+JseaGhg5iJMzaxfd02
         6do4d1z9/V5nV3wYNuu5idTr4ZC4XMJDub/o5J4Hemcl8FOPXnR8bmHhVUNoWVSI5kfP
         1bLEj+OP7VtPWtQKs3Q64TRJ8y5ivOWAdmjEyXqbsI1+YtQR40P53rk+kUqukgn58szB
         gJku650D5qeAJ4AJalLRgP1f8rxfNnOxsppGiv47RraNd+n2xExb4a1E1e5cs8p/nfa6
         ye3fsm/BG6vJmDkw/afYAo47Q6W1gNUOP3vHr7dAzYW4f6RMhigLdhrKeqIesVjN7hgu
         08yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:user-agent:references:in-reply-to:date:cc
         :to:from:subject:message-id:sender:dkim-signature;
        bh=3hBCZ2AK5YbOEcq/kf4GW0nFAH8x2dNuV/CVrmU+5o4=;
        fh=EmDmpPTALA6YZxBTc5p7OBPTCDQ3BYRzVHsVgumaYlc=;
        b=BSpvwlTS2gS3FkttdBV0aGlfkiADUFg2QOOBb9u/YnuewRx//1qMiMfjjIO//6ApTD
         o8vIeltZvKfvH8XXpIOgQ6zkZUQLYndQtuoV+jJnO80CxMlCLKu65z5S4pJhC02dYj2J
         wuPELsYqFqhQWmEMjtLqeAqZytVhiDxf8dD0/w5WL0X/i0FwRTwfsd2OAK5nDgXnqYg7
         GsDuwI5nVfq/iVSqJykGIxQtS9qYs7IWZPyLQmBZ1LnaNCWJIfCCWTKv2eQEJ1YweEG7
         P5G33lDMpHx18PiUmBGI23c+d7oRMv3Bszz0Q0fQmZu9nilrJ9XhbmVuRXrHxB65uOJC
         h7aQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mRoEpD07;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718322296; x=1718927096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:user-agent
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3hBCZ2AK5YbOEcq/kf4GW0nFAH8x2dNuV/CVrmU+5o4=;
        b=u2E+kCvpSATdk+FMNE5Bioe7cyin4yjO9SmIr4L4y17xo05pcvqfWCBmuBRgmIWzeo
         LVhVDUjX7rg9UyqK0ueKH1KVX2L47xLB4QI7RQrFC7sG6C2ONC3d0htzElh2bkZn5WOT
         c9cbczK6vX6UxWzx4ZJzePQQQZoBjfyBwzNQjQ44cvMEeSSEZmRTaIG7zoLufIx/VU3p
         4SM4aidSQbuZ5Du1Zf0tRhMlQDoirwBQPsaH2IbnRVDY2+VXG/5h6Eo1u1okfeSSPtm6
         4MmuTNScgwOqtNi9CJUQYaHVcPLQUMbxFekhZVOnT4RqShwxDUJG7XpdTzKUQyO3LCTx
         GhRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718322296; x=1718927096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:user-agent:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3hBCZ2AK5YbOEcq/kf4GW0nFAH8x2dNuV/CVrmU+5o4=;
        b=fu2mv6q06yGqcbpAoKLCamK0c6cobDA0y68aPZ0EWEPU5dpT/Y03Mg753ClLzY6RuJ
         WVVFMBmY0UnU71EYS2+O2aUWLJguQ+79kT88Cchm3oLqiUs9d5WXgj1Zjp4pICga56SN
         miRy9FmwCygqoSXzl5IRv29dSN+dOmZoyDex51dLMfqd9IeYYF0iwyVjzk+q8BFnanTV
         r5y/yClsC8w9+lh1u+i6LEx3SJw0bSeQUQDZHpKq84hA4RclePfVC+Nrm7Jbln47L0hs
         gLEDz7UtA+WjZnpnO3xhyOPy7zjwT4LzWn2dqihmcfaO72bBE2yojcaGFQIsqLNdaxwJ
         Oe/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtpAU1/vqWobMjHuTEDBf7o2QjWkPuH92pjGR6YTfb1xTkI1aouVIB0/3IWD6Jrlx7LqP494l33A+cVHr4Eb7ulkV6jtqUjw==
X-Gm-Message-State: AOJu0Yx5BvbRff4mMQ26COb/6A8hFPhGkWR4kMtkPQ9RnxY07+6u9obc
	eQLA7umTia1AkhpJB2DcpqK7VJTBWpGkcqVpxLKU85sBiCVWxq3E
X-Google-Smtp-Source: AGHT+IEhNgcb8jm73d6G2yNNTOdm79TbP5QZDjEBIjCaKc4PZ1oggWr+FBqMLJ71+z/vzAe+btmsNQ==
X-Received: by 2002:a25:c543:0:b0:df6:889:a79c with SMTP id 3f1490d57ef6-dff154d16admr946788276.54.1718322296025;
        Thu, 13 Jun 2024 16:44:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1023:b0:dfb:14a0:3d5f with SMTP id
 3f1490d57ef6-dfefe9efd41ls2392668276.1.-pod-prod-05-us; Thu, 13 Jun 2024
 16:44:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIa+PeSuAlOqt7NTAThR4IexY/oan3C1yiGpTYRoBtOXVts3f2+iecIwNn51ejcdYpvZPGJxYfDj+hByDBn+Lbn6YAT5GVBmy/kQ==
X-Received: by 2002:a25:9785:0:b0:dfb:868:816f with SMTP id 3f1490d57ef6-dff15385bc4mr1089795276.18.1718322294865;
        Thu, 13 Jun 2024 16:44:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718322294; cv=none;
        d=google.com; s=arc-20160816;
        b=y3TsFmTubP+ekDDCDQqIxJ6xszzA7QIavFdVLVaYbGB5z14ZjUrHYa6qNTOc8ANVu8
         Zw2O2Mi5/j39zwVgHfvdQ7CbfsGwynoIQakdFJyDBr8AKfB5BhIysWiEyHio32aOLrvX
         lAYmHAzQejJgqDHIyJ9cAl8mtuisuypBogYFUOPW+0cY8fyJLYOZ/q1lUNansf3KTXtX
         YMPDbqmvFiuTJBSao6Sk+UMwxGjDIGkCQwmnXU5xz4doH7ZE/buyRxil81XX/aTGme5b
         Iyhf6RuCNCzhGD4A7cZLiycdDRwEykFBhhTnaKaGgejT4EBTbhf51GFQmS+Iml16vj+/
         3iHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=Noz5pwMBvsmGR387X0Jg77Dw0n+SZY9A1aVzP4jEPgA=;
        fh=NCTHEJVo07iGHipdtTxYyBjX2nnsLy8E9D81+qu81AI=;
        b=wv0QcdeKzp2FweFvftQ+U0vVL4PWneAHSgJYbAfRHK1ptqX/LS6Vvt3D49H+iL9ojY
         YenSbhAMMe3unV7eaNCv/PqJP8PKOd5J4wcmBtpdb01VhkmtQLIBqYbRL5kB6YpcP52I
         nCgldEpgBMmD8VXUpCGdtfuksfdWV4yrv95znrp74BgkB/+mc8AWwowFdKgScOZLzMOE
         QkKAurtcavdJJGKq0Ca03D8lLqw+dzrGohwzmLmjo5EGlz6zQlCDX6sO0FgwOBC5C1Qq
         i9VpO3UYJma/dN5oAcM+DyHdq+uUTeSwHEg9yWKrocly34IsUt4+CM3CEsy10DPoNkN0
         ik0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mRoEpD07;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5a28c00si811646d6.2.2024.06.13.16.44.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 16:44:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DNSkeK022003;
	Thu, 13 Jun 2024 23:44:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yrafg80vh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 23:44:48 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DNiloE015324;
	Thu, 13 Jun 2024 23:44:47 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yrafg80vc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 23:44:47 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DMDGBr028710;
	Thu, 13 Jun 2024 23:44:46 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1muvqwm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 23:44:46 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DNiflA47513912
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 23:44:43 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0F78120043;
	Thu, 13 Jun 2024 23:44:41 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A100A20040;
	Thu, 13 Jun 2024 23:44:39 +0000 (GMT)
Received: from [127.0.0.1] (unknown [9.152.108.100])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 23:44:39 +0000 (GMT)
Message-ID: <5a8a3c85760c19be66965630418e09a820f79277.camel@linux.ibm.com>
Subject: Re: [PATCH v4 12/35] kmsan: Support SLAB_POISON
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: SeongJae Park <sj@kernel.org>, Alexander Potapenko <glider@google.com>
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
Date: Fri, 14 Jun 2024 01:44:39 +0200
In-Reply-To: <20240613233044.117000-1-sj@kernel.org>
References: <20240613233044.117000-1-sj@kernel.org>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: R8Ge89LT8ke23MedEmj8fyVcr9NYVe3c
X-Proofpoint-GUID: xkSosI_V3EwHip4n10hyZ_Dwths6J4Ly
Content-Transfer-Encoding: quoted-printable
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_13,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 suspectscore=0 clxscore=1011 mlxscore=0 mlxlogscore=999 lowpriorityscore=0
 malwarescore=0 adultscore=0 bulkscore=0 priorityscore=1501 phishscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mRoEpD07;       spf=pass (google.com:
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

On Thu, 2024-06-13 at 16:30 -0700, SeongJae Park wrote:
> Hi Ilya,
>=20
> On Thu, 13 Jun 2024 17:34:14 +0200 Ilya Leoshkevich
> <iii@linux.ibm.com> wrote:
>=20
> > Avoid false KMSAN negatives with SLUB_DEBUG by allowing
> > kmsan_slab_free() to poison the freed memory, and by preventing
> > init_object() from unpoisoning new allocations by using __memset().
> >=20
> > There are two alternatives to this approach. First, init_object()
> > can be marked with __no_sanitize_memory. This annotation should be
> > used
> > with great care, because it drops all instrumentation from the
> > function, and any shadow writes will be lost. Even though this is
> > not a
> > concern with the current init_object() implementation, this may
> > change
> > in the future.
> >=20
> > Second, kmsan_poison_memory() calls may be added after memset()
> > calls.
> > The downside is that init_object() is called from
> > free_debug_processing(), in which case poisoning will erase the
> > distinction between simply uninitialized memory and UAF.
> >=20
> > Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> > ---
> > =C2=A0mm/kmsan/hooks.c |=C2=A0 2 +-
> > =C2=A0mm/slub.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 13 ++++++++=
+----
> > =C2=A02 files changed, 10 insertions(+), 5 deletions(-)
> >=20
> [...]
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -1139,7 +1139,12 @@ static void init_object(struct kmem_cache
> > *s, void *object, u8 val)
> > =C2=A0	unsigned int poison_size =3D s->object_size;
> > =C2=A0
> > =C2=A0	if (s->flags & SLAB_RED_ZONE) {
> > -		memset(p - s->red_left_pad, val, s->red_left_pad);
> > +		/*
> > +		 * Use __memset() here and below in order to avoid
> > overwriting
> > +		 * the KMSAN shadow. Keeping the shadow makes it
> > possible to
> > +		 * distinguish uninit-value from use-after-free.
> > +		 */
> > +		__memset(p - s->red_left_pad, val, s-
> > >red_left_pad);
>=20
> I found my build test[1] fails with below error on latest mm-unstable
> branch.
> 'git bisect' points me this patch.
>=20
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 CC=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 mm/slub.o
> =C2=A0=C2=A0=C2=A0 /mm/slub.c: In function 'init_object':
> =C2=A0=C2=A0=C2=A0 /mm/slub.c:1147:17: error: implicit declaration of fun=
ction
> '__memset'; did you mean 'memset'? [-Werror=3Dimplicit-function-
> declaration]
> =C2=A0=C2=A0=C2=A0=C2=A0 1147 |=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __memset(p - s->red_=
left_pad, val, s-
> >red_left_pad);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 ^~~~~~~~
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 memset
> =C2=A0=C2=A0=C2=A0 cc1: some warnings being treated as errors
>=20
> I haven't looked in deep, but reporting first.=C2=A0 Do you have any idea=
?
>=20
> [1]
> https://github.com/awslabs/damon-tests/blob/next/corr/tests/build_m68k.sh
>=20
>=20
> Thanks,
> SJ
>=20
> [...]

Thanks for the report.

Apparently not all architectures have=C2=A0__memset(). We should probably g=
o
back to memset_no_sanitize_memory() [1], but this time mark it with
noinline __maybe_unused __no_sanitize_memory, like it's done in, e.g.,
32/35.

Alexander, what do you think?

[1]
https://lore.kernel.org/lkml/20231121220155.1217090-14-iii@linux.ibm.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5a8a3c85760c19be66965630418e09a820f79277.camel%40linux.ibm.com.
