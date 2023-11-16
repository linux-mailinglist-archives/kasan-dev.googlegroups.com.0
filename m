Return-Path: <kasan-dev+bncBCM3H26GVIOBBG7B3CVAMGQERWNZFDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 130087EE3EB
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 16:09:17 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-35abb017ea1sf8421725ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 07:09:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700147356; cv=pass;
        d=google.com; s=arc-20160816;
        b=O0kIwCv/UWqtFu1S30GdMTUanaJV6vh7184lJyQaQOCEgHFUuNOQ2+CpAMQjD+zDHG
         2d7W1ZUdYk6YeV0SdtiLxnn20VWUpJ+jvx8Oxd91hIJUAx2l8c/QKuCdRlJ1qKDVLuK2
         JrqkPtqhHQa2AsHaHKjLaVjgkzALTQkZ8aUiw/6G1NAFHs/vQ3DgoqQDwzrjsaalh1bS
         jDyssWiRkXLaK2Ui3Z/dpaoDxK28BDUTZG5pN3bKX39gMRzmnBPE/+/U9mXGNi+eq9JT
         iH4pA1zA8lTuMhVEFUlvPA7QWIjcSQxjtzdav1aeMGYroG4BcgiQp/MT9VZxJIXcU+eH
         apdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=/fbBvffjKizsQrniYYEtMDijAlYYasXp14SxcCz+Vxo=;
        fh=DRu6qs0R2xKQX+9GuRjR62JGLrpnTaOE1wQSzv/gHhk=;
        b=yQkkDNjaUqU2pEeS3UsgFI/QpN12pw/qJQHCr17n3F/WHbpIVVnB7EkDxWJ9ZMLs5O
         K/w+TNlGPoibJohQZvmfSGnOEn5buY8y2dPIz9Hc5lTHixjHlARF4pTOfPlJQ4UZDKSM
         etWJtMrUN6O1+J/WaAP3VRboSAAZ/ft2N3fwBEhz2VsbJHMSvpr7Q7tDEvXLcWw6Zuc6
         9LPWmtMeDZ1jybFMgLAmXVVUnJiaOQHj+aUiRjOcXb2P7Pwvz3gAtYvUzaT7IhSTfTxi
         /I1ZwG8XaVyvK2cGHuqAaiLvb19It/NZ9I2W+bgwDrvCffZi5tipN6ifVgqIdUHBJyqr
         Mrpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iC82ZytX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700147356; x=1700752156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/fbBvffjKizsQrniYYEtMDijAlYYasXp14SxcCz+Vxo=;
        b=Kcn4RPeZYgGQ2TntGxMKHT6osrWa/9lOw6+eBWemiYhVjavU71lrSmfnY0szPsbwc3
         t9kJE2WadTUoVZBBFXN9AM1m/zPea8jYD5kavEwFcW6N01Gom/OIMHz32+VkwHNPRT9k
         gSx5Bo9L8nAG/1TJ8Nj/c7eGqWLVv3kByFUrrhQaVK2fKSFOIOygfyS3imVZa5dVULWY
         g8I3XLK+zwwqJJI8GfCoVdwvalpTon2bsPQ6BYabQSt2r7nlj1PfPJwaCULILo0T1Z4F
         Z22QbQGpZOQ5kbOKna3owC5qbEiT3MmZbMLdX3yl9tCQG2JvxHCdajovXVnsANaBfkRE
         2b/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700147356; x=1700752156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/fbBvffjKizsQrniYYEtMDijAlYYasXp14SxcCz+Vxo=;
        b=E/o7f6ToWPpPPpuucwZ3eW6QQNWGRCNfFv/nYpnpONp6E83tgO3uIkbx0xO/MP8IyM
         M/JA0YVskuB0eB1IC2HRXDyP1xKWiIUD8NgFFW/i/iA/BQPy1g47giWJ0IOqVmRnpxcO
         ln2P7+u/uA0Gm/7SwUbI0ndJaNp0cRVLfqZhOo208DwWxOuSyBQDI0fK8EJ4tHeJSG7t
         vRQKCwlbFfCcF6zVhMpR/euopElFcO6ouQM6nU1qera6NfjttN/hJDd3ncbGgSWLGvUH
         5DW1wwPCgVOlP3xiSEs5Qb7ms4R0YYpM3AGE8q/4OQYAnIlKPNkHs1Tt0nlsdQd6TYRr
         9FqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwMrCmgEz+HAT1XeBou2bc3VLwynMIqI9iq+Rd99M1IsUjkmWsS
	WnxcHR+g6COlfjt7A4hWWXs=
X-Google-Smtp-Source: AGHT+IHBq/W2YQIM498HRFmjYSmU0+7lhbYgxj+2eF14ItObI0pBeN8faE0CIDQOVG4uwY6xkql1vw==
X-Received: by 2002:a05:6e02:1aa8:b0:359:ca5f:510c with SMTP id l8-20020a056e021aa800b00359ca5f510cmr17635683ilv.2.1700147355865;
        Thu, 16 Nov 2023 07:09:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3303:b0:35a:e129:74bf with SMTP id
 bm3-20020a056e02330300b0035ae12974bfls318408ilb.2.-pod-prod-03-us; Thu, 16
 Nov 2023 07:09:15 -0800 (PST)
X-Received: by 2002:a05:6602:234e:b0:7b0:63ab:a2c2 with SMTP id r14-20020a056602234e00b007b063aba2c2mr4771123iot.20.1700147354938;
        Thu, 16 Nov 2023 07:09:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700147354; cv=none;
        d=google.com; s=arc-20160816;
        b=Ahsq44fGXsp9CdZCam1acCv7i726bdVzZ+7uPo6ABByFDnpInQRPV2bYKdWaqY9zaK
         iHGlz8PmcrMjIukHvgXQakZ30zq4jntxcW5YLB/4Y+7Kqo5YY2QhLes0VuScF4a6xiiG
         Mm0oyOMZulxHN6KXYHc+oElJiMI+XRA+ZggowHS3wr3MFQEeV+fkHKdZxgO3EsYf498Z
         wt2fClPNmBI00WrJNMQLx30FYol/c+HZEY3wC4BusuvJPRgfX3A+P83H8t9wB+2/HS8Q
         buIqCbvpLm9RTm30TQSc2jjKYSIiVv6YCPiFeMAYVzjP/DQmkZUlX1sCRCP0N82sqE8f
         rVyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=fbR/4LYIfiQo0P1zqKZIOJ71Sdj1oOT4JYZNUwb072M=;
        fh=DRu6qs0R2xKQX+9GuRjR62JGLrpnTaOE1wQSzv/gHhk=;
        b=Px5pu0THMJvUNRgyFCLUWTn7ln+GUFWSnZZr88BXoLbryWUMVqru00GMSfgiuuOODN
         D2AlaYQw7pQXReO1Bc2ztohPct8tB1f6FmiJUCayRiT75PonteGKL2jHrpuoEdYXMQl6
         3sBEYlg8TZaxYWCWJVD33ANiZdvBtBT/5SiU1FJ3L5ZNFSKDUSEpCUk0LNpxB9tzEEZx
         35CSzyIROelI2GzcNXD+nuktpcirLOD5FP8C4ira0DvDADNefFOP8lLVsvbIV47JliVP
         Vl3fukxgrAbn72Swfn4x5TE5JoEMMpZwrtUw9ONCWzKUTUAmGc1O69KycNjXRHDzZIzR
         JRRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iC82ZytX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id v13-20020a056638250d00b0043d1cd8ec48si1667704jat.1.2023.11.16.07.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Nov 2023 07:09:14 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AGF2wT2000665;
	Thu, 16 Nov 2023 15:09:10 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udncagdg8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 15:09:09 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AGF2uF1000499;
	Thu, 16 Nov 2023 15:09:06 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udncag9q9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 15:09:05 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AGERv2d007963;
	Thu, 16 Nov 2023 15:08:19 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uapn1xx9m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 15:08:19 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AGF8G1815729200
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 16 Nov 2023 15:08:16 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 426CD20043;
	Thu, 16 Nov 2023 15:08:16 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8FE9120040;
	Thu, 16 Nov 2023 15:08:15 +0000 (GMT)
Received: from [9.155.200.166] (unknown [9.155.200.166])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 16 Nov 2023 15:08:15 +0000 (GMT)
Message-ID: <50846951de5c3c246c2c6263605a349a04a6ae45.camel@linux.ibm.com>
Subject: Re: [PATCH 13/32] kmsan: Support SLAB_POISON
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
Date: Thu, 16 Nov 2023 16:08:15 +0100
In-Reply-To: <CAG_fn=WOfRvDw3r3zcZXWr8aa6MiEuKSa1etQrGVSJP+ic7=mg@mail.gmail.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
	 <20231115203401.2495875-14-iii@linux.ibm.com>
	 <CAG_fn=WOfRvDw3r3zcZXWr8aa6MiEuKSa1etQrGVSJP+ic7=mg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ytVHJmlpUSeyjqKkMO8KNbDnnh0SJfQg
X-Proofpoint-ORIG-GUID: GoQTG6AsG7rXNy-iKNMNk95yhUTNkZSq
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-16_15,2023-11-16_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 priorityscore=1501 phishscore=0 mlxscore=0 spamscore=0
 clxscore=1015 malwarescore=0 impostorscore=0 adultscore=0 mlxlogscore=953
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311160118
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=iC82ZytX;       spf=pass (google.com:
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

On Thu, 2023-11-16 at 15:55 +0100, Alexander Potapenko wrote:
> On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
om>
> wrote:
> >=20
> > Avoid false KMSAN negatives with SLUB_DEBUG by allowing
> > kmsan_slab_free() to poison the freed memory, and by preventing
> > init_object() from unpoisoning new allocations.
> >=20
> > Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> > ---
> > =C2=A0mm/kmsan/hooks.c | 2 +-
> > =C2=A0mm/slub.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 ++-
> > =C2=A02 files changed, 3 insertions(+), 2 deletions(-)
> >=20
> > diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> > index 7b5814412e9f..7a30274b893c 100644
> > --- a/mm/kmsan/hooks.c
> > +++ b/mm/kmsan/hooks.c
> > @@ -76,7 +76,7 @@ void kmsan_slab_free(struct kmem_cache *s, void
> > *object)
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 return;
> >=20
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* RCU slabs could be legall=
y used after free within the
> > RCU period */
> > -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (unlikely(s->flags & (SLAB_TYP=
ESAFE_BY_RCU |
> > SLAB_POISON)))
> > +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (unlikely(s->flags & SLAB_TYPE=
SAFE_BY_RCU))
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 return;
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * If there's a constru=
ctor, freed memory must remain in
> > the same state
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 63d281dfacdb..8d9aa4d7cb7e 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -1024,7 +1024,8 @@ static __printf(3, 4) void slab_err(struct
> > kmem_cache *s, struct slab *slab,
> > =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 add_taint(TAINT_BAD_PAGE, LO=
CKDEP_NOW_UNRELIABLE);
> > =C2=A0}
> >=20
> > -static void init_object(struct kmem_cache *s, void *object, u8
> > val)
> > +__no_sanitize_memory static void
>=20
> __no_sanitize_memory should be used with great care, because it drops
> all instrumentation from the function, and any shadow writes will be
> lost.
> Won't it be better to add kmsan_poison() to init_object() if you want
> it to stay uninitialized?

I wanted to avoid a ping-pong here, in which we already have properly
poisoned memory, then memset() incorrectly unpoisons it, and then we
undo the damage. My first attempt involved using __memset() instead,
but this resulted in worse assembly code. I wish there were something
like memset_noinstr().

Right now init_object() doesn't seem to be doing anything besides these
memset()s, but this can of course change in the future. So I don't mind
using kmsan_poison() instead of __no_sanitize_memory here too much,
since it results in better maintainability.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/50846951de5c3c246c2c6263605a349a04a6ae45.camel%40linux.ibm.com.
