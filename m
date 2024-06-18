Return-Path: <kasan-dev+bncBCM3H26GVIOBBRVTYWZQMGQENQ24D5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id D178F90C5A9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 11:56:23 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6ad706fab2asf67993856d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 02:56:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718704583; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9SYhc4SOZrT5f4WS8HfJrr9Xwi+SIFd20hxzPqPSHjgVTY1Fl63LwPRLoeKzWZCUr
         9avtrZIvPt6eCGptfUOnz9KWEKLmi9RmW12QduVNSnRlb1inlsD9z2+zIiARmbi58A1T
         QQHgSxDniiii02tc0KbHSKKaAzEjfGV82rXhiqoKI+kocK+6sAiHjbHssT2o3i2p5jux
         EYjqg9wCPviB4JilxTynz2NGIR6rKVWzb/E4mI7EJgICSsTm4XAsCeLaygpVWRFn3L86
         qpLr3u3kNBpQmaQv5fQ6viMNs9HskXIrmyMs0/MYoi8EazX6d5x2oWYCLlIK3bcN3dJx
         TGGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=D/yUUXL7u6obJHxJPhcxpA6lzCXaa+xlW8XiG4X3fbQ=;
        fh=6PDyNl/VfwYlRGfktmItkQ4DHmPQO/vgQV4Vg4ugJhI=;
        b=hqG21ZPoIXXUPgILa+Lex6pyO95EwkLYlGRhJFctLdCjTZFm4hIwPRkE0Pm2T3/oHU
         xZ96sG1xgCxv9jADI3ZVN/1w7OwcgEutyoaFe/ZE3b/jKVbpM9fy0d+QTzFNC6L/gdsk
         9UdtE8EaoyREI0rCPwCvZSh89hDXUM9C1RgeDjKG1PoJZwTpcxtvF4t7jy5S9MoP5LJ2
         qgU8RW6pQWP/W9lxe0gVS/uTjJO4dMoeKBzQZfZ7HCJsIUSMJYWXrGguKiWnuEUgeIFu
         FrDlcMUrlYruIRJKZn1t9ZS4nQo9DZLMUxX2Kx4yEZmcXOC4mCZv1Guq8ropM0KvLRIl
         MjjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Z5AXNp3H;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718704583; x=1719309383; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=D/yUUXL7u6obJHxJPhcxpA6lzCXaa+xlW8XiG4X3fbQ=;
        b=tOC/gGRyQG0VxmaZLrzfsRgcIuBm1vbi41gGL1jxAcHdyqE/aSDjCTG20rgL5Oxmt5
         NK8bMyYNWkAt2i2c6RtQNmnTBe7VpTT7iYAZ1EBVQXd8mRgENJyJ0yezoYVY4GWgNbtV
         XArnTr0icWfIk5cze7p4ETB7/DHbTMfzDXzxnuS0VUCPPsT5P2za02xEBSdcIIP22yO+
         +ECb7cBieSwF1VCZVjMM9QMLcEECQpqjkg2f8aZn9/P0ZGAhl3HibfbSC4EGrJdsE7Hr
         +yzEtmox+170byUtZWHPyLnRqLUye/e5VoeEMV1NCgbKAMdES/RDdW8lzLOCn+R0JZac
         5NrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718704583; x=1719309383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=D/yUUXL7u6obJHxJPhcxpA6lzCXaa+xlW8XiG4X3fbQ=;
        b=J4C+jNRVxYXdy3o/3XI6wzrl8BZ2rD+sycTZ3DzQgv1j23r8dm6QDrR7WDfYkpmlNy
         Yrk6e82VicDKnAQdAuDyCza2D2f66WA1bYW41yLGA3UG8qy1INeS+L7my5mYHDaKRlRP
         PaxxSHXgVdZZn+FwP/tjnca8bUppOjXarN0RIzaTAkbTPm+7kHS6+mYMPtJPFQvZGi1S
         CQUKSGE3V+Qswbjd0hc4A0EW6vg2NW/6FNs2ZSYRV/m7etXZsRpfG4PsZhKTUKpGs063
         e0hXjW+GtEPHB9w0EPwliOL48gxOH4qmBaO7jcIn0q/D/ja5+VJtV5KDKow9v1jiFxC/
         DClg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHPcfQ8tdTEzX1rpSYCFAp4ctGRc1dkiYcQmT3QTvj2A3yaGYApXGnbVcd71SwhaFqGMfeOhckgrUz/L/71UU6McIumKEklQ==
X-Gm-Message-State: AOJu0Yz/P72PTvFiF3e4Xro2svibeg+dd5xH+JiroTvU55vZfR0dD6rl
	vRa2YNWu5fJgzLZzUIwIjuzWPifjiuqhe0aRq6Rw0NZyWQDSn7IH
X-Google-Smtp-Source: AGHT+IFAw2LWYMxOgGMzIj5mPeZwNyKGhTD11bDDDYpD5NJrlmPya5af2+ie/IHKUhP9pjgePqQIuw==
X-Received: by 2002:ad4:48c2:0:b0:6b2:b5d9:91d6 with SMTP id 6a1803df08f44-6b2b5d99431mr110223176d6.18.1718704582596;
        Tue, 18 Jun 2024 02:56:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5d8b:b0:6b0:8c6c:833b with SMTP id
 6a1803df08f44-6b2a338020bls95849676d6.0.-pod-prod-08-us; Tue, 18 Jun 2024
 02:56:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuUqgw1Lg74vwoIZ2Cq+rgb9qr4h95Co/oAjuW0GId5ScnWW0VZ0zP+XegKra6RSB1Wl+CDVTZTBkTSzryzCeHajOS1ckZ0c2ItA==
X-Received: by 2002:a05:6102:666:b0:48c:36c8:98db with SMTP id ada2fe7eead31-48dae355598mr9436955137.9.1718704581655;
        Tue, 18 Jun 2024 02:56:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718704581; cv=none;
        d=google.com; s=arc-20160816;
        b=UAlNkLwM2LkTAyDgLaKla5OM38fFB1fYrZeaMYJSCKsJ1qNLcjbZ7TBDUNrPkh+OIC
         Ghn21uRPHqq3Co9EoWbaFAjR+f9OVqL+67Sq9jMwejZEi98K0dMZohaArmVSCPwSzHQi
         Vu9HDKxqgoJh/RXaKjBzaczUMJ4Vz1DX/+C3vLv22np9rCpqgTIPjJ+/wWqxNIF6tmNT
         oMZX9gTVRacc7b0yiRTjWZQMi6wGJWWZWyIFTXycph5QY8vtusD/PohYoSHAdX9Yzdtq
         4zmWWVMhZsvrrMac22/NQxrJcoL+JAw6Ikmkgrq+HdrAWa3uNNJqfSGbeoU69wItabmr
         6+Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=56ndxlWUopxXCxRtq9AcvSBP4vgwCrhT9Wo6d8WigyE=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=kyR44LEeQvVri7OQQSibzWrC2Cwqyj2lsxB2Z23skkDppAHKQMKcDi/fjwGt5hrJcS
         WqFUWQT3xSuLghxAdJToxEX6OaSSdZowhRhz5w/8XPZOTRwm7hF+Vude4/2eRIRUjv9z
         VoW5EtNDlRNtmXTmQZGvR5IFlO85FuMT8sqWkEo5hiBZNsmzoRead6QVFVZpqjBFDBuR
         Kfhmjy56OAFHtKMlQ9f4v5NBmulZaBeb0RT/ESo6oj6PVxIIDA1O/+WBzU8Pl/aAIvl9
         RRhu02WFUeCd+E/r1k9W6ep4LHpsgPx+hWOwHlGXrCm3RG5oa+EjMzlC55DChhvVKdVZ
         YEvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Z5AXNp3H;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48da44b6bcbsi443658137.2.2024.06.18.02.56.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Jun 2024 02:56:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45I9SGHN016418;
	Tue, 18 Jun 2024 09:56:16 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yu7mrg339-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 18 Jun 2024 09:56:16 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45I9sUGQ024178;
	Tue, 18 Jun 2024 09:56:15 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yu7mrg331-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 18 Jun 2024 09:56:15 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45I7orXa009425;
	Tue, 18 Jun 2024 09:56:14 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmhfw2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 18 Jun 2024 09:56:14 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45I9u8ui49480134
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 18 Jun 2024 09:56:11 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DFDA320043;
	Tue, 18 Jun 2024 09:56:08 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5F02720040;
	Tue, 18 Jun 2024 09:56:07 +0000 (GMT)
Received: from [127.0.0.1] (unknown [9.152.108.100])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 18 Jun 2024 09:56:07 +0000 (GMT)
Message-ID: <1686a7d4dfdfc0a7820f9f9eaf2b08efd1582cc5.camel@linux.ibm.com>
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
Date: Tue, 18 Jun 2024 11:56:06 +0200
In-Reply-To: <CAG_fn=XhWpLKbMO6ZHpnxQDh+PXrTxBnL9X-1zZtBj-CoVk0=g@mail.gmail.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
	 <20240613153924.961511-33-iii@linux.ibm.com>
	 <CAG_fn=X6wHfmGsVgdqwms_Hk1CQAZ6M5623WyatjVp=Uk-z9pQ@mail.gmail.com>
	 <e91768f518876ec9b53ffa8069b798107434d0dd.camel@linux.ibm.com>
	 <CAG_fn=XhWpLKbMO6ZHpnxQDh+PXrTxBnL9X-1zZtBj-CoVk0=g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: thTUXS9VWyXfcdKqlWXkBkJtxj-ngN6F
X-Proofpoint-ORIG-GUID: PAQyFSQ5hY8FDUl-TDPKYjyoD0hkTlRH
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-18_02,2024-06-17_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 adultscore=0
 mlxscore=0 suspectscore=0 priorityscore=1501 malwarescore=0
 mlxlogscore=924 spamscore=0 impostorscore=0 clxscore=1015
 lowpriorityscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406180073
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Z5AXNp3H;       spf=pass (google.com:
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

On Tue, 2024-06-18 at 11:52 +0200, Alexander Potapenko wrote:
> On Tue, Jun 18, 2024 at 11:40=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.=
com>
> wrote:
> >=20
> > On Tue, 2024-06-18 at 11:24 +0200, Alexander Potapenko wrote:
> > > On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich
> > > <iii@linux.ibm.com>
> > > wrote:
> > > >=20
> > > > put_user() uses inline assembly with precise constraints, so
> > > > Clang
> > > > is
> > > > in principle capable of instrumenting it automatically.
> > > > Unfortunately,
> > > > one of the constraints contains a dereferenced user pointer,
> > > > and
> > > > Clang
> > > > does not currently distinguish user and kernel pointers.
> > > > Therefore
> > > > KMSAN attempts to access shadow for user pointers, which is not
> > > > a
> > > > right
> > > > thing to do.
> > > >=20
> > > > An obvious fix to add __no_sanitize_memory to __put_user_fn()
> > > > does
> > > > not
> > > > work, since it's __always_inline. And __always_inline cannot be
> > > > removed
> > > > due to the __put_user_bad() trick.
> > > >=20
> > > > A different obvious fix of using the "a" instead of the "+Q"
> > > > constraint
> > > > degrades the code quality, which is very important here, since
> > > > it's
> > > > a
> > > > hot path.
> > > >=20
> > > > Instead, repurpose the __put_user_asm() macro to define
> > > > __put_user_{char,short,int,long}_noinstr() functions and mark
> > > > them
> > > > with
> > > > __no_sanitize_memory. For the non-KMSAN builds make them
> > > > __always_inline in order to keep the generated code quality.
> > > > Also
> > > > define __put_user_{char,short,int,long}() functions, which call
> > > > the
> > > > aforementioned ones and which *are* instrumented, because they
> > > > call
> > > > KMSAN hooks, which may be implemented as macros.
> > >=20
> > > I am not really familiar with s390 assembly, but I think you
> > > still
> > > need to call kmsan_copy_to_user() and kmsan_copy_from_user() to
> > > properly initialize the copied data and report infoleaks.
> > > Would it be possible to insert calls to linux/instrumented.h
> > > hooks
> > > into uaccess functions?
> >=20
> > Aren't the existing instrument_get_user() / instrument_put_user()
> > calls
> > sufficient?
>=20
> Oh, sorry, I overlooked them. Yes, those should be sufficient.
> But you don't include linux/instrumented.h, do you?

No, apparently we get this include from somewhere else by accident.
I will add it in a separate patch.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1686a7d4dfdfc0a7820f9f9eaf2b08efd1582cc5.camel%40linux.ibm.com.
