Return-Path: <kasan-dev+bncBCM3H26GVIOBBOEKZOZQMGQEMUWMABI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B5BB90EA01
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 13:47:06 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6f97385286bsf7832456a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 04:47:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718797625; cv=pass;
        d=google.com; s=arc-20160816;
        b=l+vchrGvpWp0U3hm9JC0z0E+ui9kh1lCHodWHQhJZwaUytkQSgq6QvCK0nz7+CSUsl
         TGkUObbqR4u5HsfneDsGTU4wwfm3PQVcqgdFJZAX37BdLtEwgLyRkMB8VHSiSKTXB5ja
         mAbJCFkJ/xkwh29b5v44LtaLYbrezlK66NlMiGIwHwkrb/LLYfUR7K78FxfB3ZVWpQin
         SCv0gh28FmBcMKMnpZ77Rxzv/OIo+cKLecxNKlc0X7FLKzBxvTKAsxDcJ7nPa7zbzOkW
         uBPJ8/KzJ18dQHDKwzSiFZV+aKjdEwecnxgExJu5rfke8wzGnUSKsF7HzTgmZCKmau73
         Rdrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=r+ttPjGo9k3Tw2ZZXNpEqa1vV7/YK5KqtmBxpkNnpXg=;
        fh=qfK6MGBFO3lL44z/pZr4NIWaLgrbPDy6zXoS/AMrIx4=;
        b=MowCzVoFdVaSjSJKcAwtKCIa23p2602utoPC8Nwi2SznsaT5/FEwJWtwFTyB+iZlL7
         yc/cj20yutIy7PK5cwNTZdzeAcWKIg+vyk7fc+TuBdBC1pr4U7a6p0Do6ElzzvjeacG8
         6QnJqm0rdVAjjMvel2tPU4Zs05pVqr4D0IUVexiibtSk2yKwXoHsliMGHeBay34P96x0
         hO0X0Fwewc+gm7YtxuBmVxgkbXoDIzkhCnTQK2cHO9Xdzt2VoGIcRR/qG46NLzQTasOF
         6MMBFkBiedt/ToSd62qCmPa9O50kwCtn2RzuGbcMBs21iWMJnvTI3S16GplwY+JB9Kch
         XyQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qpWFYXBP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718797625; x=1719402425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=r+ttPjGo9k3Tw2ZZXNpEqa1vV7/YK5KqtmBxpkNnpXg=;
        b=uNf06cOCGmdkwOPEieZO5BkUve0R9TDEuvAOCxQxJglZ/a8Gi3jimL3sAZpNOJwhEd
         uxzzx9bXRxGWzEsOkKFzvkfiyybl90iU/5HGmPtmf/jp95DtUVQ7yXlWQUjF6/vD0eaq
         TCIGAmSQyVGKohovUtIWyHHIHSLSRuCqbOvVP6kQ5csqTs4HDhBcWjqcafJSzZtUt3wl
         ecbkW+yHqlvuU6ezkqfTm2S7XQrMIIpxEKCkXkLkJpTBgxNkg/UV/2UIhIuXgkbilKaA
         Tv3ImuLUe6amXjhJzMgvb+qFcoxyVQN4rmbBz1a98zZQEt+r5BMpW6pyKR6BPhXHjewr
         RoQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718797625; x=1719402425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=r+ttPjGo9k3Tw2ZZXNpEqa1vV7/YK5KqtmBxpkNnpXg=;
        b=Mi5ni3L4Bkt2PJkeA/S4Lc0LGavNFBeMpW1P7aE+10XeMTCxqv9vP0HFfBUr/FmzZO
         e6+ZDa4gnJhEkq5HGlGPm0oNMI9y47fuQzcXyTUC4lHN50WkyHVHcW9zkWMnlsHrQLAv
         WZp0nzJJ/l/GJKiR8N6zxeYex97w+V+9K+nueTxKw/0PId4ijgrQ54kqB07P4ogz5u3G
         NJGed3OT/imJ6ye3RV5Bq4mSxMIPxCf9OxOPPL/l5O5Ynv2mLIw5bNm3DvLl6WdHt8eV
         RHvekMfbqnOXeWs8eOnEQ7tlBPQy6qpKo0JxbYIADKevLPb9piEv6d3wNhICQB39T8Cn
         SgHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYeRqHih0ZRoewLL5qemHM02Rz8+zScSrII8YENP2c4Qi1YgGp56xTRqDEoUEA6wHeI6dLRnM1eQid/oR0yeumH7baGNk3ww==
X-Gm-Message-State: AOJu0Yz0eOc8cf68HzCV3+i7qsBTqWfZ5dQXyrgLi2IXKqRbRabuMr6n
	mKjL4tdbqWDQbujmXbLqkbRCuBvAWFBJ1MNSQWxzIFEe7fPfue5d
X-Google-Smtp-Source: AGHT+IFUfjWfdYzu+V1fn1W9W10KY7HV9ewBnliGhnB9hhTf8XmWAcrpAYbyk0BsWXtBhCtN5YFghQ==
X-Received: by 2002:a9d:7a42:0:b0:6f9:a90b:d480 with SMTP id 46e09a7af769-70076dfae98mr2234969a34.37.1718797624981;
        Wed, 19 Jun 2024 04:47:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3990:b0:6b5:268:d754 with SMTP id
 6a1803df08f44-6b50268dfd0ls10444046d6.2.-pod-prod-03-us; Wed, 19 Jun 2024
 04:47:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWyFrB0FpoxmJztP0KcFOE+enWaSNS9QJ5HmqI4Cw+ye5QNHhkzD1MVVha2Ciqh/LIJxYXzVJtl9BsXVAgwgyEbUeq8b7kgt726rw==
X-Received: by 2002:a05:6102:370a:b0:48c:4124:2536 with SMTP id ada2fe7eead31-48f130d24e9mr2472271137.35.1718797623956;
        Wed, 19 Jun 2024 04:47:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718797623; cv=none;
        d=google.com; s=arc-20160816;
        b=MLK342DYZLceP61TqUb2+9lE2tZ88mn2SV1sm/YwMx2Ws01VXDbD++0ox1Hsk2jXB4
         XXJE51q6r6c6tbkefm9N93U46FuSd0cBfCZwaxfOA5KLpJ1mUp+5iia42ZOM47xTGj3x
         1tD7n24pXil02EsW31vTj1Rq6WWaW109dnBUwVVdlNTDuYKONdzmn8/MVYtgfJHG2PMd
         ke7gzEn9RWRW+AgD/h90g2Q6x5yHm8DzYatUlmzM3iGEpHyATaMOChvyNLHb4by8+zBQ
         6DXXkuhGxvYuOVWRiv9QDSafHyhmBiepwRZB4Xj2trpdOKV9xlAAzxzRfRKzPpCslie4
         cPCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=4aBYdd8aAGH4U0q0/YmJqtT24ak1oG6LESBEorWzHMs=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=gVwlkHJPdkgLX7LxOM+2mveAUZixIqWL5v9gYb0drO1NE2HoDdtrCFNdWKzN4uCSX+
         LvcOoQ6d1H98EbmvWIapds4jFnHJWiWAsYqwuCH7ay9yFeG5L2RqBWo9MuGFxdqBRAtr
         uJVmeLOXVSFla5xNBjFDuLeia0jglpptK09oL8enTF+nE6tbctPQEnQWGGCKCy6PWDil
         R3FZ9rV/sjv3aAx2P3sgXriQBQ72bYkXsmMKT0n8GRCqwZmFqEKBPRxH/U8yIvD1VNzN
         M6BCwkdq3MMgR+B3Bf5CcMOLFRjWXsoV/le47ia7EXEDbhQgOfqqGoGZoRoqJKRkWDQ3
         8GFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qpWFYXBP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48da449e8c2si632856137.1.2024.06.19.04.47.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 04:47:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JBT2Gb032134;
	Wed, 19 Jun 2024 11:46:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yuxg0r1cv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 11:46:58 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JBkvMU026796;
	Wed, 19 Jun 2024 11:46:57 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yuxg0r1cq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 11:46:57 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JBQHF2006189;
	Wed, 19 Jun 2024 11:46:56 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9uv8v8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 11:46:56 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JBkote34538010
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 11:46:52 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 90CFD2004B;
	Wed, 19 Jun 2024 11:46:50 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2858220063;
	Wed, 19 Jun 2024 11:46:50 +0000 (GMT)
Received: from [9.155.200.166] (unknown [9.155.200.166])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 11:46:50 +0000 (GMT)
Message-ID: <ff3403a257086f09db1280c5952e6f72371b10ef.camel@linux.ibm.com>
Subject: Re: [PATCH v4 16/35] mm: slub: Unpoison the memchr_inv() return
 value
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
Date: Wed, 19 Jun 2024 13:46:50 +0200
In-Reply-To: <CAG_fn=Uyx7ijj-igC2hgSpdzmChM0FVy46HTRXyKzNAA0OFK7A@mail.gmail.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
	 <20240613153924.961511-17-iii@linux.ibm.com>
	 <CAG_fn=Uyx7ijj-igC2hgSpdzmChM0FVy46HTRXyKzNAA0OFK7A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.50.4 (3.50.4-1.fc39)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: tzqSr8HO345mo1Ia6Q97gqSzudRJArNH
X-Proofpoint-GUID: ljUZ8zkZEQkiMouQPJQ5SsIz1Fy2T4Or
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 lowpriorityscore=0
 malwarescore=0 mlxlogscore=749 phishscore=0 impostorscore=0 adultscore=0
 spamscore=0 priorityscore=1501 suspectscore=0 bulkscore=0 clxscore=1015
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406190084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=qpWFYXBP;       spf=pass (google.com:
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

On Tue, 2024-06-18 at 16:38 +0200, Alexander Potapenko wrote:
> On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
om>
> wrote:
> >=20
> > Even though the KMSAN warnings generated by memchr_inv() are
> > suppressed
> > by metadata_access_enable(), its return value may still be
> > poisoned.
> >=20
> > The reason is that the last iteration of memchr_inv() returns
> > `*start !=3D value ? start : NULL`, where *start is poisoned. Because
> > of
> > this, somewhat counterintuitively, the shadow value computed by
> > visitSelectInst() is equal to `(uintptr_t)start`.
> >=20
> > The intention behind guarding memchr_inv() behind
> > metadata_access_enable() is to touch poisoned metadata without
> > triggering KMSAN, so unpoison its return value.
>=20
> What do you think about applying __no_kmsan_checks to these functions
> instead?

Ok, will do. The __no_kmsan_checks approach is already taken by
"mm: kfence: Disable KMSAN when checking the canary", so we might as
well be consistent in how we fix these issues.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ff3403a257086f09db1280c5952e6f72371b10ef.camel%40linux.ibm.com.
