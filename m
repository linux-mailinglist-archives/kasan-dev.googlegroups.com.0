Return-Path: <kasan-dev+bncBCM3H26GVIOBBLN426VAMGQEJM6AYHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 875217EDD78
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:17:35 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-5b9344d72bbsf788628a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:17:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700126254; cv=pass;
        d=google.com; s=arc-20160816;
        b=h+21760ckg0dobbTUJz8y6sucgu0zobW0u9ameEtPuXJciEhcoFW9FMmMx0TsKig1q
         EHPQdsBvzuN21TKbM9SE2SEDucFt3PjzJW5/p35IOGFG8obKWq+tyVuVUyQzByIUHUG+
         BrXoNm6g0EEAVoM6K0JjwAEOos67h+m7pYVw+f6C/HTWHL7CvrbrIDHZVXBXGvbAnHrU
         uUucVf0SYXgj5djONL//aQvZpHNKhpkun0Xoa5+jsjvnGIpctjDUUeiMYPkdhuI02kLE
         sL1O/tJ0+uVWu2e1VZQEHYv623RFZWUCDOxdkOaU6djvdji/k5JDBboDSY2poyDA0IJM
         6YEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=3N7TXw/ufTK7rKPrkindVg9xRuQvt2YYh5VNeiOTDB4=;
        fh=DRu6qs0R2xKQX+9GuRjR62JGLrpnTaOE1wQSzv/gHhk=;
        b=zU1MXxjuCrm55XMWJj3BWYK9BfWVr3m7VCZNWNUsDICVvwxMjsTIwvvBk6Kwo86lYx
         n/aZCfFnUnDcm18hNdIoBXI8BZksKCZUeE1KFgbMPOl5rzvtdRu5S23nH3i+yENZzJhe
         wURdFbrS4/CPcWyBQEW9BopYpJ7lnMdmgILpPOGMvzMqAYXBzMVCko36t/THrwDpF7Gg
         rgDeh0+5E+yYzV4TNeOlf4o2NLufbXDPw5XnLrJuvgvbWhUkBRgVt6MxrQj10G+TZE+l
         qvdjtXMCajGahdRxC2ze0g3+ItY9oa/23vweoUhdAXhhcGvUFvs9/XTLr7ogOjGTWKWg
         E19w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rdPuCKlp;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700126254; x=1700731054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3N7TXw/ufTK7rKPrkindVg9xRuQvt2YYh5VNeiOTDB4=;
        b=CWHcfEFAj4ajRTVBrk3zkZF2G9W9KRXxpNK39k983nU1TiJi+YTwMVARt11ryKb5Pz
         SFhpWUuXYhEMeXa874p+JNtA8da7BZCYJ9VtpGUn2inEzeKJaeSRSmpGX/9NM7nQZlHn
         B6nqkg17PoKSKG5DDxCrCAA24QnNsMrDmXnMRPUbSzWtxUuodWkRyBLvSgvQmPwISUji
         MWa8KXDZgzEIsbeHUuo4i6dTalItDGittkN+6r/Gin/vbaMxxADQzdK61wCFckmm6iHd
         Mo+WBPZ9B7YmxGf1354U9B1tXkV+x9Ajtc0BPFH+E34BvvvAtH8i70ryMSqFrN0A5DLs
         VF8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700126254; x=1700731054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3N7TXw/ufTK7rKPrkindVg9xRuQvt2YYh5VNeiOTDB4=;
        b=ijj3EthnJouzWRizgwVFTFEFmqRs5hdK3Np1oqn04KiSVEZrHWmjZYIIA0JZnypLcj
         VLEt5mkYpJ7lr6ZP9JSH5QPOwRcQN0nHecrW0UdpgOud48Iye62+XxvOS65e03wzAQU6
         H/p0NaxaeHiCqtrYLtfWSF07UoFXxKZnf0sCulkMNjMSrcheQMSSSapg+kwiBwfRPUhi
         uwmxGRmStxci05AEglo51/cRVKoba1P4mJq6TbwMGUgGc7Ket0+9bG0u3xRY2Ugd9eco
         1tHbYlseliSLbOA/4R/lrlImHB+GAZdSIfKWIKpktWKoLZJuGsRBKpqJDWr1B9pzuJiJ
         cIWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwKQOkwHLGgL7FoVKpivPYbanDBId4/6LuKMi6JP/z7Q9BYfKCX
	v/zgyexYD809FVxkQ3ogyeMi9w==
X-Google-Smtp-Source: AGHT+IE2nCLQ+vyzetUbIZxrSj2SCQTB6f71HP2Frc2vr+QI3FbGSSM2Gvcq1XbYIPJIm2nhoqw8zA==
X-Received: by 2002:a05:6a21:186:b0:133:d17d:193a with SMTP id le6-20020a056a21018600b00133d17d193amr22013814pzb.59.1700126253659;
        Thu, 16 Nov 2023 01:17:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d0f:b0:277:5642:ec00 with SMTP id
 pt15-20020a17090b3d0f00b002775642ec00ls598524pjb.2.-pod-prod-06-us; Thu, 16
 Nov 2023 01:17:32 -0800 (PST)
X-Received: by 2002:a17:90b:4c04:b0:283:2652:3d08 with SMTP id na4-20020a17090b4c0400b0028326523d08mr17880318pjb.33.1700126252589;
        Thu, 16 Nov 2023 01:17:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700126252; cv=none;
        d=google.com; s=arc-20160816;
        b=FSngeoHRAoZV7l9KFBpCWjwcN309oAsEwhwgiNQuzFN/b4jsjaycwKqnMUk+PpKuLl
         Cd+TgncCWw2D6nNywKp8NtwDAEziAGy9FLwxp8TLuYTKNFm1q8rz56rl2pKN1HjvZZ+I
         yO8TJza7p2fnr5u+EDxgX0LBXqqbVY0sD9IrWX8TkzCAcZf8nRU87OsO11Cl2UmwGn/e
         Msy5bmiW2HPVuxw0zOneDl5JJ6WSrrm0E1PRLvUuttlSDJ5kwU4+GlKPUyiYfl2tgxoT
         UtnEGLJk9kNd/ehPPcmgHX14G6mx+tZoUWAD1OP8KOfVmIev3Poqq8ej7E/J9c1jhOO3
         Otgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=4cXgi5VLXXOtLpoCPr1dWCi1lxs5btqANVR2MmquTPI=;
        fh=DRu6qs0R2xKQX+9GuRjR62JGLrpnTaOE1wQSzv/gHhk=;
        b=KmuMEwZcA/byb7HJPoNaNJlDWE18TdrzcBYLbXcmoZm4ltR2lqbi7MXozZVkGfI2Y6
         JZzHUHT8ovO9NAo20+QkAPgPJNYzvWYfjcW8M0PxIm+5HStwSl9a9W1pvPvugZpPo5DL
         5uNN2NHlMFwbX35R0+bfq0WwGRNsVlciDHaUv3j/vkzoj7tceF5FonZoG9hnJ+Gpulmx
         xkPX2d1s6IL8RsGq2xn5/onxvALYZamyT3TwRhjdst2XVbcSb4Vob06D7kYFzqD9vo4x
         duE/rdYxgj7AJ9e6fGfo2KMc/tH8EmsjWnOp/C0PpZA+S7QGJ7Dm9I+Fat9mC3kQs8df
         XGTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rdPuCKlp;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id c2-20020a17090ad90200b002800bed3799si220939pjv.0.2023.11.16.01.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:17:32 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AG8ufRF022742;
	Thu, 16 Nov 2023 09:17:27 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udebbkfuf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 09:17:27 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AG8xPbq031471;
	Thu, 16 Nov 2023 09:17:26 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udebbkftj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 09:17:26 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AG8XrrI026751;
	Thu, 16 Nov 2023 09:17:24 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uakxt60at-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 09:17:24 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AG9HLfP18154126
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 16 Nov 2023 09:17:22 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DE39720040;
	Thu, 16 Nov 2023 09:17:21 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 97C8F20049;
	Thu, 16 Nov 2023 09:17:20 +0000 (GMT)
Received: from [9.179.9.51] (unknown [9.179.9.51])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 16 Nov 2023 09:17:20 +0000 (GMT)
Message-ID: <8fb810e5000dd66334a4a686407c0caeacb79f55.camel@linux.ibm.com>
Subject: Re: [PATCH 12/32] kmsan: Allow disabling KMSAN checks for the
 current task
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
Date: Thu, 16 Nov 2023 10:17:20 +0100
In-Reply-To: <CAG_fn=XVJNZLtHj2n3DP5ETBzgoUZL0jQFX7uw4z9Pj2vGbUPw@mail.gmail.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
	 <20231115203401.2495875-13-iii@linux.ibm.com>
	 <CAG_fn=XVJNZLtHj2n3DP5ETBzgoUZL0jQFX7uw4z9Pj2vGbUPw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: vSTD9xF44d83VprYex3tMD-37iq0_k9g
X-Proofpoint-GUID: oH4OOC-OhoTloo5LiN9lT2emIfEOQ-qd
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-16_07,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 lowpriorityscore=0 mlxlogscore=999 malwarescore=0 suspectscore=0
 adultscore=0 priorityscore=1501 mlxscore=0 bulkscore=0 phishscore=0
 impostorscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311160074
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rdPuCKlp;       spf=pass (google.com:
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

On Thu, 2023-11-16 at 09:56 +0100, Alexander Potapenko wrote:
> On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
om>
> wrote:
> >=20
> > Like for KASAN, it's useful to temporarily disable KMSAN checks
> > around,
> > e.g., redzone accesses.
>=20
> This example is incorrect, because KMSAN does not have redzones.
> You are calling these functions from "mm: slub: Let KMSAN access
> metadata", which mentiones redzones in kfree(), but the description
> is
> still somewhat unclear.
> Can you provide more insight about what is going on? Maybe we can fix
> those accesses instead of disabling KMSAN?

It's about SLUB redzones, which appear when compiling with
CONFIG_DEBUG_SLAB.

I think that from KMSAN's point of view they should be considered
poisoned, but then the question is what to do with functions that check
them. I noticed that there was special handling for KASAN there
already, so I figured that the best solution would be to do the same
thing for KMSAN.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8fb810e5000dd66334a4a686407c0caeacb79f55.camel%40linux.ibm.com.
