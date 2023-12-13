Return-Path: <kasan-dev+bncBCM3H26GVIOBB5VM42VQMGQECUG4VFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 643BB81100C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 12:33:12 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-7b705896cb2sf608175639f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 03:33:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702467191; cv=pass;
        d=google.com; s=arc-20160816;
        b=O5+4E/hKPvOjSCt2fSrcEVnSDl0MWpqMEVDpEYvCYI2ud5YXpWeG7Bt5484zbDdV1i
         MoEtr+M/WzJ2lmAU0LhZWJ0L16MWMCK2Jkontn3eN/EjM9vGgvyKuKRPd/cutLikJi3T
         BtvbDrC9L2E/tpztqF0yD+2bZzliX0Wsz8gCWMvBMK1TboTdE558tAr/3SaVEuFVKWdo
         +3SC4LOvsRbT9X3cc8oj4Yq8JHh21UY6T2hkqfe6gq0lpVHukhyIWUWruHBu7HWbNhFa
         9MVk1YbwWaazl6oUoGSVe+QWqi+l8qoig62W6GJ+jcFh4en+SxZZm+0oSHYO+LyMALgY
         hMPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=Nh7Zx49GGWIdgG21JgUOz/hITV7oyeCLzU0ScAjrVJ8=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=zDC2RcAOLFTVxU6zFMYFVfzFWqMydM4xATJR+tuoPi9qPIfGEDSAWBkJrh895t7R3y
         Nky3bY9vBMpObIfAd7+6SUHC/m0AeiTrgdF9ltB8njFF3acUZU6eSa62xZRw3yJbeiy/
         zYQsWvE/cnblU99R6ykU6hZFnhv8vp43CEwe25Fn9ifw83FOPVTfNMG5MfeaQLA5T+7w
         HiFt09NfVyFtG3LJnGtkXQeYjlwC/IM1QC4zcr1iXAd3Z0fLog3B6OETZAsOhB2v25uz
         U0U/xZLwhaglF1bPzEbWYvzXzbxEiFnT1/+/LExHwFz8wiCNfhhOa7d/EYyo12G6Y9m3
         T75Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sXinkoKf;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702467191; x=1703071991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Nh7Zx49GGWIdgG21JgUOz/hITV7oyeCLzU0ScAjrVJ8=;
        b=iLYQD+QRhShREhG9xTQWmkTpCksFxWdZRvL+FOqj9o4i8UmdD4gZskbSgDaIK6UKS9
         9n6QDksqwgSqm91vH+8IcrstzBA+ySIP8Jt7jrRZKMRsTeg3zOlAAVAk8gLJMa+SNh2l
         eHNolZt9GyF07QfD1Zbx+ryUxUf8Sn+15awq8JAKCyUeWHcbRpBCMBUrEqiyNWDSGduj
         Vc+tu4F3Ue1F73+/mr1uoLboYGqHV+noEa64OBufvME38sFVkuqFG+MestRKp7bFkGp4
         kauKuKQxCmCcDaBEY5us3pSvEFt6BjO56TJ58DjAWmq7JE3QynXZ5uTI3IJGAacIGLG/
         llBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702467191; x=1703071991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Nh7Zx49GGWIdgG21JgUOz/hITV7oyeCLzU0ScAjrVJ8=;
        b=Gbye370PWtWFfkjzv1yAdvLLMqCy2/ygG68SA/baVMD79HiKZ9cAwrZuLeZLwoa4eK
         tUryYO1QyEKwzFq8H4o3CQqZxaelZUGcNiGIjrcLwecuUZ9PH+6tBjabBIbD8wd7Ycl4
         cLC6s+RqKturRmqy8c+LBwCHXYNGkuv38iqJwbKRl4ZQd29cgw1LE5HAe3Y9Xu96cxao
         QhPSoeJEO0pbE7sByIc38srBZ+uJUJu+WsS++81Elzn1pRUWZakZoe3FeEHaec0sQaBD
         crfyyUNXFkD7PZ7IIcoZI1727ATRsSRWK6zAZcBHf5Z2pRXDi+ja7hh3mZVJb9ZYNQoL
         lXnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxTG1uvYR8Yz2GOyoI4LH72i2WCYUJbGT817L6m5+Sw5Yfhrgz4
	Oaa8uf+TNUvFXMwzsgzQ11A=
X-Google-Smtp-Source: AGHT+IH/E50CQN2t4KuUIZhEp07O/3kQBdx8nlHqYTqU5hTQUzokSTuQMoiLmNtChFcr4tEVeaQyPg==
X-Received: by 2002:a92:ca0c:0:b0:35d:a6af:5fc7 with SMTP id j12-20020a92ca0c000000b0035da6af5fc7mr10941185ils.53.1702467190805;
        Wed, 13 Dec 2023 03:33:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:6c4:b0:357:3d9d:209e with SMTP id
 p4-20020a056e0206c400b003573d9d209els1086085ils.2.-pod-prod-06-us; Wed, 13
 Dec 2023 03:33:10 -0800 (PST)
X-Received: by 2002:a6b:fe13:0:b0:7b7:122c:5b95 with SMTP id x19-20020a6bfe13000000b007b7122c5b95mr7522512ioh.35.1702467190039;
        Wed, 13 Dec 2023 03:33:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702467190; cv=none;
        d=google.com; s=arc-20160816;
        b=GI/tHWRfe8rDml4LpKyg9CSK58NzPPUycUGfob1UuMyfpbBQPtHYjqMYP/4XH/2sVy
         z9Me35Tix76KJ41Nza87RGAUQ9/dlohUlRUXRDZSE7kezV9QcSeS8akl5NRXUFP8lmLn
         X0jtOepP9KUcKYfZXIGc+DBTOtlvwu2WSzdCPnZnMO6k0EuMl+b7GnWVZ4r0JqRgBlhK
         c223bPVjME8LMkzFmwdIOqvzxQ83KplxGtS4XgJWLIfgTP/0NECo7BUFI/AhPfn8OLMq
         24CXRU29+cZknOTOe4cP5d1qJXnd0RfbA8fUfrOz7Wa54fnARHcSeQM0NoRS9flvBlIW
         n6tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=ikSRKh6y4aKglI7xPKlgKug+5Qtzfc2XgYxtrc2kCH0=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=nsppPrc2kIXagObyN4kQ2NtR7SvZF6BW+WHB4AStd2XOkMaxI2d9NSHnTsdrgUKIan
         OYrsYFVgRwI/8add55+ogfYEb4KLJ+gx8Eo41YceKu+Ot02YqF+7FGWe6QndSoi49lQM
         G7CQZPXcyvoxHq6tmDcx2AaAql5Cif/Q/6wCsXW/44ARGWzEPGzzLdkz9sb2XWMHSNgk
         vfDi3NhcZIKy1etOufzh+8LolugaqZwDeW0iyzJK+mvAS45zBXYT7LrpbRnvxG2qYAKI
         vuAlr8E03IavFTtEvJv752eVJIcGzk2WCtcbCgC52wuijfyAf1on8sKBRrFFCT8PQyQr
         kIuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sXinkoKf;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ci13-20020a0566383d8d00b00466b2a71df6si1087454jab.4.2023.12.13.03.33.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 03:33:09 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDAvp0Z009198;
	Wed, 13 Dec 2023 11:33:06 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uybam8y8r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 11:33:06 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDBKp9W013582;
	Wed, 13 Dec 2023 11:33:05 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uybam8y88-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 11:33:05 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDAcu8Q004701;
	Wed, 13 Dec 2023 11:33:04 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skg1kj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 11:33:04 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDBX18E17891860
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 11:33:01 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8E83E2004B;
	Wed, 13 Dec 2023 11:33:01 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2C74C20040;
	Wed, 13 Dec 2023 11:33:00 +0000 (GMT)
Received: from [9.171.70.156] (unknown [9.171.70.156])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 11:33:00 +0000 (GMT)
Message-ID: <46ede95a4c1d0a9d05d6cc11de1a8d39ce6c0e85.camel@linux.ibm.com>
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
Date: Wed, 13 Dec 2023 12:32:59 +0100
In-Reply-To: <626be6deb066627a77470bf80bb76c27222a5e3e.camel@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-14-iii@linux.ibm.com>
	 <CAG_fn=Vaj3hTRAMxUwofpSMPhFBOizDOWR_An-V9qLNQv-suYw@mail.gmail.com>
	 <69e7bc8e8c8a38c429a793e991e0509cb97a53e1.camel@linux.ibm.com>
	 <CAG_fn=UbJ+z8Gmfjodu-jBQz75HApXADw8Abj38BCLHmY_ZW9w@mail.gmail.com>
	 <626be6deb066627a77470bf80bb76c27222a5e3e.camel@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: uhw5klWQb4Ew4DGEdGMVbEtWPetNaOqp
X-Proofpoint-ORIG-GUID: 48mwCSMvhaKch1ti_YtF_MIEY-bAV7Sf
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_03,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=766 clxscore=1015
 lowpriorityscore=0 bulkscore=0 priorityscore=1501 phishscore=0
 malwarescore=0 suspectscore=0 spamscore=0 mlxscore=0 adultscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sXinkoKf;       spf=pass (google.com:
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

On Wed, 2023-12-13 at 02:31 +0100, Ilya Leoshkevich wrote:
> On Fri, 2023-12-08 at 16:25 +0100, Alexander Potapenko wrote:
> > > A problem with __memset() is that, at least for me, it always
> > > ends
> > > up being a call. There is a use case where we need to write only
> > > 1
> > > byte, so I thought that introducing a call there (when compiling
> > > without KMSAN) would be unacceptable.

[...]

> > As stated above, I don't think this is more or less working as
> > intended.
> > If we really want the ability to inline __memset(), we could
> > transform
> > it into memset() in non-sanitizer builds, but perhaps having a call
> > is
> > also acceptable?
> 
> Thanks for the detailed explanation and analysis. I will post
> a version with a __memset() and let the slab maintainers decide if
> the additional overhead is acceptable.

I noticed I had the same problem in the get_user()/put_user() and
check_canary() patches.

The annotation being silently ignored is never what a programmer
intends, so what do you think about adding noinline to
__no_kmsan_checks and __no_sanitize_memory?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/46ede95a4c1d0a9d05d6cc11de1a8d39ce6c0e85.camel%40linux.ibm.com.
