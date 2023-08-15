Return-Path: <kasan-dev+bncBCYL7PHBVABBBL7F5STAMGQESXUR56I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id DE3EE77C923
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 10:09:21 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1bbb34b0abasf101866075ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Aug 2023 01:09:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692086960; cv=pass;
        d=google.com; s=arc-20160816;
        b=iXykaoZDvbMxT9ecZGXTpv3gSOXhy9TyjKL8/wq66lPTy5YoSO/RWmrNkaHtlp4+Jp
         IzF/xT2dH3P0HpZ4epCwZxCPQ6u2kdwfTbMmZKg9/DoNtFJPVBz2qk/fxnIXTz9MCFxg
         1SaDZy/VJcUaOEO4L58y4IRytmlkaZ+U+aRnmn7UNuXdHSRfuVNFCHGMhpC/bmjUiCJH
         93OztdjGcF7JOdQxcO8Az+jnyFXv0MzgDzQ0qqOn4fFnHvipUysPITHel2AW20zeNvcT
         +h10yKsHsYvCtx2b5SqFPeZq1KmZXgtpGO59PWft+AVa70VRhZJ4dKictBfHh+rFhW/5
         n8Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=rR4Op/oq1z8cPSe+905RivAul0a8ehuGsvRS8kC3K5I=;
        fh=ZqpN5WUsqXGRpnh0UE6MM35kQhpRYx7kLJwPnK+TBLs=;
        b=hNQbvSPcBCq7u1+gJVLe+lRhWk5q8nG0lb3/XVQ7Zn7tIHORwxF2IZtBgZjigbSV4H
         BZzHjbg0LLn+2V7k8PgB4lxnd4qhURbMTPlxJ1Xu6jUZ6tkMbfO3FQy5gMvjuZgkhriw
         KNUpC8bTI48Y/5DVGsFtcm0p7viEHfeaiUZ4WPlzqlqlSVTymKHtIzHrwRL7QL5f+bGb
         BNDPGWXcDolQlIl9xf1WP6OUj3Xf70ppwAseRWGp7K6wTdeMQ9UOY3e/dicxSd3yVJ6x
         50/Q2ZbnW7s40WrOTk1Mk7ikRroIZPC+KGRyqiR5PENNu6eNDDrHg969/DeXurMXQOLy
         NTvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VUhtqSmA;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692086960; x=1692691760;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rR4Op/oq1z8cPSe+905RivAul0a8ehuGsvRS8kC3K5I=;
        b=sW/oPX2yxLU/09jK3gFJ8xDRlkEpwXNtWp7ZzxTy0Nd7ql2VxZLEDb6UXYVLK11D3C
         6VIpH/YzfAsMIEYOMfbW+OPPXYqqHJnFS+pggWAAbILS+zHFwx2ckvBYhZEst/Qvemog
         FNYXn4N1T7kITxG+5k74F5bHJsXELTWs4+XVQLvjR7tyj2IBgIAlWBPcRTKZlJn+JUAw
         h9ph+KCWYIHCRdb0wJNfWB0QfuWtazbRoq1Wc1ZFrgMXweD36YaBwYZjpDofikF5oiZl
         JnH5VLoAzljpZobzGmK0fAgDOyM417JXb3DcFmM1qsnjOik98+uyoivFPaKAWUghTibo
         2hWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692086960; x=1692691760;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=rR4Op/oq1z8cPSe+905RivAul0a8ehuGsvRS8kC3K5I=;
        b=EviEJjeX/EK+eZdVhb9upZ2FTnn43ZXZRe5pdLPBCkjzA3Z9IAlH9i53FfOBfafEHd
         qwmJcsjQv/exm9mn8n8Cx3l17KU54xD3Ytoxgu3ovafdKb7S54XUqAAagQGEMDokKxoa
         J18LDIiKs7zczaEvvWDJkebaRElMuEiyYVP7PpPR1XQeXjgl2PzV3DZ0Plb+I+5vg4NG
         n73tiUc4j0l9S9kDWf8sUh5mTo3QROgH9mFJkJy2GAuXfTbX5P7BVFlMCrMQjVqNEwGj
         h278cls9JnJjO6IQ8Fg6sT12mYpZPj2WCkLmzsaBV0+1XRdYcrixe8xtodWBTq1CXLGV
         3cFA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyYwd/ROHWSLVUWI9VJgoI0X75Q96ghkjarvO78CNwJYQfHzIu+
	7X9qjke5U3U7JL8yMJgPC9w=
X-Google-Smtp-Source: AGHT+IEKAlQtvNRwW5unNXHSmp1p7Vs+76hGplExfYZgcsAp5wehWnfE+uim9j5FfAAwPXziOiqY8A==
X-Received: by 2002:a17:902:db06:b0:1bc:8249:2533 with SMTP id m6-20020a170902db0600b001bc82492533mr18878265plx.42.1692086959992;
        Tue, 15 Aug 2023 01:09:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab5c:b0:1bd:95e8:f441 with SMTP id
 ij28-20020a170902ab5c00b001bd95e8f441ls4880781plb.2.-pod-prod-06-us; Tue, 15
 Aug 2023 01:09:19 -0700 (PDT)
X-Received: by 2002:a17:902:ecce:b0:1bc:1e03:3cbe with SMTP id a14-20020a170902ecce00b001bc1e033cbemr14699033plh.18.1692086958991;
        Tue, 15 Aug 2023 01:09:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692086958; cv=none;
        d=google.com; s=arc-20160816;
        b=AE7wPZ9jHNWmZjsNfI5+YPlHgX0myRa8WU9d4dvRyPfnL+PKjUogTuglMPw38DvWWm
         o2LFhkV7RBQa/sDGX7jQwiNpF7/FXGJi2QOwoVZRwwrCVUjfDqy5fY2eolCYl4VxD6PG
         SLvPth4SM68P6mC2fCuiEifglK85BEwNs3ABWF98SBZwAPj0GybksG2cKZrHELxeo2Q1
         f859qdjaOMg3pmPY+r64v/GiFQPhcXeQYYTh/5DT+KcuYzim4Htm0A49lX6hRLMt+p4I
         YzM7sM3Rr79iqEGoyR95Z5yUrz4rXD14TIdPwxkcUAPLcNn6yO1On1WEJbF3rr6nm1F9
         SwkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=t2RXLILrIgG0Fj0L0CI1FeSJt/iaLrmiUFqdyN2/nmA=;
        fh=ZqpN5WUsqXGRpnh0UE6MM35kQhpRYx7kLJwPnK+TBLs=;
        b=Qj+VawBgQQj8BMoOs7ADz6M9BeX423s4ltIVceUQm0OKib8i+shnUv/Go9M9Os2qk1
         CGHuLBSIRD/XZd6R5M0c++EZkBN4K/6wP/WJXC5XPzMv6eq6bF6K9dIq3RvLI9v0Kb95
         0Q2Q7aRf9DDUJSi/FIc3hAJmiKug8gB70iN/jYd4BwXU5sWsdz8UjQx3ejModN+12LqU
         Zu41EmwbsMo4Ylr3WVb3xq4h5gVavFxJZwXYHjCxieW8RXZ7w8i0OrRTI2oJqaIvMFUZ
         1BOOxzWlzcyylWMVkK5iUSefps9e7fDmb1IOCqdtmDuv4ohLx26tseRIWc4p3sYZYkRd
         I4FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VUhtqSmA;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id kv16-20020a17090328d000b001bb2c4018a6si514561plb.2.2023.08.15.01.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Aug 2023 01:09:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 37F82HdU031171;
	Tue, 15 Aug 2023 08:09:18 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sg5gc0505-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 15 Aug 2023 08:09:17 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 37F82M8O031371;
	Tue, 15 Aug 2023 08:09:17 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sg5gc04yy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 15 Aug 2023 08:09:17 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 37F7xSt8007861;
	Tue, 15 Aug 2023 08:09:16 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3senwk3cuv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 15 Aug 2023 08:09:16 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 37F89DGI36110940
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 15 Aug 2023 08:09:13 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7DB4220040;
	Tue, 15 Aug 2023 08:09:13 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2A5EC2004B;
	Tue, 15 Aug 2023 08:09:13 +0000 (GMT)
Received: from osiris (unknown [9.152.212.60])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue, 15 Aug 2023 08:09:13 +0000 (GMT)
Date: Tue, 15 Aug 2023 10:09:11 +0200
From: Heiko Carstens <hca@linux.ibm.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        Gerald Schaefer <gerald.schaefer@linux.ibm.com>,
        Vineeth Vijayan <vneethv@linux.ibm.com>, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] s390/mm: Make virt_to_pfn() a static inline
Message-ID: <20230815080911.6414-E-hca@linux.ibm.com>
References: <20230812-virt-to-phys-s390-v2-1-6c40f31fe36f@linaro.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230812-virt-to-phys-s390-v2-1-6c40f31fe36f@linaro.org>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: pt5R4EGEyNLFkycSwcQ0sMhAJlCPFw5k
X-Proofpoint-ORIG-GUID: yOz2XuEJqGjO8UUmcDV85oqI_O8okZvU
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.267,Aquarius:18.0.957,Hydra:6.0.591,FMLib:17.11.176.26
 definitions=2023-08-15_07,2023-08-10_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 adultscore=0 spamscore=0 bulkscore=0 priorityscore=1501
 malwarescore=0 phishscore=0 impostorscore=0 mlxlogscore=851 clxscore=1011
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2306200000 definitions=main-2308150072
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=VUhtqSmA;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On Sat, Aug 12, 2023 at 05:12:54PM +0200, Linus Walleij wrote:
> Making virt_to_pfn() a static inline taking a strongly typed
> (const void *) makes the contract of a passing a pointer of that
> type to the function explicit and exposes any misuse of the
> macro virt_to_pfn() acting polymorphic and accepting many types
> such as (void *), (unitptr_t) or (unsigned long) as arguments
> without warnings.
> 
> For symmetry do the same with pfn_to_virt() reflecting the
> current layout in asm-generic/page.h.
> 
> Doing this reveals a number of offenders in the arch code and
> the S390-specific drivers, so just bite the bullet and fix up
> all of those as well.
> 
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
> ---
> Changes in v2:
> - Just drop the cast to (unsigned long) in drivers/s390/char/vmcp.c,
>   we do not need to cast to (void *) from (char *), a pointer is
>   a pointer.
> - Link to v1: https://lore.kernel.org/r/20230811-virt-to-phys-s390-v1-1-b661426ca9cd@linaro.org
> ---
>  arch/s390/include/asm/kfence.h |  2 +-
>  arch/s390/include/asm/page.h   | 12 ++++++++++--
>  arch/s390/mm/cmm.c             |  2 +-
>  arch/s390/mm/vmem.c            |  2 +-
>  drivers/s390/block/scm_blk.c   |  2 +-
>  drivers/s390/char/vmcp.c       |  2 +-
>  6 files changed, 15 insertions(+), 7 deletions(-)

Applied, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230815080911.6414-E-hca%40linux.ibm.com.
