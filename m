Return-Path: <kasan-dev+bncBAABBU7ZRP6QKGQEQ7BXX3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E85FF2A6D90
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 20:11:16 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id s1sf3305530vks.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 11:11:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604517076; cv=pass;
        d=google.com; s=arc-20160816;
        b=qa9xVPaeYhmCjgxEGEu9tmt69CJ3BM/Jw5TreakkAI7uV1xL08yKK9wTGH267KvKv0
         8RfnApWjcmJ/mDBiQS+ZEckfOtMOYxvcxvGSgJJON4LsgjyYQNx5xuGWh2gKVBSH8h6F
         CUE4LXvl2IhDJ6wRbMClN0hVrjNsUUakjPVRhgE4oWwmVp4KFryz9id50Cyr4KRKrG/R
         H60QNp/R7ouVhbOMQuvlPffQGnRHvHrOXkqyH+3jpmS0Nuc1SVufZBdMkLl1BDNGfeXf
         3HxpwGZiplXyj6o7vz8y6pv5WCfYS/Bx23Y8+IH2UnH9weDLxh8hdzanWGyl5qJJ8H+L
         gelQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HW+i5TI4EteVOUtW/eZnsHudGzNUE2h4OpnIXNSz4PA=;
        b=cA10lCYd0vntYW108NjmApuqF7LhmLeUxTyaWqup5+s2RzhwpAqzp/8Rtio33plvXu
         qMlx4WUoPLIYGjNUGYC0itxihPd1qmySagHyjWoSQ3Vzh0bOows3KlLYFK4DtivkSEPo
         1VowQeH+ThC3tBqDD4sYNza2TikiHts+dCyrRmgfxVdeT/LgXydPIuZp8yZam2TvFoGh
         tOpz4esxHH+y/o6rtYHqgA2mV7bYGRm4170bUZKnUSmZMtSTP9Ot+IWmGmtyvGYmxhHV
         kCYPZW4FVGxxotmT+kknIFqX4CwQTcqjRkHGpmwK3pJLhDoWQavad4K724FacXUfE5kx
         BAOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RvC4Qqbr;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HW+i5TI4EteVOUtW/eZnsHudGzNUE2h4OpnIXNSz4PA=;
        b=ZO3uOljvVkSDxZw4wR7dVcICtzjMfGw4ax0KSy2aHGkmQLiye5E1pYpE3bAudPWqF7
         e0Xn6qYeC2SD5wAEbCq5blyD1PhXtDpRrVLdZB5h18W4GoCBHA36ExaeIuMn4rI49H6f
         sPoS+PYFZ5fd4HMKkxlxf4TFwZK7gB3fJhtM3CCnpFnPCSjN3Q1BjSgPcoluWoP1rgL5
         pUO1t0M7Z3u9ItjkmpIMYYAS+bX0e1pFc9x4Ot2VOKj1sTwFDZ6GEQo6+5Y6idcpqLeL
         t7FhNydhtDQ1egX13N1/SJC2si5Yf9JbMprbu1e0buPBzsTbGDowHuvY6paClYvCtNcG
         DpRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HW+i5TI4EteVOUtW/eZnsHudGzNUE2h4OpnIXNSz4PA=;
        b=KjmWEe58EWTpv5pMKFAWw+flSrDaTVTBERXWmxlnffqpKBJlh3msMgerGr8ZVwof+m
         BM5sNK9GolCm5T4HlIp04GB3VEoSiZyTGy9WZbTwJrYCcT6krPGn50wjtHV2lEAwt/lY
         +2oybI7swGw4qNR27hZ+CtMQJPc4IdhDlAPS+DdOeaXkSrfpgw9SyoC1ZjKZtPqncHLS
         flCwFuTTIhoY++gGPVA3fWBUe7ftOMkTHE/FPUAy16q1yeD54LTJBDkQBKTy53KdchHb
         5ivkOTuLvyf0/38Mih1KTVIIeFMHxzKnmaVPXMfxwgB95FYiSLOcNrC1jF2copy5L6qg
         +0dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RJzseJjhtYF8QYGEkHixkLCbtapK77rRuhzkUuqjqGyB2dpji
	byrUsH9EWBYzTzbHPV6EdnA=
X-Google-Smtp-Source: ABdhPJwloxzc05uuJ5SBVDwhsxTMq4rFgPbDRRP0J3QAaEMWB5zvYwjhDxMkXyMBKkYXezccljR52A==
X-Received: by 2002:a67:2647:: with SMTP id m68mr22977861vsm.39.1604517076045;
        Wed, 04 Nov 2020 11:11:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:24d7:: with SMTP id k23ls208723uan.5.gmail; Wed, 04 Nov
 2020 11:11:15 -0800 (PST)
X-Received: by 2002:ab0:2745:: with SMTP id c5mr6099255uap.5.1604517075570;
        Wed, 04 Nov 2020 11:11:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604517075; cv=none;
        d=google.com; s=arc-20160816;
        b=UJDR+MEd5Y4kel1DYbkMayTcS2S5mvkzSyesN1N2C3wY895Utc20es3SoKNcBXLMjJ
         GCfwVCoB84SVje9YwB7d0FSSYIKvl86K3/j6grz398pu7u0ZdUPfRDO9utFGnVfQbHcr
         Udkx/R12/wlTbPtjN7Bc8ps1EvATUp+ck9P6O33u8TVbDMm9pBW8H1rElEOvvIdQeLP2
         l1UDzADzU8DSzQzho6mjXAIobVGJ3g3NwL1/bQCgsEQAwxXZdhyL6zHWA73MY407qesP
         QTY9ctb3Lt5ic3lSU0Y1l52B6rq0KncmWDfkkzI2vjCoKNU+VHJ1s4278BngV5gA18NG
         PDww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DqOTob3AwioDey1KiiTHJajU7QOQhnFPsLrIyrA03QM=;
        b=AjFm44sQwJoPt9H2LwF5cNLM/jF1q0VIUWF0hEgfP0efbwNKJaiJdAeWoPirpoJMJT
         //gcuLyfZ71+PGrujYIM3yQ9GzALULKHK9Ptl/QauvId9rkVrmNw541CmqAUW9Z9CZnY
         v/B+8GT13ZRuZ3/UXXR4NYvNKykdwyaJbm/DDlocO9PmxrSF9+Mdght3qWbqcVW8dF27
         cLK95DKa2u2XNuaPmo1WbepP+0YvKtB0sH5KGYY8cjf79F7CVU7txRJ73RMEb71aN6tl
         KxG18z6UaAaEZe/JCc39xcgBjymjr8OUKlLT+R69BnMhkDRD44CNblqRhR7Vwi5v6YsS
         MY6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RvC4Qqbr;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id v18si225003uat.0.2020.11.04.11.11.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Nov 2020 11:11:15 -0800 (PST)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098421.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 0A4J1IjH073873;
	Wed, 4 Nov 2020 14:11:13 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34kga5sp22-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:11:13 -0500
Received: from m0098421.ppops.net (m0098421.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 0A4J1daw075836;
	Wed, 4 Nov 2020 14:11:13 -0500
Received: from ppma06ams.nl.ibm.com (66.31.33a9.ip4.static.sl-reverse.com [169.51.49.102])
	by mx0a-001b2d01.pphosted.com with ESMTP id 34kga5sp14-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:11:12 -0500
Received: from pps.filterd (ppma06ams.nl.ibm.com [127.0.0.1])
	by ppma06ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 0A4J7FfV021411;
	Wed, 4 Nov 2020 19:11:10 GMT
Received: from b06cxnps4076.portsmouth.uk.ibm.com (d06relay13.portsmouth.uk.ibm.com [9.149.109.198])
	by ppma06ams.nl.ibm.com with ESMTP id 34h0fcvn3v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 19:11:10 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06cxnps4076.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 0A4JB8vK7209622
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 4 Nov 2020 19:11:08 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3B5764C044;
	Wed,  4 Nov 2020 19:11:08 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 17A034C040;
	Wed,  4 Nov 2020 19:11:07 +0000 (GMT)
Received: from localhost (unknown [9.145.163.252])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Wed,  4 Nov 2020 19:11:06 +0000 (GMT)
Date: Wed, 4 Nov 2020 20:11:05 +0100
From: Vasily Gorbik <gor@linux.ibm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
        Will Deacon <will.deacon@arm.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
        Elena Petrova <lenaptr@google.com>,
        Branislav Rankov <Branislav.Rankov@arm.com>,
        Kevin Brodsky <kevin.brodsky@arm.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 16/41] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
Message-ID: <your-ad-here.call-01604517065-ext-2603@work.hours>
References: <cover.1604333009.git.andreyknvl@google.com>
 <4dee872cf377e011290bbe2e90c7e7fd24e789dd.1604333009.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4dee872cf377e011290bbe2e90c7e7fd24e789dd.1604333009.git.andreyknvl@google.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.312,18.0.737
 definitions=2020-11-04_12:2020-11-04,2020-11-04 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 mlxscore=0
 malwarescore=0 clxscore=1011 impostorscore=0 mlxlogscore=999 adultscore=0
 bulkscore=0 priorityscore=1501 suspectscore=1 phishscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2011040135
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=RvC4Qqbr;       spf=pass (google.com:
 domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=gor@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

On Mon, Nov 02, 2020 at 05:03:56PM +0100, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> The new mode won't be using shadow memory, but will still use the concept
> of memory granules. Each memory granule maps to a single metadata entry:
> 8 bytes per one shadow byte for generic mode, 16 bytes per one shadow byte
> for software tag-based mode, and 16 bytes per one allocation tag for
> hardware tag-based mode.
> 
> Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE, and KASAN_SHADOW_MASK
> to KASAN_GRANULE_MASK.
> 
> Also use MASK when used as a mask, otherwise use SIZE.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
> ---
>  Documentation/dev-tools/kasan.rst |  2 +-
>  lib/test_kasan.c                  |  2 +-
>  mm/kasan/common.c                 | 39 ++++++++++++++++---------------
>  mm/kasan/generic.c                | 14 +++++------
>  mm/kasan/generic_report.c         |  8 +++----
>  mm/kasan/init.c                   |  8 +++----
>  mm/kasan/kasan.h                  |  4 ++--
>  mm/kasan/report.c                 | 10 ++++----
>  mm/kasan/tags_report.c            |  2 +-
>  9 files changed, 45 insertions(+), 44 deletions(-)

hm, this one got escaped somehow

lib/test_kasan_module.c:
18 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01604517065-ext-2603%40work.hours.
