Return-Path: <kasan-dev+bncBCVZXJXP4MDBBC7LZ6ZQMGQE5LETJ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 862A7910037
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 11:25:32 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5badb0511b3sf640665eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:25:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718875531; cv=pass;
        d=google.com; s=arc-20160816;
        b=etuTngSVpf8jQrWk4z0X1XwqBTdTYKLwa56BbJXQkdimLQh+t2WZ5cvdsEU3qLZDZt
         4ZxjeE17NmJ130ASw49UehabQiw73AO3eu6u7V3zUr9KfxKH8bMgQPf2uzhMWG0G2DB9
         lnyguIZn+b+VEy66FvDw8Gj1LcZ8KQd1x1K2/09NmNxB1vW8EyTC2qVUEgKR1AbrAtvO
         YW8OkaOkM9G5uGOVSzAWHD4A1MjN6tAyXQ8p+zLaa8WZrEVNj7Km621C0OeRfMzjXrUo
         HRcrrBCtzc0WSBcDl2qvyGd880Ul18GgXx60Fri9EiMxKBqAlwN3q8kGLIjja/JYNkls
         CIRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vjpocHXOFmiyVveL2jsoZia0dG1KqWXaeSyRKmsL8aY=;
        fh=RBsCPk/lpOaM6/Z2Ze3ylKYnhXY1xLGxs3WhMhWD8q4=;
        b=xW6/OzIgJTD2CmHarUH5gWrsBBswR1b9HtMUo3EuQyEmLYmYRMVG3U2m7Km4qPAtIR
         U6KKXGOVDb3x/ZSBYOKahkPRyAsO3Jp6HCo5G7VQQBLndlf66HEEof2zcVRHc48kfu2p
         lMrOTnLa4S1iaGRl5uunW8zLNr/mHyke4XqzwbhI+gSRm7ZHhmvbbJ76i3ydFrsvJl24
         F/Gq8AVVAfjT+Qxh0cHgKLTgzPSDAwuSYtB0iK0906b+IRCkyNRO57PAeMdzI7Pn8pIc
         jeviAmNIgNfrCBycK1CVJzP0IGQk9PlKUCz1CSBqNDkuGTFLh+Fkr7rMw3qCiQozcSVi
         Vbfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Sfio6WQO;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718875531; x=1719480331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vjpocHXOFmiyVveL2jsoZia0dG1KqWXaeSyRKmsL8aY=;
        b=v6txs1BexxUNyZ2WxFcCtbg4ObMjXSvYhr4iMBtxb/eP6MPtUKqv+MfvkFXtOLxarp
         757Tzp9Uxk8aNS4e12sVmBsqO1hEaPRjXXxb15QDL2cgarevIIxKdAb/TybnAwQTcool
         Jf+HhdKOc4cS/LaWgRojZ8/9Eq2tluCxW8Z/TNuvI+B148KK6R5HtY0s4nzsoJKxC3AK
         sgoKyiTDN+ChouVqqLaYguPGSpYtekR4WI44OK5e1xfacCxkPGpLGmkjBMNpOrAUIrNZ
         a92twUIUk3ySBKD4iXSX16S8ej2kEBgFAqF3jvKQy92+dd8zp3A/Qi/ABnKsU7uKJMfq
         gCNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718875531; x=1719480331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vjpocHXOFmiyVveL2jsoZia0dG1KqWXaeSyRKmsL8aY=;
        b=SuQAGg7S2mLp801gEaMcd2TacGG1CnnXUyMJ/KYQFyXnAT1QaHAFj2i4ylCG+J57yC
         C8Hy/GIQYl/UtYy9rd4QHBOi4e8QTpHGleYNFt0ewCwRNriIG7i/GfLFDdUN5yD5Dbvr
         7AJdGCft95JPrj2GjVIyuD12ceFvZI/HgptRKR7q3jqm4iL3cT45WgaZmntISO77Gwi9
         SXWk31C6GnDvj1TJezySQq4312aHY9IgGnD+sXCSgkjDdaZA6nsi/ZnscR4v4Z7YW/U0
         nTNLeMTVUXVfvoPlJqRNmxdrZzdqOD5mtbur/CQZCGPAEehqwBzTTGVka9ADbfhk92Hj
         bukg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0wLw1Z7JqyZcmICRwqgo0lpbt17BIKJuOEogL9CfaK6nD9VT9a87BHU1HBpPmOJ3V3UejW/79A1qyTiM+WKZ/beqNduZBWg==
X-Gm-Message-State: AOJu0YwKItZzMKLIjXABOVJLUJQRENDF4CqRgToRcmkJG6D9KKJ/sd65
	KRkufTl/b3zQHrZNjBmA/+KeSuKsbCOq04biFj6ZivWKNyoPgzBy
X-Google-Smtp-Source: AGHT+IEk1CkHkKPLqbriKM5HXMS94Toqx3teCqNcp0FrwkmNUFWdKCL6Q8Mn0vbg/zeXuR+EwUOU+w==
X-Received: by 2002:a4a:d195:0:b0:5c1:b03f:bb73 with SMTP id 006d021491bc7-5c1b03fbbaemr4543140eaf.9.1718875531192;
        Thu, 20 Jun 2024 02:25:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3002:0:b0:5c1:bd4c:b16b with SMTP id 006d021491bc7-5c1bff28ba7ls574631eaf.1.-pod-prod-04-us;
 Thu, 20 Jun 2024 02:25:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU22az8vFolcvTTglQEVaimsx0gb5q0H21ukTR+eC6LaqAODXGA7bK/NcF8GNAOp2ljerHSZIbEnB+7qSQQQBTDQfiYaKvGSLM9Ow==
X-Received: by 2002:a4a:3816:0:b0:5ba:ec8b:44ac with SMTP id 006d021491bc7-5c1ad8a17aemr4926943eaf.0.1718875530378;
        Thu, 20 Jun 2024 02:25:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718875530; cv=none;
        d=google.com; s=arc-20160816;
        b=lUH/V1e1OnUDhjyrSa9PA9HOhHAhHi+BkfnxGLFk9fXTMZDRDDatfXleDvoBGcJEyd
         IruYSW5Y7v4UX+PN0baLzTucbpUrcctFnWjhcZTDHp5eh5I3ILj69XUnjPcefDhOec9H
         a8X8ApW0V+8RGgeUhEEQlIg3tRtw3FT+DE8AL3uw6aIPjYwFaFhTdo8CimwG1p0J6gkc
         k3176XEA3uo/uPybFn9gLzeoOnNeLLGpJ7znTbWiEsyRPtLI4u+mCVffe5P0/lDN7KkR
         Jj4a60WS4JEZxq4p3ohcN68R44xa6XoqM+UjEGPxlpFIdcpEKCD8cjR7eCjvjqpq4aFb
         LZlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f+xXT+pi71Ik+KvC0QHepWSaRorcAZ6T5r10Nujhews=;
        fh=eUQW7IhWDHChH74ax7Qu+GWbgAXuHHxgFdOHk9U0EvY=;
        b=QXU/kVH1smgk9oOIS9hNcPYC+aKxNkJY2AN4TUDSg2XqtZp+3u+PKhq/weeQ4cecSq
         egPZb3BPHb48JwBPVSYRgQX2TChYdsg/fWlGSH+LMLRe9sk07db/7/F4ENWOmHvGf2Sk
         NeM1CtgwyFZAhohZq31+5PhoKdqe12rTae9czLpGRMn1S7yHHa2JZoshSyFawkQzRbYV
         XNV5YojtPunY6KFru/ww+txBNWMrL6TPP3pnaipnSpS/ykz0Zt9bgUVSvpB0zmzh7sw/
         M26UaFPIbZPhULB+sFAXkjLKloAGQpysN2MH861uQIfAX9L9AHwo049jTdEZ6cOvpiIU
         NmcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Sfio6WQO;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5bd59ad0251si876620eaf.0.2024.06.20.02.25.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 02:25:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45K902cF016608;
	Thu, 20 Jun 2024 09:25:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvhd082aj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 09:25:24 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45K9PNjH007553;
	Thu, 20 Jun 2024 09:25:23 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvhd082ad-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 09:25:23 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45K8q0Lp011355;
	Thu, 20 Jun 2024 09:25:22 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yspsnmdy9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 20 Jun 2024 09:25:22 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45K9PFWx50331948
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 20 Jun 2024 09:25:17 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3AA6C2004D;
	Thu, 20 Jun 2024 09:25:15 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 50D6720043;
	Thu, 20 Jun 2024 09:25:13 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.21.176])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 20 Jun 2024 09:25:13 +0000 (GMT)
Date: Thu, 20 Jun 2024 11:25:11 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>
Subject: Re: [PATCH v5 36/37] s390/kmsan: Implement the architecture-specific
 functions
Message-ID: <ZnP1dwNycehZyjkQ@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
 <20240619154530.163232-37-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240619154530.163232-37-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: wGgihVial8kXJ1bFTIVWyPNHF-8EUg62
X-Proofpoint-GUID: 0mzQWVSjgWONbMvCB5bN-IoPQn2J8C9F
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_06,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1011 impostorscore=0
 bulkscore=0 spamscore=0 adultscore=0 mlxlogscore=512 suspectscore=0
 priorityscore=1501 phishscore=0 malwarescore=0 lowpriorityscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406200062
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Sfio6WQO;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

On Wed, Jun 19, 2024 at 05:44:11PM +0200, Ilya Leoshkevich wrote:

Hi Ilya,

> +static inline bool is_lowcore_addr(void *addr)
> +{
> +	return addr >= (void *)&S390_lowcore &&
> +	       addr < (void *)(&S390_lowcore + 1);
> +}
> +
> +static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
> +{
> +	if (is_lowcore_addr(addr)) {
> +		/*
> +		 * Different lowcores accessed via S390_lowcore are described
> +		 * by the same struct page. Resolve the prefix manually in
> +		 * order to get a distinct struct page.
> +		 */

> +		addr += (void *)lowcore_ptr[raw_smp_processor_id()] -
> +			(void *)&S390_lowcore;

If I am not mistaken neither raw_smp_processor_id() itself, nor
lowcore_ptr[raw_smp_processor_id()] are atomic. Should the preemption
be disabled while the addr is calculated?

But then the question arises - how meaningful the returned value is?
AFAICT kmsan_get_metadata() is called from a preemptable context.
So if the CPU is changed - how useful the previous CPU lowcore meta is?

Is it a memory block that needs to be ignored instead?

> +		if (WARN_ON_ONCE(is_lowcore_addr(addr)))
> +			return NULL;

lowcore_ptr[] pointing into S390_lowcore is rather a bug.

> +		return kmsan_get_metadata(addr, is_origin);
> +	}
> +	return NULL;
> +}

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnP1dwNycehZyjkQ%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
