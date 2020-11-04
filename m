Return-Path: <kasan-dev+bncBAABBOEART6QKGQE6HU7RCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 25E472A6DC9
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 20:25:46 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id s6sf7062097plp.13
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 11:25:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604517945; cv=pass;
        d=google.com; s=arc-20160816;
        b=hXYdxorWpg4bY+A1qo6ntolpsNNKr2vMADjMeEhmfmDjld+XPChysltOOZSpxFvliJ
         zB4TDjCbo7sCmxdBopQGCOaabCf6mhoM12rJfpbFK59uXcrqW8HW5suALV+gSmijfvjQ
         s9xtgCLM8/JJX4tNHnd5v+Py7Qx2G6cJ2mS2b2jZv5yubs+lZu7uDFdhzpEQD2EFQsVY
         1T/vhJJr0SK538O5abp2LxBgrUFRx6/rncLaMy4XRTpGAxaT5ISPYHAE3MxIUyWejrQB
         tBogbSiAcYCdFqitdIrhdZRkSqq8xtshlIv4tEIlKi/xIq7ZUI81NZbZId1yIifQDMkZ
         QtyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ez48E784bBbTJD1LD97Vh/2l6ON7MIU0wXi/uuyZQso=;
        b=Z6jcwwf8efjgO/Fk1xaGHTgpMQfsaTQELtXxKuh3gbJA2cr4ZMcOasD5SoRIkhlJUq
         iU1D7723O85XQDX5WmOjTQQK2TLX+2KLDlUq40DGk1Q25/VRxm+jnOvBBGNWKUrF5Ssb
         HAOjrhwTflVO6HXEIJEMWH1hD3kqwt0eN+Nx8jXIn8zp3l3V0ZYrO1E4pvMOW3NcOL7+
         HaBAV43mpTxy4w6AneP8v36kwYX8veC1jA6v0sa71RXoQwnJIGzUfVSowj1vak/xch6o
         KXk0JuKpKqe/gnDgqLNAg+hWdQoezTqJkPAwJD8EgeT+PFEcPw6r61EjijqiTc6bl6YJ
         cVEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FHK8r4uH;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ez48E784bBbTJD1LD97Vh/2l6ON7MIU0wXi/uuyZQso=;
        b=pKOyGFv0jjbufFMwqcDQhhEUqnITyrZ80fF7uRzfv5eE8JBZaRkY5T1qUoBmsaxots
         EWgx2a08h4hvw9nEkTwszMvcNWObdaKWYwazdCTb8UPpDvd+aG56HfCuYIU2ojJQx0dL
         aHUan6Tbfuppwcu0Mw/MOx8gvxzAe+ieWHAG7dVwv+VwfKGIHbzfmPG1u1pfVbCAGC0L
         swc1upt67x6AcX/ZJW6QDZ//+TaJSAEg/w/ng3DqsDzsuBKONY4ypUlKYRxO2I/xhK0H
         YokqZHjiOC6cR+mP77+OhyERQG3P01oWTaGnfKOh7FiHfnQ9UlNKGMgCKLTSh+aAhGyu
         /+Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ez48E784bBbTJD1LD97Vh/2l6ON7MIU0wXi/uuyZQso=;
        b=Bx8XE2Lg9yiG+Um2VzMOD/csVSstMfLtSiytevrxqnU6aP7X1BEogX9Tl991Z09/1A
         IaY0LT0hxbqVOi8Agqo+lBIAFes/+5xGm98kx+IkvMGWCtGgQOcZJ/weU6Lb1HGujr17
         jGW4HeHBP65A1gt+qaD4c6u9sjl2vCUY3499uyoZb3zJXuy2mzEXsb2tYRC7VEiDNAIm
         YeDMne/B18wCXn4/0Ky9L+bY1jVsT5SxQVDO5WWAFBVgjjCGQUROYlkqDcZ+7zLea7hB
         6AvuXRnytcVWLlDUojFwbpFlh+ppJxyIDcdf6Uy+/5Qxur9rnBuNIwhn55VLfUTUBC03
         upIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zjyjd2dvF8WO636vORl85arh0lYUY0Qs2280kQ4EPdJrJ27XG
	cFhdWQ7QIS1yKryVR240HcE=
X-Google-Smtp-Source: ABdhPJz1S/djlWXGb/C3kQTJxnbTLCuDXXmkZ1Laf3k6+JD/hhMDVFq1H57OUyCU2okIdwL3DW1r/Q==
X-Received: by 2002:a63:4960:: with SMTP id y32mr22583455pgk.369.1604517944926;
        Wed, 04 Nov 2020 11:25:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f13:: with SMTP id a19ls1184446pfd.9.gmail; Wed, 04 Nov
 2020 11:25:44 -0800 (PST)
X-Received: by 2002:a65:5c43:: with SMTP id v3mr23620494pgr.271.1604517944458;
        Wed, 04 Nov 2020 11:25:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604517944; cv=none;
        d=google.com; s=arc-20160816;
        b=RSO2N1CfxPxab+X+/N5etSYKern2P9hXg/6NkNXH3J7BO/gGFOTstJTi1hUkHA6i7G
         gAgAr6+oRvv6gpT6HKYfXO8ppUqrDqoktr1cm0xWFTrgxyGnyjHKOuIZX6d1tapJ2LrK
         7fnf3vkImykMyLdqGpOq3BfNnDaRacPYwx1ELqS7ABtPn8Z4SQTIJzUgyhUg6pVHTtsu
         QxOVsvYs7BmcIneLeE9mobtHO1CHJ/DWJCzDfzk+lb2j5sFCDLBOuP9cyvLBfsRcUAWl
         VApq1bONtzg/5Fm+cs1/R2bv9EJnAQQnVJCNaldD1Ke7s5S3QhtdQ2G4ymPqpY4QU8pF
         Czow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Dd13+njnwpYwPf2e/d/TSON0FWEufciVHRrSOmk9gOI=;
        b=d1TOI02G6VzUMQXcevBGF8hMStbrTTe6jFZaY09w3L6bqv+bzOTSs0+QD9oBQm/tGA
         KoRtFEj/NutcGF3DeEaXZdxTrQuCUTbsOwQI1YVPYWDj+vn3fkU6Gs3+m4BK+xPBH24K
         UI6ffVM8zj0uEH+EovfFbxuNx9FCDGddyAhTfBx/PWotylRXLs4r8eLeIPW1V3264eB0
         +NVZPOtfnUcPeIUK/6DlIVEQaxV1Ajwwi80Oy7DZOjuCx1yDGlOIurRWfG3HkjReZyLd
         ZxmTW7hPvCE/rEWwY5ItcioMoZZ9cO/Eri/2LxJLUwM3bJah884vImi1ouW0WSkCRvoo
         UUvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FHK8r4uH;
       spf=pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=gor@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id t126si231820pgc.0.2020.11.04.11.25.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Nov 2020 11:25:44 -0800 (PST)
Received-SPF: pass (google.com: domain of gor@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098416.ppops.net [127.0.0.1])
	by mx0b-001b2d01.pphosted.com (8.16.0.42/8.16.0.42) with SMTP id 0A4J2MFv161908;
	Wed, 4 Nov 2020 14:25:37 -0500
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0b-001b2d01.pphosted.com with ESMTP id 34ksrutk1y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:25:36 -0500
Received: from m0098416.ppops.net (m0098416.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.36/8.16.0.36) with SMTP id 0A4J2b2O163457;
	Wed, 4 Nov 2020 14:25:36 -0500
Received: from ppma06ams.nl.ibm.com (66.31.33a9.ip4.static.sl-reverse.com [169.51.49.102])
	by mx0b-001b2d01.pphosted.com with ESMTP id 34ksrutk15-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 14:25:36 -0500
Received: from pps.filterd (ppma06ams.nl.ibm.com [127.0.0.1])
	by ppma06ams.nl.ibm.com (8.16.0.42/8.16.0.42) with SMTP id 0A4J755N021008;
	Wed, 4 Nov 2020 19:25:34 GMT
Received: from b06cxnps3075.portsmouth.uk.ibm.com (d06relay10.portsmouth.uk.ibm.com [9.149.109.195])
	by ppma06ams.nl.ibm.com with ESMTP id 34h0fcvnc9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 04 Nov 2020 19:25:34 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06cxnps3075.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 0A4JPWOc51052868
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 4 Nov 2020 19:25:32 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2AD224C046;
	Wed,  4 Nov 2020 19:25:32 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 209CB4C040;
	Wed,  4 Nov 2020 19:25:31 +0000 (GMT)
Received: from localhost (unknown [9.145.163.252])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Wed,  4 Nov 2020 19:25:31 +0000 (GMT)
Date: Wed, 4 Nov 2020 20:25:29 +0100
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
Subject: Re: [PATCH v7 13/41] s390/kasan: include asm/page.h from asm/kasan.h
Message-ID: <your-ad-here.call-01604517929-ext-5900@work.hours>
References: <cover.1604333009.git.andreyknvl@google.com>
 <5e7c366e68844a0fe8e18371c5a76aef53905fae.1604333009.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5e7c366e68844a0fe8e18371c5a76aef53905fae.1604333009.git.andreyknvl@google.com>
X-TM-AS-GCONF: 00
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.312,18.0.737
 definitions=2020-11-04_12:2020-11-04,2020-11-04 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 mlxscore=0
 bulkscore=0 clxscore=1015 malwarescore=0 lowpriorityscore=0
 priorityscore=1501 impostorscore=0 suspectscore=1 adultscore=0 spamscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2009150000 definitions=main-2011040135
X-Original-Sender: gor@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=FHK8r4uH;       spf=pass (google.com:
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

On Mon, Nov 02, 2020 at 05:03:53PM +0100, Andrey Konovalov wrote:
> asm/kasan.h relies on pgd_t type that is defined in asm/page.h. Include
> asm/page.h from asm/kasan.h.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
> Change-Id: I369a8f9beb442b9d05733892232345c3f4120e0a
> ---
>  arch/s390/include/asm/kasan.h | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/arch/s390/include/asm/kasan.h b/arch/s390/include/asm/kasan.h
> index e9bf486de136..a0ea4158858b 100644
> --- a/arch/s390/include/asm/kasan.h
> +++ b/arch/s390/include/asm/kasan.h
> @@ -2,6 +2,8 @@
>  #ifndef __ASM_KASAN_H
>  #define __ASM_KASAN_H
>  
> +#include <asm/page.h>

Could you please include
#include <asm/pgtable.h>

instead? This file is also using _REGION1_SHIFT which is defined there.
And I have some s390 kasan changes pending, which include
asm/pgtable.h as well, so this would make merging simpler. Thank you.

With that changed
Acked-by: Vasily Gorbik <gor@linux.ibm.com>
> +
>  #ifdef CONFIG_KASAN
>  
>  #define KASAN_SHADOW_SCALE_SHIFT 3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/your-ad-here.call-01604517929-ext-5900%40work.hours.
