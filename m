Return-Path: <kasan-dev+bncBCVZXJXP4MDBBQGYSCWAMGQEFCAWRDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E1F5781B592
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 13:14:57 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-59127d45e36sf774587eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 04:14:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703160896; cv=pass;
        d=google.com; s=arc-20160816;
        b=rgJf7MNIsepRvmF5rOG6nG503qGqyzI520vaLPzDkjSn9m3ddyhqeV4EvXyptOE1HY
         huGKcUKm4pxKfreWcZ7aDL7NJetu26ohPkxdelRwsVUQnDzK/RYV3H0oBuGyBFK7K9OF
         wfYXRMxVIKofCx91H7SQmBkuUTpXyoaOdvFtg2p+P6H7d9RGoOGiFwkxDkfxKz70S3G1
         Z4F2dgaZ9WUUyPLhAOY/z0U+yzNnWHMkacw/8V3hzxSn8LWEmXeTOoJOleVXwp3VvnnK
         ard+WsOeef4OnXnegYYS67GLFZ+z03janWEPYlX1fWstPrLt4R91I4QKsLlWwondXTHG
         c8AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZlrnEezOCUT1ix0Xl+aVqHdFO/eZBXlCAAph46us0To=;
        fh=eUQW7IhWDHChH74ax7Qu+GWbgAXuHHxgFdOHk9U0EvY=;
        b=PUw5i9uUJ1RSNzbavFoJW7wZs/Rm7eyQqIyWGs5sJ9wOAT3+WG1i+j1PtyVJpdlDPd
         YPZpIjvfCOIDlfKok35SLnqTLpTz9RLO4ZpTDPF6/IPV4hrIR0kpQVqubow3X4PDWfEV
         CC9sFHARNYuSCUKeqyQd1jk5eJL70EDnXCIujh//38a9o9LT1DSkx//pXHGv7YQM7YPq
         gjRnieRC1tFuASi5WKwIlaErWzf2OEQy9jlKneLEwQX8Als9hGlU3JXLXfMEL9aKE8uW
         fD0UxaGwtcIbNHiOSHpE3IJcH17jvk67S3HV7p6bi/YAGjQj4KjNZ3WWy15vQKt+C2Qq
         Yyng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XIppQUEf;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703160896; x=1703765696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZlrnEezOCUT1ix0Xl+aVqHdFO/eZBXlCAAph46us0To=;
        b=gfoEsmIUkFZhGzeRP1QJRePJ6INmGJxzWHJVrI3cCKU6H0Q3wrb3jYU67jzrvuaeN1
         96XwAw1qvQxZ1FqlCUgRD3evD2qnWLV1JdO8XBTvUC7pA559kquEfcEZb66YBnt8/Td0
         STCe0xHP7UZ2OOnd7PScr3VX2HnQUlX1BNqJdAIA7867Av0pqVY30WVUybzzubirMDdE
         G4qL/lWWoxxvxw1BVax6gxsXovqo72Hv7vvEm9XogLFHpbv09MH3JOIjR6JHvmptfVH8
         ac/tyUgk0rhKdg3E01oDCuNa9hb5IHxiP6JusJ2IeBScIzrQp7fMAImNBZSycV76lXpD
         WJIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703160896; x=1703765696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZlrnEezOCUT1ix0Xl+aVqHdFO/eZBXlCAAph46us0To=;
        b=CEk2TafkHJ+bMQ2oUbzdbhcmEXFcXnpmIXlcm4GYUe9WC/ajXRg9sIN0SBJsrVkhU7
         jXsVYy0P4jXj8SeP8Em3b8+u3zJ5MKjN/LyD5IMAdnmMWAoXcubfLXZzlaXMILEmly5S
         V5HGdohLOOmQ9DbhOvfm80aMy6hsw7ifaLaWLSW48rs0aTmsu9YmMi+kntQdzI1ONZ5v
         vCV4Pxmun4o7/XbJqQSsaF74LjSkbZASSIThmOrcM7QFJWN9TGPhmxiDuIwVwU99M7aM
         YG1ya5pRrBXr9xFm1DKP8gsXp0uhXopdz4nR7jtFr4J5Bo3w0qMjW+IVthR/LyiEjPCV
         XqMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyMulXY31w0ua3OA/63Ex6R9+Pb4/em/1HfAsUvxeYb3ItrrNNO
	Uef56B4ZCCQW+Dk5T3HTOsA=
X-Google-Smtp-Source: AGHT+IEwq3Fv+rT99ZKoHw4tpht6iw0pgsqIjfOOD8ADM+2VRh3Y7OtpHQzzpos/Rx9pEcTDWEiLNg==
X-Received: by 2002:a05:6820:2405:b0:593:ebff:5580 with SMTP id cp5-20020a056820240500b00593ebff5580mr3146723oob.3.1703160896451;
        Thu, 21 Dec 2023 04:14:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1687:b0:593:e866:45b4 with SMTP id
 bc7-20020a056820168700b00593e86645b4ls418544oob.2.-pod-prod-05-us; Thu, 21
 Dec 2023 04:14:55 -0800 (PST)
X-Received: by 2002:a05:6808:f0c:b0:3bb:7b75:dee9 with SMTP id m12-20020a0568080f0c00b003bb7b75dee9mr972090oiw.62.1703160895636;
        Thu, 21 Dec 2023 04:14:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703160895; cv=none;
        d=google.com; s=arc-20160816;
        b=OFqHiXYRjOuywgMOKrsq37qtM6doMy0v468/Nkqr847zjaJssi0r34On2tVs2rrJ6k
         MTbbF5Kh5zpvkVi0em7UWd+1Oh9skMJswrp6Fa87oeR95IpFvBlKe5VPM4yFDMXXf454
         LZ4aRGXjEpvxgFm5NViwZU5I8vU4Bpzj0sV+p0r7f7FyL57+nTmJzvs7vPfY9oP9O2cY
         4Np7pYITuYjNBKu+wixUfK+Ad0ENAqvHifCbmeTbWB2TrAFjHXNZNUYAM1CmiHihK2qm
         HP8LoQv1DkRJ0vWN+CSgkhaKJUVNMscH9CbHQTUznIAusoFWSqqvwP33gXX6eh0Is/5S
         HfyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WZOSdZ1fWVmBniRZaqNNU9+365ekrwzEre4sZEIZQFY=;
        fh=eUQW7IhWDHChH74ax7Qu+GWbgAXuHHxgFdOHk9U0EvY=;
        b=KitAdijNN5AHlj46NMZ7yM+i6c3VwdKb/GIsrd5qAzXMrFolvKFclTFohZpoJJx1MV
         0Oxmd1PYCA35aNi0ggwJImDmLzcFNqqYX0bOVokhC5WLM/73oC0gDQyFliOhpfXbXXP1
         zjsy05+77JU8L7vUohIQoSCp7wjza5C/WEBlZPJWZxMCS5pc1bMzW6lja6Y7FSW4JdCT
         LU7Uu1gIJamdf8O5kUPZhvyhonhmOUy9xyj8l6ltmougU3inSs9OyP3fGLXeOG0I/N79
         g1PzFKgCNZ6DbGcAWh0zlPDyQ6Q66lZHql3gPU9ldn42wW7vV1oYDqqQqQ8rqbCNwWFW
         J/3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XIppQUEf;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id bi6-20020a056808188600b003bb78f4f1b6si119712oib.1.2023.12.21.04.14.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Dec 2023 04:14:55 -0800 (PST)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BLC5C9d011325;
	Thu, 21 Dec 2023 12:14:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3v4j3fykrf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 21 Dec 2023 12:14:26 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BLBKEuH001091;
	Thu, 21 Dec 2023 12:14:25 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3v4j3fykqc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 21 Dec 2023 12:14:25 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BLB80DO012308;
	Thu, 21 Dec 2023 12:14:24 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3v1rx24abt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 21 Dec 2023 12:14:24 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BLCELCW19333772
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 21 Dec 2023 12:14:21 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8CFC520043;
	Thu, 21 Dec 2023 12:14:21 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1D09B2004B;
	Thu, 21 Dec 2023 12:14:20 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.57.36])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Thu, 21 Dec 2023 12:14:20 +0000 (GMT)
Date: Thu, 21 Dec 2023 13:14:17 +0100
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
Subject: Re: [PATCH v3 28/34] s390/mm: Define KMSAN metadata for vmalloc and
 modules
Message-ID: <ZYQsGbr7HlQjlJRs@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-29-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-29-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: gQs6F1yHCC4oP4FjDomkOokf6MZGQMPK
X-Proofpoint-ORIG-GUID: Ga5RPJKS0qpjMpHhRYad4Qum2jq5TvYL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-21_05,2023-12-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 spamscore=0
 priorityscore=1501 mlxlogscore=999 lowpriorityscore=0 bulkscore=0
 suspectscore=0 malwarescore=0 impostorscore=0 clxscore=1011 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312210091
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=XIppQUEf;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
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

On Thu, Dec 14, 2023 at 12:24:48AM +0100, Ilya Leoshkevich wrote:
> The pages for the KMSAN metadata associated with most kernel mappings
> are taken from memblock by the common code. However, vmalloc and module
> metadata needs to be defined by the architectures.
> 
> Be a little bit more careful than x86: allocate exactly MODULES_LEN
> for the module shadow and origins, and then take 2/3 of vmalloc for
> the vmalloc shadow and origins. This ensures that users passing small
> vmalloc= values on the command line do not cause module metadata
> collisions.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/boot/startup.c        |  8 ++++++++
>  arch/s390/include/asm/pgtable.h | 10 ++++++++++
>  2 files changed, 18 insertions(+)
> 
> diff --git a/arch/s390/boot/startup.c b/arch/s390/boot/startup.c
> index 8104e0e3d188..e37e7ffda430 100644
> --- a/arch/s390/boot/startup.c
> +++ b/arch/s390/boot/startup.c
> @@ -253,9 +253,17 @@ static unsigned long setup_kernel_memory_layout(void)
>  	MODULES_END = round_down(__abs_lowcore, _SEGMENT_SIZE);
>  	MODULES_VADDR = MODULES_END - MODULES_LEN;
>  	VMALLOC_END = MODULES_VADDR;
> +#ifdef CONFIG_KMSAN
> +	VMALLOC_END -= MODULES_LEN * 2;
> +#endif
>  
>  	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
>  	vmalloc_size = min(vmalloc_size, round_down(VMALLOC_END / 2, _REGION3_SIZE));

Since commit 2a65c6e1ad06 ("s390/boot: always align vmalloc area on segment boundary")
vmalloc_size is aligned on _SEGMENT_SIZE boundary.

> +#ifdef CONFIG_KMSAN
> +	/* take 2/3 of vmalloc area for KMSAN shadow and origins */
> +	vmalloc_size = round_down(vmalloc_size / 3, _REGION3_SIZE);

And thus, the alignment here should be _SEGMENT_SIZE as well.

> +	VMALLOC_END -= vmalloc_size * 2;
> +#endif
>  	VMALLOC_START = VMALLOC_END - vmalloc_size;
>  
>  	/* split remaining virtual space between 1:1 mapping & vmemmap array */

...

With the above fixup:
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZYQsGbr7HlQjlJRs%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
