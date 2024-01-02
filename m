Return-Path: <kasan-dev+bncBCYL7PHBVABBB2GQ2CWAMGQEKBMQDOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B24B9821E7D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 16:14:49 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6d87bcf8a15sf13041861a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 07:14:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704208488; cv=pass;
        d=google.com; s=arc-20160816;
        b=KuIhTpOmWunKZ91owf58oaj8/0tZQ6LYCjPsbBNiTG0lXCir3pmlsylSN8YcdqsLYb
         bItzaCFDz4lznzyudpGLV9Bwjl7DjSA2JaY9qHbejpMFKK7E0Nxpj4lTAAipVOGlnBxk
         odFiRniyWGG3ZdFJCMDgTzA1y7WSP6YqA1O6W66wcaxw70SpLcbP9DKIJdi6wJqwRHzj
         8JcUzpVHOcJXNRuU4oqHG/5Nx6haIg/5Jyo1oj6ck9r2267EmJH/MiorAupKy84+PMek
         hKIhBvcKmP7b97+GRQEYYOxI526C0wvfqZO9WRHD/8BGKEkgmOtQos8zvx/J72B3xj7m
         ng0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cE+yQvljnZZXKRJ4opEFrilQy3EYh/9dhpdyhTs5CZU=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=AWWGLigxHrdjshoGAA3KP2g5iFPAwFnDM/WNP5A5sxzaX3zQ0Gy9HG5pwO1zsie0xF
         H/pbv/Vdp9fhJvtsgEdNWSXfsOP9PEDvoBookA+jSG+K61B1rObyMCgRJ1Ut+XWzgdrf
         +FpK8y5nAAabpjilF3StEyMK3Gn2p+23NkyRxCj3jf7vLmbmvU5xk2SQgrs0HTAiciv2
         fPWZ6KUpMsTJZ89jL+FgmEyVajJOUb6ZaGdBU1eOOjxsiLXpRyhajmkd1U96nhr+jj+P
         3qpEHS17q012C0GCZ1SPjEL1Ez/yf9h8rhqR8gKbwuv1Xucc0Wqo5tGjJk7syBsgcQER
         3POw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Zq3EYYWP;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704208488; x=1704813288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cE+yQvljnZZXKRJ4opEFrilQy3EYh/9dhpdyhTs5CZU=;
        b=PX62egXiSPvWoxCSVPyAz6liptbOIa5RpJSjcGPJxrpq7Si3tG+A6g23M6kKgsI4ZF
         2iYWltw4DFpk02STSWWSaxxwzib7KCzQKJLWpGk9KpTGo2lXR3HZpEVwC9HWBuSJ2suA
         4YjCldHyItQwvzo2OYh1YdoFiuKM23xA8EDxAi+vdoYGBbBv3PQY23zatvLtzTlCPqjr
         3F7ziZ8W9exgZaat/VeJ4qdWwqY8iB3N2AHUm9hzI6OnCLAKZCcs2F2pfgKXwnEM8QJh
         aznxiHdcrWPfQcPM7BGDhTgMb3oAyG5wMAFUeNi94g2xN7RM10+Cu+Thg1ttGdp8ki70
         4ifA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704208488; x=1704813288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cE+yQvljnZZXKRJ4opEFrilQy3EYh/9dhpdyhTs5CZU=;
        b=IkkIIZWCv4vT6yQPiz4aJKaVo4GkHGmNQyCAjNNVBjasG4mkV2xjb99oVzONp19VsC
         F80zaDWyxzNEJlme9j3nWd5wv2dtOs8DHrRCm0yDdPS1C+4foT98TJSkgS6DcjmCfXqM
         ld/E2W5qrrDRG/GgeHJEGbbALTWYD2bJgwsGqS8zkOo1Q77/ir5Pk6kZcdnUqkThyXfF
         uwhzjZSY+v/hGJM7EaQXfogFKsHXfDrYzBUaqCj6VI5x65xbdAgdVUt4yKvYFfRBuPME
         ivmOd4nw0VU4eaiaUPDeijqZTz+0A6nBxv2wOIRvdwRf0UoyPisihKG2cFzOZOWng7CH
         VXpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyHpcJ+8ZoJ9qWOxwd+j5qer1rGNw/rEdsQnv3PaLdVbQFZybBX
	OWbmzcVeCzMozHgRkp1HCquORQ==
X-Google-Smtp-Source: AGHT+IFw66K/OLesn6vD1zHQ2Uty/q3rLMo10MPDpczE613qvpOzj4LDhQQHBs2wASo2eOTo2hxARQ==
X-Received: by 2002:a9d:73d5:0:b0:6dc:386b:7270 with SMTP id m21-20020a9d73d5000000b006dc386b7270mr4824205otk.72.1704208488403;
        Tue, 02 Jan 2024 07:14:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:170c:b0:6da:83a2:1e56 with SMTP id
 h12-20020a056a00170c00b006da83a21e56ls244387pfc.0.-pod-prod-09-us; Tue, 02
 Jan 2024 07:14:47 -0800 (PST)
X-Received: by 2002:a17:90a:2c0e:b0:28b:77db:f84 with SMTP id m14-20020a17090a2c0e00b0028b77db0f84mr5847493pjd.94.1704208487343;
        Tue, 02 Jan 2024 07:14:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704208487; cv=none;
        d=google.com; s=arc-20160816;
        b=gMiYqjVRmCJStWBgoJXCU7rbKFK1vxlV/eYbuB5zBsdhf+hhh9n4QoxIO/z/jfRjP1
         ShkZCRA47MvKRXeWJzqZpUMaMf1cJPslUNRR/2mNRLsPf1YPAxYo5sBwKnuKZZ75iwLH
         +AooPgGLPOY6ubVXkel3KNnL/0T7LxfbyJ8xa74SLQcIrJnIOzoE6G5ZbfHb5PvhAi+k
         28xTqHjrEylcfX299/bo7kIWFwCODvusssddix9edx34yH4SRqwohzMTqOvp0aCiLci1
         2kjTmb+y5hTahZfk9cFYFhXKmy1hKRKJtyvEQopDLFzQDn4UM1FNkX1o5Z+VtsQk3R9B
         1l9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1BKcmG2jscOIY6lh3Br6/Mb1pJ/Vi1UOVkNOh1YtQSc=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=XjxC3uwRqprBF+e9Q+1UO4lzHlU9tG0IXvDmuuWpochCo73vjZKA0lpQuuB9GgPZ1d
         +eqONOYvW8eyTnyZpVsMdoC9UM44MUs1UL9HNPBCFSXNS3UsVARX1ed7VnswlvzB6ihA
         fWjFCfyeBSderwk5e0DFV6cdEX+oO5CdmS9BivXxi0RxAhXYg6VT0tLt5+XzcmXFrpbe
         tP5/+MlKnLNbVqeBv6JeV69BAN8Kfon+NxzncY+ciS7f1N6wlG094Jd48z09w0Z7DC0j
         MPnTaxzotGcoWB3GRnKBN9jENlWZeEoPuXfJEf0EQdcx9/Ofou6IafLsnmOjKFmPfIZ2
         WXaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Zq3EYYWP;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id v7-20020a17090a898700b0028c94eef0bdsi675784pjn.1.2024.01.02.07.14.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 07:14:47 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402CiIn7000998;
	Tue, 2 Jan 2024 15:14:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7wws-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:14:42 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402F7f8f024070;
	Tue, 2 Jan 2024 15:14:41 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7w1d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:14:41 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402F193C019167;
	Tue, 2 Jan 2024 15:06:02 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vayrkd7h1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:06:02 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402F5xup42336898
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 15:05:59 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 733B920040;
	Tue,  2 Jan 2024 15:05:59 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6701720043;
	Tue,  2 Jan 2024 15:05:58 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 15:05:58 +0000 (GMT)
Date: Tue, 2 Jan 2024 16:05:57 +0100
From: Heiko Carstens <hca@linux.ibm.com>
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: Re: [PATCH v3 29/34] s390/string: Add KMSAN support
Message-ID: <20240102150557.6306-G-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-30-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-30-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: O5QiWeQIJAvGTp7EVYQbU-a0u6juWUh_
X-Proofpoint-ORIG-GUID: aPmHxOhkMHaWwlCr-kgZMDd0ueILkEpz
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 phishscore=0 lowpriorityscore=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 mlxlogscore=910 clxscore=1015 suspectscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020117
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Zq3EYYWP;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
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

On Thu, Dec 14, 2023 at 12:24:49AM +0100, Ilya Leoshkevich wrote:
> Add KMSAN support for the s390 implementations of the string functions.
> Do this similar to how it's already done for KASAN, except that the
> optimized memset{16,32,64}() functions need to be disabled: it's
> important for KMSAN to know that they initialized something.
> 
> The way boot code is built with regard to string functions is
> problematic, since most files think it's configured with sanitizers,
> but boot/string.c doesn't. This creates various problems with the
> memset64() definitions, depending on whether the code is built with
> sanitizers or fortify. This should probably be streamlined, but in the
> meantime resolve the issues by introducing the IN_BOOT_STRING_C macro,
> similar to the existing IN_ARCH_STRING_C macro.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/boot/string.c        | 16 ++++++++++++++++
>  arch/s390/include/asm/string.h | 20 +++++++++++++++-----
>  2 files changed, 31 insertions(+), 5 deletions(-)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102150557.6306-G-hca%40linux.ibm.com.
