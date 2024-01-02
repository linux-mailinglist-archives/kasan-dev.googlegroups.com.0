Return-Path: <kasan-dev+bncBCYL7PHBVABBBSOM2CWAMGQEQ6DRWNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id ACF06821E44
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 16:05:46 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-594a2fb0476sf7473879eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 07:05:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704207945; cv=pass;
        d=google.com; s=arc-20160816;
        b=xM9T4jKlCfVxSVF787+tnUhZZd5c9VkYgs3lkUaosZO2CLS3HVUS8Zl8l3877xA7Oa
         +WuJ8gvL1PfWiprYmYdi7aRVa4UizRUVXhT+fdwA1qwaIABuq4WhNAFWTZIXs3TCHDey
         y9jFKUmer/pdEh0zShKFNt/yPwG75qSzSnGknaEaNgmX8sdWqVKUtd3C4U/G2wsnwGcZ
         /EYq8oNxesRWJLuloNI22zhsZNyCFLFAsaCCTUQhDQZVwaV6trrA1gFQyrN5h/1CrVBa
         jsG60KLlE3UJvC6m4Or19Mufn5uXcREEkb7z/MRWttopQxVgBUojAl8cWsnP3PDdM7mf
         5xXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YORHNpCWNyoorIDjp1qvbo3u/2yHDIkpouJO08GBhSE=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=h3UWmS4VSIrHgybZx/bORS+T4fohJ5ZaMnenYKsehJQJQo9t9Pftb5N04XlqO611Q3
         WIJsDO1osuAit8PlaThuVBaQ62oaTtUGv64YF4kjKHgBMQZp1GlBGkfCfjt/HcgTNYV1
         fF0FdsbdYgsTnxvKuAJ6oMHgZo6OFIeeB1su2jCgAsh6qkNdr5KbstqH43YVZZP9zHlU
         ZZc75wYqudeJHeBTsZOiKsz2YAAl3nc5ho2AvoOgBABCOOYNPRvEOVXIs2DXxrTLBYI0
         sHAOPfYbzcRMBQVfz4icYH2m4YnB/rHGwzV6N/q6coX06pTDWOj9K41r4QbSlCVOnq5M
         5hgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ieo1go8j;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704207945; x=1704812745; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YORHNpCWNyoorIDjp1qvbo3u/2yHDIkpouJO08GBhSE=;
        b=kgWPVMcVMn72svriVPMwLFmdtqd8FAHSwOscCHRsztjXLG4Rm2Yz1lGT5XQ+7ILLmr
         p89gxzmvSbq76lEDaIU02yGqWLXe0YN85xcBB1uTT8ZHxrNmOoajy766lJvBmlo5uV9B
         nalaZrJgy19En2MEDzMu/nsMvTx5/RLLybtbm8kCWvUoh5P4TpnLkKB/uMy6YegQafZY
         DqcDLSwziEhN2pZnFhnj9WO2KEjEACI+PH5aZgSdjWZI0WDAx197nd+DJi7q4xGiHBMc
         PiheeumpeRG7ABKQWYbZm+YdyuCOu5UZrC+t9/9C1dwoB5+jIO2AX8z5tNSEY9HX1LfL
         M+IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704207945; x=1704812745;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YORHNpCWNyoorIDjp1qvbo3u/2yHDIkpouJO08GBhSE=;
        b=h1ckax+E9GZ2/xPDhZ06kYJq88Jto+lH/W606wSpzmJacB0vnk7u5jnzbAoKf3TMwD
         3tr4QXgSHbw7dn7PgKBw+Pk2oxlNvQsjjOAqzb3BeEPwW/TM5IbIKsBjBIDNs5aKne3i
         e3ag61sXbxKQ7ANli+iYwz+B4hPXHnFxkcJ/YObzScPwfD2B4LmuJWpm56+WNI1nixQG
         qAKfsrHBIwK8uwXTbb4+PHLU4GDzxHg/fZ/i/1b1wNM9E7nVdRepdau+38lMZrrE8eQG
         tAlBJsmUyo1AOoFkZOjrwkI0UZkN7bD6J+iRpJRBLt9YcoCIiB4SkrInn8yjjZ0jK/KT
         u6SA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxA6FcmoRFwtSVOH+wV+VzGxrPXm+WDLyxx0x2fE+RP1blFOnIW
	WMzmv/5mYyAAmFWc04tAaGw=
X-Google-Smtp-Source: AGHT+IFkL7+MP68WWC5ZeSN3wnz4eKHwibaOVQBD3dwZ/fIalLpVdFbSobvynBmFaOQ05huwncfozw==
X-Received: by 2002:a4a:8c2f:0:b0:595:27d5:4a01 with SMTP id u44-20020a4a8c2f000000b0059527d54a01mr2532792ooj.14.1704207945221;
        Tue, 02 Jan 2024 07:05:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1687:b0:58d:fb43:70a3 with SMTP id
 bc7-20020a056820168700b0058dfb4370a3ls3004555oob.1.-pod-prod-01-us; Tue, 02
 Jan 2024 07:05:44 -0800 (PST)
X-Received: by 2002:a9d:6d8e:0:b0:6db:fc2c:ba2f with SMTP id x14-20020a9d6d8e000000b006dbfc2cba2fmr7702037otp.0.1704207944355;
        Tue, 02 Jan 2024 07:05:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704207944; cv=none;
        d=google.com; s=arc-20160816;
        b=yYfUwJ6LjJPmBCpODOSZE8zK2hXD72l2yWMtgTJ8dURmT/kMddQ7QBOADsSNAXk5Ch
         /9wa60boJrl+5iWExC/6qsNzdB/Xlwa/JmKoiiVNep1MS1LDRBlqMXB3SE9fGc1k3W7o
         eldQjrRpZT9i0pUrPdJiMWBMEn0iyGf29AXLBFz/WW4QZ+gV+0zg1H0nS7nFdW+RRL31
         +kF1N4O02JEUGI5PDbLaaklWL521YMRE2kyxpM4CeErgaLijrfp6yS9AwqcIgR5XalkK
         POAR/tzEQNZTZ9e9iFhH1dxm3+UeTroa7oKNw7nmCZmFRzQcJCz/UfagTqtvrD+6g0IT
         4ZOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yAUmslGfmAn/v408/JnMAl0laE6kfhNSkhNgHmtKlnU=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=X2T+D3/d0Wm3ACBJUF7dgeeKeX52E/s5wswAZxGDLMGg5Fk73r2BaSe9CH758KIYQZ
         iX11z/9AO1iriBkveOco0THJoApPX7A/aCzxybypGSkxAztTiN90cONzrQdLSETEPf0G
         Suui9QlEnvQI/1nwKJF1gLibPdEdcTP3aEBArfdRm3lv7dX0apV3m0Wyez1A3QNdTrlU
         E7M27qwBxyMfvn/SbIV0r+UlSTMYyDPiA0gIYlz6dU1W5EUymuJNAm7A3Sr/rAaKlQAy
         jyXq/NS0+FvMQIoia603+/2yo+55WmHxxvLdjLoIuiIfQEUGyG2oKNfiXG8y6CXSmkQP
         4TTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ieo1go8j;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id r65-20020a81b344000000b005ee5e3c6d2fsi1144274ywh.1.2024.01.02.07.05.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 07:05:44 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402EQJ9x007842;
	Tue, 2 Jan 2024 15:05:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7s58-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:05:38 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402EurZf010225;
	Tue, 2 Jan 2024 15:05:38 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7s4t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:05:38 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402CNLmp017971;
	Tue, 2 Jan 2024 15:05:36 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vayrkd7fk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:05:36 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402F5Xi514680808
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 15:05:33 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A82E120043;
	Tue,  2 Jan 2024 15:05:33 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8E97820040;
	Tue,  2 Jan 2024 15:05:32 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 15:05:32 +0000 (GMT)
Date: Tue, 2 Jan 2024 16:05:31 +0100
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
Subject: Re: [PATCH v3 28/34] s390/mm: Define KMSAN metadata for vmalloc and
 modules
Message-ID: <20240102150531.6306-F-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-29-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-29-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Ha6_F5y1dtYwlryom_EL-MOezepsJYos
X-Proofpoint-ORIG-GUID: YUgncFyGNiUc-bIEjUnn1fILOqO8p_p-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 phishscore=0 lowpriorityscore=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 mlxlogscore=925 clxscore=1015 suspectscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020115
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ieo1go8j;       spf=pass (google.com:
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
> +#ifdef CONFIG_KMSAN
> +	/* take 2/3 of vmalloc area for KMSAN shadow and origins */
> +	vmalloc_size = round_down(vmalloc_size / 3, _REGION3_SIZE);
> +	VMALLOC_END -= vmalloc_size * 2;
> +#endif

Please use

	if (IS_ENABLED(CONFIG_KMSAN))

above, since this way we get more compile time checks.

> +#ifdef CONFIG_KMSAN
> +#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
> +#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
> +#define KMSAN_VMALLOC_ORIGIN_START (KMSAN_VMALLOC_SHADOW_START + \
> +				    KMSAN_VMALLOC_SIZE)
> +#define KMSAN_MODULES_SHADOW_START (KMSAN_VMALLOC_ORIGIN_START + \
> +				    KMSAN_VMALLOC_SIZE)

Long single lines for these, please :)

With that, and Alexander Gordeev's comments addressed:
Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102150531.6306-F-hca%40linux.ibm.com.
