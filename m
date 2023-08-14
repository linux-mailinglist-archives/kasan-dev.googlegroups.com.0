Return-Path: <kasan-dev+bncBAABBZGT5CTAMGQEP463NTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EAF677B99A
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 15:19:34 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-40ff56e1c97sf744941cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 06:19:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692019173; cv=pass;
        d=google.com; s=arc-20160816;
        b=yIY/XA3flpcw+U+s66juT1F3p6UI+vd6YZfsQpk0rqOvC5qXVy1oHFVKuzBpyHekPw
         x74e2teOnMlOIHF++hOZoPDTyzmUivtySoxjR/qSyTFN+TeBUeq3hZAuM7+kGgtcWfNZ
         UgLWXX2h5Te6sTqtzOWCm1U0IaUXdS8eN6BWYjU4RJoXayXMpJZKBa6H7h5L1cBHC6QE
         ZWYQm3C58pYPyjUkdPTBWGTmHjRVTEDsWMojzFlyQwcqYtezFkig5ncuOKxwhBxh49QK
         Lsv3wdyVL2rzB2ytEoAxsFq2xizDLsxP7yYtkh7uzUNhCxEuwOGYZ0kBkYoZf/8U9DGd
         DITg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=XzI22pn8+Znf0cGniQtX8fx1EypDCHm9PQuPKCD1lMs=;
        fh=cNj4+sEwHTCsbOqHNet+QnLeafJ2N9QqIMtjVwe7lAo=;
        b=tYfXVAdrMfPJ6B5VzjooPOoj2lOZPFZ7ChWU8+53E5zAIjeXo/jre8lFbfJ6rmrfYl
         XCFnXOec3DWySbPapKAsQKo9JsatWc2QFauyLVLAwLhhHoNDEOq8LoNCS+aJMZbY7tWu
         sJWI50gDrkPgTUrptWKlX9qsfLYBXQvbgRJ4rlLHQ1KCJ19qEAiNOh5Pm24pK3yaa+DO
         XfY3+cEO0+9zHbh9r6ZT4f9iuOJjIt+ADUG5Tz867ELFskS3fL4T6cACwYCL+YVV/Foi
         WqoNCRUBgXg/5r6LEBWH2AB9RC+mLlXcUD7rZyDbNR2j3VEuVJNXvRpGeZTwmYU0vDDL
         ixCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fw8DfJia;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692019173; x=1692623973;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XzI22pn8+Znf0cGniQtX8fx1EypDCHm9PQuPKCD1lMs=;
        b=mxDeJd03Dyk95yF69s/7JusX9ugy1xzAqIcZLpsNdZKMe5BIu4yrQ1CACP17ZnrRUi
         qIzo119i/WRS7C4+DNzk6F80xRSjYVx/AlRwCI8Xc2MwHqX2wiZrq4yenHRV223ofUnZ
         Vj8aUXFkqMsghtJB9Sb9oYj9BzXbhx7yVwS6kewh2QD2LOSb5sDYGmf8uPZ5D1DNQuUX
         Oe+TlJLCU6+XnPFct1SQmzzBzqWI4QBBq+MKiAVv7bunm4K8OCnr2cvtKVKs3BqlA9FX
         tIVKKVpOsSDYCxJB0+SsGHoubTknq+j7TzdjPavrHHCAF6PIfVun9Mj4NgsriL5oKaJ0
         DIZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692019173; x=1692623973;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=XzI22pn8+Znf0cGniQtX8fx1EypDCHm9PQuPKCD1lMs=;
        b=TNlzNwo5LBBHu0BFg7Q2zrbXnZT4tTTdyR34qX1fFQSX9YK3fgx72ZzdjWuJW2v5Ru
         qcbBvHrN/+5o0Bq2QQn+GTLZ9s7KbnwllFawkEEHcG2o4K7T2OYfSQm0jNpOWJrh9AmA
         IyNVNnxwrrvsDGNn1zxBW/t60ygRsgbg7UZhdkv3xcKUpbRQZLK0aNS3We47+2QWBtRT
         araRbNxjJ0nTkn3gGBBz0JBu2gewlCPJXmfRYv/u6S3O3J4IVAwT/faMDisH3uVPSH6/
         YqQvarhh7OOU/+3BUw8HaMJNtb1BcaHIesHoCvXdnPNh/a4f/6rETPio04b1entkkjTG
         lQnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw8D5/+GweP2G/o4Q/BOLpT54lLmF2oxzn5k5iaUtpGN6WEkld9
	LeoEhT3Ou8hePkbcPoKWlno=
X-Google-Smtp-Source: AGHT+IHDEujIQ+l9Q4Z/cEMiqzJLTa2IvMzeIFm6AiVIM7Xt+QhyqkP0RvX1KgnEnC4d71TYCuG2ug==
X-Received: by 2002:a05:622a:245:b0:403:b1e5:bcae with SMTP id c5-20020a05622a024500b00403b1e5bcaemr560954qtx.10.1692019172810;
        Mon, 14 Aug 2023 06:19:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:474d:0:b0:40e:c8af:ea87 with SMTP id k13-20020ac8474d000000b0040ec8afea87ls1741325qtp.0.-pod-prod-01-us;
 Mon, 14 Aug 2023 06:19:32 -0700 (PDT)
X-Received: by 2002:a05:620a:28c7:b0:76d:2817:5006 with SMTP id l7-20020a05620a28c700b0076d28175006mr13552947qkp.18.1692019172161;
        Mon, 14 Aug 2023 06:19:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692019172; cv=none;
        d=google.com; s=arc-20160816;
        b=hegEHx2ZjIo+sI92qqXYEE07EtLUPBVdFR22T8DAWE4dLkxYd+d+0hWe0pvikWQXPO
         dgxzIifsVsm1dN25Mg057CpgSdeWEw2O4/Vwx7h8LLBMyijFi89D+zdLMneSaZT8XVdi
         ijks2AU8QLf4ymqztjswWs634pF1a37jnZHH8i9TUOsgWKwoACICmBX20QENoUv0P/Me
         JOgauMwVgFfe32/5mCeRo8V84X1zy5b4fxMUrWhh00g9nHkqSAF34zYB8ycZeg7u2UH0
         e0nnYJWV7N+pTYHoBYWF1OGldAazA/xOBAj78eW7P1fZrhsMUbReXZnUZVbyMY1YSlAT
         E61w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ivlxHGJUa5WEXVDIeqbk7IOfO8a4tLrJjax9uvT8zR4=;
        fh=cNj4+sEwHTCsbOqHNet+QnLeafJ2N9QqIMtjVwe7lAo=;
        b=wLYjAoheTP9S7urGBu3NGbi7NulvfPsFSoHO6M1XRb+KzfXxAQZUbBFuTEXpDofNQG
         l0RdZ/aTDAjj52tjZhFjsNHvXwtWZfQYwmvDOuWQLAdEUOm+edFiWKd+7aR6OdFraCOJ
         4em0PVs+oXHvJfMr3/bxXt5HbKEom4j7dF0hZZ3+xt+NTm7HXsmB/DdavfS2aWXcFCWg
         S0lyJZ0M4vNlhvNse1CS7jNYujghgNLoFJZByeAFkB8eCdO6RvJ75LVXC2aKtoN8bWyQ
         7i6UcrJ+1TnU3fXmFS5ZKLW7yLHxcYmPNvBV4VNwrQyOlKs+dCcnOJRGCmX1/MxCr2YK
         qqiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fw8DfJia;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id qt11-20020a05620a8a0b00b0076989bfc79fsi496617qkn.1.2023.08.14.06.19.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 14 Aug 2023 06:19:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 37ED8CGN013635;
	Mon, 14 Aug 2023 13:19:27 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sfm9q1d1r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Aug 2023 13:19:26 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 37ED8cJg016113;
	Mon, 14 Aug 2023 13:19:26 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sfm9q1d1a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Aug 2023 13:19:26 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 37EBZWeM003456;
	Mon, 14 Aug 2023 13:19:25 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3semds4yft-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 14 Aug 2023 13:19:25 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 37EDJM8P28508824
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 14 Aug 2023 13:19:22 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4FD8820043;
	Mon, 14 Aug 2023 13:19:22 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 77FF52004B;
	Mon, 14 Aug 2023 13:19:21 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.86.49])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 14 Aug 2023 13:19:21 +0000 (GMT)
Date: Mon, 14 Aug 2023 15:19:19 +0200
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Heiko Carstens <hca@linux.ibm.com>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        Gerald Schaefer <gerald.schaefer@linux.ibm.com>,
        Vineeth Vijayan <vneethv@linux.ibm.com>, kasan-dev@googlegroups.com,
        linux-s390@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] s390/mm: Make virt_to_pfn() a static inline
Message-ID: <ZNop13CA5+UaTj2/@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20230812-virt-to-phys-s390-v2-1-6c40f31fe36f@linaro.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230812-virt-to-phys-s390-v2-1-6c40f31fe36f@linaro.org>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: m3DGSqVCAnVGUrNSKh9ZydrDFzK1ElzK
X-Proofpoint-ORIG-GUID: B3t5oLeNKn44h2L0Xd7DarOZcjKUaHLo
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.267,Aquarius:18.0.957,Hydra:6.0.591,FMLib:17.11.176.26
 definitions=2023-08-14_09,2023-08-10_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 adultscore=0 lowpriorityscore=0 mlxlogscore=999
 impostorscore=0 bulkscore=0 spamscore=0 phishscore=0 priorityscore=1501
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2306200000 definitions=main-2308140121
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fw8DfJia;       spf=pass (google.com:
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
> 
> diff --git a/arch/s390/include/asm/kfence.h b/arch/s390/include/asm/kfence.h
> index d55ba878378b..e47fd8cbe701 100644
> --- a/arch/s390/include/asm/kfence.h
> +++ b/arch/s390/include/asm/kfence.h
> @@ -35,7 +35,7 @@ static __always_inline void kfence_split_mapping(void)
>  
>  static inline bool kfence_protect_page(unsigned long addr, bool protect)
>  {
> -	__kernel_map_pages(virt_to_page(addr), 1, !protect);
> +	__kernel_map_pages(virt_to_page((void *)addr), 1, !protect);
>  	return true;
>  }
>  
> diff --git a/arch/s390/include/asm/page.h b/arch/s390/include/asm/page.h
> index a9c138fcd2ad..cfec0743314e 100644
> --- a/arch/s390/include/asm/page.h
> +++ b/arch/s390/include/asm/page.h
> @@ -191,8 +191,16 @@ int arch_make_page_accessible(struct page *page);
>  #define phys_to_page(phys)	pfn_to_page(phys_to_pfn(phys))
>  #define page_to_phys(page)	pfn_to_phys(page_to_pfn(page))
>  
> -#define pfn_to_virt(pfn)	__va(pfn_to_phys(pfn))
> -#define virt_to_pfn(kaddr)	(phys_to_pfn(__pa(kaddr)))
> +static inline void *pfn_to_virt(unsigned long pfn)
> +{
> +	return __va(pfn_to_phys(pfn));
> +}
> +
> +static inline unsigned long virt_to_pfn(const void *kaddr)
> +{
> +	return phys_to_pfn(__pa(kaddr));
> +}
> +
>  #define pfn_to_kaddr(pfn)	pfn_to_virt(pfn)
>  
>  #define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
> diff --git a/arch/s390/mm/cmm.c b/arch/s390/mm/cmm.c
> index 5300c6867d5e..f47515313226 100644
> --- a/arch/s390/mm/cmm.c
> +++ b/arch/s390/mm/cmm.c
> @@ -90,7 +90,7 @@ static long cmm_alloc_pages(long nr, long *counter,
>  			} else
>  				free_page((unsigned long) npa);
>  		}
> -		diag10_range(virt_to_pfn(addr), 1);
> +		diag10_range(virt_to_pfn((void *)addr), 1);
>  		pa->pages[pa->index++] = addr;
>  		(*counter)++;
>  		spin_unlock(&cmm_lock);
> diff --git a/arch/s390/mm/vmem.c b/arch/s390/mm/vmem.c
> index b26649233d12..30cd6e1be10d 100644
> --- a/arch/s390/mm/vmem.c
> +++ b/arch/s390/mm/vmem.c
> @@ -36,7 +36,7 @@ static void vmem_free_pages(unsigned long addr, int order)
>  {
>  	/* We don't expect boot memory to be removed ever. */
>  	if (!slab_is_available() ||
> -	    WARN_ON_ONCE(PageReserved(virt_to_page(addr))))
> +	    WARN_ON_ONCE(PageReserved(virt_to_page((void *)addr))))
>  		return;
>  	free_pages(addr, order);
>  }
> diff --git a/drivers/s390/block/scm_blk.c b/drivers/s390/block/scm_blk.c
> index 0c1df1d5f1ac..3a9cc8a4a230 100644
> --- a/drivers/s390/block/scm_blk.c
> +++ b/drivers/s390/block/scm_blk.c
> @@ -134,7 +134,7 @@ static void scm_request_done(struct scm_request *scmrq)
>  
>  		if ((msb->flags & MSB_FLAG_IDA) && aidaw &&
>  		    IS_ALIGNED(aidaw, PAGE_SIZE))
> -			mempool_free(virt_to_page(aidaw), aidaw_pool);
> +			mempool_free(virt_to_page((void *)aidaw), aidaw_pool);
>  	}
>  
>  	spin_lock_irqsave(&list_lock, flags);
> diff --git a/drivers/s390/char/vmcp.c b/drivers/s390/char/vmcp.c
> index 4cebfaaa22b4..eb0520a9d4af 100644
> --- a/drivers/s390/char/vmcp.c
> +++ b/drivers/s390/char/vmcp.c
> @@ -89,7 +89,7 @@ static void vmcp_response_free(struct vmcp_session *session)
>  	order = get_order(session->bufsize);
>  	nr_pages = ALIGN(session->bufsize, PAGE_SIZE) >> PAGE_SHIFT;
>  	if (session->cma_alloc) {
> -		page = virt_to_page((unsigned long)session->response);
> +		page = virt_to_page(session->response);
>  		cma_release(vmcp_cma, page, nr_pages);
>  		session->cma_alloc = 0;
>  	} else {
> 
> ---
> base-commit: 06c2afb862f9da8dc5efa4b6076a0e48c3fbaaa5
> change-id: 20230809-virt-to-phys-s390-2fa3d38b8855

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>

> Best regards,
> -- 
> Linus Walleij <linus.walleij@linaro.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNop13CA5%2BUaTj2/%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
