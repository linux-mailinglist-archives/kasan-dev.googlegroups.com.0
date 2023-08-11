Return-Path: <kasan-dev+bncBAABBS7W3CTAMGQESDZIQIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 739287790F2
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 15:44:45 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-349a322589csf2781315ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 06:44:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691761484; cv=pass;
        d=google.com; s=arc-20160816;
        b=s5FuDM0f8W2hvHJhrZYdziL58mbOU4oelOIzS3yo2FsMLAEAC1owpzpnoo51u2bIWa
         QQDRGdGMB9SNMUvAZvgzD+CNvrzq2f7tGsNdrhpUiBxECxkn31u/Gia+/dWiACaYcUDg
         kbMlozEvMNBqgsP2IMYi/qDZfLb3R+eyjYo/+TbYsJOippIGnRewdxt6M2qzFX8QlEEk
         siHj4w/pYfdhecTdW5aQABmUaiqzIVWqHup4+XOKNujpxwg38ZAGwws9HA3LMdm48Tfl
         tSuA7IB+8Xr0FWImmYaEGoOEchUI09Qr/VyLnYMPhmqgxHs6Q+INr08gcfRQSUS07ao7
         8Psg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dH6XdEpDjYTuG0lZOJsNOlS/s7WkLeIUDR7tSk5bbEY=;
        fh=cNj4+sEwHTCsbOqHNet+QnLeafJ2N9QqIMtjVwe7lAo=;
        b=FdQbx+Hd30zeEJT2S2S5R7+jn+50nljTK8PTnNBLYtmhjqBJwJur9WGTWnDyrZT+kS
         BDg+TiSzGWME5gJ5IuWdjihGgUKJkmuf+eiSyz3NPMgQzqEANPGwq7ElgwpXKXebeVB4
         MX+SAk/LLOjlrytI08yZwMbvtuHvbr4mgayfos9XsxBDrZV62ePyIq+b6Wn0/R4Cw9pD
         49MxeC6TUMbqR+mEXOWNWSa3fUIUyY+0eLOkEeyup3g7uA4Lm9OSV5y3SZpABP5PSMtm
         6mvIY0NXIJrMuK6W9Gr5aL0XR75emoh2zW8WFXetVDzpJGuACMJH0dJv5+cqsSmiTZuf
         t3pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GKykM6wj;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691761484; x=1692366284;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dH6XdEpDjYTuG0lZOJsNOlS/s7WkLeIUDR7tSk5bbEY=;
        b=ro9XR9GD2wX2XJq3z6HH+2wMYEXDWbf9VBQxUrmN1IYzeEv/GorUwqVp6tofDR/LMK
         RyfmXn2ns3SWvSZEOeCUriFej7czmI9j3RjyCMMKZi3YBHd6byilcM3Bo62TRHYtVefK
         D9tuwi/Bj3GSatL6V7u6RTSj4w1aDV368ZefVYYwOAe1oL+ff8aaHpAFAdkcYSiJI7f6
         s8iLLp4O/uvvHXJe73NMES+MTvpyGLij9QKlEjI8HVm3uddDd6FFpJgGnAqS17T8p5xi
         Y5EU7FLK2RMA3AQzXTdWu31NGpsQsIuzJcLcuoyJHxWXt1s8zZkqFiAKkrxgdRrTSo9f
         PBDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691761484; x=1692366284;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dH6XdEpDjYTuG0lZOJsNOlS/s7WkLeIUDR7tSk5bbEY=;
        b=FdhO7ts3lmspfVb+zQ4K9dx/Y872+rUwQiaj97KwAx+05atHawGP5FNoUrdPOllSoY
         OrniK5KhQSbwHg8NIK86WesmjG32VcxzidfKBpvzBgdbyMJffm/r5OwBINNNTNsJCpET
         z81jMLC2rw5s3x3b1m+EhjtT8811P8FjR4a4axDmknJUPI88cnF5wirXBuqeb1s2Le8r
         Ji3KnQIDnx6vjMq2iREyOMs5B4thQlPE4h5SO+iwdeFji0jfJownuir4HQEXG10Peaam
         kkmF0mxMFGPvks+Dltdqqexysl0B++eq/yRtj3gGHBFoPP/fGFCJ6kkq0Q9P/ueidgpf
         zUUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YztC7Xca97PXvkEdVazAXCTInQIzovtqlNKwcopgItM0mPOUZEN
	nWp/QBRZokIBDMzPwdmmVLE=
X-Google-Smtp-Source: AGHT+IGXXrMPi7PgxAIosu3MAqLJOYpy590BhMm0E4H5ptQRfnCC0thyN/MuL54GuHXGTLt/M86tlw==
X-Received: by 2002:a05:6e02:1a6f:b0:349:2d61:8631 with SMTP id w15-20020a056e021a6f00b003492d618631mr2610983ilv.10.1691761484003;
        Fri, 11 Aug 2023 06:44:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:940a:0:b0:33b:7f21:7d7e with SMTP id c10-20020a92940a000000b0033b7f217d7els890215ili.0.-pod-prod-09-us;
 Fri, 11 Aug 2023 06:44:43 -0700 (PDT)
X-Received: by 2002:a05:6e02:f83:b0:348:fc48:6d00 with SMTP id v3-20020a056e020f8300b00348fc486d00mr1983891ilo.12.1691761483317;
        Fri, 11 Aug 2023 06:44:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691761483; cv=none;
        d=google.com; s=arc-20160816;
        b=UHExLMnfzyr6hnBt/RIXY4A9vHcHRIUWxXrDDawdf5bX8FrOu6RUXHAKCvhBoBgRqs
         47UBcf2Zdd3I1xGPqQDlfMNDxBf1whQVNc8aJPIyhTEYYm2OZhc7PyfPNfpjYbIL109p
         mNVwiGA07PdsXSWxeG4YYylZr0YtL3qUt91KwbhpgJpWuu2AORlab+8u3CnVMLGa8mkZ
         6Aq87pr45+DfnGwXnmfVd9qmQyti8mtlrQl5U1R6QYnAi0JO3133wJn+XiHy0GXtXlhu
         uwRMNgygYGZq8+81Tzd5NVjNQt5U2qOQOd8YauaEGEV/Sftf1t/cuxaGiTxfhjxIWjxD
         3/ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=m1adlM4yJTuLnY0I9nU2ueYapM266OdGoygH2JXlcao=;
        fh=cNj4+sEwHTCsbOqHNet+QnLeafJ2N9QqIMtjVwe7lAo=;
        b=y2EqDf79UUqEzU/D01yQ/S71Plq4ExRQ+RgfjE4FsOobIgvkD7NpqI84zA6TnbI0F/
         o2xtFAwEnOUfOnGHejt2aqBpgYy0eKAMSLoDZ/zd1Y5jM7KrWJ/E6Lc4UZLDnkvflrYG
         CjGoH6qycsC/TDWuLLq4TwZKJUugKl8cRJXmVOMNYj9ko49TlBpSXXmMnROgnFppvDzF
         T3dIa/DvHhdEfnrRk1N76SzrfO5mjxr/jPZqTn7lo+vqqvZ4HUz8Q3qAoekhdhbDl+OP
         yxVlukLtSDKHcxC3X10ERTcvs4Tdjg2CA8wOxxg4Z25dUz7VHs4/5WsR4jZvVeObTRLY
         rnOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GKykM6wj;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id k4-20020a056e02134400b003497967ed88si321974ilr.4.2023.08.11.06.44.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Aug 2023 06:44:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 37BDgIxv022559;
	Fri, 11 Aug 2023 13:44:38 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sdp3u81uy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 11 Aug 2023 13:44:38 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 37BDgVRx022953;
	Fri, 11 Aug 2023 13:44:38 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3sdp3u81u7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 11 Aug 2023 13:44:37 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 37BCMwPA006408;
	Fri, 11 Aug 2023 13:44:36 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3sd2evger8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 11 Aug 2023 13:44:36 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 37BDiXmw23790082
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 11 Aug 2023 13:44:33 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5D8AB2004D;
	Fri, 11 Aug 2023 13:44:33 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7093F20049;
	Fri, 11 Aug 2023 13:44:32 +0000 (GMT)
Received: from li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com (unknown [9.171.86.49])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Fri, 11 Aug 2023 13:44:32 +0000 (GMT)
Date: Fri, 11 Aug 2023 15:44:30 +0200
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
Subject: Re: [PATCH] s390/mm: Make virt_to_pfn() a static inline
Message-ID: <ZNY7PvtP0jI1/xF1@li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com>
References: <20230811-virt-to-phys-s390-v1-1-b661426ca9cd@linaro.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230811-virt-to-phys-s390-v1-1-b661426ca9cd@linaro.org>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: LVnEtS8ybxpv_rVUz-0TCfkkUxNaRY7n
X-Proofpoint-GUID: 72TIciiGjblkNZ614wNTIQ-CHKtiP1pC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.267,Aquarius:18.0.957,Hydra:6.0.591,FMLib:17.11.176.26
 definitions=2023-08-11_05,2023-08-10_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 bulkscore=0
 impostorscore=0 clxscore=1011 lowpriorityscore=0 priorityscore=1501
 mlxscore=0 phishscore=0 malwarescore=0 spamscore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2306200000 definitions=main-2308110124
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=GKykM6wj;       spf=pass (google.com:
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

On Fri, Aug 11, 2023 at 09:02:47AM +0200, Linus Walleij wrote:
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

Funnily enough, except drivers/s390/char/vmcp.c none of affected
code pieces below is an offender. But anyway, to me it looks like
a nice improvement.

> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
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
> index 4cebfaaa22b4..f66906da83c4 100644
> --- a/drivers/s390/char/vmcp.c
> +++ b/drivers/s390/char/vmcp.c
> @@ -89,7 +89,7 @@ static void vmcp_response_free(struct vmcp_session *session)
>  	order = get_order(session->bufsize);
>  	nr_pages = ALIGN(session->bufsize, PAGE_SIZE) >> PAGE_SHIFT;
>  	if (session->cma_alloc) {
> -		page = virt_to_page((unsigned long)session->response);
> +		page = virt_to_page((void *)session->response);

The cast to (void *) is extra, if I read your commit message
correctly: "...makes the contract of a passing a pointer of that
type to the function explicit..."

>  		cma_release(vmcp_cma, page, nr_pages);
>  		session->cma_alloc = 0;
>  	} else {
> 
> ---
> base-commit: 06c2afb862f9da8dc5efa4b6076a0e48c3fbaaa5
> change-id: 20230809-virt-to-phys-s390-2fa3d38b8855

Thanks, Linus!

> Best regards,
> -- 
> Linus Walleij <linus.walleij@linaro.org>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNY7PvtP0jI1/xF1%40li-008a6a4c-3549-11b2-a85c-c5cc2836eea2.ibm.com.
