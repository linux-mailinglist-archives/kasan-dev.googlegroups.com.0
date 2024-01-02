Return-Path: <kasan-dev+bncBCYL7PHBVABBB7OQ2CWAMGQE5DK52LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E8774821E7F
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 16:15:10 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-3bc20d3baf8sf151585b6e.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 07:15:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704208510; cv=pass;
        d=google.com; s=arc-20160816;
        b=cLIl8I3wwHAwAXsS3pOLe9p6lnO0bM3hIW8p+mjueV5lBaNo4PcO7FDzSXvk6Yw+Qz
         xeiRj2CyUxfId9A5SyYhxL7hygxt7GLSG41uePSrRDinEpXxIjub6znktmFwcDW8HoUj
         4vHLLCF9EC8UkHDs6Jyi+u+tH1Xg/6keiFjQnn0CyA8v+zVPqX81mqIQ+iFAdgx07R5y
         TXNePpp2no01qcQxJ1gUfcIKSSVeHaSekZ+sqeHni+MdBcUZSHaB5uSrsh5Fo0cJsC+q
         k7cr7RqnobTunFtBZdSnHSIW0Mjnk71CViFYdE0EisEJGtMXUjOdJlD3hIk9QVYKsHCB
         0FVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qwWbva6AHUwQt9UEDVe5jjoMTo2S56pbEAlpT6isXVg=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=qtxfzXoYG5nXTJmelTCCOhauz+QZ22EYYgjuflYaGmyyhh4YqYqqo79ceB1+D6Te5s
         nYRQ42gOjQiEnW98MSGe5FdoenpvkgnnU4CqHSdy5H2rGxP1JjO5X0WHaJkbuMPdJ5g7
         PShl/BEHAUHbQ1Gjr9AyNrf3hKdbb3J2aM/ReD/7/nD0InjaOy5VqofjFn5xEMRnHYag
         abE8Wi1XhLEqOGpAm0qrBViI3xnz5CL4UUj2N16O2nHx1cti1Q9M93DnXbKYQzDwrLuk
         ifAw2hvCm+7+oIDfT8LMrJW5NTfRLFof/BTv2xMvtRE7ebbCKmBOGR0KXQbeO1IDIBta
         F2Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GyyDIVkE;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704208510; x=1704813310; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qwWbva6AHUwQt9UEDVe5jjoMTo2S56pbEAlpT6isXVg=;
        b=lk6pSRNRBKrR/MCGS+FgZ2qgmA8nHvWHwOth2MyYlD/CUEab/oEO8VMxwsVfju/T60
         AE2jigJ5Zjwstp59Accpkf4Wl4BfkA5VH5plbMfrQSskbdpk+KtUh3OpMAH7BJltrDL0
         IRFL5qTnqNUV6ovOG4QYsO/SQEoo8H53tecKW+jK5MIXU4UXz1F59rINhVYJhAJYDKmH
         Cbt4mqiVl0PszDumD8s4wfZMrBGBpJQjNXg8UJByzA+7yRKgt7163QpkkPXndrgxa5fD
         YgnUt4QVW6xAQba6dhvCQwMTDab63nJ1MGs3Se7SH48OQ6SNNJ3ZkxkgnIY5ZJT9MHWm
         iWnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704208510; x=1704813310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qwWbva6AHUwQt9UEDVe5jjoMTo2S56pbEAlpT6isXVg=;
        b=Uzodjq5b3TG0a8lcXn0vo3fWp2K81vrGSsC9elfZxovJ2mNxcK/cgrnGxtW4w0gBfW
         ofK2K90qtEp2Vh0EETCH/Mx4XFO4o9+jqIGPaaXjflCCltK3mircbqumKPodnfHi3TAB
         V0JiUJ1+LLhZfPYZy0/WZgia53UB0OP1+4jz0LbKRzA02Fa+nl63Nm3szrqjC6av70Q+
         wvnPWkiMHQFo/jEDLsgcrB1Ts6XCxz05e5eca5OqirvgEINW0iMIqK/T/90lwb7rsm3u
         q2HjHta9LrbC69vJ9wysSIOz+2O/6Z+2TY9I8nUnbGJUkY71HV+GSExzpHpTfiSw1H5a
         gj9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyXJik35/gmy/wUNKhXE52lWLaE7K1pBjhXSAT1iEpXcHVwb0EI
	xwOwhwpoNw8Qlzgb9dSkZA0=
X-Google-Smtp-Source: AGHT+IHsX7T3CJ/zFl6di3fsZpvs9dahaCkQkWeSxqjQXR3Fn4wlipXYWtB5tdUCqIdQ2YVu+H0U9w==
X-Received: by 2002:a05:6808:210c:b0:3bc:156a:125f with SMTP id r12-20020a056808210c00b003bc156a125fmr1420909oiw.27.1704208509825;
        Tue, 02 Jan 2024 07:15:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c6a:0:b0:67f:6bd0:4930 with SMTP id i10-20020ad45c6a000000b0067f6bd04930ls3090201qvh.1.-pod-prod-02-us;
 Tue, 02 Jan 2024 07:15:09 -0800 (PST)
X-Received: by 2002:a05:6214:519a:b0:67f:4926:60c9 with SMTP id kl26-20020a056214519a00b0067f492660c9mr24340660qvb.115.1704208508958;
        Tue, 02 Jan 2024 07:15:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704208508; cv=none;
        d=google.com; s=arc-20160816;
        b=Krqu7AFUmY0kTfThuFeWk07KFd9BFa1THKMvi8jCLG+F3NpbwzPjKBFTurTmdboei+
         BIILg9+zBvARAKB8YcrVDXD6Xwn2mQc1e1P8l6/BWI/f4X/Lw6AQWHnZKg9te73L8wDF
         T5DLFjqNHTviU8GI2Iafed/gxevcNMdFLgxbdjzSgaesWjt2GQ/DQ6jkiO2XXElmmVBi
         gDSFt4q7nz/xBhDrnLg3SlzO9cozpENIjn5xETftAO44bu2DFonxGNB/zixQWdKXU54V
         CHJ5jGJ2PLaB84jUI6ZvAfL9q9RVm2CKLQeUAMFqvkVidZ3o8+YstwyFawdlikZjgZ1U
         UlEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5R/MUyPZKXiGnRfyDR7/fa1BTIb9z0ZZv7WNzsdcXEY=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=hBDhHtkymMGuXSGlhhu2sR5W1O723UJpFi6Jb/I9tqhLRsqdmrtp7bk3MUFfVsUdEM
         WDh5BBVmxOYkzo7k4nqb4R9U2AiKXbL/p3lnpx6zTdaXPZWtWbwoQwCsy12BiO84V6LY
         OAQJ38FNIqiXvSoM4ELbtl/3tRyAIFtlRtk8sj111ecc5l4ab0t8NN7WLGc0FuRosgof
         PWuDDS03ZnhTLFAQeQ6D+rLkMzFBDR81SxMRwmYcmM21qpdMZmfYrNb8ffik6OMXpNEX
         SHJyULc2ArMQpEEQCnZkO6whEMKs34qJ6uvLiURqdRcNoUskb0sNZxOgZOMjUgxHlrCH
         xlzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GyyDIVkE;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u18-20020a0ce5d2000000b00680aba839c2si504053qvm.0.2024.01.02.07.15.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 07:15:08 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402CiInD000998;
	Tue, 2 Jan 2024 15:15:03 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7x4t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:15:03 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402FEmSn008974;
	Tue, 2 Jan 2024 15:15:02 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcf2j7x47-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:15:02 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402DmnDH027299;
	Tue, 2 Jan 2024 15:15:01 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vawht5u20-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:15:01 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402FEwtx42009224
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 15:14:58 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7EBA920043;
	Tue,  2 Jan 2024 15:14:58 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6486C20040;
	Tue,  2 Jan 2024 15:14:57 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 15:14:57 +0000 (GMT)
Date: Tue, 2 Jan 2024 16:14:56 +0100
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
Subject: Re: [PATCH v3 33/34] s390: Implement the architecture-specific kmsan
 functions
Message-ID: <20240102151456.6306-J-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-34-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-34-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: x9nKpR2aC7bRml8eajt4FMkQlPs2Gq8M
X-Proofpoint-ORIG-GUID: vr5hM93MX5JzVTHczD6LZ9lrx9kC2RZi
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 phishscore=0 lowpriorityscore=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 mlxlogscore=460 clxscore=1015 suspectscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020117
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=GyyDIVkE;       spf=pass (google.com:
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

On Thu, Dec 14, 2023 at 12:24:53AM +0100, Ilya Leoshkevich wrote:
> arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
> prefix and calling kmsan_get_metadata() again.
> 
> kmsan_virt_addr_valid() delegates to virt_addr_valid().
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/include/asm/kmsan.h | 43 +++++++++++++++++++++++++++++++++++
>  1 file changed, 43 insertions(+)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102151456.6306-J-hca%40linux.ibm.com.
