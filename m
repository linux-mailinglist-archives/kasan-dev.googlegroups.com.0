Return-Path: <kasan-dev+bncBCYL7PHBVABBBYOK2CWAMGQEVAOIT2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id A36ED821E36
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 16:01:55 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5ceac510f8csf4801a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 07:01:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704207714; cv=pass;
        d=google.com; s=arc-20160816;
        b=FMGOwlk0ysLLTD2R1xPXS+nQIK5KsdCOaP14CLwxZ3Ty5WahgQQZzqucj9R3QfYlUQ
         P6YQNdow2iQF774+N0fqWcXpuzEMKgTxYGfjwPvUMxP81WpWA9cWLmrlTFfdDDKbSvnP
         4hhg2bPzpkhQZuwtLJC8gw++0lD/47nHgl8OR59jw+BdxOIazMM4PipfXYqe/ZP6svf8
         w8Z6/JYu2e5X1mhpHleEE2slKedrrJyKhVd2mw0qh6GwDPh4J22jNhEcf3L0tzbDaxnn
         zT+pf79gOJlXcXFPTn8zitwI/ZSkWqmqE/ZEtEPFpa8DhuxPUCGgZaISYLUjQBOAdvAt
         77UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wPpl9IxpYsIxF+cXycx4je3I7oKS+AivhegNckNJEyk=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=p8kNtbAx3GZ0e2GRsfUo7X71H46XsSmF7vVDPodfDarU/rCnNnspw3y/GNUL4BG6lh
         Czf8bpnQXiP6R6K2vw3H/bCQ1Ak4rDVUABGFe67cIgzF7csscPmfXpcr43nT1ttl82qo
         QcmQ26/Vxv12hA8Wt8eWG+HcoUWmZBi2Imrn1hvFA9maRNoEz+iE1L3O8Id2P5m4djlQ
         5uP8BsoSeTO5vStZNXJI91sht9o/AD1w36/hyTh5O0+JhdYCkP5xo/FULSAz/lfIC9fJ
         A/gs/rLE4QFUNzTSvw6CrIzM5SCIwcAre3hbNx4Z66Ob5HH27NSTzrJo2WCVmgCePWfW
         L3Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=llleeLZ1;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704207714; x=1704812514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wPpl9IxpYsIxF+cXycx4je3I7oKS+AivhegNckNJEyk=;
        b=kEWozapt84Xt/nkN7FD861V5dd3n1n/Vsew4q9/XYXRnaYO8nEzZoruoV6uIINcKfV
         74bZg8w1d9JpH6JT1wBe8T1ClLEesMAhU5+nHYAy6V54IM5ejWqWbZ1JkdjCs0477jd8
         U8VfkT8j4tWC/TVZ2ivtiZTvPwBLUWz/bIbkVXsnmgY8JjUXvnv5nMSdilGKH2kz7Lwj
         a47th8QNQ7WBor6+U+Y5XiwEFevY9U1FwKFZydg45c0cqIX7UO/0KuvOLE1f8CpekSJF
         5WqaIU6mJi8kaL/1smN8CDXCabB9hcDfSBkylOfpYaoiA1IhwJx0bHK4zsr5D+Q9vPL0
         PqJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704207714; x=1704812514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wPpl9IxpYsIxF+cXycx4je3I7oKS+AivhegNckNJEyk=;
        b=DXk+BVne/DZ4e6KtSR8eOdGOhDZoGU9L8DbhaZe7tWcCXn2CtV3MKpW79lIl4YMdXy
         LCBvC0c989GDA7rg9CBEjzELMTiAz3If2EqD8Q6bzNSFIv2W2++wAuK6e/7tUb5EDOU5
         rGp7iNKiwrEXai+oGnmsmHW8qXtZFHAU2poKnKLO7z/LOTcrMhnHrmK6pixbvjtJKbyO
         l/YQ0oRo/pz6jifL6kb5l7rxb2tLvMArJUYhlU4JGEMfMK+tZ8T9uVTM3c03EeN/LjjT
         CmTm2SklnWc5vvbxONXNLvZh8AQKU5UHvRCv7GErpBRHrCwP95sbcS4xlisJ52G6tUWR
         Shlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwHnKqh2zpwtOKWUfWXr3vDw0CCP1rIlwS5BXFn0weuHYM7Dmzi
	eMMbC01OuuWBCTcmdae2cp4=
X-Google-Smtp-Source: AGHT+IFGny62IC8aEd3BTlh3fisqTIK39VLmluaZxDh2bKZmEi6C6dWWSEZzAD7pwNnfxNm7QTWOEQ==
X-Received: by 2002:a05:6a20:f397:b0:196:bc45:284b with SMTP id qr23-20020a056a20f39700b00196bc45284bmr9840245pzb.2.1704207714080;
        Tue, 02 Jan 2024 07:01:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1825:b0:6ce:f522:ec5b with SMTP id
 y37-20020a056a00182500b006cef522ec5bls3118733pfa.0.-pod-prod-05-us; Tue, 02
 Jan 2024 07:01:52 -0800 (PST)
X-Received: by 2002:a05:6a20:8e23:b0:197:458b:96b2 with SMTP id y35-20020a056a208e2300b00197458b96b2mr596501pzj.121.1704207712436;
        Tue, 02 Jan 2024 07:01:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704207712; cv=none;
        d=google.com; s=arc-20160816;
        b=vUWx+4RAhWpfkzKVn0yyNldZdWo6kGJW5OtFWf5SFoNSletWnX1yp/0BisBy9DWFjt
         8si9tO9qWqGunQZ6HD+ROx/srOJZZp3NnNsegt3WcS2/Q7C+GY2QVJ+3J3QllHlD2nBt
         c1jOZKFkhi8FmrdxMUiJ4821wbalo15BXstu1kow3D+xyqrvwgv34FuX7yn9jaEmbNw8
         Ynwp4zp9k2Ty8OMw+mHGSXbaMUpXP6DELKwsNdhnzbq2iprjoA6x6u5cWXyUZx5dl3Au
         Eqz7iQV7B6UUeyzKSxwpBkfl8MMwL7fe9S5ApWg3cubOEwtIFkhORSbJ9PZ4r300AkEv
         6xHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5DfTXPVd/eM6V5PQwyJZ3YoyiYCR8XXYxNPU2tae1Gc=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=SJfwPIPNeGA+oE14II02t8LWBBmX/ftCWNE+EOrmq7tgcNLHx1YpwvJ+u8lRQkCyKo
         lF0PzhCCldLV3rSnuzP50GAm2fQloSH+/1+N878lHe+3YEp6hFrhwUzTH8og4HUokg16
         Eqn7XzYQfWmMJGq5cR2gKwO5NlMm/ikqzZTUiHthWJpgx1sjQDETw/6lXW5Ah4QehZUC
         fIGS5NPGyR1ESi2Sm3dZhKwEDxvpR7j7dznZqFkTxX7KXqOfHk1yqEvI8teh/Js1DKTv
         O+izitdjk4k5mSK4qpL9H9XfFfpQYt8r5BpT1Y2atX/gZlWsgV+cgNEKh9OGwUXcU7gq
         EIxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=llleeLZ1;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id o6-20020a635d46000000b005cd919bdadfsi1897386pgm.0.2024.01.02.07.01.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 07:01:52 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402Em3pb016145;
	Tue, 2 Jan 2024 15:01:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcmjmgd3s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:01:48 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402EnT7r021329;
	Tue, 2 Jan 2024 15:01:46 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcmjmgd2v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:01:45 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402F0adP017991;
	Tue, 2 Jan 2024 15:01:44 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vayrkd6r0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 15:01:44 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402F1f3350790732
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 15:01:41 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 889F62004D;
	Tue,  2 Jan 2024 15:01:41 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3725820043;
	Tue,  2 Jan 2024 15:01:40 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 15:01:40 +0000 (GMT)
Date: Tue, 2 Jan 2024 16:01:38 +0100
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
Subject: Re: [PATCH v3 27/34] s390/irqflags: Do not instrument
 arch_local_irq_*() with KMSAN
Message-ID: <20240102150138.6306-E-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-28-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-28-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: fwlCQf0fqngEyUEwz2n1oINtNGsURlEU
X-Proofpoint-ORIG-GUID: 0BosCkKzyYZnSHJAxdZslg6QZCVj4M3P
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 malwarescore=0 mlxscore=0 impostorscore=0
 mlxlogscore=968 suspectscore=0 spamscore=0 bulkscore=0 lowpriorityscore=0
 adultscore=0 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020115
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=llleeLZ1;       spf=pass (google.com:
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

On Thu, Dec 14, 2023 at 12:24:47AM +0100, Ilya Leoshkevich wrote:
> KMSAN generates the following false positives on s390x:
> 
> [    6.063666] DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
> [         ...]
> [    6.577050] Call Trace:
> [    6.619637]  [<000000000690d2de>] check_flags+0x1fe/0x210
> [    6.665411] ([<000000000690d2da>] check_flags+0x1fa/0x210)
> [    6.707478]  [<00000000006cec1a>] lock_acquire+0x2ca/0xce0
> [    6.749959]  [<00000000069820ea>] _raw_spin_lock_irqsave+0xea/0x190
> [    6.794912]  [<00000000041fc988>] __stack_depot_save+0x218/0x5b0
> [    6.838420]  [<000000000197affe>] __msan_poison_alloca+0xfe/0x1a0
> [    6.882985]  [<0000000007c5827c>] start_kernel+0x70c/0xd50
> [    6.927454]  [<0000000000100036>] startup_continue+0x36/0x40
> 
> Between trace_hardirqs_on() and `stosm __mask, 3` lockdep thinks that
> interrupts are on, but on the CPU they are still off. KMSAN
> instrumentation takes spinlocks, giving lockdep a chance to see and
> complain about this discrepancy.
> 
> KMSAN instrumentation is inserted in order to poison the __mask
> variable. Disable instrumentation in the respective functions. They are
> very small and it's easy to see that no important metadata updates are
> lost because of this.
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/include/asm/irqflags.h | 18 +++++++++++++++---
>  drivers/s390/char/sclp.c         |  2 +-
>  2 files changed, 16 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/s390/include/asm/irqflags.h b/arch/s390/include/asm/irqflags.h
> index 02427b205c11..7353a88b2ae2 100644
> --- a/arch/s390/include/asm/irqflags.h
> +++ b/arch/s390/include/asm/irqflags.h
> @@ -37,12 +37,19 @@ static __always_inline void __arch_local_irq_ssm(unsigned long flags)
>  	asm volatile("ssm   %0" : : "Q" (flags) : "memory");
>  }
>  
> -static __always_inline unsigned long arch_local_save_flags(void)
> +#ifdef CONFIG_KMSAN
> +#define ARCH_LOCAL_IRQ_ATTRIBUTES \
> +	noinline notrace __no_sanitize_memory __maybe_unused
> +#else
> +#define ARCH_LOCAL_IRQ_ATTRIBUTES __always_inline
> +#endif
> +
> +static ARCH_LOCAL_IRQ_ATTRIBUTES unsigned long arch_local_save_flags(void)
>  {

Please change this to lower case and long single lines, so it matches the
more common patterns:

#ifdef CONFIG_KMSAN
#define __arch_local_irq_attributes noinline notrace __no_sanitize_memory __maybe_unused
#else
#define __arch_local_irq_attributes __always_inline
#endif

static __arch_local_irq_attributes unsigned long arch_local_save_flags(void)

...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102150138.6306-E-hca%40linux.ibm.com.
