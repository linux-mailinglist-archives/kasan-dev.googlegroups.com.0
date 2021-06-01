Return-Path: <kasan-dev+bncBDJJJ24Q5QBBBGEB3CCQMGQEWWKPGNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DF7639707D
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 11:40:41 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id z14-20020a6be20e0000b029043a04a24070sf8699198ioc.16
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 02:40:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622540440; cv=pass;
        d=google.com; s=arc-20160816;
        b=RX+yK4jGl1zHu/t6uQ6nyeG/My0PVOYB0/nq4cDIRKue9yx4bFyUM0JjlRBLxLnnIi
         lUoybfW0KfNDkkdmbRNF6n/0H7mVKuc5KPMYHTn1wJpsxuo20QVYohBGB7bZoAC1O3ul
         eYa7CZ46KNG+mSJTE40FvCnjuW9Z4su6Br7JfKA/72ERLqr/TVD2kh3xUJwHnNlLx6PE
         exMohyP4ToZLkS9SVGObqEHVcbUNe1my2+GpEzTeGWsChjEA8qTlsLNvcGQlWZT6EcLX
         EhATqcig8ecjoqc+1n5ZBl6ar8jM4yhiakALoDcMesQW26cCtfrVzVgtvC+GaZzNjBj9
         cPbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:user-agent:mime-version
         :in-reply-to:references:to:subject:from:date:sender:dkim-signature;
        bh=WFLaqWi41pI+pW+rHH7RfxvUE2rMknSyCnm7V880GCE=;
        b=pMuQAEbjsIxQs4KxvfSQWsKP5KuSt40TujytLTLviLOCdxJjHP6Sm3oJAcyXKTBJKn
         AdGLRbTGsHSwE51SX4OsL4EoPO/if+4iRJ0hv4uwGH2+3ZrJDsK/Nm4vB91nLFMa+fJ6
         ho2WX3xWGNN1WBMuC4T7YoMGIT6sWE4wl7ulq7xLXt+I0VrQmM0cbhQTH/fv8EZ6Bm5B
         Q3oFooytLcOK6VSJsgEJ2ipBVzgUs8A75IbX1hBrVFsBPZshgFLyux+uO85k+Wz1kN+r
         A6WS/G3yc1OgqmIUMDGhaCLjqYn1tYldZAjUhh6H0VGIgVp79vgq0kglA91IWIXQpM5m
         p6HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RptHl9sO;
       spf=pass (google.com: domain of naveen.n.rao@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=naveen.n.rao@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:subject:to:references:in-reply-to:mime-version
         :user-agent:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WFLaqWi41pI+pW+rHH7RfxvUE2rMknSyCnm7V880GCE=;
        b=BQzvp7aK3YwdlrdB/b4U8qAcCHappx6IaX+I+RXDJwHgMNNzQ/mg/NsNSeK75LfdyS
         I8ZO0hpXyW6MpxcdTwbGKFJz8fl2X+MKYiyeO+hFjjDHUbp8EgCb52awG8ELFdkoernW
         6xdToouZ918gKTbr+KwjvPFEuYXFg0bLodaT9Ix+4D7ViH5oKsB7GIhtxexjiqslQLXa
         1vuOCr36Q5nYNUBV9IE0oIY7B2PhwBc5qqosk6WctBHQAHo1hDkjJdFfq6YB9TnKxuAT
         Qn1XRPdF875fpSs+a/NHYxn6BLrDCke5jEs7prS1g9geOW4RXYC0Uy7W0sbxOx0I9M1Q
         k18w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:subject:to:references
         :in-reply-to:mime-version:user-agent:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WFLaqWi41pI+pW+rHH7RfxvUE2rMknSyCnm7V880GCE=;
        b=JfeyP8VxD8OjP6qF7UbFBTREx1bJ3AEJZYTve7FPVKB9q4wxpEWTKjp3nqsAY+UdX3
         eI8or7mbR2F0xdiReDzi9LH/bYQ6qvTeTyeeN7CWC5WA/ePcZmY228tRUeTUgdaAyp63
         w2fcIjgfFLwSQbeSgwLuA0/IbrmYElECFQKVyM6ZvL7etSEcZaGtmp1Qd8v7RfHH+Uug
         DOaeV1hdoh+iCJCyKPVp7ZbU/FeMU1f4Ylzo4RbDwqkIYWjSZ+xI5EBE/+0Z0ODO13fO
         3cRINgqcqLMaTxuxtlirXe0wJiLR7cDQamTQn1oGa4hZXdYL9U4wnAqwa6dF5gf6NRDb
         2SKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304fOjxhIb6Nza9lY1iTQGFP6c2yZYAD4BvCoOdsr/6HsV/UA/D
	HoAdBdjGWqcveToXgFYNMn0=
X-Google-Smtp-Source: ABdhPJz6rxSYnt85cVUep0+yFm6+Stp5J4YSe/UEulwf687qmgrM7TSVnomiRrnDvpOvqKmJQvDLyA==
X-Received: by 2002:a92:c24b:: with SMTP id k11mr20931216ilo.303.1622540440575;
        Tue, 01 Jun 2021 02:40:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c4c5:: with SMTP id h5ls303881jaj.1.gmail; Tue, 01 Jun
 2021 02:40:40 -0700 (PDT)
X-Received: by 2002:a05:6638:118c:: with SMTP id f12mr24346395jas.143.1622540440204;
        Tue, 01 Jun 2021 02:40:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622540440; cv=none;
        d=google.com; s=arc-20160816;
        b=pffOEKGpcZIPZH7MXxHAE3nC8+HK0kOz2vV8Pk5ZITr9w/hQbPxeV699golnBNww4D
         IyqWokFdHdtgZHNfdLAS1XR5eh9i67O/5KxXEMtn0xycV/B8D3N7VXRzTeUQGR2cBo+v
         tUF7cutisBytD8/7MTsjyaAAIdwSFI8umFnULsBIqQNg4iYlK1BERAwTfUfMmO+jPO/z
         Ljgp431EStL5VI7toU15E7LD/ezFwp24kUQjEANa1VjFDw9uIwjaQpWDqdr0Jwc7DyzB
         IKxTB5tuPveo0/I0LLnrKoY4jmTNmRTjfKogp2n5diEa3TzsrsL8fPBKIA58/5M7islS
         GDUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:message-id:user-agent:mime-version
         :in-reply-to:references:to:subject:from:date:dkim-signature;
        bh=HS7GLo4YPRH9AQ/D6Y/8pCOpDeDKHLzs46UL2AE4h3g=;
        b=SJ3kmQljM3epV1XcIaOSpC55WJbJqRT2BPThPxwX5gfQMrPKVbmTBhfh7q7flsWZrv
         pgjgHgfXKdBfy9JR9cHevACYP9aBPvjdYm1G2sOb/qLyJOHZS2aeHiCFRFPKqqDT6fk3
         bm2eUV+w+LvoFEQEL4oq3ZTFZo49/y+w/RHHH26W50yoTSCgOb0SVcQn1DVl6qsrbaX7
         r/iNB7aSFcbFSISqQUpHVVzKMOaXx3zgbJSUs2H1AJXPc0Xa63+thZ/QaoKOTLJmm98J
         eI1rK4VdXKlKpnaK7SVpDrNc4K7CFooZEOzmtGnFJvEtfUA1qUgyCzd40ib+TkQX5cfF
         1eDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RptHl9sO;
       spf=pass (google.com: domain of naveen.n.rao@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=naveen.n.rao@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id l7si1282811ilg.1.2021.06.01.02.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Jun 2021 02:40:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of naveen.n.rao@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0127361.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 1519WiXH170898;
	Tue, 1 Jun 2021 05:40:30 -0400
Received: from ppma04fra.de.ibm.com (6a.4a.5195.ip4.static.sl-reverse.com [149.81.74.106])
	by mx0a-001b2d01.pphosted.com with ESMTP id 38whnn1ddu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jun 2021 05:40:29 -0400
Received: from pps.filterd (ppma04fra.de.ibm.com [127.0.0.1])
	by ppma04fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 1519cSNJ011666;
	Tue, 1 Jun 2021 09:40:28 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma04fra.de.ibm.com with ESMTP id 38ud880v2v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 01 Jun 2021 09:40:27 +0000
Received: from d06av22.portsmouth.uk.ibm.com (d06av22.portsmouth.uk.ibm.com [9.149.105.58])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 1519dri133882440
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 1 Jun 2021 09:39:53 GMT
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8D4944C044;
	Tue,  1 Jun 2021 09:40:25 +0000 (GMT)
Received: from d06av22.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F332B4C04E;
	Tue,  1 Jun 2021 09:40:24 +0000 (GMT)
Received: from localhost (unknown [9.85.73.71])
	by d06av22.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Tue,  1 Jun 2021 09:40:24 +0000 (GMT)
Date: Tue, 01 Jun 2021 15:10:23 +0530
From: "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>
Subject: Re: [PATCH] powerpc: make show_stack's stack walking KASAN-safe
To: christophe.leroy@csgroup.eu, Daniel Axtens <dja@axtens.net>,
        kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org
References: <20210528074806.1311297-1-dja@axtens.net>
In-Reply-To: <20210528074806.1311297-1-dja@axtens.net>
MIME-Version: 1.0
User-Agent: astroid/v0.15-23-gcdc62b30
 (https://github.com/astroidmail/astroid)
Message-Id: <1622539981.k2ctwb25pa.naveen@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: vaCDV2d8Q2KLE_33lWuk3O89PWR4ogFg
X-Proofpoint-GUID: vaCDV2d8Q2KLE_33lWuk3O89PWR4ogFg
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.761
 definitions=2021-06-01_05:2021-05-31,2021-06-01 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 mlxscore=0 lowpriorityscore=0 mlxlogscore=999 suspectscore=0
 clxscore=1011 phishscore=0 adultscore=0 malwarescore=0 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2104190000 definitions=main-2106010064
X-Original-Sender: naveen.n.rao@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=RptHl9sO;       spf=pass (google.com:
 domain of naveen.n.rao@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=naveen.n.rao@linux.ibm.com;       dmarc=pass (p=NONE
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

Daniel Axtens wrote:
> Make our stack-walking code KASAN-safe by using READ_ONCE_NOCHECK -
> generic code, arm64, s390 and x86 all do this for similar sorts of
> reasons: when unwinding a stack, we might touch memory that KASAN has
> marked as being out-of-bounds. In ppc64 KASAN development, I hit this
> sometimes when checking for an exception frame - because we're checking
> an arbitrary offset into the stack frame.
> 
> See commit 20955746320e ("s390/kasan: avoid false positives during stack
> unwind"), commit bcaf669b4bdb ("arm64: disable kasan when accessing
> frame->fp in unwind_frame"), commit 91e08ab0c851 ("x86/dumpstack:
> Prevent KASAN false positive warnings") and commit 6e22c8366416
> ("tracing, kasan: Silence Kasan warning in check_stack of stack_tracer").
> 
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  arch/powerpc/kernel/process.c | 16 +++++++++-------
>  1 file changed, 9 insertions(+), 7 deletions(-)
> 
> diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
> index 89e34aa273e2..430cf06f9406 100644
> --- a/arch/powerpc/kernel/process.c
> +++ b/arch/powerpc/kernel/process.c
> @@ -2151,8 +2151,8 @@ void show_stack(struct task_struct *tsk, unsigned long *stack,
>  			break;
>  
>  		stack = (unsigned long *) sp;
> -		newsp = stack[0];
> -		ip = stack[STACK_FRAME_LR_SAVE];
> +		newsp = READ_ONCE_NOCHECK(stack[0]);
> +		ip = READ_ONCE_NOCHECK(stack[STACK_FRAME_LR_SAVE]);

Just curious:
Given that we validate the stack pointer before these accesses, can we 
annotate show_stack() with __no_sanitize_address instead?

I ask because we have other places where we walk the stack: 
arch_stack_walk(), as well as in perf callchain. Similar changes will be 
needed there as well.


- Naveen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1622539981.k2ctwb25pa.naveen%40linux.ibm.com.
