Return-Path: <kasan-dev+bncBCYL7PHBVABBBQOI2CWAMGQEQANHSNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F7C0821E2B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 15:57:06 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-42823a4d128sf24986741cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 06:57:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704207425; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvtmRrMF43C3kNVI6H/nx45kcxEN8k3VYqrCOZcHlOuM4qmH6mymwSSoHqjyaReGP3
         6S3D6d1uNixIeMGbhmJom0qtifIT5V5pJk4Mbg3sCqriGL3g1N6RmBqLyX3K7gpcgBDD
         JJk9uB168/HLGTtAbuFo553P40Oz4FiN5pWo4/PpRBW6Jr1+AiRzO68EFuF5FB33hRsy
         o5j21W5F8PCZ7NQJl6/vCBXrddJSuz9TpU25HqcVrF/SY7wZ5lkB5Sj5+XHy8xEB0NLv
         yA8rnEf5zcDQxs6NUN7okfn98N211P8L017zHUXNHKT4pUBHif9xetbtXZIX61muO0Id
         uEWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pUEyxg5sxB56ti/AZ68wtVDjHNBEfz0rJUqOU/3nOCw=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=jTqAfG1nZkLBh1EollbpUJAakn77TAB5Gs3ldaWbP7q3LQnKPFprpAae5pV8TsZUn3
         lrdcIOVy06lOOlUF819S5B65dFGaDSPIkkjFnaGZl0KpvTzWsX3KOCMdqWnEnORRjTrq
         0HkFBui3C0IM01KAKiBnPtk4rprpYZuZbbnAaZQGETCvutrlxO0w366fXdYwRF5GXiof
         e0G7LSiSdcT/ESIMxUi7tJKqqsBRDJ8he23Ucq6klGmyxx+RgPcds80PZ9QUf4+sDQY3
         mVUTwi5O1tBvUELFj6V8yHAOysCozXW1BXjDdN2YrMROHdPLBhT9uKuiq+Dkudf7fKey
         XhnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FXbIqg4H;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704207425; x=1704812225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pUEyxg5sxB56ti/AZ68wtVDjHNBEfz0rJUqOU/3nOCw=;
        b=muJQFftpOp/dd7b7EZ67lnpaxN/FDQWWJ/VlqtKS6d/0bDkXN8wsKfr9TND5AKiqil
         T7xHxp1AN5DtFD4gVMMP7WbvO+4yVbJIdT0WLw9biKVrCINeeCKdY4K4PL7oeue6OXHD
         BeUF87tK8LvPIclPjMhOA36OV4kOO7y+QgiPoWhDNdHyfAvWSt1FwTiSZauhrrxK6lKj
         w1A8vNr+4i8D1fYl9w29G/kwdum+UGZN607rg2vLRcoAI8LwuPcamSyuCRXZIhBr/GgR
         GHhae4uAWD+idArm34H+RTv2FzDBFrFtoes89SbZGc6wLIkrO/dB5sfaikOA1Mp5I5R0
         egIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704207425; x=1704812225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pUEyxg5sxB56ti/AZ68wtVDjHNBEfz0rJUqOU/3nOCw=;
        b=pyKi2pd6igjlqhLSo2GTp1ITbnwoo7snTlsEtuO0PrJkg2XyrTVroZz+kJ203BvGxS
         8jHuMn9njBIr9Bn7IrX4a6bMDNFDeJWDP/n+L7TzXYtTwYILO7FzEft8J9dXlqw1GtbO
         yD6vKg0dN63yTMRhr7C1Xrfq3dB89vd1vyQFQHDKGcLNmi1mbA9vgveGhOuI8Rz7f4VP
         1mq1dD/eTKL6Qniff7mshW5gyR3BrB/YgKazBhcmXd8Jbxgd5V6wwYU3M6Igb22gdne0
         Jf1V2VRWEQWGXJ5tPPsdNaQzxc2q9/hggSTBHAnvLN50w5S/EjB6QaDtUviUCiikqAR/
         hBdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyYgHErOQUUjBmA5V42r7Ehyz6GJFAdGCFyDOQR6bjAsF+vHfU+
	07SwTkIcgK/8uN+wIZEdK2I=
X-Google-Smtp-Source: AGHT+IETu1Tpu+N1H9EkC5X1ZPq5evjZ4TMMo3eZ6K2yjdAmokMhso3A+zrrnEWMdlIo5KBfx2amjA==
X-Received: by 2002:a05:622a:5a89:b0:427:f260:46f with SMTP id fz9-20020a05622a5a8900b00427f260046fmr14811928qtb.16.1704207425240;
        Tue, 02 Jan 2024 06:57:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:18a1:b0:427:79b0:3585 with SMTP id
 v33-20020a05622a18a100b0042779b03585ls532905qtc.2.-pod-prod-01-us; Tue, 02
 Jan 2024 06:57:04 -0800 (PST)
X-Received: by 2002:ac8:7e96:0:b0:428:a5c:502c with SMTP id w22-20020ac87e96000000b004280a5c502cmr8624083qtj.19.1704207424589;
        Tue, 02 Jan 2024 06:57:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704207424; cv=none;
        d=google.com; s=arc-20160816;
        b=MaxuQnoD2CyVEU+f2RD9ZCkR5BHu99uuaTSo9sqwzzl21BYCDVtal9SSGyEledUYAN
         xBAfPsB14Naio91qMb38aP9isCw8rQhKrlOYKUYSx2wMUovvbF7aZ7KJw14bEyRpN0Qp
         w770iu/zoZy+hI80O37Gy8MMwG41owTuM3JV9Ig6lYZ+vKEVK6XBJXhivEgTlXv99/Lv
         CupdTzpUReBg7j6Meh28FOSfOx9RtaFj914t0O93ApLK7KLg/rKu5ARCPxtIUDJ6X86S
         AER3nBDeGdrYUlFRLrRs1kLYEI88MSns4J+ZIHMSzc+/HMuxiJ+7bat8Tfr4pGe9U72a
         2FAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bL+ZIKl6ttywS56QSUlX/YXzFOtll+hBW6t6aAV1Vp0=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=m89dVJ2QmlxvMhhpl6E+AJSzvwiWo4Zy+DjFdCpOgLxl/mKCRgxim+kEfqQVOOKIyG
         OP9gKp2++CuFFSZh+RmfjUGXp4BhPdFGv1Pr2g/DJ+5+AsVKG7n/pkLsI3w/BOGIdNmd
         NRPjdaq8SzZ487AbEDT54jQ7Fe/BD0PoW6y5uaNjXBEvqSAL7/rbuqDCOFMQ3ymxEJAU
         ihWqFxlzvOytvjg0AMTfy0xRNTQILtWxMCohsctY2L6GoeT7YpiAtDfMuEtBBQxgEoIq
         mLtvN3rSsWp3bKUrqgJzb6gitUF68zQGbtz3MWiwxnECPvqX1Z5/BS0LiU4XrDvu580k
         Slzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=FXbIqg4H;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id g3-20020ac85d43000000b004281b3b36b0si368851qtx.0.2024.01.02.06.57.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 06:57:04 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402EhEM2021402;
	Tue, 2 Jan 2024 14:57:01 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcmg7re0c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:56:59 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402EjXkx029393;
	Tue, 2 Jan 2024 14:56:56 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcmg7rdpv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:56:56 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402ED398007417;
	Tue, 2 Jan 2024 14:56:29 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vaxhnweh8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:56:29 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402EuQBv58393020
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 14:56:26 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 65FF320063;
	Tue,  2 Jan 2024 14:56:26 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 546F42004D;
	Tue,  2 Jan 2024 14:56:25 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 14:56:25 +0000 (GMT)
Date: Tue, 2 Jan 2024 15:56:23 +0100
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
Subject: Re: [PATCH v3 25/34] s390/diag: Unpoison diag224() output buffer
Message-ID: <20240102145623.6306-C-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-26-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-26-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: RUOkeM2Jhk_VjhploDiahEDWYEBVFPeb
X-Proofpoint-GUID: _T0ziB-ASJYSISr80eNxgXOERvkM-ZsL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 suspectscore=0 phishscore=0 mlxscore=0 bulkscore=0 lowpriorityscore=0
 adultscore=0 impostorscore=0 priorityscore=1501 mlxlogscore=999
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020115
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=FXbIqg4H;       spf=pass (google.com:
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

On Thu, Dec 14, 2023 at 12:24:45AM +0100, Ilya Leoshkevich wrote:
> Diagnose 224 stores 4k bytes, which cannot be deduced from the inline
> assembly constraints. This leads to KMSAN false positives.
> 
> Unpoison the output buffer manually with kmsan_unpoison_memory().
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/kernel/diag.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/arch/s390/kernel/diag.c b/arch/s390/kernel/diag.c
> index 92fdc35f028c..fb83a21014d0 100644
> --- a/arch/s390/kernel/diag.c
> +++ b/arch/s390/kernel/diag.c
> @@ -9,6 +9,7 @@
>  #include <linux/export.h>
>  #include <linux/init.h>
>  #include <linux/cpu.h>
> +#include <linux/kmsan-checks.h>
>  #include <linux/seq_file.h>
>  #include <linux/debugfs.h>
>  #include <linux/vmalloc.h>
> @@ -255,6 +256,7 @@ int diag224(void *ptr)
>  		"1:\n"
>  		EX_TABLE(0b,1b)
>  		: "+d" (rc) :"d" (0), "d" (addr) : "memory");
> +	kmsan_unpoison_memory(ptr, PAGE_SIZE);

Wouldn't it be better to adjust the inline assembly instead?
Something like this:

diff --git a/arch/s390/kernel/diag.c b/arch/s390/kernel/diag.c
index 92fdc35f028c..b1b0acda50c6 100644
--- a/arch/s390/kernel/diag.c
+++ b/arch/s390/kernel/diag.c
@@ -247,14 +247,18 @@ int diag224(void *ptr)
 {
 	unsigned long addr = __pa(ptr);
 	int rc = -EOPNOTSUPP;
+	struct _d {
+		char _d[4096];
+	};
 
 	diag_stat_inc(DIAG_STAT_X224);
-	asm volatile(
-		"	diag	%1,%2,0x224\n"
-		"0:	lhi	%0,0x0\n"
+	asm volatile("\n"
+		"	diag	%[type],%[addr],0x224\n"
+		"0:	lhi	%[rc],0\n"
 		"1:\n"
 		EX_TABLE(0b,1b)
-		: "+d" (rc) :"d" (0), "d" (addr) : "memory");
+		: [rc] "+d" (rc), "=m" (*(struct _d *)ptr)
+		: [type] "d" (0), [addr] "d" (addr));
 	return rc;
 }
 EXPORT_SYMBOL(diag224);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102145623.6306-C-hca%40linux.ibm.com.
