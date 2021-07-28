Return-Path: <kasan-dev+bncBCHJVF74S4BRBZG7Q2EAMGQEAFVYTDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id D3D103D9608
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 21:28:42 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id e19-20020ab02b130000b02902a1de813977sf1480471uar.10
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 12:28:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627500516; cv=pass;
        d=google.com; s=arc-20160816;
        b=IBPmNxjaJxTvziZTxDKmKRJEIqiPaWMq6X9v6KbHjoxhy8WLo57X7ld3D6QXIL7pVF
         /xTwsj/I2y1gWZSU50y9VVLoKghcRpVyn3zZRqI9OwkYHZ3Ba4EL/piOvvwDxyhPigSp
         zEd5xGolG/5714kYM/Krlr9vPzBpbSfnczLS87cG4/MYAGtAX8MLXnpUvO6/1/EuGHHN
         IWsds5e8NhMNnQGzLbiwiCh286K/a7f0Us3krCK/qGfZ+0I+9TMxcILPKjE7R0EXnNXW
         ViPUxyb3a/8icdQmhf1Gq7OTMBL6ZcPXl2WN2zP9loXLijNtTgaaY6P5Ems4Y0aT0oro
         Ot3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :in-reply-to:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=8WCF0XTVKxvttv5ldf6c0lfHuGpiLxbKHwfn80dv5zU=;
        b=pHUdyApcq609gZYhYf9XB6bWorqhNlfwmCaN1NoAhb4ZIvpXV1bahTIx+Bhj60OPpf
         y01K7/N9+zTHYc/4wfdb5N5sOtnkesIunnSOWHbmXDLiw2YSU6DAxiZ6qZPWNzaldYhP
         HmGlBqcYZ5Ed5hsCla8/XNrI7v4ieeXGnULGNuu/yHwxibTuuchgkGSamcEaLNC5Wzua
         VNbk70P+tyt6gV5zyGglIoNOi+OXiyV+RNpII/iYae8gSuMj3VmRwbOoLlVtA44TE7Ql
         r5p5o3xk0ak7Kifu29zappfrQAEoPpvpv1ynm7wvgmm32a5Y31NRmm71pGPzfASnmwqc
         X7Xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fMInDaUj;
       spf=pass (google.com: domain of borntraeger@de.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=borntraeger@de.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :in-reply-to:content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8WCF0XTVKxvttv5ldf6c0lfHuGpiLxbKHwfn80dv5zU=;
        b=XDgSFrJkKd8qhDHK/WVAk/SW9zwVIYgqpbOZvk+wBCxHR5OK+fJFB/OidNEkX05+SO
         6VdQ5MSjMcizHCo4iDEt/kjyOH8oKAnlqF+lhzWb/1UoW1U5tH/T1K42MfRp76Sv8RmT
         hD58gC+z97ZWIwTVGql8s4JwHnSdiU19aSeKQdS3/7lfiaWLSAJGFnP2BejnHv7mbyD3
         ZrPh7TMic9XsNWLIYwPDk9sgEqEYberpfVSWYJ+pr4VK59iBU/yK+yziG7JTLTiilOS9
         f1K1cqXu1jyNXd7eou+tDlwQS5CICOmJl2kbn9qxaEKiXSM3A+SeBpOv7OL+UhfT5aT4
         BGHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:in-reply-to:content-language:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8WCF0XTVKxvttv5ldf6c0lfHuGpiLxbKHwfn80dv5zU=;
        b=aWjYCkTeOCthbFFfV26Fibm3SKN7t/mEs5YA9egvPzAMj/SgoVV6TIkXZfkRwolHYh
         56rv/yGxf8fZHtCej3MI4hm8BH9p1LOpQvjcGiXEHC1k92264FlrwBCQ0ZNy0cqwZHMp
         8+E31uCG2aqjtogN20uePdtOhFmPeRzxFCxCiV8RZuLO90Z8lGFwcyUP8sOxOiFUfqgC
         6LLBmwJZj6nSACeVSjYmsEIjayNzuajZM5qIWeBdLOqfoszapTMLZ24H2RMwL6CweDJ8
         YTBEQft0DLXwyMcvxAQAeJOaeV5i1USNZIkazVTCG4b22gpERHPdDMQ73uN7ZiUuzt5R
         ihBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302wQvMXvb0l6n3xtJDOCtlhMowFV11dh+iM6e2v4VjWf75ahZc
	UTRsP+MqXrZr7+ZHgvK24S4=
X-Google-Smtp-Source: ABdhPJy6Pa9SAgYpQ9g598NTEAy1+RAXWgrhjH89Hrx6SvRK06zMUKlAZCYIv6LW28RCbpgWLREj1g==
X-Received: by 2002:a1f:5cd1:: with SMTP id q200mr1527335vkb.4.1627500516693;
        Wed, 28 Jul 2021 12:28:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c488:: with SMTP id d8ls669405vsk.7.gmail; Wed, 28 Jul
 2021 12:28:36 -0700 (PDT)
X-Received: by 2002:a67:ea98:: with SMTP id f24mr1647378vso.19.1627500516130;
        Wed, 28 Jul 2021 12:28:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627500516; cv=none;
        d=google.com; s=arc-20160816;
        b=OyABxiVqFDj+qJvEWBpfoalBIe1PYkPIkSe26vv0Pz66MYvyyfLew8pjuMjfxdi7Ce
         7XdyRg9wI9OpuCQh7t2J4DlONyJPbe/UCckpkOdjHwKPKbfLeeQKxM64/NBmeiJWcMpL
         VZI7DTZu5E6/0et4/+zFj/S+ivtk9m5ipSZCrZXVQg5k5tsLZnr36szWMlQLTzxKstw/
         g+Ye9F+umiGGOZmDJMhPMZNh2wFWCylPl3+S8v1mlzcDEsGs3jUvcQtnrOYquHU/h3ws
         nWzoitf8/QMDLhc5+N1g/O7aIj3YqNWievUJ2u9wQMIXAmdITPi8QgfKBn1eMZKdCr2i
         6CPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language:in-reply-to
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=kyaZ4GYcmSZei/dzdWHkHv20uzLVnPG2c8tJNuEPL68=;
        b=nEjAdMlIHPYJgHzMJAZPifaz6JRl03tnMhZXO8B5ZfE745xdtWukJ9oRZOqHXcLrJt
         Pp82eTcDJ/o/KtTI51mPR2gLesyryG1vkRNBlQUVood85rJuma3bTS2d09eSgPc+LWkC
         S/07mcQMCUrcHEkwV8bZa8quHgj/7VzA6XP5wUtLKOF5pIF+hrjYKXlHyqKb+sfESzq5
         kUWoRBGmdIlKjsYZIhFVsq4SnQvEmn1wF2YGdRN/sT8pyT13GsFoI9mzUd9OHObTlgTV
         kid7aBFQOJfDYVJ77EK8Uiu1/kVQ5UDO5v2bUIP+MSxAajJasTW1bgKk8hNB/DA3vV7j
         b8Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fMInDaUj;
       spf=pass (google.com: domain of borntraeger@de.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=borntraeger@de.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id o17si40556uat.1.2021.07.28.12.28.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jul 2021 12:28:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of borntraeger@de.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098399.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16SJ5RmD195628;
	Wed, 28 Jul 2021 15:28:35 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3b0xv17v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:28:34 -0400
Received: from m0098399.ppops.net (m0098399.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16SJ6lF1010114;
	Wed, 28 Jul 2021 15:28:34 -0400
Received: from ppma04fra.de.ibm.com (6a.4a.5195.ip4.static.sl-reverse.com [149.81.74.106])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3b0xv17b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:28:34 -0400
Received: from pps.filterd (ppma04fra.de.ibm.com [127.0.0.1])
	by ppma04fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16SJNRSv012081;
	Wed, 28 Jul 2021 19:28:32 GMT
Received: from b06cxnps4076.portsmouth.uk.ibm.com (d06relay13.portsmouth.uk.ibm.com [9.149.109.198])
	by ppma04fra.de.ibm.com with ESMTP id 3a235kgu3a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 19:28:32 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06cxnps4076.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16SJSSmU30278036
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 28 Jul 2021 19:28:28 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6A572AE051;
	Wed, 28 Jul 2021 19:28:28 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C1C7EAE045;
	Wed, 28 Jul 2021 19:28:27 +0000 (GMT)
Received: from oc7455500831.ibm.com (unknown [9.145.170.45])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Wed, 28 Jul 2021 19:28:27 +0000 (GMT)
Subject: Re: [PATCH 2/4] kfence: add function to mask address bits
To: Heiko Carstens <hca@linux.ibm.com>, Marco Elver <elver@google.com>,
        Alexander Potapenko <glider@google.com>
Cc: Sven Schnelle <svens@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
References: <20210728190254.3921642-1-hca@linux.ibm.com>
 <20210728190254.3921642-3-hca@linux.ibm.com>
From: Christian Borntraeger <borntraeger@de.ibm.com>
Message-ID: <ed973c3c-2f2f-0f01-d4d1-96c83daff1b1@de.ibm.com>
Date: Wed, 28 Jul 2021 21:28:27 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
In-Reply-To: <20210728190254.3921642-3-hca@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 0m4aXonDSTnYHZBiEnr2dNIdvC3bWxar
X-Proofpoint-ORIG-GUID: xxPKxHU_4mDiA__dUAxdGqsDT-zwgXzO
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-28_09:2021-07-27,2021-07-28 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 impostorscore=0 mlxlogscore=999 spamscore=0 suspectscore=0
 lowpriorityscore=0 bulkscore=0 adultscore=0 clxscore=1011 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107280109
X-Original-Sender: borntraeger@de.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fMInDaUj;       spf=pass (google.com:
 domain of borntraeger@de.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=borntraeger@de.ibm.com;       dmarc=pass (p=NONE
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



On 28.07.21 21:02, Heiko Carstens wrote:
> From: Sven Schnelle <svens@linux.ibm.com>
> 
> s390 only reports the page address during a translation fault.
> To make the kfence unit tests pass, add a function that might
> be implemented by architectures to mask out address bits.

FWIW, the s390 hardware does indeed only provide the page address
for page faults. We had to do the same trick for other software,
e.g. see valgrind
https://sourceware.org/git/?p=valgrind.git;a=blob;f=coregrind/m_signals.c;h=b45afe59923245352ac17fdd1eeeb5e220f912be;hb=HEAD#l2702


> 
> Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
> Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
> ---
>   mm/kfence/kfence_test.c | 13 ++++++++++++-
>   1 file changed, 12 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 942cbc16ad26..eb6307c199ea 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -23,8 +23,15 @@
>   #include <linux/tracepoint.h>
>   #include <trace/events/printk.h>
>   
> +#include <asm/kfence.h>
> +
>   #include "kfence.h"
>   
> +/* May be overridden by <asm/kfence.h>. */
> +#ifndef arch_kfence_test_address
> +#define arch_kfence_test_address(addr) (addr)
> +#endif
> +
>   /* Report as observed from console. */
>   static struct {
>   	spinlock_t lock;
> @@ -82,6 +89,7 @@ static const char *get_access_type(const struct expect_report *r)
>   /* Check observed report matches information in @r. */
>   static bool report_matches(const struct expect_report *r)
>   {
> +	unsigned long addr = (unsigned long)r->addr;
>   	bool ret = false;
>   	unsigned long flags;
>   	typeof(observed.lines) expect;
> @@ -131,22 +139,25 @@ static bool report_matches(const struct expect_report *r)
>   	switch (r->type) {
>   	case KFENCE_ERROR_OOB:
>   		cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
> +		addr = arch_kfence_test_address(addr);
>   		break;
>   	case KFENCE_ERROR_UAF:
>   		cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
> +		addr = arch_kfence_test_address(addr);
>   		break;
>   	case KFENCE_ERROR_CORRUPTION:
>   		cur += scnprintf(cur, end - cur, "Corrupted memory at");
>   		break;
>   	case KFENCE_ERROR_INVALID:
>   		cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
> +		addr = arch_kfence_test_address(addr);
>   		break;
>   	case KFENCE_ERROR_INVALID_FREE:
>   		cur += scnprintf(cur, end - cur, "Invalid free of");
>   		break;
>   	}
>   
> -	cur += scnprintf(cur, end - cur, " 0x%p", (void *)r->addr);
> +	cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
>   
>   	spin_lock_irqsave(&observed.lock, flags);
>   	if (!report_available())
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ed973c3c-2f2f-0f01-d4d1-96c83daff1b1%40de.ibm.com.
