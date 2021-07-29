Return-Path: <kasan-dev+bncBDCPRA4X5IERB5PCRKEAMGQEDYQRT3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2453E3DA49E
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 15:47:35 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id n192-20020a25dac90000b029054c59edf217sf6801515ybf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 06:47:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627566454; cv=pass;
        d=google.com; s=arc-20160816;
        b=pp9uxILAXEz6iaz05or5FBVONOsFffHoaf08vwZG27h9ondR/9eyiBoa2Tdfix3n89
         nV9AMRJe0vd9A3zB3Q0Euk+YQSnFEYHbxzumUVFHwiFubo+5cbPZ2lCAhQztWpZ0A34o
         RqBNnFB1S5r/ApkhJZJMQojtsvBUUNHUb+MqUZcHUX+X2HApu1WL50z/cNh3fTUlCsZE
         9e7Ao75FISwoWFBApaLVuJM2FqMjinePMqXeOn6sgkHu1+ADEROyEgY6JXJPauMPk7No
         8CSIukp5/q1cmHGfGFYfmY3zlq8Pm/LiRaKolCDH0YOyKQpYp6IHnmwRmUJuQtu/PKVd
         e8ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=Mqm5bEjY8qrZHNiRxv+IsJQuQ04tVQ+EQXk1yK0cz4E=;
        b=mBCCenOV4PR5aW7X6wbe+6Q4whlSv2zOkVyS3qkDgDsnUzc6no2mfARSxMtX1kgOrQ
         k/xQfSLk9480/c7VaBP2JdEZD5LelrmdZBQonETSFpykidttsnK+3iAre32o8A+29urI
         +xGDiaSOyyzjkqPllTlN5Tj2JLeNy7wpprku0JarAiZildTZ/wl8RpGpxvPnJ1n/oUsA
         9QEV/Twp+en2IP+rr34Cw873oLEFY9DKBpMeFEYw0xaEjGNhG1QBhlBc4uORbZEmK7Pc
         Td6U3Fb/XcWCaW5TyvVSqJyBBP9/sMAJQMfHmwOZnRbOnZ+FsuMQHp7LJWho+tzDKWEm
         ug8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="coJYu/Zt";
       spf=pass (google.com: domain of svens@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=svens@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Mqm5bEjY8qrZHNiRxv+IsJQuQ04tVQ+EQXk1yK0cz4E=;
        b=DoRAn5L2gB5ISstuhX4IpOBjFrdZhVuOGmhUZEcL603657MozR81wrVlJ/s7WqSAkX
         pHbwB7t8bZRgUfCP6tU5d8h4m5hi+idpf/pIeJHnODEfRErAXlAGX6tvkmSFD5k00/+e
         q2lyi39Kd1OR3dCVo9FqAKd1FC9dwQF7IHU70ozqpDGHAlkc/T1d5xHYjJpGLPrcUDgO
         IClh6DR4Th4uiacoXhTdlBLeLuUWZ8KucO19/DN/le5piRuXjPFZgENzQMV20f07wGc3
         a11aYdogU5Vg5oUIrf81ilWCxCBxbHKWOLB7LNJzV2pBViUxPfu0A7KUoW/vTif49/zD
         yCZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mqm5bEjY8qrZHNiRxv+IsJQuQ04tVQ+EQXk1yK0cz4E=;
        b=MRL1m+XQdG/Wfb6ajrI8kBHKciSk0ula/8SoJ9hm+Wjh6PvnjOHlFDnjLpCW4NTxSe
         xF3x42b87j+bxNg4V4T88HoZEOQNSDNmP0/GG/7pyACcNJ61+h00r1c4Xiy6iE1lZ4gk
         rO4SOeFZr71Dij9jT22ldQUEbV2BjBxytxWROuEbnH7gTG4/VrOmNYFFv/wbUG9GSK3Q
         MkEkWtZK+3Fg8jbjn1+E+EafRORhmVJTnO/cXQC8yNYh3x5eKNIeWceydjW63Vue0YQr
         5Sh57JNSZNhxOXltcaFw6wO2JdJnJERGob7RttECtPpmb27fl/JY8Yvo7k5meEep/ViJ
         oc8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530caSosLBTqgctvXF0+XAOGdxjwyNxpe7XFU1DBD1vVG+S0gee3
	BBAbtVsKN5oyZBKZ8H57deM=
X-Google-Smtp-Source: ABdhPJwmXcLCxJMD5nOx4yRYFa01P775G19v31obff4aR6ctULSJhZL2W4m1nKTB8Bp/JMIHI+UneA==
X-Received: by 2002:a25:7cc6:: with SMTP id x189mr7630279ybc.371.1627566453947;
        Thu, 29 Jul 2021 06:47:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6e04:: with SMTP id j4ls3160010ybc.7.gmail; Thu, 29 Jul
 2021 06:47:33 -0700 (PDT)
X-Received: by 2002:a5b:303:: with SMTP id j3mr6386912ybp.433.1627566453451;
        Thu, 29 Jul 2021 06:47:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627566453; cv=none;
        d=google.com; s=arc-20160816;
        b=C7AhV28L3O6UYGBrFwQul3h8gKRDSuQ3R2P46V4WtB1qk1LE1Uvy2VXeNCHm02HNHq
         MRbePNfdsuEWrJNL0zWwPZim2YauVtj1DSgLQuM8eHYk2NbzXEEDIsRia0xDW4J3XWxM
         jxLTgNMbfHqrh+Qnc5buauhwem5Kj0mTiVRmmCX6aiiH5oK3oUPoVX7x9rXq7hsQxnjo
         gB6xEbJO6JOJAXl51jZZLNE7bUh0xEJjIBwawPp64Dq2vMFQaElNtiFpzu0AH1YZNbni
         yoaATpwHaEZEWEICrnPHgjESoAedid7yD2UACVG9keUrHHsRwXxYJkOO2X9uJH2DW45S
         +4TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=9O/GEXoZTqlR+xJfXv/WGh/M7l0aIVQd0qAa+HW+Jb4=;
        b=ypv4V+70/eODQjZEe1x7ht9eX0PWkbdOZ+6U+haNrmglaJi0R6eCy+W8n80YCAHYOT
         wwG6jHby1VZAOfI2IoBZVjulcxQclaH/QZvG+0Hi7C9h7xlh2JGkphTMlrbOf0H8eWYG
         3FbFkOJtt2MID4kEsVv2kVcqBrUlePaqtZ4Tw5MGsLG0JhbYb9gDbzzVivNDPJ4nOQdn
         p5sipUmetzW8PUAt3EjzxU+RDXEfa6jWJBvNUxcuJFhppFThPjlU/o7ldNQIHXb5rzGh
         DSb3XoMfYN6CVSgNGqdBiJYQ3FlgV44D1QhGCWQWpmQpTaepYWqJId3fJ0BnP6iga1s8
         ilvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="coJYu/Zt";
       spf=pass (google.com: domain of svens@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=svens@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id z205si368760ybb.0.2021.07.29.06.47.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 29 Jul 2021 06:47:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of svens@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098417.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16TDXWBw110609;
	Thu, 29 Jul 2021 09:47:33 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3tw7nkue-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 09:47:32 -0400
Received: from m0098417.ppops.net (m0098417.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16TDYInm117541;
	Thu, 29 Jul 2021 09:47:32 -0400
Received: from ppma03fra.de.ibm.com (6b.4a.5195.ip4.static.sl-reverse.com [149.81.74.107])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3tw7nktt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 09:47:32 -0400
Received: from pps.filterd (ppma03fra.de.ibm.com [127.0.0.1])
	by ppma03fra.de.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16TDZnjZ002896;
	Thu, 29 Jul 2021 13:47:30 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma03fra.de.ibm.com with ESMTP id 3a235ks4ry-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 29 Jul 2021 13:47:30 +0000
Received: from d06av23.portsmouth.uk.ibm.com (d06av23.portsmouth.uk.ibm.com [9.149.105.59])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16TDigBD25428294
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jul 2021 13:44:42 GMT
Received: from d06av23.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BF0C6A4051;
	Thu, 29 Jul 2021 13:47:25 +0000 (GMT)
Received: from d06av23.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 58190A4080;
	Thu, 29 Jul 2021 13:47:25 +0000 (GMT)
Received: from tuxmaker.linux.ibm.com (unknown [9.152.85.9])
	by d06av23.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Thu, 29 Jul 2021 13:47:25 +0000 (GMT)
From: Sven Schnelle <svens@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>, Marco Elver <elver@google.com>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger
 <borntraeger@de.ibm.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux
 Memory Management List <linux-mm@kvack.org>,
        LKML
 <linux-kernel@vger.kernel.org>,
        linux-s390 <linux-s390@vger.kernel.org>
Subject: Re: [PATCH 2/4] kfence: add function to mask address bits
References: <20210728190254.3921642-1-hca@linux.ibm.com>
	<20210728190254.3921642-3-hca@linux.ibm.com>
	<CAG_fn=VS_WFjL+qjm79Jvq5M0KaNScvX2vCw=aNxPx14Hffa0A@mail.gmail.com>
Date: Thu, 29 Jul 2021 15:47:24 +0200
In-Reply-To: <CAG_fn=VS_WFjL+qjm79Jvq5M0KaNScvX2vCw=aNxPx14Hffa0A@mail.gmail.com>
	(Alexander Potapenko's message of "Thu, 29 Jul 2021 14:43:51 +0200")
Message-ID: <yt9dtukdteoj.fsf@linux.ibm.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/28.0.50 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 1Grps8gXUt09Y6zVx3mspHN6fv6-rv4W
X-Proofpoint-GUID: dN18rwQmbCZAayJ0xzHHDeX5X82kCHcf
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-29_10:2021-07-29,2021-07-29 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 mlxscore=0
 lowpriorityscore=0 bulkscore=0 adultscore=0 spamscore=0 impostorscore=0
 malwarescore=0 phishscore=0 priorityscore=1501 clxscore=1011
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2107140000 definitions=main-2107290087
X-Original-Sender: svens@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="coJYu/Zt";       spf=pass
 (google.com: domain of svens@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=svens@linux.ibm.com;       dmarc=pass (p=NONE
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

Alexander Potapenko <glider@google.com> writes:

> On Wed, Jul 28, 2021 at 9:03 PM Heiko Carstens <hca@linux.ibm.com> wrote:
>>
>> From: Sven Schnelle <svens@linux.ibm.com>
>>
>> s390 only reports the page address during a translation fault.
>> To make the kfence unit tests pass, add a function that might
>> be implemented by architectures to mask out address bits.
>>
>> Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
>> Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
>> ---
>>  mm/kfence/kfence_test.c | 13 ++++++++++++-
>>  1 file changed, 12 insertions(+), 1 deletion(-)
>>
>> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
>> index 942cbc16ad26..eb6307c199ea 100644
>> --- a/mm/kfence/kfence_test.c
>> +++ b/mm/kfence/kfence_test.c
>> @@ -23,8 +23,15 @@
>>  #include <linux/tracepoint.h>
>>  #include <trace/events/printk.h>
>>
>> +#include <asm/kfence.h>
>> +
>>  #include "kfence.h"
>>
>> +/* May be overridden by <asm/kfence.h>. */
>> +#ifndef arch_kfence_test_address
>> +#define arch_kfence_test_address(addr) (addr)
>> +#endif
>> +
>>  /* Report as observed from console. */
>>  static struct {
>>         spinlock_t lock;
>> @@ -82,6 +89,7 @@ static const char *get_access_type(const struct expect_report *r)
>>  /* Check observed report matches information in @r. */
>>  static bool report_matches(const struct expect_report *r)
>>  {
>> +       unsigned long addr = (unsigned long)r->addr;
>>         bool ret = false;
>>         unsigned long flags;
>>         typeof(observed.lines) expect;
>> @@ -131,22 +139,25 @@ static bool report_matches(const struct expect_report *r)
>>         switch (r->type) {
>>         case KFENCE_ERROR_OOB:
>>                 cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
>> +               addr = arch_kfence_test_address(addr);
>
> Can we normalize addr once before (or after) this switch?
>

I don't think so. When reporing corrupted memory or an invalid free the
address is not generated by hardware but kfence itself, and therefore we
would strip valid bits.

>>                 break;
>>         case KFENCE_ERROR_UAF:
>>                 cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
>> +               addr = arch_kfence_test_address(addr);
>>                 break;
>>         case KFENCE_ERROR_CORRUPTION:
>>                 cur += scnprintf(cur, end - cur, "Corrupted memory at");
>>                 break;
>>         case KFENCE_ERROR_INVALID:
>>                 cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
>> +               addr = arch_kfence_test_address(addr);
>>                 break;
>>         case KFENCE_ERROR_INVALID_FREE:
>>                 cur += scnprintf(cur, end - cur, "Invalid free of");
>>                 break;
>>         }
>>
>> -       cur += scnprintf(cur, end - cur, " 0x%p", (void *)r->addr);
>> +       cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
>>
>>         spin_lock_irqsave(&observed.lock, flags);
>>         if (!report_available())
>> --
>> 2.25.1
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/yt9dtukdteoj.fsf%40linux.ibm.com.
