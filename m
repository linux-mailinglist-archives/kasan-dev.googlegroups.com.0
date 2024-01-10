Return-Path: <kasan-dev+bncBAABB7FQ7CWAMGQE6HEVHDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D32C8292EF
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 05:09:38 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-dbea39ed9f7sf4144567276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 20:09:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704859772; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pa0rIKtlyLnVt6PO1GTuVpBQ9t7asibh4pgKGQblg9iYYqFKWpbofcX1Nr9E6gL3vd
         D6+0+gd/m8JyRXufMIgcHw+/ZAHGaosa/2kqUHU/ntIb8UPpY0N6dsPkUqPK+S6si00s
         AsmBEW6GQ57DY8cwRnopy5uFeRymBtC6olCaAd941fWXhso/UNjAbGMMVMwuBFwJjiPh
         cRVo2WdT592Z3t/CsJ+VTjgojKFTxzurqUapCXjMpHNjsw3UZkzBqooj7tSKXfY7xz+P
         M6VDFMnK4qAaWju1gDwaxo4YU13B6kFcfpwyyKUNeWmjGtZ/jVzkfsTSu4EzMFNZ8rfy
         aphA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=agtfpZN5b/njbfK48ZzxWGwoUzoedYIjVnUYOV/VJfA=;
        fh=19QRHzWtwJBysBWqhACwuwtJqFcvHTK5MOXxC0X1NmY=;
        b=aauCqc7WAZlx+gYhseQHe39Bo80fxwYT/N33HaUrnIHV4/Fcw4Jq5WtFTfwi4G1syv
         8yaaUMiZQurDjR/yxqNdRa6mkBZJXUVYzb+qOfG3V8G1dAyfPJsMuESIwZ1y4cU8VAlY
         lJM4OBP84vEreyXYNxFVU/bNtKd7QQ0i8dPZuKjyOROE8055R59hiXj3uWoTGW0p+eBj
         2PWpDAT8Q8slPMSVz7DKQU1qIDuCdBxrsaCr+ilRlXya+7ZFdW/8YPf1jqEn6RHGQOjJ
         Bc5kA3lJFnJRqxkvXnOFJTKUxzcvyOVCUkpOCdTsLiEVI+8gKaecvqhPtA59fPY1kUWC
         pk1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fiEa4OsP;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704859772; x=1705464572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=agtfpZN5b/njbfK48ZzxWGwoUzoedYIjVnUYOV/VJfA=;
        b=rhNQ5Iazgaq4xkxnQX6yTq0EncJ+vZy8jLoNuU2CY/24Xnes9nJDrHLYC880JbyHnl
         GfqDP0FDS3p2M8XOUDs8c9MLFZqA13UJ2HewcqTL9jDab0yuDwwRKJB3leYDZYd7Nufh
         8TSsL6UI9pgmaFU/4CFecLvmZbMCj6x2mAJAqJDKTFzYGf9A5LSbQ3FnknCJZwCHkftH
         ZknqoLIpKtRNhAykFYcm0HC851i1mweVXtnZ0NHIUV0V6jYcoya1Y1XURTQe+LwkJm9/
         cV9HR2Kkuxd2ALSWpS/f3SLpF3SXIqzcrK//3uRTfVrmMy041Pdm08x2ogHpg5lByBWG
         h4vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704859772; x=1705464572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=agtfpZN5b/njbfK48ZzxWGwoUzoedYIjVnUYOV/VJfA=;
        b=qjbqxssp+zEWciEBerQ1F4GNU9n18R/BilJO5I3ZnhOUS0EV1aEbfSsP/2DebrdHfZ
         lIcyKpbMh3Zpr9M+y3L0fhY0j0ryj5QAFyDwrEMlHOqf1u4T8S4Aqovs02Z9xB1RaTRC
         jEvWnPw+WgljBrImEunv4GJNhHkGnsUf/WAq1qZLa1udYLv4dxW/1PstpsVHewOwM5wT
         cch4BXCqpr09mOvytetrDA2Ea8CSnr+AG4Bbe1PiO1XB+I3mlw9seaEPY2+2ukaExFL7
         swXGpskHy0J7L3kaLcWKqISQGlx/bDkKHYzUC2quFH+Ms7bg3JUaOFOMd2vh1LJog/UG
         amNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzPUT+WMrOTSEW92kSt9ksH9F9tF5GV0CDnfpWxjUGZZg1MT2Js
	n1WK8grjJgKzj8iRPnWwHMw=
X-Google-Smtp-Source: AGHT+IGW5WtIBy8XEb8IKLLN/csPfb2ZEIqFzEsV4gef3wyt3pe7dXWpOTXmBaLjUvmZy1joEmAbhQ==
X-Received: by 2002:a25:f628:0:b0:dbe:a335:1dad with SMTP id t40-20020a25f628000000b00dbea3351dadmr297795ybd.57.1704859772179;
        Tue, 09 Jan 2024 20:09:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d0ce:0:b0:dbe:9c83:a084 with SMTP id h197-20020a25d0ce000000b00dbe9c83a084ls2142610ybg.1.-pod-prod-04-us;
 Tue, 09 Jan 2024 20:09:31 -0800 (PST)
X-Received: by 2002:a81:57cc:0:b0:5fa:31c0:9851 with SMTP id l195-20020a8157cc000000b005fa31c09851mr341093ywb.70.1704859771367;
        Tue, 09 Jan 2024 20:09:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704859771; cv=none;
        d=google.com; s=arc-20160816;
        b=L6jpNOQ69csU/zgGZu8UcdBBmljgotSCyXy9SVdt8Gtt2uV37MVF1U/t3DqAl98p4I
         KNOBqalTyZLcVMfJkkKNiySoR5h0xHi15+igOjJZV0+3jJYsD5qZNGoViPHIqJzdf8C2
         7tsSObWZqxGGOgEchJwWGKhNPRV5uYiH/FEL93gr/BqVIEqI1PO/3fs0oBdbNpRpXt8P
         r6x1XduZNlKDxKKNMiwydLMMV+xp4+CkzYDUmIIhLPHyUMnDto5ip3UOtu/XtyhzkBr5
         oZzL7GnERIIQt6XB6jopUllCK3TlrfJUSfpD+ABKb+GWGbcT25yQlxGCQ/+6AAMgKfpG
         n+JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=PN/94FNaJE5gXuuzukilNXUTnIvClfuno9VY3Eps0R8=;
        fh=19QRHzWtwJBysBWqhACwuwtJqFcvHTK5MOXxC0X1NmY=;
        b=Qebd2XAD49MDd0ZuwWo2MF4ROso25p6/RPw6n1YpG1zpK5aoMW3AOmedtTidthMQkz
         AKGtvNhN5IecVRdDr6D1/HkSjGPYAxYaLc3bV47hxKnzWcanzLrgKLrqnRMffuEzViGj
         L9Yo06rt67c9v0ptv3WOjiX5BZpjXeOrv5u/plx1iiijM7yJOj6IlFCuzkaA14OIyc/1
         swkQ4AOjrC/CcTrWOIlQYOQ6j1QYZMQ68R8Gw8Qdz4lA7SQEA6rnOvN5HlpmpsFDCvYw
         aebIcQx/HnTUlye59kyX8XefQq0e+p80Wq4X84oKgx7Kvw9cOY25A/8CT0D1HOHxQ82l
         PTmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fiEa4OsP;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u206-20020a0debd7000000b005ee5e3c6d2fsi305519ywe.1.2024.01.09.20.09.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jan 2024 20:09:31 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 40A1qbdo008950;
	Wed, 10 Jan 2024 04:09:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vhhxytac6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 04:09:24 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 40A41KHw022734;
	Wed, 10 Jan 2024 04:09:23 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vhhxytabj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 04:09:23 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 40A3AoRI000893;
	Wed, 10 Jan 2024 04:09:22 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vfkdkansb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 04:09:22 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 40A49KhL24707790
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Jan 2024 04:09:20 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AA8B420043;
	Wed, 10 Jan 2024 04:09:20 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C835E20040;
	Wed, 10 Jan 2024 04:09:19 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 10 Jan 2024 04:09:19 +0000 (GMT)
Received: from [10.61.2.106] (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 845DE60218;
	Wed, 10 Jan 2024 15:09:17 +1100 (AEDT)
Message-ID: <55c57f88-9975-4510-b6bc-7e78462e0a62@linux.ibm.com>
Date: Wed, 10 Jan 2024 15:09:17 +1100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 12/13] powerpc/string: Add KMSAN support
Content-Language: en-US
To: Christophe Leroy <christophe.leroy@csgroup.eu>,
        "glider@google.com" <glider@google.com>,
        "elver@google.com"
 <elver@google.com>,
        "dvyukov@google.com" <dvyukov@google.com>,
        "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
        "mpe@ellerman.id.au" <mpe@ellerman.id.au>,
        "npiggin@gmail.com" <npiggin@gmail.com>
Cc: "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
        "iii@linux.ibm.com" <iii@linux.ibm.com>,
        "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-13-nicholas@linux.ibm.com>
 <2f35548a-bdbd-4c37-8f60-cebeb381a7af@csgroup.eu>
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
In-Reply-To: <2f35548a-bdbd-4c37-8f60-cebeb381a7af@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Z0gqHeXQBF-DTvYR8mq_KFNHfNuG0Tvm
X-Proofpoint-ORIG-GUID: 7207fUxSVPuK1YLYSW2F-TQqKjaebXMm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-09_13,2024-01-09_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 phishscore=0 impostorscore=0 lowpriorityscore=0 malwarescore=0 spamscore=0
 adultscore=0 bulkscore=0 mlxlogscore=999 mlxscore=0 suspectscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401100031
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fiEa4OsP;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=nicholas@linux.ibm.com;       dmarc=pass (p=REJECT
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



On 14/12/2023 8:25 pm, Christophe Leroy wrote:
>=20
>=20
> Le 14/12/2023 =C3=A0 06:55, Nicholas Miehlbradt a =C3=A9crit=C2=A0:
>> KMSAN expects functions __mem{set,cpy,move} so add aliases pointing to
>> the respective functions.
>>
>> Disable use of architecture specific memset{16,32,64} to ensure that
>> metadata is correctly updated and strn{cpy,cmp} and mem{chr,cmp} which
>> are implemented in assembly and therefore cannot be instrumented to
>> propagate/check metadata.
>>
>> Alias calls to mem{set,cpy,move} to __msan_mem{set,cpy,move} in
>> instrumented code to correctly propagate metadata.
>>
>> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
>> ---
>>    arch/powerpc/include/asm/kmsan.h               |  7 +++++++
>>    arch/powerpc/include/asm/string.h              | 18 ++++++++++++++++-=
-
>>    arch/powerpc/lib/Makefile                      |  2 ++
>>    arch/powerpc/lib/mem_64.S                      |  5 ++++-
>>    arch/powerpc/lib/memcpy_64.S                   |  2 ++
>>    .../selftests/powerpc/copyloops/asm/kmsan.h    |  0
>>    .../selftests/powerpc/copyloops/linux/export.h |  1 +
>>    7 files changed, 32 insertions(+), 3 deletions(-)
>>    create mode 100644 tools/testing/selftests/powerpc/copyloops/asm/kmsa=
n.h
>>
>> diff --git a/arch/powerpc/include/asm/kmsan.h b/arch/powerpc/include/asm=
/kmsan.h
>> index bc84f6ff2ee9..fc59dc24e170 100644
>> --- a/arch/powerpc/include/asm/kmsan.h
>> +++ b/arch/powerpc/include/asm/kmsan.h
>> @@ -7,6 +7,13 @@
>>    #ifndef _ASM_POWERPC_KMSAN_H
>>    #define _ASM_POWERPC_KMSAN_H
>>   =20
>> +#ifdef CONFIG_KMSAN
>> +#define EXPORT_SYMBOL_KMSAN(fn) SYM_FUNC_ALIAS(__##fn, fn) \
>> +				EXPORT_SYMBOL(__##fn)
>> +#else
>> +#define EXPORT_SYMBOL_KMSAN(fn)
>> +#endif
>> +
>>    #ifndef __ASSEMBLY__
>>    #ifndef MODULE
>>   =20
>> diff --git a/arch/powerpc/include/asm/string.h b/arch/powerpc/include/as=
m/string.h
>> index 60ba22770f51..412626ce619b 100644
>> --- a/arch/powerpc/include/asm/string.h
>> +++ b/arch/powerpc/include/asm/string.h
>> @@ -4,7 +4,7 @@
>>   =20
>>    #ifdef __KERNEL__
>>   =20
>> -#ifndef CONFIG_KASAN
>> +#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
>>    #define __HAVE_ARCH_STRNCPY
>>    #define __HAVE_ARCH_STRNCMP
>>    #define __HAVE_ARCH_MEMCHR
>> @@ -56,8 +56,22 @@ void *__memmove(void *to, const void *from, __kernel_=
size_t n);
>>    #endif /* CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX */
>>    #endif /* CONFIG_KASAN */
>>   =20
>> +#ifdef CONFIG_KMSAN
>> +
>> +void *__memset(void *s, int c, __kernel_size_t count);
>> +void *__memcpy(void *to, const void *from, __kernel_size_t n);
>> +void *__memmove(void *to, const void *from, __kernel_size_t n);
>> +
>=20
> The same is done for KASAN, can't you reuse it ?
>=20
I tried this but I believe it makes the file more disorganised and=20
difficult to edit since there ends up being a set of definitions for=20
each intersection of features e.g. the definitions needed for both KASAN=20
and KMSAN, just KASAN, just KMSAN, etc.

This way it's clearer what each sanitizer needs and changing definitions=20
for one one sanitizer won't require refactors affecting other sanitizers.

>> +#ifdef __SANITIZE_MEMORY__
>> +#include <linux/kmsan_string.h>
>> +#define memset __msan_memset
>> +#define memcpy __msan_memcpy
>> +#define memmove __msan_memmove
>> +#endif
>=20
> Will that work as you wish ?
> What about the calls to memset() or memcpy() emited directly by GCC ?
>=20
These are handled by the compiler instrumentation which replaces these=20
with calls to the instrumented equivalent.

>> +#endif /* CONFIG_KMSAN */
>> +
>>    #ifdef CONFIG_PPC64
>> -#ifndef CONFIG_KASAN
>> +#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
>>    #define __HAVE_ARCH_MEMSET32
>>    #define __HAVE_ARCH_MEMSET64
>>   =20
>> diff --git a/arch/powerpc/lib/Makefile b/arch/powerpc/lib/Makefile
>> index 51ad0397c17a..fc3ea3eebbd6 100644
>> --- a/arch/powerpc/lib/Makefile
>> +++ b/arch/powerpc/lib/Makefile
>> @@ -32,9 +32,11 @@ obj-y +=3D code-patching.o feature-fixups.o pmem.o
>>    obj-$(CONFIG_CODE_PATCHING_SELFTEST) +=3D test-code-patching.o
>>   =20
>>    ifndef CONFIG_KASAN
>> +ifndef CONFIG_KMSAN
>>    obj-y	+=3D	string.o memcmp_$(BITS).o
>>    obj-$(CONFIG_PPC32)	+=3D strlen_32.o
>>    endif
>> +endif
>>   =20
>>    obj-$(CONFIG_PPC32)	+=3D div64.o copy_32.o crtsavres.o
>>   =20
>> diff --git a/arch/powerpc/lib/mem_64.S b/arch/powerpc/lib/mem_64.S
>> index 6fd06cd20faa..a55f2fac49b3 100644
>> --- a/arch/powerpc/lib/mem_64.S
>> +++ b/arch/powerpc/lib/mem_64.S
>> @@ -9,8 +9,9 @@
>>    #include <asm/errno.h>
>>    #include <asm/ppc_asm.h>
>>    #include <asm/kasan.h>
>> +#include <asm/kmsan.h>
>>   =20
>> -#ifndef CONFIG_KASAN
>> +#if !defined(CONFIG_KASAN) && !defined(CONFIG_KMSAN)
>>    _GLOBAL(__memset16)
>>    	rlwimi	r4,r4,16,0,15
>>    	/* fall through */
>> @@ -96,6 +97,7 @@ _GLOBAL_KASAN(memset)
>>    	blr
>>    EXPORT_SYMBOL(memset)
>>    EXPORT_SYMBOL_KASAN(memset)
>> +EXPORT_SYMBOL_KMSAN(memset)
>>   =20
>>    _GLOBAL_TOC_KASAN(memmove)
>>    	cmplw	0,r3,r4
>> @@ -140,3 +142,4 @@ _GLOBAL(backwards_memcpy)
>>    	b	1b
>>    EXPORT_SYMBOL(memmove)
>>    EXPORT_SYMBOL_KASAN(memmove)
>> +EXPORT_SYMBOL_KMSAN(memmove)
>> diff --git a/arch/powerpc/lib/memcpy_64.S b/arch/powerpc/lib/memcpy_64.S
>> index b5a67e20143f..1657861618cc 100644
>> --- a/arch/powerpc/lib/memcpy_64.S
>> +++ b/arch/powerpc/lib/memcpy_64.S
>> @@ -8,6 +8,7 @@
>>    #include <asm/asm-compat.h>
>>    #include <asm/feature-fixups.h>
>>    #include <asm/kasan.h>
>> +#include <asm/kmsan.h>
>>   =20
>>    #ifndef SELFTEST_CASE
>>    /* For big-endian, 0 =3D=3D most CPUs, 1 =3D=3D POWER6, 2 =3D=3D Cell=
 */
>> @@ -228,3 +229,4 @@ END_FTR_SECTION_IFCLR(CPU_FTR_UNALIGNED_LD_STD)
>>    #endif
>>    EXPORT_SYMBOL(memcpy)
>>    EXPORT_SYMBOL_KASAN(memcpy)
>> +EXPORT_SYMBOL_KMSAN(memcpy)
>> diff --git a/tools/testing/selftests/powerpc/copyloops/asm/kmsan.h b/too=
ls/testing/selftests/powerpc/copyloops/asm/kmsan.h
>> new file mode 100644
>> index 000000000000..e69de29bb2d1
>> diff --git a/tools/testing/selftests/powerpc/copyloops/linux/export.h b/=
tools/testing/selftests/powerpc/copyloops/linux/export.h
>> index e6b80d5fbd14..6379624bbf9b 100644
>> --- a/tools/testing/selftests/powerpc/copyloops/linux/export.h
>> +++ b/tools/testing/selftests/powerpc/copyloops/linux/export.h
>> @@ -2,3 +2,4 @@
>>    #define EXPORT_SYMBOL(x)
>>    #define EXPORT_SYMBOL_GPL(x)
>>    #define EXPORT_SYMBOL_KASAN(x)
>> +#define EXPORT_SYMBOL_KMSAN(x)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/55c57f88-9975-4510-b6bc-7e78462e0a62%40linux.ibm.com.
