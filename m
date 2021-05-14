Return-Path: <kasan-dev+bncBDCPRA4X5IERBDVS7GCAMGQE5T7ENJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D2F4380803
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 13:03:43 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id v21-20020a5d90550000b0290439ea50822esf11070055ioq.9
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 04:03:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620990222; cv=pass;
        d=google.com; s=arc-20160816;
        b=WHzyoSlbmnt08DwvxzVTVr5lNS1OL1Q4LPztLmWs2CFG3tT6HSteS2rlav+/blc79n
         3ZQGoMtcIbt04kcwGezyUICAG8E+G2k/lz1F/4kjx4osp58RFOpx0EO9Azq0AgIZ3htV
         Z/XsDzgBUbi4al+/lYcXZSnapX+Tf14Wz7nairSvk4mDxIB8hML7LIb1q+5J3oN/v2tC
         uWqtnkTw8Lprpnj8G6ogvBhfiZ2+PhNPpRFzG1gtoCMPAh+K/+9ZIZaxWJ3uZt0/uxB0
         2qHRo3clwxr3fDkO9VURz4Wbe1GCBfZlTdBSNkbyMqus/DVXAGvBH2aEOfa7VDivdwGe
         K4Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=PyWIf9RB8StFiD7wnGHWfe9yjk89gz03KtnAt84nV9U=;
        b=kgeQo6WrtzMR5hREsq+uYqbtA4Q68ae/uXcbV3k3yEj8KrzNy0HqajDywnaM/g4ccJ
         ofwYV+tPXxJ/+Nj1iZ8V0tBF6NSm2XyKTvqU04vWB6bqHy6uSLxkRJaHxDDmLKF7EHPY
         ABZEPSBMpZgtIXi9oaWx5CAOFFM0YHP+H22ZkIzAz2NTc+KNqON9rOX4EtjjKWaNxIZa
         FOIjnokwBSFmv6TUvHMVUJRV+zJWkVHtoZEMfJ8MXES2dHHpI/kcnRVuKpTfmvoaY7zS
         eI56iWjMjhnuyqmub4uVx+qL+p+gLAUEgUdTTiK83d0IMFLzXEJz+C9d4RaA9nVGGsOm
         JyHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qMfSAkl3;
       spf=pass (google.com: domain of svens@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=svens@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PyWIf9RB8StFiD7wnGHWfe9yjk89gz03KtnAt84nV9U=;
        b=bgu2rJv+2GqXMFK+zmZ/4KQjq1aHKC5OhZKjqlWM/X7K5tI/0+BSjwgMJng0mCNda6
         c3IvlcatwXBZCVAJiS4QpxP9LTLVMFY7Q6TrhXM5D/ECxtmANtP7MOHQ1KtKZgai9eJ6
         /oB0I2FIwIZ8gdc7Axkc16GqLZbW8UmIb670v5A32g6X39223Rr7GNP2Fgshna6KmaLz
         20xWWOsIkcciEk8r4x1cP9T5J0TX9apH//Sl+CRM9OJ0bRf83VP149lNXKUAMqvCqoaQ
         lWFOwiIkSZmk+k8WGo1rRQrYnF33iZIneMdQ+x1OUtvCRrjboHMlJVe6AVDld2/ytu0T
         dwFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PyWIf9RB8StFiD7wnGHWfe9yjk89gz03KtnAt84nV9U=;
        b=UKFWOa9pEuAQ6kI09Ilze2esJmt95+3WLqLrGp7Ybl18/T2iUFpuLvYnYfYKYjA9eU
         OjeOWd9Hs5zAsSF4cptqHMvU4spmI/REzUskEecgMnUBVXVCePLdlmBSCnKVIasi7F7L
         Z1CWqqJ6wpOT3Zn47mFcWDe8BJ5gxktXY7QKG0GEssshgMvHMW2k95TTkXYAKrYW+CWB
         5oLE48SYOqTYKwtWy+2OWALKFWoONE3Sq332N7TVeENtlXmT2uVEKf+9H25iOf+kHXi2
         GOERc0yWoNvPJxw7V9Yt9uui5qgsdxu+KzgtiYAQ92x3qFWZ5WqTzMlmT7g0UPGklG5e
         0wDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532qpfms24mZqtSS9qa7bQ1dmX8dIKVN5b/YJvJWShQ8WWue0Szh
	yQcCUUJauDFayvaQVpiOwe4=
X-Google-Smtp-Source: ABdhPJy3iXVeb6E/4o/xCxwv59BTIL3HTisHwNixkNlosd/P37knHxNQ5PeJoXlD49Cv0MHfOuj9MA==
X-Received: by 2002:a5e:8c11:: with SMTP id n17mr25667961ioj.53.1620990222143;
        Fri, 14 May 2021 04:03:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:c00c:: with SMTP id u12ls1332330iol.7.gmail; Fri, 14 May
 2021 04:03:41 -0700 (PDT)
X-Received: by 2002:a5e:a619:: with SMTP id q25mr30681452ioi.95.1620990221814;
        Fri, 14 May 2021 04:03:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620990221; cv=none;
        d=google.com; s=arc-20160816;
        b=0x76jh/PRPUWF7FkpUaALhWGym/vzAG5BsWGNaN8PmOqBdKZvTUkFOESI/qZsS6cw2
         pxYdkGW+88GeXz10u6d4nXbiKK9zzoHwiyvkZ+qOBAFU6V3q9y5x4U/cGaU1vAojX9Qg
         KukDGCWwnXaJ6C2ksmPFQHl5v7nUQxpBzHmLgkN2vovIsyH3tML5330oBZWU4doilkX0
         7L706SjEF1Vggl/P3PgoOwlkVmVtyPnC9iRfWJD0RJqEokrjOHRwsNpll3GwiN4nc78y
         GdwYyJBe1uTIOqQB8SHPZYSz+b2TiGAH/JTTqHcd3LcUx35cVA6c29VI1pTEagdrMM6c
         u5YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature;
        bh=trM4RvVKWsggwPkZQfHTLqfcekUi7iRQiTHlwo0qPQQ=;
        b=N3Kdw8Dz3i2gOPfCF7FVBeWKlMkTbxVTEZZfDdZGaLvsx5I344KcEin4YdeSHQyYI8
         VwXd/xNkf/45D8NyjSlx2ShGIZV7Vz+JVht9AKKMEJVySq/RcFg23FvJzqp0m5cQt94i
         haZZR5kmnLFpM4vkmIyoho6pvbk1Z/zDeGAQ7Hrs7lhseZHhjXbX4Hd6aqSip+z11aHi
         ebKsy0tGGyJf0WztYlZbjSGsLK1LHJbk8Fr1/VopbrF44WCwU5djQO+hrdkpR8AG3mXR
         78+pqBOk44balAqF1+Ya/sSUsK8pHVe/KLfONUkCKXN7v59vBOjUkSntcZbwQuMjH9jw
         hQ9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qMfSAkl3;
       spf=pass (google.com: domain of svens@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=svens@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y9si424695ill.1.2021.05.14.04.03.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 04:03:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of svens@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0098417.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 14EB2oTQ066963;
	Fri, 14 May 2021 07:03:41 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 38hj2xyv26-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 14 May 2021 07:03:41 -0400
Received: from m0098417.ppops.net (m0098417.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 14EB38E0069351;
	Fri, 14 May 2021 07:03:40 -0400
Received: from ppma01fra.de.ibm.com (46.49.7a9f.ip4.static.sl-reverse.com [159.122.73.70])
	by mx0a-001b2d01.pphosted.com with ESMTP id 38hj2xyv1d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 14 May 2021 07:03:40 -0400
Received: from pps.filterd (ppma01fra.de.ibm.com [127.0.0.1])
	by ppma01fra.de.ibm.com (8.16.0.43/8.16.0.43) with SMTP id 14EB3cG3013243;
	Fri, 14 May 2021 11:03:38 GMT
Received: from b06cxnps4074.portsmouth.uk.ibm.com (d06relay11.portsmouth.uk.ibm.com [9.149.109.196])
	by ppma01fra.de.ibm.com with ESMTP id 38hc6u84fd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 14 May 2021 11:03:38 +0000
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (b06wcsmtp001.portsmouth.uk.ibm.com [9.149.105.160])
	by b06cxnps4074.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 14EB3aoo27394458
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 14 May 2021 11:03:36 GMT
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F360CA4054;
	Fri, 14 May 2021 11:03:35 +0000 (GMT)
Received: from b06wcsmtp001.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C29EDA405C;
	Fri, 14 May 2021 11:03:35 +0000 (GMT)
Received: from tuxmaker.linux.ibm.com (unknown [9.152.85.9])
	by b06wcsmtp001.portsmouth.uk.ibm.com (Postfix) with ESMTPS;
	Fri, 14 May 2021 11:03:35 +0000 (GMT)
From: Sven Schnelle <svens@linux.ibm.com>
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
        kasan-dev
 <kasan-dev@googlegroups.com>,
        Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH 1/2] kfence: add function to mask address bits
References: <20210514092139.3225509-1-svens@linux.ibm.com>
	<20210514092139.3225509-2-svens@linux.ibm.com>
	<CANpmjNNB=KTDBb65qtNwrPbwnbD2ThAFchA1HSCg9HKETkQvCg@mail.gmail.com>
Date: Fri, 14 May 2021 13:03:35 +0200
In-Reply-To: <CANpmjNNB=KTDBb65qtNwrPbwnbD2ThAFchA1HSCg9HKETkQvCg@mail.gmail.com>
	(Marco Elver's message of "Fri, 14 May 2021 12:54:11 +0200")
Message-ID: <yt9dfsypinlk.fsf@linux.ibm.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/28.0.50 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: WLxwDTnW79MZMK5F4j3qlMRIvVaEa87j
X-Proofpoint-GUID: rik4xugDhTQ30p5phi8M9e28La1f_tPy
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.761
 definitions=2021-05-14_04:2021-05-12,2021-05-14 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1011 suspectscore=0
 bulkscore=0 adultscore=0 spamscore=0 impostorscore=0 mlxscore=0
 mlxlogscore=999 malwarescore=0 lowpriorityscore=0 phishscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2104190000 definitions=main-2105140085
X-Original-Sender: svens@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=qMfSAkl3;       spf=pass (google.com:
 domain of svens@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=svens@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

Marco Elver <elver@google.com> writes:

>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index e18fbbd5d9b4..bc15e3cb71d5 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -50,6 +50,11 @@ static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE
>>  #endif
>>  #define MODULE_PARAM_PREFIX "kfence."
>>
>> +unsigned long __weak kfence_arch_mask_addr(unsigned long addr)
>> +{
>> +       return addr;
>> +}
>
> I don't think this belongs here, because it's test-specific,
> furthermore if possible we'd like to put all arch-specific code into
> <asm/kfence.h> (whether or not your arch will have 'static inline'
> functions only, like x86 and arm64, or not is up to you).
>
> Because I don't see this function being terribly complex, also let's
> just make it a macro.
>
> Then in kfence_test.c, we can have:
>
> #ifndef kfence_test_mask_address
> #define kfence_test_mask_address(addr) (addr)
> #endif
>
> and then have it include <asm/kfence.h>. And in your <asm/kfence.h>
> you can simply say:
>
> #define kfence_test_mask_address(addr) (.........)
>
> It also avoids having to export kfence_test_mask_address, because
> kfence_test can be built as a module.
 
Ok, i'll change my patch accordingly. Thanks!

Sven

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/yt9dfsypinlk.fsf%40linux.ibm.com.
