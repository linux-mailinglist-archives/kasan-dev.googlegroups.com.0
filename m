Return-Path: <kasan-dev+bncBDXL53XAZIGBBENDXDEAMGQEFFPJ5HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id DD813C409AB
	for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 16:34:45 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-341616a6fb7sf1262447a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 07:34:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762529682; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q4zVKujeMOQKzt0iLzMqO9Ly+dAOMTllm70yJ63LWHg7INKrZyAuyMuzgZb6yDs/vc
         UKlSEE0OUDYf7aTk3hjQ6rdP/ddRrJEAwetGB6/XZIE3DFE0WnIPoC44g5HGyXEz8kt/
         IZov+mhViIsD6unROwPare2wxm0VSroZbtLPpg6e03AnjyW/WkoB6wffBtWLUksL/rt9
         8MdgTH2Ubf9vDOA6M4/+Z/3L4qxYDMDNEJaHw0nt2RHDV3Rrn5JoWQr/eJzrlQHErRMY
         WGELfns5B0IatlmCAbo7Mz0FpVoUc31r4zL7TckDf5eU46kULUz+lrGTqe6jxWG+JRUz
         hykQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=KqHelj0EKookYkcPF1hdyaZddfz6NUHjhfjrv6mlKT4=;
        fh=bzvmrPMEvPVBBRCJf46i4IwaMzeYFFYi95yDR8FHYg4=;
        b=fEGu7S7oBC+NJKd05ZhvCkVvCgV/YYFMW55frdc2yUEheyFyaVtFqyG5UiHsBXH6GN
         GVOwgvUXXhRxvQg8WRB0wxM5sb5h6EWJoMfQkR2XPUxPXSawrQ3G6hPIV27Y8yYnXvJN
         TBmwRXK43UGsAty0FtTVOAby9472cCpRJRuLlwUbgOG5caKgXYBJIrcG7/wyyshp9dVB
         KDw5YrR6HpezO9REwWPhW1nni8MPlVtOR6SeLmmbhlT0IOF4+MiZYxCkvdLERBJGNrvs
         njFcX3ZsFmnVD2aPkX9Yn2AE4m1vDPi9rZ0cI4kSmTVEOBT6kv/PnqKLD9n1vVk6hNRj
         vvaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DmR+SrlZ;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762529682; x=1763134482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KqHelj0EKookYkcPF1hdyaZddfz6NUHjhfjrv6mlKT4=;
        b=F/7R1GxqqCzXbopZnDjgROcXx2L3zm12hmEacVoPpMUcqiQigkyPqHf1G1tFiAVEdo
         4rj5c7oiq7rf3zPXP1ysfThNvht6yvoq2det2NDrRiDeKi+2xZUBr4Rql9bE/bkcfwnJ
         rlpxuiC6RKY1MBaVoohEj2Ry6ITj3JRBpbnFDTCTWdsoX89upKMF59OUwTHOT5isgEwg
         UUJujlH/IlAuYY0Yr8+Z9qCTuo6wg+mE31AL9kbnNWoCRCc4hOyttL2Y9LhIMNW72SyY
         k44QARSQ6hJYuLmOH05EyAsAANMWYiztXr8H3uR59fHThq3fY3EwcuCifoDrcseP5oXx
         mVYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762529682; x=1763134482;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KqHelj0EKookYkcPF1hdyaZddfz6NUHjhfjrv6mlKT4=;
        b=mBLimonBBQDoXkTU7FpodA7qxs7h6lSKrM5O58B4h76ZA2kI2XpS6JWZhKbFLig5fl
         /EOFAMD8wKVELZ+gNscKKPmPdnNOuw4p5WrqIs/WdFB8MWfc/24cZdqq85CncrrXifQi
         4YRQf+aFQAMG0k4JPmQzSh87Cb0ru/F+m4/AURqoLQaooj567fEXSXKF6gU2J9D4g4cL
         0cOYxxT05f+9Y/i7hniR0Wq6CBtPI6OWotp7IyGVYNtxLuS/nsth3qkLnvbnMbBRyAXg
         wRACkik7SEcKoLUZUy2xWs/CJ40nqPJvpR42whSBgK2tFjqABjkfiRY1vVOQ8B577I2K
         pnWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdZwjhF4jt67ud8uTvoCYv0iPRQ3R4te6y8TMhlmQ51mimh1LDTASjDlKwF2DeauaZNeWnVA==@lfdr.de
X-Gm-Message-State: AOJu0Yy0TlEOoMJlVqPSPegJw8bm3iuJnKsA0foxtHypbpKGVgH07S/U
	NW+xL+zIMNkFT5w/gSNOaffzJtr4VdQfBM7jJDV2tWOyTN6q0JSyj/5H
X-Google-Smtp-Source: AGHT+IHrQnDldE0Hab/RA3/TafRAxqxwH+rMGMP7tHUTVckCg+G8nQbe5fNhcSjhVjrp/vMfULN0ow==
X-Received: by 2002:a17:90b:2fcf:b0:340:b572:3b7d with SMTP id 98e67ed59e1d1-3434c54966cmr4520950a91.19.1762529681636;
        Fri, 07 Nov 2025 07:34:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b6cvoRDanBULFKa7iMH8/djC3V0eZMaozego7L+Sfs6Q=="
Received: by 2002:a17:90a:1049:b0:340:f807:a7b2 with SMTP id
 98e67ed59e1d1-341cd2b6468ls1880138a91.2.-pod-prod-04-us; Fri, 07 Nov 2025
 07:34:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWDO1j6uBRkg4iKIwvputz4eLodY3Pu7SiIwbhAUtJL9AqJxrbMrLrEs58HVNSi/1hptuB+O7c7vt4=@googlegroups.com
X-Received: by 2002:a17:90b:55cf:b0:33f:ebc2:643 with SMTP id 98e67ed59e1d1-3434c548d7emr3530132a91.23.1762529680018;
        Fri, 07 Nov 2025 07:34:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762529679; cv=none;
        d=google.com; s=arc-20240605;
        b=chZrqHwDTB8+jZXmRcxybXDbqqijZMz9seF/K+7ALKZTOlR/9nbu09T9FBn4/CRZmW
         ooseNXBIBhRtO1icsDuLc23rzuBjCs/6hs3nPLDzAxfmMIuLGhDpFgxoNIs0iNCTvAJT
         nQXxHmIvHuLVm3qxmZzWaP4KRQQcLDBhnWSVv4RRs/2/YYxZmdXrPK9NIB58tX4qMRAH
         qAQvTp+ubNsHBDfz6ystz+ay1Zmd9Qdx/j9oJnFV48oHsvfbvVtfjB1EbqiymIPZnJ5Y
         g9SJqTIX1S1nPovCVVhVk/kJuBRWDTDGLJclRRmt23ULnFhRNqboVCouMQppOr31wXnH
         5t0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=YmobMJcsCJcwwI8/kU9x3dKjZAgMtB9UEjqodE7qgtQ=;
        fh=MyR2Vvw0dIHEvZcWLeDbz/8ZulxxJTLAiSX4Qd4qQTE=;
        b=SWyDzntJZri9aS1U9uctrSKMtr43c2eav/UOPTVnQYvZXB9+WF5RSvn886GM3Oocf+
         WpQescTuCuHVxMaFEUZhWP9SFqnFQBpygu2PKWDjYxHwgq/4UA73wLQKUlbHWzRdTkKG
         CG6M1elWY8wP6dtGgl5kJay/XHbm8pAFwLBOmWQSwjwJIepKZL9uJqdPtc6t6W9c7k0b
         JZSn1W5RvcnWzjF+M5xMA/8FOLMXo7szxBeYSkOYR7our7xHzt/kJS0R74JFGdG/zZAZ
         8Z0uojWqMfO8Cuht4SVa8XRGZ5UZPSpzq9LbmpMbkrVioSqJUdGLp97/5JcEzD87nHbi
         vhfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DmR+SrlZ;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-341d11e2611si55539a91.2.2025.11.07.07.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Nov 2025 07:34:39 -0800 (PST)
Received-SPF: pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5A7Esa9i030417;
	Fri, 7 Nov 2025 15:34:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a9jxmr7v7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 15:34:39 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5A7FX6mu020594;
	Fri, 7 Nov 2025 15:34:38 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a9jxmr7v3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 15:34:38 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5A7CTAXt021482;
	Fri, 7 Nov 2025 15:34:37 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 4a5xrk37jq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 07 Nov 2025 15:34:37 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5A7FYYFb52167018
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 7 Nov 2025 15:34:34 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0097720043;
	Fri,  7 Nov 2025 15:34:34 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0222A20040;
	Fri,  7 Nov 2025 15:34:33 +0000 (GMT)
Received: from [9.111.68.113] (unknown [9.111.68.113])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri,  7 Nov 2025 15:34:32 +0000 (GMT)
Message-ID: <72ec25d5-e077-4a84-9eca-ce886e2aaffb@linux.ibm.com>
Date: Fri, 7 Nov 2025 16:33:40 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/2] s390/fpu: Fix kmsan in fpu_vstl function
To: Alexander Potapenko <glider@google.com>,
        Heiko Carstens <hca@linux.ibm.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        linux-s390@vger.kernel.org, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>,
        Juergen Christ <jchrist@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
References: <20251106160845.1334274-2-aleksei.nikiforov@linux.ibm.com>
 <20251106160845.1334274-6-aleksei.nikiforov@linux.ibm.com>
 <CAG_fn=WufanV2DAVusDvGviWqc6woNja-H6WAL5LNgAzeo_uKg@mail.gmail.com>
 <20251107104926.17578C07-hca@linux.ibm.com>
 <CAG_fn=W5TxaPswQzRYO=bJzv6oGNt=_9WVf2nSstsPGd5a5mNw@mail.gmail.com>
Content-Language: en-US
From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
In-Reply-To: <CAG_fn=W5TxaPswQzRYO=bJzv6oGNt=_9WVf2nSstsPGd5a5mNw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=BZvVE7t2 c=1 sm=1 tr=0 ts=690e118f cx=c_pps
 a=AfN7/Ok6k8XGzOShvHwTGQ==:117 a=AfN7/Ok6k8XGzOShvHwTGQ==:17
 a=IkcTkHD0fZMA:10 a=6UeiqGixMTsA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VnNF1IyMAAAA:8 a=ZY0oy1BPkzOObeRiG5MA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTA3MDEyMiBTYWx0ZWRfX1RZyKuD66vMJ
 eIa01JZb2JMXI/qy3VPM6vE5n8WCXkhlk7uNzUQ3CKuEowwO9zxk+mUQHNTenHEnZ+p6IGqc6XI
 lUSONTvT7bnW9zpujYYljr33v16OeLUdaS47nBkbkEawXqKMz+XDgEPAAfytDy3dTbxtxnDgrJW
 ovTJPyF1HIZj5T6PXTLwZtfN48J6n6gnrTiOCV8S5zcl4D6OLSQG40jW+WsojAHelO+5LE97xNY
 VW4Z6HZst5bBxX/cmR2T36OPbKrYqdy5hBbRAhKslspln/Fq07HojJBxxsdOJzYTmiXz3Rfoeo1
 /p7hLGZymH4A9y/e010XxdUHZrGjT/Book/aNbVF+ojiUDTZ1VdTdQ78J87+EjqUY4wXEmmM/cm
 wq98K0wWihWsN9KYPgB0EC/bfr9+Hg==
X-Proofpoint-GUID: 9qF3Hk4uKD18vkj_pkFjCP3ioH97AV6j
X-Proofpoint-ORIG-GUID: b4Vc7OTegufQwkjfSDN4buqtpdpRwd5v
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-07_04,2025-11-06_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 adultscore=0 spamscore=0 phishscore=0 suspectscore=0 clxscore=1015
 priorityscore=1501 malwarescore=0 impostorscore=0 bulkscore=0
 lowpriorityscore=0 classifier=typeunknown authscore=0 authtc= authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2510240000
 definitions=main-2511070122
X-Original-Sender: aleksei.nikiforov@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=DmR+SrlZ;       spf=pass (google.com:
 domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

On 11/7/25 14:32, Alexander Potapenko wrote:
> On Fri, Nov 7, 2025 at 11:49=E2=80=AFAM Heiko Carstens <hca@linux.ibm.com=
> wrote:
>>
>> On Fri, Nov 07, 2025 at 11:26:50AM +0100, Alexander Potapenko wrote:
>>> On Thu, Nov 6, 2025 at 5:09=E2=80=AFPM Aleksei Nikiforov
>>> <aleksei.nikiforov@linux.ibm.com> wrote:
>>>> @@ -409,6 +410,7 @@ static __always_inline void fpu_vstl(u8 v1, u32 in=
dex, const void *vxr)
>>>>                  : [vxr] "=3DR" (*(u8 *)vxr)
>>>>                  : [index] "d" (index), [v1] "I" (v1)
>>>>                  : "memory", "1");
>>>> +       instrument_write_after(vxr, size);
>>>>   }
>>>
>>> Wouldn't it be easier to just call kmsan_unpoison_memory() here directl=
y?
>>
>> I guess that's your call. Looks like we have already a couple of
>> kmsan_unpoison_memory() behind inline assemblies.
>>
>> So I guess we should either continue using kmsan_unpoison_memory()
>> directly, or convert all of them to such a new helper. Both works of
>> course. What do you prefer?
>=20
> Upon reflection, I think adding instrument_write_after() is not the best =
idea.
> For tools like KASAN and KCSAN, every write has the same semantics,
> and the instrumentation just notifies the tool that the write
> occurred.
> For KMSAN, however, writes may affect metadata differently, requiring
> us to either poison or unpoison the destination.
> In certain special cases, like instrument_get_user() or
> instrument_copy_from_user() the semantics are always fixed, but this
> is not true for arbitrary writes.
>=20
> We could make the new annotation's name more verbose, but it will just
> become a synonym of kmsan_unpoison_memory().
> So I suggest sticking with kmsan_unpoison_memory() for now.
>=20
>=20

I'll rework changes with that suggestion. Thank you.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
2ec25d5-e077-4a84-9eca-ce886e2aaffb%40linux.ibm.com.
