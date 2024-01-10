Return-Path: <kasan-dev+bncBAABBC5K7CWAMGQEHIGO7JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id C4E278292DF
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 04:54:53 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1d4d4501c72sf621385ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 19:54:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704858892; cv=pass;
        d=google.com; s=arc-20160816;
        b=m3VjXzUhcXjxuB+tXYroMLJDv2aaUakDs1YqHdzDcjbw47TxgSSoAgvpaKU0SPqZx7
         9FjBuEnwQM4+C4VtjIMbXKE3g0jdePyAdNqqvdshm97lNK7nI8F4K6wFXOTv+mRckJwH
         ykLbmXr/IV38xRavR4zFrOWo7ya0vdtajROHMu8dQKe4mMQ4JgNXs2PntfbnMZPTvuWl
         3+FsvwR7tPYXKMua8rQQwiyLVwnECLvnG91L1/KsPqae+fQMbALKmScvepC3CFPTXYtl
         C4LN4ZP8jPwWLXAz5xGVSC/0wXDseMdQAZKupFr1+JtHxfoB8C4e0vf8E9J3M8ham2KG
         7u+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=IfZ3gyV1E9IK5hgMJh5oOTPsTkFaJIM6ExlWlIa+SC0=;
        fh=19QRHzWtwJBysBWqhACwuwtJqFcvHTK5MOXxC0X1NmY=;
        b=ArMIaN0J3kjgeqEoDapS6qe/HLhXFWUN4sgEN9FxcezrrULaioaqc8KF7LwfvlNx3P
         6dbmcFmtKp2juvz6vHtE2TwhzMGPpsgH7xtV5T06AJ9Z60VKSPho5XmWGfEIPwXS0++8
         NorHmEOtbKAy9eDE57f9R6itpU6mrsR/zOBnBQglWPTGdIBiATq34iEwZhdNhf1OR/f8
         QCLG+2doc7muSztLGq1kUITmr/w0W7n3X+mmDEXZo5BOQdiaPhxrwaB4XVBSKtE46GB9
         NRMW1I6sqstgPJLa9H1rbeuHrWQS1qlDAwuJwrEpus99CczTxoJc40qfJWMJGjUca8cA
         tdtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pWydVyLK;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704858892; x=1705463692; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IfZ3gyV1E9IK5hgMJh5oOTPsTkFaJIM6ExlWlIa+SC0=;
        b=Z2KzjfCuSGVUAd2ljba+Walb+s4kvzI/TbEbKsEjCJWA/+qdykD3QvF0tgQSww5hGs
         2JbgWc6M5AwEhrAaPH+6VqUvUbOyi+6FAFhBiKiHP2RXVRmgASWLAuWZeFstWxKZ0oaQ
         E0bOrXB4XEpm9f3LKp20s0vPeliMZunfplOuOWcejWoxU6jjlGhFouKAqADGdf+T1652
         q3Xdw9TaTQRwHvmUzkEdT3OGq4w7LbZrazxA5jW/gIwvFu/1hVRwEDYLjXLa1Ql8ODBP
         5/boegFhZPBmcavp4OxPRRA0Vd+F4hHCD/A5o1IdkG3k5l3xqBcUXfTlNgWyrz5KHMBZ
         4HXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704858892; x=1705463692;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IfZ3gyV1E9IK5hgMJh5oOTPsTkFaJIM6ExlWlIa+SC0=;
        b=dG4WmAt7Wr13fwURcWckVMpsJKOMWvpeo6iEYIZX3OdlwNvsfyBF42kFCfv2a1EAL8
         gvY1vjZ7ffpVaSRHDfVDOAMTRjVOh1/Mi5tglE/u8hMt0fsK/br7BIcAF4I4H4Bbc161
         jciLAIAQgRF8MGC2Sw+UE9TLkP3n5vfaVPxS44YZ8CMMLrUDKAtZqFyFWZulCjFkENMk
         UwP+Y7gwJMxRKBY3aRKyvN6cObM1JYnCo6yHO9wOYFJqiyQDtJsSqGQyBgTbsw34ta1z
         WUCFqTldVHjJF6fKtNQuWy3HqHKKxHywshGD4lIw9vfJn4eulV1WwA10MLJ+S2Goh/hJ
         C15Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwxbnlDImgi+OFB1ohU8wocm+5CzZ/BCLTroWv4KA70Z7aRfRqa
	JMJ/0aDYQCnVBxdA88MdZ9E=
X-Google-Smtp-Source: AGHT+IGNBYTmsh9ueTu9s6Hireoe1fxGpdDfap5U2qmLXP5E2RdJ08Hgxq0ttvl3jcTp0vNoBk/8fw==
X-Received: by 2002:a17:902:ecc5:b0:1d4:4482:83c3 with SMTP id a5-20020a170902ecc500b001d4448283c3mr174445plh.16.1704858891885;
        Tue, 09 Jan 2024 19:54:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5313:b0:206:1f45:390e with SMTP id
 hx19-20020a056871531300b002061f45390els957353oac.1.-pod-prod-09-us; Tue, 09
 Jan 2024 19:54:51 -0800 (PST)
X-Received: by 2002:a05:6358:c3a4:b0:175:67e3:f9be with SMTP id fl36-20020a056358c3a400b0017567e3f9bemr298449rwb.31.1704858890942;
        Tue, 09 Jan 2024 19:54:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704858890; cv=none;
        d=google.com; s=arc-20160816;
        b=yhL9ycA4T7QVuXH5xpgcMhX2bbkoylPJXiyVENiW6LQwb5woOMH5XyOAijLLtzDDGo
         SyvOj0kOT2tSRsatUhXKBNui4gmqgthMk3e1m6EHQ1zBUADIjBQw10iW8mQ8OyGYLIcm
         cnH0DXjeger4rXqkL05BDVjQS4hC6GP1aQJCyK2Upksm6ke1Dxp1wP2GKscWxAjTOww4
         m53DQe3vMc0iUw/Eg759NgJrhTot/HQlWGKCEREgsb1EOMaZI7piU6WIDIqV78QCWjrV
         HzpamcteWkfMf4B/9kQ0aq2GkCt4P2LiuDVpV7uiSNENdRjKi6wYWkj8dyUb6NFSNnHr
         fcmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=pUVAfEd8UZ3Kgup8PAC9DYXLhqDnscMMx6ZISfm/AQk=;
        fh=19QRHzWtwJBysBWqhACwuwtJqFcvHTK5MOXxC0X1NmY=;
        b=viT+NZJl/YwMCFatebaYr+XDofp8PFGOI/IkqoFS9eeQvqvH9dG182PlyhSbSVf0JT
         k9FuGQM6LLkcrOV2FdE+g2vSphJF0JfTmd0amab9QT2V9RXyriUPFBzUivE4qKbUCYWy
         CzyrfJPIFOOvrnepT1d4Q9RTo0OHC6mYgpHPmTi2PaqFI8VWYqHaYkwMJ5RR9HcQ8HSe
         PI0EQLwU0j1iBOOQMICAyw3hwkPvKS1t7kPXQi0qUXR5h3ki3opbGQOd4f8FFIcUd8XG
         chPOWhjbSFUNRitEo+PTZW4PKX/LZIww8N1eGOukA+iTMcOfBvuzhT7x8GDhKPCAYahF
         qjmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pWydVyLK;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id h8-20020a170902f70800b001d495d75b56si270385plo.0.2024.01.09.19.54.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jan 2024 19:54:50 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 40A3okpQ001962;
	Wed, 10 Jan 2024 03:54:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vher165ge-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 03:54:42 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 40A3pPpm003780;
	Wed, 10 Jan 2024 03:54:42 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vher165g9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 03:54:42 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 40A1AjOq022793;
	Wed, 10 Jan 2024 03:54:41 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vfhjyk3m1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 03:54:41 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 40A3sdW728836314
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Jan 2024 03:54:39 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5229920043;
	Wed, 10 Jan 2024 03:54:39 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 87BE720040;
	Wed, 10 Jan 2024 03:54:38 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 10 Jan 2024 03:54:38 +0000 (GMT)
Received: from [10.61.2.106] (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id F126560218;
	Wed, 10 Jan 2024 14:54:33 +1100 (AEDT)
Message-ID: <74ad4d5f-7bf7-484c-9386-07945f0c6c5d@linux.ibm.com>
Date: Wed, 10 Jan 2024 14:54:06 +1100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 10/13] powerpc: Define KMSAN metadata address ranges for
 vmalloc and ioremap
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
 <20231214055539.9420-11-nicholas@linux.ibm.com>
 <d24c430a-bde5-4432-8550-57de33cb203c@csgroup.eu>
Content-Language: en-US
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
In-Reply-To: <d24c430a-bde5-4432-8550-57de33cb203c@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: hNZCu3MwXqikP36POMF8gOd8dje9b0A4
X-Proofpoint-ORIG-GUID: aw9dGrggdNPFi0nAkY_dW39AreN6AI7l
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-09_13,2024-01-09_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 priorityscore=1501 adultscore=0 bulkscore=0 clxscore=1011 spamscore=0
 mlxlogscore=999 impostorscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401100029
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=pWydVyLK;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted
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



On 14/12/2023 8:17 pm, Christophe Leroy wrote:
>=20
>=20
> Le 14/12/2023 =C3=A0 06:55, Nicholas Miehlbradt a =C3=A9crit=C2=A0:
>> Splits the vmalloc region into four. The first quarter is the new
>> vmalloc region, the second is used to store shadow metadata and the
>> third is used to store origin metadata. The fourth quarter is unused.
>>
>> Do the same for the ioremap region.
>>
>> Module data is stored in the vmalloc region so alias the modules
>> metadata addresses to the respective vmalloc metadata addresses. Define
>> MODULES_VADDR and MODULES_END to the start and end of the vmalloc
>> region.
>>
>> Since MODULES_VADDR was previously only defined on ppc32 targets checks
>> for if this macro is defined need to be updated to include
>> defined(CONFIG_PPC32).
>=20
> Why ?
>=20
> In your case MODULES_VADDR is above PAGE_OFFSET so there should be no
> difference.
>=20
> Christophe
>=20
On 64 bit builds the BUILD_BUG always triggers since MODULES_VADDR=20
expands to __vmalloc_start which is defined in a different translation=20
unit. I can restrict the #ifdef CONFIG_PPC32 to just around the=20
BUILD_BUG since as you pointed out there is no difference otherwise.
>>
>> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
>> ---
>>    arch/powerpc/include/asm/book3s/64/pgtable.h | 42 +++++++++++++++++++=
+
>>    arch/powerpc/kernel/module.c                 |  2 +-
>>    2 files changed, 43 insertions(+), 1 deletion(-)
>>
>> diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc=
/include/asm/book3s/64/pgtable.h
>> index cb77eddca54b..b3a02b8d96e3 100644
>> --- a/arch/powerpc/include/asm/book3s/64/pgtable.h
>> +++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
>> @@ -249,7 +249,38 @@ enum pgtable_index {
>>    extern unsigned long __vmalloc_start;
>>    extern unsigned long __vmalloc_end;
>>    #define VMALLOC_START	__vmalloc_start
>> +
>> +#ifndef CONFIG_KMSAN
>>    #define VMALLOC_END	__vmalloc_end
>> +#else
>> +/*
>> + * In KMSAN builds vmalloc area is four times smaller, and the remainin=
g 3/4
>> + * are used to keep the metadata for virtual pages. The memory formerly
>> + * belonging to vmalloc area is now laid out as follows:
>> + *
>> + * 1st quarter: VMALLOC_START to VMALLOC_END - new vmalloc area
>> + * 2nd quarter: KMSAN_VMALLOC_SHADOW_START to
>> + *              KMSAN_VMALLOC_SHADOW_START+VMALLOC_LEN - vmalloc area s=
hadow
>> + * 3rd quarter: KMSAN_VMALLOC_ORIGIN_START to
>> + *              KMSAN_VMALLOC_ORIGIN_START+VMALLOC_LEN - vmalloc area o=
rigins
>> + * 4th quarter: unused
>> + */
>> +#define VMALLOC_LEN ((__vmalloc_end - __vmalloc_start) >> 2)
>> +#define VMALLOC_END (VMALLOC_START + VMALLOC_LEN)
>> +
>> +#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
>> +#define KMSAN_VMALLOC_ORIGIN_START (VMALLOC_END + VMALLOC_LEN)
>> +
>> +/*
>> + * Module metadata is stored in the corresponding vmalloc metadata regi=
ons
>> + */
>> +#define KMSAN_MODULES_SHADOW_START	KMSAN_VMALLOC_SHADOW_START
>> +#define KMSAN_MODULES_ORIGIN_START	KMSAN_VMALLOC_ORIGIN_START
>> +#endif /* CONFIG_KMSAN */
>> +
>> +#define MODULES_VADDR VMALLOC_START
>> +#define MODULES_END VMALLOC_END
>> +#define MODULES_LEN		(MODULES_END - MODULES_VADDR)
>>   =20
>>    static inline unsigned int ioremap_max_order(void)
>>    {
>> @@ -264,7 +295,18 @@ extern unsigned long __kernel_io_start;
>>    extern unsigned long __kernel_io_end;
>>    #define KERN_VIRT_START __kernel_virt_start
>>    #define KERN_IO_START  __kernel_io_start
>> +#ifndef CONFIG_KMSAN
>>    #define KERN_IO_END __kernel_io_end
>> +#else
>> +/*
>> + * In KMSAN builds IO space is 4 times smaller, the remaining space is =
used to
>> + * store metadata. See comment for vmalloc regions above.
>> + */
>> +#define KERN_IO_LEN             ((__kernel_io_end - __kernel_io_start) =
>> 2)
>> +#define KERN_IO_END             (KERN_IO_START + KERN_IO_LEN)
>> +#define KERN_IO_SHADOW_START    KERN_IO_END
>> +#define KERN_IO_ORIGIN_START    (KERN_IO_SHADOW_START + KERN_IO_LEN)
>> +#endif /* !CONFIG_KMSAN */
>>   =20
>>    extern struct page *vmemmap;
>>    extern unsigned long pci_io_base;
>> diff --git a/arch/powerpc/kernel/module.c b/arch/powerpc/kernel/module.c
>> index f6d6ae0a1692..5043b959ad4d 100644
>> --- a/arch/powerpc/kernel/module.c
>> +++ b/arch/powerpc/kernel/module.c
>> @@ -107,7 +107,7 @@ __module_alloc(unsigned long size, unsigned long sta=
rt, unsigned long end, bool
>>   =20
>>    void *module_alloc(unsigned long size)
>>    {
>> -#ifdef MODULES_VADDR
>> +#if defined(MODULES_VADDR) && defined(CONFIG_PPC32)
>>    	unsigned long limit =3D (unsigned long)_etext - SZ_32M;
>>    	void *ptr =3D NULL;
>>   =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/74ad4d5f-7bf7-484c-9386-07945f0c6c5d%40linux.ibm.com.
