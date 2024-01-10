Return-Path: <kasan-dev+bncBAABBSFU7CWAMGQERNPXWUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CCD88292F9
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 05:17:14 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-6ddf0a7d461sf301286a34.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 20:17:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704860233; cv=pass;
        d=google.com; s=arc-20160816;
        b=rECGhWAUu00BI9W7vryeVY5bCgWvdZ8fkLhAab2WqdDP0sgtgrqJXcSERdMYjjg7qB
         86sMXqTmOLyNDlLBVCVeDPpuRqFhHOHc52fot/+8PRUbC0QDHTgCMdMe4ancqXg2ORSi
         nRCJvDW4vDCCYXepVpoGaqgvdRIXCt7XwuMgOxVExuN6YWIcrIDOKFFRRf78uaBqHtwO
         fnhl58mY58CjTG3bLe/mEFFLQompMYKL119uefFvtWXs7VEY+lShVoKImtS0osUMCYLV
         S6S/3BKHLYfrnlcDvdzdeZaHBqhiedzS0vem2yeBY3xFGMeSHvfvCn49MZoTxvM+6dXu
         hbuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=F6RZwOYK+nBvgvvBaQwUYp5Mtb+DV5xbYzkB9BGlQDA=;
        fh=19QRHzWtwJBysBWqhACwuwtJqFcvHTK5MOXxC0X1NmY=;
        b=GWVauECe61dIfrQvniJ66vodxVg8tVmICQs3jErJleZEhxig3mxI4iebDKruFIKqmg
         D3SQ0lCGJS7/Y/uy6OfYJAGRfUgLRpu52D10IHnda7KG7xx4SKLt96OoWX37uKVaa6FP
         b7v0whBv3ypHvg3WdZi0RdILkWp5fOYhZitd7zODt8idQ0lwKAU22s7kotWOAJsYsTW+
         U4uARBIfG/tOQFhkou8FL6EZ9mTzE95evWN8fgTOURJUO2DMISqRwfacK57Fz4izRCze
         G4goHCBBiDUEisV2Yzdn3JRyWUseqM8BSev7pXdtqiEaTPr8V4yn0huYNnqwC8ZxabeA
         fKqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mHalI2Lw;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704860233; x=1705465033; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F6RZwOYK+nBvgvvBaQwUYp5Mtb+DV5xbYzkB9BGlQDA=;
        b=BFSgknXZguMnvMDyDQ2eZX+l0iAl1yr8imMeWHzW6faGAwCDRQ5YCES04YdwnX2bCf
         m7JhK8T/SpWYXsz3XFnOG9yVh00IRIUMT4K8+e987PxBwRm6h8mhxIzsM00I+nikEYRe
         tf6hW8ERmbxBT2/YnD5YyOpBzKmvIX4SBJqVj9SSZzaA47380r7N/PDmbff9DZTJ+KUg
         agxtPHTP5ptnGBnxItwYlQJjMSWJPn5hCZudGsWfnmogBRmM+clNxwUSHE5Ctu336yDY
         +9wLhAPyR2HGMq7xCQgCGALufvQX0G5RlS1cBAdeLMLMjeBUu0OZA2EuGzu2JQCvrT6u
         RvWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704860233; x=1705465033;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F6RZwOYK+nBvgvvBaQwUYp5Mtb+DV5xbYzkB9BGlQDA=;
        b=XQogzxnzXNImF84BrH0duUgAN6nrWDXWLLN7w6xFSjPzaHTopQ33qPaEQ9uIRB/ftG
         QWgNJrhw+y+0RCRTMxXh22yWhVdmha+dZT7H/QwU+sHMC2fZzbdsAHwbkU212RzY9iv4
         ThGjDsGh86j0Sx225t1hr/JXwKmQhiIp9lQouJ7OYvMFMc+IEa4OL54wQIjCrNYovKW1
         MadGIo56tVg+IRLzEWyW24AJc8gLuc7A8y676Uvp0CWV/57FBO3ynXIuZd+zVSMPJbjo
         3p1CIWLjRwnWMzX8TUZOdrjDZ12j4C87pXyohp/+pxmxc0kvgobUTIDnpQI5683trblb
         4/Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxxAzigy4W6MYBeJsFct7HKCuFiXhFuUEi4t0sweSFwY6EWqmcv
	OPTDbPIcLg6qHlqRowGbHuE=
X-Google-Smtp-Source: AGHT+IHJzYKeIx7oGKtr+tb9lFiPcu+ASWznFkiyojlnUcI3PLnZ3heZ/Fagl14t8+QjiP/SmEZ2Kg==
X-Received: by 2002:a05:6830:1212:b0:6dd:ef9c:8b6a with SMTP id r18-20020a056830121200b006ddef9c8b6amr78404otp.33.1704860232909;
        Tue, 09 Jan 2024 20:17:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:454:b0:598:9cad:5e43 with SMTP id
 p20-20020a056820045400b005989cad5e43ls25931oou.2.-pod-prod-06-us; Tue, 09 Jan
 2024 20:17:12 -0800 (PST)
X-Received: by 2002:a54:4398:0:b0:3bb:d136:d446 with SMTP id u24-20020a544398000000b003bbd136d446mr321940oiv.107.1704860232241;
        Tue, 09 Jan 2024 20:17:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704860232; cv=none;
        d=google.com; s=arc-20160816;
        b=scw2LdYDZ1mvaNTHxMFCx4TeswkZ2RYyTT2Ie3G+TR9gQp3AzD/BqSAkwJFWpUpObA
         Hq8u/5UedFf3CTJ4IowjfTPPNVQR39OVuu9YfNN65QSjmxsrWvnaTjpgtWEotlJkJe9P
         7sg7crqaiQJbX6ZNxEdicIDhMaospnOT9NM6fcqgyttDBUnpkA3EYuP1rLfV4C5ffpTh
         aXFc6J/FEWo7qnFfH4sDLENTE6RoRncffwAZYkbTgSF5aYO5zWIWVvD2DT3WPRPIer7I
         f54kILwlx2eBJXzkNyqSSqidejZErF0YMITKNibDDRG+DrSlbXKCoufcU8ID2MZxk9v4
         V0qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=LblpeOnKAG7ZiMLboCXzTZu8Qz2iYku27kij+rJ4/ns=;
        fh=19QRHzWtwJBysBWqhACwuwtJqFcvHTK5MOXxC0X1NmY=;
        b=oTNbAk9qY7WOW9EqxPC3HQQBuKR0J3eCKNydvwYA9hjujDedESWeg5NLkpQhDNZ9Hg
         W1NYkBDeELSy6gju3n4OR8uIEAMITJVGjAt3PGxAle0ESoBPsiFdcsjKHpvSVJDJZPKA
         9OhM+J+/ofqOdqdt2FkEWn+xut/WIfsxJe74W0fvin6aRT+GMRfBhYIkeIomBEUa0Cml
         lT3Ob1FaPHHAxxUKZWT3cvgvLfVBeNkY+zrFN5fT2E17WKfWRTCis422UCSZR3X1P7ar
         GW1XtvYC/VjndH3gj515iOmZZPaod4duBd3Plwv5wRcB5qzQWsrDzlgKfMfnTz5Z8gBt
         PD9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mHalI2Lw;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id t21-20020a639555000000b005c622d1ef04si222498pgn.2.2024.01.09.20.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jan 2024 20:17:12 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 40A3TDEo005600;
	Wed, 10 Jan 2024 04:17:05 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vhgdvmvst-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 04:17:05 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 40A46i5Y008316;
	Wed, 10 Jan 2024 04:17:04 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vhgdvmvsp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 04:17:04 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 40A2VeuT004389;
	Wed, 10 Jan 2024 04:17:04 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vfjpktwan-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 10 Jan 2024 04:17:03 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 40A4H1Ok35521020
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 10 Jan 2024 04:17:02 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DDA2520040;
	Wed, 10 Jan 2024 04:17:01 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 69AE02004D;
	Wed, 10 Jan 2024 04:17:01 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 10 Jan 2024 04:17:01 +0000 (GMT)
Received: from [10.61.2.106] (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 0781C60218;
	Wed, 10 Jan 2024 15:16:59 +1100 (AEDT)
Message-ID: <b48922e4-a89a-4aaf-94cf-bb2b1bff22cb@linux.ibm.com>
Date: Wed, 10 Jan 2024 15:16:58 +1100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 09/13] powerpc: Disable KMSAN checks on functions which
 walk the stack
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
 <20231214055539.9420-10-nicholas@linux.ibm.com>
 <e70b4365-cb0c-4565-b7b1-ac25be85c5a6@csgroup.eu>
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
In-Reply-To: <e70b4365-cb0c-4565-b7b1-ac25be85c5a6@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: lXcvNy98EeOQfMelbTu7LH7BnZ-p2zEy
X-Proofpoint-ORIG-GUID: XtMIHxtsP68xzx66riI-pk7vgjKZbboK
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-09_13,2024-01-09_02,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0
 lowpriorityscore=0 suspectscore=0 bulkscore=0 phishscore=0 mlxscore=0
 impostorscore=0 clxscore=1015 mlxlogscore=573 malwarescore=0
 priorityscore=1501 spamscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2401100032
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mHalI2Lw;       spf=pass (google.com:
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



On 14/12/2023 8:00 pm, Christophe Leroy wrote:
>=20
>=20
> Le 14/12/2023 =C3=A0 06:55, Nicholas Miehlbradt a =C3=A9crit=C2=A0:
>> Functions which walk the stack read parts of the stack which cannot be
>> instrumented by KMSAN e.g. the backchain. Disable KMSAN sanitization of
>> these functions to prevent false positives.
>=20
> Do other architectures have to do it as well ?
>=20
> I don't see it for show_stack(), is that a specific need for powerpc ?
> Other archs have the annotation on functions called by show_stack(). For=
=20
x86 it's on show_trace_log_lvl() and for s390 it's on __unwind_start()=20
and unwind_next_frame().

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b48922e4-a89a-4aaf-94cf-bb2b1bff22cb%40linux.ibm.com.
