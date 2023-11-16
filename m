Return-Path: <kasan-dev+bncBCJYT7F5XEHRBF6326VAMGQE5JQYCGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 139577EDE63
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 11:23:21 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1f50a75ac32sf711020fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 02:23:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700130199; cv=pass;
        d=google.com; s=arc-20160816;
        b=pobGmmmaMIr9lxVhLkYB1ZQnEQ5ldWqfv+alCAALr8nKY+KuM1hTbyXDMvuhU80PvJ
         k2O9kZG0HLnityhMY+BJf38jFpZh7yUbGHJIDrLNKXxZBhlCicbshFUUkq0C9duEPazF
         OVtwPpXTO2VUb0Tvsobltcq5JJMNeIsKoU459tBZ2M+94/sdt+KY0rxoTg9JyS+uzLSd
         7npMSWLI7KQHqLCVHeaH4NH5KkPcvITl3BMZDw7PsjxPIUEqlhRa30En0aFk44Ku7cow
         P94Txdmb6Y1REyE1VWB3hHo/HQ5EkNL2kayNdQXKgFmlLEtZAdfr0Z0TFRPHp1K27VLg
         USnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:date
         :message-id:sender:dkim-signature;
        bh=GAhcookiyfwoqsqWGnOe8ipZEvgqz6dPz2euyQzL/HE=;
        fh=aDPT0fTC5HNDCb0kePjeRjwpcDWywFr6LaMRQ+J+kVk=;
        b=ARC8kn+u8PwUm83j4Wui0H1/H/SGmGKmK+shzsSBw9WgAHb63uk2Qo1kB5swGH9p3d
         fqa+y1rb2Qa80ne0fbQdanDFDTD/LtlwQr6ctUdsbSejKBna6XlHMXd2ro3ZFVTN+elp
         uNoBrBi8Da3y10Rn532ZCWUP+RJJEp+mQdr7VnuTXRjFfe90qK9p0ZemxkjIPCFHhzoD
         2klSz+yEKM24MG2Zv65JCqxZFHjIlZoDo/SnVzuy6waitlmmiQc70TW84/dlWYrmaVPO
         dRgHkwP9mEzz1psutpc4Lb3Ny1fQWroDdAUnAZb6RoUp9XICuDLgtdbJJgjRquXTPmdz
         L6LA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VHALO9KC;
       spf=pass (google.com: domain of borntraeger@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=borntraeger@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700130199; x=1700734999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GAhcookiyfwoqsqWGnOe8ipZEvgqz6dPz2euyQzL/HE=;
        b=PMa6EyHgsSyZSOBo+m4Lc8Ev3v23451UqM3RtMKb7+tDr7jFhUEU7e9enPq6KxsHpA
         R4DiL3bNzM62td1qIsVocXv+LpjPNrq3CNY+nSTI583/rp1+ll4SIg1aUY+rxVElRgo8
         gGm0foDepqAc/E8adV5ELuKdY3sCX5g7owFQ4xH0/w3xLyyQ2LZZNw+wg6v4V1IktL56
         laPRJnJ84qzXFLMWUwNMxfJzG+VEUhddjK72LEGXndktKkAxQJzOUeQ+HENWDWc5YI2w
         Bo44jWlQNwPjLgxW1iHsgeYNwGo7qe9PXpzzZ9vgCO9zsEUvbkqG3ObjHp1aPRv0QAzU
         knlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700130199; x=1700734999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GAhcookiyfwoqsqWGnOe8ipZEvgqz6dPz2euyQzL/HE=;
        b=JoDDD8Jh8Ra60CBOAlmkU8sTHvL9f2vpJmgdHjK1I12z2sfmLsPWrrrwLHpI0dpJBe
         S1gUNb1JfBrn+7tAut2uViMVzD6MtllIWnZUcK9XCvzWtcpJtiqkKR4qBIHHIl0WG/5s
         o5qn4qCOKQ+ZePb1x7DFGYABZEhfp14cMP1HspjZYHCZqVfFkMEezmEPA7GdGIelhPCs
         SNPGfElSxDtcsCVwHiEA/pNIpP5DWeaDe0j61cQX51jPqQu+iYBkgjV9NRb608ZU3bpl
         IRS4jtEZKiagy/sMaH9JJZGEOYZdcqZRp9qXA9VXC+awVOF2Qmq6CQajLMr3zRWnbY76
         U3YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx/qH0DL7Cd2+7UcoApKy8YNfNFHl0sLN+2F7PjiqGkmYokF0hI
	6vkRCDwXftkSyhZvikDq5JI=
X-Google-Smtp-Source: AGHT+IEbKhWf/pKnvaAgtWSYJ1f5PZ/M+3und4JE6ifFcDkuBps0E/VRsCOu6PzEmpc1Hyp1QDE3/A==
X-Received: by 2002:a05:6870:5b33:b0:1d7:1533:6869 with SMTP id ds51-20020a0568705b3300b001d715336869mr14705943oab.31.1700130199570;
        Thu, 16 Nov 2023 02:23:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9d82:b0:1e1:5989:cb9f with SMTP id
 pv2-20020a0568709d8200b001e15989cb9fls969697oab.2.-pod-prod-04-us; Thu, 16
 Nov 2023 02:23:18 -0800 (PST)
X-Received: by 2002:a05:6808:1413:b0:3ae:50f7:e3a4 with SMTP id w19-20020a056808141300b003ae50f7e3a4mr22780460oiv.22.1700130198775;
        Thu, 16 Nov 2023 02:23:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700130198; cv=none;
        d=google.com; s=arc-20160816;
        b=ApUqQ1ml7VDrBKS79UI29trjGnCKBXZSpTwL4Yz+tLEW/2wmht76vXkOePTg0AcEix
         9RrXKBSWt+nE88vuTF93HPcATa/NxtoPYijqChslbrI12IoFRjzxWXD3OOTwMjxTmVyb
         AJLLLA9tGf9HcLJU8vsWgm5oWg76kzaOJKtypjfTq8j+2WwdSYKu97E2nhp5t1GzWOQh
         MYN0wUGX8xcHsbUXg4vNwouBmOQKtausb+LX6p4td1aPJc7ZtXHQ2o9P4khhLBZ37dMN
         5/B0GIHQ4Ng6i2OIFbDNVaQPJ4g3DUW18eDH+yIzytBbGN6hZYq20ZKgWdAZY044NpWL
         B/aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature;
        bh=cvnBaDkwCSJUFqJZJSMQvsH7aGC6e3bGVunSJv8rTBk=;
        fh=aDPT0fTC5HNDCb0kePjeRjwpcDWywFr6LaMRQ+J+kVk=;
        b=Hj3w54JFG8vG+0nVKbukWdqSMz3QLpBQALYedHGzvJOfbPtH4koNsW/EY1AvTAa1bJ
         w+Nozd45tu40+4Dyz3jhEzM3hXQEMdUuGVWBg33mNLnWocW2p0hDX2wNfrgCp85OBEEI
         EYFz754iCFbvZP0eGRZTqiTHVYrbWKpsJnePLaChc6wW2/GO2vmuHNNDoRgqzkKmdMk7
         ighoCZrY9VDWQyq2Qa7z84sIMEbJS2wZKw3Ia7PYtVWz3DdiVW/wrMLJLZbiNqAYd7HK
         NHxRCAhDmGt5mKfn+2XB4fGVmfKcCslo1127H6tuOfkzCg89DDMa45egdfQ236g9HJcC
         e+cQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VHALO9KC;
       spf=pass (google.com: domain of borntraeger@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=borntraeger@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id bf16-20020a056808191000b003b2e4bcfc9dsi874099oib.4.2023.11.16.02.23.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Nov 2023 02:23:18 -0800 (PST)
Received-SPF: pass (google.com: domain of borntraeger@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AGAB1QA022436;
	Thu, 16 Nov 2023 10:23:15 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udh3k0a9c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 10:23:15 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AGAK3WO023501;
	Thu, 16 Nov 2023 10:23:14 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3udh3k0a34-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 10:23:14 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AG8XqwY001298;
	Thu, 16 Nov 2023 10:22:56 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamxnnw2c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Nov 2023 10:22:56 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AGAMrvV20906626
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 16 Nov 2023 10:22:53 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 306A420073;
	Thu, 16 Nov 2023 10:22:53 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9116820075;
	Thu, 16 Nov 2023 10:22:52 +0000 (GMT)
Received: from [9.152.224.222] (unknown [9.152.224.222])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 16 Nov 2023 10:22:52 +0000 (GMT)
Message-ID: <b7fd839c-d23d-2c02-a714-ab33f09da632@linux.ibm.com>
Date: Thu, 16 Nov 2023 11:22:51 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 00/32] kmsan: Enable on s390
Content-Language: en-US
To: Ilya Leoshkevich <iii@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
 <CAG_fn=U+X=EE9SSb61E=QDReBXn6PGiX4gJnMfNKsTwQ6saKcA@mail.gmail.com>
 <7c222eff6c1baaa7647a9aa43a1ef19de9670230.camel@linux.ibm.com>
From: Christian Borntraeger <borntraeger@linux.ibm.com>
In-Reply-To: <7c222eff6c1baaa7647a9aa43a1ef19de9670230.camel@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZIvUF2jrGdhEXqto_k7IWZeaNIojFbmu
X-Proofpoint-ORIG-GUID: lP45VWXyXrrPdCpCN1fu9xvnRZLr67yC
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-16_07,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 mlxlogscore=737
 priorityscore=1501 impostorscore=0 lowpriorityscore=0 malwarescore=0
 phishscore=0 suspectscore=0 bulkscore=0 clxscore=1011 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311160082
X-Original-Sender: borntraeger@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=VHALO9KC;       spf=pass (google.com:
 domain of borntraeger@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=borntraeger@linux.ibm.com;       dmarc=pass (p=REJECT
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



Am 16.11.23 um 11:13 schrieb Ilya Leoshkevich:
> It's also possible to get a free s390 machine at [1].
> 
> [1] https://linuxone.cloud.marist.edu/oss

I think the URL for registration is this one
https://linuxone.cloud.marist.edu/#/register?flag=VM

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b7fd839c-d23d-2c02-a714-ab33f09da632%40linux.ibm.com.
