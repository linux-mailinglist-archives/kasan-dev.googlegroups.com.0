Return-Path: <kasan-dev+bncBCM3H26GVIOBBQUZTSVQMGQELFM6B3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id A50B07FD37B
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 11:04:52 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-6cddc344b98sf82967b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 02:04:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701252291; cv=pass;
        d=google.com; s=arc-20160816;
        b=A90bhnq7X60vBXrhHAr2oaibEVkQNQ61vRn2U/yRyDLOkhpbu7XpZefiOw3VErXeAY
         3xXk4eEpzhyTwXzyK+V9hqczx3ZaG9Mcl4CW51oWGHJQS7QuEgszpySyFszp+0tg4amf
         99x2eaLtTNVGJeFM+HHXI2d5xdl8hS+M74A/sQrZ6xibmCvA/zV7ekAwT5Nl1OX+JoNT
         GMViufYrhHJqtOpo9BpusBtgtnMqMZMKzFcWEtz3KAi4I0U+8XtAt7gdh1lPMSZP1YFw
         WfXSKPYzYgpkE0ryUZVwNVISC7NUb5IfdMFqXjyLOnUmxCc1JRDLNIbM9psOEdQnmMwn
         WV8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=YDVqcCEU7NBEIHgtFD/KpWXyEJbXLQvHgw2LW1GljHk=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=PWwGGncsZ5+9hkrTmAFFCLJN8C6i5y3DRt9hmf5X8hKQj8P2h0BzIaOJ17fMyNxJml
         E5MaR14Axsnahk5V28/+aEhuKZGgdA69xCmeoZb0zd88Z/J7lkm9wKbNqkWjZITXbQto
         yWlcApOYuv2SBhaWK0yjSg4MnsrqKwUNbbTUjv+B8o8QDeC2Nv4+r4kMzn6RfITQJXYD
         QK4Orc7TXB69VCwhPTXqsgY5SC0Af6u6vSB5UzfdpmbnsTTc9XzpXd9Hum5fIAC4NEBK
         Xk+eddsM48nfMTQdQcRqP4kZJ3vxkrS+ylfN2cYd+PuyG3JgMoXJZDO4qumYz+6BKz0b
         Cp/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RYnmXqyq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701252291; x=1701857091; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YDVqcCEU7NBEIHgtFD/KpWXyEJbXLQvHgw2LW1GljHk=;
        b=mEAhfdXHE9jAIfgu0oIIB2ysdf2m966Hvqc7Npx9UqSCvcS8x+8YgEDx+W0aJzEmdI
         vlWXkOJd4RI0kabldoPG4/6G21JYkcdebfplFQVj2WTWv3kUnP7BoLNZYq/NjsXEfUny
         Y0iAmhaWErL5tFkSXPPMnd71JskaCj7kKLuwSSb9Mp38gkT/+XLax98Nf+gbBsVO3VjR
         JynRoqxHd0B1tM4Ef9GI5euqfTI5/MSOjv9H0R/i6otVroqbpbt9zyLDVZgGhDPoyl8s
         yHd2BuO4kTS87PDVNPUItt3cecoG7je9r1/FocDNfMRPp+AjnCKWkkw9+XmSkov+wRR1
         jSpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701252291; x=1701857091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YDVqcCEU7NBEIHgtFD/KpWXyEJbXLQvHgw2LW1GljHk=;
        b=Ka0QURISJkYrb7Zo5RWQ5/49zI3qzFZS2E1WA08EnlWEX2B79idT2e/Kal/6CoaWbe
         Y54ubVYEoU17GFelPHhpn1E3dki9WU1dgtnXdNcdlR2vV02Tq4J8Xc+EOgk5eo2qwpGc
         bbVJNAPkMa/Anp00EX9qP1YiHdpaMJUzhrKDTh8p0VAdtYt8CRs/v/4Nxuzn7J3AT5t7
         h1Xp6TUOC8r321UZrVIVPqnQueI/poeuuhqYq7TSC7uV7O6vUW7aWj7AhJLYAHc+jh3q
         T9HOvUL0C6JI0U1nech4Mp/poOQHA4TsN4KyPYGjlQFQQPKqB248zk+NFoDeyrtZiOrz
         f5Jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxhm0YYGKa8c8uot0Amq3n0gNOz/KBbYyZe7lYAaMFagHgY3ZKf
	cmnq2D5W9Ucd4s62liSbL+E=
X-Google-Smtp-Source: AGHT+IGDbIgqENzUOLSyHur3trcqzE+R+yEIJfTGBBMBAeZH5hxraUULpRlNOA+jSaK4kJUw4hm0Tg==
X-Received: by 2002:a05:6a00:244a:b0:6cb:a2f7:83d with SMTP id d10-20020a056a00244a00b006cba2f7083dmr20886645pfj.19.1701252291060;
        Wed, 29 Nov 2023 02:04:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1c85:b0:6cb:e4aa:4071 with SMTP id
 y5-20020a056a001c8500b006cbe4aa4071ls4660678pfw.0.-pod-prod-00-us; Wed, 29
 Nov 2023 02:04:50 -0800 (PST)
X-Received: by 2002:a05:6a00:acd:b0:6c6:9f26:3a00 with SMTP id c13-20020a056a000acd00b006c69f263a00mr5463981pfl.2.1701252290463;
        Wed, 29 Nov 2023 02:04:50 -0800 (PST)
Received: by 2002:a05:6808:179f:b0:3b8:5d96:faea with SMTP id 5614622812f47-3b85d96ffa8msb6e;
        Wed, 29 Nov 2023 01:58:56 -0800 (PST)
X-Received: by 2002:a54:4587:0:b0:3a9:b9eb:998e with SMTP id z7-20020a544587000000b003a9b9eb998emr17021352oib.51.1701251935501;
        Wed, 29 Nov 2023 01:58:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251935; cv=none;
        d=google.com; s=arc-20160816;
        b=LOMXowhbQog/4zD8pzd/Ysd1htFlFZHMKpoyeO0qkRtAWaUwCG0p77U5ggodSNuckv
         xk93FAaRq/AsNtRKCWvHvSK80TusMjpkNcuCJ2ENaqTKJsVCQ88d7In7fFftixjGoUX+
         vXMqPpyLMQOXTdICNrPGh1eVVxytwrQdxI6qpyUPSY4dUYdXIdGiUxuzJKuz4HsZW2qX
         tkAWlaZfYUnZGmPgSNgFsYJ+L/Zj0SwEkYM5JkfFxgr6NHiXjc/+Ui/yVPNo2vYuXBPQ
         3ydK7N5e/ToX9LuUdC/Yj67BZRi85nfWd6w/owBEdS8P87XkZFUfnuo44O7TCTs3ulu7
         xftA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=Hv358qHkkkSpvNupSHYh3b+P8ZW0/9o2ISigxsZiDRc=;
        fh=SMIKM+y1F5Yf09jEKMp9vgMRdDDYr6DfomPBwv55HT4=;
        b=FWQzi6DDuyHmdpSrMXnbzp2HI5D8PqhQFlq9oW/F9x+XzY4ttqNTygCoSkxRaRc/HC
         qJrUgq2G6DzTG2Batzl2CszVCW95QfYrUP+n1nRC1gX8b9H/iryy/37iMtR9cAyEGghJ
         gKivWh1A9M2My3M4jB7huOgOxlu8i/bY8xdKxpEah9dmCFWLK0MthC08v7OVocdS4Xcm
         23trssRmC7DNOPENRTADXJFB40yrkwAy7Hp9lmDYfIkEvoNgu3TnMpym+cqYocz7msRN
         0hSne0DeRZnjUj6adb0p4mubiVMC+Irx9LzdmEoJWe5FykRtg6v3/S2M8ibtNsRd4ylw
         UtBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RYnmXqyq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id x18-20020a056808145200b003aef18f3442si1310369oiv.0.2023.11.29.01.58.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Nov 2023 01:58:55 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AT8lip4006099;
	Wed, 29 Nov 2023 09:58:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3up23phqtg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 29 Nov 2023 09:58:52 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AT9hwi3002169;
	Wed, 29 Nov 2023 09:58:51 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3up23phqsh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 29 Nov 2023 09:58:51 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AT8VHNw012197;
	Wed, 29 Nov 2023 09:58:49 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ukvrkp9tm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 29 Nov 2023 09:58:49 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AT9wkHg16057068
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 29 Nov 2023 09:58:46 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9F79A20043;
	Wed, 29 Nov 2023 09:58:46 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 646F820040;
	Wed, 29 Nov 2023 09:58:45 +0000 (GMT)
Received: from [9.171.93.155] (unknown [9.171.93.155])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 29 Nov 2023 09:58:45 +0000 (GMT)
Message-ID: <edd48d556f3951384f9ac72462f16ee9309a739e.camel@linux.ibm.com>
Subject: Re: [PATCH v2 33/33] kmsan: Enable on s390
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
        Andrew Morton
 <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>,
        David
 Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami
 Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven
 Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil
 Babka <vbabka@suse.cz>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle
 <svens@linux.ibm.com>
Date: Wed, 29 Nov 2023 10:58:45 +0100
In-Reply-To: <CAG_fn=XCeE7JF5hbpzXu2A0Cae3R16_hnDwF0==oJMX320wBHQ@mail.gmail.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
	 <20231121220155.1217090-34-iii@linux.ibm.com>
	 <CAG_fn=XCeE7JF5hbpzXu2A0Cae3R16_hnDwF0==oJMX320wBHQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.48.4 (3.48.4-1.fc38)
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: bHuUrUxcKhPwsCQNukrG6dt9RnefPY2L
X-Proofpoint-ORIG-GUID: XkNrh_4ciRiXY49x-H9GVRo1-JXJIiVh
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-29_07,2023-11-27_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 suspectscore=0 mlxscore=0 malwarescore=0 adultscore=0
 phishscore=0 mlxlogscore=832 priorityscore=1501 spamscore=0 bulkscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311290073
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=RYnmXqyq;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, 2023-11-29 at 10:19 +0100, Alexander Potapenko wrote:
> Hi Ilya,
> 
> Sorry for this taking so long, I'll probably take a closer look next
> week.
> Overall, the s390 part looks good to me, but I wanted to check the
> x86
> behavior once again (and perhaps figure out how to avoid introducing
> another way to disable KMSAN).
> Do you happen to have a Git repo with your patches somewhere?

Hi, yes, the latest version of the patches is available at [1].

[1] https://github.com/iii-i/linux/tree/kmsan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/edd48d556f3951384f9ac72462f16ee9309a739e.camel%40linux.ibm.com.
