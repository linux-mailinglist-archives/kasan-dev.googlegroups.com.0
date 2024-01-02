Return-Path: <kasan-dev+bncBCYL7PHBVABBBPOI2CWAMGQEASSXGUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E3CA821E2A
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 15:57:03 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-5cea0804a37sf824057a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 06:57:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704207422; cv=pass;
        d=google.com; s=arc-20160816;
        b=jYNYjBUZXm796k4ZksfZHMcM8uX6ZKuNQ9Bxh/99t5Q4wDLPkmVdIeHM2HfZhFtM5E
         rgGcgZ2o7PJ7036kDhGfifHQQmuiLcXyuvwSDvOuPN1c4g8ruyrLaghtleys8nKMKvRm
         +V2sJQX0WfFV8lVf6YSSLxu/BDT7AHPDnvBu2SfUmdAeZDKCLP/DH9L6RvhqQaNuL8s5
         jMMhaNsquwIzJu51GfdiB5ZEJV4wZCDcnxc6FMQHK+d9Ck+3j+kYKOhW+HMN0ovfFmj/
         bQFuwraDW7Ijb9ydIrv4fcKVvJC+4SC7PM6LilVfd4SLAohdn+o94Qz5PgasgDcQz6QF
         KyEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=49jhlTf4pDMFEFof6X0aYZ2Aq+vGNSojEk3lNP3KLhU=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=Rl1skcnoHSg1UbrWOZ4tr8Z6/biRriuZlGBn8RDAr2mIQ1tBr8PE8aJA6Bk7sGnBdh
         U4UHlVM3yU6bFxUY0coLO6fMgKovQ+r2QgiiXmoyW2DGwF2459MDWL/Hzip1aRws8r9p
         vNO3YO2E7puRYnDWAvTchfzOsnb1feK4Zz8vrLcxUrpR0V9ZWuN2qRtRXcUodt8tPqEQ
         NWyr6axZ90ffZ5wOnV3GZFAo+1tBjDqAvO9lSBKUfu6g6ULrqaWAzaMl/0mNyC3E99bk
         4JlB6mz62LmfTQzHnhYLxyxreYrcrzli4NlFsd5MqEPh+sY+n+PzQvfRIsyPbtrVhAcp
         SwUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UPkFrzD5;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704207422; x=1704812222; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=49jhlTf4pDMFEFof6X0aYZ2Aq+vGNSojEk3lNP3KLhU=;
        b=JLUXa1ZIFqKis5uRzVHP1Cf+vx6uT1Oyg4nL9jOiSZWKXpwP0FzLP1QWPhhi78Gpk2
         rumHLlBWwH20J9lyJ19Z00brXBrw+dvwL9DvCaX1YURkAwi9IwU9HNp43UnxY5awxG6Q
         6Skr4QWwpaDoyNk7wvUDeBR4Z9wBg6A8UHtm6jRZUCFa3o7zhwNIkidA5rYd1lMLRQQh
         evfVtQJe5VoJF3BtEeWC7ifRrqcvEbW3ATICJy7SN9PUttCkIkzifKRmKv8v9vULykQb
         8Buv5YuP4bSqgRcuibw/j/CbnD0L3h5NckR5FR2BAOgj/iCYxirgPhczl2IeLw5YMbkL
         Lobw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704207422; x=1704812222;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=49jhlTf4pDMFEFof6X0aYZ2Aq+vGNSojEk3lNP3KLhU=;
        b=H8subdas8TQ6GJFCV/lPd78ykdIvh5hvFWK8xf1lRbgYnFWVMfubdQ1y84J1ngOOGo
         mAL0jucTSmAitUFN7w7fN7YZd1TFzXP7AeNmMTap1A7kkZU6Bso1rcdHmiXxg8kghMju
         SV7NZVQtxILQ6ObD+fSbU0kUsxJAlFITthpluL5kCTr+tHPinKZ6rmoZtfG/Qixg3eSk
         LJnHxKBxLcWfOq1KIToLOZZCN5To8U2MerwIV53n0uqkA62zUVD2zct5otKC4L3nKmoX
         5hyvqXM2FjCVK3dqWCmYt/YYp6DaCMunYQoxHzg2YTPwHzMBVBykU6NKFttCnWr32WVT
         O4Ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxQZ4Bk6HNWZJ/Mim9WDNPojXYvALZ9EaBiQK6fiAdoX1b9xlI5
	6WSt0kix9ZogmWSzDtQQWhM=
X-Google-Smtp-Source: AGHT+IEiaWZlCLhpogjS6gcqmxTbEiatusUCC52CsK+89tPcwCtVH48M4zG9fD1cIVtXVHm9MxFOYg==
X-Received: by 2002:a05:6a20:8e04:b0:196:b7e2:6c44 with SMTP id y4-20020a056a208e0400b00196b7e26c44mr7020911pzj.72.1704207421971;
        Tue, 02 Jan 2024 06:57:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:188f:b0:6d9:bc43:1b0f with SMTP id
 x15-20020a056a00188f00b006d9bc431b0fls279364pfh.0.-pod-prod-06-us; Tue, 02
 Jan 2024 06:57:01 -0800 (PST)
X-Received: by 2002:a05:6a00:2d9b:b0:6d9:b386:c079 with SMTP id fb27-20020a056a002d9b00b006d9b386c079mr18865572pfb.43.1704207420999;
        Tue, 02 Jan 2024 06:57:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704207420; cv=none;
        d=google.com; s=arc-20160816;
        b=ZsOXJeqn+8FvKxJAK3MNAZ+Iz7jo0AzgkkhJ6oRDf/CnMKn8GIC8LdhpvSsbi4c4Sp
         OtUuJ6hi86vkZmA1D1YfF+4tXvtrj7EdeB3h/dhoCCQyJ76yc193wqVwdmYzD2Qou7rW
         0aZMrUhRLEw/GEMYURlrD9NqnKY/sUN0cLYi4M6cU48AcZxkwgkTqGygOgI41NBfIURN
         2eO9zIn6uwnzO8iPTY8Xy0tb1NVhxZqkpsOHpjm6JoL6MIYpA7R0oIPgpHoiO+FHLMIF
         WYy2+CxTgUGdVOrBRmGOfvg6dviuXkQI9qV+YVH4TQyDF99bUJ2NM02nauMiCEnU/4IR
         Z3xA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lsm9Z8oSWVZr6wzE5pLu0Eka6uF10LkWTmR40tX3qI4=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=vn16rwVa8+yoL0sxBni5ZgjTMKt/jBrRQbsesypVX76sP4G+KG4ZdvGJrOj3s929CB
         izYlqrC5VYLIRG+tg33C0w/Lmdv12X/91h45OosE+Dyhv6q5XKZOhlnCVJLn0feGkRt4
         l+jyMx010QmDede5bWRQiFfph6iG1o1KbbM6eNlyx87FtIBgQ/PMmBK5UnL5SKhN8jQr
         SUqkPxrolsGACkzF2EH/HEVx5RKVZ3m5IDgKik1RuqZt8cBMxhKFB/xKefXQ5MKr0uIP
         qYtC3G9sEeJAGu6pmr8XV8dpNGfOr8XPQn0m3ZoG4F0UvQ4lgGF8cqxHoF6DUawmP0Bz
         vOhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UPkFrzD5;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id jc18-20020a056a006c9200b006d9b1734f65si1153174pfb.0.2024.01.02.06.57.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 06:57:00 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402DiYWJ028306;
	Tue, 2 Jan 2024 14:56:57 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcjquu2mv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:56:57 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402DifJu029532;
	Tue, 2 Jan 2024 14:56:56 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vcjquu2kf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:56:56 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402EUC52007568;
	Tue, 2 Jan 2024 14:56:54 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3vaxhnwena-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:56:54 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402EupRq9503450
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 14:56:51 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 752C820043;
	Tue,  2 Jan 2024 14:56:51 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 582982004D;
	Tue,  2 Jan 2024 14:56:50 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 14:56:50 +0000 (GMT)
Date: Tue, 2 Jan 2024 15:56:48 +0100
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
Subject: Re: [PATCH v3 26/34] s390/ftrace: Unpoison ftrace_regs in
 kprobe_ftrace_handler()
Message-ID: <20240102145648.6306-D-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-27-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-27-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 0mYsWeZo8_mKnSAkujm5HJyJGjjC43NV
X-Proofpoint-ORIG-GUID: 8KZKMcBNnDM3yBYkxj3czEh8Z83hu_tr
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 phishscore=0
 mlxlogscore=704 suspectscore=0 adultscore=0 priorityscore=1501
 impostorscore=0 spamscore=0 bulkscore=0 mlxscore=0 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020115
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UPkFrzD5;       spf=pass (google.com:
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

On Thu, Dec 14, 2023 at 12:24:46AM +0100, Ilya Leoshkevich wrote:
> s390 uses assembly code to initialize ftrace_regs and call
> kprobe_ftrace_handler(). Therefore, from the KMSAN's point of view,
> ftrace_regs is poisoned on kprobe_ftrace_handler() entry. This causes
> KMSAN warnings when running the ftrace testsuite.
> 
> Fix by trusting the assembly code and always unpoisoning ftrace_regs in
> kprobe_ftrace_handler().
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/kernel/ftrace.c | 2 ++
>  1 file changed, 2 insertions(+)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102145648.6306-D-hca%40linux.ibm.com.
