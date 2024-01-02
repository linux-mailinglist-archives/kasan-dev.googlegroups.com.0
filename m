Return-Path: <kasan-dev+bncBCYL7PHBVABBBBGA2CWAMGQEFXMSOIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7079A821DD1
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 15:39:01 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-42832cffae0sf90371cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 06:39:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704206340; cv=pass;
        d=google.com; s=arc-20160816;
        b=pxW9Sa4iD/bToNvMVI56NGMRVMPAtMutdg+6JofTlCDpM5Tm2lhSMrB+/kC845PZfr
         apNtQ6I29ZWvFxql5FS6Oe6KX5S3uaF0IT1sK8EaSNLuZs+Ao1GbaB7UK6BRPrPBiCNH
         gBRao/r/406cj3NAc2H+DmNBxvhxo/O4MSqkgZVdc4Wp7N6y57RrnKjzv6ijN4vpoCcc
         /YkP9keRQbyBMSdJKYZKfku9uL9OK20RQhuA2A+rXYow9BZ8ebk9pP5tBc7dd1s714EC
         PwhLKeqflj2fnazx/ceIotz5D5MtzjDdhWugBgeyesE3oQAnC1uYh3VFTuj8lV0NXdah
         2m+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fmeztQ5zecpvN8tp3iwyRAwa/j8d3Ap9TJz50aqQfyA=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=nEbJaUplNgKlcLfm7Mqawn792S7x7FWILw/CnvjVn/kgONaATKoSQ7PiS500o5ROFX
         F01IxAGrutiKNFyLgefmkOI334jEN7o62PDFGudF9m26BOxDJPoqFAJqUCh3DE7lbNjO
         034r1oV/PNTdjdlIJmOcsI3OF+2tZpX5O7cMZzTlWdEHDbVL47QvBPTg45X0FCXqFgtL
         +M9mLQHw4y8sIVTrVWLWZlG5OHZ0xBlL9oog6wxYbQbR2WkgTKtWdsv6luvY58DSA+5h
         /DGdMPf6c+EKcWN4RAe93FGkJkObuT5zCVrU57Mk7J6h59F7PsaEzqa8RZLuu0Joi2G8
         rh8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NEFPA7vn;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704206340; x=1704811140; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fmeztQ5zecpvN8tp3iwyRAwa/j8d3Ap9TJz50aqQfyA=;
        b=alyQsCQwz2EL9a/LSfs+4vFU2SM3P9v+73klbTjlaUXZLggn71szpALlR4r0kbKV/L
         PewZX80b/b3ZxMRGrg1L2Acg0xmv7eHFm7hlN6N3RXqKJNtjwePSyrLJdjut33gP1oiv
         ahcKRwuvunTK9FlTIk0ugOSdOqCUUHOftXwvQ9wVZjhTFCJh7eCeIfgh+m7t+JZVDtAV
         62f4mI0rK4Ynm6wrTewN/P9OhyAjubgYcpMKYUJoVqkFWYud0kZbkPGEn1dT22TnSA8b
         ECGPSFmfYMo0C1O8uXgGIPNsXqSQq5GM0cDMRTCdu+Xx4m143tkqL7YEAtCbDdIzHb7U
         gOAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704206340; x=1704811140;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fmeztQ5zecpvN8tp3iwyRAwa/j8d3Ap9TJz50aqQfyA=;
        b=foKcPp2zc1E693HhEknKCWDRWQ/pEJ0j+rVUxaanq0zXA5ZqXM9aY1QIZ+3IFdXUPj
         qJYTVH1NDI76XuR1Be66qwMN85xOqU6Gi8x0qxw3h+ZZ4dCBANWf4/++aJnIN06LuG40
         LqBgNFe0Jn2m1v8CMZB/AFdDYSMuulLrpdLDk0kVcoxBHGrKpI2yp1hXMud9jcl6LxiA
         lOrjIDhCaDV2WJKyuhka0TSTU/TumXpceQnvvcJZT1PZP/CE3Pq9/N3yblHAGjzJzdZz
         uqfDqG/KNrxA4IDVrC6pFsW7mzZw0sRbqqxl2Ps7E8eOmmlrxZx6Vye2sj6suD4W5j4m
         2Vkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxhbn2zexWft2jEt4jn5fQq53ywgdPxcWVHjlMQ3ZslHzPcg5e2
	Q5iJjaOXxZ1cFV7be6HyIoA=
X-Google-Smtp-Source: AGHT+IG3Aysg1MvGL7qWPvqnM+hY5uh/OjTTz4xBCg/JT4/StS1uYeb1krlmh4OuIN0M28idYlDJzQ==
X-Received: by 2002:a05:622a:c8:b0:428:adb:707a with SMTP id p8-20020a05622a00c800b004280adb707amr405721qtw.12.1704206340116;
        Tue, 02 Jan 2024 06:39:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:3d6:b0:595:d44c:8f30 with SMTP id
 s22-20020a05682003d600b00595d44c8f30ls553789ooj.1.-pod-prod-09-us; Tue, 02
 Jan 2024 06:38:59 -0800 (PST)
X-Received: by 2002:a05:6820:824:b0:590:875d:6ee2 with SMTP id bg36-20020a056820082400b00590875d6ee2mr11305865oob.10.1704206339384;
        Tue, 02 Jan 2024 06:38:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704206339; cv=none;
        d=google.com; s=arc-20160816;
        b=AVv+hJNzYJLxrschbINWpsGfHA2N9nxQXHQ5QrKpFFdPffI1bHlpRMSLPRTUBqmht/
         uBjLh6ygyD6ktJK/IXVjPVOKMuvqd9oObD2ds4u2M63sGWz8ekDlx7TLljyoE8IcA2RE
         upN6EUZ/PmmhIErND2e9z/VcivVeqHmj6Mq6NXSekGya/FtcBuSbBDkIypwfdBiSDxgB
         C7ZcuG5m26h+QU03H3BYsB89+3HbJLbidRgFlGUghvXVsZLfrvc1atHOfzUflOKGg7rA
         jLJ5nl89ThJ4G7tzsWTPEbJZwV8I459T7hUWHpKK6q/as7tYMAiN9t+06Rqyq3Tb4aDm
         SUbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nMN2ZiX5fBPheidUVHXBOQeJqaVq22NMKNPrKMlBIko=;
        fh=mnX3wLuzTrkmgdlNsEgQXOForHn3WUzT3G0xt8tsRls=;
        b=EBp8rYcsvg4JGlVeUBV0Dral+Wo9lh/lP/RyRz8PY5zSXYIKJlfhnKBwJY1C0SSubT
         W2S1vPawopbDLk2b/hYRxor5zZojR4bJRy6pr7QWYKbsmkwf7kGROsMP6RqCQ9Of/Xh4
         29XRYX8WyejfCIOKy8Of/JWt7j4dZSnR4u8pNV2a9h4c1OKRqZDg2/wmAAQMABllOQqA
         zYnSHYbtnJkhv9/CXrT69x1XtYW55yUliGM8U2c36DDR6GlfY0r5twfQ8xx2Fjkd1m2V
         xzkImg2R/OCFNZ2LPteD115Vzf+WqLBLns8gdDuP/SXNiia6SOeRjBtnPF9cxWndqD8H
         k8mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=NEFPA7vn;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id n5-20020a4abd05000000b0059572e71343si212638oop.1.2024.01.02.06.38.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jan 2024 06:38:59 -0800 (PST)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 402DrFMW030277;
	Tue, 2 Jan 2024 14:38:56 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vckrss3mg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:38:55 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 402ESQmP022837;
	Tue, 2 Jan 2024 14:38:54 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3vckrss3kq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:38:54 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 402CCo8h018138;
	Tue, 2 Jan 2024 14:38:53 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3vayrkd0gw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 02 Jan 2024 14:38:53 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 402Eco3o12387020
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 2 Jan 2024 14:38:50 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6D9C32004E;
	Tue,  2 Jan 2024 14:38:50 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3108320067;
	Tue,  2 Jan 2024 14:38:49 +0000 (GMT)
Received: from osiris (unknown [9.171.22.30])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue,  2 Jan 2024 14:38:49 +0000 (GMT)
Date: Tue, 2 Jan 2024 15:38:47 +0100
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
Subject: Re: [PATCH v3 24/34] s390/cpumf: Unpoison STCCTM output buffer
Message-ID: <20240102143847.6306-B-hca@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-25-iii@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231213233605.661251-25-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: tigr5Z3z0BxX2AirZXNHzagI1bfeH5jj
X-Proofpoint-ORIG-GUID: qfT-irTXYoFc-48gwcgYv32GP9D1i41z
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-01-02_04,2024-01-02_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 adultscore=0 malwarescore=0 bulkscore=0 spamscore=0 phishscore=0
 mlxlogscore=623 priorityscore=1501 suspectscore=0 clxscore=1015 mlxscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2401020112
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=NEFPA7vn;       spf=pass (google.com:
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

On Thu, Dec 14, 2023 at 12:24:44AM +0100, Ilya Leoshkevich wrote:
> stcctm() uses the "Q" constraint for dest, therefore KMSAN does not
> understand that it fills multiple doublewords pointed to by dest, not
> just one. This results in false positives.
> 
> Unpoison the whole dest manually with kmsan_unpoison_memory().
> 
> Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/include/asm/cpu_mf.h | 6 ++++++
>  1 file changed, 6 insertions(+)

Acked-by: Heiko Carstens <hca@linux.ibm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240102143847.6306-B-hca%40linux.ibm.com.
