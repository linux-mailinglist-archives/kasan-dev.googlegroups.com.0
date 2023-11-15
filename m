Return-Path: <kasan-dev+bncBCM3H26GVIOBBXGW2SVAMGQEEP4DVNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7416A7ED219
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:37 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35ab1928d5bsf673345ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080476; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRhmEAYGzEdN/eh8zUtOdkez9NRQZUMSyHiiIdZXrhOJaAYYqbkYNXjP78gQX8xp5J
         llJiGSDyl1jsaiUAFsE3weKkcwCXu4+2kQdIOQXakzOEhc3JHNnafoOjHK/26Z/DEhQq
         Yj8XcLc9WxaxNoXyBEra1hbasn62u2qBFaQQLzrJ8HarubalAafrrgI0GvHgcHuPN53x
         0KKNM2zD+H7bTX2NSnqQAfR3jIPhou0CEbMv4bJunEjmPobZzDYSBIu8OEaSdd2DJ6UG
         Rgs/KpGHhzI8wJ0udL8nBY53gnVQCqM90NI42j8HMZ6SHqg4jxdRtC/U5dEruMvmcDnF
         8BuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=okuQyAbR6kwbEySYXob+p8rUVGpg+6WSOsn774G2ncI=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=J2HusDfKZ8SAe9fLEJ+RCec9HZB7ShAj/uf6KvyE/S8tIfm2CwLamywobMFGEnAo5T
         yx3skdXatsgLUZCTCCsgcgDUij7+AAoSqeNKlMC2Y4AzcLYKxVA4kAQ4doXZPr6u5YEI
         1aQcaqvaSQ/yZsYxVb8CVzVftYQo1VNf6Ny1yk+/zde7Ge9ll4Bp4HG8or8Y7c7TTxth
         8PM7aKv0uvEdck043qxzz2TpHFtc9Vvf68SwiaiC4W8ZxU6IF/hbeHxc23TDfyfIUuwu
         BKle4wi8gZpeHbPq1AX2FHhYyWS1NvYRX2wZJWdSBAKU8LGt/JRnu3U9ME9XfcsJIiAF
         VQ5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Ax/r8INR";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080476; x=1700685276; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=okuQyAbR6kwbEySYXob+p8rUVGpg+6WSOsn774G2ncI=;
        b=Jc6NLF+8o61WRgAf4SGwjC21LJdQknGW6qub/x5KFZKw1ZsTkCwL8l+tPJb7Vot/98
         yzFi++kbW/jQVghvBzSMtqOXLkay3GFIRLx0+nCIOK7vufYqHV0xrvwTsIh8RjoqK3lP
         jGjDGNXGMKvg1QgmEQCgKmwMkyEyzf1SRZzFuWmENF7LFpFwcLB6euvdZeAaTnZDjZLA
         dH4Xq2SAu1s2mbY3c8kHq+ZWOTh9bUbhQslNjna4RJ5hKW43OPMhaklsOgSChzUUn4pV
         S1HxaW2ZFA/IGdnhe272tM1/HS6OaOaVsWCot+0Dc+F0aTEcgIsHqOTQ8aUSv7RiVWLn
         IgRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080476; x=1700685276;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=okuQyAbR6kwbEySYXob+p8rUVGpg+6WSOsn774G2ncI=;
        b=M3zeLokWiyY8DSqtnGk7JqxVl41R0jP82ZvsWjByHVzGdb/ZPtjGE5u1n7nwy72NFQ
         BEHY+GyBZ0/kdkRDnvAsa6spznZ65AJh9TfvemNSq3xPApVjHfY1W7pmHJEcUcT4+DMT
         WKLhQmtz/QYCqUPYHppkkyM1yFp0qgj5nydV+x0SciW88RyC1tp7wPU+wGkA+E2ihqnX
         g1ebu425quwXDNOHllWKVpsKs+rxLJxD2eEnIjVJpQ+eUBVb/6+dOyXqgMCnYCOEkizC
         H0lONXlGTqP7sVklkSgzjIOnJGR/wNuif3GTWHiQfzQcRsFvN9nwgta8cYryUMK5T6JZ
         /uvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YytHoGHQC2WGHCxOJBNUSww7zukbPXbJ47iWMXgzRRjI3qDLkMj
	I6MnohPDRUgOcoSn6+XC5Wc=
X-Google-Smtp-Source: AGHT+IEicafv/G8O+vtV7rXDyP3dfK/jJKzq/XkqBQ69LYFjdAVYDaOvg7JACQVVT7ICt3MwYbimNQ==
X-Received: by 2002:a05:6e02:1d8c:b0:359:d32d:c559 with SMTP id h12-20020a056e021d8c00b00359d32dc559mr18498368ila.15.1700080476339;
        Wed, 15 Nov 2023 12:34:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:50f:b0:359:3c28:e053 with SMTP id
 d15-20020a056e02050f00b003593c28e053ls53949ils.1.-pod-prod-07-us; Wed, 15 Nov
 2023 12:34:35 -0800 (PST)
X-Received: by 2002:a05:6602:4185:b0:7ab:ec1f:f4a2 with SMTP id bx5-20020a056602418500b007abec1ff4a2mr18999950iob.8.1700080475601;
        Wed, 15 Nov 2023 12:34:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080475; cv=none;
        d=google.com; s=arc-20160816;
        b=W+zRR2DNcv09gzOA8IyREVScDst7WddQy4L8jMYrGjHHswoKMHESFCm8a9oKzMQcVp
         EpE0+dsXTUncfMnlZqrEj/k5MaLs8B356iodJ45qD1nVYQTmFp+eYgmhYK6NRmehEGuz
         zEFYv1mDx/u1gIyI3YAbYWL/hU+qIgkhIf6lZi8rneJzpWVnbJ7lgwwPFnf7RR1c8bZ5
         /0B8ZuPQ5/lt2ECFWs45sh948LBvLVgXfJoygEBQ8jmYxLy55mVTISFejsNh54tiaecq
         ag2L6IwY4QwRjsvTnEzZzlG5KoeEMe2G6zqH809Td6X87mRzLQgg2OaDRNYbXmmRoRl4
         1SXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MFebAvBrNyYRaTzmk1ztFiN5idJvQDPy2C+0jY17reo=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=aNQvTC1oFppt9E+WDugtJzNEwEDtYI8gvs4AY2PctgaPDoCGTIazEKogWeZ0LkNSpY
         B/AuGDqIMVPGpRIEbvLuF/BuXj8dsheJQ+N6eMH04emm3NRrxLMS2PvbWvoAc+9yawY5
         dVoWRBfTEPHGzbD4FPw4OX8i2xQbXPuGcMZCtz4HWbzQSztwzoo/nq8dZDnc2eBBsMvM
         ApZgzay7z7G7bg3aISYxvkzuFl7IkTWXwey08kRpEG7OemT1WXLM2WCpl2eq7YHWj8HQ
         qR1o42tryW/ucAwsn6sJsbBfRVr8KRPGT9fBfNjtg7KRxWIDsY4IY/f2oOmUGMm6q7h7
         HygA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Ax/r8INR";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id r8-20020a056638130800b00463fcd15b78si1261164jad.0.2023.11.15.12.34.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:35 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJZYl002178;
	Wed, 15 Nov 2023 20:34:32 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4jtgubj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:32 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKJqnw003771;
	Wed, 15 Nov 2023 20:34:31 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4jtgub8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:31 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIusL015453;
	Wed, 15 Nov 2023 20:34:30 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamxnj0jt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:30 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYRNf39518974
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:27 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7464520043;
	Wed, 15 Nov 2023 20:34:27 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 280DC20040;
	Wed, 15 Nov 2023 20:34:26 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:26 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH 11/32] kmsan: Export panic_on_kmsan
Date: Wed, 15 Nov 2023 21:30:43 +0100
Message-ID: <20231115203401.2495875-12-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: FrroakPiKF2R0pV-9SgXrQ7N8s7ondQG
X-Proofpoint-ORIG-GUID: DtTvJ7EVUczYgMPe3hqBK1_qhPzkipLH
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 adultscore=0
 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0 priorityscore=1501
 clxscore=1015 mlxscore=0 mlxlogscore=999 lowpriorityscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="Ax/r8INR";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
Content-Type: text/plain; charset="UTF-8"
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

When building the kmsan test as a module, modpost fails with the
following error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for
modules.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/report.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 02736ec757f2..c79d3b0d2d0d 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_lock);
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-12-iii%40linux.ibm.com.
