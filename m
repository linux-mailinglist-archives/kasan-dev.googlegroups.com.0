Return-Path: <kasan-dev+bncBCM3H26GVIOBB76R6SVAMGQEVRV2RLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id D5BE17F3890
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:40 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-66d7b90c8ecsf59212356d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604160; cv=pass;
        d=google.com; s=arc-20160816;
        b=CoVbYQCeDQsFIxTOD4rs5vlkxDJ52CKH+neOhOCM9qbhcm91Ypk2TWQuPbp+Q2LD3/
         s/AEl+U9PS2cvwy87DSiegEMNHwf1Myv4QqvnyZ+qovf4hce7KgtDQvwEMmoqquRap27
         mxSJnqai1+T3UoyR/EZlqDlaxk9R0mA+0zGoZJcBWriPWv5kyw8o+sctOi79iTRv3fgD
         lg/oca89q/Bm+Z68CDJbPMSs4ADkdeiApXnufjHBKg8h/88Ov9C52xAw1Hbjz8scjsta
         nGYDw7YJva/3LOpKWK/BXSQyDM+7h7mpAu1voqwLi54GajM8RIHNJI+OKAHc4Zv+DbN3
         tUGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5Pv9QZO30vJtfT+rcUecqv+KM6ln1d+YOjx8qqlYxQg=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zNa1F3QxavdsoyaFsi0qiIMjro9qXz+pCuPyk/GKOOWGCfP8Vu5YaA7BVIQucWEQ85
         Pp+ZAsd7YMe5bVXptdxbfpfBNDpGMB0HDjUWPV8EZox2ojC/9lwZkp3DX9HNZ+jr5Qcz
         G2zX07lebT6gokZz7m52XP1DovR9tnL/6RQGqiZxthSEt9XWj4hyvqq8c/96I1B4jBWs
         I95c0PSktgkoqFI/frnZfeb+xUSMgsShvQvc9/3f+GgQv/YM1fB1dFeqG2jPp2+RnUhl
         p9JLCe54xYbPmmFN4nU4eyjdJNVtC2KiUGWCGBT06P9mqjZW40UT+dhKYaJC1XQtH4vy
         3k5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sP24bB60;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604160; x=1701208960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5Pv9QZO30vJtfT+rcUecqv+KM6ln1d+YOjx8qqlYxQg=;
        b=a1v2vdZkLNHI9izXtSi9ihe9e2/1Y4igWTFw//AoH2usibbrBs4sjMg9h1zh6zBPVZ
         g/WsxJITLq/LgFzH+cxDIkOe1FDKG2T7ffJ+giHvTv7mbFntQhuGqgDEX4Rk06mI45pY
         8V451hsybj6CMLVsM9sKB74uUjAuAJtzM3G+jOzKAJ1iNsEXhP18EBSDFmBUASWIUcqy
         HBVz9Hvt1JSA6OSFW/4kaZ65H8fkx8cHXCX1t7tFHE7OLTGTrlREztu/JB2AVblZQuEO
         0216O8nlJbdswtlX08ElDY8RSZuHSVxcPwgOyf30nEzz9fjMciIHlvGgDELgWty40rVL
         TjSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604160; x=1701208960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Pv9QZO30vJtfT+rcUecqv+KM6ln1d+YOjx8qqlYxQg=;
        b=MzfYPMd/vw/b51ICuyU0ZeimDojFaxjHlKBgYVPOOWecaEUWGuQH6tObo4aYfaj7+C
         xgZ6r3tpPUxYS3nwQhUePT/md5UXBP2rf6HDmMxFtmenHWfg4QZM2LT0ljAdGExDejAg
         VptC37+GTu4+dx7zOk4UrLMkhMVudz9brwVL/tDw3Lz8df3fXOuOi+/nV/z+0kOOON82
         Ubyc+GJpZ7SxWQNvg1Ya7J9mp4Iq931EcBs0XxaC7YVwTwAmYWojidXnSolHyt/R+mxn
         pHtzDRraEKS6zgt5eT7JVc4h4j3xyWLBLJETExTg74zk5HACE2J8EzgLwTFwLd6gt+P3
         Wt7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YweLYPL1XwZrgi9XsmkwgP3P4gwrub6WThrbNIDTfp10wvlCM3U
	6ACo/v9TIg2/DkI0kNaNuQI=
X-Google-Smtp-Source: AGHT+IF2p0/D7+Mb4aDaXnJQHFm+avymG59p54ahXKO2mhCmcUV5RIMK44smbDE5H1KafNLCWtbcoA==
X-Received: by 2002:a05:6214:494:b0:677:fb3c:2189 with SMTP id pt20-20020a056214049400b00677fb3c2189mr533338qvb.39.1700604159863;
        Tue, 21 Nov 2023 14:02:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:a93:b0:670:a1c0:e4e2 with SMTP id
 ev19-20020a0562140a9300b00670a1c0e4e2ls626947qvb.1.-pod-prod-04-us; Tue, 21
 Nov 2023 14:02:39 -0800 (PST)
X-Received: by 2002:a1f:ed81:0:b0:4ac:174d:4d3d with SMTP id l123-20020a1fed81000000b004ac174d4d3dmr910980vkh.2.1700604158903;
        Tue, 21 Nov 2023 14:02:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604158; cv=none;
        d=google.com; s=arc-20160816;
        b=vvZo/0+8iYOgKddqn1IV991TdhtCnfiqcKv7NxMqWvQSbOUg89b1h6vBs91O66i1H2
         zO+C6Av1avKWaSUg9V8+AktrJRJQeCbwNdrhjPypAR2dcyc/UcXh8g9xbbWHjGnnXmda
         56QHl74aFyQoVcscYybBsJNij/1dj11550e9/UgPX314LozfRhyuMpaWD4D0R9pJoPOv
         J0f3DfSMkJ9DoduQ7bzBHpfCZ8T/KGw+OnMalOOjJL6LRTrWAoDzSE3WWrE37EXZym73
         82STMER5pAn/MFrW4q6WZ9QY9Hr6ZDHpqMmXo/6BeKtey9wVcFeeRWRYVPnv4HwNJjjV
         9Ytw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bTFzvsbItI2YX574/QmpTUOGiwhXjtDXRzmEY8O9hz8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Ri1RH9X4MGFGeMytT9S69nrk6t3S5QisDu++9BQZbm24V6Pra3awyD9kmuvPwwOSId
         lHaeiMYeJqfAaJ4slBgdRh9/49gTUp3BYfs3oWilY9n+VKjKBmluviTvq8tp3AdRQmqn
         ReWbu4RP/rIoY5H8BHrCzjLN/E+u/BFl/YjIELYMpoXVLu33CFwe9TpGnLYhkCKWfWqq
         RKmtagVTDhLqmYtNjqYWblYVl0wH+XFNNMedaYdm1Zp6CZkVk/CUP+qwINIaLsnH5d2S
         TpANkG/umP+PwDB4x39TWoZjxcn5nHeG7xP0kDAPwECkbsTvVOyxMb8CxBIgZvZA2rkC
         xk5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sP24bB60;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id n6-20020ac5cd46000000b0049d13f0321fsi934709vkm.0.2023.11.21.14.02.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:38 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALJ7QGk028037;
	Tue, 21 Nov 2023 22:02:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we6yg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:35 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLeZac017347;
	Tue, 21 Nov 2023 22:02:35 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we6qu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:35 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnVZq010626;
	Tue, 21 Nov 2023 22:02:11 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujp0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:11 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM28jT23790152
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:08 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 60BDB20063;
	Tue, 21 Nov 2023 22:02:08 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id ED27020065;
	Tue, 21 Nov 2023 22:02:06 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:06 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
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
Subject: [PATCH v2 03/33] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Tue, 21 Nov 2023 23:00:57 +0100
Message-ID: <20231121220155.1217090-4-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 0LYcBzq5jSpEB8aw_PlqHWuGzXMh3HEY
X-Proofpoint-ORIG-GUID: 9ZT62xIVFrzmlZgxIWxw28Gr_G-BJyeS
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 impostorscore=0 suspectscore=0 adultscore=0
 malwarescore=0 priorityscore=1501 phishscore=0 clxscore=1015
 mlxlogscore=999 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sP24bB60;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

KMSAN relies on memblock returning all available pages to it
(see kmsan_memblock_free_pages()). It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages. This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered
an error. DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as
incompatible with KMSAN.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/Kconfig b/mm/Kconfig
index 89971a894b60..4f2f99339fc7 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -985,6 +985,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-4-iii%40linux.ibm.com.
