Return-Path: <kasan-dev+bncBCM3H26GVIOBB76R6SVAMGQEVRV2RLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 310027F3891
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:41 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35af4a64ffdsf2227795ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604160; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uk3Jj8ZiHgOb5H5mh6usGGO4IQYYoT91LtK32s8XjeMe+ml9dFcyeOaSaYnrrzRO+C
         4HCJyeE4CSJAhUBteHIV9+tOvBrZXJ7RBkNWArVgbA+c0bdM5NRpzwOw1x5sSmCZOpY/
         QfBLc1jO+uIjSfLo3ug9vGKVVYZUsFQQa32pJ0e/m4bircIkj54zugSdWyizgGhKfLoY
         oji/fKjPDPmxW1A9G/W/cfV3JcGjA+JLEbTzhSu5RGJzoEKUY5yxMUw/ofwB1BNkG/bu
         AEK+KxgYy/ORAS4fWchAoMMN5p/q+EbOtv8K66Jrzfet/ASV8vcXlh8y0PasQV230MdD
         E1Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cpXaX+Z6naS2ew5xwR+T5qMjoF3UPygxJvb27gXpyP8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=KFla3H8qb2+h4x4gnuwRIlDc/VmbIj9X2zKPV9jqXoMk5PaQ4+NNwIXuUidPA0M69b
         U3SNHXvnuzDRf1rKiv+Hs0hoJeWxuUphkTAnPPAU/FS7ycrfXQpkTKg9IrdcPpN7w9Gk
         6EiMA1vcinshtlLmAsU67Ry/GtD1IvSYZMfuAViJOLVc3DWSNRbuSgEt4o3Ul5mp21Le
         ZALgAFgxnAcN6SKU7qK94hhJ8p6IijRODy23AZJwwznY61lCVyB4UIWzZwh22Ii2pw4w
         CsH3JOnq4ZDgSro5mZPTBLa/bXESE5t2DQ8kzGRebP3hkfrNjngBq/gB2rCozp7RQJKd
         1m9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mgOxiBg4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604160; x=1701208960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cpXaX+Z6naS2ew5xwR+T5qMjoF3UPygxJvb27gXpyP8=;
        b=mMAwIaKK0i/fxQoReROFvW2O5vOM8SJNppeMH3AW4jtsMBYkGckAd1AnqzpJ2d2Gb9
         vI6v6Wlvtn+SZRTgBScYSeLuiAp4UGq7RmdCBRak9drZSQKmD3lzctwP9O8RYI8GqkQH
         ggLPAs0bBmzDalOXJasYQSGT25Mufdq6N/pckGZe3k//S3ZzDuPEEnEVq/M1eJYA4Act
         xEJ2SLnIk/eHXPeH+Hwi8Q5v5bEf+zaj0WzzQjz+guISr0YdURtmCMG8KCWqOkCeqSf7
         p4TUEbrKFgdoM8seCd3hgZq0epQkOHd9oUrbOPG3jRFlgJ9klUZZRPo30EKDLzEIpgT6
         e2yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604160; x=1701208960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cpXaX+Z6naS2ew5xwR+T5qMjoF3UPygxJvb27gXpyP8=;
        b=CcWuOZKnyyEqwQn94SI7Ym0jwvYHIUte4ZWU5bjwVMdSNsrdLDIVf4r1X2psh69aV6
         q/L6P4uNVAsu1NvbDodLAN1PurR68R2CGpfob+i8gtp5JVjHRfMxFBTBvlG+VeGY5WHb
         Nj9QgwxIvV3yCv17Sl0yiec3eiIE5TV4Cpcc3QIVwYEkzdAYKPYjy9Y8SzFWB4gtERoU
         gS/ZxTnTPvM5iQXEWZllSZNKyXIruvQZF9ZHEQsw2TvWa5UsewSSWyS2QOxuWg2hbTsy
         /+pwG+ln9UWbRbb2W+cngANxmdtPK66Gfh6d3rnMFwAh/Epa3izHocmL1k7XTB59cD5j
         sQ7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyJ0HBVaC4bOHCcJPkUz41DyOuRRXMZkv9KgRcN+rYbguby1Nsk
	NrpXwcj1FBuJ8c7ThzkYOVI=
X-Google-Smtp-Source: AGHT+IEUj2vXRPbbCKUdVVsZnI2b7NeweePZBvu7YFIC/U5YUnBL0Uc5ftzkXjpEZ9z/buhjnvvJHA==
X-Received: by 2002:a05:6e02:d0b:b0:359:315c:368b with SMTP id g11-20020a056e020d0b00b00359315c368bmr252927ilj.4.1700604159813;
        Tue, 21 Nov 2023 14:02:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1088:b0:35b:272e:5b04 with SMTP id
 r8-20020a056e02108800b0035b272e5b04ls374278ilj.0.-pod-prod-00-us; Tue, 21 Nov
 2023 14:02:39 -0800 (PST)
X-Received: by 2002:a92:190f:0:b0:35b:a5dd:2b5e with SMTP id 15-20020a92190f000000b0035ba5dd2b5emr57666ilz.13.1700604158977;
        Tue, 21 Nov 2023 14:02:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604158; cv=none;
        d=google.com; s=arc-20160816;
        b=0Jei4scLS+VSgKA6XntO553It16nVlfcS4VGepEpIv3dZ7jhouBL/EHyI/nv3PK3G1
         oGtEsoG1Iheljize9DgZetlX0eiMU5LhDnfLQz8pjJWW2KJLtDK8k5X2p4lMc1mpDwT/
         0ledFPWjPwgoJaMNVxugAKJeGZWmkqooqeErIgtIHFtOi7RwBSNt0ZJ9BjkYuyco58nv
         46f4sDLOjoUdIUFClkAjWCZpO4sHZjuJlCmcTLnOlD7LovrMS1r6nnkR6ytyxmE5BxxC
         aIWp0xkOEaB2vH2Y+ztd8M84HSBhPazmXObehHRI42byIEhecFpES/UBKfa6H1Fx3H7Z
         WA0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VZEQ7DLTQn6OqQgSLo67A6SEZnv9L1qroObhIZ1xXOM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=EZ4WHAKCu4SRe2T1Sy7TX/iz/E7JC2xfMHK6DJixWacP3ydJ96q8a9LQvCs6Xt5da4
         yS4WOaXrdZEFp067Va9/uB7hcjI7AOzqzzEW9mU+/MZ0mLwK7Qee5VeyX7L45jwd4HGt
         djSSb/HujRInL7c+dvRkfpG1OQfU7MF8fs1fsl5/mS4x/h/67WiEH8ibwJfHCW8IwPg3
         gvjAB5AZRVfiD9ZjLAk/KSGZhctPi836CdGa8siKqbWFHq5RbZS5mz5uKDhvMajR/tQP
         8f8olcPuioaCijY8oUCRNkfcHQC8ge2DIk4HvZ1P2qelWD/F6Ayc0cxCgD8pEH5I8dyf
         sOcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mgOxiBg4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id bp6-20020a056e02348600b0035ab2f0d294si1924078ilb.2.2023.11.21.14.02.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:38 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALJ7T9P028372;
	Tue, 21 Nov 2023 22:02:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we6y4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:35 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLuF5n031183;
	Tue, 21 Nov 2023 22:02:34 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we6s7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:34 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnGnm007559;
	Tue, 21 Nov 2023 22:02:15 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf8knuq1f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:15 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2C8u22545102
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:12 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7D8DA20063;
	Tue, 21 Nov 2023 22:02:12 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0EC9520065;
	Tue, 21 Nov 2023 22:02:11 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:10 +0000 (GMT)
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
Subject: [PATCH v2 05/33] kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Tue, 21 Nov 2023 23:00:59 +0100
Message-ID: <20231121220155.1217090-6-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: pQxE31YLEFvKPgXf6AYghjpxqouNt4v2
X-Proofpoint-ORIG-GUID: BV6bqdLe0fSLFh1pyvZJn_aJSFvjCpVt
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 impostorscore=0 suspectscore=0 adultscore=0
 malwarescore=0 priorityscore=1501 phishscore=0 clxscore=1015
 mlxlogscore=912 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mgOxiBg4;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Skip the comparison when this is the case.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 470b0b4afcc4..8a1bbbc723ab 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-6-iii%40linux.ibm.com.
