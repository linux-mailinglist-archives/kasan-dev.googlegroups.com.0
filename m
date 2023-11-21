Return-Path: <kasan-dev+bncBCM3H26GVIOBBEOS6SVAMGQE3UZ4YZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C3417F38A5
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:58 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-7ad3237aa9bsf620497839f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604177; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFgb0ujAG+6FjI8cyWdHcJIWL9qEWJ1PxOIZ4svb4/zLJQz/yidcMEN0Smi/Mk9Y71
         sJkWwSv3jsHKst/AjtVpbHc4NnPd4ez2iR0LRqxZ3aR6T5nI5w1+GcoHhdaJPlHY+OCk
         fSdH5pwTM2fcnw0yz00u4H9iTkpI/Bv/R2SRKFFYUDa/UujvD6FA7bh3vun3ZYy4CYDt
         ER2izHB5kcLfaCiWufWLA2w0ixlfdqsjNRh6NX+fbFzayUgMAdpizjTenJYBUUv1jjCk
         fkS+AB++SnspcHndHYb2QkO8HyXLGfIsS8mAvGmzGUtOW5a/Z7NqibpTXlyaKzMtXBPi
         Lnew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rl3oboXXoOo8MVAWZKE/BGW65K+RngF0uxX0FXl7IW0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=R7lF8ZqjGNdi6qNcBcxaCtCLvW43XrB4IIq8o7Kcpe/ss6o18vZniCke48q4IczeBG
         NS/o03J5VRE0DzzlMax9WD77rik7KZ6Ih3xfP8J3DbeAjjDbdE5vKjzDyywJeE1ZzVbh
         EEjs2xB4zXXk4TzqvdKNENF06mgEqbHly/q7yYZ2zoZZ/6GzrSeyGgz5qezqrRboElfk
         L2xnCtoCsPjzO3E2glq9drIRjmBbQArUT1sIy7rIlIGL/jdYyjYokhDQj/o/Eusa52kq
         4qK9/n7CsyehrvAica86s1PcP2wSMn+gm/6YfjohUtjy29vCHKNd8fS1Ha2xHDHHAU50
         GbSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EHg7nucS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604177; x=1701208977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rl3oboXXoOo8MVAWZKE/BGW65K+RngF0uxX0FXl7IW0=;
        b=lZLY/byxa3WsL/9jsKdAgVgUoHnOptudndHVl0lb06+b+HWy9NxwAQ4ggkDKKKm2eG
         gjBzCiTNjR/rTAr/vNe2tk9EydOhHSCqwb0g/j5XrvFQdJra2xmRshl7S6I6UvRJaTh1
         GnwzfVITO1iuQ0ZARBrsCXqyFj3U/Y44PeC/j3gYn9a5SQoP8+r2GiVlTRw8WUG1L7LE
         2QewT7ODLBhI7MCp2tsO8oLOMWOUOpVWjQwhMXRj5vUTuXXF0VNEv22Z3U5PX+QRLmLx
         mA/Uoqkj53kQ/CR5KwpcKXWAc4lC9WzmnGG82K8JMUfo66+oymkXdIZ0M9974N5ol5t3
         YSFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604177; x=1701208977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rl3oboXXoOo8MVAWZKE/BGW65K+RngF0uxX0FXl7IW0=;
        b=GBT8pDLVVeCkNAtg52tWCQvsaaLcJkGktowyUuuwqCu3D721+dqWjFJlD6dwd1kzdl
         RNIbjIUtuDdvXJX+b7cFuJU6EoK4IurZc617zMq2O1dTyLSN8waYjHvBSfb1E6Q3kUMw
         V29aT9A/0XO79D/DMW6TNapQbaJUS4xL+xBcNNAZ0QpPwBX+M/ue8FU+9Ai5v0rj533l
         p9efioQEqv8Vs7dt34USzvcc8sW9OoXN3vD3I+mwOe0u6azL7f49Dfo1eW3CLv6q06xr
         ND8T8OWQrnFs3Yqbt4IyoyxlL8+XofawIoOvBkS/7SbvEBjDY/IGv9cXUKn9OEqWjOil
         FILw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz0PxgRX3hAjsiHLn4Bi4E5TFftLDv6OaswFJUtq4YYNeQaf2lN
	M0V4itkMDU6NSsy+6ETjabg=
X-Google-Smtp-Source: AGHT+IGvsNG1UsY3Tt8t8SgItbEtiAV8D9jdERa4dj9qm7upAoBm+cW3df93Yp6ERtyVZLxtIoQygg==
X-Received: by 2002:a92:cec5:0:b0:35b:38ab:ad4b with SMTP id z5-20020a92cec5000000b0035b38abad4bmr249063ilq.31.1700604177461;
        Tue, 21 Nov 2023 14:02:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:351d:b0:357:3d9d:209e with SMTP id
 bu29-20020a056e02351d00b003573d9d209els3535198ilb.2.-pod-prod-06-us; Tue, 21
 Nov 2023 14:02:57 -0800 (PST)
X-Received: by 2002:a05:6e02:cd2:b0:359:cbff:fc69 with SMTP id c18-20020a056e020cd200b00359cbfffc69mr295084ilj.12.1700604176816;
        Tue, 21 Nov 2023 14:02:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604176; cv=none;
        d=google.com; s=arc-20160816;
        b=xHKXfCYB750Qw7/fjDe/60ouG5yz3nzPe3GVd3PQBum3P0Il+B0p/vTRel/xCL2tqW
         jU/GleEo+duMGY17RPdSfDyGnAmRQh590aeTZPIaTxQ5JUuMLxdxOJ2AneufC3CM2RNN
         RCx/eQIdauEXoda02ndmnTvaaBr2RCp8Xq5lrjAS+8CnTBjboVJbqkLYUf3vRQk7AjgT
         lFs5meYRTaOlqfUy4gcw8ESuRmv4l/W9I08H4wP0GCiqJjp5L3U7bR8rWEzgY+eA0Vwu
         9YF9uorJMlozbVV5FfZ8HHfNtteuipraWRZmmb2JJ8sbsXAZ3nRIOWmMPDD75ijFAJPH
         VJog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kfW8KavvUaBQqtKF5dduUkWqnOOlkspXX2HeV3sVIpc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=EEuwSaZzYI3M+lt14J+vVoxJtE4PALrzgcxIED4Zy7+JlkZbz0aOV8b18c7/yrXApq
         ZVx8NEDMfaOdNFrYz2R82bCpBMENXHbTswFYCPIhynT/ewmN1yJiJIVR+SImMtdV8j0S
         jdAsk/Vz7r5mWV5i6C71O5e0bq5a5X1D15bq9QYvdH1lEf2bqf6z+CReaeGvABRid7rn
         H/IRzAjV3+S7NAgH0euCgpXuMunEq0/oS/c7VV9Esnvqbj72+/BRlE22kMLrTkyFK/jY
         sQwgPSlOAQL5GAHhCY3Oyq8MtCgjmBRRt8f//bdyeIB7gjYt7TYG9gNRFUKUOQ5WkCg8
         Z8pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EHg7nucS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d11-20020a056102148b00b004508d6fcf6csi1689857vsv.1.2023.11.21.14.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:56 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLlRYF007601;
	Tue, 21 Nov 2023 22:02:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0w08-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:53 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM2rD0023510;
	Tue, 21 Nov 2023 22:02:53 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0vyw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:53 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnSwA004666;
	Tue, 21 Nov 2023 22:02:52 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf7yykvm2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:52 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2mwX17629892
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:48 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BE7D92006C;
	Tue, 21 Nov 2023 22:02:48 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5659620063;
	Tue, 21 Nov 2023 22:02:47 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:47 +0000 (GMT)
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
Subject: [PATCH v2 24/33] s390/checksum: Add a KMSAN check
Date: Tue, 21 Nov 2023 23:01:18 +0100
Message-ID: <20231121220155.1217090-25-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: L_ABN0HzUfLqG_KLz5kux9W7F8dzjLKn
X-Proofpoint-ORIG-GUID: 16J6Q4WIDKq65IooDS5rJhcteOo_izuB
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 mlxlogscore=863
 spamscore=0 suspectscore=0 phishscore=0 priorityscore=1501 malwarescore=0
 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=EHg7nucS;       spf=pass (google.com:
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

Add a KMSAN check to the CKSM inline assembly, similar to how it was
done for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/checksum.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/checksum.h b/arch/s390/include/asm/checksum.h
index 69837eec2ff5..55ba0ddd8eab 100644
--- a/arch/s390/include/asm/checksum.h
+++ b/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/kasan-checks.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 /*
@@ -35,6 +36,7 @@ static inline __wsum csum_partial(const void *buff, int len, __wsum sum)
 	};
 
 	kasan_check_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile(
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-25-iii%40linux.ibm.com.
