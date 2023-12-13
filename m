Return-Path: <kasan-dev+bncBCM3H26GVIOBBHMA5GVQMGQECQSLD3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 016F281230C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:03 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-35d65c9dea3sf77698775ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510622; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDiXeDXVpZN9Gdmyv5CgQX6CVb+lOkZrLH+cqqulN5xln4apoke6lxjsEIWBFoSbJY
         fd6WmIv5TvaTrElM9S/Wd1AfMHcZPUYv987UGWUb/YjIfEqqTqyFVnrHCdqjrZv7oNOP
         qlekFuaOopMuQOnHyLvP61mS3X1Igd4uJ87H7cZ9qfg9BcaLQNDzXGS3p7HI30JNxqzs
         mZiuDs0QQBBRcffRg9XAjH3BedcHEOJWykDbP23sRDCCVAzQYMTl1uXhC7Kh2C1k124k
         m/F8JNrgGZgEznS34WHd5esV07e630KtDp39/nW10p2Bu0aee3CCklQJm1HrTfQG8Z9/
         H74Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xN9PgGorP5faUuwhQAZZt3xhVA7g+3EOUcYGPD7TfL0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Gu6iUM6IJj1yCqXt8uv6t5sQ1SFg2A1Fb6aYDgazcSY6cfTg3suxAdB97BSegftCfl
         hjxaVFbTur7u08D9p+pTGJw2R6cKNE/uhbLyv+qnETqok6JuDSV2yEoOcaWX/R6a+mc+
         ZVcXtwDwbUaedaqt0tZ2uiaU5ov4RgzgUfsB67/+XujwN0FIEKeQ7pXCVmsXsIOGkGpT
         7J5fU4QJSvULxsK/eDqdM9+nGz4W6fCOOqMpr3ArE5ZZ4sLGm3UYmy4MQ4OR/gaDiUy/
         NEsnc/d7nZKP5eUC6mg3foJDz8MACFsT2MkMNbAHRjHMsRqczlSnTgfW+7wuU9pPGtcY
         1hsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jnYe0A8f;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510622; x=1703115422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xN9PgGorP5faUuwhQAZZt3xhVA7g+3EOUcYGPD7TfL0=;
        b=vSsrBZ24AXEotDHOcvvXmjMBfi1JHSbuiPUSPLtle1wjAnq5n2QLKQqIZTD7E4raCi
         6bGzQi1ggp+yhzQmAf2drRMvGDQroL/BL8ZtG16yTGWiAinJ2ZHuDCMFndt6xVbeU7Qq
         JRFgKABNL4g9c1KoYDnpQ4ava0ic/09SfKgMwKwg5Oa/Mp6VJRExp+0W6W5rOIGFu7mZ
         6I9d4im53VTIe00LKz+B6t/UAJQMaUHsCAlL/tC6Z5eR0tyR8wFdMAIsJc/kskTTPS7r
         v81p4XwNL3jep32Iy517w1/Yb+KzV/b/Q04B13i51WatGYYtIP/8BmIEGLJHvxp28eev
         LsUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510622; x=1703115422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xN9PgGorP5faUuwhQAZZt3xhVA7g+3EOUcYGPD7TfL0=;
        b=QK72F4HOmpypJAYr9mu89ulZktLlc6wywbN49yc7UHElN19+zIuIWWb8lYS3i1O1Wk
         Da6L4JYcb1J+56a95kRjsIpBSkRd2oocjCW81FIFRd8DhHJKmF3jJ92Q3FtD3QQlhsAs
         zIIRCANvgKflUrSXp1g2PDXjJSdfs8HhrDZn2PbIUjh2H8sMUUOFEIKfiVJZQKuNPT/M
         qy/FCFOujyAyCoNVEcRQey6MJX3Zq9ttOthS+j8bDoEie+rqI7Y7vWOqOCeftx5v4cXX
         N6kc/wQw3xZwWS7Dr2L/rlRQ7pv9JQEyolrwLNYWAbmSQyHSmk7764olNtM8POkmuEf7
         Ts1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yye0cL10A7ImrSCmIe5VH9rGMKlbm3QSSoH9j1XMWi7T28xSjYI
	reqtEkkw/fWvprwvQ1wkuQA=
X-Google-Smtp-Source: AGHT+IF5jcHvFisgDawwnT9GzGX7XTZSzGilJoOJPWUuMmHXx4sQtgMAA77Y+BApEib6x2IO/TvbGA==
X-Received: by 2002:a05:6e02:20c8:b0:35d:5027:bc4c with SMTP id 8-20020a056e0220c800b0035d5027bc4cmr11717735ilq.17.1702510621776;
        Wed, 13 Dec 2023 15:37:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:174a:b0:35e:7419:87c with SMTP id
 y10-20020a056e02174a00b0035e7419087cls3251734ill.0.-pod-prod-07-us; Wed, 13
 Dec 2023 15:37:01 -0800 (PST)
X-Received: by 2002:a05:6e02:1e07:b0:35f:6607:28e2 with SMTP id g7-20020a056e021e0700b0035f660728e2mr4008418ila.29.1702510621108;
        Wed, 13 Dec 2023 15:37:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510621; cv=none;
        d=google.com; s=arc-20160816;
        b=WxzOi4xN5CS95AbsNjRDUP/1wH+z5ncbkOmeJeeFMKsbK0ErQYdaotUEmPws6xFgtp
         uctgXeYkB97ynSIBciDkL7DIVbxatvxsD5JL9f/bK+WTnlExHq3HEqna7PezjofpLjb2
         6+iEfGinZIJglZL98Lkp0Ohq8H/Mhj+V4sgxboPb/1TNSS9IROkGgMrcjVRXF+43Fq4T
         M/LY9IsLJX0F9qBAf8pV8upvvTAkyrv7Zfh8czaB3k5rwczW/l61dLPqiMsI5DmnDpJ1
         aEr4Dp1A6f0+erECXQDZrZgMOW6u9NEDyooNO3v1bpt2IYKrRis4B82GBsgPYiOXkVT/
         YG0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WBZ4pxSCZ168xcDVwjX2FOwBhQlGhgRwo9SK59J+9m0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ZVSXm2MqggPLDpIMJdEC6n8t6FntGnu5gknxhqVke61GgF/kjxzMQ2oO7wvlompaYc
         2YcespoGofhatr78Ub+wg5d4i/t1sF7oLB9rPz47UJ2zoFDpE7Q5rq82SryY3g8AqAVf
         oNiHtM9a1+cZBcDsLkG83icS6izYLxagm7AXIwF1nQEylDzo2o1Kneozt4LwrP/VJqVf
         XoaOFA/Mayllm1BMwJkufYkp6LWyF0cgSrHFME1+P7BQUdtrn4gprMTrf5C9CWRoH678
         IqfSgzakhwGmtNByKy+OQhytCcSaI5AKbi/tX5xSZEKQdiSN9UV8XEJjj2kCp+LBhKJ0
         CeMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jnYe0A8f;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id v18-20020a056638251200b0046922e192a1si891485jat.3.2023.12.13.15.37.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:01 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMS9rP011054;
	Wed, 13 Dec 2023 23:36:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne61651-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:58 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNJSMP013370;
	Wed, 13 Dec 2023 23:36:57 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne61632-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:57 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMqU2g004701;
	Wed, 13 Dec 2023 23:36:50 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skm9xn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:49 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNalXP13173362
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:47 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 277CB20040;
	Wed, 13 Dec 2023 23:36:47 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B61FB20043;
	Wed, 13 Dec 2023 23:36:45 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:45 +0000 (GMT)
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
Subject: [PATCH v3 24/34] s390/cpumf: Unpoison STCCTM output buffer
Date: Thu, 14 Dec 2023 00:24:44 +0100
Message-ID: <20231213233605.661251-25-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: YiKbpWQLLwQUnerv4xUFC7hQLzJO51wl
X-Proofpoint-ORIG-GUID: 8HJohiuwzOsfmPazVmpspQiv9nH_OTSY
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 spamscore=0 bulkscore=0
 mlxlogscore=942 lowpriorityscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jnYe0A8f;       spf=pass (google.com:
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

stcctm() uses the "Q" constraint for dest, therefore KMSAN does not
understand that it fills multiple doublewords pointed to by dest, not
just one. This results in false positives.

Unpoison the whole dest manually with kmsan_unpoison_memory().

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpu_mf.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/s390/include/asm/cpu_mf.h b/arch/s390/include/asm/cpu_mf.h
index a0de5b9b02ea..9e4bbc3e53f8 100644
--- a/arch/s390/include/asm/cpu_mf.h
+++ b/arch/s390/include/asm/cpu_mf.h
@@ -10,6 +10,7 @@
 #define _ASM_S390_CPU_MF_H
 
 #include <linux/errno.h>
+#include <linux/kmsan-checks.h>
 #include <asm/asm-extable.h>
 #include <asm/facility.h>
 
@@ -239,6 +240,11 @@ static __always_inline int stcctm(enum stcctm_ctr_set set, u64 range, u64 *dest)
 		: "=d" (cc)
 		: "Q" (*dest), "d" (range), "i" (set)
 		: "cc", "memory");
+	/*
+	 * If cc == 2, less than RANGE counters are stored, but it's not easy
+	 * to tell how many. Always unpoison the whole range for simplicity.
+	 */
+	kmsan_unpoison_memory(dest, range * sizeof(u64));
 	return cc;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-25-iii%40linux.ibm.com.
