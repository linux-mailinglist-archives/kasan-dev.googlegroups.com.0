Return-Path: <kasan-dev+bncBCM3H26GVIOBBM72ZOZQMGQEV3T7RUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BB8790F2B0
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:56 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id 46e09a7af769-6f8ee93828fsf7483006a34.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811955; cv=pass;
        d=google.com; s=arc-20160816;
        b=LUnbCCpR776OSZlBBo+aRroRj46opP7zKhjeRnc3ZUVzCQb6bcYb8mPe6L28FkvVAm
         0KUNPhe8WgMo9rJpDzRD+W+wmspZ/oEtL0awKlp4y+t8TtcBIclfSoT5bW8bFcT+PK+0
         4isZG7M8UHy7AcP6X4tJ51fmXRU7OJ6kS01terxeZY7Z0+dplA7UisJCL9BkyAChLvjO
         L0wXnZ6MTCtzcFUfu26MGLFth4lGEGZp1uJY/BW79WvCNY049MZ/poC49MGS9Z6fgNY6
         nnvQ2RlRw9hcl5rMsREZSYGF2wuzGKaShIVRUtx3CnR78SA6W+1BYDs9i6LiqfrGvCHH
         Z6ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1XwEaxlCMkMZ4ZGGRNuuVW3VcZ5IQePWfq8Uc2dRJr8=;
        fh=r0igP9OfVJYMarSlrox/bAdbAC4SlcdwRHrp2EsLNLA=;
        b=XVGWwmC7KUh3fPPGzcMZFrZDVoJcy/n2EgfnFVvHvXUnH3H5XyGXBtWSkL/b52Z1uP
         ps73eks4dOre6YtakaR0iQ9lW8L9+yXVcEnncTTAAA+RKhgiL5IuFQHAUoQVQixpkyjO
         0paRp1UZK711MCZTyckcuE9WVyMm96blkAH0wmPP/Xq3EaL9z15kVR9ve9BIf6UYwLmp
         n+zny63p2leucEWunUIz/cwsj3GBgztIrIrssVKUOGOzQFZ4BW+5E8vUerlbhA8NIhpK
         YFyOSprQy80z1oKL5cClPgp/LOWCRO/yR8GAaMETixsFWEZrWq+7XSbs2wTiBkZn+UUk
         6++g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=M4Gv2CfU;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811955; x=1719416755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1XwEaxlCMkMZ4ZGGRNuuVW3VcZ5IQePWfq8Uc2dRJr8=;
        b=IIqq/cAPBJH0YMmJiRdfi296xEe3P76B6qEGhgaJ1t3vYB5iUB5Bf8LES8ZL+LzRmA
         dMqyjV3+sG3+y1LKAwEsjgqqjIYsWpAKI0eChWXnln6nnsAl0yPHbaNE43i5lcy9rtam
         l8301IJqDUYYxk+08hff8dK2k1QWyirF5ZCUOh7n7ASfwmQpBHbqu8TtZ6RfJfhMEioJ
         1EGCDKfnLN6XdShWGPc8YfaAZh/XNt7hq5HcVbwndBVxbIhKKpyEXOvJAexcQCwOLqPG
         a75znksZ7FJTggrAMVOTheMoBGq/0ZDxW4FjQKWM43LEqzjHi/Gym4KFUjm3hY9jAkbo
         UdSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811955; x=1719416755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1XwEaxlCMkMZ4ZGGRNuuVW3VcZ5IQePWfq8Uc2dRJr8=;
        b=Xm3igeLQlLP2055A3d36iRPRbjgDxWDVmTC1EZQOqKn51VceIWfEMXeuONNIFxNV0r
         WQXQ5hxlU3Qbnu/hZgtDnRv7JZ0UUo6i/wParUXFeSktPk4JaX96v2DwtITZscPV3CID
         14Vp+N2yVrgDRBi1lEHPLrcdSIbmQGbAIDTU7EFmJ2MiE2NyLc0FfH3jQlHc50xitvVo
         7pFvI1Scjj32WgjphhF7FzfkOJge9p9xdhZR6S0z3BSp15H9ymz3CHSmaLUpx9vSwYzD
         fYXgzx+oDN/3w1HGg3exk6PvZ5A59oJiT8t1yJwX0yu5L70O3ytn5ZvAw1pJYldXRVOf
         6JXQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/KIvlUae4fKwExnMuuT+GI31/ERse40iRToYM7qAJT9uslCSSedgk7/xdgFtRs18nJsROpVFBHwCl6cIAl/ApBuIy+dn8UQ==
X-Gm-Message-State: AOJu0YwP6ju69DFFfsaDRGjO3NnihoOrXOAo75Dn9T4tdHINuAbRVQWf
	DDEwNW1sWsg4JDVwjVCwskbUpeZTQhhRQXgbIUa4P2sX0SMHyJ75
X-Google-Smtp-Source: AGHT+IFLOd0k2ewlCjxs37LYK+XItBL4KUMW1s7M5MSN54VVWuX9W9Tn47mLlbZ6W2HTAss/gw3t0g==
X-Received: by 2002:a05:6871:3325:b0:254:a810:cdc with SMTP id 586e51a60fabf-25c948f40d8mr3279331fac.1.1718811955191;
        Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d286:b0:250:719f:50cc with SMTP id
 586e51a60fabf-2552b685ffels1622134fac.0.-pod-prod-09-us; Wed, 19 Jun 2024
 08:45:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyLgsM5Tzun3xjHtP7ZYK7i4BgsA8Fl7lOKYuYGARbEhtGnBYwJAohBukDS0sfn/79CFQdtgKqGSSwe2QEGG4GhuRfPX1FlrMbjQ==
X-Received: by 2002:a05:6871:5224:b0:255:2865:51cc with SMTP id 586e51a60fabf-25c94991671mr3438287fac.13.1718811954373;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811954; cv=none;
        d=google.com; s=arc-20160816;
        b=VqJj8vru9KYGt8S1mPZwG+HQ1t0bYXu1/9vGrgDLHq6HB59rdZzwrRxOnNjTxgy1SD
         HBSERwSNlx2mj+WJ370kzscLmgJyX6KDdV8TzEibWCyL8a/Jf0VbD/3tPmt4KfDzkPeC
         Lv7dBomscEGhpA7wV61nyp0FKTYpZ5e4HPoIKqc3pxdpFPxsc+14GvwKXBcnrmtkeSi9
         oArhnev/XX0jCP99KHP/xK3Fm5U/eLrIpCfMgHw9wyguF9A6dHfiIxmew58p+yesKIac
         bhs9ezLwH3XY0E6ymKq9thSEpkOlBzg/gQGheCOvemAZG02xN0pp99glcmO5soyYuqvf
         g6AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tPY2/xfj0WoITwfgq4isE+nahUee+x7RgpdrRutXdLc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=tA04toM/C0Az9s5UfJ+fvXrPFsrkdMEvTNgVVBjNzjQsWzVsib3012dNhzEK7XdJR0
         cvZxtb+9OFx0YXGnsf+H247bAmpyZ5TdJ47tsKHt6OymdXGzSFDalnmg6vAZg+2Qf7Fz
         O+KXpzkZRgH25wTAIa3m9Z3NsuHZxWpW0bb5+SgLIy0YhZe90mfCjemZmM767FAt6Z/P
         H3aEDDnqN4+qH5A8RAmDey2r1u2W1aAZzE7keGyEEX/0S8gNibBlycTdXFKKlV7RnEW9
         0KuKuTmdx0gcXVw6NgLfhgZjYcTjhGJd0r9h6XWlhMr7wWlRzR+ETbl+/sJVY/jgTzpu
         CNOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=M4Gv2CfU;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25ca5c48ec4si52240fac.5.2024.06.19.08.45.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFQiFX016498;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv0p9gauj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjnlR015818;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv0p9gauc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEaA8K009941;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmnh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjg5R52101510
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E0E882004D;
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9298D2006A;
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
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
Subject: [PATCH v5 26/37] s390/cpumf: Unpoison STCCTM output buffer
Date: Wed, 19 Jun 2024 17:44:01 +0200
Message-ID: <20240619154530.163232-27-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: MQJ_dURzM-5GEVXffgkba3S507BXDR3N
X-Proofpoint-GUID: dwqmb114eEQPjYtUC_yhsHa4FOTTZQn8
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 mlxlogscore=948 clxscore=1015 mlxscore=0 spamscore=0 malwarescore=0
 adultscore=0 priorityscore=1501 lowpriorityscore=0 phishscore=0
 suspectscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=M4Gv2CfU;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
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
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-27-iii%40linux.ibm.com.
