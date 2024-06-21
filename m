Return-Path: <kasan-dev+bncBCM3H26GVIOBBWMR2OZQMGQEA5JR73A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 115F091175F
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:07 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-7eb5f83ae57sf205291139f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929625; cv=pass;
        d=google.com; s=arc-20160816;
        b=rufF1HWnvhsPOWUtDXJcjhLNy+QJ/O9NNMHv5gkem/gPV0KCcbh133Ekm/D+On+3jP
         5xVzG4opvZ4vojvdKe6hJddNs8Y8Odly1vtfep3oSpFzo4kjmvE23yg8S6uOeBm7Cc4D
         DKina//x25Y2qwTyOcUmPwoQvflZhI2O0AEOUF1QkK3TIG/prjkPH9pwpUZIxT1FiU80
         W25QMEOwvXQ2ZmnwWJ1nB/vTprkTknyDEK4nbfZQaVGCYVQlRgEe3sEKZeWh/M0Eno5A
         f4gESswkClri0Npdu4nf29X/xfQ3Xrnss85ucK86OA6/cfNfH/OnGD3Bsa39qK/3EJae
         23rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w9kPljYASzGjA57Voqd+PQDAdOOgsEMba77YZZkHtiE=;
        fh=tsORa1xbO0tdKlL6wi8afYMnadNMSU8NguWuwiQNqNM=;
        b=bb2C1P+UQvqWwlSIJNzTGS+UMWDKiPVlSLlaPv+cYc/8ElQIaYtMbDMO5/xd9A9/0P
         Q1Jh6tQh3HT+LvlT+rYDQIm8/sctKWTZ4cEJx+BVoRm1b9wIvjIcQzcK08Xxp/2Zpw2v
         b/zMFdqROr9RJdTqbc3epVWPib+OHWX1cXyyZfRVxfVeYU+7TptHY1mtxZU12+1UkuuT
         l/oLxHutUv6sWcGVfCnBoQDrxcT618Zwp/wbheFzKsD3o5RYv79bFMQkQ4dweW0n2TfG
         NfxVS9d38Wppw28/Sie6wteX5nfFSBH+74CEiiSZH+CSkNRwOfyqVNMuoNmp6tPPqHvW
         fxVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WOG9KwPy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929625; x=1719534425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w9kPljYASzGjA57Voqd+PQDAdOOgsEMba77YZZkHtiE=;
        b=hva4v1Yh58KfPHQtIu9Bq7wE1CUnb35TKzp0npqRrQbUZ2pWqR05X7+fIJOxrSA+wf
         lwrKUZRevUq1UEbUsiUAcRAk1E2DK4BE3zEJ9S14m8mqDhCgTgUxI3/h8JcI5X4RuGIb
         95mSsU6kGNgttt8XlMXhirFWGC3QguEmSE3GbOXxY+7KoO5jOSf8y+QZjSHP2aQHFRlu
         uQbGjwST9JSjboSSrb81skeFK4/kigWsEQbQ+LFgkj1c+kRtVcev9UfLTo+ffgEGpx/n
         sfiO6ZfijyT1jdlt4haOK+M9PEKnn9nYU6bpHubOtVSXnTy1rMHCBiqNRILCYe4M61zS
         ZcPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929625; x=1719534425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w9kPljYASzGjA57Voqd+PQDAdOOgsEMba77YZZkHtiE=;
        b=Lc7Ub3XnepCQ4XppIdKxMcvRkbNJagL+z8WSUUEB4HRMMfQBz08+terkixHTnB8Emt
         OAZq6CjS7QEWLIxF8ZRvtTwJRdMQzaoODtwPS5WRcHjhmpQWCAmsr1tpJ5Sw2CFiQSnL
         stoxswsKkc1RzIPHYe8OrzXncd4IsBoy9RekKnuQyrRwuoCxOJym750znf0J1TYwuA3K
         8mGhQPOVJzb/qZTp5mxKuHra89rxg1brt4ivOtgJmyOdoLkpotxA/z+no4NxGFr0F1P6
         VMijdh9Naxa3IgljhWiPjYqPHQwE5t3VFJ82vhsQd0FiE/8dd6k0wXiGUCybegnM9UFr
         ZPIg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxA1An7pDbtqm04Xa/GwRE793qyUfpsW6sZbULDd1ioYcwVQ09nAm0NTRAzZyyzKwjHBMbk3oDo4wP/lQKuMavZqmHCRdM0A==
X-Gm-Message-State: AOJu0YwJ3GuNU3j2kW2Li6yT1uHOwBe3VfpUlCmMU6W1NmYqmg/y4wUU
	mETC1lZdZWBzC/aj1wn1wGZH6EMESc3eIAgZliHFOkrIDGzYI8vF
X-Google-Smtp-Source: AGHT+IE3d9XrK31MTRW9/VYdeJGgaELLg38GByxt0K+qCPfH1CJlP66K1RAtnwP9nJiTe4B1SdsFzA==
X-Received: by 2002:a92:cd89:0:b0:376:2246:3b43 with SMTP id e9e14a558f8ab-37622463cd5mr31626475ab.1.1718929625649;
        Thu, 20 Jun 2024 17:27:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ef:b0:375:93f4:7453 with SMTP id
 e9e14a558f8ab-37626ae011dls7720955ab.2.-pod-prod-00-us; Thu, 20 Jun 2024
 17:27:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjh9fpqPrhd6XnNlhEgg+cJ7wXj8Fg6vVYW6mkEZ0YEpqzSN2+pA3J3aPGV2tVH5FdH+1mmWqSSIY7RgW81hHiMiU+8dQT3P/nRw==
X-Received: by 2002:a05:6e02:218f:b0:374:96fb:9ce1 with SMTP id e9e14a558f8ab-37609557c59mr78797435ab.14.1718929624864;
        Thu, 20 Jun 2024 17:27:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929624; cv=none;
        d=google.com; s=arc-20160816;
        b=j+uXsON4oxw37VsVKxmoYvyladb8p4EcFG5txbAP6DpIVVr1nsBV0I9OIjkBbb8wsP
         wDyCkI3Ih92njDHPu2hgGTpxQ+3hmgIBOugTUKYu714RS0Y8BokevMhKFD2OFasV05Vr
         QSz4SLiJUrW3eA4wTybE8fk7dZNV7jOSCvqx+aRQ2Camw2RkZ/nqN8f96EiqppQjvwnz
         1+iHngf3zAWzFQ6ZhhpUkQePXwz0i3BCtqBNt8WAeN7FDPvoyJwzM6wVmqxxt8zyjIa9
         GtYm/1+o1cEyHOX9G1c+TPR97F8D+tCX2Rpg2k4u+AjTF0e/ZGn77koXBdHUdxAIAmnU
         49GA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tPY2/xfj0WoITwfgq4isE+nahUee+x7RgpdrRutXdLc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rQ1VsgN83PBAHwRV0IIcuxcxnZfCFEkbMRY/i6AZr2TtQ60UMh/XafP9nSiLZVrQcH
         BIH29ocMvRswOasMCkZaRIuvmDMuDRsbG5rulECAjGC603peRtLPfpS1khMPA5SJ9WVZ
         PiGxSksNcKhccIcOan8QOCDdveGFnjAfTf9vPv+SQh316db89P0n6/uZBSGKVPJ05WTm
         7tMCbFQvdeWqcZEaeQuoY02iYtD1yGCRtu5aMmdBWrAlgD5qKVyzqjkZ0kSI11YKXRtv
         9PHXWoqZe5hlAf4Nu41hi56495mLO8ysBUeu0GhodIL4WXvqesS5QhBOEDANg5UYynrs
         iU/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WOG9KwPy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3762f27eb30si174725ab.0.2024.06.20.17.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QQck007775;
	Fri, 21 Jun 2024 00:27:00 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c8769-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:00 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QxAf007945;
	Fri, 21 Jun 2024 00:26:59 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c8766-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:59 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLeEAh032326;
	Fri, 21 Jun 2024 00:26:58 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspjn0y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:58 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QrZi54067482
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:55 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1160D20040;
	Fri, 21 Jun 2024 00:26:53 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DFBFF20043;
	Fri, 21 Jun 2024 00:26:51 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:51 +0000 (GMT)
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
Subject: [PATCH v6 27/39] s390/cpumf: Unpoison STCCTM output buffer
Date: Fri, 21 Jun 2024 02:25:01 +0200
Message-ID: <20240621002616.40684-28-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZyRH2cM2a1ar3ozL6AHjMGtgyGHBGmOh
X-Proofpoint-ORIG-GUID: ikkOvxFQ4wm1Gq2BQy-mlkcEGMDjF1s5
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 bulkscore=0 suspectscore=0 mlxlogscore=958 malwarescore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WOG9KwPy;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-28-iii%40linux.ibm.com.
