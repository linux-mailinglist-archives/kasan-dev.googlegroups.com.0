Return-Path: <kasan-dev+bncBCM3H26GVIOBB7WL2WZQMGQEU6TUGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DE1B9123D8
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:35 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-25cbcdd596fsf2097103fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969854; cv=pass;
        d=google.com; s=arc-20160816;
        b=kE4m6id9C/Ape1ZbzjJcYKlEcQdXPVWfFPTY95ZHJR6pbCjSpbeIpVNpLIo+B/HM6V
         uP2uEvAGiEthJAj3zVMYM7qmdMIE4fpTKVD+vYi8um+Dkzubv4Y23kvJTBUc6BITL7pJ
         7JlPolzrtI+tf9VWl3+4Awf5oeU6CwqbWGHOxmeaFQT7Fk5Do8ZuYc4p+zYlDurz/umv
         3fky/Yl89nYdfb0om6ulPXMkL+6cQprkplRLuXaQq1ggntR+XUKBMijU0K17eV2hEnB/
         x01f3W6MjrPg+ptsMoDbe3mRZRFbQXlk9zWllRJTXlJoT0u+s4jown+G2jUHP66lphe6
         Rc5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DQaww4fqBvZ5qoPf9/4eXBsBApO+92xKl7sqhbcIeB8=;
        fh=GQTLoTdmIQvdgjKKCX3BTW9HxYNIfRWVmLiiCVFY37M=;
        b=rOmCn1Xr+V0LxyCr1ZoMjdJAcjaI6EbGxf9qDykozTZn9M25wkrTzAVX2lsYY7ENyu
         uS1Ko9rvADJJsFB+WOISahYBgjWr9WUEMZo3amUMDmmvQKZDNoweBb8YXC804BjxMpUB
         VQrchhtGIdHW6BmVR5oeUjcEEQuYkH8fRTZnFmYjklhs8F06efcQb3jMwa1xGs4e7xkC
         6K4gnMeE66Q5NHIRuJVe305bdzKKl1i7Kc/wVbi9yfxlP9dOUZGw1+jvzoBMfwOT1NBD
         TVg19QrirRafQ6/HUKPAq5wWW9B1Uu547l9Hs4Xgu/Ngk6Ge8L9g/vor6CmC+rqRR1h7
         VN0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h2ird5e7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969854; x=1719574654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DQaww4fqBvZ5qoPf9/4eXBsBApO+92xKl7sqhbcIeB8=;
        b=fwYz3SA1/659It25Hdbkztay9GOV8dv+Twf0WWjBjH7xFr+/LfeK9M51E2AHCpbQLt
         wufKLuQWZZazw4mMyAJxsvuie7poCYVXZh5jzBL1b+eS05xbfXVHokSAY/0oApzT9YLR
         nS2PHDIh3yAqKasJo4CxuyR8HTefqNuEolI4smQ5ZhQ0HIJ3RghiqbOQbTfJwPARR6Xe
         YXl4s/qB8HgstC8gMD3ZjIlHRbbVqAdC0MD4Y0l8JRl+0+03p8GXUAmHvCyf8DRqkT9x
         MlSNhNgSrAcL9hsvix2gyHcXmWpIuPGoOviCc2QJiYjdiQAO1PdskYPN3BUur2UBokAT
         xqKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969854; x=1719574654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DQaww4fqBvZ5qoPf9/4eXBsBApO+92xKl7sqhbcIeB8=;
        b=RZ9IT4PWllOeghpKjJBVrE7N07A4sK9o+3yZkKBkiRyZ5abcDHv3OaJr02DEnsaFT/
         VMWjcRflL2LG1GMEmt9STpOu2OcCF/jEmUewwBF2eilkutpKOgn3RnAvb9vgnmcwt+UP
         51DYxV77Onaevb6ssAsH2LFMhfTafpoI67cCotg6adaoaA7gylCsEq1OkUd2pnTERMjM
         fMFykOyaFe6mQXnX6jnJfyR1kwwqXFec59SimdR2FMotdSGxdDc9NLkpBVb0xCna0ugV
         jLlfvB3g1H/A53WvIJ0EfziWABd04LMtqVnfbQx5KrxSn3Tft+pnlNI0+QhdloSr9P6d
         Zd5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzhToYZv+Uglh/JtE809wht1A5P9WCuP+YLGz8B5Pwi2cO8RLfpYhbyOfAU7AfsUuk2wvxzgUoPT3AFU5+b/bRbhvALf5YSw==
X-Gm-Message-State: AOJu0Yxo8/VXnyGgynnTaKB9q9+z0qohz5ccfE6BSRVvnAglDKVep/0i
	R5S8sk8WFuDy3d0w/CS5fo9KHb9S5s3Am9lz4QmHdSYn3HuPm+S9
X-Google-Smtp-Source: AGHT+IGk0MtnxceX+vtMSk1W6qEz/LtfsHmoBxAdPcQJLWDTrMOY71J/OqmScubdDNYZ7pMxmuSqgQ==
X-Received: by 2002:a05:6870:524f:b0:24f:d3ce:fe92 with SMTP id 586e51a60fabf-25c94980cc1mr9332640fac.14.1718969854323;
        Fri, 21 Jun 2024 04:37:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:418f:b0:25c:a475:98e6 with SMTP id
 586e51a60fabf-25cb5ed50d7ls1698171fac.1.-pod-prod-02-us; Fri, 21 Jun 2024
 04:37:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/G7fgLrVMK/uWmP5sxHEY0LJY3DF4MVRKMZZaFAD4hVkkHvRH3Li7J/tr55dvwZMMB2M16xOCffqiBqYX6gv5h9gab4A7NtKuIw==
X-Received: by 2002:a05:6808:1451:b0:3d3:597f:24b4 with SMTP id 5614622812f47-3d51bb05068mr8213037b6e.57.1718969853619;
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969853; cv=none;
        d=google.com; s=arc-20160816;
        b=o0uWRLxRRpv1NeyCPN4S002HKAz74RYaONOaXd4MOoCUyPlhT1QMKsC8dIQMXCkQ5Z
         MYcmeUd3VsPccb+jhGoVyPzjolsIA1nlMOEZWxTq7MmdgqBY5dgvHT7dTaQmRcJI3PC2
         EEEHsvSllVfsukry+yntlppNUbpRGJjXA+GMBF976FPJA4iI9BuCJ7BfRKjoJ54fpOhC
         M2Vq+4e0tAEfOqHDEds0RDQuLALMroq3z3FLIr6tQdf/858RVuGF9/r7HdUFgwmAoItT
         Rtiva5fJFiIqPuTjx2jieGZhB/cicObp7+uU6cv8oS+IoDXafuYMjep3KQxO6ZEIfpI4
         x2Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eOJVqKOJuZasA86pPY8j/wtn7XC9Zj2RO1nXjWn3Mgo=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ol3jCvk2ZY5vPWUXnmzIE0DKMzTPIfs75j4EMt3UOCR2vYfXIhRx/r8wNbMBGCqTUu
         MT79SYPVyhbqeKBT8QgH8r59fbbxaJR7UCkVgwd0TtjPE65ip+qcSuuSmQQW0dGe27zx
         HHGduq0nCtH+LTZpLB8yZ6XI2XsRrtggDaYRh0HkjvYsRF0w7jcSLPJn2+nTTlktNYI8
         H+ZIWjVuBl51y2lIPBZXAHDMFtoYzx1u8aepO9s2SRCMJldJpZEyW6R4hWRNb1liSpZL
         m1W0SrIkBbQ4ZU8Zfbl4B3Ll25TqsyjgaEIOO4ymmcqOJMbxpL6kTDW6z9bx/zJshRlq
         5J2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h2ird5e7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5344e7c93si56112b6e.1.2024.06.21.04.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQeuM012239;
	Fri, 21 Jun 2024 11:37:29 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw89g0290-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbSS1029851;
	Fri, 21 Jun 2024 11:37:28 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw89g028w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9DLqD031890;
	Fri, 21 Jun 2024 11:37:27 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv5u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:27 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbMLp56885692
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:24 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F0FEF2004E;
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6786E2005A;
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
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
Subject: [PATCH v7 21/38] kmsan: Accept ranges starting with 0 on s390
Date: Fri, 21 Jun 2024 13:35:05 +0200
Message-ID: <20240621113706.315500-22-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: toFATofS8B9_Z_taxWBad7ov9MB1B9Uz
X-Proofpoint-ORIG-GUID: 9wCxo3our9e3SLqooNZeo9rdl58xG5ZV
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501 mlxscore=0
 bulkscore=0 spamscore=0 suspectscore=0 malwarescore=0 phishscore=0
 mlxlogscore=999 clxscore=1015 impostorscore=0 lowpriorityscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=h2ird5e7;       spf=pass (google.com:
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

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390. There doesn't seem to be a
Kconfig option to describe this situation, so explicitly check for
s390.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 9de76ac7062c..3f8b1bbb9060 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-22-iii%40linux.ibm.com.
