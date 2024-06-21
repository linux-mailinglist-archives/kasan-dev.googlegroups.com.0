Return-Path: <kasan-dev+bncBCM3H26GVIOBBSER2OZQMGQEDBGFULY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F08491174B
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:49 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2598b09a748sf1855166fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929608; cv=pass;
        d=google.com; s=arc-20160816;
        b=GpyQh56QdK7EYZPAVju8xpl1x8kJG0I8twNfNYVFjthDtXCGMdkasZg0vOfMF39xAk
         lG0AiOm1trvsS0cJIETMRYitxvmF3gkvL9rkQpTu6V+phRNx77iWLJVSrDL1obyt3P3G
         59f8S8HFlp7FXvgRpSokufsAswxMDk4BG6B7i73FrEOBMrjg7+CVuZ5g8M42aAqLo+CH
         jcNTDwClD0NSphT26+sYP0AKnLuLxy/T5TUB8GK1HhUJvh2NXs5eF3VsDNsPF0T8pEQK
         tvswvZNS4QnDZvzgFhXC3FeyaadNL6nC9oNcfPHGLUL97078kJarxBGgK5bgSXBq0Lze
         oVmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=e3vcmPE93lWDAfD2ApvMrTMIaznc3ycyhCMbHZMpKjE=;
        fh=k6eV2uSUsDl3ORN2OEFhymjmKs07RnX+gTD+SpxdbSU=;
        b=TVkYkygSyHB3mmJmHIth604pEF9pX76gnLcgh85r9ITdKaX4Q3RTrBwCy96d8yaD49
         1M0Peh+u/o0MhirLI74LMjuALPA86UNi/uIYQu0p4lm19BXH4jXMF7KdYsIqYjLc+YHG
         iVYNRTOXooGEPuZv4LwlWWzis6g6cy35PJhiw3KVqm3oefU7piRIk3OABUP0Cz9u9Dqv
         yaKHh1igjv79mR0nj7JlWjWev+69xHlD1SuIhZc6SAP3WA6AKrfHjS48QfytXrMar63Q
         5V1f7wTabvjcl8vM1rChnQM/cqaYUcfJ9k6erIF5fHCqgqmsk/tvECoqFOCki3HAjBiE
         TvDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TyYZLocx;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929608; x=1719534408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e3vcmPE93lWDAfD2ApvMrTMIaznc3ycyhCMbHZMpKjE=;
        b=XRzxEkRSdqNo3PZ2BgbhpI1Ht91CBSr8MWpvgXys6lJJA2ODy7wVpoge4wkeeRq8qK
         atJ5VGXxMVq32c0091Lv+QckszOSlqKBfsx1ithTvsLzz1KttC3p71KAqbdiMkwOay96
         WY2ORcjdZDeQmoF4IC1SZ2qLAeCYMK8b5juLvPFfQZUI6+B2Vf8Z7B96LaE9YOwur37M
         RNZSmUAB0PikWeoB78WRsioo06VpPh8Pz6UW0NA6yYLmua62lHHDCyZaN4rgOgmAqWSV
         9Knq0kXthWVVNzKT+yADk1wmRaU895S4O36R83YG5p6buEbmVq7ymFgothjIYeVf/tMa
         F/XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929608; x=1719534408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=e3vcmPE93lWDAfD2ApvMrTMIaznc3ycyhCMbHZMpKjE=;
        b=i/tDxQt7aGFV4I1q6Si7+pX0dPDu9yXABlEKvptWetIGLmqXdx78fGfCVIvwmCVRgs
         8aDFuSeyW0NrTJTphs2wkLUXwA+aX/cLWUIjPew4FdSeksdegpsN2sqTWxXd+HPIPcA+
         EcEpTekX/n8uoQJLiwd5YlQV4yaeqLgwb3gmQIQ8nJoNOQ3NNMV84lb/tb3hz80GduuW
         f3NUEO6xXzAuX98u5XVm5I5xbBwwAupMvp9hMjFZWUFnpCc0MxnoeH1Q5gAf0GGjW9Fv
         NiXySdNxGUeoF3NZAvuYJamERczyCFWmGh8tRh98e7CEjCdFWVQ9qnToAPPVd0hw8EIG
         ghcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnWb1U8UM3NicbZwLewsKn8Aq1kv1Mesm6zxUJa5ICSx0yP23f4oB9f88SR9rLK65VPWrWg0v0PTkJCBPXMeneQ5rbAB8tag==
X-Gm-Message-State: AOJu0YwP/+SLk+s4AnBjpK0bJcwo4fkMpvTNd5si9MO1T6nSx0kC6c7R
	nyVqf5XStnv4LZvN4UY76uVeeA1Ri0D83swond360c13hGURrxt0
X-Google-Smtp-Source: AGHT+IEsnEJb92PSggr4Sxf5lICTXOIFGVPx2Qz8QTUZky30STUZ/jd+dfk2ScHGANkAr5Lskm6JSw==
X-Received: by 2002:a05:6870:c69e:b0:25c:b3c9:ecb9 with SMTP id 586e51a60fabf-25cb3ca26afmr4504630fac.4.1718929608334;
        Thu, 20 Jun 2024 17:26:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5305:b0:250:a95c:3b4d with SMTP id
 586e51a60fabf-25cb5ed5094ls1618603fac.1.-pod-prod-03-us; Thu, 20 Jun 2024
 17:26:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCTV1upcc7XonRmpKAm+5El51SC2aDpJ/ZesXQp+fgGjeHtr6hTl9GNWupPKw+mv7AFMnHLfT0GAxUCsKfCiqmE2jlARHxudB+Dw==
X-Received: by 2002:a05:6358:3115:b0:19f:431b:9203 with SMTP id e5c5f4694b2df-1a1fd3696f8mr868698655d.4.1718929607447;
        Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929607; cv=none;
        d=google.com; s=arc-20160816;
        b=JNrvVRugdg1bpdvLdMA9FiCs67tDFYbbrVWAWea7krTRj5cA1Bjf/C+prz2J3DW+jW
         5D2fnK9xyWm/hZ82b9lG6CvaptTSbPGS5rJcRvEQur/wBEFfNQ1lhUku3qzqfIJsc6WF
         Pw5x/ZDqhio/cP/PtUxMA9btQD4femh1/breNvMjLNpyJHReIkyi/tuXhYm8kwp2MbnD
         uOQ+7V36NqTI2mKru7NQLLsITPeZZedFLn9QwYHFSGQTUi4SEIXA8MO7inCLRQ1+9Ff3
         Lg4bvb7ggGPINybpm3GOxbGr0fqd+lKGcfod5AneplfC9BQrFxx5V55cuIZ0+9fJBjXg
         iPuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wYZcdN8GaCldurJMmgBO/xn6iWaosLK3Wj+Mr2vvPT0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rPiqO1UpE7bpJqErobLBIVKOcFCS9v66e88+GFUBkinKbM67OmCdVRLV8A4mthJEFg
         hjCTAvFVmY9ieFzuhPVGIMYLepUy18427rhvIGGBODOJgLHVWXK0VW63oeUwslXnMKWx
         xrCk7yAm+wpa5oINq1w4Dr3uH+1/qsnLOiVhK9Zp5MvgUTCl6pDUamehC8odYxb8d9GA
         r6yThsEbhl3pImo58AN76R0QUuMmzWJkMjUB63WkfpKDALk/H4hxSuSch0gpFnQxGKuV
         HLV65VGy6w7PujU3v0FtjcS6igwggYG2A0PdTOqtUfvcw4uGjzi5lzhc8BO9zseE8Ozk
         3UAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TyYZLocx;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-716bbbc6b2asi13157a12.4.2024.06.20.17.26.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNSIao032554;
	Fri, 21 Jun 2024 00:26:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c070g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:42 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QSYH022603;
	Fri, 21 Jun 2024 00:26:42 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c070a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:41 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0EnR4019910;
	Fri, 21 Jun 2024 00:26:40 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqujnwx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:40 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QY4p49611188
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:36 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A9F7720040;
	Fri, 21 Jun 2024 00:26:34 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 86EEE2004E;
	Fri, 21 Jun 2024 00:26:33 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:33 +0000 (GMT)
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
Subject: [PATCH v6 12/39] kmsan: Introduce memset_no_sanitize_memory()
Date: Fri, 21 Jun 2024 02:24:46 +0200
Message-ID: <20240621002616.40684-13-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: HVD5r9y6qc451bgRBsPVDEcQFobrK51H
X-Proofpoint-GUID: juOALtlB8s58b-RD-irHl1aByTJkzhA_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 bulkscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 clxscore=1015 adultscore=0 malwarescore=0 mlxlogscore=867
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=TyYZLocx;       spf=pass (google.com:
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

Add a wrapper for memset() that prevents unpoisoning. This is useful
for filling memory allocator redzones.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 14b5ea6d3a43..7109644f4c19 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -255,6 +255,19 @@ void kmsan_enable_current(void);
  */
 void kmsan_disable_current(void);
 
+/**
+ * memset_no_sanitize_memory(): Fill memory without KMSAN instrumentation.
+ * @s: address of kernel memory to fill.
+ * @c: constant byte to fill the memory with.
+ * @n: number of bytes to fill.
+ *
+ * This is like memset(), but without KMSAN instrumentation.
+ */
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return __memset(s, c, n);
+}
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -362,6 +375,11 @@ static inline void kmsan_disable_current(void)
 {
 }
 
+static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
+{
+	return memset(s, c, n);
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-13-iii%40linux.ibm.com.
