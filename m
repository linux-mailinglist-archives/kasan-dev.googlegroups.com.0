Return-Path: <kasan-dev+bncBCM3H26GVIOBB6WL2WZQMGQELO7L2MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF7F9123D4
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:31 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-24c6783b8eesf1419502fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969850; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLvL/1S0rqY6bjEzQk79ltY0ZaEDT7BqvqhIOeZsZS2H6N26uX6+V4hbc+Sjn2GcLf
         nEiVMRceuVvJzNzbPQ8TomD/sD7qoTsfoxUpMkf7Tau5WaqaaYJdA/ekvTWUM7EfONsA
         OEvqfRhPOD2XcpAvZhGK90yG+VE1FXh8fGITxuONJTqQxSaI0yf1K3l8e/MwTzcfKyDI
         y5pCDsRMsXbuHroXAXVP4pJPizWiMICMURyJMmSLK1JlzcPBVjZfvU6uQBi6tJY1vrN4
         aAAOI0G9fuhyrpZqZA+tiMDTPYygEQe9O5g5ltLTh0w51RvwQGzCOes2iwotNgqv7h9P
         gIbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9wz5vbpT02Eig8nHyaJ8v7Sq6vKXY2swSQmuv4lPh4U=;
        fh=VO1o3vve45ByPxeQWTO8ptBMlYJtI4P6OhFzwlZ8uDQ=;
        b=r1hAr4aMvV0q7MdDgOOk/ieGZXLoeptjuhWUuz52TgM/icsFKe6qUgGcBO460ZdIA9
         mr2MNChVszvVa03hLChr+FPAxvioIWdaxlB530DiY7p7fquZwvMNJ1sns6aYNKO8xIFN
         U3OPbv2lnC3/y8bw+UKGroIwaJe5773yO9hC0pFC7BRZm105EqwFr3Sv+GJFCJ+MUt+C
         hKIRLi4uiBEAMjRmtbmammbZWIbX9EfMh+Ob/Ie/m6V7PIkQ4a3S+2JzC/zdDyUA9XJT
         dFiiEarESALdzZYBIgGM5iLnr7z4XQPmaYANf9X6Okd8RxAyyzkrUZH17Pmya7lGW9x0
         r4Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WVsuBQc0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969850; x=1719574650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9wz5vbpT02Eig8nHyaJ8v7Sq6vKXY2swSQmuv4lPh4U=;
        b=HNoOCqBUjKlP5VwLJkLTTxQSFsC1ixIRr7kFqwK+6IhpbPlxL1DEC4jl+O+VblFPL/
         azhaQo2E9F9BhwOpiPhKesmclUEJ0MYoLxmEhYB3I263kuv+Gw1yCV3cr9BM5MKbXAef
         +wsyoOW75EITuLoCwDu/IdKkr9wYnjjqOlC05JnMEhd4UuRHRrfkpUpll9KFRLLzEMYU
         OFOXoYi7GgSX6YPfe+FEK1OjYqUD2maqa8gEhGB0aHK9tMzbT91cPX4Rb88Q9Qj5qfn+
         uC4C3GguRzmFXasLvbYNmTlMHe8q9k0TJeBPY3Hb/2f850t9xcfX07VdME7w38LKHipP
         76pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969850; x=1719574650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9wz5vbpT02Eig8nHyaJ8v7Sq6vKXY2swSQmuv4lPh4U=;
        b=rN1DMEjy5mKdgXA0rleS0LvkG0K+560RGNV+eLhy5BvlVrU/MMV/hIxgP06tLCpxAP
         FNJRU9/hrMwSJBoCUIb6BwDgi9BN2D6Vvar5kcsbZJ1ecBq56u1wmxL6LCEoimDIDy3n
         cWjbn/KFEA6/hp4b0V49g1dktkQHH8E+wH9dfLN/bPD9mcGZcGDBk9gLzxCxaKXATHpM
         dGdEGVgeHxU/4oP2Z+Lyq+c6AIM1K7/407fCUXtyiTHm65+HDoVwl5UJV2UQjG8bmj7A
         eiRTGYgoQQ/OPPl7DhJU/NfnHHsV1LyPeEN0+D8UOaFWk3jlfqo2VjBQBRDuMBOtfDiD
         8xfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVpIeY5jlITALm5Qo9COV0aGmWDpv7mGMtVrcWRVQAffK/ov7BC+xqmwvI/CriaSSAfQETTGlPQUyQU7sdZpdAjT310yc3rRg==
X-Gm-Message-State: AOJu0YzjI/qCysmaIqnhBnvFw88CHWwBMu40IRxn17naVl08UQJaRuvn
	958sjqS7BkK4dqrvbWU1+z57hddyOxu0o8g4omJjA/YaHtbUalSJ
X-Google-Smtp-Source: AGHT+IEQi2+Y3Rw/jGxd/r8/o+O/EqqaawzugWRhROHgA6sAdEnvkblogryo5HraJdxH72dSmTvr5A==
X-Received: by 2002:a05:6870:71d4:b0:254:a009:4c2f with SMTP id 586e51a60fabf-25c94d005femr8125995fac.37.1718969850431;
        Fri, 21 Jun 2024 04:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:700f:b0:23d:21b7:fd9 with SMTP id
 586e51a60fabf-25cb5f44a68ls2082691fac.2.-pod-prod-03-us; Fri, 21 Jun 2024
 04:37:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWY8MvIM36mqa5UyiWwwaqbyonCC54+CNmUPF5copJ58q7qGWAIkA2MlT/POgUs1S2BS+6g+ekT2nHgj/eBzXhgglCfiIn0yEdIWA==
X-Received: by 2002:a05:6808:1886:b0:3d2:ebf:c0da with SMTP id 5614622812f47-3d51b9e2f4fmr8475322b6e.31.1718969849404;
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969849; cv=none;
        d=google.com; s=arc-20160816;
        b=J7YAWSyJciPNplD960c3bs0XaUQXvfRDXLaJFWyphKFBfImz5GsYM/Gdo8RQjzglUR
         1EmToDW4JwTQP2OwT83P4Je9zqdObvZ5c6216aAlHz15GVQIeo2SiLFElhCh1OvGskTD
         iQRhhwS9zyAZJ8/xmQgbT04IbieJk+ge0JXMK0rPv8h/2PSPiNL/yOSbVCNle//IaUbY
         WE6KepI9hbqnwrVqm630Np2Snsod7vdFvpVXXQ+LsQUi+OhL6zRUUIa8vnyQXb+ZWaug
         ik1RVZFzYRcbKJAK7t4jqftMng1vA92x9EbEk9dTKNQwv9ZSkB3LPaQe0uHrnPH6nxpw
         iRqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MbSV/0QgndyxPpucafkqjoUk93XB7CWZmEyrMAmxEI4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=IgJW7ew0Ym/UPSXdEq58CCYt2GU93JZBPUBCc+F1FjakbSCpiRFgrffiZqy0z6cUX3
         tUnSDaB1vMOikrD8wkUSw1Y2J99AjFY+gk9A2NrbvE9JcFu++l7ilewNHwUr6CmHJJrE
         8OrVYZrdFFTzmntp8KEZwSARNDXUuBnC+vCapcdz68g2do1yK0/xDpEY2jA0XhPeM0SD
         MLo1sRgQ3dcmvGw1xbf7lnlLkrUjQh3CiFI9azYgg8E5/8v3qFSJbd539ckpNiTs80tZ
         c6faTnx5024pQhm3bGVT+wAa+bUmHNcyA3vNrFdhlHbItAfJvshSSK6krr/kfxdynRby
         pEUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=WVsuBQc0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5346875e2si64101b6e.4.2024.06.21.04.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQuHD001093;
	Fri, 21 Jun 2024 11:37:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf28-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbPwi016947;
	Fri, 21 Jun 2024 11:37:26 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf25-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9Ijck007683;
	Fri, 21 Jun 2024 11:37:25 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspeupy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:25 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbJgX45613486
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:21 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8B39D2004E;
	Fri, 21 Jun 2024 11:37:19 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 021142005A;
	Fri, 21 Jun 2024 11:37:19 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
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
Subject: [PATCH v7 17/38] mm: slub: Let KMSAN access metadata
Date: Fri, 21 Jun 2024 13:35:01 +0200
Message-ID: <20240621113706.315500-18-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: VRoYVuf6wSjVVShG8oiBisGc_65CLQLh
X-Proofpoint-ORIG-GUID: -PKd_YmlYz_4O4aDzcsYfKbEiXGbUZuR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 clxscore=1015
 bulkscore=0 spamscore=0 phishscore=0 mlxlogscore=999 priorityscore=1501
 suspectscore=0 adultscore=0 malwarescore=0 mlxscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=WVsuBQc0;       spf=pass (google.com:
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

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
KMSAN to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable()
and metadata_access_disable() functions to KMSAN.

Acked-by: Vlastimil Babka <vbabka@suse.cz>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index 1134091abac5..b050e528112c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -829,10 +829,12 @@ static int disable_higher_order_debug;
 static inline void metadata_access_enable(void)
 {
 	kasan_disable_current();
+	kmsan_disable_current();
 }
 
 static inline void metadata_access_disable(void)
 {
+	kmsan_enable_current();
 	kasan_enable_current();
 }
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-18-iii%40linux.ibm.com.
