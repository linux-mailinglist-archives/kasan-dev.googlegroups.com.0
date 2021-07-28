Return-Path: <kasan-dev+bncBCYL7PHBVABBBZ6TQ2EAMGQE5Q7MTYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 64BF33D95C1
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 21:03:05 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id q63-20020a17090a17c5b02901774f4b30ebsf1619353pja.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 12:03:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627498984; cv=pass;
        d=google.com; s=arc-20160816;
        b=G8BvLX5x3UZSm1pR+tnUn1AD6jvBnxn6kqP6JGhhD+kbRvngwzMzYThgWhJv8I6/fL
         CDkInMygKD0t2I7NGJTs+OWdhOTWFMH0TBLRTTV/0+nBPUxNCh5NsSLDRINe/n36ZIAt
         r2EYAfi0KKOq1YuV65KBCPeHFw8avodXpA/Y0WvU3zOCRmvVwqrPRv4ndQ0fNkglov6f
         j39ZvNC1lx4T0C4K9SHkSZnyeM0QxH5opCH7kVJAwWO3lykSauAqiCUvxbmeUUj/nXUs
         +aRFlqff1MT2A/3UqwGKSy7FihP1e2uZANC/pPkhnQPILp5oryD9Bkv4Vx3NLq+lvNdp
         Nv2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qR2uJb15wBcU0EWY9cdDDJFUM1HkZG3jvwqUGmorzVY=;
        b=t5ecscbRXVk8ldt01ydWp/uQY1BKAiTb6KqL/vrno0P1b2VkYcCt/3q2pFTUREQYgO
         WvGLnQjA2mDaPcX2kuwH64OQhCRBX4obFgVSMWyVs0oHz1xoSDAIDLbpq5ho3urzZfsE
         mQQbyoH+h/qW579yGpTX1FS1A7bbhik8otCtEtZaYtrZRPY3pJ3Wa5ZG71ssDlKf5F1j
         rZTP3TFafB1gCLaltxNH3G8vIgv85U/+OWVmmcKNATMSbhgoqDSNU8Fea3oswOTRwzl+
         chKJdA515j9Xs0nGPVlmTd7qz6Y3oA68VXIbUqNbRKPGf5IA16u+/6WRQFGgcbKhvxVj
         +hpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PJxqM8Mu;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qR2uJb15wBcU0EWY9cdDDJFUM1HkZG3jvwqUGmorzVY=;
        b=fn7oXY6nPh5/X6QVUQ89vJ6a3lxO9MD+FMmYuLjMkfpWQpgTKmIggqlrgYDcP5uTCb
         +NQWz75KGLGINnJvZ95WIM/ow7F08/gqag1ndwKgHmIIMkK8df+7ncXtvbD8fzNfzFtx
         zDECKRRfYw5VkGlH4ArfCVAWSQgPkCT+BLXwq72AVaE/RHb6230A29eQ4wFe88lVsLRo
         Nx5P1jQ/3CzT2FXSaZ0+WrSTVo2tNwZ8A9k/mxKxj7kg0U1Hutu+Eo/I+jlrhWaIyhmQ
         9HOUZbsoB5TVSZWZFkvrh2DMALBl1pdT9/V0ETYiQpRHbaACWGtnWc+EFLKsEi9eVn+Y
         sv8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qR2uJb15wBcU0EWY9cdDDJFUM1HkZG3jvwqUGmorzVY=;
        b=QJl9XYiWNLVx7YhqJG1PgNvn8vavjtMZFAnSiawwOq/ZO0OsdehjUxERZ+6tou/3SR
         XZ4oQ7LPsukfGonDShJoXj54OJuvO6mdBjejzADeYmWercO9qnRSrcE8WsNkqCqlaQ5f
         DXGfSbtPDsrAj73R4EF7nc1j0IwSkZ5onWMQyqWutU48etWxUF1yJLibB0CaIUspoFSx
         EeAZ4mMvkOY7hzK1sVWk6beBEBc4ZMS7iV2Fiic9ykca283fTLt5Wa48PVee4fzdAx2E
         WCj2jZ0oCIuuR76ohapaBGyo4ikU0ufoiuOgm9VFPa3FabK9aC6bJ6dmZVDvjdvldsQM
         NPiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326B9Y++heu5cPG8aVZWVvJD170H1KGT00pszL8uqmWKB0XrON7
	mcHFkq5WcLY3attC4lUBd8I=
X-Google-Smtp-Source: ABdhPJx24CUvZ19J54fTLnLVOcWjytwLKXUpTM7McNOu9hWJ0glkGDZXk8SU8pS6F+iXzv+iNOG97w==
X-Received: by 2002:a63:110c:: with SMTP id g12mr316321pgl.139.1627498983973;
        Wed, 28 Jul 2021 12:03:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:144:: with SMTP id 65ls1133408pfb.3.gmail; Wed, 28 Jul
 2021 12:03:03 -0700 (PDT)
X-Received: by 2002:a63:1960:: with SMTP id 32mr365563pgz.86.1627498983271;
        Wed, 28 Jul 2021 12:03:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627498983; cv=none;
        d=google.com; s=arc-20160816;
        b=BDa7feOYtwQENJtNSYvcqKS/r1lSaDTINuFvuLjWzD0HNgzz8wI3mWaxBjrmdRoQL2
         SNC6dSDJeaaciNH39hWqfukIs6/LPugoyLxKhdIGES23v9EACGCCUiD7ZudT4403nzfO
         QOheSeG1TvRHYkDczBzaeuS8CpYufFnHD7aAGlP9r196PquFDWpUvToisGpCxHYvK9qd
         kScALjaTbIvzm5MJaxRCiOMBaz/LT+iKyEi4hh/0ZFbBg7IFYwfw4gUgJE+bJpRxv+2T
         Qts1Thl69xiy5UD15czoToydbxVGyt/E49N/ikkL9XvXgyD6qWYhrAXEKbXFOoSEe/5H
         RPQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8LezzyXc1E62vmg8wXGBQL0Vz13l7KfGGIMqHe37pm0=;
        b=sbBpFpF9K/OochuV7PAXJ2nY/181CEh7ak8HQPgK6RumyDMtLE8vSHpiUexfBaYAT4
         UCN7k7FRfC/9BJPtUHkdGENGnZAO/7PsVUhGHDqXmzoBp5j3pdCw5atY/JbnhvkVfKR5
         kA97fPf9g6fqJ9kUIhZ/RVNHRzYUzO4Qv3KdnMqWIRLNM0VbKUSYgeDA5ltgDyNE2ndq
         kmEecy0IUca+WfJ011rg6Tnv66VderMb3cvwUI+lt8Y1PTzXyDSWUedWpXAZogD0cJzg
         I56b6LEAOnjjDDbOPsyyAgo8Y13fWJttABkfad0HwQKQg78kKolR7ebsnnn9Jzzr+8wb
         1Dng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PJxqM8Mu;
       spf=pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=hca@linux.ibm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id p1si50903plo.3.2021.07.28.12.03.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 28 Jul 2021 12:03:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0098404.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.16.0.43/8.16.0.43) with SMTP id 16SIxbng108838;
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3b10jwvw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from m0098404.ppops.net (m0098404.ppops.net [127.0.0.1])
	by pps.reinject (8.16.0.43/8.16.0.43) with SMTP id 16SJ0OWS113703;
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from ppma04ams.nl.ibm.com (63.31.33a9.ip4.static.sl-reverse.com [169.51.49.99])
	by mx0a-001b2d01.pphosted.com with ESMTP id 3a3b10jwv7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 15:03:02 -0400
Received: from pps.filterd (ppma04ams.nl.ibm.com [127.0.0.1])
	by ppma04ams.nl.ibm.com (8.16.1.2/8.16.1.2) with SMTP id 16SJ2xMj022888;
	Wed, 28 Jul 2021 19:02:59 GMT
Received: from b06avi18878370.portsmouth.uk.ibm.com (b06avi18878370.portsmouth.uk.ibm.com [9.149.26.194])
	by ppma04ams.nl.ibm.com with ESMTP id 3a235m18fh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 28 Jul 2021 19:02:59 +0000
Received: from d06av26.portsmouth.uk.ibm.com (d06av26.portsmouth.uk.ibm.com [9.149.105.62])
	by b06avi18878370.portsmouth.uk.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 16SJ0DNl33292744
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 28 Jul 2021 19:00:13 GMT
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7514AAE051;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
Received: from d06av26.portsmouth.uk.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 14145AE045;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by d06av26.portsmouth.uk.ibm.com (Postfix) with ESMTP;
	Wed, 28 Jul 2021 19:02:56 +0000 (GMT)
From: Heiko Carstens <hca@linux.ibm.com>
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Sven Schnelle <svens@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Christian Borntraeger <borntraeger@de.ibm.com>,
        kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 2/4] kfence: add function to mask address bits
Date: Wed, 28 Jul 2021 21:02:52 +0200
Message-Id: <20210728190254.3921642-3-hca@linux.ibm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210728190254.3921642-1-hca@linux.ibm.com>
References: <20210728190254.3921642-1-hca@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: PzPFJxJ0ZhUBqUTiUpsv0108PjxM1qJg
X-Proofpoint-GUID: 03zJ3GMQF9vyTBQdUuHj3O3iMZe1d4zM
X-Proofpoint-Virus-Version: vendor=fsecure engine=2.50.10434:6.0.391,18.0.790
 definitions=2021-07-28_09:2021-07-27,2021-07-28 signatures=0
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 bulkscore=0
 mlxlogscore=999 priorityscore=1501 spamscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 suspectscore=0 clxscore=1015
 impostorscore=0 adultscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2107140000 definitions=main-2107280106
X-Original-Sender: hca@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PJxqM8Mu;       spf=pass (google.com:
 domain of hca@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=hca@linux.ibm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ibm.com
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

From: Sven Schnelle <svens@linux.ibm.com>

s390 only reports the page address during a translation fault.
To make the kfence unit tests pass, add a function that might
be implemented by architectures to mask out address bits.

Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
---
 mm/kfence/kfence_test.c | 13 ++++++++++++-
 1 file changed, 12 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 942cbc16ad26..eb6307c199ea 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -23,8 +23,15 @@
 #include <linux/tracepoint.h>
 #include <trace/events/printk.h>
 
+#include <asm/kfence.h>
+
 #include "kfence.h"
 
+/* May be overridden by <asm/kfence.h>. */
+#ifndef arch_kfence_test_address
+#define arch_kfence_test_address(addr) (addr)
+#endif
+
 /* Report as observed from console. */
 static struct {
 	spinlock_t lock;
@@ -82,6 +89,7 @@ static const char *get_access_type(const struct expect_report *r)
 /* Check observed report matches information in @r. */
 static bool report_matches(const struct expect_report *r)
 {
+	unsigned long addr = (unsigned long)r->addr;
 	bool ret = false;
 	unsigned long flags;
 	typeof(observed.lines) expect;
@@ -131,22 +139,25 @@ static bool report_matches(const struct expect_report *r)
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
 		cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
+		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_UAF:
 		cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
+		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_CORRUPTION:
 		cur += scnprintf(cur, end - cur, "Corrupted memory at");
 		break;
 	case KFENCE_ERROR_INVALID:
 		cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
+		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
 		cur += scnprintf(cur, end - cur, "Invalid free of");
 		break;
 	}
 
-	cur += scnprintf(cur, end - cur, " 0x%p", (void *)r->addr);
+	cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
 
 	spin_lock_irqsave(&observed.lock, flags);
 	if (!report_available())
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210728190254.3921642-3-hca%40linux.ibm.com.
