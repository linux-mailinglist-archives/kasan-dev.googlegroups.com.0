Return-Path: <kasan-dev+bncBCM3H26GVIOBB6OR6SVAMGQEFKME6NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id D105E7F388C
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:34 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-7aad53fd070sf19893439f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604153; cv=pass;
        d=google.com; s=arc-20160816;
        b=IrSW7d+y//yYIvUj05kBYaS19YtFL7+0ioCSc+7ppkF2iyetUHdqPOl1JzMP5XRxB3
         oZPITZU4+3CJJ1sJsSqEXGWAVFqEcxGYIRmTVO3K26vjvUQSGicFFz1pIdke+mU4z5F1
         A5jpOfiS63aihCw7k0OvsP4Bwz1xyDdIwmKkUpxTRvw9mFQjHS+QhOhgOigmtnxtR4bi
         jYgRXaUEdau3t/KG2tl/l0bnH2A4TfuAvhEbj86tEgqKWPNDfiEjGQWm7jQb3Q4L0Wv0
         cd4edBCljSmQEkarNyzE5tnEtgFK7DzIDawPg66/keDvBB0wP7arWkxBq6BRNjyyjkz8
         Y4LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zQq9+DrB6jTsXY5KYYK1ugOL5MXzl13Y2GK+o0g2lnA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=FUdNvvwCQ0em4hfU8ue8SGHMDTsJVuMcJtmF/aqxtdObPP7m9HJq/5fH4vlyr5CMYP
         07NChZT7YppQA/67vqTmeD/RocC60mCOE+kI4jXJLR94Ms1e1OP4ZZ9K8ZVM9k2pZMYL
         x5fe96WHgEGuKaNWOBnQx5Rxw5gqF/1KgBi5+LhXnLQNER1KVY5pS7Mnb7KpKumzdorJ
         QR8+OPUtrTMsEcQIhRMNHzvs94VTe9VNCtpS8P26PJPZRsLsvJljMWmo+r7GDN8MA2Zd
         uBZM825dnfbpXvt5OrSj4Xm1/rgU2JftkEDvRFRLidkiCN/da/Mw6f7KRcbIs07wDekM
         l6BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pe92F3dr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604153; x=1701208953; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zQq9+DrB6jTsXY5KYYK1ugOL5MXzl13Y2GK+o0g2lnA=;
        b=pXj8WNkF8/CeiXG6FeyGJYu5wM6sghFpsuc7vZxGFYdy0ymcXNjVVce+Rf+OteHgxi
         /O+tQ/zHjyOjtMH7Eb1xgFRe8H0w21NvjBIfiOozPpAHEh9400i7V/Co/Wj+J5vIuUWU
         Krxo0hcR028DrHwPv62D0A5Jobj2E3FcDn77QiD+1qVGUwFkm6ThP3zwwV+hPfp3MEOA
         f8FknyPojVVEfU0T8Ih/Ok8/+1uVYwFoX2KcgTNQBiU18AGcKmGc6GTB8x9sgThcq+2P
         o9OeqOFCwkCa5J/RAoqdGXeAPiIbtiOGg313IDiJtDrjPdbgvir7o3MMsOhXxk7dq1dL
         V2tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604153; x=1701208953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zQq9+DrB6jTsXY5KYYK1ugOL5MXzl13Y2GK+o0g2lnA=;
        b=Y0oCRBrZ3vmAneho85dJgvHItmQ/tnZZQezUAF/ndnDAFW6t+zKXm28sy1Ek/b1csx
         2XNraOU6Ota1psZRHnaBZ5ZFwk2lmhv6WyeAv73r5R8w20Jjgyl90FtMVv6MFn5idqyp
         MgtYzsZpDIZcv1SCKYzvc//BVcvHYfXNdy5BtGsGBCjmtF6buFx0o5XfPq+ZHQyCeoyc
         Jge4nXg2esfffBj9KVtPwO7u0EURJ76DAQF/q3bPteT0OVsPtBhk1biEk8buXK8f6C/Q
         +fQ0N/A9sXvDAe7YuTrUZVteLuhKYuZQb5i3S6Pi9lXHmdxjKONK+vzfRF+OYAKXszXz
         L1yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxrE8uRdCwAr7PN/WKO/lSsFfWtb3GabdmH5+YuAKuiLZpklzkd
	tHsvbrHDTPaOcavjUTAooeY=
X-Google-Smtp-Source: AGHT+IEyJZ4KkZlc2Wkdyjr3JHSENVPlm3/W5Gf94QFcI1u05VEB1JmYU03j1Q+VIMUkOnTnxRqorQ==
X-Received: by 2002:a92:d40c:0:b0:359:cc98:7516 with SMTP id q12-20020a92d40c000000b00359cc987516mr315154ilm.0.1700604153230;
        Tue, 21 Nov 2023 14:02:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b744:0:b0:357:fba9:f281 with SMTP id c4-20020a92b744000000b00357fba9f281ls1080057ilm.1.-pod-prod-00-us;
 Tue, 21 Nov 2023 14:02:32 -0800 (PST)
X-Received: by 2002:a92:cb0a:0:b0:35a:ec21:9db9 with SMTP id s10-20020a92cb0a000000b0035aec219db9mr202643ilo.14.1700604152394;
        Tue, 21 Nov 2023 14:02:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604152; cv=none;
        d=google.com; s=arc-20160816;
        b=uRlbwOg03BkmWdpfjLrLUJtHyDWVACmBf4C7MA/8w7hqnRXQ8MfMt6VgmNc0sCuMYE
         jxXBN1VKh4W2nyx5VVV+ZiXIjAiXzxcPKVz/NAm6jYs6sJND4jba9r2rz8rXlvoJgq6h
         UeJulXMdJxd9IxTV8pQGmThAG3Dv4MofYcwG1pOMqtCSj5eBAT1Mtns9I6BQDsUC1zpI
         mB7vO+s3Kt7gBGWX7UG602ucD4kiLHMo7sBsbeWiBhd9k4SNRjkZmA/nwRgTGni1kdj9
         HvjPdK+aWkfho7Eywf86wZHjsufJ0b4LCF0MytOqLwlwNCvE7rGKNgcr5b9tyzwF1cj8
         yZwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=O8wBfJCJJ84JoxGkV/wE+lBTd4WAHnLXnoA+A7etFDk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=hpLzP6kimgQXFAOjGqXmEdpDRoUEHI4iznnJuYp+IoFuCPh7iX6UF+pYl2o9IoqAyZ
         CFtZrj5gWsFPwDz1TyMtOSKRIjGqRyKvxjcEX/QOeh0hvEZeMmPTqnE69BeaZnHhC1Wr
         MsbI4AIciiKS5edF0G6i9mBKq3c5Ne8ttk31eI+EINjAT4DA8KOj8sjquZ3L1QGP8+mc
         y/sBf05mKNN4N4MFG8q9MbLCX+5sUWz6ZzbBdYGwL/Ps4BpQsFRIJAIaZWnhtredH6r4
         lN6GhPy6sLxVun2Uvn/gFi406xxKQv0BTTdl/duKuYbiuKWev8yY1Blq08WoZ8ZqkMDy
         Z7Ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pe92F3dr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id bn10-20020a056e02338a00b0035aeaed6368si1816231ilb.0.2023.11.21.14.02.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:32 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLgbYx031926;
	Tue, 21 Nov 2023 22:02:28 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8f2e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:27 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM0Lbe014571;
	Tue, 21 Nov 2023 22:02:27 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8f1p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:26 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnbnu007088;
	Tue, 21 Nov 2023 22:02:25 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ufaa236ex-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:25 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2MUr23593484
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:22 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4002120067;
	Tue, 21 Nov 2023 22:02:22 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C563120063;
	Tue, 21 Nov 2023 22:02:20 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:20 +0000 (GMT)
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
Subject: [PATCH v2 10/33] kmsan: Expose kmsan_get_metadata()
Date: Tue, 21 Nov 2023 23:01:04 +0100
Message-ID: <20231121220155.1217090-11-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Iv65USKYmiYbkWS0ooHqZdevzeumyOMK
X-Proofpoint-ORIG-GUID: nB4chayEJtuXCJhOq5DWV1VRTMeDawyG
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 mlxlogscore=864 phishscore=0 mlxscore=0 adultscore=0
 bulkscore=0 lowpriorityscore=0 priorityscore=1501 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=pe92F3dr;       spf=pass (google.com:
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

Each s390 CPU has lowcore pages associated with it. Each CPU sees its
own lowcore at virtual address 0 through a hardware mechanism called
prefixing. Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to
resolve metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the
arch code.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h      | 14 ++++++++++++++
 mm/kmsan/instrumentation.c |  1 +
 mm/kmsan/kmsan.h           |  1 -
 3 files changed, 15 insertions(+), 1 deletion(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e0c23a32cdf0..ff8fd95733fa 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -230,6 +230,15 @@ void kmsan_handle_urb(const struct urb *urb, bool is_out);
  */
 void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
 
+/**
+ * kmsan_get_metadata() - Return a pointer to KMSAN shadow or origins.
+ * @addr:      kernel address.
+ * @is_origin: whether to return origins or shadow.
+ *
+ * Return NULL if metadata cannot be found.
+ */
+void *kmsan_get_metadata(void *addr, bool is_origin);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -329,6 +338,11 @@ static inline void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
 {
 }
 
+static inline void *kmsan_get_metadata(void *addr, bool is_origin)
+{
+	return NULL;
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 8a1bbbc723ab..94b49fac9d8b 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -14,6 +14,7 @@
 
 #include "kmsan.h"
 #include <linux/gfp.h>
+#include <linux/kmsan.h>
 #include <linux/kmsan_string.h>
 #include <linux/mm.h>
 #include <linux/uaccess.h>
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index adf443bcffe8..34b83c301d57 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -66,7 +66,6 @@ struct shadow_origin_ptr {
 
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
-void *kmsan_get_metadata(void *addr, bool is_origin);
 void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-11-iii%40linux.ibm.com.
