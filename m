Return-Path: <kasan-dev+bncBCM3H26GVIOBBB6M2WZQMGQE7UEGHYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B147E9123E5
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:44 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1f9a0cb228esf19212835ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969863; cv=pass;
        d=google.com; s=arc-20160816;
        b=vxgEUGj1rDqgiljHf9PfYK7RF4Pl2o8laUdI89ev6fDObp+Wp2peLvsUbniGXYxrGt
         mPqmQ0Fm1VJW9hPbqWDh67dM8cO3EgmZib5LlFgZGfm4lKL8IteCM5kRrUbcs1XsKWtD
         fl+R8mDWtyLZbVPui5zesdIalaqIq6jdOrgSgl5FaDq8OsZV4XiS97Yx22G4/B2X4QpO
         qwXSEtjZiUKFDtYGqjIQwuMWVjiSxSuup4e+RntLJLsiJLqMMkleM9GGB7A8c6hmY7FO
         /oZ90lxK850WaSQkUTDE8zAIDULdptq1hYAsF8dwSykHW6Q2ZaC7Ux/NZYbgJ8Ag3t4n
         +qqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iAZTQwonRgj/+5co3iCv0NED2UlPPQHUtC0jnjnEvSg=;
        fh=yppp+WBt+OMU6qSaG9TBPFVcnlVOlzEBh5Lm4jTVvcc=;
        b=XSYjfRl2XZamLBbHJwpai5H/vKmLSK94Txd9S7Rhk1Tp1oFGNs/XQafu7xB9fBa6qi
         QalUd74OlIVUP6qiMeFtsJ+nIRp09C5bjpgCiLoymLmAz1/91b8g5znugPiDIuf5DhEL
         0MhGXit1mQ9AsPj8VTGVuR3qoRF1C460rrUp4J3cJ8wB6XF1Sw1FzrzcXeMYYYx3M3Fm
         qqzq3ONUZI2k+11vp6uhNqQRQkQJ15sgJ6NcNn2NTRTbLPCX+zpANU7T+s55X+lBUMc+
         OhZNrUaAVDd7/xYN6sw2VOygv1+Y4qxn1fXlYaYnmCd+fwNiTwg0grTNP2WqfUKvbhss
         wMzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mvP63znE;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969863; x=1719574663; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iAZTQwonRgj/+5co3iCv0NED2UlPPQHUtC0jnjnEvSg=;
        b=lYwolJdCqzMYmBm+U0Ex4lfgz8h7Gu6hqM83LxC+OenJjkPlQG6FJui9L5AidGupCp
         8lFr+ENDJZhNtfcgBso9fziHT6HHH9wRsPV6ZYY9OyFQq//bUGVtiXWzWY4IaN5MLvwR
         IiEWuVgfeFAmNja3aoT8inOm74gYNAjJXrG+wobZisVOwla8C+jfnlT4ugL1Z3AkXpG5
         uYy+ze6QkwmFpJ1Pspn1hG1zSHNdUDHrxG4W+G4qrZLIzaZnyKuTFCmYhgBcqjFZxmDc
         liG08aOg1YzXr9mNeC7C6Gd/opDbsdtCHNrt4uYYqeD0UCZejTxMysyjEwbKZRbnvXOg
         Ibig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969863; x=1719574663;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iAZTQwonRgj/+5co3iCv0NED2UlPPQHUtC0jnjnEvSg=;
        b=tbxYBIF+nWMcvaFY6mmyM5PAoZlyX9rHRfJFtOGSfX7k0thrziAofNKi0yYQXn1rf0
         mRp4Lq12IVvaT0UwO+sU2/RaSl8xRMqIpfvvhfgBxytjRlzRqKx6CRweE3Z/3DHAEqlU
         wodH8cRCQM3lXuCuBTLJhbuZpiEDrvrdGNmzeDSGVKFh4TDEN3wnZkBIysvogmOl1Klr
         YuqNPVucsdms4govS9gaguXdoigBzoDD60OU2qsT8AXFWzyUyfk1IWyMCMDhSi4/qkZf
         QOnj3PbTRuWdvhtYKxBPUAv2R5gvxs7jrJVCkpVUOio5B0aIjgzIaJCgtDtZApzvoXD2
         yBeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnGi37bTVRHHIS5hGrEcaSNdFfPCyxqPp3Q5ecnuwGZq4OAq0cmSoZ3A+Fjv9IOaeFtKc1qSM+bUbG0iA8QvNs5Q5zCKIsiw==
X-Gm-Message-State: AOJu0YyT/W80c0beOE3v17SI7ctOaYpMC91rUQDAkxMCirFSnTOGyN5V
	emkB9HNsoaULzCy9V602O/Xelt3wwbQgAM0YiDDuVrBCfDj+K+3g
X-Google-Smtp-Source: AGHT+IHaIADBjG3yakRJM52vnOnafyOGbl6BaR2eCm6miO7tAtYsYnIydUDIr7a0vn6S0vzsd82Oqw==
X-Received: by 2002:a17:903:11ce:b0:1f4:b859:cb60 with SMTP id d9443c01a7336-1f9aa396f5amr87791595ad.10.1718969863255;
        Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1cf:b0:1f9:a616:fd14 with SMTP id
 d9443c01a7336-1f9c513f3f1ls12852265ad.2.-pod-prod-02-us; Fri, 21 Jun 2024
 04:37:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5Q7CSbpCYvA3lLUTxsnBj52ZE7jaX4v4M20gwa/nwatHB8MQNqaNCKWIDo5LaeU683W/xyUPvjNSLlbrrz0ObJNGC4rr/GOP7/g==
X-Received: by 2002:a17:902:cec9:b0:1f8:393e:8b8c with SMTP id d9443c01a7336-1f9aa464599mr87817195ad.60.1718969861978;
        Fri, 21 Jun 2024 04:37:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969861; cv=none;
        d=google.com; s=arc-20160816;
        b=TmLMNj7/AAj+C3ijZCn6/sUXEU+G0duEpmlhQ0deUcaa3q/TlXK4Iod8XTJsbn3SlQ
         RUUSyy6mTbFYpP/sbZOwLcN2QqzSP7VTW7521GSn5pIlWSb1H7ylHIF81vt9RM8AegNk
         py34/RsE/I3dB3N8aUx43ZCiHLfW276/6RVYqAsRdoO/Krp34Hr/p/ufbfVA2FSSmjkV
         b3hwh/0R/qPuzIRFX012IDMdJWlq7XnkhqdJaI3JrzyPrlyz/ZQrsFjvC15p9Nb1TdfQ
         hVYm0UAzaB0y+z+cspFtV4N1T2HyYAF9c1dLr5OOkQ+eN9eBk/g2k8GubPlyQ0ZxoMMA
         hDbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dJTBCTVm+DYwwDfuPqhjkMdDHVgbTJOgQUj+bRO14r8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rg443wcwX0rgcFUeww1eMfOFIYVJOQhzHgJVn1SbgY8fEFlhi/Jc6/cN3kyDG0FuJF
         WQi/7cK2h2BtGvSqMnhQEfrKcYC9B39jHiRf4pxgE3bETt40epgB5bvh33XpJt6H3AoT
         9wA7zWO7muzlkPsfII5NyNeF0ScHmzqB5i5vxdcE4j0CJHuRja8jV2hjE3/1UMmMCocZ
         g4/pPzDX5ut43n4ySBaG8foIJ3BFMlsynBnWAnxcJrPVQbmyIwGoWAGqEw4klCbNScnd
         jk+jIhbK9uw8Vb+xpW7vXBsf9AgJxbTKbA9t8W3xtlEL22XiKoMXaIdFkRyEfR6Ztb8U
         52Ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=mvP63znE;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb3c4d12si476315ad.11.2024.06.21.04.37.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LATgMN018262;
	Fri, 21 Jun 2024 11:37:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t5046n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:38 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBXEi6012851;
	Fri, 21 Jun 2024 11:37:38 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t5046j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:38 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9EbHe025663;
	Fri, 21 Jun 2024 11:37:37 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv6w0u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:37 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbVHE35389950
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:33 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C1E7920040;
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3803320043;
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
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
Subject: [PATCH v7 37/38] s390/kmsan: Implement the architecture-specific functions
Date: Fri, 21 Jun 2024 13:35:21 +0200
Message-ID: <20240621113706.315500-38-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: zaL6FENoUtTNqWUO1NRkU-7HlS4JHT7A
X-Proofpoint-GUID: dbvEu-32DCOymeEi7JVqGwWM6oYY8HH_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 malwarescore=0 phishscore=0 clxscore=1015 priorityscore=1501
 impostorscore=0 mlxlogscore=916 suspectscore=0 mlxscore=0 adultscore=0
 bulkscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=mvP63znE;       spf=pass (google.com:
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

arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
prefix and calling kmsan_get_metadata() again.

kmsan_virt_addr_valid() delegates to virt_addr_valid().

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/kmsan.h | 59 +++++++++++++++++++++++++++++++++++
 1 file changed, 59 insertions(+)
 create mode 100644 arch/s390/include/asm/kmsan.h

diff --git a/arch/s390/include/asm/kmsan.h b/arch/s390/include/asm/kmsan.h
new file mode 100644
index 000000000000..27db65fbf3f6
--- /dev/null
+++ b/arch/s390/include/asm/kmsan.h
@@ -0,0 +1,59 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _ASM_S390_KMSAN_H
+#define _ASM_S390_KMSAN_H
+
+#include <asm/lowcore.h>
+#include <asm/page.h>
+#include <linux/kmsan.h>
+#include <linux/mmzone.h>
+#include <linux/stddef.h>
+
+#ifndef MODULE
+
+static inline bool is_lowcore_addr(void *addr)
+{
+	return addr >= (void *)&S390_lowcore &&
+	       addr < (void *)(&S390_lowcore + 1);
+}
+
+static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
+{
+	if (is_lowcore_addr(addr)) {
+		/*
+		 * Different lowcores accessed via S390_lowcore are described
+		 * by the same struct page. Resolve the prefix manually in
+		 * order to get a distinct struct page.
+		 */
+		addr += (void *)lowcore_ptr[raw_smp_processor_id()] -
+			(void *)&S390_lowcore;
+		if (KMSAN_WARN_ON(is_lowcore_addr(addr)))
+			return NULL;
+		return kmsan_get_metadata(addr, is_origin);
+	}
+	return NULL;
+}
+
+static inline bool kmsan_virt_addr_valid(void *addr)
+{
+	bool ret;
+
+	/*
+	 * pfn_valid() relies on RCU, and may call into the scheduler on exiting
+	 * the critical section. However, this would result in recursion with
+	 * KMSAN. Therefore, disable preemption here, and re-enable preemption
+	 * below while suppressing reschedules to avoid recursion.
+	 *
+	 * Note, this sacrifices occasionally breaking scheduling guarantees.
+	 * Although, a kernel compiled with KMSAN has already given up on any
+	 * performance guarantees due to being heavily instrumented.
+	 */
+	preempt_disable();
+	ret = virt_addr_valid(addr);
+	preempt_enable_no_resched();
+
+	return ret;
+}
+
+#endif /* !MODULE */
+
+#endif /* _ASM_S390_KMSAN_H */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-38-iii%40linux.ibm.com.
