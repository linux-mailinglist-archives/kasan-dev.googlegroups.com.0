Return-Path: <kasan-dev+bncBCM3H26GVIOBBNP2ZOZQMGQEGJZY2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id DC6AD90F2B5
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:58 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-25ca69dc35fsf487772fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811957; cv=pass;
        d=google.com; s=arc-20160816;
        b=zmDx4SGshnvwAlsOAe8nYy4o26TD3/IQuQ3C0a3R50H1yPfGoOmW7uZGHjtrtuiPu4
         6sWdNBXLD63fyibr2OGR12BVHax90YHlTKBvYhA9UJRoXY8dkmk5JnHVr+JMJ8Y5Hx6g
         9cc9w1J/e/KlIBOfV5N6OVHNo68TjtfHIZHlQ8Zl1xcj6jICQ1dhFYxd7Ry0e7Y9AGGz
         HyyMFuEW6pU59I4EmglwhwfCJw2Kw+yXizlWuKYTfrS5jOOuM8gSauGjsvp/a3pIL7Rs
         VQdd3pXwSeHz1EjX4cvkduGxML64SokUL0DPbpSdayJhkOY3FbdA0UTJ6TL2lZHEHUOh
         tjPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=n/Ia1SJg2t6YqQKkZUv5jXDlze6kjW1dSqSXWWDEe7k=;
        fh=2Iu8XCnwNklFB+R7Ko1G2RRNkw+kQG8pJZTMtLCMui4=;
        b=H0d+TKUnhs0TcwILcrZFees40BQxwkKJGXe1FCuo8i37abQqlF3YFFONDRIX5d9OcE
         +tN+B3Vw+FGmmu3hLDKl/03+HXByAo324/7CrbFoYmkxWofNgnRy+FiARdFvvN0/wX1L
         ire8jTESF0RLRYNuWxDRjSxnsWQhAs53FJPrU1Bl6I6+Sk8dyuDtrX9ZPX9Q7s0J3ABe
         1GvrPeE3/oH78e3Wfth5QDHN6cbc71SYG1/QLjuDQ5TATOMUJ4u0zWGZ6a5KCz5+rY0E
         LyXDqn5HnWi4JjdztTwjIMnekyiDIqan1Eh829u8U+iLQ4RZM+DY308bUMj8Lj+GLKRs
         dtuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BEPtJdz5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811957; x=1719416757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n/Ia1SJg2t6YqQKkZUv5jXDlze6kjW1dSqSXWWDEe7k=;
        b=ifzhE0Oqeae9OUVwX0+mB/3XNt+36+7IQTleiVhhWqWvDsypxWyhGKbGj6du39Rgrs
         h5rICL4H5/wcLyD/MWVcai9dY5U6Tkqj1q+LdNcfXOg5o/eBysbYvITRG3T1yliCY1am
         b4ZaBSX+2qZkfv2Z0ZHmVAZb/nLuBFMMKDVOX2bMobcwRV8zKc1N5GK1oItEnYGSmDSg
         8nyLdMWOIdokViXcZsoPsn8/+Y58bhUfKOkytpyWPZIj6pErQy5cijwkVIaOs0ItdHOG
         4iBrmn98oZPMzhX5TR94Q+WugeE0SWaSKk5e5asBkg/8HU1iHGDTO0WkcB3Dvd3tB99t
         XTsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811957; x=1719416757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=n/Ia1SJg2t6YqQKkZUv5jXDlze6kjW1dSqSXWWDEe7k=;
        b=TAo4CEgEo/xEe5e4KEWOs97JYvc5Z4sC3NEvkC864mbKh6uEUjraFSSQO1l2xvQvBM
         JlBt09GwLoqQvV0yuXVqW6qQAQPby57D5P3kcW8rY8jawweb1Ipspc87A65t4ORGdkNb
         BK1zT6NEujO98cCilqPVuG+86d8pUYqgqkwNWQAFAjiOnEL6wt7FsM7jRxfe4Tn+EJrm
         OxGLYS6vEv7D0V0J3UbBmAn8KW3CEOdsXpzZolzAeD5MHfe01Qj0BD5djgyRIOKPBSbR
         v50VdDTx2cHHvpHUohsM+rFRGXx/YLCUP4H08Z3N+f8Dlb3I43DfLGPvgnCAC3NoK7ez
         v1sw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVFkRSnLVxBhItCL2xzLS+bFyx5G9bi86J4IaLDRtvzrzZkB1msUFtAcaJk11rWTM4ViMAeg0FnzAkBuAcuQflkkTlWC23/tA==
X-Gm-Message-State: AOJu0YwvsBRmW5EaJBpq+/cxa/o86JAluD4ztD1S/d77GlkPKcRf67z/
	Vyu9lQEK7aHxNMxxSlEHx05GDaXt9UG9KrnY8sKOlB1sCPFvWJNU
X-Google-Smtp-Source: AGHT+IFcSW0dCQkQTQ4FcuRl82LceC2msn+JxFjPBRKETHuLQz5xRminlS4OL2zJkP6/AGDqLDC8LA==
X-Received: by 2002:a05:6870:c10e:b0:25c:9bf2:cc18 with SMTP id 586e51a60fabf-25c9bf2fd1cmr956255fac.7.1718811957607;
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2321:b0:251:cbd:f69f with SMTP id
 586e51a60fabf-2552bcc6f67ls536472fac.2.-pod-prod-00-us; Wed, 19 Jun 2024
 08:45:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFwKCNAYNfiqn0u4Y8op+ioJmS7lDtkUvcf0MXXo3eubEIOiNjaBziWgyksTfGR7yIeyiTyskjelZvpOXb+YHXSVKOzU+ppywDMA==
X-Received: by 2002:a05:6870:d38c:b0:259:786e:3c38 with SMTP id 586e51a60fabf-25c940b5320mr1446279fac.19.1718811956881;
        Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811956; cv=none;
        d=google.com; s=arc-20160816;
        b=Z9ox+bPn2l7oi7iVc+YBfhuArHtUTOFER6SfagJdZbOA4PAUEgAYmFBGSKVwUUZQAc
         baciG6uzAFpIAXqobkkwJrlQ3iAMLpB9dbxxu8L6hdgfQndkQE46MdUhnF8ELPGyClIJ
         SHHKAWdhhF4VKqOdr3uHXQFhcauc+YxcPaR3yaeL1I461393JkW4A8QdZppCaVNKuJJX
         ZBukxrGRFf3IiUpM6pU/p1e+dL3AHkNLtgx4+kbKeKvVBawwIu4g1TVBEf5MW8VyGHH3
         mEjo00GUjCM59VLEoe/Mckh5hSBAiT8PHhAu+hT5KcnXkC1FYrObLJ0CGxjEszLMf0Z0
         Z1BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nB1l8vkNyM9mVWovTL+NH+w81puT/zMq+tuxLWRrLkQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Chih1xos5cOzHEHWF6E4Qo1qWbbH+MlUJNPQl4opHfBi6epqUnOGT/BcakBi1uyc4y
         MqAKqwkn0qun9CGtTAy+5lFZQs/ezDPRIQe5NvPJGyANsG01Cq+SKqeYXNbO57EDqsc7
         PIMGGWsCLhwvZZa5PK+L57e/+fuXsLAkD+v0lnXJv0Ls/x/EZbxxyxAFZGXdlU+Lv18d
         1LDFaY34QI5Kw5W9dPm01VKYWqow06+v4ViycNmHl2NEBI6wnMIRNWbyr/WN6lBAxmca
         J1cIleOgWsQKp67YRXy5mchrfMoizvA3gFPQ8dsaG0/X1BcD384g1iT66/uqdeYoVSkx
         fV6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BEPtJdz5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2567a98fae0si600339fac.2.2024.06.19.08.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JBQbWl032598;
	Wed, 19 Jun 2024 15:45:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux7j0tcs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:53 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjVIg028737;
	Wed, 19 Jun 2024 15:45:53 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux7j0tcn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:53 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEeOYF013440;
	Wed, 19 Jun 2024 15:45:52 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysr03wkre-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:52 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjku833555194
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 661AA20063;
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 17F8E20071;
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
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
Subject: [PATCH v5 36/37] s390/kmsan: Implement the architecture-specific functions
Date: Wed, 19 Jun 2024 17:44:11 +0200
Message-ID: <20240619154530.163232-37-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: G-HYbmsxvmzkpVnASbMNe4jf4vNgUmy7
X-Proofpoint-ORIG-GUID: voXdK99_pqsmHaCFVP5r8s2pFVOzBayF
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 mlxscore=0
 malwarescore=0 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0
 phishscore=0 spamscore=0 priorityscore=1501 lowpriorityscore=0
 mlxlogscore=916 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=BEPtJdz5;       spf=pass (google.com:
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/kmsan.h | 59 +++++++++++++++++++++++++++++++++++
 1 file changed, 59 insertions(+)
 create mode 100644 arch/s390/include/asm/kmsan.h

diff --git a/arch/s390/include/asm/kmsan.h b/arch/s390/include/asm/kmsan.h
new file mode 100644
index 000000000000..eb850c942204
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
+		if (WARN_ON_ONCE(is_lowcore_addr(addr)))
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-37-iii%40linux.ibm.com.
