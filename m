Return-Path: <kasan-dev+bncBCM3H26GVIOBBVNFVSZQMGQE62SUCHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B1689076F5
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:06 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-24c6783b8eesf784975fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293205; cv=pass;
        d=google.com; s=arc-20160816;
        b=KwIVZcZ8paJGU8yRfUeu4hQ2/8eBNf+SiNOQp5K78Q3YFL3MxiGDTgXeOH59oapBp8
         A+tPDpe4uwug7wdM/wC2WiOkumx7FZO8cNwuhWnYMbD9q+Ft+xEoVQ8wliqsXEqMDA7Z
         dsGLnKjavKzPYMseRjHY9DL2k803A4jOEyQLW7+cXku+eOF/JvBz7Jys58/KDBWLhIy1
         a+McL9Kj2mkzvMMw2chbyryGhDdG6LCeB7v0y1K5DJMwoEB2+z+9HrKkbWWMAmpekgvP
         Vn0iWKibyChTt6sczc+BDyJ61Iw/U/H7K4xF7OmMQBnfZSSzMJrpGzvGVAzSlZ82DHLF
         28dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uw6vu5dRoQ8ONx/Vm6JuHcRZLUyr0YRyce+k6dOCD34=;
        fh=OCAgkjXLm6dv8EBZ11GN4wYYUJ7Er00Qh9VigIpIVdQ=;
        b=Oxc4pHbLiM2s8r7h36wkfj5I6vMfrb5XrXmOGMVJDOLH3kB2MqxnlSw/g2GqYX9VE4
         be43fgt1ouHwphzI7oO1/E5boAMIjYTLelI8inOC439Tmm6RrrKONxDZsJ5IyPY/vcoJ
         rOyugKIhlojB+NjjHTmaF568s5VP0hIl0AtjBm32atmhto9MSkRFdZ15KJ1kbDvTJkqj
         mg2RzChv8zprR9EZaAJng24EI2TxemZvxq0ed5PKdw82X+RtlNZMWUQYykLWubiF5IkY
         vVIp/J8iMtlubvYedyWPlUQ3y6iEGGc3Sdx3l/CjkFyBPbHpV4fUT7GMXu7MDkXUdT4V
         QL6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IRh013pY;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293205; x=1718898005; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uw6vu5dRoQ8ONx/Vm6JuHcRZLUyr0YRyce+k6dOCD34=;
        b=ubYTUNos2oJmeT9SjOzKTj6QR8X0K+20l5C9pAj80+n9g9GtCu9JIFfUr8RHxqEZBV
         uBb29ezVOedr9vJJUHM3O+VoBVinUqHmVD0oXT09NRVvXwCAeNz6CpKM37HRRd640taw
         BAt8PJmBtkOlzf+UYxwETpvLIq1iloG36b0lFwZ3xQXybkEvMXw4rY9bx1lD/GGXgUGL
         BH3NCQ0upLBu/lha987gGqNft0Sx2PEge/izgaCNH1F/5j9DVgHTBOtDTtgbc7tDwycE
         zpqhjFbfQx4yTHunlssxK4roFoVUThQqje79Fk5v8IZSR76X3kv+vRgIjwGlcZ/sVZ4+
         3s1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293205; x=1718898005;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uw6vu5dRoQ8ONx/Vm6JuHcRZLUyr0YRyce+k6dOCD34=;
        b=iTSuD15EN0ycm4cW7DfdiBybx9Uw3Yblugzcmoq3WCE9smu+3n7hVIF2KROYuLBPHl
         Z4iJmWWYBuMJ0VHqrYzO2OZa0dHRfK4MqBWSGboIR9b2Dg/k/8ZO/JFIhWN4REqoTALt
         CrYowS5b98ywNKyX49iuGbI+IAMgb/j6qsMqMm4f28klSrOpJ+LIPBvlRgLiWWXJzf+w
         0FUAokvoCWlIbEwe0E79zmMq+qadaoJ+w3ToVfPkWGJvYKjCDg6lgkhW6yEAeHpc2JCO
         1f50eUrkhkCyILCG4S1+zAaB4kd3ZbvDl2CkDNxCqfan82GVj+r0ulMLRRmdzBcYb1uM
         sByw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0T7qo4f2mM+X/58YBtMM5Fz/IQqbUhD6j7G4uo3PVKwAFQpgu5dSuzIBCfHo9X4BLHpcy5b5uobam/cdllbZM9WMV119DmA==
X-Gm-Message-State: AOJu0Yx6697Z8K1Y99wC4ryfn/9r7yeaEo/koXQignMgiq/6l4lWDP7h
	qqJm/mNYgtb+iTNYvW46Dgy6gqt2UzuSMdf9T5m1koXayJUivQuK
X-Google-Smtp-Source: AGHT+IHbvvaT/frG373gbDjtdJgSL3zr02XHwi0gpoy8K36ZGuaBCfGuq1+6VOwhDfJrrCcxMoWHHQ==
X-Received: by 2002:a05:6870:d62c:b0:250:67c4:d73c with SMTP id 586e51a60fabf-25514c19405mr4794104fac.28.1718293205240;
        Thu, 13 Jun 2024 08:40:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2321:b0:23d:21b7:fd9 with SMTP id
 586e51a60fabf-2552bcc844bls1144952fac.2.-pod-prod-03-us; Thu, 13 Jun 2024
 08:40:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMjiMs7gtF1kJIy56YqGR9H2Kkva9Z9qXRSyfbgzHN21j6zgg1+kbUc0fGfDgYCYwSyqcaJHbOPq9g8xyCP3n2VDxnpwEXeDlOrQ==
X-Received: by 2002:a05:6870:17a6:b0:254:acd1:52a with SMTP id 586e51a60fabf-25514b8c00cmr5449326fac.20.1718293204303;
        Thu, 13 Jun 2024 08:40:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293204; cv=none;
        d=google.com; s=arc-20160816;
        b=x4iC8ov4guRyVGnJLi2P4mThjdfaNwK2mNQxXvW4+G9hkXYz9/cRGVjWlEbki43u/w
         cjoJLjeGcMChmQi70RDnlGvx9C3BthEpI0FvYXuKSJRGEkqvmVtIf4TpYxDi4SaLNMi/
         HoB9pTDbKs+c+LLQOGYRbqJoRt1uyJkzSymbU5/BcClW8Y963fF2SehjOsOwCQiifErN
         iJQ/mGfIkWdWsCZsDJykccTff2Iba5OS9K4/PMOhEHCHKJn4RaVTmhGk1dxTYnwNxYQt
         jp0hkHDYHTnNY9QS18ldZxm1fJNe16bPfD109secFpIm5M1/cAfOv+h6oEiaCrHkWi+c
         b62w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SGtqtZLhmZTpZhOs7cGVRXCfbxWX39hF+gqk+Qx83+U=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=yLS9wisdBExIlPPg9BI19vmP8U9H6dBe8gEgmwr3coUQRu/3nGzc+T847pyBynEjmu
         4SjO/hC/2NK6M1JRu1sIqyZ/DTc0P1UbVFMqSQTfJI2/Ujm4uv8cGvvrDl0m95XnJYAm
         lkYfc0hdAumMGWTVWqBT+p+TbSP9zRBaSECjDCwe0JJzVOZ7NKGgUX5YxFUu1L3GPYwq
         pYufmNyEMLVuEoznpL4oLS+yW5cjNEdq6igHYglF4jLO7Vhi+UZO7tf3mzDHCghs3k4+
         NSmO2uc74LLdTntbgTGzU/8ExZISjSAQ2vISE6jrlS/yDfuCl6HBnn/Kf2xIlDhwpxBK
         NHpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IRh013pY;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798ac0ada77si7961185a.7.2024.06.13.08.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFRpXY006834;
	Thu, 13 Jun 2024 15:39:59 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext12f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:59 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdwis029870;
	Thu, 13 Jun 2024 15:39:58 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext12c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:58 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEAxec023597;
	Thu, 13 Jun 2024 15:39:57 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn3un0qhr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:57 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdpMb55705908
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:54 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A321720065;
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2DC672006A;
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
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
Subject: [PATCH v4 34/35] s390: Implement the architecture-specific KMSAN functions
Date: Thu, 13 Jun 2024 17:34:36 +0200
Message-ID: <20240613153924.961511-35-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: EyA2kbsVp8WqCccHu6SjxoBNfiDsWCum
X-Proofpoint-ORIG-GUID: GZ2-WR2_gP5V6QUvEBJcKL9zIIoL9Eok
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 adultscore=0 suspectscore=0 lowpriorityscore=0
 clxscore=1015 phishscore=0 spamscore=0 mlxscore=0 bulkscore=0
 malwarescore=0 mlxlogscore=747 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IRh013pY;       spf=pass (google.com:
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

arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
prefix and calling kmsan_get_metadata() again.

kmsan_virt_addr_valid() delegates to virt_addr_valid().

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/kmsan.h | 43 +++++++++++++++++++++++++++++++++++
 1 file changed, 43 insertions(+)
 create mode 100644 arch/s390/include/asm/kmsan.h

diff --git a/arch/s390/include/asm/kmsan.h b/arch/s390/include/asm/kmsan.h
new file mode 100644
index 000000000000..e572686d340c
--- /dev/null
+++ b/arch/s390/include/asm/kmsan.h
@@ -0,0 +1,43 @@
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
+	return virt_addr_valid(addr);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-35-iii%40linux.ibm.com.
