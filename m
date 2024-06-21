Return-Path: <kasan-dev+bncBCM3H26GVIOBBQ4R2OZQMGQEPJPUSII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D3895911746
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:44 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3761e678b99sf79205ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929603; cv=pass;
        d=google.com; s=arc-20160816;
        b=ypBk+qKEPLIDjyb3xMosWBiizRuT7zJaDcazSVIFSZc/gcDlmfLCU8yBdlkq79fv8G
         590bcKwdRiG52nVsSDySdc44N40TT24k0XASUCE7uHky+B1hHPDNApd+WZO7CL0X5mDS
         HP9P6Z6aC5fQ9fchcOkFzkktiJow1qhM3xlzNqguUDy6o3jalV4wtcErHLmGX0aiT9HM
         0v9uXz/TxnO/x7X7iuiKV+fPk53omtxcDMZDJ1FiDGb3447++F+En7HFHdEV3D9/cjpO
         HOr4CCzvJltSsPoVX9KWXKUQfcL6D9l2IBfLyVwVQMQ6+OoQ+dsT02iJdLRiOEYx80vw
         23DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+4SPGouM6PanmK36dSBc/IrmaIqm7d+Rpue4zb6+PmI=;
        fh=udERbA5C7/zDXEJKrb7Q3+yKLreYoBSufkDFXhX8q58=;
        b=e1UBQnkawHWqx/7lIo9SgJZlbi30Vrwyn20Z+DnTxFachwkIwdX440e1wfsCrZKT1j
         Y/drHc2O5W1uqXp/HDLmqO5JIKHulZYnwJ8syRT72GZtYeiRVmf5Vkd1lSZL0x2cxShf
         BbqKTshKGXnzaSYvpz+9gykrWVFPdO0oLgA8WLLPZuboh4/eXcG2F+WuLZ9tyO78FodM
         1QQ+T3rKaaYkcEQjqmlFX1+X99Lf5+tV9zVTuAueAL2M9WGzCS9G2953o2yPQpSGYSzL
         cVSnkl9CFH+AGavhOBD1qJ8/eOmKjuyb8zF+8FN91J9Vf82AE2v2HxBnPns8UkLUXDuW
         ikVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=T1ae6wqR;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929603; x=1719534403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+4SPGouM6PanmK36dSBc/IrmaIqm7d+Rpue4zb6+PmI=;
        b=AdvZrwFpi/dbiqKxsHgovizKT+xGofU1NiwMdN9b128AJKHg/7w16swqP/CL9NO6an
         l26CONyNkSAKh7JDxy8Tv3fwtVfyTVYHAYdm2wdoLdsz1HrN3yzkCZ79mXFdHeacbA4x
         iLTBJCDaAd5WErf55K5clFNAi5xQi/Z7svYXik7iDlhShtuyJW5m7G2MqCpi5ctFkxvS
         ptxtzhOojFPP/0qE3Ys8SiDKwCeVJoKvly/p2pj1gAznWXGnomBpMbbRvYeq2tvh2xhH
         uXU5+AskHsBf7isTTnYZDaiTemHLFLysqovjTHJYKkE8bc58CdW3VzuqqNnmgcykRfZO
         Lclw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929603; x=1719534403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+4SPGouM6PanmK36dSBc/IrmaIqm7d+Rpue4zb6+PmI=;
        b=L8z4yIyfD8ARX/V9KwyXxhxMqzZchVvAc9t3XZuep7gL0eqOjWiXoaVUmDy0IAnioK
         d1S7QaYMlGoIKmOCm6AKW35jOrIYpQPLM1clPqwOpRKxtWEdzsJY8tBP28DHXQ4zWihu
         pXF74RVFyFlPbX+mHwFbaHVZUkg4Ob/MekPFthXew4UXWiGeSjkHLFhL4PaSSCleRf4R
         lQhunPJ8+DNE0RvEezfdPx0fgoee1sJ9McWrptl7cV7445rZuw+N7AAU1gGIkG8KmI27
         tKzWkxw3jb2EDBYtueoWDNt6BRNpn7DYbSXsQabBrTNh8GksoqrjMYlW5+FP8kdljKqj
         RqLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9klwmIl/qPsdrVytgzF7DocROTf3DycaUsjE3LbQmTwtgjlJCZS2EV2ksUmqI0LmBOvRHea08LT8Rce+95QmeUgjE1fHzvw==
X-Gm-Message-State: AOJu0Yz6XrwLWYiJ9TRY7rZRlF1E8xEdyZWGouWF3GecmCQvb9KdgWbS
	+C+zQbSgv7QpHj4DDkMaaHOm3g3RNTY8jqBPsjHQvo3ycMultw7C
X-Google-Smtp-Source: AGHT+IE6aBFt2T4ML8iTJuyyiTGL4mxICnxRut4nkMV689aaEHoov5tu7INPhcF0hMGcnHaOM6v5Lg==
X-Received: by 2002:a92:d908:0:b0:376:dd0:7d73 with SMTP id e9e14a558f8ab-3762f4eff18mr699995ab.15.1718929603666;
        Thu, 20 Jun 2024 17:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2199:b0:375:cf99:f713 with SMTP id
 e9e14a558f8ab-37626921da2ls8021865ab.0.-pod-prod-00-us; Thu, 20 Jun 2024
 17:26:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWE+Vs2MgQ83EGQ5v8jyuHMO+nCFNtZZC+5hU65+F50rmZmd6njK2LFJhgZDbExTzLEwH1v557+xzYlfXlYPs4EOupx5gxyizso8w==
X-Received: by 2002:a92:c545:0:b0:376:2a41:5f42 with SMTP id e9e14a558f8ab-3762a4160b1mr15690285ab.10.1718929602911;
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929602; cv=none;
        d=google.com; s=arc-20160816;
        b=rhyKNU5GEy7TjGBFZG3ICpN9Xtbn/tZhguCU34CuLQGsV6E079AgYPkXo3KHseHqai
         pQW1QqdyiRAMDazKMPWYoh8ba6M2C4PPqF5cvSXC3+jtJqFtyIytbAFjL+zE2Pad+DRJ
         zt3E3iLfN9b8G5YUvumiLRBwBxBXkl+Xv+aBBKTrX7wV5G2/q8zEXUpEmZv6rVzQ7H00
         ZANwESGKHgq4WtWuWEGLKwSBiGVLosCmjCQOuam3cTaotaB6AIW0nisbfKug89yTUCiB
         lKe8Pd/9Q/4y2r+3zOEhUvZrdPgzmjDT/rOIM4QyWN3jrSsZYv/Rn0oDFucITelsMhjv
         uF9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YaTjcojmIIYPSV3AqgAoZ8tGeMyuD+KvoajbKIBgv5I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=YnUA0tVNFymejU8YI3N9yRJ1CMuEy2Syoxx4DKoJ81+Qj0IFOurMZZC8VDqq0Pg3TP
         ZxTqW0u5NZfBsGrSMZw37/eVf3P2wrh+oSy89caeJH5YaL4vSy6R6r9oSVgIxaJV6BCr
         ZeLFl7IIbVANOMxVlPJraTH1MCyL5mSCoIn/osY2T0of8wUGgIYJLZIGuAglZiKsNGQk
         mWtoyIsJ3h9RRG7mwcyzjCpPxH2+8lpsFN2p4CXvEFWcikkPNFKq71btlcyFZbh/RK2H
         UbecNGSgIeE1/eJ4Rtzfa0bbrcPRzc5RI45WUKmQ/TbSURZUZqyjM3QqR3RXWSY1Dxwy
         XHnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=T1ae6wqR;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9d12706d3si11785173.6.2024.06.20.17.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QM6r009279;
	Fri, 21 Jun 2024 00:26:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8ab-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:36 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QaaB009416;
	Fri, 21 Jun 2024 00:26:36 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8a6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:36 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0GVsp025708;
	Fri, 21 Jun 2024 00:26:35 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv2nku-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:35 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QTRt52101600
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:31 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BEEE02004F;
	Fri, 21 Jun 2024 00:26:29 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9F4C92004D;
	Fri, 21 Jun 2024 00:26:28 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:28 +0000 (GMT)
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
Subject: [PATCH v6 08/39] kmsan: Remove an x86-specific #include from kmsan.h
Date: Fri, 21 Jun 2024 02:24:42 +0200
Message-ID: <20240621002616.40684-9-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: vyxYbYMv0_NAWx6wam-6wBrYJn6RoEVq
X-Proofpoint-ORIG-GUID: 5IOHAuWOwgEPcoqMkZyFmjoadwmxjUKH
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 mlxlogscore=999 spamscore=0 adultscore=0 phishscore=0 mlxscore=0
 lowpriorityscore=0 malwarescore=0 priorityscore=1501 bulkscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=T1ae6wqR;       spf=pass (google.com:
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

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

While at it, sort the headers alphabetically for the sake of
consistency with other KMSAN code.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index a14744205435..adf443bcffe8 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -10,14 +10,14 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
 #include <linux/irqflags.h>
+#include <linux/mm.h>
+#include <linux/nmi.h>
+#include <linux/pgtable.h>
+#include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-#include <linux/nmi.h>
-#include <linux/mm.h>
-#include <linux/printk.h>
 
 #define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
 #define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-9-iii%40linux.ibm.com.
