Return-Path: <kasan-dev+bncBCM3H26GVIOBBGEA5GVQMGQEA7D4IIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AF5F812305
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:58 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-286f8b84890sf5249883a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510616; cv=pass;
        d=google.com; s=arc-20160816;
        b=j2obyXmd4raUm6gutObeOz8XHsqJ/O+DGiT0hSCiFAvOJUUTVU7eMvI5IJ14eAwlc3
         AQCPIvTmm8FP+dVC/LBWskPkTUOttu/GpjU68PcTrR2IRc2v5Ume1bVUh5spSN9O820h
         td1abnxRH25QFkNgh7p7jPd/Zja7VLTwwtsvQV6tCBPl4fpbhjiLuNEXNF5YSOP6+7pK
         dPDEpAXk5PjutRW/5ADo6qejTIXLcKNF6JYQ20fqJ23dE+0mB9GyM9+oKjuy4sDu2CZ8
         idnT73QYrHAioV7RxfDe/gIv4S091fVL+fIMYjwNV49j6GTx8pUht4XYeyrlipoxl3uk
         4GYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=F7u7WKUYXbx+ov5XZPIdtjlhUowc5kt9FRiy9kdufck=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=AKWIJn/Cl4vGdXFnMJAcLyhH/N0/RTK/L4lUacek1eHUuGs82L6Tgjh1hGvK5+NrDV
         pyxDupOW0L7QzxeAFUMyoZ0rQ1tzkkfeNPNxgfVCjtsbfjrcJYrCLnByUNnguAb3auYz
         gPutejdGkj7Cl3PuCSzUP7LdUuDgFw1GmWrkKKV5Yrz2FwG4tZWrja5WvAdY6/HIv9+Y
         adwMfm0nPvtR3jIfQUIQBuYbE3hvoeaEncc9zhRVq7yMoGThfCLrCKojcAO5hvZt/DOt
         S7W2GbBkxTosvT1eJW0QrFa2GVz5Mm5JcNEeAnlWPMHET+PIomwwiObpdocK8N/E39zX
         4DUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ASry9qRJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510616; x=1703115416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F7u7WKUYXbx+ov5XZPIdtjlhUowc5kt9FRiy9kdufck=;
        b=wDTz0ANH8xv81J+hgZ6xlqmERSYuSbWYAy0BzbKgcrkdB9rrVeyfwXvv2t16/UGS0E
         aMaWGQD0f8/malg+Bhmnq1nT7uM+fxjxeHFkDIDfcyuT4gnXSnZn3PIcwqvH+t9nTi8i
         xMUyqGGX+yo3byx1GrJGNvAjKX1u3Sx2CI5og+ATpSw1QGo3N8hpzsSyqTuf7U4GoGRv
         QAWU65GRJND3I0wqFNDRNVoViQrMNW3nFp8g6GlcJfZ8Eth3t0m6BKUaZUqfsu5T3EwO
         z+RHCpHeLaf+CKgWYpBXLeN5Tr8f9s6fMGUhpsl4IDURbo6ZN5TYuhzyhvOts9ZZoTnS
         sISQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510616; x=1703115416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F7u7WKUYXbx+ov5XZPIdtjlhUowc5kt9FRiy9kdufck=;
        b=Ry4yxmzuqrzfwAEx6MMWlJ5dq2VFEc74DziWUQiiGurNxFNVe2HoVpDro7z+L+5QgB
         yiEElLhofaHe39K0a5TSq0SE6xrpmzNKGWuILTPe8KRaP0fmXeVU+xg1qoZ6DdBAexLg
         eUeEJSk3UtqgNT4wGjnMWcpzXPIw5qIx2zDjwG1MGdG0uSuk22DDVF+7UdCTdER2W4oZ
         S52TCbXx+Ml1agZEY5hGE/nvdVXQj++5RqDRB5Qi8gS+kLHTO0AYUodGJaSjfDHBtPHP
         XiyKm1woJYfMf5rvAPgRWB2TssmBeoeedfUJ1omHZaBQ31C+TOu6Ut33bY7SEsjJtP45
         cwoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw8RNoXN0VGj5faecPqiHNRYlQ86xRMAZVo8/+6LJAApY8IsY0j
	rmFKAZUBbRGA9xQkaEOfs94=
X-Google-Smtp-Source: AGHT+IGF8Stay9SM75g/12nnGgqwZC17MZo6UIEl552v/dLzLVD7rYzfxLu65R1qaHqFQY0mAwKlQA==
X-Received: by 2002:a17:903:245:b0:1cc:6cc3:d9ba with SMTP id j5-20020a170903024500b001cc6cc3d9bamr5799080plh.4.1702510616655;
        Wed, 13 Dec 2023 15:36:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8ec8:b0:1d3:4aab:1968 with SMTP id
 x8-20020a1709028ec800b001d34aab1968ls756063plo.2.-pod-prod-09-us; Wed, 13 Dec
 2023 15:36:55 -0800 (PST)
X-Received: by 2002:a17:902:7b87:b0:1d0:aaa9:76a4 with SMTP id w7-20020a1709027b8700b001d0aaa976a4mr3721138pll.59.1702510615538;
        Wed, 13 Dec 2023 15:36:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510615; cv=none;
        d=google.com; s=arc-20160816;
        b=S6j5LhY6pTrfF484KRH3QaPMhaxr+smup4mWEWDFWasjfv4f8CDmQ/ivXotLZl5J8l
         bpIa7cyEdyIh45te18Yd0OPV492WJGdNcYtbTWgRx8tBECqu/19s18XXwVr1HPFUaRbZ
         bTwVYqjGoHQ6k8lRpyRvqto/hZPNhThmg7Al8ZNjq+HEH/0EsIdu9IIcYax4caLG0EeJ
         NLREffOPywRr9X/Xu0UwGfwTNenqnqGH5W9rjpPcvUDDGo7JPBOOWRbrnWVXOZ+oClCg
         P4SYcfHrmcLwOzuDtu/PH+r4HyJ4TKa6Ng3OKvfyqchzhunRSYtsw6h1xHO5zUUOpvCA
         G/Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nPr4alGoOUJayRzkAPpg9VfkeGGPXaolpxO75YhNs1k=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=RuajTmbHlYn5D79EyBGanLrKtvriChVccV4I4Lpg6qyZonkeY+qv9DNv0ESYNLM5FV
         VL0iSl+gkaIOzOWM8VWspu0PogMnOaR9aej7v3zIYZzgGGfLotHrTMXAwC78YEGel0lb
         TO87GKdZ67jCDWO9ZcXlCHe7+l35iYytWiolx1FO7g2xsJk9z3V7tCjLjAWF/QTRvvYB
         aUwpPw7DIJzLoczuDQayZDD7l3LBZO6W1L+M+IeiFvCISCRPrzWh4pdeoYlhbINBClJq
         amxZsvtDAOR7BNfkKAfzL7TkqE3A22lNlpAeGT/9IX/6wio+F6OvszNG3sxbGpHZ2nMe
         VvrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ASry9qRJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id km12-20020a17090327cc00b001d060bb0567si843485plb.2.2023.12.13.15.36.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:55 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNHZbp002538;
	Wed, 13 Dec 2023 23:36:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cgb88-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:51 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNK682008396;
	Wed, 13 Dec 2023 23:36:51 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cgb49-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:50 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDLqJBP012555;
	Wed, 13 Dec 2023 23:36:25 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp4n8d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:25 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaMQ58978946
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:22 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 507FC20043;
	Wed, 13 Dec 2023 23:36:22 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E01D720040;
	Wed, 13 Dec 2023 23:36:20 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:20 +0000 (GMT)
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
Subject: [PATCH v3 08/34] kmsan: Remove an x86-specific #include from kmsan.h
Date: Thu, 14 Dec 2023 00:24:28 +0100
Message-ID: <20231213233605.661251-9-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 8E582euZEm3s7d5GxDRwQqNuLDV7uvKY
X-Proofpoint-GUID: V3HcuBJ_eVO8GlBaivggkJfr_vYv0Ls5
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 spamscore=0 malwarescore=0 mlxlogscore=999 bulkscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 adultscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ASry9qRJ;       spf=pass (google.com:
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-9-iii%40linux.ibm.com.
