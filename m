Return-Path: <kasan-dev+bncBCM3H26GVIOBBQUR2OZQMGQEP4LMDHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B7017911743
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:43 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3737b3ae019sf15689255ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929602; cv=pass;
        d=google.com; s=arc-20160816;
        b=woy17e9jtxHobu0KVTnYukNhsZX68q02x5UGFHzxmzFYXpqGVKcE/+iHQLvC2xBtT5
         M4x+B+kFbOf/YMrS8lM1T4Vp0Gh2J/DirdQt6eUmmfOW3+kUob0c38YgSJc3OIrFBMEr
         yrBg1GQwq675LKpRwf+v7qNzNndPBtGoG1LDkBEAEAKYou3XNCw9ca/KasqgcwvvUT9B
         oEUTmzzQ15WvBRTRCPX+G9hc3ecLmNP4+Eh7Vkd3I0btSi5D3Y0t3t3fItfIS2ia9WM9
         k6nR3+80UIC3WLfhk6VRXlv0ND3C2kKuc2d/uNCjy3bPuVai6PNsZ7UiOJlXwcP2EIeb
         aZ/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ccgSLi5sFbOYR57VAGImEjmXbksECuIsewAndaxjRPA=;
        fh=0xY4dU2QoKyt/EjR/qf9GdOj7jTKbaTHTqj/A3XtMew=;
        b=twH4CwCDju1m7xwihoRVKx+yZe4DtkivRIWPS9yEf+qTCOPv+SgaWuE+0YS56vjysX
         YpZ9UxY1h8ypvcmCDz7OfWW9XFOByRgkG6OnVHKqlv02+bb7BDY2fNpKTY02rejNKGO2
         tmvTzLgJ8MtL6i9BcBKSY2gXzdxYclyg/JGCFojT0EFy3iYsil5hmL7JxVgMJtKz+DO9
         BNzX/AApWzBtPkru7WE/JmbIiFCk4WBPaeGhU1wsNCduaorlqBfmt3rvwLQhenB7yVPu
         DufQhqYB4LXdJIp/LV2e/kQ/VCsCY14aw23zFjVP64CiUH8wHy0ppHmqlj5szDP/Jdvh
         sSzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=K33p1SeB;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929602; x=1719534402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ccgSLi5sFbOYR57VAGImEjmXbksECuIsewAndaxjRPA=;
        b=qUhOYs5aTZm2Gdn0iYu+1NRWHnBCuwn/CZW5x+G/3vPRslisIZsPsmqNp95Eb8DOwC
         nSmxnmsRzowl1IhVzNhFuHULTIx982LR/5bvXbRGF2vpMdYCjlmtsD6p/oP1ZSuf+thS
         e6s2AByjMtgTn4firhFckg6zcEI3uG+YrgarvIjOdKWppHDwrOHWggiaZWYFzNwQZDFq
         FQOmd6V2+TDNwNN7MTCQ72qR6IRGJtBu4PrleLWA+U+zsFCqfTIAqmyB7jRA/BJvpsdO
         KOzqJHirP86HD7+i+tY4tPsfXclcP2MmNNWP6hJw+LKvVCM/jHqqp1xlm3k68/e+GO9q
         kaIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929602; x=1719534402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ccgSLi5sFbOYR57VAGImEjmXbksECuIsewAndaxjRPA=;
        b=JbVZk4O1oYPQXYpI6Jik8Uw5T6GOjonsoTc/mwSxx9fxuImyuBlZ+T6jg1W9/hOI4J
         f18SL229JRig+F/yYIf1637YmqDFDa8AfOk5UobOsX1iQp9AnNHsTd2kPYne4gBynUdW
         QdBUqXekERRoNW/gt7Y2eyUMg9Zt20FrSGSb4O/JOxanbbdh3r0n+BF/ju7Lm89yOXjl
         0OfQLOfSaEqqkfLtlQWfRFXDmAnKOjbHKxSmFnI0riUhEDvmWwTc7CjbK/H1W5Yg5lbI
         WaOtVF1/xd9QaoLYyBe0QuCyNvd8nbzk0DdkEoU7di0gJHejuaDvjaxNNmyIHLQ/AIT3
         oZTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVF+Man+e3hiBBPbni5wbRqbUATwFPDHt0s7RMPSaTzJCtL0x5kDhrJwvZkuCkMziR27Ah4OpjsXG7puJPJrl3rd/tpXrqFwg==
X-Gm-Message-State: AOJu0YylbpbY8eku7I1mwgpsPG6QlYvzNFWXLyAgraUBeUomkGE7+Z0u
	t1poc2IupGKdsfxTHItEHrHMdeR9BH/iiHIvKQ/cu1sCHqa3KA/A
X-Google-Smtp-Source: AGHT+IEoIzXTBbOSO0qVvHLGdSdBHMpQvhkkrQbh8IkyEPEMkSIF90mgBIb47ebC2pnLKvFpecUHDg==
X-Received: by 2002:a05:6e02:178e:b0:375:a0fe:4535 with SMTP id e9e14a558f8ab-3761d656704mr70314855ab.3.1718929602331;
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ef:b0:375:dc18:bb99 with SMTP id
 e9e14a558f8ab-37626ae1941ls12041085ab.2.-pod-prod-04-us; Thu, 20 Jun 2024
 17:26:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWDyb8IE95JRzYwF2rJ7BoTpyzYSP+CRRvxtYYUhg+UFonbRn0jnviBXEYncd2gI4VYZ7QYDQqUyEfrQIP0OUhcQWMcb4tqunrVNQ==
X-Received: by 2002:a05:6602:164e:b0:7eb:8874:99e0 with SMTP id ca18e2360f4ac-7f13ee3efc9mr794140339f.12.1718929601537;
        Thu, 20 Jun 2024 17:26:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929601; cv=none;
        d=google.com; s=arc-20160816;
        b=MAi/WjaXEvEzIfNZlcqEQhXYjB1yEpQNN7OBd1T/U3qqD1yXxvywavj9aWFd9scwag
         W76jUBMqG2BH3PFkbtwPFh7sWO6gXYtV3f0AvDa3wHUjTCn4DYeyfRNYFVukByt58kqo
         P7Zghn41Hprnq5ddd/pjvxV6SExktfvZt9lpLeLktoU4K/6vYUHSqaj0Lc4Ih3FgEgm6
         WmfH7JJUtNi4L7BJoEIeHKdVBCfLNGeqy5H1LFNr79s0sPeE/+dWEQg7F7DT8l2eApn9
         0PzRfRo2TRyePfC4R+AgaS5nmByae19dEzTYwBd0CYod2q/p1QPc+r8wnZqnA8MqeR4Y
         STUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9fryXD6fg7ZWH/K5Ic2hWhXvK+X7HFTa6K6lMBwUrkw=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=stGsyqNQaNS66R2G3KFsfxaDjxbBY7Z113zASC8qNtK5v53ENeHPE+k0erF3BIfSur
         msixzYTl7VvD3pBaOW58iOMma97aUVywkKzD80nS8Szwo4Ik56EubAU+uY6v5X7nMyPj
         BWvNXSdCAZWN5YvF2S/lcLA4M5cBhS770zHyA1ClVupjeLSLc7pfuEkk6ppvL8RlqsL7
         sS2p3bh7Vkw+2LTruW1VHmqF2sFIGZp2ZSfjFAumHj8+CLpVzUr91YG7ihhPA+/wf6pm
         DU2OG7tyE1JbCFYpSEIyl88Xe2DiR5MxoHuEXbe+MJgOz+OvOvdRzb0yx3ilYSEUe4Tt
         1lOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=K33p1SeB;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9d2153ef4si6382173.0.2024.06.20.17.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNxAvS026339;
	Fri, 21 Jun 2024 00:26:38 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1gs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:37 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QbsT002972;
	Fri, 21 Jun 2024 00:26:37 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1gj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:37 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0Htvv007678;
	Fri, 21 Jun 2024 00:26:36 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamnp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:36 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QV4q53543316
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:33 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0202120043;
	Fri, 21 Jun 2024 00:26:31 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D390120040;
	Fri, 21 Jun 2024 00:26:29 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:29 +0000 (GMT)
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
Subject: [PATCH v6 09/39] kmsan: Expose kmsan_get_metadata()
Date: Fri, 21 Jun 2024 02:24:43 +0200
Message-ID: <20240621002616.40684-10-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: YaBGm8Uku-1CqTA60xZdI8aAHaTLGkj_
X-Proofpoint-ORIG-GUID: A3KZS2CsvIPX-Ah0HUJbanUJ3wQFkNA4
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 mlxlogscore=884 bulkscore=0
 lowpriorityscore=0 priorityscore=1501 spamscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=K33p1SeB;       spf=pass (google.com:
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

Each s390 CPU has lowcore pages associated with it. Each CPU sees its
own lowcore at virtual address 0 through a hardware mechanism called
prefixing. Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to
resolve metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the
arch code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h      | 9 +++++++++
 mm/kmsan/instrumentation.c | 1 +
 mm/kmsan/kmsan.h           | 1 -
 3 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e0c23a32cdf0..fe6c2212bdb1 100644
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-10-iii%40linux.ibm.com.
