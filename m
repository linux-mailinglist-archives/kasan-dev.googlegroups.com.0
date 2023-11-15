Return-Path: <kasan-dev+bncBCM3H26GVIOBBWWW2SVAMGQEBPLFCDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B6AC97ED218
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:35 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6cd0a9b5a90sf70611a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080474; cv=pass;
        d=google.com; s=arc-20160816;
        b=gWWq/enENLZM68ZDEYS1ugwTMBIcB9VfLSaSBLNQb5UmZ8Tatv/+RdNtfX85rTyW6S
         VKIJ1xKTlXhipWNtk7CHlUDo7j5SvE7pSZZGYU9vGd6R8zpVIJGRwNuKEoliDsZKSg5o
         TW5NGbYxPhDFXTQYiSa/HGNQ2dU/iQhjYSMdhByRfPLws8JVH8NnhwNm44IZjz65f4Vo
         VaiHF/3UWis3Fv3XSAAACct3wyuCcLYAQitd1v16vwzzVaA37cHyaHpHR340pB7Lt3be
         /Ws6cYKR4JYUYk92J69JyjUH1wH4nor7MFNKRzKyb5jXm3BmH28BLe7T8sKR5qJJO92k
         iaNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w2nbp3e/hcgZobTWv8HyFUmRsWJXuTaJG4B4KXwDk+Q=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=Lw4sbgeOEOh9XRSvvmiFqBeGpEVvR6QYSrKj8aKe0Ev4/mpggZui8/GQn9VLE7vBBj
         tsoHyoT6hQbzjzKoiVxwobo6v10ewcVoYbRIycUk8vKWjD1GOhFAA5HbXn85GqagiBoA
         OGblwq1UN1r9NFtk0x7xXk5q5PwMhi+naksHBDaKuNqCpNA+i6LWf6LEmGnMBmFye2+d
         1Lyv4muObhA/I9FbASFikJIEcd/zzYWW1o8iBBe1/rpLBgshEfmO2pWQJpjtaoK9JKtf
         HVWGCp3dbBUCVK/LtLKHRN7Z5/oOcm8rTWFmlj+et94JYz+f6V/Ldekg+YuFAlwa7xvp
         mIaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sw+mhheF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080474; x=1700685274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w2nbp3e/hcgZobTWv8HyFUmRsWJXuTaJG4B4KXwDk+Q=;
        b=Pmre/F9sjtKBYRqAoZa3U7ZsjZ2ZL1tUOryEFzv/hXQtTgIJzsV8SZzRwZFFlmjTPa
         WFZWXD7RnNKKKHSiVitc26nvTUhdKZrUm3gBxV3fbSd8aT5k4B+IEs6lOk3d7WHMc8mv
         I39ecgt5N3X6FtwhGa7RqM9jUc9ERNZqMfyPDRuxXldEBo78aHkxlWcvS+6DKA/Qh59s
         E3DIeWvA0hxaloJYRn2dY23vxFwSYwMkFOKdT1yJpI3n5/mbbn3QF1Hz21XEopCZDLQb
         LrWlv0a9mnKW6fVyA0XxxGpQJ5/pNPciZZ8QI3k3WwucKjvPyFRYC1QFw2Ooh0vqOY3h
         RpLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080474; x=1700685274;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w2nbp3e/hcgZobTWv8HyFUmRsWJXuTaJG4B4KXwDk+Q=;
        b=f6uGlqvICSs1Ue47fK5SLgkpEQQw7BuMKEEGR5b7cSkeny/2EQA8CnEl3HzRThlkFO
         KhVOoZNw29G0qUMwCnL46rzRs/NZQIyg/087nFTPfmf/BP1Xc8dPkSXX9WFYZTkI0udo
         imr/kNxzbnKS88bRjL1jGmmpumRK3YLwGCFWGQA3JAld6rMaO1NxKikpqQyhFPxvpY1f
         ssJVsQZmw1YNT/YmanDYkpzbgQFeup73vOJTf54fdkJaQIFdfl6K8woUoMNYlr6oESz/
         5oZeOzTfE5fmkxt6lSGgnyAhvd4LlSQKQcW95nFDEqiEyFMp0GAug8rqvkFAh+kuVMak
         d+mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwzI7QifSSjx7SSgemz5Rowb52jD24nWKW6M4hv2E2sQdSf+xQQ
	wTBjUGUUxAWhhHACnfDM7Qk=
X-Google-Smtp-Source: AGHT+IErJOB60P/jZvq84H/ubJ1Kzb4O2HCG20NdhnXM41UqfZkrbrOO7y7COz4SfxcEpAFIxHWHhA==
X-Received: by 2002:a05:6870:4c81:b0:1e9:9aa6:eeca with SMTP id pi1-20020a0568704c8100b001e99aa6eecamr18652607oab.1.1700080474624;
        Wed, 15 Nov 2023 12:34:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:740a:b0:1f4:88df:8b64 with SMTP id
 nw10-20020a056871740a00b001f488df8b64ls136828oac.1.-pod-prod-09-us; Wed, 15
 Nov 2023 12:34:34 -0800 (PST)
X-Received: by 2002:a05:6870:5254:b0:1c5:56f:ac08 with SMTP id o20-20020a056870525400b001c5056fac08mr19001313oai.12.1700080473958;
        Wed, 15 Nov 2023 12:34:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080473; cv=none;
        d=google.com; s=arc-20160816;
        b=OOeSyli9N0qVx9v/R4/S4OMANndhPtTGOyzjkP3HTiPZlpTrBLUu4x3xfuQGn5b/F+
         jzDDfqzPI7Oy9XkKIxxGWJ3kRuIfpuaWuNW6hAm0O/Qgb6lmEzslnzRaySjGrAy/N5lm
         B8EJCP9HQIAgZ0pjFYwrH1ncOF1SWsBREiVh7+lxYDm+z8wnhiA/+FgwI7mvXf9RvMnC
         xtMClEaZDOa6HSywIj9hPSQtgBJz4XUPWelBm2GvbGE4s0xNhMiFDOryyMQ9UkUTgSCh
         hTG09yciUkCIMIJCDaZIfkeF1AJsCjJFXmdBkguKQhO4+BRqchkPLYfEtdgVbZnxi8Kw
         oGyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fibwjw/KiW5HEuIH+IZjTN+t/6WZNSSD23GOexOJS9o=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=Bq3jSh6cQuSQMSR65x+YkLGHSe8IZznHSJC8HMXMbZSYkDWfHmPg+NN5x0vOGutFPu
         y65BNPcl/wVNewS05+2kTrTwrfwhH2VNdKVENv6jvOjze4xKvDxi3KsERgz27tZbKW3e
         4TosFu6N6KgOJc2/E8AyIAg/Yxr87GEjs9bzRto1zYGz3lGYQie5LjhoYbNtwRiAW7JV
         2IXg7Owe/Tt6vKg776w0A7soPMz6cqSy4JhBxiHTIPk21erGRU1EWTrJBX4YtseubTKi
         vhAvm5OehUs0MZj7zdeq3KwDaTXEqywblj8a8HPHeFxFxA8Ez0lM+7u/oQ9bboP8PWx7
         YeRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sw+mhheF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id x16-20020a056871065000b001e99e02fa4csi856333oan.3.2023.11.15.12.34.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:33 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKTffZ023085;
	Wed, 15 Nov 2023 20:34:31 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud52r847x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:30 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKU8lq025130;
	Wed, 15 Nov 2023 20:34:30 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud52r847e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:30 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIvA5015481;
	Wed, 15 Nov 2023 20:34:29 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamxnj0jn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:28 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYPUT20906506
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:25 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B405D20043;
	Wed, 15 Nov 2023 20:34:25 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6847620040;
	Wed, 15 Nov 2023 20:34:24 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:24 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: [PATCH 10/32] kmsan: Expose kmsan_get_metadata()
Date: Wed, 15 Nov 2023 21:30:42 +0100
Message-ID: <20231115203401.2495875-11-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: F7flrmLyXJJJAcGqET6C8qzUnTyLkokl
X-Proofpoint-ORIG-GUID: g1up5JlfCWsuRUJ_ZeEJ6SY9HrOevKDS
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 impostorscore=0
 lowpriorityscore=0 adultscore=0 clxscore=1015 priorityscore=1501
 mlxscore=0 phishscore=0 spamscore=0 mlxlogscore=864 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sw+mhheF;       spf=pass (google.com:
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
index 3c0476d8b765..2c743911a8c4 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-11-iii%40linux.ibm.com.
