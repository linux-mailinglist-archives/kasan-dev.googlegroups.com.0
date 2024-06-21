Return-Path: <kasan-dev+bncBCM3H26GVIOBBS4R2OZQMGQEOPSZWUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DE6A91174D
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:53 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1f9c6df671esf14249855ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929612; cv=pass;
        d=google.com; s=arc-20160816;
        b=rs5gjxCaB/A/XWRbCT3UkMWD11mM+aW8fnYfcGuiOLBZMY1jFMeKb80kimwF5abKrA
         pUkWM2qB/bhG2eRfdpn9jVrF6NLfY1GgKovyaatDoBlmpeG8n9BFnEkHEiQ0xlWjM0Ph
         xxb38Aq1cRCEorJPWnH/NFej6JG4bnSlkHRRQP+tge6MJgGjbo7BCO4zK1yXc+fCA7sk
         0zU8KkwgLnc6ZtDcVO3FhCtCGX7yNNtppCo/FlGBPmp/4xH2QCvcQ1vvWUVkHSAd7kOk
         W6naNDol0MMAXxT7k53C3TnRQgBRUCvhyA3AbYt/gke7evijZGrhe2bInuKluqamZWoY
         rOcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=z+xJMTzP5VY99TOGMirmye+38zJtwYWnnDgC/hnUhfA=;
        fh=VzXt64bGTntLPx8SFWia9mQTHuIxlql60kq+3brmUXM=;
        b=i6U0JjzzhuPy//zoRYB+S2ZNc3cw5raV5rFFHFabVukHWNX4RqUtDqwBnCRDQCpNUD
         vSVqunuOaBeZBKeGbq5oFeaIBYqtMMbNOxfLdUMjrwQWCAVX6RMoG9bvNI1ItGe/H7El
         fpPkbgAqxa6s3geWSOZ2v8q9YsulIiAnoVmILimEvkFtFJJetwL9zTDOzYN53XVbeKS4
         /MHMQnJZ6OtDi6ik6rZqdR6LLn97iHJXfMyczkvTE4u8nGRx0pWPn7MztYx6zYEzGG8O
         wE1N+C0+fFTi4qqjagNV6sUb72iEpCKgWzYlQYM0EqKE9XpeFaQLSReo7kXpSkZL9XaF
         dakQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RdWGIW+G;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929612; x=1719534412; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z+xJMTzP5VY99TOGMirmye+38zJtwYWnnDgC/hnUhfA=;
        b=IneDJb2EkkQE9QOLBnnrPTyIbF2brGCC0jAdUMHJgxmw4OChafFTJdQLgjISEiU8c5
         3TqeWppcq64Kw5uI5GOcNannfysCGSxmeN5Dlv7Jcm1E05c1gkKeb2IKFI6zoiGJqsLx
         GCu7401lPJ3ZfZN8ABOhLSy0ItFTVsUEiF2egWAc4r467ypyVnP0VOtRWSK0oPYmkYR8
         txt+5oszRinu6vaf6OGVvfCeN8MMl1e1fV31uUXyr0NX579lekWnmmzdNh5DCO7VscP1
         0sZyk1M0JqkA2dqPtPoh9xXcNtqpfwYj+VMLn0Tpu623YdnGMXOIzJGiqMeSBQ+aDa0g
         bnNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929612; x=1719534412;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z+xJMTzP5VY99TOGMirmye+38zJtwYWnnDgC/hnUhfA=;
        b=QubK972+ni5ViPyEMA5OhSjuLm1mS5rjNUJ/bKL4AnJmi6AnZHCZniB9ZUCgRL93Hk
         +PlOgr7NXgyNzlG6AD9SiVnP2cgSfwg2DawbZwPIVyVqNSrDHpYR2/a253EzW+RCwqSX
         4uIa9LWyW42yGlnqzDs30XmLXPScULhYnvcQaAR+zMGZWJ8EX647QJwmNu8KIadaPSog
         WmLktFEXWHk7M514rx8YY0Q2jjqTXlRWfNoUtxJBu3RPoWFSDM2uAsY25TgVvhGnTUni
         kOmSB4OgJ1UsXNHgvpagqF91++P5+V4J+geWyF8x+G/10Aycr+YKNrxK/d9iYtpOjRWV
         zx4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVc6wI7qdioAPBXh77WIF1CbcUJ23HcIo6PZmFpYfxeex9czX8gnE/P/DBClShwrVicgkDY3EwasuughUfY0sP1Vnx0QxbRMw==
X-Gm-Message-State: AOJu0Yx7ViQdzAN2kdRTYOx9P4mql7eI/8GbXNoTrM+sjQic2rSrwora
	piCgolMG3afEpJAfiOm83lpaguaXH674xW7trnrW4q7oi9+n0O1X
X-Google-Smtp-Source: AGHT+IFq+vBezvPNMfAOA1slvZhVySiDxyHQ3Wff3BBPa7elmkXiFgNAYlvenzcjTVCqvQs0/9jj1w==
X-Received: by 2002:a17:903:190:b0:1f9:aa05:878f with SMTP id d9443c01a7336-1f9aa2627d1mr87402505ad.0.1718929611973;
        Thu, 20 Jun 2024 17:26:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e811:b0:1e2:306e:bcec with SMTP id
 d9443c01a7336-1f9c4ed2345ls11211185ad.0.-pod-prod-03-us; Thu, 20 Jun 2024
 17:26:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8uqJjXlxrVvH6/rNrFFyUZIoQx/Q1S7wsJ+QQ11spUToRUZFLo6qzm+J6UhkRGKwFekbMY5E4nZvOn1x907wNT+VJOEBZl/1cfw==
X-Received: by 2002:a17:903:41cd:b0:1f6:62cd:2c8e with SMTP id d9443c01a7336-1f9aa46c694mr79918495ad.58.1718929610900;
        Thu, 20 Jun 2024 17:26:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929610; cv=none;
        d=google.com; s=arc-20160816;
        b=k0MAZkDxwhj+pc3tFRKeYbHh/0+NigDY62HdnhUQbhJeMjTMd2J6m19VPOkLsM5Cps
         2ntG9VQk8GBBHWjg33IemkUwon4hyXnD6K8I7Vg3h2WHl8mYs16BbnW2s0Fxx4fVJiVI
         2wGrI54VgDRihbXc8b4CQl0lC8XlTD+qo6qGV7Za4LgcMHu+qUlL75MvxHMmbK5QLGrx
         hgSh1wFBOZwzM4BUYQwftmz1vcYN5q1H8iTZoOOuk9Qjp5JePkJNPOTy8pKfr7bsR9ig
         HNxbK2tywkezTtD9QVBkALK5YTHYeSKY0qRzJiibYMIpioxM8Bo7yEi6C4/S0bCtuUOn
         HXvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0LPmEM6eL+o7Bo27nUv4gfJxVa+Lf6wjrMNv3AzectY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ek6YFsW65VK+fiZ6KeqzU5kWaIplQdkT+t3YIz8aAEeB6XHM1FTspqJ46Q+BjcjPAB
         5ebjnWPw2XHpL3SHk1dtUStHYnAbcrWQaJCPTL2OYHEV1jGByBZyQ0+vWP4D8f+ndkR5
         WWmhbwp61jHBMKzz0dPwarZlF6b8KAbMNAaSJnZc6OUOjUT2mrna5ghAwUsLcCVEP+E3
         IDLTdC0DEGLHhTI5AYlAbGSn9i13GgJqsMjsxoxGfv5X6AuORhWmWSQchza4Z+rSx8yw
         2+pPLSdUkSns+GzzLrukj/ur3h4MgAmlUx+qUNlbYxJhV1QtKxlZZyGbJjoPc2sdKacX
         eNlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RdWGIW+G;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb2eef89si152965ad.1.2024.06.20.17.26.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNwn3G025841;
	Fri, 21 Jun 2024 00:26:47 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1j3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:46 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0Qka0003184;
	Fri, 21 Jun 2024 00:26:46 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvxjjr1hx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:46 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLiBxH007687;
	Fri, 21 Jun 2024 00:26:45 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspampc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:45 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QdWT43385164
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:41 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8AC0520040;
	Fri, 21 Jun 2024 00:26:39 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6B8CD2004B;
	Fri, 21 Jun 2024 00:26:38 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:38 +0000 (GMT)
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
Subject: [PATCH v6 16/39] kmsan: Expose KMSAN_WARN_ON()
Date: Fri, 21 Jun 2024 02:24:50 +0200
Message-ID: <20240621002616.40684-17-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 3TpJaJWUrn5ONmFvCjHZ6jquugwLqa_O
X-Proofpoint-ORIG-GUID: ZSyRtuJikAyuhF47I2RpjGNIZUWKxRc9
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 mlxlogscore=999 bulkscore=0
 lowpriorityscore=0 priorityscore=1501 spamscore=0 adultscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=RdWGIW+G;       spf=pass (google.com:
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

KMSAN_WARN_ON() is required for implementing s390-specific KMSAN
functions, but right now it's available only to the KMSAN internal
functions. Expose it to subsystems through <linux/kmsan.h>.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h | 25 +++++++++++++++++++++++++
 mm/kmsan/kmsan.h      | 24 +-----------------------
 2 files changed, 26 insertions(+), 23 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index 7109644f4c19..2b1432cc16d5 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -268,6 +268,29 @@ static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
 	return __memset(s, c, n);
 }
 
+extern bool kmsan_enabled;
+extern int panic_on_kmsan;
+
+/*
+ * KMSAN performs a lot of consistency checks that are currently enabled by
+ * default. BUG_ON is normally discouraged in the kernel, unless used for
+ * debugging, but KMSAN itself is a debugging tool, so it makes little sense to
+ * recover if something goes wrong.
+ */
+#define KMSAN_WARN_ON(cond)                                           \
+	({                                                            \
+		const bool __cond = WARN_ON(cond);                    \
+		if (unlikely(__cond)) {                               \
+			WRITE_ONCE(kmsan_enabled, false);             \
+			if (panic_on_kmsan) {                         \
+				/* Can't call panic() here because */ \
+				/* of uaccess checks. */              \
+				BUG();                                \
+			}                                             \
+		}                                                     \
+		__cond;                                               \
+	})
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -380,6 +403,8 @@ static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
 	return memset(s, c, n);
 }
 
+#define KMSAN_WARN_ON WARN_ON
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index 34b83c301d57..91a360a31e85 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -11,6 +11,7 @@
 #define __MM_KMSAN_KMSAN_H
 
 #include <linux/irqflags.h>
+#include <linux/kmsan.h>
 #include <linux/mm.h>
 #include <linux/nmi.h>
 #include <linux/pgtable.h>
@@ -34,29 +35,6 @@
 #define KMSAN_META_SHADOW (false)
 #define KMSAN_META_ORIGIN (true)
 
-extern bool kmsan_enabled;
-extern int panic_on_kmsan;
-
-/*
- * KMSAN performs a lot of consistency checks that are currently enabled by
- * default. BUG_ON is normally discouraged in the kernel, unless used for
- * debugging, but KMSAN itself is a debugging tool, so it makes little sense to
- * recover if something goes wrong.
- */
-#define KMSAN_WARN_ON(cond)                                           \
-	({                                                            \
-		const bool __cond = WARN_ON(cond);                    \
-		if (unlikely(__cond)) {                               \
-			WRITE_ONCE(kmsan_enabled, false);             \
-			if (panic_on_kmsan) {                         \
-				/* Can't call panic() here because */ \
-				/* of uaccess checks. */              \
-				BUG();                                \
-			}                                             \
-		}                                                     \
-		__cond;                                               \
-	})
-
 /*
  * A pair of metadata pointers to be returned by the instrumentation functions.
  */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-17-iii%40linux.ibm.com.
