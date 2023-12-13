Return-Path: <kasan-dev+bncBCM3H26GVIOBBC4A5GVQMGQE2N53A7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id DFF6D8122F3
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:44 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-28afd8d5dc2sf774504a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510603; cv=pass;
        d=google.com; s=arc-20160816;
        b=yVBi3cpHscWlNJcGXQcXozuVUyv0R/zl46zp0krXEVyrg9wMyHTW8nR5H9hTEdZ8Sy
         ljyTtMB5YqTUEYE4nBomMCM6qLprKH5niJ7U64+sXeX0Q2CiTdMVrhiQA8HTV+PmpgTR
         h7QKfx31U4JH+DaIWxghYbP4mkdQq+q9dACubDoDGIco4RI/OToibDleDPiJgx+zYro/
         qxdbcBghQyapHpqEVckNirvckZF1jbz9MY0v58d8lzEbjcTlc3gHs2v+ZydNBgrrSSJr
         /n/KpnuWw78qTuyB+XbyggiGLq5d2rKYLs0yWMkODzIVnHQ2RLLJfLm1ezAW/OihkFRU
         noSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=l2igGQyz5S7Tq2BNgoLXN3AIZ7vnWY6olBs/oRz3qcE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=sPNP8aPpcU6JWx9IjsnZxkCr3nQV9y3JyCyBk+0eS31vjUCG5lJsMLdPaK0r76trAk
         axPxtev6r0Lz2bBYxGm/GpKibWkMqmUk1D97Y7XA5jxtZvuUkftRh9SWIo6dFV2//Haj
         0WtOh0MgBClYmpSI6BqA/89RbEsTja8bj7k7i2q1rP8tvv8ZlLZVizjp3e8ppy+rAjdO
         ejrk+aAXOvIXv8tUpLfWKO90rtVp1bROhNHGueHm8/ywtMtfRePvzG4WkFf8GDH/eUY1
         YPeEPILK9a4xNGgi6D7IEq3sCgweXTdlLXMua6TCh6aQnnPhonDGDTQF6NlEGCEkBUWi
         ssXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rti6Izmv;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510603; x=1703115403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l2igGQyz5S7Tq2BNgoLXN3AIZ7vnWY6olBs/oRz3qcE=;
        b=wCxzvhcQqLfbKBIA03ZHITcGOemXgsDU/CgUDdqshPACMAIdGDEV/yaMxSxeSuGRRO
         rei2xkotfCBhHV7GsiGIBHB2f5gIkqHFgPU3bKZSmB7OkyfIZ3m9cRfliNF2B3C8yser
         im9376uFTsAjcVyV3gROaDLWb2jc6W7KhwNslciiSD7SN4bIdW8bdbeEkAfTeKLV3N59
         r+ZX6rhSRXEPVNLV7sluXd0FUcVe6ENyRlbUykn4czQunAIgsGTyvtH4mqVPTbfBTj2p
         X1B7buO846WikwsxxrhX6krwSbOjNYLrBXEZ6Xi7quc1NVmoZoDqGc/6qovht6RBsTr0
         6SbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510603; x=1703115403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l2igGQyz5S7Tq2BNgoLXN3AIZ7vnWY6olBs/oRz3qcE=;
        b=edM7D3vRIswDXJZymhhcR8XSXbcGAjiRlBUsKSgmqdaVNhp1q3u+lGZiVU83bTLmyP
         nzgifllKJhO6k2DW6N+Tg6sHx/bGiRLh9Idjlp4cSnjE4TYpJ4ibQ8LU7wSxUYt4fYhb
         Wg/x5mU0+KeIzNYShFbydRIklYZ+PHKE6wU8O4C3l4VxnoKIk832JHwBNjFyELhofSnN
         hb76QziQaXv1p9Xg0RBYAnPqRvICt7wj34UE+zHL5YQ2SA+YTLLmXHG9yGJdORIeVE0d
         MvGTG9HKjP4Bz7IovNRaYBbtjshjJt7yEGRSeGMdx7qbP9d7X/hpZFj9PwpKJx4Tw4Wp
         deaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyN/hlvBq9iTgPTp4m7zdmrytisTfO4U1foEV0aVVsXZyCkBVvw
	tsQA28+SNNowzStrUphCJZ8=
X-Google-Smtp-Source: AGHT+IEeINzQwpR8q8AyTbUGyra9Jue9YnVON3a53BsT46IMvAm2D22QxzQfd8boRNeGYAt6FCBTFA==
X-Received: by 2002:a17:902:ef89:b0:1d0:a791:758d with SMTP id iz9-20020a170902ef8900b001d0a791758dmr7765939plb.135.1702510603441;
        Wed, 13 Dec 2023 15:36:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d98:b0:1c9:ad7b:45e5 with SMTP id
 v24-20020a1709028d9800b001c9ad7b45e5ls2578437plo.0.-pod-prod-08-us; Wed, 13
 Dec 2023 15:36:42 -0800 (PST)
X-Received: by 2002:a17:903:40ce:b0:1cf:7bf7:e655 with SMTP id t14-20020a17090340ce00b001cf7bf7e655mr10187658pld.8.1702510602465;
        Wed, 13 Dec 2023 15:36:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510602; cv=none;
        d=google.com; s=arc-20160816;
        b=RxfC3ijvwpaUw7LnMMWXxjtlS9BllkiDAUgruQMc9Ws0hVGTsw7boG49O+6cULHEm/
         5Mq+DriXBDoQXYsjk767xdR6c5EV8uj5U6JRZVBs9rJ9GDBQnBIMeLUAYPb6f9oUd0f2
         LcrmAnEtM+vzPmfMVt/PDAVvYgrONjANTu9L94oI9lfkOwuplHRreo1HboVpOCUD2qrT
         mw5u0IhlU0xqvCY+DPHr90kb3rdFM7vEB8u1N18S18qi3M6Kny4h/WEXln3WmGJ0Bncb
         XSfwTVciLX++tJRZrFKn/EejmiIMxHNloHbe5NmfXYck7WMZFq7BzHcst5Sziequp+By
         +3sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kALH6Y40PszMAinDNJqUOT92xkYCLa2PA86QJ0JSv5E=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=bCQLvLVQlVf3U4nxf9bNrloc1+l9SQ68PDsCghYNUUUqOBEwM7pLaUcCmaIo2H1ONi
         /9IGJ7RFW/zsm7zWiyiRQuA4KoAbjvwIIg+mRNJ1u2vhnKoFMJHBYewVncHGFHDZ7YUm
         Hj6QzIT/iWf5lZq9oUCFOyl3pqed1TMaVvvZY32RinESPkflumjUotKd0hiRCDYi9PZS
         TYIoQXnZAdyaCb8AObHJuc5Sib9S5fL/My7DQckMmonYqo/wBfgPGF++804rPwOTE172
         58erBp+flNZ2ZByBTIJt0BImvQXFDV+TqOeKmrPz1fZR00zCCMx/LXvr4FR5jZaFdBKL
         RSIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rti6Izmv;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id lb3-20020a170902fa4300b001cfa77a33e0si799243plb.12.2023.12.13.15.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:42 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNWpG0008639;
	Wed, 13 Dec 2023 23:36:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypce81tm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:37 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNaaPI017559;
	Wed, 13 Dec 2023 23:36:36 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypce81sp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:36 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKwk1X008585;
	Wed, 13 Dec 2023 23:36:29 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtmvkk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:29 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaR9V20906592
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:27 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E149B2004B;
	Wed, 13 Dec 2023 23:36:26 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7B4F320040;
	Wed, 13 Dec 2023 23:36:25 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:25 +0000 (GMT)
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
Subject: [PATCH v3 11/34] kmsan: Allow disabling KMSAN checks for the current task
Date: Thu, 14 Dec 2023 00:24:31 +0100
Message-ID: <20231213233605.661251-12-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: jBznlbH2FEtEOu-Pu04xnJahDcCOZLZZ
X-Proofpoint-ORIG-GUID: is7ZIVg49ekM5OZcy2r9v7nHMXQ7PWe1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 mlxlogscore=999
 lowpriorityscore=0 adultscore=0 phishscore=0 mlxscore=0 suspectscore=0
 priorityscore=1501 clxscore=1015 spamscore=0 impostorscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rti6Izmv;       spf=pass (google.com:
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

Like for KASAN, it's useful to temporarily disable KMSAN checks around,
e.g., redzone accesses. Introduce kmsan_disable_current() and
kmsan_enable_current(), which are similar to their KASAN counterparts.

Make them reentrant in order to handle memory allocations in interrupt
context. Repurpose the allow_reporting field for this.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 Documentation/dev-tools/kmsan.rst |  4 ++--
 include/linux/kmsan.h             | 24 ++++++++++++++++++++++++
 include/linux/kmsan_types.h       |  2 +-
 mm/kmsan/core.c                   |  1 -
 mm/kmsan/hooks.c                  | 18 +++++++++++++++---
 mm/kmsan/report.c                 |  7 ++++---
 6 files changed, 46 insertions(+), 10 deletions(-)

diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
index 323eedad53cd..022a823f5f1b 100644
--- a/Documentation/dev-tools/kmsan.rst
+++ b/Documentation/dev-tools/kmsan.rst
@@ -338,11 +338,11 @@ Per-task KMSAN state
 ~~~~~~~~~~~~~~~~~~~~
 
 Every task_struct has an associated KMSAN task state that holds the KMSAN
-context (see above) and a per-task flag disallowing KMSAN reports::
+context (see above) and a per-task counter disallowing KMSAN reports::
 
   struct kmsan_context {
     ...
-    bool allow_reporting;
+    unsigned int depth;
     struct kmsan_context_state cstate;
     ...
   }
diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index fe6c2212bdb1..23de1b3d6aee 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -239,6 +239,22 @@ void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
  */
 void *kmsan_get_metadata(void *addr, bool is_origin);
 
+/*
+ * kmsan_enable_current(): Enable KMSAN for the current task.
+ *
+ * Each kmsan_enable_current() current call must be preceded by a
+ * kmsan_disable_current() call. These call pairs may be nested.
+ */
+void kmsan_enable_current(void);
+
+/*
+ * kmsan_disable_current(): Disable KMSAN for the current task.
+ *
+ * Each kmsan_disable_current() current call must be followed by a
+ * kmsan_enable_current() call. These call pairs may be nested.
+ */
+void kmsan_disable_current(void);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -338,6 +354,14 @@ static inline void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
 {
 }
 
+static inline void kmsan_enable_current(void)
+{
+}
+
+static inline void kmsan_disable_current(void)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/include/linux/kmsan_types.h b/include/linux/kmsan_types.h
index 8bfa6c98176d..27bb146ece95 100644
--- a/include/linux/kmsan_types.h
+++ b/include/linux/kmsan_types.h
@@ -29,7 +29,7 @@ struct kmsan_context_state {
 struct kmsan_ctx {
 	struct kmsan_context_state cstate;
 	int kmsan_in_runtime;
-	bool allow_reporting;
+	unsigned int depth;
 };
 
 #endif /* _LINUX_KMSAN_TYPES_H */
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index c19f47af0424..68c68b30441d 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -43,7 +43,6 @@ void kmsan_internal_task_create(struct task_struct *task)
 	struct thread_info *info = current_thread_info();
 
 	__memset(ctx, 0, sizeof(*ctx));
-	ctx->allow_reporting = true;
 	kmsan_internal_unpoison_memory(info, sizeof(*info), false);
 }
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index eafc45f937eb..3acf010c9814 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -39,12 +39,10 @@ void kmsan_task_create(struct task_struct *task)
 
 void kmsan_task_exit(struct task_struct *task)
 {
-	struct kmsan_ctx *ctx = &task->kmsan_ctx;
-
 	if (!kmsan_enabled || kmsan_in_runtime())
 		return;
 
-	ctx->allow_reporting = false;
+	kmsan_disable_current();
 }
 
 void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
@@ -423,3 +421,17 @@ void kmsan_check_memory(const void *addr, size_t size)
 					   REASON_ANY);
 }
 EXPORT_SYMBOL(kmsan_check_memory);
+
+void kmsan_enable_current(void)
+{
+	KMSAN_WARN_ON(current->kmsan_ctx.depth == 0);
+	current->kmsan_ctx.depth--;
+}
+EXPORT_SYMBOL(kmsan_enable_current);
+
+void kmsan_disable_current(void)
+{
+	current->kmsan_ctx.depth++;
+	KMSAN_WARN_ON(current->kmsan_ctx.depth == 0);
+}
+EXPORT_SYMBOL(kmsan_disable_current);
diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index c79d3b0d2d0d..92e73ec61435 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -8,6 +8,7 @@
  */
 
 #include <linux/console.h>
+#include <linux/kmsan.h>
 #include <linux/moduleparam.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
@@ -158,12 +159,12 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
 
 	if (!kmsan_enabled)
 		return;
-	if (!current->kmsan_ctx.allow_reporting)
+	if (current->kmsan_ctx.depth)
 		return;
 	if (!origin)
 		return;
 
-	current->kmsan_ctx.allow_reporting = false;
+	kmsan_disable_current();
 	ua_flags = user_access_save();
 	raw_spin_lock(&kmsan_report_lock);
 	pr_err("=====================================================\n");
@@ -216,5 +217,5 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
 	if (panic_on_kmsan)
 		panic("kmsan.panic set ...\n");
 	user_access_restore(ua_flags);
-	current->kmsan_ctx.allow_reporting = true;
+	kmsan_enable_current();
 }
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-12-iii%40linux.ibm.com.
