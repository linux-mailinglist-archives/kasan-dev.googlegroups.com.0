Return-Path: <kasan-dev+bncBCM3H26GVIOBBR5FVSZQMGQEWWPCG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id DB5ED9076DB
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:52 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2c2c5bf70f7sf1001300a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293191; cv=pass;
        d=google.com; s=arc-20160816;
        b=CAcPHB3gW/A9G7BLWSmQFpayrKKuLCjln7E1N2ZF3LDG02QBnAEnAcIwu5LRn57h59
         hxmamn9+qWw6nseH74b0sPeBFpwZsYdEh6ylPfxNDmkQSupKDigYGvtru6KZERJyN8tU
         fXCJlmpg1+noyC/4/YZcFTg3Xypls3J1PTAqFVJRUZ4wfGVeQW75re2E15AuA44SiL0c
         hFpIBjp4QxPktEmIZ6MWQrZagyBUCzyi8fxq73fJa269ZXGwdP/G/Snyuu/dIDJQ2vnh
         6+3JF+XsO5Vm0mQn90osx7ipIjN7hcKJ5ewavM2T79AvgwVjK0URSH/EV8Uu7gszfqrK
         1Ppw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=78JVyNMlPAqoOboUmn80XJH3rJJqRmqjdUF2JSe8JSE=;
        fh=a/c5yIwY9yK+lLoR0+qss3kIIjOEqvgUyiixVSB3sLk=;
        b=g8wX6Vg7bUCaRRjrBS5sfTWW3f1LTvk5Wy1NozLjxjUiQPb7Z4yKanpSjZO66cTxkU
         6R7a1rv0wvQzHY8uG3h1+HCh/ubypLETntyKL7kuJ/5ynuKwxHiUGTFxUv+BfloGt7k8
         ZMdbzpqSorB1REmKdyHru/uwllNs1St73R9tjGO5TgB2w+Zba8mOh5PvlYbk6nWCMBpp
         TPLZk/4MG/HFsh+6dugnoLGAAiLPyYzyQx6cMpNVtFeyFwSuIf4MDZQFCkQvu5fAVLq3
         YCrc7b5mw3X1H21yXSBsaSO5+xfkJt498Ao3Kv+dVPyvuMFsQ7VF1QhAGj1kzgSefRDK
         F93g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qK+vecRb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293191; x=1718897991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=78JVyNMlPAqoOboUmn80XJH3rJJqRmqjdUF2JSe8JSE=;
        b=a2OioliAaSFhztWQpVN/lvTJRnkGz+QlnfkEmvesRyH3T/e3VeEvibTTSxnNPDEM6d
         CReR4NiCRp0G0JwwwKOcf6pVGFTSh+U7Mah7uqYHk8EfJfF2D3zwiR22Qyvq1m25umz3
         tUPg06d38sbGtiNm1e8FcJ0/j8EJI74TXzCCkj6ZfAUIlTbHiINEfBpCFkMlbEPuG8Db
         UAsDy+5BG+ZQ3/eReEwo8a2X7CbLMx/my0KU0J1ZbFpQ0VOKSGWibbBT1o/hwwAvdu5t
         wDSGW19MBlrtCu3ZctlA8kIm1f6/QJYhL+J4fEt6R4tCUOC8LmDKF2qxEzLwozXlEddv
         aP6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293191; x=1718897991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=78JVyNMlPAqoOboUmn80XJH3rJJqRmqjdUF2JSe8JSE=;
        b=tGt4iDt8ww7bNA1PQZ/uPK2DiIeyOy2tR+J47VVbqlbUkFoGgDbmYAAHAyCT5dMkhH
         cHXtZhsix9MBqdzkuYNgScVc3YRfxtJjjshwUygYbfJHeE4R6w5fYCZmxR6IpRKtBP2W
         Ih7d5ZDF2ZKS0B/IamYiDO1VaLbUUzbvl8OuYRAXuqxI8Z19RQrodTkspgjYamLyuW+o
         LLmS6+mFQvdic5YXjK3QWRxlefCr4Mov0DehS1qcv/QCHl+aP3WUh/C4u43rtRdelVrm
         60/LF4EPu60py9A49GAwLYk1Gutn2V9+8k2LpS+385bWqQKGpQTHhV8z1waR6oZIVc2F
         Az6w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWilYkTFY5hLpTW0AcqZzIMSrmUDBUgHw2pWwmnDsRgtmZRoneQBGvsXPDeE7wYINR8/wDDjFy3rcqmqrClomFGgGg1oT9rAg==
X-Gm-Message-State: AOJu0YzbudpnnJZBKDZLUJ+eHO4hpXOwakvH7pRU/zQhrCribI6zibvq
	GgO1S3xEUDiR+VXVmiVFCa53CMyr3mjQHhPso4i95/8ZzQ8W1uRE
X-Google-Smtp-Source: AGHT+IGXOsSnpjDUmCV0+s6tQ21fSbQy2HwHiWMmBSVt/dQ3qgD8SbGd9NlAqXWniWafCCbhz8CBsQ==
X-Received: by 2002:a17:90a:c086:b0:2c2:f6c1:4d87 with SMTP id 98e67ed59e1d1-2c4db24d144mr137727a91.20.1718293191195;
        Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7182:b0:2c3:159f:cc9b with SMTP id
 98e67ed59e1d1-2c4bde84c72ls655555a91.1.-pod-prod-02-us; Thu, 13 Jun 2024
 08:39:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrhAFAAr0sKGh5n+97DFwXy/J4d43n75ISpTl+1q/tF7p5Kxuz+7jYWr3iI6J5rbFB/snQzHRZoXoIAP0LXHzlEB+KVu08RXqlVw==
X-Received: by 2002:a17:90a:ab03:b0:2c0:341d:1e30 with SMTP id 98e67ed59e1d1-2c4db44b46amr139022a91.23.1718293190060;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293190; cv=none;
        d=google.com; s=arc-20160816;
        b=R1ddfXDlLGj5UG5gfuX+WBj1a5sVBHP4+vWDAoVNJ01BqdVFgIWkXEj/AVrhwkukhF
         acHAScKasGScENbR8is08R0x5P4WwWEK33K2pH56xx6libWcW5AZWA/FBynCq9NDOIdh
         A0VCD3jEQ6lX1BZXCVbT+uwUKbcSLf/k1soZBJR2dube7qYkW1fS79k3rWk5h/Vrbw4r
         9q8wYncdGfdGmaowxzgsyu12Us+prsEc8rIK35sX8aAyGchzkP2+QCHlr2F1IxUG0nbv
         Rs1o8OmN/KYZTRHpz6GkeQ4gZJ3LGRllXX6a3jopR93YnF16Oii7IROzoDJn130FvI5u
         kWCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EtpzWUsKPF6Xqg09UGXz7IHFcSozBdT63cYyYIkbG/E=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=pRnWeblutLHzjxibQ7+MIYdJwRM+d2zGhlofjSETrZjxNUUHyhBSULqXBTwREKVn7P
         634dn8pxjgsFiR1tMO517o2p2jLgVfaARbwXScICbtVM8Z3QAG8NfLv71ezENkSZfFBv
         P6vy65KtL1zxd+fu5uF9mtYc/17RW3nwhG6lyOIOvYDyi8pZ/cqtEDoZ+CfyzG7ZBD40
         RuyQjkA4rKfnj8iYq1H5cnEuD4Bixd664bdjPtub5RhZ903eAFjDlRUatDPfJ8LCCqiW
         HAaO283IjQHHcJJTOuPeTzl6NlvJXcZ0ZF60pYoXeLeZqnzAjkDyDahA8ZQ8DY7ia6ny
         +sqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=qK+vecRb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4a5fb4166si317502a91.0.2024.06.13.08.39.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFaxh5028926;
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr320r32t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdjpx002434;
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr320r32q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEU7Sm008700;
	Thu, 13 Jun 2024 15:39:44 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk0u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:44 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFddjr52036052
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:41 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EB49C2005A;
	Thu, 13 Jun 2024 15:39:38 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 783B82006C;
	Thu, 13 Jun 2024 15:39:38 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:38 +0000 (GMT)
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
Subject: [PATCH v4 11/35] kmsan: Allow disabling KMSAN checks for the current task
Date: Thu, 13 Jun 2024 17:34:13 +0200
Message-ID: <20240613153924.961511-12-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: LKpz0MVqEHZkt6RKhjF39DHCXdemLjnE
X-Proofpoint-ORIG-GUID: 4diWKsJb6QpzSM8Rww7A3YFM9_vI0f-x
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 impostorscore=0
 mlxscore=0 adultscore=0 mlxlogscore=999 spamscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 clxscore=1015 lowpriorityscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=qK+vecRb;       spf=pass (google.com:
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
 tools/objtool/check.c             |  2 ++
 7 files changed, 48 insertions(+), 10 deletions(-)

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
index 929287981afe..dfc59918b3c0 100644
--- a/include/linux/kmsan_types.h
+++ b/include/linux/kmsan_types.h
@@ -31,7 +31,7 @@ struct kmsan_context_state {
 struct kmsan_ctx {
 	struct kmsan_context_state cstate;
 	int kmsan_in_runtime;
-	bool allow_reporting;
+	unsigned int depth;
 };
 
 #endif /* _LINUX_KMSAN_TYPES_H */
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 95f859e38c53..81b22220711a 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -43,7 +43,6 @@ void kmsan_internal_task_create(struct task_struct *task)
 	struct thread_info *info = current_thread_info();
 
 	__memset(ctx, 0, sizeof(*ctx));
-	ctx->allow_reporting = true;
 	kmsan_internal_unpoison_memory(info, sizeof(*info), false);
 }
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index b408714f9ba3..267d0afa2e8b 100644
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
@@ -424,3 +422,17 @@ void kmsan_check_memory(const void *addr, size_t size)
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
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 0a33d9195b7a..01237d167223 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1202,6 +1202,8 @@ static const char *uaccess_safe_builtin[] = {
 	"__sanitizer_cov_trace_switch",
 	/* KMSAN */
 	"kmsan_copy_to_user",
+	"kmsan_disable_current",
+	"kmsan_enable_current",
 	"kmsan_report",
 	"kmsan_unpoison_entry_regs",
 	"kmsan_unpoison_memory",
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-12-iii%40linux.ibm.com.
