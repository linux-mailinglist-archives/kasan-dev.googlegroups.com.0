Return-Path: <kasan-dev+bncBCM3H26GVIOBBYOW2SVAMGQEQQRHYMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id C3EE27ED21E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:42 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2803256bc44sf841a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080481; cv=pass;
        d=google.com; s=arc-20160816;
        b=anDLxRFs29aJBMMqEnEKyFAeuTqChGH1lQ/6f4OKSRTyuitNlK39fRCvVYgWrmefE2
         rKqetg68hNv9p4mxdvRkVQ9EaaBIsCtELwg8u9cFH4odOww+qwuwcKDvz8l+2kNpXqyl
         RYmiOHC4VO0EUwlujhsrAIrAwYo8wRcCxxXUlIQSCks2lz+DZd816qrUCoKrrsPESNWa
         Ar+7uvT1N+NFhGljJR2X0/vHfiM2uNAIxZ+Utg5tM++RwSxLsWRewaEUADPafyNhdP2k
         /ojodfOo615oZoYsmxULFJqiZ9NE1rYIdu8G4UjQ84v0zLK1f+WHI3UxKS1bFHEZImuV
         gnQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6ZnRheMhxdVr5KJce7xo5NQzaF5BZtJjE6tZMDDVl34=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=iziJ2Sb5Gun/0kSmVg0rs/gOVrTBMM7g7tqno1g9WYfDL7m0p7RIKkk5zg838PdaWj
         G6+qIbJvENMncdaowUr1VrJ9YnD7nR6y4ohub2byUhfoq/hDV1HchB4qp8OHrIsbnWCx
         Z1ld/ijwWQrBkRaVVJ7sHE/yLTKQUXjjJj9p4TfZWZ6x35BgyZebBNwMLfA+NP+32YS+
         SIeBWhxEEW1ikJ0MY+aCfM0TsM66EQFKPWJipV7C0uTR1q9GMa1EEydzXXAU5+aimGkq
         JuorbdAqlJY7uyFldGMGRUlRua3hOzs1Jb2xA5xKLr7tL22+lyYs+gJRxcGSFXvU1fC3
         Imrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="axpKf0C/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080481; x=1700685281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6ZnRheMhxdVr5KJce7xo5NQzaF5BZtJjE6tZMDDVl34=;
        b=TS/vkzSo40aMMaM8Z8PLxujcebGm3SnBIDOh4lfazM95flW+ZpPNjLd1z1mlX+mReZ
         2hMM1L2Fh/XCeBGCAaHe3oCczJABzuBWPUUrdOTau1WMTsDFE6fzA4J4vzTeGbcPf9Tr
         lYvr6Up6FGUorxOdOL/NcEPren3mo8lclmDtv39UZ1cUUDzApTwV7uqXARURu7mR5i7C
         edEZbX6nM15HkN9Wc5shhUc8L0N1VD07Ye1iN9tn629xbizHeKOf7fYHnB8hoO1nfPxx
         Vq5orldvicNhpIlEMX+EQq6wPmYDizHS2irfBqFhuXom9YoFP6MlOoqGQi/BCqaGDyNp
         Iz1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080481; x=1700685281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6ZnRheMhxdVr5KJce7xo5NQzaF5BZtJjE6tZMDDVl34=;
        b=Y85Z5Vm4WSOait+WCWpgWyQbL461zTG0BGci1MrRQjHrwfngJufDOU8i4cRP/T0nfZ
         DCPlhIroH4TTDrVSbP9Hj3qhTB9PFLsOFUR4acG++p3cwDwhLeikp1WrDPmNbox/kxOx
         8vvj0E+Ce7iI1iHTsrvibAPIqWvA4gKZjWCVFQ3aQyPkA++JpZgkBwzQ+l2uVUyZxjVW
         l0Zoy5znMRJG89preow6blGAYEaKHkr6tv575eE3BJznPsKqseUVgBHCGZxD30k3XjqF
         kjIE4MMEufqo/oxAtljIoLwmRAp9AjWucYcjIqP6Ct/eBJz7v5UA1vVDIF+0SRghKcss
         h1GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw3IUxLMZSMH3S/7WRctStD868vDn0lq7t/GmyKAJC8CYnUVzk7
	TPavzaSbjspNFSAdk1xleYA=
X-Google-Smtp-Source: AGHT+IFhDcZL6W00Dy/zR/5ME1Y4zUeDoe4b3ji8nmB3MUAmT4m5gcNZnoPcEbiglcddoQ4db/WnnA==
X-Received: by 2002:a17:90b:4d0e:b0:27c:ed8e:1840 with SMTP id mw14-20020a17090b4d0e00b0027ced8e1840mr11080371pjb.10.1700080481132;
        Wed, 15 Nov 2023 12:34:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d181:b0:27b:4224:3b48 with SMTP id
 fu1-20020a17090ad18100b0027b42243b48ls134276pjb.0.-pod-prod-04-us; Wed, 15
 Nov 2023 12:34:39 -0800 (PST)
X-Received: by 2002:a17:90b:1e08:b0:27c:f8bd:9a98 with SMTP id pg8-20020a17090b1e0800b0027cf8bd9a98mr10428258pjb.40.1700080479407;
        Wed, 15 Nov 2023 12:34:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080479; cv=none;
        d=google.com; s=arc-20160816;
        b=zy35SvaoKBmpm4SBGPJ/qUeTl6AjVedYhZdOFM++2nu1aGw1NHga0KsgKxj+V7DTaE
         jCjV9pphyeEGfbG1oUbIL+5cJFBD1pqNGFJ1Q9HOR2m8MwXBlcgqzsesdJ3R0pGwl1RL
         ovzMjPu4xTVDRb6Gb9roIYFi/Sft4LZpCdNmeFUvrDZVl6ZH99AaYqkNmi6SGUsv1+t8
         R+gXAm4Z0hk9PIVRhFlFJTncB2ibSKEu+8CniaLhCxWYi+OswHMViRqbs4x4yc1pTDsP
         kChFb2QonvL8QAGF6FbhwgAkbkLgP951rNUXd3B+Ip9j4h0YFvd2K8UfTX2Betyz2khY
         Yzuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7CSL1yly+mfTewmMZpRp6TG2r/w75e0//7iE+NvfE7E=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=wccH8WyXlz/a0cNlKPNiagdQ94JPcaF5o8MnX/dxwavcwznjFJ4IhBGr3ZkCNGOyHl
         NeNRjDJPKwjHGfWmlQRC9vrx51uuEU66wz6GAhws9Y07/a3oSl/d3+Lf7mBIlnxVsCOl
         Nui8/ooP9RBZmLuYe/Y9NGC8j6l9Lrh3vkcfx0RL9VPNDuQrboQvqJSgDaRWP4qrKl6n
         EKJgS4BkZZcPiG4zmorolmb8lh81iIG46f3SLs1KMFFlsG2rFlWAhIAqMip1aI5SZn63
         cwa0o6w1FHIVIKtdnwRxzO/fDQoRHXsOF8SmNoPKKSyKE661ZIu8wEmpGYw5bFaU2mCG
         HQvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="axpKf0C/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id j15-20020a17090aeb0f00b0028000e8c2absi220953pjz.0.2023.11.15.12.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:39 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKWmer030721;
	Wed, 15 Nov 2023 20:34:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g1aj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:34 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKXiCV001884;
	Wed, 15 Nov 2023 20:34:34 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g1a3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:34 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ06d014625;
	Wed, 15 Nov 2023 20:34:32 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvsy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:32 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYTS916253564
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:29 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1DC912004D;
	Wed, 15 Nov 2023 20:34:29 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C5CD220040;
	Wed, 15 Nov 2023 20:34:27 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:27 +0000 (GMT)
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
Subject: [PATCH 12/32] kmsan: Allow disabling KMSAN checks for the current task
Date: Wed, 15 Nov 2023 21:30:44 +0100
Message-ID: <20231115203401.2495875-13-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: _iPe_nLp2MEt0BGzXvKFnSXZBmzon80R
X-Proofpoint-GUID: zd4VFCqUaPM6hnX8Cj5Ti_7HDBuQLQCb
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 spamscore=0 adultscore=0 priorityscore=1501 suspectscore=0 clxscore=1015
 mlxlogscore=999 bulkscore=0 mlxscore=0 lowpriorityscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="axpKf0C/";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

Even though it's not strictly necessary, make them reentrant, in order
to match the KASAN behavior. Repurpose the allow_reporting field for
this.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 Documentation/dev-tools/kmsan.rst |  4 ++--
 include/linux/kmsan-checks.h      | 12 ++++++++++++
 include/linux/kmsan_types.h       |  2 +-
 mm/kmsan/core.c                   |  2 +-
 mm/kmsan/hooks.c                  | 14 +++++++++++++-
 mm/kmsan/report.c                 |  6 +++---
 6 files changed, 32 insertions(+), 8 deletions(-)

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
diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index 5218973f0ad0..bab2603685f7 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -72,6 +72,10 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
  */
 void kmsan_memmove_metadata(void *dst, const void *src, size_t n);
 
+void kmsan_enable_current(void);
+
+void kmsan_disable_current(void);
+
 #else
 
 static inline void kmsan_poison_memory(const void *address, size_t size,
@@ -92,6 +96,14 @@ static inline void kmsan_memmove_metadata(void *dst, const void *src, size_t n)
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
 
 #endif /* _LINUX_KMSAN_CHECKS_H */
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
index c19f47af0424..b8767378cf8a 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -43,7 +43,7 @@ void kmsan_internal_task_create(struct task_struct *task)
 	struct thread_info *info = current_thread_info();
 
 	__memset(ctx, 0, sizeof(*ctx));
-	ctx->allow_reporting = true;
+	ctx->depth = 0;
 	kmsan_internal_unpoison_memory(info, sizeof(*info), false);
 }
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 4d477a0a356c..7b5814412e9f 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -44,7 +44,7 @@ void kmsan_task_exit(struct task_struct *task)
 	if (!kmsan_enabled || kmsan_in_runtime())
 		return;
 
-	ctx->allow_reporting = false;
+	ctx->depth++;
 }
 
 void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
@@ -434,3 +434,15 @@ void kmsan_check_memory(const void *addr, size_t size)
 					   REASON_ANY);
 }
 EXPORT_SYMBOL(kmsan_check_memory);
+
+void kmsan_enable_current(void)
+{
+	current->kmsan_ctx.depth--;
+}
+EXPORT_SYMBOL(kmsan_enable_current);
+
+void kmsan_disable_current(void)
+{
+	current->kmsan_ctx.depth++;
+}
+EXPORT_SYMBOL(kmsan_disable_current);
diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index c79d3b0d2d0d..edcf53ca428e 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -158,12 +158,12 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
 
 	if (!kmsan_enabled)
 		return;
-	if (!current->kmsan_ctx.allow_reporting)
+	if (current->kmsan_ctx.depth)
 		return;
 	if (!origin)
 		return;
 
-	current->kmsan_ctx.allow_reporting = false;
+	current->kmsan_ctx.depth++;
 	ua_flags = user_access_save();
 	raw_spin_lock(&kmsan_report_lock);
 	pr_err("=====================================================\n");
@@ -216,5 +216,5 @@ void kmsan_report(depot_stack_handle_t origin, void *address, int size,
 	if (panic_on_kmsan)
 		panic("kmsan.panic set ...\n");
 	user_access_restore(ua_flags);
-	current->kmsan_ctx.allow_reporting = true;
+	current->kmsan_ctx.depth--;
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-13-iii%40linux.ibm.com.
