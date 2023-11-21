Return-Path: <kasan-dev+bncBCM3H26GVIOBB3OT6SVAMGQEASS7EOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C67F57F38DF
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:06:38 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-35b2908a225sf7392845ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:06:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604397; cv=pass;
        d=google.com; s=arc-20160816;
        b=wen1LUUHw5FioZm5ZOquMC8RoRUaUuRxPTxNCDbrlNU5TpBIt30b0RufKT7D+v+BKZ
         9kTanhW7RlHgYtDgOziBm/9ql+WfGy27Z7KIIWWZ5wPhMCRBAttChzYwHf/dIrHPssi2
         9XtPbs5SriJULdke9ZBTg4l9Q2TWSQL+wgPQDxKwBeQeCJuGmOJck5+sUIDVtJpqdN98
         S0tHYC+CGiPVYVKQD3aapjFIeetPtNN4M/LP82DPoeS8fzaOZ3QoO6AVwyWzWqCBYmPa
         kjhd7DiLoWM4DNp03hhb2BNXPi07Vc+2YNRyv/A25VmCbj6g8jCdGefOn687XBAxNUpc
         o5eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JTzO/7DUtgPWgJ011AzjEFavI1CshuDZXKHsCPTwu9s=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=pfcVzwh8ZTkdAnKCHzdV2SbLKfgAZd58RhpxyssdXxhP/WOY2XQDhVjKDLV7zAjMhJ
         bd7iKo4vKTkmo/H4RBzSLoG2KOy2UWiFMhhImzfFex7/7fBZUfYJDxSzdnRlTHJq4lGC
         ltYdMqIWNZOpbN5P7x6fEcaxaQEMMhGuq/BgeLodPHVyHWamlbkxwmHyLim5J1k+oMAj
         j+xnK66i6LIsxAtijCMum02DgiQdKQrX3z0NM6Wb8OviZRvXU83YQ0zfqqOrWP8koWld
         iXsvduV6TPhcXe+Dv/GvgbBV5fImh/Wrp5i5k0I6iiocm+K0yH8s8ClSz1rIj0sL5NfA
         +OPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IMKNmzrv;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604397; x=1701209197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JTzO/7DUtgPWgJ011AzjEFavI1CshuDZXKHsCPTwu9s=;
        b=dfpiEpjM+Pgp/iYDd9CiV0yEQPp4WHvJIMQtq2OPazQsmwY9ieSyAX4CetNH1NJQVP
         ifOwCGj37SyN5Vnp/ZsWo0lv7E7sCwxN3niZFLQKbnuB8CE676UeLyxZ2Kli4w1ToHhs
         ia5ovgtrU9aXiBq0N3/uIEqJ8/vTUKqLlL6wMp5vMeKsoyETCJ4l6K/6Th0j5d90t+UY
         zkrJARfCWVw0eJZwap33AoC9/Ea22lBekhYntWCLVIJkQc/bYHe0WgBBuhVjsiOfVxTX
         spM8dc5s+3z5YsFXLUAKwgZ9m95DpEoPUdpMN8+pNA+2GgidreZX1z5kx9M2qtY7Osmx
         IMvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604397; x=1701209197;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JTzO/7DUtgPWgJ011AzjEFavI1CshuDZXKHsCPTwu9s=;
        b=Uw/xkKm6m9oJTaM+TmdHt2o0iHw86RWmA3FtzXpgSpQzj/sbf36nRUYR6tzlk4xqoJ
         wK68FYloCulZVAhV6iM3NlMTkFmJqEmIbl34chS163jfBJbtj2lTX0ksJGp5OGGpZzTT
         UPkf2ncqTnfYw0sYhltu+Kp+ueyaohipYkPQUAhVLLgaEHVy2aqQ3Og+Pcre6k8wRp9+
         jq5+TV02Y3JlD3GnxBzpAdFsUDky4xzp336Zd5FyoyHqTcK/hZxeeYxUyz6Wts/u6yPA
         nwYk+fSDLmQxv5/c7J3rO5FrQ/EK8ZF8Qy33m9GuL7T8eqLcs+lRM4YoqTpC5Mxn1KgW
         lvSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwQ9oZyof4Sza28nKolCT1ObLE0gPf/3VPKkqweW4DJQPs5mjia
	8wp2be1/041uf2zRsUg+eDA=
X-Google-Smtp-Source: AGHT+IFmrLacRSWVZ4BF61Cn1UFJDRqhivYPYSTnKrfZpKSvMi6FEE/HyFVlojzHjaMicoXD/vsh7g==
X-Received: by 2002:a05:6e02:f41:b0:35b:2e81:7272 with SMTP id y1-20020a056e020f4100b0035b2e817272mr311871ilj.2.1700604397698;
        Tue, 21 Nov 2023 14:06:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:339c:b0:359:6bf2:7ab6 with SMTP id
 bn28-20020a056e02339c00b003596bf27ab6ls3795033ilb.2.-pod-prod-09-us; Tue, 21
 Nov 2023 14:06:37 -0800 (PST)
X-Received: by 2002:a05:6602:1508:b0:7a6:7bbe:5aa0 with SMTP id g8-20020a056602150800b007a67bbe5aa0mr385993iow.0.1700604396989;
        Tue, 21 Nov 2023 14:06:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604396; cv=none;
        d=google.com; s=arc-20160816;
        b=GDkzogcaTrEjp5G5xOjqjooLywjcGjUH5fMOCz9L8rOQGNUOXP7pBfGrPPTx8bKG7+
         hjNRLJKhDbGCOtfRN6KnBxuY198twVwGczW+06qpn+vvARPsFlojz+eU/CFcPGvQ8Nbp
         ee2bA13IZ4bNHD09v9xfNjT1A/P31fKCddtq3JNLbMTQWh7/t0ciCgziNzRUKFheoFH4
         T7V65LL5EgXl6VivhqEfyiVzy/44VE6c2N8Wrcqm+eLYZRVAgp89TWaKKgblb8Fj5vv5
         V0lXhJPFDmsA+smZ5Aq+JUfHF6/40WWnqLKOHXNfV989+EyAPpTs33xHQJRVia9KYrl0
         mUgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7CSL1yly+mfTewmMZpRp6TG2r/w75e0//7iE+NvfE7E=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=atFA2XAHN7TyycWTr6UYdFIRjJBmwhhDsIJpR3sTS//7OVkeqKQy1ZtRx+vukGRcfE
         x4cEIGhrD83T8eyd25WdUk3PqZvDYmKKvxQfWu9wo6JEPDFStyLBQnrSgU+uSH6dEUPK
         8Vxnd56/yEZJR+6M/lxZXoN0Eh2s4AGtj3bi/hukUoxhjtaua7xL/a9nwtHNHzeayhDc
         OxuEaKN0+C6xcoukLKDS4EUkResCsoOIB3tWXUf1dhCzmzMDeHGGaID2ylFZ0MwJZX9K
         tn5WFlSCyTQqa4pLOdHWv4jfADXz5HXCuxkZX6NH3haRMwJomKz6yFni5iva40sXa6J/
         hgjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IMKNmzrv;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id b7-20020a056638150700b00466568ec864si349536jat.7.2023.11.21.14.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:06:36 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLqdb5007881;
	Tue, 21 Nov 2023 22:06:33 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4um08k2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:06:32 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM6Von010668;
	Tue, 21 Nov 2023 22:06:31 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4um083j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:06:31 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnblU007094;
	Tue, 21 Nov 2023 22:02:28 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ufaa236f7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:28 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2QxG22545122
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:26 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 01C3F20063;
	Tue, 21 Nov 2023 22:02:26 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8A1332006A;
	Tue, 21 Nov 2023 22:02:24 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:24 +0000 (GMT)
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
Subject: [PATCH v2 12/33] kmsan: Allow disabling KMSAN checks for the current task
Date: Tue, 21 Nov 2023 23:01:06 +0100
Message-ID: <20231121220155.1217090-13-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: vq9TrT9-Ju98k7vaL7yav1286yi8B8Ws
X-Proofpoint-ORIG-GUID: _KHwdu07uF0ruSXi3x2EIAiyQ3KGTxsR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 mlxlogscore=999 phishscore=0 clxscore=1015
 lowpriorityscore=0 mlxscore=0 adultscore=0 bulkscore=0 suspectscore=0
 spamscore=0 impostorscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IMKNmzrv;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-13-iii%40linux.ibm.com.
