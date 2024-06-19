Return-Path: <kasan-dev+bncBCM3H26GVIOBBLP2ZOZQMGQEAYHEUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8509E90F299
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:50 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-36db3bbf931sf72169635ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811949; cv=pass;
        d=google.com; s=arc-20160816;
        b=klS2qkSfHEAfvViFkRm8flSkFvge9ARh7jBH70YeHlxikNWzusj/21b2XY+C2b+SkC
         UL+k5Q/1nh46qjDDuPK0XL8DFGmbaJbrtFgrdvw8JjxI+Bj88sFNDjsj6ypL0wm7kTH4
         knXGy7pOFj81YlUJIwsWaOnTXeGag08n2KlEX7rwiQP7jCaDGbsNlxJZJIzqFyV/5aWK
         Z0zEIL1B7qYEROcKQUfKWc5TF1BMzoisyRT69G1dCxDi6prBxZ+Ts8PADyvyqjFIeDn7
         tCdXpNpMZp83/+tgCqc5QmAK1FFJld7FIHySGgJ7wTJQfyPrLNEuiB0r1A5W9rdJnkyC
         Xjpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mV2D3wVZWAfwx0x3P35Th1dfCQWxNx2C1uTe6Fdj1p4=;
        fh=26RfVrawAcYRzDlyExHcou0uUa2Zhd8wHw08cL65r5o=;
        b=GK96C6vhQaipHgOYJIMeVvLfNu+RuWPG2e+ajXU4xeilDvia40ooY4MBNDrd8di/Dj
         obB0u4wTlME+5gGycYtCTlD237b8BmM6kB7DDegIPmhFNN2Ke380hbyivRiiLj1azM2p
         n2+tWdhpoeuTCw1aLklWmgAzD7NaHDiNMdeiHA32lD9ApQoWjykhWv2UUhJ7Q+Vpl1OT
         ZjYGXBNHOuhcIcdwh3bPCCzdAKRU77IUFUBwDloihAWsR5MwGefzxjwTdprZlE/irsYA
         kINz33yb73SH6j6msYxcHD8zJYupUxAgYE3pHtJrryli2mKelt7BqqH+EZCROfZ30TQq
         x7XQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MM7V8Kud;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811949; x=1719416749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mV2D3wVZWAfwx0x3P35Th1dfCQWxNx2C1uTe6Fdj1p4=;
        b=W8rjMRJkyDmr2A3UJSf0dZJhCBjRGchrKHTb+z8MjGro0VK5nklu7JKbGm+pYZCwGF
         NHNsyh9nCH9IbowWgwnhb58K257pYEl96ejNuNVvyblXumdbqEXQ/r9jWozOg6OjlKzw
         UTSNeCdG5wJOm1uZzRmumFxIcFBY2aEJrenfJeGHFebX+FVjhUFo1SsDJk54mhp1Dtdc
         d/XGaBpAfqJWTvR/zl9Tnd6ydt3AMG+cSf8F6ton8c9sixnMGfuM3sIz6kJRqHH1jaJ5
         odyU19Enysbksh+sTxXk/qT9lpG5hInKPJHBdKImXkQWKMxfpGRBCKNieVsOQDF0HtMk
         g4ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811949; x=1719416749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mV2D3wVZWAfwx0x3P35Th1dfCQWxNx2C1uTe6Fdj1p4=;
        b=UKFepKhi6KlBHe2dETJMLm+LhkB2WvgYpHu2lztY6NCEFDNOfwqcdAZfmVKyAxY71q
         lznw3CaoQZ/D9B7B732Wl1QTDOLC2HlAWWDeglXWd2J7pyD5XSjVcagKr0rzk+Qpp+2s
         rdBOWOy280pMnFGsylCG2zT93Uq10lVxu1SkCoU9o08S8YX5pXlNXNdDy/kRIiwGda1P
         1U0Y6eoK6d46f1DsQxQOt0xlvSGOw+7de/OLY9zaNMxyI08TjpgEyCqedNvsaT8X9pJy
         aADUIgkXlNgYcWb1cqDy+54WaQp8jXH4UtNbLjI8GWZOFFAYLx0rRqKmC1ddNIriIHh9
         qAGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUCtm++9n8me5ipps4bVbVxFpHEdn7NnoX9OzABldEou5E+WzEvkBBvjmofNNVuFT4SgUmh1T5LK9ObiQ0eNYtR/2erw2oV6g==
X-Gm-Message-State: AOJu0Yz2AMZGKXJuAri/WNkbPfOpk6vh+hWJw1xRWLCg9RgVnqX3Zsf2
	AYIURVsBHczjY/daxs7+rUUIvXbLHkzjnBFmU4tz5Ce5KzWOI4r6
X-Google-Smtp-Source: AGHT+IFYulNfLjdMVv8lP7dFNMXgCjXkUPGfcqW7//y4hFw1+AE7kbH6lAa4C379JF8cqkCdsUIjTA==
X-Received: by 2002:a05:6e02:194f:b0:375:dad7:a645 with SMTP id e9e14a558f8ab-3761d71fcb9mr29592045ab.27.1718811949283;
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a84:b0:375:a281:a669 with SMTP id
 e9e14a558f8ab-375d56b6a46ls48262425ab.2.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWr4pi7778RX2uCBbG0moU+grjtA9BWOO5jUS51B8iwmlIaPTS2P7iB1if3u5pSFBku2xZFObXVpeLO/BFvVXGE9I3tQ64Q9+3vHA==
X-Received: by 2002:a05:6e02:1c2a:b0:375:ae6b:9d92 with SMTP id e9e14a558f8ab-3761d68491bmr33584105ab.12.1718811948603;
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811948; cv=none;
        d=google.com; s=arc-20160816;
        b=ajl8l41HvQIAV2wZl7G5TaMil1l27Db6L4fNNSdJYgDy23PI24MEkdfTc2s2icN0s7
         aKF7UPj+SBb9sWq0NjtgNQlrTreJkRQ2NMi0c2fuFV+5rDPUDyc6yxzxNfj2zfD6J5lW
         QJSmKHC17E0aCzViv+0AUthqEfOariDLqb3uirsSMtMmDE9wL9Vw6qbUd8sByW1mL8RZ
         ouqprqB3DjlGPqK6ARtnivIaLjw7eb6/svcyvwQgqrCH8INZDQe/utsiWxbpYLbOIqxo
         QD53PC72QPlenu3EtarTFyt3r7XmkKF/Q9yr7g927s3hw6BYfdZ/Xlt4atDBzpld4fyB
         RXXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VXS/CROs6yE7UNWuiQuFKJi6Qw5yeAHe/FeukS5ug+8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=EQM8KrkcswYcQ2HLLCNqM3AqDmgceH0e3ojACgFLvkfUf7f0EyZj43OrEPP/ytcQIr
         /66gUVtFzOnZQ+HiO8TpAIaZbzAnZFsDiL8s9hgbzoulBH5M6zlWeOCGIljivYJiQId+
         ATDdHQsBR0aHeOLKT+pCFm9+c3DIfC6FuHFd0qdVuR2zbKhZpXVtiCQtrWl32mBVW4PK
         XmbJUKboSdnS8MKSUP9PYS3Ubhjx851wzEDk5mW317wXuliy5GvsEw8RjrQ10iwZ33zn
         J6/GIMFgm9imVfsYQv4NS57lJ6ccGKtMoBQP+9J6Lewl5c3nb+a+9P2BtA3I4O3n6m/z
         Iqfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MM7V8Kud;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fede16a64asi800525a12.2.2024.06.19.08.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JETKsZ000677;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8bq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjiXA027307;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14tg8bg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEdTxx009433;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmmk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjbaP14025152
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:39 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B37F02004B;
	Wed, 19 Jun 2024 15:45:37 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5919F20049;
	Wed, 19 Jun 2024 15:45:37 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:37 +0000 (GMT)
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
Subject: [PATCH v5 11/37] kmsan: Allow disabling KMSAN checks for the current task
Date: Wed, 19 Jun 2024 17:43:46 +0200
Message-ID: <20240619154530.163232-12-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: RrhlJjxZQYf9pK6OPK865PIXzJkUUgUU
X-Proofpoint-ORIG-GUID: rnvyXIBHOyj0RfBbiCienZKnto1dMAcv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 lowpriorityscore=0 malwarescore=0 suspectscore=0 mlxscore=0 clxscore=1015
 spamscore=0 mlxlogscore=999 impostorscore=0 phishscore=0 adultscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=MM7V8Kud;       spf=pass (google.com:
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

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 Documentation/dev-tools/kmsan.rst | 11 +++++++++--
 include/linux/kmsan.h             | 24 ++++++++++++++++++++++++
 include/linux/kmsan_types.h       |  2 +-
 mm/kmsan/core.c                   |  1 -
 mm/kmsan/hooks.c                  | 18 +++++++++++++++---
 mm/kmsan/report.c                 |  7 ++++---
 tools/objtool/check.c             |  2 ++
 7 files changed, 55 insertions(+), 10 deletions(-)

diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
index 323eedad53cd..6a48d96c5c85 100644
--- a/Documentation/dev-tools/kmsan.rst
+++ b/Documentation/dev-tools/kmsan.rst
@@ -110,6 +110,13 @@ in the Makefile. Think of this as applying ``__no_sanitize_memory`` to every
 function in the file or directory. Most users won't need KMSAN_SANITIZE, unless
 their code gets broken by KMSAN (e.g. runs at early boot time).
 
+KMSAN checks can also be temporarily disabled for the current task using
+``kmsan_disable_current()`` and ``kmsan_enable_current()`` calls. Each
+``kmsan_enable_current()`` call must be preceded by a
+``kmsan_disable_current()`` call; these call pairs may be nested. One needs to
+be careful with these calls, keeping the regions short and preferring other
+ways to disable instrumentation, where possible.
+
 Support
 =======
 
@@ -338,11 +345,11 @@ Per-task KMSAN state
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-12-iii%40linux.ibm.com.
