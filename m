Return-Path: <kasan-dev+bncBCM3H26GVIOBB6OL2WZQMGQEL2B3X7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB4DD9123D0
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:30 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1f9bc7d4922sf19068565ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969849; cv=pass;
        d=google.com; s=arc-20160816;
        b=OzJQ8BG2jmDa3+jLuhO7oi+/ax2fEN6iL8UunPLvONoL/chEYuvBw/qfIEOXSttkcg
         tHw8WVuSd+eAE625JGzfoiL7CJtDzXuoVOC7cAYOY+QirTyVsJzsZYw6t2awjyIU60FS
         2HhqTTypSNnYkifxktjSuYvwOryrIgP4s+8yRoYTkx+GdkR6NppZ+PPtP+/JgQbqKuZm
         J94XljnLcfdPLQaTYxbSfF2RppJc4E/oTNT05+hZj6iLfecy5RUaal0VpChgnflPls7F
         iYsDTpNomDNiiIASlx1l6yUfLWgrbyH6GAheQMD3Pe2pcyV1SkC6D6ykQaKE2F7YjgSq
         Gx8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SQQDfgjaGG1frMivgThzRIwS3VxSkwejy/9HCyHayOM=;
        fh=E2x+BTBUb9YHjP3qULhtkr4laAXH6LZSPZS85ToH7rg=;
        b=b7KzHmN41BoUwS9bv2iPad2uIOJyiyFXffKz0Uhzt7e5Sn0impJ3iDHEA5QSNA89kl
         44HrVdhrrhqe4Yz89CAlabUhuvBAuNJrQ8nuBTGBDurrVY+VbHrbbss/+r9hCZ+5KIfJ
         fSM+Hd433QjGIc7TTYsfDXS/dfaN/oVDeK2xuk5/jf21jNVP1s3JuiixME1iZ/KlD38q
         7hub7FwgaMPYGOJ80IGQ2q5lISZSOKxPKzvqXGpMa8Gun3S72Lj6NnSB9LeiJneZcyN/
         I5emOZdHhurMyqLhZtr9tFjPhwevQoORcz7dl9p1VZwzDGBnuwldSzE4radTn8f3m8kn
         Nreg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=c5DR5J3c;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969849; x=1719574649; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SQQDfgjaGG1frMivgThzRIwS3VxSkwejy/9HCyHayOM=;
        b=MFqnW1ukdvwPYh/4swhCNh6zXpgKf33/odoWttxrzFYDYNsWNgn3Gh4gGnZENbfgbL
         qkK23C5lAj55Ql1b910G5Zex9H8RK6KV8torConfybSZG9y03juxij/o5rLUQOZlSs9/
         3Seqp7YCxTXPqcIX1Pw9wpe4e93Ds7YGR/a2HGfXU7+kIe3B+b/pXuUWDQfc0QY50WY7
         epdnu+lg6uM4p1nN+1UVxqtSqOC1hoxwvmoopxPZ4gANWmtla/1IpY2Yud60W1Zf4/Pp
         uqwg9dbOQXB+6UaJOOE7UPZPVh+b5bwwzigRwsyTYrCJBRjaKbTf09E8hGdn+kLUFNpb
         8kuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969849; x=1719574649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SQQDfgjaGG1frMivgThzRIwS3VxSkwejy/9HCyHayOM=;
        b=mW/BLobgECSU2d0hAtea+DXsYNAd9Bl5lnp1ln087OIRkwGn7tUc4rx987BKOo0lAj
         m5VSxnRLILBo4Z/6vs/kGhuYltnm+utrv/dS1DPEapeYvx9Amk6+JTqcjrxno9k9SIeS
         A7VWxrgxEPAYDPovIgae1g4MxnBSO4K/Y4QxRpmeEnmJyaESYmRK/U3bQz5Y9NE0nDaj
         8gxT0HoevoJDvhW3+MKcV6PrWbk2G4yRKylqtyH4+XnJqS1AbK17abCigvmv1B1Enq/D
         4LPaleLbwDRnXy24a/SVE94nGLw1KKvDaUw8aAK3D2wuoqc4hh63XXWEIWEk+4QI9nbj
         0wfw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXS/qDdo4IYAamWZ3EvDTlQqtljcMZn4sYCnO+FsjLi5bcC17zXnxdbkycSBYVXjTDFTRdj3JmTFwPVa2jw+Tc7SdjTDPx2Q==
X-Gm-Message-State: AOJu0YxAqfT7PsplHBhudAuUWYu/Q93WXMk7dB4V4iCzKoFQiYWb4vfx
	si5YPuThyqPMWfahA1jz5Kx4OELZelb6w2nSgXdO68qdlnRX/b5E
X-Google-Smtp-Source: AGHT+IH3rr1Sl+ZTdfd7vJ3E7Lv4bC2Y91+DbJj0Eu+XyfiJmbSPE7SLQWVHsAcEfq7ruMrNkPR4EA==
X-Received: by 2002:a17:902:b185:b0:1f6:7815:2325 with SMTP id d9443c01a7336-1f9aa472626mr66494635ad.56.1718969849370;
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:414:d68b with SMTP id
 d9443c01a7336-1f9c50d05b4ls10372255ad.1.-pod-prod-06-us; Fri, 21 Jun 2024
 04:37:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXW5IZ9YV22+4xPll+A7U/diwx1hiROo0wkTXbbbzGLIQ55MPYdf55cF46vxeyV7/p04HxAZkwjzB+1c3biH/wymltGLhvC8ds2dg==
X-Received: by 2002:a17:902:c40f:b0:1f4:9b2a:b337 with SMTP id d9443c01a7336-1f9aa3bc6dbmr87724795ad.3.1718969848189;
        Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969848; cv=none;
        d=google.com; s=arc-20160816;
        b=NapIBWfJr3r18hGDcjpkAramU4BFSIKlZLoO1uzqzZHcQDBFNMbYhA3wJdB8K5xfXJ
         AJB4aiymq8XR7MgOu74PPrQymFtwfWUTYE1LiXU1Zl5lyXCks1eXgA6oUKmaihi9tExZ
         Fc7M2/3z1Y9vhAYbSQgCk95O/hkRHZQScDEXxt2ycm60bORf/NSYYifW417NLXOXrK1G
         Zmjm0JHxZJeP/PBF0ZzeGURLPlKCjpETTzMOukhyQU07uT7zzTKIKEttc4d/R8qH4dCA
         dFFHjCxPhlcmjBQwt9Q1ee1NtpuJC35lj/ST3GJUs66PfeLstJKt4fGwfMr7+Cg07eTt
         pvYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JyCixd63UT10LcLHBLxXvC3vYkg4ad8S/LeVZYMb+Kc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zB27szt2t61Ys8I9PUgdRPt+xRAL0rTjfd5Ba/uPkYxlFuu1XcPgfT7SHGTDExCKqT
         QgGa8dVa+VQUfAYbxtZXG6f9uYeIYpQSwpJsD0jPpkJ/p9CbfjC4kWyJZO+io5NsQY7+
         s5n4dlipG6/8HKBv4vi1QEQEpzhiG8hIoS3MwlbbttWYjbhPwX9B2WkxVnFe51GKAfvo
         hpHox4oHFaBFRX42GcBtC7K8e+BnfpxkxV8QAOcuaneDkqEIRxhb6HcIN19jXhAQc+0d
         sMqnIa76+TGrGLdxvWnYHvDHSgeSqJkE4sLqbNMf6QRq5lU6l1bgmk9TVE73ng+Z0o/V
         5pjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=c5DR5J3c;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb1ce573si472995ad.0.2024.06.21.04.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQuFV018507;
	Fri, 21 Jun 2024 11:37:23 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09bq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBXENT029185;
	Fri, 21 Jun 2024 11:37:22 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09bh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:22 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L97R4T025644;
	Fri, 21 Jun 2024 11:37:21 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv6vyr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:21 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbGwO30737090
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:18 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E510C20043;
	Fri, 21 Jun 2024 11:37:15 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4F37A20067;
	Fri, 21 Jun 2024 11:37:15 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:15 +0000 (GMT)
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
Subject: [PATCH v7 11/38] kmsan: Allow disabling KMSAN checks for the current task
Date: Fri, 21 Jun 2024 13:34:55 +0200
Message-ID: <20240621113706.315500-12-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: xBEEimwpCOprxAXVdAos-Qmu2NP5Qg31
X-Proofpoint-GUID: DJB-acoyJ914G_wwdJYFoZ67c-BSzTg1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 priorityscore=1501 adultscore=0 mlxlogscore=999 impostorscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=c5DR5J3c;       spf=pass (google.com:
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
index fe6c2212bdb1..14b5ea6d3a43 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -239,6 +239,22 @@ void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
  */
 void *kmsan_get_metadata(void *addr, bool is_origin);
 
+/**
+ * kmsan_enable_current(): Enable KMSAN for the current task.
+ *
+ * Each kmsan_enable_current() current call must be preceded by a
+ * kmsan_disable_current() call. These call pairs may be nested.
+ */
+void kmsan_enable_current(void);
+
+/**
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-12-iii%40linux.ibm.com.
