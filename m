Return-Path: <kasan-dev+bncBCM3H26GVIOBBR4R2OZQMGQEEU2V77Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FA02911749
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:49 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5badc34a45bsf1165392eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929608; cv=pass;
        d=google.com; s=arc-20160816;
        b=sEWPMWkXvLNDHYiPcTtx+3t2/D7z1YOi0+q4SQ0fn91uZd4yVT4vuvUehqWM/19Twa
         1oLi7qYYt7iJvWQRMYOUz4ib4s4wVca5oqNqNnZUEJ2tbvC57AhmpmdEx6WxLDAvDmYQ
         48QlpMy/udv7Cn610R1XNMXFVW+mhoU80PQ00r50vE0hztCfjaHAfaBhudqNpXN2TESl
         9TNUc63nrb/M8ULU/9MDWNz+MIAimMnyGJsOWz0+acRMODsi8HgyrEahl7+sWtvDjWYj
         OukKuNaj8nWM+v0pF29wsa2diSuSszjNkUX6pQC0AEWcoRbit9JmJxvjXRzMB7myfHlW
         Qh2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BVPXHi/inHuqlFYxUEd3VFEy1+fxCykSpsTwEDvo5BY=;
        fh=on+pxNsBvsCnHuXN2ei9YgtA8SwchOEEeiNNLpZgGcA=;
        b=Ah9gYho8pnNdou29VqiqKI5iVDGIm083ZLxGDyWwDW+pwFZB69znhEfhz1KEpOufWl
         fwXC4lV3Fta5XIgb6L2mFIYI2DuF1cyd15qr7rL8AqJTNP/V4x8Qsg10j3GDzkt4keaQ
         MQr3DcySSXhNlavFjs2PkK3ZbYgjUHr9aVzW4/z+JK/m+C0Sj0WEPEr3KPRgTcRRyoUH
         8x+r2crbe/15Xs0pMBEQGO0Lo2HkfaJyTXV4LM9EflHN9Xlfly3tKcsROapcWIHqwOEs
         iMsfRQno2iuQ7nrXkovB08KvhSmCuieXzAbTBLZBoxE85y1wyOt9AB0pkL5J2gi/N7K6
         4o0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MJukNpgb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929608; x=1719534408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BVPXHi/inHuqlFYxUEd3VFEy1+fxCykSpsTwEDvo5BY=;
        b=YXn54CJB0OP7Z+/xD0LGQ1TTutq1qJd12D9kwjjr3pxYgBTXlwIcFshmVrSFkIlDFl
         43f75hFLnY+dESmPNapp4TL38/dLsHahjlXDInxM3pu+5aZdbluRNLGE5LYbWwRMXf2T
         WcbTeAtLbUg0qGf1oHhJ1LwzKKFEBBDs17agySSfn23qFF5+Ei3g5a/oKsaKUAclK7vV
         OfN6qHXQC/xk0Gucp8iWGw78j7A+aU3BTgWIXtsjuk2d5P9gh+XqOBK34MDAZP+V1Q/g
         bHmsiRVQ5uAhmeX9mNe01D/gQC40wLGHs4AGFKfyqGatwtynaye9EZ0anpRVM1s2exG0
         yV+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929608; x=1719534408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BVPXHi/inHuqlFYxUEd3VFEy1+fxCykSpsTwEDvo5BY=;
        b=uITlCKp64/EMfgzyBdNMsSpq3mYsIz0KYBQ2nI0/CztSqtGPPw5C9QrlwhNe4/p9LB
         R5LRTXsPkQYkosn9BFKiNM160A7zNhJz0juzWPP5Fw4Udtzv3ZJ/kMXGepnUY82sZmoD
         HPHBBAtY5tqABsh8CKqA4zHg4BcAMmr4ZOg2yJa0CJKY8FzMvWWjpJ3GNsFATjmV4ngR
         NW1uDObW6YmDJcCDjCTGbfzUMnBy+tgptLjjfd6A/lGOovtGJLYb3FDrrRSOILvgztlh
         QqCwuR7KC1djsGiRU6K2kuQ5Za94MzH0jZVH4a4EGGcQ/RLzZQAO4A3gkwbKd6L/zQ5f
         6K0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXp/D/mxe+AkooxwRGOQxZPhPZQMXcDa+orzZoyi+qkNK7YFEjP1hDlY9pnRZA6cWLyl/nv5w+rP8vvkWvkfgMjwRGi+ZVDFA==
X-Gm-Message-State: AOJu0YyuWus5BOjCUKhnhdeNRJT5mhM95cfjVY9uD3i5lpxi3fItPmwW
	UmxRpV/RddrpoXxEtHhBQPF6Po9X+mg50OC+FsF2lChvW4x869yU
X-Google-Smtp-Source: AGHT+IHaT4ow6rfqf+MR6J0d25NfxQuDBv6+tGJiNDDYq0wxIPezZbIrbLnq3Dd3eSaE6ccUGmKUgA==
X-Received: by 2002:a4a:8449:0:b0:5c1:9e5a:ad9e with SMTP id 006d021491bc7-5c1ad89b668mr3143209eaf.0.1718929607781;
        Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8042:0:b0:5ba:6b54:d29d with SMTP id 006d021491bc7-5c1bff406ffls358395eaf.2.-pod-prod-00-us;
 Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1bM0BKuOgiImQyUVVSJP6u0+DN/B9bMQ2jjFSK3oNKj6IO0lGhRsjATpDKns6OEMOxQ+CphykI/+ZR7O5jQEcIjatL13NwkgDXQ==
X-Received: by 2002:a05:6808:1401:b0:3d2:3216:9125 with SMTP id 5614622812f47-3d50f11cdf2mr5080210b6e.19.1718929606871;
        Thu, 20 Jun 2024 17:26:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929606; cv=none;
        d=google.com; s=arc-20160816;
        b=TE7LeSOAGQ9x27FCr7OKVrrQhn2ocPlrDgYU4Bnr0ZQAn6kGZEExt76cck6ln2qsuf
         PCJwYj2RjA7iWFQSZVAHY84OxeIfodHMZIkmzflzrL4LcSVGgRSYHgiiV057Z32oumDO
         xehCZoZR2kl4Kwi8H967CvpLyQrW1XCqJUj3dr4tVzr/xWDhWQWic5X8MxYdWmofVYCe
         GK5zlm34ikdjIDJk1yPvEfcrKZ8tE4/J3wkmkdQ34zDd6bsLNO5J0zxH1s2AmSE/yVLx
         nMOyPOnlYgIZZD0U8c1DnonD1Ty70fAV+TXnSD/7f8XoerZeDxthDndsMFZ56YBKeQtn
         qTKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JyCixd63UT10LcLHBLxXvC3vYkg4ad8S/LeVZYMb+Kc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Qj333fY8BADrc/ZEJy6HttsOZjZOj0t60ESuGhagEkwUT7Rg56lPMF2CUgIFPlEQ9S
         7W5JGK8pefahz0XfyqyM53EotSNWmF6YP0uNPwv/xRhCsP1OLlDPwaK5MpLf8J4aWX4Y
         Zdvi/GYDGySsUJgB+z6D83tZXLl41JNx665HUa2TU/iCTs6okxLzHc+r7+XtCT7Dkitv
         83IohMlXsFRTwkTY9DDssVmqyjPjwtXd6BtZt6zarxlzLLGs9OyNYOLgZKKkTvvtFC1K
         65HVR7PYvFtq44W4Q/XRfvPacXpm6FkPT9/6STfeSRIXww5eUIIf7RGirxBmYkyOSQ4G
         ZG2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MJukNpgb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25cd4c0a1b2si21860fac.3.2024.06.20.17.26.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KN6ts3030154;
	Fri, 21 Jun 2024 00:26:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c070d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:41 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0Qepq022701;
	Fri, 21 Jun 2024 00:26:40 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c0707-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:40 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0PCOc019980;
	Fri, 21 Jun 2024 00:26:39 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqujnws-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:39 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QX1N16253262
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:35 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 74F5B2004D;
	Fri, 21 Jun 2024 00:26:33 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4673E20040;
	Fri, 21 Jun 2024 00:26:32 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:32 +0000 (GMT)
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
Subject: [PATCH v6 11/39] kmsan: Allow disabling KMSAN checks for the current task
Date: Fri, 21 Jun 2024 02:24:45 +0200
Message-ID: <20240621002616.40684-12-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: clVUn1IDbtacwO_0GWY7U5sOyrimaMLk
X-Proofpoint-GUID: X4_a9bjV2cmY5PTGlnJ8u_RDQjykc-B4
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 bulkscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 clxscore=1015 adultscore=0 malwarescore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=MJukNpgb;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-12-iii%40linux.ibm.com.
