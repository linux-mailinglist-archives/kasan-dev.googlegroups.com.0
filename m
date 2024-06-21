Return-Path: <kasan-dev+bncBCM3H26GVIOBB6WL2WZQMGQELO7L2MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 576C49123D1
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:31 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-37597adfab4sf18071265ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969850; cv=pass;
        d=google.com; s=arc-20160816;
        b=CoIaXuI+yU1tky3tRu0tWxq4tPrWCVpExLE4/kBzbkt0lTqW5ww6y6C3TyLc93FU8E
         /jau8lqUrmzwo6kupJVTksVdUDX8Ypv39Y+XmQ1OvnaFCRQZAgXkDwl6g18bFVw/F5yU
         dZLW0T393XXivPU4kXzEBOaAN1O6VBY+6oVzLFp7ySjqJINnmENFfMWDM2WPc5e89D70
         uRSUghYaXZccspM+J97CSo/TMPX2rbOlCVqDDSuAB6oeV9ExppvZ/h5+0wbXhkdHixWo
         DGmNC7XNPGu7edXG90Ry7G36o7SD5AzE+FU9z+2ZsPTkckUZ9wkeUD2ucK1p3fphR+0w
         WgjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VWJT16/cAjyF6Rz4zKB6MzkMQ6t++JYhwe5cALgFCpc=;
        fh=9XIDFefjDbdoZDRGhY8HeJz/J48MnZLSF4bDZ8/FSVw=;
        b=xzdIr7NWK+w3l2p3woD6t0ga9Vc0WP+ThQR/gaJ/B700yN1KrHLqD5zV2VMymBBXPA
         U/QU6NfqJz0ax8oSFNCzQU6rsVhbYz1gvy4+0aBVox8ZXP/EZO19KWJ40KjbVn/TyAml
         oNX9dF9YNkH5XtmYxn051HoprkeuyFcn59nLrRjdOMeSg9IG41onr/ULpzjyuePzAzO6
         hitpWitWbH0GgnbcyIUqXMGp/gMpo8p7eh5orn6ySGChRHh+XMPcRH+ybHJKKKJNVMQh
         J0VV973NdH9vFwaqruZM2YWuZjCX8YZfOnk6GjKhXaj+43KWsyFh8BYC9tR5KZICIQJR
         Ef3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fbsMil0j;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969850; x=1719574650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VWJT16/cAjyF6Rz4zKB6MzkMQ6t++JYhwe5cALgFCpc=;
        b=v/qwP7OmfeCQxlZxbq7W2RZqEBUhmPdqJTeB5HzIho0HkUVsp/+P3mBuyyrsg0nj5j
         zr5Yg1tK3Whsp2HBECJV4bR1h+8setsO3EmvK/0I7IfBj7x59aB8Z+ilAT5LIUMZU2CX
         zasORf27+MLCduXDvjlIkvU4tc32EPlZcW//dHN/Qh9LQqkFrfMBUFHzUTkEtZtLIFy8
         +PTK7FH1RJpQcNzrfkU0tK1N7fcqBnFAmjykTjIeGYlLrQDNrQk912aqNR9mo1251PZF
         2UIEBaSjFoqFndT1IJZtMSpf90U4SZNcBO11PcXadXm2gz4+lqSOI59uHizXczQw8Qji
         kaUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969850; x=1719574650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VWJT16/cAjyF6Rz4zKB6MzkMQ6t++JYhwe5cALgFCpc=;
        b=OZu6onn1eW84WF/XI+ApBy5eu4DM4H8IE3191HTZ+vKBERAKXb1o9VJs7ezgtFxDiG
         GU71Ao9EEqrl0UIFj5N41/f5mvka2Ge8+7smX6tsW2Mp7L2GV1VjJvArDbdIGN5m7ucu
         Q8XAu2bLar5ATAcgetU6LIh3wotHh5vmkmRx3azWxE4fsYq7vMsZ7W3kAh3KMbfAJnLR
         r9qwUD1Rf3jDJrWhQzGk9eT5fD2yhVbqRNwNJarRNPB8ilCZNxHqls3LuinD/v/oHkD7
         Gx4awpDf8lNeLNp8DwiN+P4TQCtcw1LNbZX3Ayoy7KdPRBV4yMg3vC9hjFbnT3KlMiuE
         KhtQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVk664WEJ+Shv79BfgnB19vG1NkISPpuvRbzF+an2g7M8Dab9CfXjnCljMMzGQ4UnEqWNYk2aPfHvamesr1BSe1fGyOJS6jxQ==
X-Gm-Message-State: AOJu0YxHVwJn0XjfFE1OuCC90Pu6u1mi7GscLBvJH0sPgdO/J3KxL5ai
	OVQpTQBtMhFwAVEVtspncZbp+BvtsJteEd+vKp72KjYqILkJL1Fk
X-Google-Smtp-Source: AGHT+IFm3qF0aha5Z/k7Q1WTZJaKbjb2uI7WUDtM6d/h2Pwl5mBiudn8uBKtgLZ9wdH+w3L1Wqn+9g==
X-Received: by 2002:a05:6e02:1c0c:b0:375:aaaf:e88f with SMTP id e9e14a558f8ab-3761d7518bfmr83111425ab.27.1718969850135;
        Fri, 21 Jun 2024 04:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a24:b0:375:c5d4:a300 with SMTP id
 e9e14a558f8ab-3762693bdd5ls14029465ab.0.-pod-prod-08-us; Fri, 21 Jun 2024
 04:37:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXh13Aaj3BKLZOHKW+pOIgl9bsQfgIOaTmUzcxS4VxmZ0Znk9DzsKQoc1ujaN8mEDPbQUhQjoEbQRsYft78uE6tWl+lctlOcL9P8Q==
X-Received: by 2002:a05:6602:168b:b0:7eb:f3c8:c59b with SMTP id ca18e2360f4ac-7f13edaf9b9mr1018035939f.2.1718969849351;
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969849; cv=none;
        d=google.com; s=arc-20160816;
        b=VdUx8rDxlnG5d3R5WDBQzsOj1JuFIZe75WTEA2U+i9Vuqmb84i5bsc2OwR4OE0q+zh
         Cs7Ss8TUBpN4G6SRtB0o62GjCaruZk1TZ/GFou3/iDDpn5HZYH7LHjHJSoFaRUeCuvnu
         yRqUmAvhtzstFxePX2cNJe7igJ8kaaaVli/hKDLkZK/FjcLql1rqfWxXRXRdU4/2tFlB
         G7PoW9oSqvv4dCuX/PmIBJ96QhXZmkqucO4+KgimZEgMEFbB053k0oXzShpoR5uJG0fN
         7osD/Ku6gfHofWYmK1FOlocH26s3RDZDKPXxw+BycC7QoEeGW/1ykZL0qvwHJDf9+msc
         vtKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lus2RQSPSM7ilXLn7l1YCQD25SLYNKHC3cJu5hwIwnE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=VDaGMGpMyac069tz3TxAAsjzcFfP+PNyg/++CVcDCWUOKrXbGq25IKLfCD7Icv7zAL
         s/LdCdvfsTE5uC3jYBlLkYlr9OMr+EMYMd5k8ZnK8klAk1OKraKe2YN/o/m3YzGaHyVl
         /HRJSm7NIMDft9cieIaza/ExvOAMlvKQfGgJz6qMt2MtN5vfxcWcMB73LCuOsmMFCkeh
         dCDTAMSCEhi5zvzY7I4+wYwns0wfjJ96TiR02hMw3n1Kc5OPWAro0ejVGr7/9t0hXTpR
         CaOXsF73ME132w0wlsPSumYpYJhD/f/0RSQ6wA1L1yovJtn0m/dtAzHD74KVHDdefAkA
         Cpdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fbsMil0j;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9d113c930si47186173.1.2024.06.21.04.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L8gL1Y029535;
	Fri, 21 Jun 2024 11:37:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrgus-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbPNI011172;
	Fri, 21 Jun 2024 11:37:25 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5ksrgun-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9ITHD019974;
	Fri, 21 Jun 2024 11:37:24 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupvyy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:24 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbJ4g48693522
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:21 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EC6292004F;
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 63F6A2004E;
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
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
Subject: [PATCH v7 16/38] kmsan: Expose KMSAN_WARN_ON()
Date: Fri, 21 Jun 2024 13:35:00 +0200
Message-ID: <20240621113706.315500-17-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: KG3-KuwzimdCy9fz-zfFvPuK-LKymJ_g
X-Proofpoint-GUID: 72jJRBL-nnrHizPPhKPV3cqq5Hp9wCZ2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 malwarescore=0
 bulkscore=0 adultscore=0 mlxlogscore=999 priorityscore=1501 spamscore=0
 clxscore=1015 mlxscore=0 impostorscore=0 lowpriorityscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fbsMil0j;       spf=pass (google.com:
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

Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-17-iii%40linux.ibm.com.
