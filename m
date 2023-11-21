Return-Path: <kasan-dev+bncBCM3H26GVIOBBI6U6SVAMGQEMG26I4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E8617F38E7
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:07:32 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-58ac3c313casf4794457eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:07:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604451; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUglAvZWurY3SXjMxd4Wg0VJtNxQffJ+XiIr6Bh9fVQMrOcfsNolbCYHMH4SXp9X8f
         h83eXpchulvTwNnJ31hXoWtR0w0hpWb+t5AWtHrwEl05Hy9RXVtKqH30AZIwnIT7PTf9
         zZAUC9W7dgtBsajz5WMeakeVws0zXdHrmOmBORGs5Te1fdoeLj9R7zzU5zvegHAbjQMQ
         lqHlKfMlM6etZcWxgvmS6pjis1JFwG6M04My77gJKmBhU+Bz9kwZ47ruQLd1oMJpTUMB
         0NQeju//wHhQnonDzKlwomI8cXC4hiOD/0EddqZCnzhZK3fsLwVKDz6O6XKCa9eD2KJh
         eA/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3rTBkHHXN7w6A2phdH+LqkU15NLZdDcUSzODcqfgP9E=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=SB12pxgJO4/lxBJfsCj5Gdq/nh1hhGt6auLTVBEor6U1vkCiL84jNvIJ6cAz31rQ1N
         NvbU7J6aNLiXzKqaPiA7i51/z78oZyFX2X7IS1CZ1B72zCYtvh3WQ0LK47Ga1QLTgxhE
         yCVrEqCr3rySiJv2NMG5K0+jHhYZYZjoZ90VBB/IMNhknOPxcPuQUkarBOvQIW8TauuJ
         qvb+HO4Cif4USoNxgOyp8lALxjFzZAI1qg3BUGSxZf/iEatDzc36XHd0UgcxAkqdv8uW
         vl1yn9N1QLCZi+z7LA9Au9tgxDVZaJCyVpbMghKuySWIvAMRs420OIs3RkvC/gKDrGMG
         W0Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hqOXpP1f;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604451; x=1701209251; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3rTBkHHXN7w6A2phdH+LqkU15NLZdDcUSzODcqfgP9E=;
        b=g38rBV+g796OG+F4CmxTXr7ML5hja6QrBz4EpU6Ygtv74KhnJZvscOn2pt3ku74p+X
         B9vQFVJ5xPSRFx3u03dvj9PKu6WSA+vCsceQdtAviJZqzz9Ohnna0JSmjeMV2MDlv4W7
         5W44SAxok4tfo56dZ5NRg+e0JPf4nnx4DzYSYH9mJmb2l+DbP04y9tadIV5iR2ZbfPZb
         U0t9Oef3YqYDtuswCjianJD8p584kRKov8ryGNKvHPySu/5jvM/a5Ay1ADvGgChmDsAv
         7SRlzouFlw9D85BB+Wv4gabNIXkMiGxIRzMh9Fs42zcCF9TN9bFmD9qFtGPG/tM4iH38
         FNgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604451; x=1701209251;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3rTBkHHXN7w6A2phdH+LqkU15NLZdDcUSzODcqfgP9E=;
        b=aTjJzKOtqukXE903YsBSwM3Upygmwt0CqRYYLARfikNDmfRexwfZNOcskJzsshK0mZ
         npLnS3CZuRbhW2ILW272yUBvXXM4Mg2QswARPF5r9ejMVWNtHsD5/Bjd6h+FgR5NJet/
         gJcfHMrQjrC7P2I0GkcQ79Fw1sPPU98zXmxCi/9n7KqGbxvdzNr8Pq6qJ0Yx9NdvT94d
         AYbGcdEDPdXlF3WjmnQkhj6Sv7Wa7Fp/Y+1528IEsigma8vuFJFFYQK/aWO+QpvgrANV
         qMuL3ZgRC0pie9Mm5xkCyhflK/V24gNYgLLnZ5WIJjplglT8UZNMmTXkPUzuBQE4ik3g
         P4Rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxC7PWc8nVKTgvBjhXP0FVUeAF/TohspiEsbyiSfsZFER7NuDDt
	5uQi1k7dint4uAfaTwpmW6Y=
X-Google-Smtp-Source: AGHT+IGv8FDp3T08GSFvijos1JIkwy8S+8rR/kbA6xdfpylK5mhqE1KDjJecUU3pm8NgzQtfookKew==
X-Received: by 2002:a05:6820:1ca0:b0:58a:211:acf8 with SMTP id ct32-20020a0568201ca000b0058a0211acf8mr841761oob.7.1700604451113;
        Tue, 21 Nov 2023 14:07:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5808:0:b0:587:ac60:9825 with SMTP id f8-20020a4a5808000000b00587ac609825ls450969oob.1.-pod-prod-04-us;
 Tue, 21 Nov 2023 14:07:30 -0800 (PST)
X-Received: by 2002:a05:6830:11d5:b0:6d6:4f84:b5cb with SMTP id v21-20020a05683011d500b006d64f84b5cbmr684922otq.38.1700604450512;
        Tue, 21 Nov 2023 14:07:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604450; cv=none;
        d=google.com; s=arc-20160816;
        b=XQgviTr3d4iS9V4ikvmzoLUm5rkwrxUjfCnnEZbtT1paVG4xCkfwiJ5ohXQLnndwLA
         AwOgwcy6ewFsUWt0wBkYsI2Vakfe+cGi526qFh9fwwac6wbNs1BPDpF7hwg+F5VqJdQ1
         vARBnL1ADrPuRkzCobvAbfl9PdUj5D1FnKjpDc9nDqNo4KOcNKpCryXi3r9O0uYhMprt
         2bK6WWguc+TUEBbSEV2xcb/9YbUgoLGaAXD3fLdxATdu0XLAYo4EipKjrhPILHrLFxnx
         NHS6bUKoSh61T2Hjr8lSmhasqwVlWWnNpVF3brm3rjp/oRSnhKnNeqHnL9g3+j9DJhBy
         Q6IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kILyw5cdgjGn5/bq6lT/7Km7hA/yuzYatpUTfjRHTeA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=JXdttBWtLXuczJL1hWmmgSWPDu+ejqtScR7BzampY3I5bOpYvRfQC6vDXYDj93Yt3d
         Qmq3IZD0jZg+8jjPEmR4ljSs6L8nRxpqlg42ELpKFtIoTOiGmjTI2q2B9jojUhWdE7n0
         QBnHxDcD7VZPobrpefLeQaLU+beKnMaBnNyhD5gTLCv9bJx76KewQHsYPgBVd3EnYGwV
         2D3mLqV8yS3CqYUgkmfN6YhwwLfs7DBDXmZy3EkBwBT0PzTMyoF+3cHApXv5CewwMRuk
         byFa79HR9GNu/kSLKS9MsIg+rUaFsWp6kejn7hQWXIHJWqUHJicXW0nZCUyyKKuDl8UT
         tBjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hqOXpP1f;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u13-20020a63470d000000b005c220d4fc0csi452510pga.2.2023.11.21.14.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:07:30 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLvAQh004984;
	Tue, 21 Nov 2023 22:07:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn8asq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:25 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM0867014409;
	Tue, 21 Nov 2023 22:07:25 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn8arn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:25 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnHT6007594;
	Tue, 21 Nov 2023 22:02:23 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf8knuq1w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:23 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2Kne18416300
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:20 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4DED620065;
	Tue, 21 Nov 2023 22:02:20 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D486F2005A;
	Tue, 21 Nov 2023 22:02:18 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:18 +0000 (GMT)
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
Subject: [PATCH v2 09/33] kmsan: Introduce kmsan_memmove_metadata()
Date: Tue, 21 Nov 2023 23:01:03 +0100
Message-ID: <20231121220155.1217090-10-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: YLZAtK1TpMNezhFcBC9jhFUedsl6RBkF
X-Proofpoint-ORIG-GUID: o6c7zDwWcv-L2Rb3-jDw-jClXErr2uGi
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 priorityscore=1501 suspectscore=0 adultscore=0 malwarescore=0
 impostorscore=0 mlxscore=0 bulkscore=0 phishscore=0 clxscore=1015
 spamscore=0 mlxlogscore=999 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=hqOXpP1f;       spf=pass (google.com:
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

It is useful to manually copy metadata in order to describe the effects
of memmove()-like logic in uninstrumented code or inline asm. Introduce
kmsan_memmove_metadata() for this purpose.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan-checks.h | 14 ++++++++++++++
 mm/kmsan/hooks.c             | 11 +++++++++++
 2 files changed, 25 insertions(+)

diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index c4cae333deec..5218973f0ad0 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -61,6 +61,17 @@ void kmsan_check_memory(const void *address, size_t size);
 void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 			size_t left);
 
+/**
+ * kmsan_memmove_metadata() - Copy kernel memory range metadata.
+ * @dst: start of the destination kernel memory range.
+ * @src: start of the source kernel memory range.
+ * @n:   size of the memory ranges.
+ *
+ * KMSAN will treat the destination range as if its contents were memmove()d
+ * from the source range.
+ */
+void kmsan_memmove_metadata(void *dst, const void *src, size_t n);
+
 #else
 
 static inline void kmsan_poison_memory(const void *address, size_t size,
@@ -77,6 +88,9 @@ static inline void kmsan_copy_to_user(void __user *to, const void *from,
 				      size_t to_copy, size_t left)
 {
 }
+static inline void kmsan_memmove_metadata(void *dst, const void *src, size_t n)
+{
+}
 
 #endif
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index eafc45f937eb..4d477a0a356c 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -286,6 +286,17 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 }
 EXPORT_SYMBOL(kmsan_copy_to_user);
 
+void kmsan_memmove_metadata(void *dst, const void *src, size_t n)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	kmsan_enter_runtime();
+	kmsan_internal_memmove_metadata(dst, (void *)src, n);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_memmove_metadata);
+
 /* Helper function to check an URB. */
 void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-10-iii%40linux.ibm.com.
