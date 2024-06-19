Return-Path: <kasan-dev+bncBCM3H26GVIOBBL72ZOZQMGQE2QGLCVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id EDF1B90F2A3
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:52 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-70417103e68sf6214077b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811951; cv=pass;
        d=google.com; s=arc-20160816;
        b=dKmFpbWmb1AkLPOO3p/HtvwwUdLiscfQrsorsDdgvPgwhCUR7xxNKkqrSS2effvLz1
         sqiv4tAo7/FsnvJZ2m4QdgmPqa+S8lWJVg6pNv0urVz7nX9Vcx/OpgQSRGcnb8UFNvEb
         U3dia8wAR39cpI4iDTsDPuLDGsBgpeaA4GlJQ22p/7pxse5VFzVbXRQLZJVRS/Qd7wWM
         6x87nYnESVtJrNA3Vpvy5mn0tcXiuEAWjPVwT/aiSbt9uz7vLgAetiYaR0B3I+c8Qx5z
         a+qIRmzVyQnqr3l+eK7dex9i9ZrSCIoDz7O8JkHmB8p3xT/1IV2n1Ru/cT7k0f1phhZk
         fgpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rQ0sWIvtJTFR5/b0ehqEg212LfpU5nd0OVt2ZQtZJPA=;
        fh=NEHaM5WWSRk24JxnbzxYaI96h0Zw5D0ouCqSpUg3NLg=;
        b=W1lsURaTBoWWiwgJDNZPhQANA9gAe7Fe6Ue4ZtzICOwOFGkvtbj840To4n3MT9nM/e
         3u+l02/4tBvOj4wZ/zYWzOwqijnfitKHXNGjyPSb/Iyy4jJ8KjWlmHTc4LsWr+vG7mRh
         WyNw1hfXw8NbPCLB1TKibMqaIZjGVhvQ/AMtHp2hTor6NoxoWF05qmq76l1QXIlYGgJg
         5a8sk0VNZQdhDp2HZ/sleO6kVpfbzoPz8hK09BA7VxopwPc39EB6/zfcYJzr/nrmIDdi
         6AujaNT0cYNhDTMdrBlKPTQrWgn7ke4TcZEyuDfcQafDIk583C3dmzZwkxSYjG4UQ/XF
         cTQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="T9/QNStg";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811951; x=1719416751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rQ0sWIvtJTFR5/b0ehqEg212LfpU5nd0OVt2ZQtZJPA=;
        b=A7bclGG3kHP5jv5Z9jzuhofUjvB1FqgLp6l3oAEq2a3WDlQHUC+TSN5WZD0Z+vt/QB
         ZaCfgs+k5ng1JsKV7oTlc404Ms4v594gDZiNhGrpGlGJ5hjWr7wKdqQ1zfS4q/Tj2rOt
         CEV4QPIhgRk5f0r35FL6Tf96nA+SPwdQWE4h4P3ECFb4g8X2wB8Yau7DpJXbumcDwrjo
         PrfiN/12jpMOtAE8sISWrk7tf8NTSrSLoAlwkxmjFfrPXPagrKCcKGmcTFNuivBsTCB7
         0gM+GjtPeBRJycyJfPrGXBm4rocWT7crjKk2bFJ9agyhL8XghSrOMBkKLOmgXLJy5KUu
         ghaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811951; x=1719416751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rQ0sWIvtJTFR5/b0ehqEg212LfpU5nd0OVt2ZQtZJPA=;
        b=sDdle0y5ztdcGuDR8rbT7DIFTkZcR3zs0n+uwHyRb0QXwLs7B4Ihf90EVwr1mcnHV2
         Fb08PYzRyxMOjiuLbYKqCjlSw2Vd/sqyJwGCRdgVGhgL2sqhq5G/TUYwJ1VyJ0planUW
         Ug8HgQxS7PYLRSVMjZ3lASqIZ4kWr+Pzb8dBmpUi8pzEJnfVEy53OBw9SQnZsPb9woPh
         +tKHNyi0diy3IpONNCdFxdpJypO6TnPFmfm4ZfZw82c5RaEtON05Bdowb7TSyEcVqKFW
         qdQZg7SNVvfsyFOFMis1ahUH/a+N4OWHe7WsggdKvalIaAAUVuUaMz8NtgeMaHT95Lis
         Mtug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrAW+0llu0KkDEqxlfx9CJ9JZnkQN10dGjfrg8KuEoNxdNZ09rMP/XSHEsdHhR1YwmoB0H2fuscvwKKwYxxa3N3rmbiBm+Mw==
X-Gm-Message-State: AOJu0YzMTEItgHY26VmvWmZ2GPMxX27pUzuDjq7tWUXCPKwb8X8E/n01
	OowsYxMP5/8Gyxo0MM4E2chx75VtNkvAJI9glvBj7Mis+KQcOkwM
X-Google-Smtp-Source: AGHT+IEUAJQh7rKehKOIpoPFLLw4/+hWGeXLTKCz4q3pSjA2bxh2KrV5DWZ9MPjVqlL9RGX2V4MYjQ==
X-Received: by 2002:a62:e503:0:b0:704:6ea0:2bba with SMTP id d2e1a72fcca58-70629c1255cmr3148641b3a.4.1718811951381;
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:8d0:b0:702:5b8c:90d2 with SMTP id
 d2e1a72fcca58-705c91d0e94ls5316940b3a.0.-pod-prod-08-us; Wed, 19 Jun 2024
 08:45:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUV598QLDXfAXpJyuphQLycuxkwWIdQ0MZCtN6Z6oAeBuAS0G01TVOCTB9XSy44NOMRCjZsk4Z8MllKjB5m9YLRf5Z/tueXcWXp3Q==
X-Received: by 2002:a05:6a00:3b0e:b0:706:3329:5539 with SMTP id d2e1a72fcca58-70633296109mr1995633b3a.23.1718811948031;
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811948; cv=none;
        d=google.com; s=arc-20160816;
        b=FD32E9gTgR+D6nEKk9hL0oSbF20eGJROV7SMdxFG1xmMKv8tD1gCXE5q504Wl592Xo
         /X4161/9QGpwTF2tObqYpnQrH5j1llkAu4PlWk3C/A4EefnSD1NOUrnaTF+CVs3zuQEb
         2TIwcFILeCcFGPTDNoV2/RcuCM7c/1z8Gqqty1l7/wR4LKgFXfQvmnEU0HLWnDcd7YNB
         TfrN/MfYFmTXmvl2txdL019lLAa9uT2jsfN7+H8ddHhIbS3Uv7QtITTjxY/W6jCJJxsi
         SMTM65/8+VdryykVEve0l8gR43U1JwPgE6iyK7kjicDusonF/S/mhdNRcVmB4LyZyvCq
         aaXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YaTjcojmIIYPSV3AqgAoZ8tGeMyuD+KvoajbKIBgv5I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=lZf3zD979YAYtZVPUrRgbtr4Gnyl3kZlisxWQgiMDShzUocMc2E2ntbsNlJP8kAMlr
         NUw1rheJD+GGVAhDh3CTkOHHOfVJRqqs7KjyBJYu9hHPF7DV+jGQ4G5nNba9wWtjkE+L
         sj0Hu2jBVvFI+/g7wicFevF66Rrkt0HwPoNakCeL8cxSa7NechvDdOF2RwPv6JylAgoL
         me6XqBrJyON3hQw/7k8s7Rvii2/FnDIKYTtv4GWoz1QMc6O5Yjh2a7KQO9KYcT0e147d
         XIAFv5iPBRGGDljkXgqw18nkCbBEeRbfaJj4erJHCCEyQHXSTs4lo/qz+Dtma+KSJpKp
         NaJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="T9/QNStg";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7062bf98e05si104480b3a.0.2024.06.19.08.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFLaLh001491;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14ug77a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjhNK006742;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv14ug775-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEN1Zj009422;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmm6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFja4u53870878
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:38 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9FB982006C;
	Wed, 19 Jun 2024 15:45:36 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4EF012006A;
	Wed, 19 Jun 2024 15:45:36 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:36 +0000 (GMT)
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
Subject: [PATCH v5 08/37] kmsan: Remove an x86-specific #include from kmsan.h
Date: Wed, 19 Jun 2024 17:43:43 +0200
Message-ID: <20240619154530.163232-9-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 3EHcAU16HywOuVUpF9m86EEUX2NDcAqX
X-Proofpoint-ORIG-GUID: q8eP9SI0b7m5NXggC0ByeUb5R-fj8JuI
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 phishscore=0 impostorscore=0 mlxlogscore=999 suspectscore=0
 lowpriorityscore=0 malwarescore=0 mlxscore=0 clxscore=1015 adultscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="T9/QNStg";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
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

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

While at it, sort the headers alphabetically for the sake of
consistency with other KMSAN code.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index a14744205435..adf443bcffe8 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -10,14 +10,14 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
 #include <linux/irqflags.h>
+#include <linux/mm.h>
+#include <linux/nmi.h>
+#include <linux/pgtable.h>
+#include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-#include <linux/nmi.h>
-#include <linux/mm.h>
-#include <linux/printk.h>
 
 #define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
 #define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-9-iii%40linux.ibm.com.
