Return-Path: <kasan-dev+bncBCM3H26GVIOBBT5FVSZQMGQELGOXFEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D7669076EC
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:01 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1f70b2475e7sf9052625ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293200; cv=pass;
        d=google.com; s=arc-20160816;
        b=ns2pO4K5Q6NIjGzigadrlgqafUfO/pHt4pZi++1UV4JN4PQUI1gTtE/dKB+zlpxfDB
         FiW5XZlvlW5yVjhMAdUKDqoh1wTSiF1/YPSnX/UqBk4uVUDyr5t9gA/H07wj2WjEh6gO
         UKFLLaSqaMv/rI4Bm2FDw4rVWVxoYpj3rOwPEYqK9kbzFWhhCRRzcjSbLc86sHu+mCVe
         Pq17Fs1amFEAvx4p6uvgS4Of/awVUQAphDXiIxl3fMjeUCddu3DKLnNjMk8SJLzUZbmr
         cZx2xzejCBIhqrx1X9Ty+c1dUMouZHfnrpv6O77Krme+eudjYdsH/ug2DHBYTnSst5WC
         q/bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=D7YrXpigbl1ruZTN8L+tccPxmJOPaPhZyDxW8C8vbig=;
        fh=riPAA4Zq07+ke21Z/a9lOvVh1EZ3897JzJ+uenB7430=;
        b=0EivySc4E2SPnRLxEILRivpzfqwTZlduy49p77qRCq6XXWv5xt0FJ3MgeoHtmm4rcn
         2Cc13XvyX6ljagVDlD7NZlyh2I35bOoJVWsN703lKARXtFG59qkE6e7SXNJ0Z8qeG9uu
         0Sq8QlmfEt9rYyr91niVahxS2Lhvo3N6jlb6xx0f4xpw4xatu2nEwHd45PBsGhvXxqSv
         aiw35AEM5qEs5OMHZVa0hHxd4Ino8q+oMaH/Vtn11/B8xw6MTqZBL3XtTnC+7OwI3RXP
         WyMmTMJu92XjmC6vnq+e8/kmoCQeQJT4oejx5EEv/xisyxwk3QfJYHW8dRCY8HbubhUx
         wyZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RNt9Kpbt;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293200; x=1718898000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D7YrXpigbl1ruZTN8L+tccPxmJOPaPhZyDxW8C8vbig=;
        b=BbAEfkXmW7lAUzcepYynKUVK8q2RsdCm5/XDU8SULMhlpFfYFO5vn0yop+rbIHbO1B
         yykVJq8j92MAJPOxwhCnyN+vtuKeGKRQm/wNzQ+80v9oQHUh+kyQwrUFFhS1CmfcuIXe
         gZe0sUkT9XrKyrOSMfOrOWEoC2wCiSrICq2ecM7N0Qxc+YG/JfKdBrYWytAFABs8M6Hc
         xgojcIwwTPwq7PX8oyPev/ALTpbrjXLixXpm4uaDxABhurH9HsY8Jshw2Pk5xq7GrKTp
         aJpKOScf33lOXT0QQV5OGkJL+2JZu9VBWtE6PK4w4acwmjzsg/ddLNmqFDCq7vHPpA97
         0gPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293200; x=1718898000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D7YrXpigbl1ruZTN8L+tccPxmJOPaPhZyDxW8C8vbig=;
        b=R4d25oklMBqQNa/zHfO8R2EW8DL8AjF1/ULL053zBm1s4ZIY7NeVt6OflyETDnUQOP
         +vw3M//aozhan84QLHePmkZuOS3QmhZNXy4YnA9/vDUvMVZOzLriyu2IoZTRU345ebNv
         TAJT9r4K1dIMkK9BzjYudGecMza3prPJyWymJUj6Wn4HnQqZMOmYCc9Qg0p13zqG6Nf/
         9eklrvkvBNe4Z8qRtp6mmcqlIk/4cEH5Y2qFgNNDmj6MOXLe8W8j0m7LKGvgRl31VlUt
         7f4L7i5UHm7/nSLpFYx9OUZ7yHM667a7Q22x6ogi6/RHbvYWgBLSOu8KVtlZ9Wda9Pld
         aGNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqlDOwaQaRfJZPmTzMbD3BVUgeznE7zJWuECp4sTr/oD91T9lve8wrx+Mub2gkn7PLyVaBfvjugIkgI1yLHl5pYHIZu5PqGA==
X-Gm-Message-State: AOJu0YwVAdCUU6vjQschlMRxrBSbmBGhOVqymITAQ7mUnMq9LxKPa8SF
	ZagJP8rh3Nj7Vb37ZpyWIYrfaAiV1LdvzTvoSQRsEcUEhk7kV8wf
X-Google-Smtp-Source: AGHT+IGGk6KhwEro1anQaL5tcUvEs3lERZ51qjfonR4DR2vYl4HCps+hYMpvUKunhpyVubkdqpQmOQ==
X-Received: by 2002:a17:902:c40d:b0:1f6:f05:3189 with SMTP id d9443c01a7336-1f8627d0c17mr254585ad.40.1718293199811;
        Thu, 13 Jun 2024 08:39:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:22c2:b0:1f6:faee:c7e4 with SMTP id
 d9443c01a7336-1f84d3dbc24ls8778515ad.0.-pod-prod-04-us; Thu, 13 Jun 2024
 08:39:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4Cww7C7m9ppw0p49L14CoUfWdtBepIYtWTzM3wx8dArPYcgSm7KE4+5bKfb4R9rPVf3LTOVy59kDR6wgfRMMx4XaUuKJiDLf5Dw==
X-Received: by 2002:a05:6a21:3991:b0:1b8:92f4:ebb4 with SMTP id adf61e73a8af0-1bae8451b3amr151013637.62.1718293197763;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293197; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJV8GM9cms2o6NqBd2SKxRANF5JaYrlajK16q6w+DPhe5Lg7+nWGwmm4oxN2Bug8wb
         8cZ7X8+BGQyGQURUuwstxUtqBnPtp83EVfPue1Ywz/V6tWOdquGvjgCScCrcf+a/5zP3
         //SLEHeKbfIiXVDaqDiZPiV5d3jUFwBcemusTFr+CKJh6RsFSdLwPyl85gRyIPFuUm5N
         htXhi0AydGDZCy9q61WrbVhA368/8d57/4eCZ4UbC9ofOoFQ+0Bn7+Z4e6qMMjHPDwGs
         VhLkD/g54O0IZundIONuL68xA3ztFmdkJ9BlTp0dWZ/1UBAO51U6j0O1pK7iUepMSYvs
         jA2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tPY2/xfj0WoITwfgq4isE+nahUee+x7RgpdrRutXdLc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=yhcBTz9zRg+XW57qvpMDVCD3VyoWpRi5SdMJREWT0iwsPIYIWKLRIIl1mIel5xxTZR
         fo84r/pmXYx7muLItORp3peYfbBPUluVfDjziHjp09JccQBie+PXMWBxFSfC0t4n1b7q
         2nMyBfSZw2ww6man5Y7wAR9iQSmqgCVcAVOyAWIQKIfxPjAKldLPxLu0RPcsKZcTIyZc
         2p5QxgHpogXl6+aIlJ6Wq+jZLL/LBULzczGFVBP/pIHmsS5kmQfn/j6FKodujJC43dFc
         NtxsR6oYNMNYc41EdTXzsFBqtiFtXsmiCeUrqT5SRjV+5XTt2sVGmvnPn29iKF4gUkri
         1C1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=RNt9Kpbt;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4c9228c35si73576a91.0.2024.06.13.08.39.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFQWrG031303;
	Thu, 13 Jun 2024 15:39:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw7hv3h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:54 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdrZX022239;
	Thu, 13 Jun 2024 15:39:53 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw7hv3d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:53 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF9UK0004368;
	Thu, 13 Jun 2024 15:39:52 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn2mq917v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:52 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdkST44368360
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:48 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A5DC12004D;
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3367320043;
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
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
Subject: [PATCH v4 25/35] s390/cpumf: Unpoison STCCTM output buffer
Date: Thu, 13 Jun 2024 17:34:27 +0200
Message-ID: <20240613153924.961511-26-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: hp04Eoi4U7PgytUYtQKm5O50m1EiIDWu
X-Proofpoint-GUID: aOZfXgWJlu59bLyx5qDPGv483tF6W8_R
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=957
 malwarescore=0 spamscore=0 adultscore=0 bulkscore=0 mlxscore=0
 phishscore=0 clxscore=1015 priorityscore=1501 lowpriorityscore=0
 impostorscore=0 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=RNt9Kpbt;       spf=pass (google.com:
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

stcctm() uses the "Q" constraint for dest, therefore KMSAN does not
understand that it fills multiple doublewords pointed to by dest, not
just one. This results in false positives.

Unpoison the whole dest manually with kmsan_unpoison_memory().

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpu_mf.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/s390/include/asm/cpu_mf.h b/arch/s390/include/asm/cpu_mf.h
index a0de5b9b02ea..9e4bbc3e53f8 100644
--- a/arch/s390/include/asm/cpu_mf.h
+++ b/arch/s390/include/asm/cpu_mf.h
@@ -10,6 +10,7 @@
 #define _ASM_S390_CPU_MF_H
 
 #include <linux/errno.h>
+#include <linux/kmsan-checks.h>
 #include <asm/asm-extable.h>
 #include <asm/facility.h>
 
@@ -239,6 +240,11 @@ static __always_inline int stcctm(enum stcctm_ctr_set set, u64 range, u64 *dest)
 		: "=d" (cc)
 		: "Q" (*dest), "d" (range), "i" (set)
 		: "cc", "memory");
+	/*
+	 * If cc == 2, less than RANGE counters are stored, but it's not easy
+	 * to tell how many. Always unpoison the whole range for simplicity.
+	 */
+	kmsan_unpoison_memory(dest, range * sizeof(u64));
 	return cc;
 }
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-26-iii%40linux.ibm.com.
