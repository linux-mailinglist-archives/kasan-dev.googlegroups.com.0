Return-Path: <kasan-dev+bncBCM3H26GVIOBBT5FVSZQMGQELGOXFEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 919839076ED
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:01 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1f84619fce8sf11050395ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293200; cv=pass;
        d=google.com; s=arc-20160816;
        b=E7StqQa2fOe1DFzrkcuCOd3zzSSPwoR5f71flPArINlvtwbA5CFXmXx3rL0Oqt9C1n
         RzZH9pCfmx8rvjLDX721qNNJyq0piaYtwsDjkJqAHC6c8By7U/xI9mlO33eryqQp2g3u
         ZI6AjP00Lw1tPLfbdzGfL4RL3pMw+Ooonp163QvnBH4lbYu9fbvCONrkah1Rp/ZgPNGK
         w6NYai2Uy6r67l+MI16UL1lj62zkrkdQIjDeE0oRhASBYhd6uzbafRgOjcWrYIIxpYrU
         8UKFuTIN/EptX2ZzmDqQxTm9dPmExzHEFDAdU9oMIsBPmnQWzfqxtjRmjUk5BZ8BNs4C
         TJ3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=auAPv6DY2WYYy6S5lk0VUj1LSkhZNMX1W61+gcP6DUY=;
        fh=l5ORmtXANclHNT1CHCcJnSB39o3fCyIOqAHXXxAGP6A=;
        b=gnS9ben0fpiUmO3C44kZ9ynXDAFEOh7UYkCgXtdueli+A8F0G++NPfTMEicWWuzw3F
         7bterv040LaUTkn4gMeAsnN2/rCtSNo5xPMT/VL2PI1w9gha+WkkolrMnSjgrZw1cSqi
         gaC7opkwQxTCfKwJzSZ7VjznZapskEYcdOssDTmJh33rkOIwpF0YITaVULNhaZkFFkl0
         Bq3n5MDjOA2Xc8dsFHLPzHYIDQ9a6cemTL/O5iATiM/ucDat+hjG/XCufXZ5GSS6dCCA
         V3u3JLLf3cuSpsxUBysBKMYV+zHr/qcyK0xmDf2RQYswsortDpua82MSdAMQW4LgDXas
         Zsmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OO19bEtV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293200; x=1718898000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=auAPv6DY2WYYy6S5lk0VUj1LSkhZNMX1W61+gcP6DUY=;
        b=EROtQvj8tCQ9s6ZzmEPd1bswiLYU9f2m4YZegv6rgqcBfjiMOAE/7XFnOToViXUh0h
         Lf/As6pl2IXBud0edIHis0nqx2G6Hp3Zj9Z7veRICrAZ9ZaH+ysUYbPvxJfNKlSCJ9pr
         kLBR+00Ud/9p9oQTazFp2ff7itQhTEtLENkJV0kbvrFKlcQdftvDP6iDXdWPJ3UL4cU+
         GkInZREmztVQlqLvpuIOFzdSOqmYeV+tuu4xQxCBbM3TtTheqmCRtF9alG7Wc+5VgHpa
         1Q48WdrDnyT7DVR3Vl6DuckbgCT4nETAfIbuof4Pq97f9MfvSdUhYwhi6mMQdZkh9VgP
         TGDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293200; x=1718898000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=auAPv6DY2WYYy6S5lk0VUj1LSkhZNMX1W61+gcP6DUY=;
        b=HHqBT6VMNXT0x4/l8RnP0znczWstXRUYKqRMU7HeELfsEmATgoOE0IuScVj0HiYA5f
         c6nY9j9rowVcEwcygtqrWXorn7O7KwCtXhR7HDmYKKJ5QpdbdOhyhRox8CqAiv1jDOI1
         4u/qKFvvrhlOi3zl3m14qJbKT+2R9SulgBg/yfI1KpVcxGqOU/rBzzaA6OOplSwDTsK4
         Rog/T0Mc7bgpHTLWmbE/TVR7mckukjCTxWOY0gEn1Mu9MQ8rIFTF3F+/l42/q6Vu9Lpq
         eHiLmLCF/VLlC3rES0NRTvH1FxPG+XHoYOd/Bu8UuYPNGemOG/lRfTUwqBH5L3lXupAj
         DfLg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZppy+vRFGl2Hgt2tI8kK4+ERNgAEwdZqXPzJnppGWpFHr9lnJxoOdgW8iqWxTrjvIslta+ifWHmx3bbHHG95J1wOBvXS5VQ==
X-Gm-Message-State: AOJu0YyTSTox1LPW5M3BtA9FuBiul9R3v4WHpc9LQkYtLfcp/HtUHG70
	17pvnx69vnwL+TqAoFyZhZaEl4ZjyAe+EW8trrBmvinCnKNzz9Oh
X-Google-Smtp-Source: AGHT+IGZc2mGpeYX9ebuRbyfdIMQ/ZurcugLOVGJU8jWvORaE9Q1yddzM+5qD2KItMUotcf8mBU2HA==
X-Received: by 2002:a17:902:ea07:b0:1f3:266b:ea23 with SMTP id d9443c01a7336-1f8625c1641mr474585ad.13.1718293199755;
        Thu, 13 Jun 2024 08:39:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e54c:b0:1f7:166c:6c61 with SMTP id
 d9443c01a7336-1f84d6429d7ls9243215ad.2.-pod-prod-04-us; Thu, 13 Jun 2024
 08:39:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/RWXFtE72yAl6nCV9jP3ES/zWdZBij5GqRQBQL0Wv/7nFMD12K7mCKxS3/xx8TDv8/lY9rw+hmRfsID2MYqVivDiMmutbEGVXhg==
X-Received: by 2002:a05:6a21:6daa:b0:1b8:4107:ce4f with SMTP id adf61e73a8af0-1bae840d963mr240322637.49.1718293198404;
        Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293198; cv=none;
        d=google.com; s=arc-20160816;
        b=QxS2C/RYo8mYSMoFL8Uxo0e0kubsFF0v4jeSEL4qhuwwv1WtVfG7KIBnC6yDXpV83B
         in1bNgOdH34AoBMDBq1U4viumRZ86tJ///BFgvRJAok8EwTRdL/OrXWUfqyM08bkYTCs
         o5NoL8GhCYYHT6xZ3F6C8UlNyOeY7mALzZIp2wXyK/A4t4WF8VT3i+Vt+fLT8p8RmbDx
         DiVbtOH1NUIWpa+9xAaqI4tgtNNQXk8S/X/vp1om8hkfeG2jqP4xlFCVFWo4QwEnly2h
         WrUgtgYkBnQ5maglhk8tq1BjTP0KysCzlboh/YNQZq7Tn6BceH57XQ1gOJU1qfMbiRvR
         5RSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WE3ASvt90HWWKhjLUTLn3R+jUtOfzIMMtdYDGL1//DQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=z63WtS+gGQiemAkT8R5XYSRd+pdaZhQJG9D44RvRCn2L4qIs9FUvR+GgEfzkBqtIBe
         vFTdkWPwabjDCj4RFbldD0Rt+C9LQtZFrsdK0kW6vcUCREk9AOvIbxYJnDBQTHUCNB0Y
         kiTsXVf+XLgJmjyBosQrNRRYeu3AjFp5MHwRZV7fRM/jQSL9PeBOk/dv6Lbh9E1HPzCE
         non06HtTGXa4YQBnWVKx1BqHth6aORdy8FWDI03hdL2YydaecYPdsoSzVTRohMhBfYxR
         39/xiwYtQmVewbi0vosywK+SPulcdkK3K3rk3EL0gXO7LNnSnekygfpOd/TScM8NeDVc
         ANWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OO19bEtV;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855e2c38esi555215ad.2.2024.06.13.08.39.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFb2rh029023;
	Thu, 13 Jun 2024 15:39:53 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr320r339-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:53 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdqjx002506;
	Thu, 13 Jun 2024 15:39:52 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr320r336-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:52 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DFQIkC020048;
	Thu, 13 Jun 2024 15:39:51 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn34nh0cs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:51 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdjs034407104
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:47 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8F1C12004F;
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1CB012004E;
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
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
Subject: [PATCH v4 23/35] s390/checksum: Add a KMSAN check
Date: Thu, 13 Jun 2024 17:34:25 +0200
Message-ID: <20240613153924.961511-24-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ulTkjm7pMVe1lJk0PKbDneTOx4OY0nhv
X-Proofpoint-ORIG-GUID: 9ji9F25my1L1xSdWHnNVFlCBm10zOxYa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 impostorscore=0
 mlxscore=0 adultscore=0 mlxlogscore=936 spamscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 clxscore=1015 lowpriorityscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=OO19bEtV;       spf=pass (google.com:
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

Add a KMSAN check to the CKSM inline assembly, similar to how it was
done for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/checksum.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/checksum.h b/arch/s390/include/asm/checksum.h
index b89159591ca0..46f5c9660616 100644
--- a/arch/s390/include/asm/checksum.h
+++ b/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/instrumented.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 static inline __wsum cksm(const void *buff, int len, __wsum sum)
@@ -23,6 +24,7 @@ static inline __wsum cksm(const void *buff, int len, __wsum sum)
 	};
 
 	instrument_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile("\n"
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-24-iii%40linux.ibm.com.
