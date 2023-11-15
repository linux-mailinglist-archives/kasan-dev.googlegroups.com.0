Return-Path: <kasan-dev+bncBCM3H26GVIOBB4WW2SVAMGQENYCQUHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C68197ED232
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:59 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-280184b2741sf11840a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080498; cv=pass;
        d=google.com; s=arc-20160816;
        b=T5qiY0A18b8u62ZAGaw+ElY6lDp/YQlgl7o1y77QDWo90gx5FMmuJIqgEveeie0PgC
         wyb8zCc8QhreC2QxaCRmtmeoiRfsoiOsS1ZsZHRc1Qk85Zku3NI0NspcGmMbvGg9hqM6
         TzZGdAkl0BoQ6sdYpIht57H+BjCa6sWxMD5hscfYfydlxTEldU8aAALhn2o0R1L0yDXD
         5lJ+KfFOlwiz+8uWuqJm+JbDUAIbCr5N6nVe3fO0kuqKYmG4BjhcxCP8/DmhDBfozS0q
         5I3O+ubMU4aRClgSqMJPRSa5K2G3Jetzr8kEiinbxOIvPa0ucIVsu837IrQqDAsxfAjE
         RpOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1TbTe+weGnFoce6c9KIm1FnNpqTghR2WnpF+BWAasIw=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=BPmkEhaGnDnSU96u2wljYiOOfQb2tbXmJtYVA57JDVgiSmqW8zp/T+/zwDnTOQIzwS
         w6lkQQzfj/zdV7ShaWWmZDHORr48kZNkzDSWenK9xAHQJsnsxWm/svzYqcUyDIHf/5kT
         2TYnRaerasjSQPtnIcTtUBc7Mmh4hS4GZw20gzZPdGQpbF/E92dY+BbFie8INzXrboa3
         WD4ctg3lK8ZBrjDa/87O/bMl2jqTUQL+fQVdaOgqYyotBw1fAxeOEOdJ8W7Se6suvG2P
         sh4/GyyFrZB9FFRDzFCWgfyrtgR326gmFKGCEnYYaXyqIwn3XWPb2kh97RP5fadpQNgW
         o/9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=E5bEhLE1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080498; x=1700685298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1TbTe+weGnFoce6c9KIm1FnNpqTghR2WnpF+BWAasIw=;
        b=rJ9X5ZQWDynA20i1KV2XCKKay8CisPKLucgkD8M5EAO+eQNoLwRcmwDkkTnTJ8PjAk
         RIdFmrrPEZJqpHyGmm4Ba5vl3/qktg1J4INfosuDwvBUf71VgBtG8k3haWrW3KmK52y0
         zveczUSuwb3Ir4g38LkqmZwEELDWDVlVWGXZpkFDX5fBQEVedeMVIy97zkm+8StJhc/Q
         MN2ldrpjMJNuUs3XD4WhpxhIMDDkHoddsoyUVnSbwco/GYiLls8+456fNqdJGqN1WR8x
         18Y2zOyg7b/yXJPfQqv7yHtdW/EgpwcVvOFOmUvvdsM12271pX3QisKtoYXy7iqaHbEN
         XI3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080498; x=1700685298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1TbTe+weGnFoce6c9KIm1FnNpqTghR2WnpF+BWAasIw=;
        b=Bsg9agqZr3nFjUvDZ0O9+l8XtHC3c+BBeBRfsIag57rICxF2Gh1GVZA1Ozz9+ookMJ
         egPcM7KTKp5WCHK87BnQaFHnL4Yr99jkhRHm3QJ2WVrwtbHuLyd62CEeZBoNsiLenBKM
         b1T9AmmXMYTk1wkLMbZuKSY5iGzNzMAoBR5VlgtcuX+LCk9b5UlAiEGvoT8kRaTcbToL
         LPa/Quk/enRDq7zpVvB5Q8m3lK43vRZg2RFpQPx4msiEPDz9DPVQqSBkhEWHtqaLIezQ
         Q0sFMmGk8GXgP2o0uCZMBjj3JduiBfm5LWuCRqwDhvdcIs1oAs6b6NCIz7HCtIuOmnkX
         bbfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwNu8cWXvIXF06BLCZ1xNuoRJkEz/C8KnuQT8dQ5CHQq8UwFnN0
	0Yc9Ybtaz6mDnrAOtnt6jWQ=
X-Google-Smtp-Source: AGHT+IHqbN3Lo6Vah8OC04K/xHCydOaEOPnOCkmReIQKEErmDHvmPlJgBGukHNoXcSrDfahyJlRadA==
X-Received: by 2002:a17:90a:e7c7:b0:26d:17da:5e9f with SMTP id kb7-20020a17090ae7c700b0026d17da5e9fmr12102022pjb.1.1700080498377;
        Wed, 15 Nov 2023 12:34:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a0d:b0:280:8f13:2e91 with SMTP id
 w13-20020a17090a8a0d00b002808f132e91ls93410pjn.2.-pod-prod-02-us; Wed, 15 Nov
 2023 12:34:57 -0800 (PST)
X-Received: by 2002:a17:90b:1c8c:b0:280:cc2b:d5be with SMTP id oo12-20020a17090b1c8c00b00280cc2bd5bemr12820822pjb.15.1700080497372;
        Wed, 15 Nov 2023 12:34:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080497; cv=none;
        d=google.com; s=arc-20160816;
        b=tCWqNMY9tNS0Hg0fRCGWwDppnEmUZF39Xg9M6g6w9jJy7gsyb4oGFY0WImUvroTRf4
         dA24xTZ6cyOT/BreXJHTEGT8G3IEk8P86s5sJqqh94OuUOJmqwRar0C5qx+UUUxIq82H
         BTgiCmv5lo8aCcMlbTYuz2ed02zAhZ2W2Kwh95NcAOhxTcOwgxJr9L3+X9vxJOMGSZ+g
         /4BJImiYKASwNTdNWVqeDtz8ksMMAFgh86IDGjVEQOgIwYgCUUuyP7VvjAxB+lJloU37
         OHJ7B4uIPs5WztkKxt3qOiGcsPAQA+ZsX1myi1Ih+VaECGZwyaEc+9emhDkNwGP7dozT
         9mJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kfW8KavvUaBQqtKF5dduUkWqnOOlkspXX2HeV3sVIpc=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=FtiPPWv071xRU/XPnza8yiynmfHV8SfPr1yjwkzEUyvi40456xnYoYSAZd2uIlWgKZ
         JvJpeK0LKDoH7Clam26ZXIt0aKPOxSaVpToUTSGdFna0jQiZLMucQOyBgWM/fB26L3qT
         YaIWHYg5pimXHNmEo4RNSq5CowyThJW0QcBiopeWxJyoGslxlRsiMQQGECB1aJ3GcEpW
         EjSet8UvIvDaFWI0fwi+16z6j9720X4aFQ4jyzA9ZKVpYZYH3gG+Mn1Q90Zvoh90gcol
         BUIB/SHJGj0s57GhTAB7Wpwtqu5XADDAeahziiuh8CCBETYnUU3zQy9kPuny6gtJO65D
         3MKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=E5bEhLE1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id pj1-20020a17090b4f4100b0027947b933f3si148164pjb.1.2023.11.15.12.34.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:57 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKHxQH030223;
	Wed, 15 Nov 2023 20:34:53 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4w2rc4x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:52 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKJPjI001881;
	Wed, 15 Nov 2023 20:34:52 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4w2rc4j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:52 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ1Tk024874;
	Wed, 15 Nov 2023 20:34:51 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uapn1sj94-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:50 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYm6042074868
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:48 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 108EF2004B;
	Wed, 15 Nov 2023 20:34:48 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B4B8E20040;
	Wed, 15 Nov 2023 20:34:46 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:46 +0000 (GMT)
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
Subject: [PATCH 23/32] s390/checksum: Add a KMSAN check
Date: Wed, 15 Nov 2023 21:30:55 +0100
Message-ID: <20231115203401.2495875-24-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: K4Rwon4YSH9HOVwscBn7CFE6ESwPGPsU
X-Proofpoint-ORIG-GUID: J_mHkBdjQbZ597hhWyOrstqRqqNqOBMX
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 clxscore=1015 impostorscore=0 phishscore=0 malwarescore=0 adultscore=0
 lowpriorityscore=0 mlxscore=0 mlxlogscore=864 suspectscore=0 spamscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=E5bEhLE1;       spf=pass (google.com:
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

Add a KMSAN check to the CKSM inline assembly, similar to how it was
done for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/checksum.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/checksum.h b/arch/s390/include/asm/checksum.h
index 69837eec2ff5..55ba0ddd8eab 100644
--- a/arch/s390/include/asm/checksum.h
+++ b/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/kasan-checks.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 /*
@@ -35,6 +36,7 @@ static inline __wsum csum_partial(const void *buff, int len, __wsum sum)
 	};
 
 	kasan_check_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile(
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-24-iii%40linux.ibm.com.
