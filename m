Return-Path: <kasan-dev+bncBCM3H26GVIOBB5WL2WZQMGQEIEXNEWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CDA29123CB
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:28 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7041c30be29sf1784523b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969847; cv=pass;
        d=google.com; s=arc-20160816;
        b=M0h43amyN6Cj+orjjWt5yXpspVNeBIuBKoSFe2aUYRdFTuztrm7WHWDdTWRqWTmCgl
         T4Wx3etfBse9Y3LiW0fAKmMV8rQV/zBTjnzO7r+v94aC856dlS+GAoB3KM7rUyhC9yye
         xsrH2a9Hkh4ZoFMxG9dKod0vv3oA7ZERxLRkuk92FXtr9pDa9n4yQkMNtZE6nXzWfXDf
         TjefDy3Mzc9j3s3AYX/jgmtTQrSfN7H9HuqeWUmzV5DUiEtuIFvISb9XqbNtD6j3QQKm
         ifvWzgGbdzdOQ+RBzXTGHuNaMOFote9Av0H2q5Gd8DgeuNgfN9ZTswdBfY35rWKw1Bf2
         VCTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/J8XyDDvTpP4z1OorfhSYY5ND85vBMuMF7ef3Hh62do=;
        fh=qs7joqzH7EuOD01P5HRE1SFba1SDp17Ijy+j1KmT8TQ=;
        b=IxqQEN8q1jp5blp4qnjGsQY6wqYjn2K1Mr4wFDKPTNHgQz8QdvR6HZ/7bZLbLBb7Xl
         teB16OJg1zVDh2gm4P3mKqOoBt7CAup6Ag8NMHH3g2wCuIDyv4tPfjyqqV9tPRoL3y6t
         YoESXtaa4LaIg+UWwowxRc99kFoEQ1Wvq9IwhF7LJJdKoWsP610OzcuXleYEYecYZTI3
         AzjwOfFFFJFeJFxlpSDT4C9QHn9kaZMbgEGtnv8p4X45woOBvw4Dm0ZuIpDlT5OvTWzV
         E11jAzClMKdkpqEUCkvW5X7tKsk+DxyZvcYIDI0CNzG4ScOffq9NT0rut05l55ZVuM3Y
         1Llw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IS4ZtVj1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969847; x=1719574647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/J8XyDDvTpP4z1OorfhSYY5ND85vBMuMF7ef3Hh62do=;
        b=JYgYyudKC4D/kWdinlxlkF4sYpVBkaOL7+6C68shFKgo2m06ECFAGZDk/9x05rJ9yh
         DUALVWYFUWJ2yFITxssGMs3KvZrCXF+UyeSrB9+Frml7PmvMDmkIfMAMbeoNyRaq1Do8
         FRvXom8ZqLh0Pt5MGlcCB6ZEFVehgTCcdKMbkiNG6w/C0fZPzjAedyQJlh0Pw1TyTgUW
         mTXhyb5kWdskUoXt/ipJOqhy1mu8aya13H7XWUZtJvWXIXc/4sG7NC1S3o3fvF8EvJoG
         FXngDIjw3b+9+NJkh9liR4Ex1OXyi9DriTCGJa2RbgeYDPsFmeKdbf9GDpG0M1DGBHw+
         eLBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969847; x=1719574647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/J8XyDDvTpP4z1OorfhSYY5ND85vBMuMF7ef3Hh62do=;
        b=iw3tgE4dcyr7u/SQv4HedT4WWu48Q8w450Q00b858zxJVCZByWHbLaX0LFqdkX8gF/
         TrztY7VXCGtSZ6ZepentUe0qZEW2FwAqtiPLfBH9Rt86iAIBU8J8T6VQlKIF2seFHeTk
         XXX4pgkAHxBffrws2H1BIjZJwkdoeT2DsSSFgBntARzm/8gRwBnv5O3u/Mor2NhwwBjx
         6dK4TU1XypQYIO3xfXrQuTknbwUyw4uvrYQFe6BgLJmnyrI1Yuyh37z8JOnW4nWjEy21
         DkY0QQ4m9hy/SR2UFIncc1ecpMJ98cmWYjHrL/6W1MRwJ036CeCH3bTXdk9YaBJ/fSSg
         jkOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZ8wcZgwVPC/cLAfO0d0VydQLR1az1PplPH/2plAWK3gXTinfV4PVK0oa7kU6/gwDz52Ub+lAc1mzancgXFzWKOmUTqtahQQ==
X-Gm-Message-State: AOJu0YxfqXrzKVxqxJ8/4YmUrmuZwy1uZ3xMzjB9SeBSxSSfmM5aQpXh
	dpoavd+AgE78SpeOHhu8lhC4mXWJPtgM4/cxMyIxiJiT9EsoxNZX
X-Google-Smtp-Source: AGHT+IE7okpowiBts4aSYLJvOeeSU4tLCrdAbPf5xfu7ABHAKUZZsccA9FrtkLo1J2suIA7sBDFU3w==
X-Received: by 2002:a05:6a21:3389:b0:1b5:44eb:2eda with SMTP id adf61e73a8af0-1bcbb386a8cmr9954445637.5.1718969846883;
        Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f3:16fa:bc77 with SMTP id
 d9443c01a7336-1f9c50e8b29ls15130345ad.1.-pod-prod-07-us; Fri, 21 Jun 2024
 04:37:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV37SK+NKi6FeHW9LnkkdeWH9OcZ/1hfse2umvPo5z+ooXiMZp/urtKW+u1cKWje0kBsJhs1ZVjTDPHiY8/VuBrdIp6ann9EAwr3A==
X-Received: by 2002:a17:902:d508:b0:1f9:d1f7:3fe5 with SMTP id d9443c01a7336-1f9d1f76f10mr43559455ad.34.1718969845776;
        Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969845; cv=none;
        d=google.com; s=arc-20160816;
        b=maDHiQyvGVAs5vsZ4KAmBsU5spSKDJ8uiLHHq/2gyYfj5HmqlypTQmsS/+Oozq1IQ9
         fFp18PZRBHVCrmmexp/qX3Pm+4Idygj68UOtjuFjVXHMttZn8Ccl8kqvqJH940dZuOYP
         p3LEki2vbxdkvgtx2VDZwVJTBvqDpaRtomAva8idJyvP/i6cgXRZMx0FhafiC15doIEf
         IPJxplaQT04EYmkYuYxrcwaxEgaCK0dirsLUgM/j4BPCTAGpn28PndgckPjeowZDSHP9
         Lm+6IeqIxJwHk0SKVRvxxC4L2gmtVhxZhBuN5Sn0uLPWquyWzxK1P3c5YB+2U2pHpKpa
         j3KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=B2wiMcD3tdJRzJi1KnXmn1aGmTaVwcFVLNTdCb0XDUM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=WTxeI8eRpZ390Ljy8qYL2mho5n4IJtYV8gkDe4GOAK5rUxWWykIVuC/JHRErKHSfKl
         FaNy5KaHYn3zfp+nHZIqRIjaklAxplVYhruhSiF9fh11awvm1BTGAjLOdbmsewwbBvrB
         NdxgCK862kyO6HcDHJmHWVxf6qoKbGluB89Y65/POT2eI0eGqwWGNxE1yYkAQfrxArt2
         vLBBQrdQIv9lNt4BeJHuEXbXakkfIpRVBceRjyjvl0sJSxrgnt+dJVNgZIqjNKeMiuzK
         J8VZIuV9pBvvONySq8rMqvZF251y9FLivlgW1A/1cT7uCgYKezKLxE0cs+Y6ukDHvmRp
         AGSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IS4ZtVj1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb3c4d12si476205ad.11.2024.06.21.04.37.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBT2fX021960;
	Fri, 21 Jun 2024 11:37:20 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09bd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBaJmL000419;
	Fri, 21 Jun 2024 11:37:19 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09b6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:19 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9EjD0019980;
	Fri, 21 Jun 2024 11:37:18 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupvym-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:17 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbC4S45613482
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:14 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2A8B62004B;
	Fri, 21 Jun 2024 11:37:12 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 92E262005A;
	Fri, 21 Jun 2024 11:37:11 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:11 +0000 (GMT)
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
Subject: [PATCH v7 05/38] kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Fri, 21 Jun 2024 13:34:49 +0200
Message-ID: <20240621113706.315500-6-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: _QxgKIXm-H474SZgRMjPUkGWFJ3XjBZb
X-Proofpoint-GUID: yGqjU0FWgkV47EzU5yDvoLI2eE9WBVok
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 priorityscore=1501 adultscore=0 mlxlogscore=952 impostorscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IS4ZtVj1;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Skip the comparison when this is the case.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 470b0b4afcc4..8a1bbbc723ab 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-6-iii%40linux.ibm.com.
