Return-Path: <kasan-dev+bncBCM3H26GVIOBBL72ZOZQMGQE2QGLCVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id C5BC990F2A1
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:52 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-44054f0bc43sf77830091cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811951; cv=pass;
        d=google.com; s=arc-20160816;
        b=QHrbeAgxQano7L+0J44W7xx45cNZaWl1J4qLp7rWtgNzNp+/+Uvj+8o6d26KiIQ599
         WMrckUkGWJ7waI9h98GeRIMZDSrVGPxElSrXCvBM0oMnvTlWHNJ9gxrGX/FrVGkLG6yn
         tWS3HahzeEP9qourwnwxs/eoyPcB+lFcQKnZaJKW6rfl4RKztrZfAHrxPsztoYTYlLGs
         rvLUMfTNG/Py3uVmNPTRKw8JHhsoq4fl/5FuALiQExnIhy5wI3kkox9JKx7qEI/ex4id
         cAAjzAt/Km4jd1Xbo/ObDxdGjtH5OMyrjfcH2POe9vWzWUqQ0aofoC2rOrh7oblSdfIj
         sHag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8aheUQyQf4MR1EwsX54X+0liwnViRruVbBqUh4s1NME=;
        fh=Mapdc1c1FS/znITpbJaUIjgoO08i2nPBwypuCOf3RZc=;
        b=NiYM42AE66cvSLxV4A1Qm5rtjaJ0UXilGjvrHlXpmuLcqE1NXt9ZZSMaMNpgg71m5V
         xMzs4KT1qUwg5ATrf7zMSVuflnw1UuDf1XRAiS35gm+cx5CNqggZyxy8+Qmj+Hb8Iiy9
         O5dTn5i793eoPkqHTZDaJUJ9idHYB9CZz6+iCFoc71hNq9IR4wAl3fpDTH8pKjykr/wc
         l9CUyOXsyCtufW40gL3YXsIE+AC8Mapjn1yeWnuB1ZKn84qoMtDd2F13Q3jPiAWLYSE6
         xxz7yt0c20ddoGAA52b4T7/2MrLAY/2Vcx8kdfr+EMoFgDOLMOBPeHnJzdlAcbELuaHT
         IuuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Jz9/nrAf";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811951; x=1719416751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8aheUQyQf4MR1EwsX54X+0liwnViRruVbBqUh4s1NME=;
        b=vxZ7ObvkoggSdp/GpIG6VFy2NqOjksrCRv36bU2T+kzMCuoMp5+lBkb5oHhOfspp6x
         G27ROdTvg/f9V+rN3FIxbnBAazxyLPDYwSWwWBhhHo2zmLuAtfIIdAqAC7WeF5xJGEBD
         0WgkaTBtlurQkSDTjkhYN7lwcCVr5QeBqEp/9qP6QD7NUztAmQxzXttaOJq3NJAsRe0b
         HXBqbUSUoj/mKVQgDf5gYwT6cKg4Af1O9LWYKfm+lC9fasKfoWIVeS54A96i9ENUCDAl
         bQzfLhKBVfVIzyyQRVEzFYTx01W5NcdGaBLBnwM+52BZ3yg+NqbmKvPQnA3Vij//GQN4
         ET1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811951; x=1719416751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8aheUQyQf4MR1EwsX54X+0liwnViRruVbBqUh4s1NME=;
        b=eBjkJlt9eVpYosE1heIp/D6lonwLVlz4Z/mm1H1/Ay5UDOtkOH4pD+QtGvdO0SAXQI
         RSFNBXxuDd2yCCDSQap7LyKSg/P+E2BQ8C5qeotJhUFEyIExZkZ2g7ukoYl6OOoO08Zd
         4YlfxlJMoVGlq4f0rFfws4R409MCUNCDWs2YDtjNVlFatf/VYR1aPoO5gpxcrucPhqov
         Gd+udyDLlJHtacBWFatM4jGLSG2305kR1daIGDQymVttahThEblM7ZOlxvPNljPLgzG4
         /TTa5B3LOsrlTqt0bXQvq/t+pnZN+pAR8A9PIzOr1B/DCVfcUIPiMwPy24W8ru+6u9Xd
         KfSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvTYEngZsElVRyrrWWTdj1T7CEwU/AjtPsESf5KSrT3RV49pzlcd0MkQEHPU4O0fjCv1Clp79u4ESA9JxZmuIm4EszgOIdqQ==
X-Gm-Message-State: AOJu0Yxp7UQHfVpvLvbYFNXyyJnZ4keVIG/eyJQwxe8IBhfD/bzdiGNZ
	EUol/k06p+XGzcOQQ/o07CVDd0s5Rq2SnUJiANL8Sr+2gOLPPzYd
X-Google-Smtp-Source: AGHT+IH66hBTC/nlWPJ0CCj563EysAD2Bnjpg4s9OfFILCMn8WGvXwU/bMWr5HlQhRb0KK4XNrNsKA==
X-Received: by 2002:ac8:5981:0:b0:440:ccb8:af2a with SMTP id d75a77b69052e-444a79a9cc6mr38394141cf.12.1718811951769;
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1898:b0:440:c5bc:db8b with SMTP id
 d75a77b69052e-4417aa38e6als95219161cf.1.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwij/NBHIaf3UBrLmuRNAdMrw9lXBDdM6GhYH3C175QyIGQCVkuvHsNGwZvxKcBrUssfALGPkafJiulFFYzQZY6VJgi0zRiyIUUA==
X-Received: by 2002:a05:6102:548e:b0:48f:1537:faf1 with SMTP id ada2fe7eead31-48f1537fb4emr3011853137.2.1718811949591;
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811949; cv=none;
        d=google.com; s=arc-20160816;
        b=tf4J3+Q8D2261y6LqFPHpnZykiKmRd8Kp41+t+Va/h8ZHS9lMSXNahMruMTOKha9Hy
         SHGGgsBv76huRHTzOyi1z7wOygUwnAQ+52BjGU5A8uvLx+0CkmbF6pLhobmHCPhuSpgr
         PaKDEe98UG3v5E2VsaUTG8lUd7CMIOGVdF3YpYIPPKDs2cw19jEhkmhm1q242l1r5CQf
         Qu/u7aLTAQKjbw9/qstlXDartM9958ITviecgu+M5zPfAT5YDBqvM0gK3jxcIBinKQSN
         WNhClmz/nEur0fgzNAMnTr7JqVkDEd3dD3epFAaTVd1CTPrSGXdPoEJPBzwmAkHmNGbB
         +SdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9fryXD6fg7ZWH/K5Ic2hWhXvK+X7HFTa6K6lMBwUrkw=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=INsz/gcrtoZNJvyRC1uvC+h+rCvcWuCZaxiNNMF5vZhkZACVNdDT2xcZznvtDyRfoU
         8KrjamQCO2ceM0e8svUFM3SsUelgJpPYsSKu8oefFOmZ1281MDXc4sFTZMLHWVoCQKlT
         PF+NSQ3aL2GbLB9FUZbTvPQ4SM/A+fmEot6Jksnf3JPfI7LQhWPFf4Coa/vEWOucoshK
         5zCPhxSdTVna01CLQ0anzKeCK8geaQY5RfKZxuCwFDJ5dJOCKbiOrSIJvz9vD8HVbcwN
         vSbOEYGjLJNxsoqRe8YIm82efHwxADvGj89TIlVN/KHSssOG26rYylfHGlNQpdQJiSH+
         IhWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Jz9/nrAf";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-80f55f4ecbesi120973241.1.2024.06.19.08.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JEx3tN025123;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5bb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjhGo005735;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5b5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JErhcX013488;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysr03wkqd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjbpM18415998
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:39 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F27852006A;
	Wed, 19 Jun 2024 15:45:36 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A33472004B;
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
Subject: [PATCH v5 09/37] kmsan: Expose kmsan_get_metadata()
Date: Wed, 19 Jun 2024 17:43:44 +0200
Message-ID: <20240619154530.163232-10-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 0jGG39Dru2q_AB0R1nHJ-WBhtrcxjIZW
X-Proofpoint-ORIG-GUID: eeWd6pnR11NC5-RtTJGUnFqboFK1-_M5
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 clxscore=1015 bulkscore=0 malwarescore=0
 mlxlogscore=884 suspectscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="Jz9/nrAf";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
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

Each s390 CPU has lowcore pages associated with it. Each CPU sees its
own lowcore at virtual address 0 through a hardware mechanism called
prefixing. Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to
resolve metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the
arch code.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h      | 9 +++++++++
 mm/kmsan/instrumentation.c | 1 +
 mm/kmsan/kmsan.h           | 1 -
 3 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e0c23a32cdf0..fe6c2212bdb1 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -230,6 +230,15 @@ void kmsan_handle_urb(const struct urb *urb, bool is_out);
  */
 void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
 
+/**
+ * kmsan_get_metadata() - Return a pointer to KMSAN shadow or origins.
+ * @addr:      kernel address.
+ * @is_origin: whether to return origins or shadow.
+ *
+ * Return NULL if metadata cannot be found.
+ */
+void *kmsan_get_metadata(void *addr, bool is_origin);
+
 #else
 
 static inline void kmsan_init_shadow(void)
diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 8a1bbbc723ab..94b49fac9d8b 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -14,6 +14,7 @@
 
 #include "kmsan.h"
 #include <linux/gfp.h>
+#include <linux/kmsan.h>
 #include <linux/kmsan_string.h>
 #include <linux/mm.h>
 #include <linux/uaccess.h>
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index adf443bcffe8..34b83c301d57 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -66,7 +66,6 @@ struct shadow_origin_ptr {
 
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
-void *kmsan_get_metadata(void *addr, bool is_origin);
 void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-10-iii%40linux.ibm.com.
