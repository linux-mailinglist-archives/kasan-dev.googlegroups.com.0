Return-Path: <kasan-dev+bncBCM3H26GVIOBBR5FVSZQMGQEWWPCG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 96D259076D9
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:52 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-254bbcb5585sf1143046fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293191; cv=pass;
        d=google.com; s=arc-20160816;
        b=x8sZhHsRMIJwTrOLi7mu7KSTSsuCXMWZoj1HANl0J4k1WFN+ZiAoTkkfavCVSkkXvy
         MDOSnZ1yOI4C5KcVCjbVEY9PKoLSZJrHLccJpa8IkjHnbJS2JOsiUPxs44Pln4+iIJKt
         +PhZc1R3MCGlyc1Jf/BqJgc9970uDl/1yRq2yMRqqQxfm8nL6+sIyVRLEhKvG9afdEo6
         zUWt825oePDinRGRVIOmeMKCpaZYyG7skAOG0p6NggLbYAoSmyHKNANHOxIwhinuzpQt
         +WHeiTO4P9WHHTNCIoVUoRGRJC6KFYOjvkQtj2JTxzu3AvcwKjrtEieelUKdbwqmVqtM
         BbaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=H/Vnk9QYLfvWa0juDODUgo2jkyMTHMTrzsFyMWG5Pv0=;
        fh=rdM/8q3qm1LFpA3dQP1BDxGgCTCl/oJTMZCIBa3WeGc=;
        b=NeEx0bOdDetQDRCvoMkS0zB+n0yRDZ8ca6ybJoFkhKSvL5Zod9aUdInWOUVnjSBM49
         o533elARuvBNJWxj0Yf7ZhebP6UC91fI/RJS3kn/OBrpxxw7UzLBM2CwPHbSZ3hY5DDt
         rK25fOGpu4FNAqfg/Rjf1BJcXbYnNr775EU7rCz4dOUhkzPO1hq9gIh4mMQ6DNdGxe2K
         Me4SitL8oTlbdKKqp4VQRhalY4nvRi6pklKmF5teLmKfN7a1mOLLUDGTIQRrb+H88H7i
         FO69w+xVhT7IPpVkst5PB53BqqnrAOsec7m9fj3I1O056VTua6DJWmoqSGM1whH1FlUz
         I0gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kpM3vAT4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293191; x=1718897991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H/Vnk9QYLfvWa0juDODUgo2jkyMTHMTrzsFyMWG5Pv0=;
        b=PRkBCaQ8CWhyloi9wlT3YUMf5HPkEfHlCgybzV+L29H0MNw7NvDURHXVsQETQ4VrmH
         vyAOz2F03sBRuVue5V6YfMKyfJEz1DNrktT35nkI/1AWu8VgMk72aH+XT9hX1yhReG9P
         6o5xhVfN89TUh2mzvNPeaHUK331//d2eTT/25jOjvRDbaFyXGD1BhRY2ZWePz9h9/4Yb
         W4+4LHx+7G0mDEdeBhSDSDr9ByJftSFELbV7I5qU8nOSVAkeZJzVrN2iOJDEUXZ4t4Xn
         JxPy2SvqDKUEXtXFeczU87mNm8b+2CMG4wsAQN0BAD6jesY/W1Wr0FBrnawy1fEVfrxH
         oCdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293191; x=1718897991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H/Vnk9QYLfvWa0juDODUgo2jkyMTHMTrzsFyMWG5Pv0=;
        b=ARCwYt1t7//e91dhcnu6XazBZquNAdFd6rSm5rF5KZEHDy52dEc7G3hrthDxDwBCf2
         VB/Qb7T2KR8ypNe108F+T9l3NzGnOTP49M1VcFb0xMuN1PqHycXPsOnUjgcqyKcMo5DU
         Np07w2O3NBOjRhoA0Lnk7jzkSWESFBBNP3cWLGdzor4JaBivwWlbSx5Gh9VRGxsxm+my
         qTow8lQebPGqM40skIIt9riQwfULXRLHsAaZ5WHmxd1s9i+A7KWcj+nphAToX1o4FYz8
         2M/vklzNYZrOD/0ADPtt4h2isAzZE0kDMAt/HLy0qGcAlo1mPo68lYYo/qvdfmb0TGi9
         qO/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRE6SHiNfYd+88qNPuLghjvtOKIyITtyeayCjmENF+PJHlmDW/nJDsvCvwyopuz2GPZcqaVNylo3lgc0rCp53CrBXN3G9Fug==
X-Gm-Message-State: AOJu0YwYn58NQuz8AtXzBcdcQ2CIXbftzzz4Hk4vqFxUwB8UrL0pfy5M
	PNF27mZnW/sDTihNu7HkwHYV4OYmA7WxzuZuQF8h5R0Y1EJ1dM6q
X-Google-Smtp-Source: AGHT+IE1cppdPVuFMlRq2fGYZQb1f/b+CXe6NRYN8R4/x6XIeL+qk4zuDJGewxkszBL24gBbKIiVbg==
X-Received: by 2002:a05:6870:a549:b0:254:a2c2:d3c3 with SMTP id 586e51a60fabf-25514b7ea35mr5694418fac.2.1718293191344;
        Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a791:b0:24f:6f0d:5f4a with SMTP id
 586e51a60fabf-2552b69c1a8ls789526fac.0.-pod-prod-01-us; Thu, 13 Jun 2024
 08:39:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHQ+dwaz/11Klol8rA+sLsEI/TtLwT7olSMTPAvWnUGNAuK5PPRVZHKBKPAfBvwEIF9crcI0++ElI7KOXHQcRLF0NACxCI5J7uyw==
X-Received: by 2002:a05:6808:1908:b0:3d2:2806:a1ba with SMTP id 5614622812f47-3d23e0cf640mr6836421b6e.39.1718293190420;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293190; cv=none;
        d=google.com; s=arc-20160816;
        b=iY2EHbj1FkYUwbhJM5E9CM+aUd7vbC48yhXnASck/gSSjdTUobUEafMeLo3F49Sqjw
         WXNyS8OFDEYLURsO5NfaYVeYLxKX7VSKmooSZFgyC0y9Slxd9WDPrgUd1bTT9aytlMDm
         6iAyTgY92lFD1VIBc67JT0SqVRJIIFs7vKrz7mjMRUe6SPz7Cf4L4YjmLMHkbgWBlRtp
         ylSCgyuLw2FEH/iO/L85mT4WKZWXSC+rBQWTSg4x3OkJG4e/eKfFJEsKwZra6FAnQLRD
         JrKE4c2dyD3/nYvfY7m/hKseFe557FR9PEscVPDuvXapD7BIen9LWOoYCPgL5JGDDvxD
         lvng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7LzF+mdGOSfbikK0rRRb7FcZ7CcG1T7oFIQ1dXnxY58=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=d5dRcIDrHL4pI2euiPW9lveaNWnaJQlYwn1TtgFSLwgkuP2Ht8NurvQyyrfB/38OXj
         KaAALYWzJZwBsM2q8HWVmi96qixFiA+twyB8BUA8N0O35j4fTHfx6w8MNUrYXvK5sU/x
         9sWDZ1JWT9n6k0ZiR63sQUikBR5sbiW6KRvNPVaMEeHeB0S97vBWV3ol/j0PfIAzGhHx
         fw4ryVyLCdmly89+QLCym+sR5AwBSEf4NCTZ7YLe4jpr9J4ofw6u06pY8r5Sic9XE8Gq
         o2xbsv3w5yN6NFRn1Ff9j54MylDh9qCvucYBOzjnwH6ieSWs2wDfH/pXMVPRPa6u2oUb
         ZLww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kpM3vAT4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d247667130si88082b6e.2.2024.06.13.08.39.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEKeSI029454;
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqr0vsy4h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdj3A023918;
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqr0vsy4e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF7EKD020041;
	Thu, 13 Jun 2024 15:39:44 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn34nh0bq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:43 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdbKC56885574
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:40 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D2C5020043;
	Thu, 13 Jun 2024 15:39:37 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6087E2004D;
	Thu, 13 Jun 2024 15:39:37 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:37 +0000 (GMT)
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
Subject: [PATCH v4 09/35] kmsan: Expose kmsan_get_metadata()
Date: Thu, 13 Jun 2024 17:34:11 +0200
Message-ID: <20240613153924.961511-10-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: DNHr_yy1T_Z01HP8UOfToGMrh2Q-YjYa
X-Proofpoint-ORIG-GUID: _fT-888Ew5czqGiJ_jte1hCxiA1X8Tlx
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 bulkscore=0 impostorscore=0
 mlxlogscore=877 priorityscore=1501 spamscore=0 suspectscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kpM3vAT4;       spf=pass (google.com:
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

Each s390 CPU has lowcore pages associated with it. Each CPU sees its
own lowcore at virtual address 0 through a hardware mechanism called
prefixing. Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to
resolve metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the
arch code.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-10-iii%40linux.ibm.com.
