Return-Path: <kasan-dev+bncBCM3H26GVIOBBIUA5GVQMGQEONZARZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 54FF0812316
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:07 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4259021e5a8sf145491cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510626; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hi1LQFcEPEmOIvhWhQblfLQW/HcuIYJkFzY0EOzk0AJI2njjotea7lPXe4Vi+etIHG
         U5qzs4i1Dlfp+jwdi8axd9Jm2pCbfOkY+T6jPqL/+ElPX/6fOGzPqGUksxZ1h7rc19qZ
         U1EDhVjsgvhIVETZpbE9We69qePdu0jNCcfDDyi+FZ5Oa2S3xatlzcYEbJ5z/rEorV0j
         f/Q4vlJI1+REHZ9ge8qrcTgisY0STwW+1RU+jA8IPmNYUwqtdRVV79bML5OuD5QEofAg
         o1mqvdX7QnA1ge3Q7vLG1xWRtuMtMRu99qPq7uZSUT3dP9CzH6GJUjTN1ZVSipFF3gaX
         IFxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/LTej7SB2IfdryHYVvmeFY0TNQvdLQe/Ckp6YVVaSJg=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=fXlBjiyeLH/rr2UZvDGiFvwXZ5N4iH0cknKp38nL++NaTK324NsDfkyyctMTO/dI2x
         Tn/7FgVPZM3LV1fOKq/ci91taqcxUMIrWXLjErEjHVqmCx+mZSMeAGCBGEiIn5SGfzsN
         SoIZzkPJZiMzs3dvk33uqaWbPf4NeEX6hAAE4nWf3Oyz7RI/X7P28kLuWOhKJu7xleo/
         c4fG9gISmeDitCUTsgbgZKO+3rfsvGsn4yTMLPVFv8b+3EcKCcI8mLVR5HSFkHb63uEy
         IslPBxtO76HHo4SXQPR7joLm1EShim3hEvcycEFtr/DYCDk9FMqt1srr9AkezFSTseqb
         /+sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aQI3T2vl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510626; x=1703115426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/LTej7SB2IfdryHYVvmeFY0TNQvdLQe/Ckp6YVVaSJg=;
        b=BFfdNYmLpf7DXrIERRgR0ypt7XmLH0A3IGav1XQxOWIm0izhxRQI4cHvO+jbnAWDn7
         sY4okEe6mqTCLTv1Pn08JUFb8MbqmYDbB30TToCvrZ/bbzVXBcYSF2yyn1IQ+4Xccyy4
         bbp0BtyVCWEHiaF7KDjmKuUFjpZXzYIp4lm+YAn6ZrmA9qHiP0hVcTH22vxnarj3VUVO
         p6lCRsrAmGn+fUv+ApgJ8N5oxpJn7X1Rrl5+5GRPmbp20pdwaHBX1uZCcWYFnBowQbv2
         htBMosBGw/TkiVtSz/sIHUJzIEb2lowhnkEiHx1FJ1r+9NAWzxSZ1S/2Gda687uRrNWf
         eY2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510626; x=1703115426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/LTej7SB2IfdryHYVvmeFY0TNQvdLQe/Ckp6YVVaSJg=;
        b=wH3jnWHYEPwljd03lvoc1cvvYzsA+R/H+3QRMm6MH9iYj/Hp0zhbDk5QNInEAKDTbW
         0qwWSQcCBR9e62ikX+nAtsDTLcEzyERzO6IhARo5rbm1UCQXemM2qbklXx2j96YAW4+z
         5Bv8t+CTBohFnzWmSRRfUqTEteHbfYCo3Jk/bQO1epIY77C08DSu5+YyFEYPCNZeNoBb
         P8cBbQEnYkKFtTA1oAwinmo734F/5xZvqATjImeJ7MoC5woicWdGcIUJ0CaXBwirEpwI
         wbQyg4J5YPtXyftN54lfpavjYu3XgKezUYWA03ox6ktCSgJf1U9thHMmhcLYeDS5E0R5
         RQfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxjmjWS8mp34f/u7L7X403LKsR0uvfmyj0JJ1ug2+yABuzieJRp
	7oLXGaHYFjHYyzMCm7QeDDU=
X-Google-Smtp-Source: AGHT+IFtcPdmXmRYWecZxuGNnX2qr5OgfZg1X7dZnzzxGtoBCa/c6UlHQ3RI7WOKlRrMsy+QJRU6CA==
X-Received: by 2002:ac8:5908:0:b0:423:fa07:a686 with SMTP id 8-20020ac85908000000b00423fa07a686mr1538636qty.23.1702510626422;
        Wed, 13 Dec 2023 15:37:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:22a4:b0:58e:2e05:d95f with SMTP id
 ck36-20020a05682022a400b0058e2e05d95fls776620oob.1.-pod-prod-02-us; Wed, 13
 Dec 2023 15:37:05 -0800 (PST)
X-Received: by 2002:a9d:7a94:0:b0:6d9:d7d8:ab4f with SMTP id l20-20020a9d7a94000000b006d9d7d8ab4fmr7298405otn.34.1702510625520;
        Wed, 13 Dec 2023 15:37:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510625; cv=none;
        d=google.com; s=arc-20160816;
        b=0O5uOT3lQdduH+rr9UIn3PfwaGM1hTA8BOFpuPO8L2v+L/PBsnyQmT7yJzCImbdU5H
         56uh74IdedIQvKSpIf5ZGl7qTs/C6mNtPSErKWxb/AajJpF4kyKbRmEy230FvZbNfE1p
         l+eQ6HuwYj/0uQbGpEd0aNRRe/AhzMI0WvpQ2RT6i+/2GdjOow42zF/wmVp6GhnkQtrO
         V54JlyanbpIjDMgDEQHgfuCPQ2NlG5OVi86kE6VCTfqZtofi75bFFlSKcuV1Y/rCVbBV
         //dAcHrnQrbeVqQ7uiq334Yxgb7JTZmTm2ijYZiUonrWGsxDRfVIztjEhukhoILPw5rS
         6/6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YWzC8DsQqa6wKXOwz7r3yo3WLfhtbao5IRz+1f0SKy8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=j6W8jzhH7wXxZMz0wGyKwpuJjkuM8B+Ggt6FYpTXQANuV9FNd2Sng43GKxEJzA/kFa
         V8Zl/kLxsJhvgNaFLd4Tv7y5aN5BXE2dNkUoKfu2rrv0htOJix2cH17po4q3eW4PEgcp
         5RtpipAc753UmRb9dT4iXBLggtr/YFjGR2o5PVFoN61XSkXrIxAO3s3SK4g1/LxGQqj7
         /c6iT5xrLJkTHzPikXbMn1OO3MyZBZtojJMi1F4aIt5wG7KoFrKeo/JMR7vCaIaF3t+v
         OmRTM6QFkFYdQ6ySKv1srn0enjKkqYrtbNuaZCY9OcrKj65uUA1qFLlsxAsdchfP4n96
         Nvlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aQI3T2vl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id hm5-20020a056a00670500b006ce735228e3si945008pfb.6.2023.12.13.15.37.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:05 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMSAMJ011063;
	Wed, 13 Dec 2023 23:37:01 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne6165w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:00 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDN63Dk009269;
	Wed, 13 Dec 2023 23:37:00 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne61605-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:59 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNOPrE014136;
	Wed, 13 Dec 2023 23:36:31 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592c4fs-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:31 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaS5539387892
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:28 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B36B620043;
	Wed, 13 Dec 2023 23:36:28 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 08C3A20040;
	Wed, 13 Dec 2023 23:36:27 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:26 +0000 (GMT)
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
Subject: [PATCH v3 12/34] kmsan: Support SLAB_POISON
Date: Thu, 14 Dec 2023 00:24:32 +0100
Message-ID: <20231213233605.661251-13-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZPYGJjS1ND9T0j1SVbC9BdaZjseEeUwb
X-Proofpoint-ORIG-GUID: mB8Th-NtdbtQGDfs5uCnRJQbqp4W6oNm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 spamscore=0 bulkscore=0
 mlxlogscore=999 lowpriorityscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=aQI3T2vl;       spf=pass (google.com:
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

Avoid false KMSAN negatives with SLUB_DEBUG by allowing
kmsan_slab_free() to poison the freed memory, and by preventing
init_object() from unpoisoning new allocations by using __memset().

There are two alternatives to this approach. First, init_object()
can be marked with __no_sanitize_memory. This annotation should be used
with great care, because it drops all instrumentation from the
function, and any shadow writes will be lost. Even though this is not a
concern with the current init_object() implementation, this may change
in the future.

Second, kmsan_poison_memory() calls may be added after memset() calls.
The downside is that init_object() is called from
free_debug_processing(), in which case poisoning will erase the
distinction between simply uninitialized memory and UAF.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c |  2 +-
 mm/slub.c        | 13 +++++++++----
 2 files changed, 10 insertions(+), 5 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 3acf010c9814..21004eeee240 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -74,7 +74,7 @@ void kmsan_slab_free(struct kmem_cache *s, void *object)
 		return;
 
 	/* RCU slabs could be legally used after free within the RCU period */
-	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		return;
 	/*
 	 * If there's a constructor, freed memory must remain in the same state
diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..b111bc315e3f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1030,7 +1030,12 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 	unsigned int poison_size = s->object_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
-		memset(p - s->red_left_pad, val, s->red_left_pad);
+		/*
+		 * Use __memset() here and below in order to avoid overwriting
+		 * the KMSAN shadow. Keeping the shadow makes it possible to
+		 * distinguish uninit-value from use-after-free.
+		 */
+		__memset(p - s->red_left_pad, val, s->red_left_pad);
 
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
 			/*
@@ -1043,12 +1048,12 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 	}
 
 	if (s->flags & __OBJECT_POISON) {
-		memset(p, POISON_FREE, poison_size - 1);
-		p[poison_size - 1] = POISON_END;
+		__memset(p, POISON_FREE, poison_size - 1);
+		__memset(p + poison_size - 1, POISON_END, 1);
 	}
 
 	if (s->flags & SLAB_RED_ZONE)
-		memset(p + poison_size, val, s->inuse - poison_size);
+		__memset(p + poison_size, val, s->inuse - poison_size);
 }
 
 static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-13-iii%40linux.ibm.com.
