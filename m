Return-Path: <kasan-dev+bncBCM3H26GVIOBBBGM2WZQMGQECECC54Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 44DA59123E3
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:42 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-25989b941e9sf2196057fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969861; cv=pass;
        d=google.com; s=arc-20160816;
        b=JGlwceERa04WcRgMj5H/A7GORnIoArGOVwVDCs7pJtZLpcJBw0ObUmnoekKnkh58c6
         g4AHklgX1B648qktFx0xtYq3k7j4MzlhrTojiVlZWGiKTqipupmOzpAXSTQxKkbn4m6J
         xIU6Z49R57VsFzk5sQGcU1eN5yNg8NsTamdPQps8at2G4Q6XmPQm43L1c82HezJ+mv+z
         mXp+nFQ4j0LYEweIbyaPVKLhL4R6ADQTII7TG7NTIECGvhTa6R9BdE49INHJFfXKHSSk
         Qx78xZv55CA1HN4V/yk12jONZKPpF/jq32kJmiBm1km7uGJ/tOK33TjSZyvvyuIpZ9fl
         zY4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vuilDRTvZf3EbLaDVQaExmNJAA202Al78TeXLgAXQXw=;
        fh=cn+IfjRYjxX0pU1onCr1RpRLT9ZkWY2I1PX5x8FipBU=;
        b=et6sgwiYYSe+aSt2bSA/FhsSQ5bNfN29JiRjCERftoptb3Md1MXtdu+g4Ky+SoLm18
         BW0UtqYYD74BPgexP1szghLnWIw3XIwV1U8D8vvz0B5KOLq8Xd1lIsUBuw7xuIKYLPsy
         k3Aa1GE49O2kqkwplTckrpOb0q827tqmhFdpo44dkWIqM387XMywSgzabLl1PI213TFm
         rh49x0pf5eDnAiAwvrgkvbgWT93c2G2VXSHPiuwaGsFeVJiCyh9iuTdvE0Tbpqkpms9i
         q6Dur+eU/jLd/t5efeVHNsITkPenHk6qxG5kfTksMZfKorktTH89XacIB8C5UgjafQAF
         Gprg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=R6UM91jS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969861; x=1719574661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vuilDRTvZf3EbLaDVQaExmNJAA202Al78TeXLgAXQXw=;
        b=ijnIhQwLhjAJByBddFSdakq4zxJx+02QWPM5SyCBvi7PAQ4BTcQlVU4Fnb+7qs8Wm4
         q4nl0EuAgiPuFwHnTRFNunKFVIiNHUddAnoLs8xJvgGgKFX/vdTfhBo/NrTAmQW6PZ2A
         c68ZCaqtlGae57Of4ZWYOAHrcXrj1E79JvIoQ61guTNVBk3+GabYQcgF5qOuxECmkDeJ
         YoxIHkxEIsyfxWHS/Vgmd3IliWvH8RW4UgjUefDmVjPz2nOJ9bqkeNKjoTJ4cCZWS8qp
         NdtbWPZi3SOaYbjF7EdKzRNcX5wmJ//0npkhQ7nW8SeG/yEW6i699V1E+2cTLmpDHvsB
         wnOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969861; x=1719574661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vuilDRTvZf3EbLaDVQaExmNJAA202Al78TeXLgAXQXw=;
        b=jXF8hej9DVrdqYdoCElEWH6FhNb/QRl6mwEO+KAWXqhtDjfxE2DBu693Jy/Tmzwopa
         T5vmjl1cIrLcUwELQLe9vPiSEpSlekV988HwoH0cRvsl7N/8w+hTn4yqMjwVINnb7+QS
         Qc+zW1j9145s60MB4hBDG89DNLw/n4o64CIPRW/vLdrtpZJHSErlaJNkGZDOTm3tv5wS
         kKQkJzPL/9gXEvDwaAjWaUo4pPuEXymXcou4J2+gBrFnOcaXcJolx8pqGp07OFhlsDTi
         wN2Ou7pAa7daH/3SFfuTF0rgaduUmkNJ1RNrokVrquCtCwpiN2ysc7+qJsyu23go8Waj
         fIww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5GWce1Yed4ZYRyUtx+7vbX2okSrtS79JBRas28CzkShqnHu880L31hV2hUaS9BerWSBYk8SO+dal+Fdh9lAW/I+nTG7r5bw==
X-Gm-Message-State: AOJu0YxgMOpPizvdH2QAhx2M7WES0/imx7yi3obIabWZjBiMOJ9WAQoj
	KCmqi6z+Rr3FaD4Pmok3T7YS9Ebn4gFBL8wAeytUjj+5U4jKAf+/
X-Google-Smtp-Source: AGHT+IEqtoSUz0Z89WKLxhsKgFVTmPpD+A7xZapRydtVowCJuWJBaZGZToKUQQqvbIRCzE0zPZFwOA==
X-Received: by 2002:a05:6870:d38c:b0:259:786e:3c38 with SMTP id 586e51a60fabf-25c940b5320mr4177300fac.19.1718969861018;
        Fri, 21 Jun 2024 04:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1b07:b0:24f:f6d5:2d15 with SMTP id
 586e51a60fabf-25cb581b64fls540023fac.0.-pod-prod-00-us; Fri, 21 Jun 2024
 04:37:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2TjGo+BBwTGY5JaYTVUpd/hJ4h/RBPggxf72dlwWvKBbotRfflCw/9dyxeN+8Y1Ssw6R6oXDNl06FEKxDxW9WzXVkdHAyhugv/A==
X-Received: by 2002:a05:6808:130a:b0:3c9:9e8e:52f3 with SMTP id 5614622812f47-3d50f0ab24amr5106284b6e.17.1718969860246;
        Fri, 21 Jun 2024 04:37:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969860; cv=none;
        d=google.com; s=arc-20160816;
        b=kURSaRlnIu9lcQw8bRVjqsDKiio1ED79WVavI7NZKgx/as+kS55338JmTTC9kq5fsx
         Q7yQGa8hCbaMvlLCcEMYdOfMw3sOxJO5lAbB+FOFAJC62Woaf5o2Vf0muSfxw92FcUIk
         g3s3dT/NJvNi62167jw/1AMkubZpebD20eWtUf9q7dOLP48Mw5OrOd+bZ6Zes+1BN5Oq
         jW+r/OmGb7YbIWNjIlIgaDEHY2VGc3olCWiBsZJa29Dr/tItxuT/VPV+XmTsF6tvolXK
         1+bY/JekrMVLcjunru150YrJjGbiUMg5FraDqR3IZa1eW4lXaVXo0jI6o+Hrdgd0U8Y+
         xzsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2Lekuxa2dBCBcc5htHlKGfkEfSg9eOPP5CW8wCh3gqI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=an0ebmxFijdq211NQfAxUXo9aLMYrnR9YKXiuvt5He/TDEkH6XYiwZj6rSQIDsXLEQ
         uuhoxEchrBXDIuP5kCJxK9uUOKoqovsYSmjHpxt4hIIqhM2YJboTcrDT9sp+cJxxQ0/h
         qgHXdnSN5rxPSIX+2iJNB2e+Bt74qHKE2IU4P+DnJ5vlaKkatVxtkJ/pPATHsiVGl51h
         nOoTGQIPvLJA3O7O+jcBS0TFPPRc8+7BsDkUkrdYIzP4cXEFz7wptHSVlgxDhghgd4jR
         r/6ui36IInwjdAU8iwEzWAiuADJq2oIq4udvh2o/ONyR+5hJkksa8WWSDGmyeCjQGm2B
         s56w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=R6UM91jS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5344e7c93si56116b6e.1.2024.06.21.04.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LAThJS018266;
	Fri, 21 Jun 2024 11:37:38 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t5046h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:37 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbbRH017573;
	Fri, 21 Jun 2024 11:37:37 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t5046d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:37 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9F81Q032326;
	Fri, 21 Jun 2024 11:37:36 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv6d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:36 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbUNs33817122
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:32 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8DE0C2006C;
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 03C7F20065;
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
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
Subject: [PATCH v7 35/38] s390/uaccess: Add the missing linux/instrumented.h #include
Date: Fri, 21 Jun 2024 13:35:19 +0200
Message-ID: <20240621113706.315500-36-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: mhn8jrenjGfEm4-xUpGHErN466P5A7lV
X-Proofpoint-GUID: HzV0N2f4Iy-hsOvGb-JmJc_00Dwo5ipb
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 malwarescore=0 phishscore=0 clxscore=1015 priorityscore=1501
 impostorscore=0 mlxlogscore=999 suspectscore=0 mlxscore=0 adultscore=0
 bulkscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=R6UM91jS;       spf=pass (google.com:
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

uaccess.h uses instrument_get_user() and instrument_put_user(), which
are defined in linux/instrumented.h. Currently we get this header from
somewhere else by accident; prefer to be explicit about it and include
it directly.

Suggested-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/uaccess.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uaccess.h
index 70f0edc00c2a..9213be0529ee 100644
--- a/arch/s390/include/asm/uaccess.h
+++ b/arch/s390/include/asm/uaccess.h
@@ -18,6 +18,7 @@
 #include <asm/extable.h>
 #include <asm/facility.h>
 #include <asm-generic/access_ok.h>
+#include <linux/instrumented.h>
 
 void debug_user_asce(int exit);
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-36-iii%40linux.ibm.com.
