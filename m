Return-Path: <kasan-dev+bncBCM3H26GVIOBBMP2ZOZQMGQEMLXPF5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A3BE90F2AF
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:56 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-62a08273919sf107531037b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811955; cv=pass;
        d=google.com; s=arc-20160816;
        b=dUc7maR3zlNTxRdVBeTRQxUENm84/s21ZkxSM2Hfwf2QlNjNudHDKSBAiGMxGEzFjL
         DhhCEPS/sQqcCruwAwXVjdgBqrbxYbYP0kS29fK84XWpsXn7jjeHvL7Plezx14aoFPL8
         ZS/goHQlLhjlWMOV659v44kwjSZUis+MmAqJ5gpGui7KInRQ5PzaWN56v57eR5jN2dX0
         HvyaMKhJKsKLM7FS+xZfTP6K1de9pJ1ORtKsHtOec2rJXNQ3Phii/O5Tha0gy4zT5pG+
         zuqS+ReKqwi4DjMDccDE3YjuB9DfoDyU5n+BWME8GO4n4UPOCcHewdli5UOBKGd4lM4O
         Sz5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hvULm/yMX8COVzc0W+g3XvRUYTHFaTcghtyGSaxxmUE=;
        fh=VDWtdtDtKKOQOG+sh7VKJXGx+Pbhj9DmHjIgONQverk=;
        b=nwbi0PkFSA0Ic97M9pR79scYaD6Ii0GNekUl2SqpLcHtMD9PPHLdPfpvIxkDBxi53b
         t8wY9ANsEdP5v9UGvK80fA6tkIhmsyyezpi2LaMVMmDEec5f2E3xg0jwFQ6u+kb1vQJR
         AfxtKqo5BCLTNKbevRk1aLLs0u0hib66mVd+MXaWODOJZ5M4jQeHhBqAaWPU8TzXRbWs
         Arj+amZv9DTSxOMfxvaIeNPwQWKeSVL+3P48xNsLjhztdLO7nSvzlI3P4vkKUlEtb2cO
         4UhWeqMOpMvccBLdnfhlsoZxFUXe/mFJn9yDB0yLbxympr/LPpcrU7FhNUpmgnfGlP0r
         JUEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hrkS6RNO;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811955; x=1719416755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hvULm/yMX8COVzc0W+g3XvRUYTHFaTcghtyGSaxxmUE=;
        b=qYQiecNj1CUaKzPlQa3Hebnbr6rXO6hsK6hNHNaLbaeWLk8JNHmP4qBLoasmJFNdI6
         pdq5DDzoORb0yTT8HOs2sisiRXLvrwBM1FnjpyPYjqibvUhxI9+V/g1I7DTRYrz2yYDF
         kNajnQtcJQwFbkT5A1UO6jaI7gk0t8QP4z/6nYEUVIvmzEzZ4vpv9euyoxXTA2wYLDSd
         BeguA+rAmWObFXmQu/R37sO9shkg5iz3HgymJgvmdw/BYDKWPfKKWuiR+7iZy0y6f5xd
         xTg9mhCLs5XBcd2LmLLlj1K55qjFPuuO1CWA5antkvCgLK/iN1v6ZzI0Ch0S54uX8XZY
         SVlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811955; x=1719416755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hvULm/yMX8COVzc0W+g3XvRUYTHFaTcghtyGSaxxmUE=;
        b=aVJlSl3pjbLygu9AYYZR8HmIqug2ug6qztSY4l3eKZqQQ822Y01symdHOXeYpDH/Eg
         PS3+eTio+Ljg/uX8PuxmpGsnDGzmZ0/FJhW2Ju+vLrwB+wf3dJNSOcyeat0GjV+uNM5g
         pg8JvZrQ8k/qYSiBWoNAYBfR6JPHlgZTm9nL1O+DPhR9yqQ707GmkHZObSDEtPm/ie5r
         Omd8vgqeLGRtRcaduC6eNWI/+Pg6N9ArIcjgt713jh6x5vzEFfutjGdMXB5Opy6F5+Ln
         xbY1J6UYHVS4SGcei+9gvRDno/JeJIQicS/8kdwCQnTPR2oftdmVWQfe456vvWMQlv9T
         6vYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxNsVxMQrpmb3z0tOMJaFL0t/KSArY2q7OE85sHOq5wPGVLUquSR7/FfOXQtJa6H+qU6DmFdt+14nZb1iKMfcLaPnjcduQ9A==
X-Gm-Message-State: AOJu0YyYTcTa3oDtsywhXMFWpiuGznGT1IRuwvr7xVc6WDrOcYKMbzvT
	yt0PhMh6fNwhc8o4SablObeo71pypVH4LImIAAgM/EkHwHQ01eIQ
X-Google-Smtp-Source: AGHT+IFGEMW65NtYtpwzczlfu8xxYYii/9uNqusv7DxB/BhDhdmQChfoDxNLpa2ioeCQb7u9XAXWbw==
X-Received: by 2002:a81:9e0d:0:b0:62c:c65d:8d1c with SMTP id 00721157ae682-63a8faf2eb6mr25717907b3.52.1718811953631;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2d43:b0:6ad:7b3c:b7c7 with SMTP id
 6a1803df08f44-6b2a3507c5fls93392656d6.1.-pod-prod-03-us; Wed, 19 Jun 2024
 08:45:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZ15naRbnNFEfwJ5qZIdzRliabwI1spMOMIsHwRpYbAXndIgktwx+l9QPnDqWYxs69Y00LeL5GWhZk4ypc3nDtrT7l3JczqzudWA==
X-Received: by 2002:a67:fb97:0:b0:48d:bec2:2cb9 with SMTP id ada2fe7eead31-48f12fdcbf0mr2761703137.7.1718811951696;
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811951; cv=none;
        d=google.com; s=arc-20160816;
        b=q/rxRAFG0zsZ/bbPjWJtg/eDbGZeA89dTG3RQOedRsdufqFbAxtNfWl9lO5k67vm3n
         DwU/CfcpTRVOGeKmERgBh5SdI9GSD4zvu1YgLpw7Q0YXqntB5xneU3a0NHVioqg/JUrX
         x5yEpZ2jjnNHMkUXHcE2yGUJzlitjIN0PhKr1uRlu8mByMR+s7bYC5z858faSn1tNO7W
         9E5fbZE2sCaV8Gt25drqPrVTMeOqGRfNNVaYY68ZGdJP/3myt+ilvfPy22YgIf0gsPv1
         crpczA9UGwLeGqZjd6mcEdbVTy/FarhLRCKxiM5Kyr4C8C2OeVeOs9hXx8qb/u2mPRHi
         lAIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fhyNLk4BgDYNJAsfSc8ftWCxz9OlL/4RiKPE6HJFalY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=NuHBk8yBW6Q7bQEJluYAlAcQSB39Gh0Pm55U58tLCsRXRpaYcZFn/N8L6pPRX/3z+l
         y5PrkwSi7k4BL7rYdSAY4BAtgAn1dd27Zfm5t4/Fy3laOURaPMhqlDNwAeIGgrKLmK/u
         NXb4ddXOXHV7nHNbFjh3Y2xOqOjG1gf692GtZivxIsPwW9oFfaWAurUQER0FDGanlIPQ
         YdXT/6w7kZ3uxIOVmk9asO5lWUzkxt5cmB8YVW2VKZgKvwdMV/KusIHd1mccTqvDc6nC
         u1Z++Q+2SpW9QhPsiFe0BzZdaclmyhQxiTeDSF5NpW9B6vfsYjl6P06SE7bag9rLNfO+
         Lk2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hrkS6RNO;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48da44b6bcbsi569894137.2.2024.06.19.08.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JEwgQL023598;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5bj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjkwE005769;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5bd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFN5s7019545;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysnp1e4wf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:44 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjcse47513874
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:40 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BD04E20063;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6E7592005A;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
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
Subject: [PATCH v5 14/37] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
Date: Wed, 19 Jun 2024 17:43:49 +0200
Message-ID: <20240619154530.163232-15-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: gIZT5DYHh1rbbpQa0FFDm_E1i5yVi9Yw
X-Proofpoint-ORIG-GUID: OHhlw3JqsWTVZx2EL0dqKaWV5MgXhMBa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 clxscore=1015 bulkscore=0 malwarescore=0
 mlxlogscore=999 suspectscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=hrkS6RNO;       spf=pass (google.com:
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

Improve the readability by replacing the custom aligning logic with
ALIGN_DOWN(). Unlike other places where a similar sequence is used,
there is no size parameter that needs to be adjusted, so the standard
macro fits.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 8 +++-----
 1 file changed, 3 insertions(+), 5 deletions(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 2d57408c78ae..9c58f081d84f 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -123,14 +123,12 @@ struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *address, u64 size,
  */
 void *kmsan_get_metadata(void *address, bool is_origin)
 {
-	u64 addr = (u64)address, pad, off;
+	u64 addr = (u64)address, off;
 	struct page *page;
 	void *ret;
 
-	if (is_origin && !IS_ALIGNED(addr, KMSAN_ORIGIN_SIZE)) {
-		pad = addr % KMSAN_ORIGIN_SIZE;
-		addr -= pad;
-	}
+	if (is_origin)
+		addr = ALIGN_DOWN(addr, KMSAN_ORIGIN_SIZE);
 	address = (void *)addr;
 	if (kmsan_internal_is_vmalloc_addr(address) ||
 	    kmsan_internal_is_module_addr(address))
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-15-iii%40linux.ibm.com.
