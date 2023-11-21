Return-Path: <kasan-dev+bncBCM3H26GVIOBBA6S6SVAMGQEKWYMKRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D4857F3893
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:44 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-58a5860c88fsf7259168eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604163; cv=pass;
        d=google.com; s=arc-20160816;
        b=z6C4h5m0lhCrz27xZJGPQ6ccjSI/inMZEC8mw/IuYJntOTNrzIoC65G1F778cEWg+l
         +hlNNozswzN6Pi9ixgg3mH/prs7OG5Uicl4gL/KMyXMa6ywIAPWWZo5WPRaKFLUHkiX0
         P5d+rmnvQT+7bBekuquAmUOE6vItiUy8x7SFzlhySNZcynJFyJmyiHXlkTecq03YEAw6
         ++upaKyXfSm3pYUXlgENFELWVvlX5xYB/qdxnM4GATRcbTASpvNJQrmR3R9PLY1UL8rI
         ZM9VSf3sch36mpCEdG00H+lzwkHh8UXhomQ0Py4DT8hQ7XdupAo2TrIfIBVx0tbTQjns
         7G8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=92J2pJhtHwsLrrFd4zeAFEG4TQpZRNT2uEU0SH31erE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=dDT4HlCYUHMDBeuMcO64LMQU/HSpyT1PXXmk+MH6n0kmnBMFCmktErXSy7ZGE/NqdZ
         QXXyIHLZBrc3YT6qx/ESodyvoydUE3c5Bln1zGIBSxg/IMwE7scX3C54Em6FXq/vF0iW
         2uDQ0SwR6zJwpYlfgBPD+dcCWgIvawiIb11LwBb6NeiaFq25bIF/Pm8MkfzXLl3xxXAP
         f/9OUpJQRlLbR8FCu/4PlzkDkY4MCeWtnFc2d0KdkBujlSDvzlGw2weElO88JUhQ4Z0D
         ynDMgmH3m+FnIu7vs2Ukvl0UD+64Mck5JqARLpSBLwIoLEGeJSPQgdSPD6gEHr7Ery61
         RtWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KOLMzVoP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604163; x=1701208963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=92J2pJhtHwsLrrFd4zeAFEG4TQpZRNT2uEU0SH31erE=;
        b=YgUwd6H9cmZ4qXNAnLIRr8JlmXAbB2WHqTM0JVhdg8u3oQsNsVM+ap3vKu8AyHXhYb
         Llo74CqIoT0WO4TBbI7si+t9g/G5w5PbR1NakrBM8sJ4Q0sYCMO3HVLZ0K7g5b9iFmTX
         GqnbcjqeHbMPvM5eUeiKaZhI0LZjl107iI7xAMvLx3vxYJDRbvz+H6QI12iV3By3Pl2T
         nAPTvCg5gKxGx/rMI1eYTBnpuSDsdRT1lo+iXFflUu8l1BJOgPDrk8G4TSVgbfqGnWVz
         n1I9qA9p39Bkp8tWT/eICdl6vWk9mGv3/etvirB2ZVwYbrpShuQ8HYj4Xn9YI64uaUah
         kzYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604163; x=1701208963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=92J2pJhtHwsLrrFd4zeAFEG4TQpZRNT2uEU0SH31erE=;
        b=dCtxGt1YCBvV2BiqniXBeKoxexDCvrvFEa6dytCT6URgsHc6VoR1uA7ubBRLboxos5
         AV8Vz3kOx2Pgbt91STjJLsuL7nq7VItUGX8O8E0XijdROVD01NO1ToEHWk+Og6Hknwkh
         B3K1DgfiEqmS7EMaaCrU4TtWFmZvRs0De9FDoKgWMP7pNK4TDatZbIKaned+QhIzgvh3
         osnzGFhEublq5XKFQ8zI2BdkAss/OF5F9NLc4Fvuh5leVNxbIdHLe15+sF7iBCDsgKr/
         LbeDHptFJpAhOzzOy7DbG8RvZv+FdcTHq0uzEJOovlg9ydtdiPqd6BDeI4es4peRqTo4
         wbcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxDunYNiZjwhxZ2VIP3YSaQ+TZfZAHY4RYuSMOjETSC5lFjosf6
	3TGd+LOJ30ID7No+gziTsxg=
X-Google-Smtp-Source: AGHT+IGzYibyod370NpP8hOLi9tYxih1WB93+KSWVgZFWGpqWLGD07Z2lQBpaUAqLsYmyBChWLZYHA==
X-Received: by 2002:a05:6820:1607:b0:581:d7b1:786f with SMTP id bb7-20020a056820160700b00581d7b1786fmr821115oob.7.1700604163427;
        Tue, 21 Nov 2023 14:02:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1503:b0:584:3ac:b4f8 with SMTP id
 ay3-20020a056820150300b0058403acb4f8ls478414oob.0.-pod-prod-03-us; Tue, 21
 Nov 2023 14:02:42 -0800 (PST)
X-Received: by 2002:a05:6808:11ce:b0:3b2:db86:209 with SMTP id p14-20020a05680811ce00b003b2db860209mr796303oiv.38.1700604162686;
        Tue, 21 Nov 2023 14:02:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604162; cv=none;
        d=google.com; s=arc-20160816;
        b=xREtDWbF0j5Z9iIM7vKznFctLogD5v2Gqs02rty/IwgBWT1ndixYLhEx3FtiIzKz1L
         xsRkMguj9+n1Dm4HJEEEoH1LrfGRpiW9WP18qLaKOTYhIeeJeEKz9v+FM15PRvRhpzdr
         p6n1sYXJe08yghsd0eBdzEiOEu6+FT0PMDHPjj+qtoMrzQgM84hU0zO7awtEmNhXPEIo
         mfIGb/BqqvBThZbqKUt9Lc/L0/sN8cMcMR8Bbt3F45UUPyA+iuW7vUwfVkjrAZw3C1OJ
         ODsCXClYCxY7RT1W4Cu46/qjFFL8+/XT4lmX0ePCvlH3UMQSdbWvbCCkPtxITxmAEXfm
         +FMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QnHpD2/5G8nBf7RYxex7ZCPkjJMh3IfDIUDgzy28hLk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ao4KFCiM7stqsGlC7WTTM0pIWKaE5ACSenWSC7gWLLR2gszu2onGGWuRnUb44y+YQy
         HKzo06dnQLqC80pb/kKxs4Vcungql0VFlMy4O5vnaVA6y21uNA7Uu62n9F3vuj5RDmAS
         YhK51pJWMrnPwSLwmlSg6hxM04jhZXfSM1j/Nm6ICUH6MOfRm3ATHXphaEcZxP5Qwbt3
         Zoy0r9r8e5rj/ITjdRNU4fAkQaAFwiIfGQSugZkdDSewABM4G+J7ZOgOAz3tnN+QBkvp
         f9wsbG7l+uNuAUFzBRHQpqosCku99Rnp6YgnxjejGZ3Xjt7YT2Sgn2oNpvdhRgMyE3fB
         xlFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KOLMzVoP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id l20-20020ab01d94000000b007bfc3296157si854402uak.1.2023.11.21.14.02.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:42 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALL79FR001860;
	Tue, 21 Nov 2023 22:02:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a1a4y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:36 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLgHKi029220;
	Tue, 21 Nov 2023 22:02:36 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a1a42-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:36 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnSZD004663;
	Tue, 21 Nov 2023 22:02:34 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf7yykvh6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:34 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2V2l14942770
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:31 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8906F20065;
	Tue, 21 Nov 2023 22:02:31 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 21D2C2005A;
	Tue, 21 Nov 2023 22:02:30 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:30 +0000 (GMT)
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
Subject: [PATCH v2 15/33] kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
Date: Tue, 21 Nov 2023 23:01:09 +0100
Message-ID: <20231121220155.1217090-16-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 2TCo5LFGLjvBe_FNuSOp8ISqSS6rfXb4
X-Proofpoint-GUID: PizVCBmrtyUfaXPpBjtJCvjSHdm3Jo8r
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 impostorscore=0 phishscore=0 priorityscore=1501 bulkscore=0
 adultscore=0 mlxscore=0 spamscore=0 mlxlogscore=999 malwarescore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KOLMzVoP;       spf=pass (google.com:
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-16-iii%40linux.ibm.com.
