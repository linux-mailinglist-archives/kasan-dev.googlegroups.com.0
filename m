Return-Path: <kasan-dev+bncBCM3H26GVIOBBV6W2SVAMGQEOCBB65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 884E37ED215
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:33 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-6c7c69e4367sf94662b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080472; cv=pass;
        d=google.com; s=arc-20160816;
        b=0xcxcAuWgWRD/79teFw+BhlxUcGWyla5F0OZ7fSt96qV9ZPvzkvQhq73sz1Jl5gvE7
         IFHP0uvzWddmyax8c+3MQ1cOfjOH/R5YfqOz1fbXHQ6YO5A6t+alkuKCncbLTs05Jxme
         bG4dcKhe7TBExXmrA9dT/UdqJ5+Jir6YBWJ1RqKRLPsLmkXmt341Khu6rfVjQzQKz//j
         Fxc3GqC9o+ES/3lFWCrzL/pWxI8AeRpczcKH2359ZYG57ArThfYpEhm/ubtaONP9cfqj
         VWL79yF6o0i8jh0607CF4XZKd1hWpa0QPl5XkK/nOeKluZ4MqK/yjbPSO2UU3cj1Kh0O
         tNmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Wp15FlJpx/TOBg8VKqsZxjFuMtVEdl8gMd4WuAvKwCU=;
        fh=rr9aOGaxyzCIKap4dF0OG9XKBkjSWIKv3pUt54EDRpE=;
        b=mpI81B1sxPEvOHOQIcjgX1ooGksnZejfSaas0M03Ti5tsLyQ0STeRZaI+5WEEb4EVV
         z6DaZnxE6Ht0FpBO5+K8hWu7o94FEySk9BMoJH0syVqs5nAnDqvab1YNLvO7EXZaGDnl
         NZwKpmuyGslVKvKpFB16ESUgzpkrWgVoHDxwbJU7ZuleFPgR52cO6YE2oYDfpNwWKh+6
         xY+voKl1e2wOeuivi1QmcOX4NWIXyz3QvaC13pOvGf0Ey/PaWyO2RloUbHhx7GRsidB0
         tjGIJeA9IjWFQf0nH2IL8KL/tccgjJNZqgTeVZsGyvgWnDf0DLXeK2G83Pv0JYPVMmqu
         9UUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JKsnlmqY;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080472; x=1700685272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Wp15FlJpx/TOBg8VKqsZxjFuMtVEdl8gMd4WuAvKwCU=;
        b=bP6mnX6lkM6MbFdX+rPfeGqD4tHASPsv8I196P2RCMImPko316XTwoOyFbajfTCMPR
         geDTHJdXS/XWCs346Wi2liUv7cVLIbqd2mf7SY18A0oTFADGv5wH109jsTYPWrMSUCKw
         PZDMrBy5gncQC2LtDqfz1TuXkbk+0atML3VIcTaltOT7sL3SwZD/42vKv7HsKR8a69M1
         gFdA/b1qnPhxENI0/Wvo5FKhWehJ3qIXE8eeby6TsoM+d6nkCGHjo14YrmN4M/MJjaTW
         9V7BF01Uw22XmIiT1jC7jsjlgCFOoIdXlbBYHel3NPm1NYeiVr17Z94fPCW3OBnlMoJq
         fMOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080472; x=1700685272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Wp15FlJpx/TOBg8VKqsZxjFuMtVEdl8gMd4WuAvKwCU=;
        b=hWiPL7eEkMWQT8uJqHI0ogpk/iXg1PYIbrL5wmByU9F029B+tNolhXe8Cvr+SkEXXs
         dxWhKoi32YT+ltN3Ax7ObfIuLD5xt0gIbIeGwGl7C7IHVLD0dLyNrW2ik+Gkc1CrPomM
         RlgKZ1RYJbxpKT+goQCbiWfHY+ikSyVx9UJR+HY+ep0tNzaazOpzwlEffKU7DXFPvct1
         Id4Sp157eqG9DKvshA2BRZNTsMvP4lKvWS/1CvvdeOJe1+JtMY/ajJFoof0Yb3jAWD2m
         UU18yg5+tewZbLphB2BRfbjFAT0l030T89hGvdmXqHM1LlpFUNcuZYCuweI+crslhkwN
         ns/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyTgh0tEm+Kn3QXUOfoB6aZDTekkF8xfZ55h0hJYrR8rw+zYgp5
	L47FxrTv8hHeOFVRkZbRzQM=
X-Google-Smtp-Source: AGHT+IFSMiKI6gn2GMcroL3Cfgz3PFaDgGBYITqATT+Plx/lTQoW+bLil7T1og1fl5RUuFa8j+MW5w==
X-Received: by 2002:a05:6a20:3c91:b0:17b:3438:cf95 with SMTP id b17-20020a056a203c9100b0017b3438cf95mr13210416pzj.14.1700080472030;
        Wed, 15 Nov 2023 12:34:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:279e:b0:68a:47ec:f3f9 with SMTP id
 bd30-20020a056a00279e00b0068a47ecf3f9ls188051pfb.2.-pod-prod-05-us; Wed, 15
 Nov 2023 12:34:31 -0800 (PST)
X-Received: by 2002:a05:6a20:6a06:b0:187:8eca:8dc6 with SMTP id p6-20020a056a206a0600b001878eca8dc6mr1656805pzk.34.1700080471112;
        Wed, 15 Nov 2023 12:34:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080471; cv=none;
        d=google.com; s=arc-20160816;
        b=jSbOPxLpP7sxZDPgJJKBV8ehlhD++Dg1CZJgt7HWZ4Nh60rMYSUctl+sI2uzKF2y13
         c3i6bbdLRxxx2Ie33f+s7U0ICRiH0t17GRGaH0y9uMwlGgwYywLghwBQ5q85rkxcF0CJ
         SzyCp92R/r56Ux/heq6cn0gtUqiUKS9QmPwYmDs9nbK+7FI2hsGvl8KYF6Ns4DYh1MFJ
         LTM2cZnNvLOJnrDb0/25+T3EOxV3sJgyyj9KSyZ9HNdqCDqFZKm4kAmBFnYeQqH1t3Sq
         C50Q7KAOMAO7QZvJhXNo784BfV09RiPZViZBR4100PYfFVnx7dEeMo0BNFyjBqBG/RwK
         FU/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mBEHNMnK5aXgU11e7B7vZsvrm9vZAb+q2WVIriQE/Yo=;
        fh=rr9aOGaxyzCIKap4dF0OG9XKBkjSWIKv3pUt54EDRpE=;
        b=PRO0f4Krr3l1icfJ1LBgAJOkoE9oFt5W6PRWBlRXeDUJQIWi9rJQ8PVJm7ftdYQn92
         BQvqFWWRJNDzBX2Mxbf+0a+2A9SGjXadDUwuFTaZZWAj6qmBWjAY889xC0qpABkgBzqP
         eYI25w+lfV6SI2e2sKW72I62ruBO1qtTq+s1o9lM21EYyMskSzCL7DAWbjjx1lIFIyq0
         8XdnXVW5mA4PX34olJfYxvNiwIx89RnjBSIo6e1LVI0B2SC0M7IpLcBzNSz/sO23ocr3
         SjrcFTmz8p2bKPgZ0N/WJzgDvZDXej1dstRa6sA+cuYdKR28akW/fil6rO8fFiiNo3+n
         nLuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JKsnlmqY;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id fc31-20020a056a002e1f00b006c6b364ac74si558478pfb.1.2023.11.15.12.34.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:30 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFcUi004338;
	Wed, 15 Nov 2023 20:34:27 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v30cj4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:27 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKQKK8001965;
	Wed, 15 Nov 2023 20:34:26 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v30chr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:26 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIuc7014591;
	Wed, 15 Nov 2023 20:34:25 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvs6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:25 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYMHI28639758
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:22 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 496D420043;
	Wed, 15 Nov 2023 20:34:22 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E63E420040;
	Wed, 15 Nov 2023 20:34:20 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:20 +0000 (GMT)
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
        Ilya Leoshkevich <iii@linux.ibm.com>,
        Heiko Carstens <hca@linux.ibm.com>
Subject: [PATCH 08/32] kmsan: Remove an x86-specific #include from kmsan.h
Date: Wed, 15 Nov 2023 21:30:40 +0100
Message-ID: <20231115203401.2495875-9-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 8cX32G095gCIm8Y6i1Z-p6hF-gO7JK8X
X-Proofpoint-ORIG-GUID: 6fvVE8Mcwxt4i9yfIY7fICgUPY6nXNrE
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 spamscore=0 priorityscore=1501 bulkscore=0 phishscore=0 clxscore=1015
 malwarescore=0 mlxscore=0 adultscore=0 impostorscore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=JKsnlmqY;       spf=pass (google.com:
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

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index a14744205435..3c0476d8b765 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -10,7 +10,7 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
+#include <linux/pgtable.h>
 #include <linux/irqflags.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-9-iii%40linux.ibm.com.
