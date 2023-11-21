Return-Path: <kasan-dev+bncBCM3H26GVIOBBFWS6SVAMGQEZ4SDAHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE1517F38A9
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:04 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-28516109204sf3780760a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604183; cv=pass;
        d=google.com; s=arc-20160816;
        b=GOVFsABUKqlEs21Wu6vJHDdr+f7QyNCkL61zjaVJxW9MjT0IINaWWf2vpWMLAIkAjB
         EI4sjd1ieHx8r99Og6/KkTc5e6D1OodRZZUag8cZEfJzoml9TPkW858Jj6M9MGTR3OIT
         yuHISz8Htk4508888GDpYXNVZQZrWpN3J/bqWrZc3mAFsiBZK/ZY511hiTKKOFvgklzK
         s0Vs6LWxhjmHzxvhmIz7d95O76WN1g+n3UQSp2+xygx8Zw4jfBTyS7OwPe/eINQRwaQ3
         axC9i2R+fk90Unx4FdND6XUGUN+ssmwk9vKAxk7J14I5A4UN526rqgldaITd6MLfwkle
         88+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q6nwTmW3wY4qnWSRG8VDc4oG+0epEtlCIvzlFomytBQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vubP7zfB7z8lOJVnkAcZBC/ymQR8PcUVzlOX5ecFH/BDTaWh5edO7MV4MZSOlSEZpj
         ZMpyZ6KoQD3r9m4YF4UqEbPRwguL5dOCdaE7uc/AYGgu1BsdrhIgzChMQTEqyljQZxtb
         EEEMBDszlIt+aRrbUdogmhnVS9MWzPjkdd+ESzUS9g9IZ2lO1xJO4/RLf0d0U2Yw1ey7
         jzlUEdH3zpC3i8ZdRAbTnEZUkQuDBEbQgW96wo4xdOl0XLtnLOB/sR6iplhO7Bo+rxx3
         8WjSZKi6fTFeh7xzQfRV68a7Jq8QRe2NrlpoMBgfo+Vmk74XHmQixva+3peHbRCPcii2
         /+Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cSUECP3/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604183; x=1701208983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q6nwTmW3wY4qnWSRG8VDc4oG+0epEtlCIvzlFomytBQ=;
        b=mN7rPaK+mMxtWJPDvUX4oTikJTFAatwetHcbKiXwgxtPf0BWEhHW+jEpyzXh6OKIwC
         OzhD2RFQtzzs6kApU6WDR7mnp8+IMdcD2sGmcHlrtf28hChfdoqUH8HSIb6HmkuU1Ivo
         /jgSEKFntV0jey7ATdGMWj/xWSzHpeibuTZB3rc1cPZhxXB5KbxWo/m5Idt/Ad5lBBMx
         qw51yviJaKASXjn9O5Cen5363tKFxO/vGo+191Xk4DkRdS3fZf/uY/S4QboTJ3MBr53Y
         aJY7m/a/SeMQMkBlSqWWHL9KuTrIFuPJimgPndDzQl6eeNlTOJUNX3RPDf4T7j/tUZ4g
         z7pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604183; x=1701208983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q6nwTmW3wY4qnWSRG8VDc4oG+0epEtlCIvzlFomytBQ=;
        b=IGa14aAEeJqAOgkiNikPWYhUCi2U/OSiBu1Vg5RzhmMikCFWx69wYRHz9YKGi9zKVu
         8oonY3eP5vLtjqG7nBhQ2zN0Gll9gBQ83V/tscWLuu8h39A88hF06rWjXRsDp2uO6LAL
         Y+DFk1tPUYdsk7QnqHtLnbQwmZ0nFBOQyGrnGaqj137iYYpEEIylUjw4ulxLQvX2JQ0n
         DIGcWLdwVBFOIsL651QWIvVA5WYaU3r40Iv+v9k8xib/qc/AeJ+TgVEqxpBTFvr3cGl7
         PTFRPNeRSHjItN4SlxcjqPFYyk3KRkL9z7cEWKmIfahM2g6kbaRknlRsMuN55Ed1Vzt8
         LL/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzTg9Crdq4Mc20udCEQz/ao+1c0A/OWynzVz3Cq5ciFCKXi1X/0
	6eaVm1V7YsFeMrJGPIG6cd8=
X-Google-Smtp-Source: AGHT+IGAnwLz5XNIy3D5de+5Hya7KQBvnh3frqNarxXJ+CUwNWtisSdgr03ipwIOZ9wPy/Z61/+RMA==
X-Received: by 2002:a17:90b:4a8b:b0:280:8544:42fb with SMTP id lp11-20020a17090b4a8b00b00280854442fbmr623327pjb.17.1700604183386;
        Tue, 21 Nov 2023 14:03:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a897:b0:280:2219:a6d3 with SMTP id
 h23-20020a17090aa89700b002802219a6d3ls4825073pjq.2.-pod-prod-01-us; Tue, 21
 Nov 2023 14:03:02 -0800 (PST)
X-Received: by 2002:a05:6a21:8187:b0:188:39e:9054 with SMTP id pd7-20020a056a21818700b00188039e9054mr372433pzb.6.1700604181627;
        Tue, 21 Nov 2023 14:03:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604181; cv=none;
        d=google.com; s=arc-20160816;
        b=BJ/4PMlugRr31Mc0NWs1vCPPKj2q+gJvgs9x71Y+BoGXoAu0qjluHVmzU/SavOPFj3
         HnkmiPfS2+kPJesxllaHsAMt+FVFwkoxZePnCZAU2I2g72NFIeBNvsvhKbtmaUNmJW9v
         QwK0bSTg+UUkIu5pdPK0ZGSiFwEIZDPhF6nLFMUhMn3JbP3tVmPk9XK+FMPRBrQItZs/
         qk7vhESw84aYhzXhYtiD3zoFUuMswA3fQOjCSbbgskliwRPN7o2XtivbUwgcrNQQ3Cbd
         O48VORW+srNXQJg3OapcmPxKHlDVudNHc2Yvg4OjxPyRzO3maQNqckDmazrHdqiRPTHJ
         EvfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6cPRly3Y0R+ewW/cAplLp4HHPc78tqbgSvA9QXIrbXE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=T2KsKbrAt7QzrMfFyrDP9guDOhenRoG6LAIHH1MeZDWVoFalSSrmW9hx3soojYgf7h
         HAIWzdzBqTbg/QcwAVnjhJw2YmG2oFrvdj+Tp6tB7qTZKv2AvFRUM9THY9L5AAOBo6zq
         CxpHmXPc+nT7ah4VL8gEWFRNZB9bOUy9MUMZ+dh45zkE1KW4cWhoWJolysH+XPO0GhP+
         WgbRoBaKfD7jMw/o4WwbYM0GAHmFWE+5Aa+UPUXq1O4BwOjkQniM6s7eP5z+rRsqL3bE
         woDiCWHJQRpePDHr/IVCLEbOuK7B67a4Zpe4FXNJoU3DYOzR34jP+6KjOo+cJrVhO48m
         piAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="cSUECP3/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u13-20020a63470d000000b005c220d4fc0csi452055pga.2.2023.11.21.14.03.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:01 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLv3Hv004850;
	Tue, 21 Nov 2023 22:02:57 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85m3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:57 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLwGcc007922;
	Tue, 21 Nov 2023 22:02:56 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85jv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:56 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnH8t007583;
	Tue, 21 Nov 2023 22:02:54 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf8knuq5v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:54 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2peQ38797748
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:51 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 29D0C20065;
	Tue, 21 Nov 2023 22:02:51 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A629020063;
	Tue, 21 Nov 2023 22:02:49 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:49 +0000 (GMT)
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
Subject: [PATCH v2 25/33] s390/cpacf: Unpoison the results of cpacf_trng()
Date: Tue, 21 Nov 2023 23:01:19 +0100
Message-ID: <20231121220155.1217090-26-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 4wGsEei1adE6EAeSSPCgAcoSTHesl0xI
X-Proofpoint-ORIG-GUID: XlcEUetpo-dhFdRyXdztfF-8Z86qF_LJ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 priorityscore=1501 suspectscore=0 adultscore=0 malwarescore=0
 impostorscore=0 mlxscore=0 bulkscore=0 phishscore=0 clxscore=1015
 spamscore=0 mlxlogscore=755 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="cSUECP3/";       spf=pass
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

Prevent KMSAN from complaining about buffers filled by cpacf_trng()
being uninitialized.

Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpacf.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/cpacf.h b/arch/s390/include/asm/cpacf.h
index b378e2b57ad8..a72b92770c4b 100644
--- a/arch/s390/include/asm/cpacf.h
+++ b/arch/s390/include/asm/cpacf.h
@@ -473,6 +473,8 @@ static inline void cpacf_trng(u8 *ucbuf, unsigned long ucbuf_len,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-26-iii%40linux.ibm.com.
