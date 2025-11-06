Return-Path: <kasan-dev+bncBDXL53XAZIGBBK4QWPEAMGQEY4CXGVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6873EC3C439
	for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 17:09:17 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-88050708ac2sf527706d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 08:09:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762445356; cv=pass;
        d=google.com; s=arc-20240605;
        b=jMaQ4ks7OLIABK2IzKE85t5QQV/RrpKP4dU+PRuEGn/Z19xnUgNiSPFvRs/oK6Jmil
         CHiYzf0biWKA7XtGFNFT5wJwHETu3vOSG2kU/aLjjuJL2pfKCYOQ4wJJfILXZJKJIHaY
         dUxgS4M2vTyfR0+MM/3ff6H28vZrgOwvS3b9pTB1tiQJmPkdL/8++0tWh+yYZW3QegqK
         e9MaKifdEoGC3eHuxeqA1EcaIFnFPNCCXunkb51JYlJaRwYk2Q8yvDFuU7yhKeLt8u9C
         PCm3afHNjvmh8agSFm9sx64yw3KFOqz8QIkdiIAoL08OuYJB74HbwfqrC6FDyenSQKQ2
         Ubvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tCNTAFS7OJal+623cpiDhBF+mVI5+kuh2yIABSFV16M=;
        fh=7vcjC4eqGL0EQrDYwJf8jC240FlVsi5ElyMphJubhM8=;
        b=AQsK5odf8c6vkelDrgAnOGeNqNWG88sMBhdjePZ0iZDLrvBv7vZ+gnQVJiiQiKSscb
         2lmZcpRZ8tkaB+KNx0qaer0bdhk3NJT/zHkL+skUaOjo2mkS2r03VJc43jMlwN2IrbV9
         ITTkY0zg0a3ZB0ATwTD1GRA3xyITjWlA35BmMqMswCG8ey95aOe6QtDdf6hI2lcOVL8b
         hUsrHGm3Eg9MeTdip/96UUnw2lQ+6X8ZnvEo2lvdYaeBaJwEQRajU9ND3ZQnJytsIPs9
         frGpykcUfrGmbjCDCiNvUa16fdvfdA+Pd+LVybIrc8gQP1L7rdrD1taxMIsK1HGaY+6x
         elWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Zh8XAC1V;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762445356; x=1763050156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tCNTAFS7OJal+623cpiDhBF+mVI5+kuh2yIABSFV16M=;
        b=wRoWzqKdWROjtu68ENE+SlAG1lV6mCgxgIAVz/IW19f8/feqHGVzh/vjd26AQjBEHZ
         7FpA0beGpq1/LPVnj9SOLyWHb7zZDk9HOz1gUVpp172dYkjGGbljLHFvK7qbQaOx4pDz
         XkJrZY1wUiEmCgJCJmfXoK6UOkxN8B1GSKeK1oxSiz6gZIbeF3iRFsgOcRBXXsaDe2zl
         U06UjQmO0tDExD/IHqu9DaDsytZKRscnkkHeyaZD2HFlqw/5Tw9umFoSb+HoMr5PLQwR
         fmIFBWLOzjNZwcZgrVAkwYPA33jBmhnxREVoXgwa1tNnobYTvk7faSEaJwFc+zkau76M
         +TeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762445356; x=1763050156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tCNTAFS7OJal+623cpiDhBF+mVI5+kuh2yIABSFV16M=;
        b=uXK1pnlEPT8rTe2MfTs50JNSWJneKRj90uwSKDWi74TMH4kCZyJ5lSQtPlefWQf5TG
         hMMEEdeZNXpTR5b0PBtI1C5528L0rA+qvhrEChnzo0DtC/4IBP4Hha1bEyJXnklzPhxJ
         wAmdRGt9cXE3HPqOssXB6jEY8W2A2olXHnPHsRNrYd+wpE1Teeh61ye+Vx2XRYCcUSQN
         il8X3Ja2gf2EQJpn/89WHUxyqwFPdZNfDCaU4J5l6s8g/Ui0oBHRTvbOC4fLFdZpKLWO
         JzeTyOmTGq20+lGpQ/4ClbAHxmu8JzREqDwS+TbumSCQs3ur0cfAsvrv7PTmiXmuL6qo
         Jejw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVA4rHyIfsqlxgQ+XrhufOY0K7iIZyz0JFcHhnzxKMbR221zXTtdvltV2e33VXpsZgyTvHkmQ==@lfdr.de
X-Gm-Message-State: AOJu0YxeAcx6tb5XTnqYOdPfw48r6FQqX1+gHWd0PagtAVdMGaIeO5sk
	gLoZ5uCSy7BM8gWcUy0uAnSu2LzdR5tPGYXJPyJD8dWtATbJiOOpk7HA
X-Google-Smtp-Source: AGHT+IH0QJeqtbwmJ73K+QlDuZyRp9SKBMq8PP5fVYuOwoZhVXqpoiVHau6cfOCJpFv2ILiXsALxBw==
X-Received: by 2002:a05:6214:202c:b0:790:3b37:8ec6 with SMTP id 6a1803df08f44-88167afd03dmr513676d6.13.1762445355567;
        Thu, 06 Nov 2025 08:09:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YnHnLaiAi3aviN2ywJvhKX4olpPW2VycB/bKamROFf8w=="
Received: by 2002:a05:6214:300f:b0:880:59ee:ba5 with SMTP id
 6a1803df08f44-88082eef318ls10175266d6.1.-pod-prod-02-us; Thu, 06 Nov 2025
 08:09:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUWfBxVDZcNjsTUz+LYmNa1Kq7vrtcfTfBagRMRek2V7lnGpLBJjBJSoVAd6NjaTMP3Z/ZHtfDQhx8=@googlegroups.com
X-Received: by 2002:ad4:5fc5:0:b0:880:501f:608 with SMTP id 6a1803df08f44-88071192336mr103284566d6.46.1762445354266;
        Thu, 06 Nov 2025 08:09:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762445354; cv=none;
        d=google.com; s=arc-20240605;
        b=gOT8Wv6K0+1Buxnod4pWi+He/1/3Ho3CmcTeLSfGmzKkyKaxu/TGBh3pemqK6ODwlW
         BMtISBwyHbI6X95tbqA1ltYBRqixkpVeFzzjESPUmqJx+0VnHo3Un9G+De/XBiYJTBmv
         WQZQsQwAAjITHHriQQOLl9ZGQYyIGSl0SC9XHKHH6ej0JUm9GRvn7eGfdegLnZhGaN8h
         Mw4wE/5Zk3CJ58vJa9Gm0b/jDsqEh1LBB5WDD4RV8siB3pyrR26iRcavG70vanEs2juf
         yiGgqyMmfgMGScduLGCUjM7JLKRYlnTXN7PT5VV5Qrp3zw3ThfuPRCvfLpUVJYPvTP1v
         nJ+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VjZfltUSwZHxE+uDUdhq3CJlPnh5lohyju6CeAaqcrc=;
        fh=05xDZPCJVkot3PeIiD3W9iaPvWiXB7vxfuBVYOsVC1c=;
        b=fAwl5B0dc9meynop1A72lUAS/eC2zhjPTSOkr5YRECG8LIvhqbsje+H8dWnqPjnwGE
         kSB3XFtAmtE/g5kLVvO3GRkHne36qv98xNrgY9Wi66ayozPkv2X7Llsa0CFGGiOWipS/
         giMDYk8XD8iR901DltC1FuccsrIOEl4lH1kaUaHPhC80EZWoGV7TO/qGu2H2GXntxPLJ
         Y31W44/SgFITu+xXM9vOPIAN8g3p+rxICjWOpRJKO8ixH/bdsjGOEmaofZ/W1e+uJTo+
         mCUAXNhco/4mVuOL0dNnVG/GaYX9FL/CKTbR/CGgLn+DNqz1Bl6w2MkefKcr5wrx+h7Z
         9D2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Zh8XAC1V;
       spf=pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-880828c2f7esi1684656d6.1.2025.11.06.08.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Nov 2025 08:09:14 -0800 (PST)
Received-SPF: pass (google.com: domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5A67KHRN023521;
	Thu, 6 Nov 2025 16:09:13 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a59q986sk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 06 Nov 2025 16:09:12 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 5A6FxXs0008061;
	Thu, 6 Nov 2025 16:09:12 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 4a59q986sg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 06 Nov 2025 16:09:12 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 5A6EwLJB025557;
	Thu, 6 Nov 2025 16:09:11 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 4a5vhsxh26-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 06 Nov 2025 16:09:10 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 5A6G97qS51249586
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 6 Nov 2025 16:09:07 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 468EE20040;
	Thu,  6 Nov 2025 16:09:07 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6459120043;
	Thu,  6 Nov 2025 16:09:06 +0000 (GMT)
Received: from li-26e6d1cc-3485-11b2-a85c-83dbc1845c5e.ibm.com.com (unknown [9.111.24.158])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu,  6 Nov 2025 16:09:06 +0000 (GMT)
From: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
        linux-mm@kvack.org, linux-kernel@vger.kernel.org,
        linux-s390@vger.kernel.org, Heiko Carstens <hca@linux.ibm.com>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>,
        Juergen Christ <jchrist@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>,
        Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Subject: [PATCH 1/2] instrumented.h: Add function instrument_write_after
Date: Thu,  6 Nov 2025 17:08:46 +0100
Message-ID: <20251106160845.1334274-4-aleksei.nikiforov@linux.ibm.com>
X-Mailer: git-send-email 2.43.7
In-Reply-To: <20251106160845.1334274-2-aleksei.nikiforov@linux.ibm.com>
References: <20251106160845.1334274-2-aleksei.nikiforov@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=StmdKfO0 c=1 sm=1 tr=0 ts=690cc828 cx=c_pps
 a=bLidbwmWQ0KltjZqbj+ezA==:117 a=bLidbwmWQ0KltjZqbj+ezA==:17
 a=6UeiqGixMTsA:10 a=VkNPw1HP01LnGYTKEx00:22 a=VnNF1IyMAAAA:8
 a=KOBABV2IKOkdypTAImUA:9 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-ORIG-GUID: wsqpo0y6lQa7s9mUgKxY6TctUwToHVni
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTAxMDAxOCBTYWx0ZWRfX7jgjMaG+XyZ8
 mThr2JYAcbWr0jgLh7hdJxD6YOimrAM+XG5dJiU0u4CPphdKdoI7caEJL71U/VpnjotTaZtOnbd
 OcJg9y1xzEnJD+Ehkgrp/+e7d6B/l4RUwFbplfBctghdzgVEFdn+ZjfHnVLWkOpZCoYPeBlVjsA
 UDpfU90jbCNps5+SnuacrBu8RsktfOxDycQidVkiOPOKJR8emqoKBiG4x3cix3ytROGpbJHdaxX
 nJvWGhbiWr6n+zsh3DjqhIxyKwbdxzg5aJG1jHTRy5bC2jjbLexTu4Mmv24mAoQQ1tERVkwtPvD
 bNo7Q4iQr9Cg8DvV+DWYcBNBD2GwjpfwlmykT1WdjoatAzkaddngjw4I1ybTFOiE74ZyJoEPIV/
 EuS2J9r3JLpENr1OdNdyGp+G8o8ypQ==
X-Proofpoint-GUID: RQXdUhJfyyG6VwdC6vI3fgqe0m3GUW_M
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-06_03,2025-11-06_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 spamscore=0 suspectscore=0 phishscore=0 impostorscore=0 priorityscore=1501
 malwarescore=0 clxscore=1015 adultscore=0 bulkscore=0 lowpriorityscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2510240000 definitions=main-2511010018
X-Original-Sender: aleksei.nikiforov@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Zh8XAC1V;       spf=pass (google.com:
 domain of aleksei.nikiforov@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=aleksei.nikiforov@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

clang generates call to __msan_instrument_asm_store with size calculated
based on inline asm constraints. It looks like there's no way to properly
write constraint for var-size memory write and make clang generate
__msan_instrument_asm_store call based on runtime-obtained size.

Implement instrument_write_after similar to instrument_write and
instrument_copy_from_user_after to manually fix kmsan behaviour
in such cases.

Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
---
 include/linux/instrumented.h | 14 ++++++++++++++
 1 file changed, 14 insertions(+)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 711a1f0d1a73..a498d914a8b0 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -41,6 +41,20 @@ static __always_inline void instrument_write(const volatile void *v, size_t size
 	kcsan_check_write(v, size);
 }
 
+/**
+ * instrument_write_after - instrument regular write access
+ * @v: address of access
+ * @size: size of access
+ *
+ * Instrument a regular write access. The instrumentation should be inserted
+ * after the actual write happens.
+ */
+static __always_inline void instrument_write_after(const volatile void *v,
+						   size_t size)
+{
+	kmsan_unpoison_memory((const void *)v, size);
+}
+
 /**
  * instrument_read_write - instrument regular read-write access
  * @v: address of access
-- 
2.43.7

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251106160845.1334274-4-aleksei.nikiforov%40linux.ibm.com.
