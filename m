Return-Path: <kasan-dev+bncBCM3H26GVIOBBBGS6SVAMGQECV5266A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E3A717F3897
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:45 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-58a8142a7a7sf6068081eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604164; cv=pass;
        d=google.com; s=arc-20160816;
        b=IF0kkssq1QHq8dlOQsDNg+izOg0zGwBJHGy2nONcPKfKbWeDpEcPH/vryhWwCyYn3k
         oh8aUCav6ou5zvCX1rXNQI1xmxw2FTcdbj6E07mnPtuVfAUsBJlH6Wbb3yCwfTTxFSOL
         sMk2pwQ7hIu9tFZIx7V3/DekLlkj+ujo0a52F+wViay5mZVClYvNe5pFxW6EBwYkQ+L/
         QRjzFoPcUQ4ahNBQccGY2jC2NY1zo1/6DbZ92hBEPC7+oQI8UoQOdKcYLEzhgQtoSXoZ
         XhpvSVmdj4TbgP/LDizlgXWjZNLHwhulre2tUT3Iw5/WO7sCuGQNvo9+5gZdre4xBMxo
         rN2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AJLJBRySV2fOHOzQCFT1fWopbVaJBdb6dXKlrphc55A=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=r7+HpqOeBnGcZWwTX2GEZ54wstJ0AoTKafrZlPwPkwZI38kskdSSViB7/wQWRSrFET
         XMUDjur71QVkxia9LV9AnhJ5TICcQzOwZMmupvwn4uis/ssTvAmhx7awUlMu8CHaYO+U
         yeHPE8TEcc47G6B5kC0+hvjswza09zROysKtL2WMeZbW7d2Lhe7DQ4jEGboDANkd0vLU
         y1z2JN/q4DkNGtAsUcMHnatgKzZet5gXcWtphTd/1wfJCOTAlhlCk1S5yA9G3v2qjcbF
         mHcGI/+riqURKc1l9a1kCIDALp9PM3Tg33ek0ilTu3laMqHYh268KFdPPFfjFieKbIBo
         f/iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=E0uJNgWO;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604164; x=1701208964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AJLJBRySV2fOHOzQCFT1fWopbVaJBdb6dXKlrphc55A=;
        b=k19Ye0/IpsH30vjKCelGmaGogHLsbOuo6QihesxWvU7cuPH9DaU+VAsOOvWeUVIPNj
         b2RNlYBVsf+uk3Ay4Yv4XYRL+cKTtyVfz03xVCveDLrgUs+BL/0cL298KM8ZgHj2iMfT
         XNEMe3pqNl+efS3KToh8EBBMvv7r2W4TGjKgxMvKo/ODTLHArdrZqeReho3hSAOIS1s3
         gcpxnPAS+3tNHBdBhqkjNaT3FvyNVjeLTGIjaUl5tkDa708dwevskjKE9/G70wOvXc8W
         mcGSVFUiLfKNV33ZZmgvPEJ/WulPN8m+4CaFZYZYGsvhx9vPLCy9bAkoNneOMkdLI37q
         8B9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604164; x=1701208964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AJLJBRySV2fOHOzQCFT1fWopbVaJBdb6dXKlrphc55A=;
        b=vEGhH6iJx4vInlsz5jdlxWdRYSGLcFpq1F4EK7Yy3z3HHytEG6e8sHapl0o4YLxWG6
         HkqlLkTBwFa7BjIiWvv2Ca9TxCSvRLkPImYnpueNURvN7nOtsbZXD94sE6X0JfhZcK7I
         vRFftZpKkUwsyHyT4OVDu1q++14f3Vd54J/E70ifM5Agf+RHkqFfTPRC9kmZADHViUnm
         EmQ2oVTGsRK/FCP7xbkNlDHZRHVy+oDsPIuXXi9SJMhap8sCCVGgP57lmc0SvIHMKoJO
         nviESup9C8nC2V3KVNa65IiQaP+hlc59Ngnvh3T7isIYOUWuQS7lv1Er3FGLmAGcEX38
         JQIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwtLhR1Tm6ZgRzL8tx/e+5NDq4LUE66eRZJRfcOx5XxMMb23ADs
	1/AwMcqnIBWLl+bN/8Y2EJ8=
X-Google-Smtp-Source: AGHT+IGq3ZKORRZlw15X26wCHGxWm0Gs8nYQYx3yWpTFZhP8dq3i+4Lkn06vkjY/vGoNUYvt3Mlvmw==
X-Received: by 2002:a05:6820:613:b0:587:992d:48a with SMTP id e19-20020a056820061300b00587992d048amr807011oow.1.1700604164762;
        Tue, 21 Nov 2023 14:02:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5507:0:b0:586:ac7a:39b4 with SMTP id e7-20020a4a5507000000b00586ac7a39b4ls516015oob.1.-pod-prod-02-us;
 Tue, 21 Nov 2023 14:02:44 -0800 (PST)
X-Received: by 2002:a05:6830:3b8e:b0:6ce:2789:7195 with SMTP id dm14-20020a0568303b8e00b006ce27897195mr612508otb.31.1700604164135;
        Tue, 21 Nov 2023 14:02:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604164; cv=none;
        d=google.com; s=arc-20160816;
        b=pYaZjgL5aQ6vHMjlggPG22g/CUAKGAGsKJVeBOmha88ygNGYAr7qzQ0ZJw9zFHPtz5
         CXD3hqfyGPi6akjtxtPJh2aSCnkriWQ+TAt9QSkaurUrRXcpdyupAqlMt7idFtrCh8KY
         2C0Erwj46677fnn45ygC8xoJnJi2m95LW1VMG1f9NjtXP8IMHdYGyVB51bH3FkDgLdf3
         eA9ZXxHxlsWWDXLAwqr9UVgNmDqWwn0KGqOm/3ZHCiwymeDwTFply9HjYSpQyU5URDjb
         WUJ2/+H2FLyS0Nm6u2CukKUuAb/kfvyKlY0g5VkWXVR2lYRMFg2DeVTRuVNoIzj/+sJs
         nxNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ll1jVWIn1WYeqe7oeR3JXJSFtnz9SYnx4hK39Q+YxwE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=OtgBxQ7YbPfVPTV4lwgViM3gsR+ggAHy2yqz8bDXIkRT2DmRxR9AjjG6JQxnG6fX3i
         2Eb5PQjw7cLC6JVjkvtJdusnsawlfQNSUUBdTWEeww8LUaUBsG7JAB0IeSCYRuMv+p/Q
         6b0KLOT6J92tmyOcudrqph3o9Bp+ZmZCUpodS4zFmMvmgbAGbYPmApoNMAcEcHVXpi/B
         kPZuhf5eiW1x5CfqXrWg1bP2spKAEMLM0JfeycbZgXKOs1pmRGfjp9KG6slIh05AH5X/
         gKD5xzOz5GvkRGS12JU4wr6GKBwXHkPTn1xkCnMLjLuatlxyV1zNECYjDzUgQh2DIxtV
         zN4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=E0uJNgWO;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id cr24-20020a056830671800b006ce2f207148si1715829otb.0.2023.11.21.14.02.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:44 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLlNiq020065;
	Tue, 21 Nov 2023 22:02:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68bs8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:39 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLo524026845;
	Tue, 21 Nov 2023 22:02:38 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68br7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:38 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnYv6010672;
	Tue, 21 Nov 2023 22:02:36 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujr7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:36 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2Xf814877208
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:33 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 71D6720067;
	Tue, 21 Nov 2023 22:02:33 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0A6F220063;
	Tue, 21 Nov 2023 22:02:32 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:31 +0000 (GMT)
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
Subject: [PATCH v2 16/33] mm: slub: Let KMSAN access metadata
Date: Tue, 21 Nov 2023 23:01:10 +0100
Message-ID: <20231121220155.1217090-17-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: Kr3chWIa4VLpaiM7it2xt72zkEIATI76
X-Proofpoint-GUID: o0Elbdg3uNB8jhs-NEltJ60ebAxZlMmP
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0
 priorityscore=1501 spamscore=0 impostorscore=0 mlxlogscore=999 bulkscore=0
 mlxscore=0 malwarescore=0 adultscore=0 phishscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=E0uJNgWO;       spf=pass (google.com:
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

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
KMSAN to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable()
and metadata_access_disable() functions to KMSAN.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index 169e5f645ea8..6e61c27951a4 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -700,10 +700,12 @@ static int disable_higher_order_debug;
 static inline void metadata_access_enable(void)
 {
 	kasan_disable_current();
+	kmsan_disable_current();
 }
 
 static inline void metadata_access_disable(void)
 {
+	kmsan_enable_current();
 	kasan_enable_current();
 }
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-17-iii%40linux.ibm.com.
