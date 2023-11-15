Return-Path: <kasan-dev+bncBCM3H26GVIOBBTGW2SVAMGQECM55AGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 459A77ED20B
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:22 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3594fa6ef2esf110345ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080461; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmisbazNUy7faF6wVyekM9VDpAwXClxDWYirjzBhM6LUJlX93AF6632i5VS0BgkNNf
         qnyToQYmufZQXZRzPwhCMxWlMT+O9f4tupC39y3MFXLe9Geeyua2/TbXfr/kKEyXOzT5
         S9lhHWuMgre4BwDRRgEUXIT1ngDcQ5nbO0DDF25NGtJ5Q12rd7tm0CzLomTr/Bmbb8zz
         aCtx97zeP9fEUVdqMWWuX5Rwofb0c4pr59sUdaDnk3rEkdIMmmTjc+/qqRQXstdZEd/1
         BetXUzmDSbhwtNpmke3SZbkhspySrXzkDJeealSZg1OFab9CCHQsDIvLkqEQU5twD32I
         obaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QqASwZ9a5+CeBf0RunyhO9VfhR3f1oPMwarFpUMrQI0=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=Rqb5DzzbStyi4nhuJRO3EnS5o1eHuVYRnjiCDVfX5DmrsWjjDA5Ct6mR1yIZPLlnbu
         mM+QkhgYW40ZQTIn+1y7rVaa9sHtS6TMConehD2NFKy7tPkH0NSmsgHaP0IA6UbL2+Ws
         h8SIj/NZ5h04hNSlIjw7lBbGNPK5TDwDoC1cCRjnQ3GDGOcpEho+xyRL7HcH+40iocON
         sZk44VhV+Dt2uUb2clCT/udQKHjO6ttX7ptv3jGeyKaC8VbEkDPklu+InTPmuUVu0gLI
         ojQ8qLmZ4Kp6VHSa/X2Ylrofs7i9PUXYkh2dwX3u7cmBTtriF/GpVrJ75kQnqolmOpuh
         YBZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Wy5tAH2Y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080461; x=1700685261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QqASwZ9a5+CeBf0RunyhO9VfhR3f1oPMwarFpUMrQI0=;
        b=XoKYxLrLsET7n/dooMYnnudTcc/ritavAh819TrScliKHpIMA1wmtajSP/xDZGY8y+
         +EoKC3ztecN0D4F3xC6xXCEbt6cRYG+dmda0XGONL/Vw+80DN/zadCq+QFeTc5tu6Xp1
         1sqbiCR2jQokvEGgs8Zt6gXW0ikzHy4C2AhDqgMa7Fh0BgZY7+PMs5i+n2bebAD2q6ZW
         s6RE/Rcmy2t+Hy+JqEN2QnNJ9tBzVPwbGbWSrnWpMbT17LrPYHqXt80403rfL0POFUky
         pq5QQRQ1a1K6ZOarh6gmZTtb8/Wc1EZGw8hcee/kiURUUTMaMbxTxYO42ICpwaadpU9Y
         t+kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080461; x=1700685261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QqASwZ9a5+CeBf0RunyhO9VfhR3f1oPMwarFpUMrQI0=;
        b=rXFMWG13J78uy4xmktML7C9t73v0RimFmfNaW7N+/QRmQgYetoWvFPrNkgX8oKKyL/
         tVwz1oBmYB9BQrT7F0gfMxfDoz5J1Vp4d6kZaU4vWwg94J3155KTE+JhPV3OpzQNHS2B
         cV6FvdL96gd+c15hOiL1X+Rm+kkmiVDBXJzBHUfgZgAC6mf0WE9pBGP1pbm8rrzqzmPV
         9PhCDa8b/GQgdNbw4ZHZX3it0bD9clyJ6poSuq4c0Fdje/3OkZL2jNGHtCuV9+zunTFT
         fLJ5mskAX2G87XD/U8t3A+eOmiba2akmHYwu8gjCEB1KZ/Z1c0E+hoIqOgbVXrdHI7Np
         csKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyVLxBocdX0YusuNFe2jmsLFRyKwdGht1sRBBkTQnitFMQZW7A3
	fY6Z9zTezh1JMt+cIqVzkD8=
X-Google-Smtp-Source: AGHT+IFgEXj0FqpE0q9MmHg00phimeh1l5GRZxSvq3OwdSpKe1hWXFzRiRBqXSe/Q4eyXhJcDe9dyg==
X-Received: by 2002:a05:6e02:1ca1:b0:34f:da0c:e1c5 with SMTP id x1-20020a056e021ca100b0034fda0ce1c5mr13025ill.24.1700080460755;
        Wed, 15 Nov 2023 12:34:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:cd10:0:b0:359:4f82:4931 with SMTP id z16-20020a92cd10000000b003594f824931ls68842iln.0.-pod-prod-00-us;
 Wed, 15 Nov 2023 12:34:20 -0800 (PST)
X-Received: by 2002:a92:d9c3:0:b0:357:9ea1:ed94 with SMTP id n3-20020a92d9c3000000b003579ea1ed94mr6371066ilq.16.1700080460006;
        Wed, 15 Nov 2023 12:34:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080459; cv=none;
        d=google.com; s=arc-20160816;
        b=h6A5Q1lpOyIrI62eqgksShR5V2ngNFr9Sl6qElj/xDCQUPyM7+ESgeUMUGsgGHAB7p
         tUHj9wqxg5t/xRpHrqh2ZLut3Jd+9vT/ffaiENHUvirIQG05ECdpEeW8eD778RRRDBXG
         hutd8oLe4GWEzXCeHOIM0OJOKbwLBMxbpEoCslkvdLw1Hgh4RAQYkcD4goULpqReHS2C
         A5OJv+oQom/aiLL/RFPm6jN/nQR8PMp6tE2PshNTZ337NKrUDnuSaad5IdaSmJNRJzi2
         DxkcOAPTPj7ZtBEJbI3dQFG/GaI5mjQGSr5RCl160Yx/kCIZ6upg31ylzyV1eGh6xeEI
         iPuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CZLHkQEJKjMWj9tFsHKzWIaMVL7MbTldFAitesNVJzU=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=ONcsX2ZkKa7LWZRnZIfXTbGAkIgt6sE8QwNxlpYtBne+YG/LJi3a2D2MDhFEJ8cO13
         zCWnAuPvVtOITCR8+/OpUAK96m+mhL280W5ido5LFeLRUnpYN7xwCGw9A16aBOb5Fbm+
         UpjkRGKbNCJ6GhvwbXD6tUeNUp8JY1qh8hTCnP/clyHOO7uMihYnfzuDxAoMcfroqQfS
         ++XEQ1khj0wbdxt50Z7wM9LOyY7MYyz3SfoWsGfiqgajOC1OjMrO3tdB6xp+szJ6rGbU
         R1Mjrn5l10k2gp+gfMdZQe4MoAE029h4cHlMjS3X/MoBrjPxecW2c+x+NegB/CbLKwbn
         9Lgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Wy5tAH2Y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id cs23-20020a056638471700b004312fb02a61si1497884jab.4.2023.11.15.12.34.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:19 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKQiFh031245;
	Wed, 15 Nov 2023 20:34:15 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4tk8fef-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:15 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKRO1n001546;
	Wed, 15 Nov 2023 20:34:14 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4tk8fdn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:14 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIxY6014619;
	Wed, 15 Nov 2023 20:34:12 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvrd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:12 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKY9l222348470
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:09 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8BE1E20043;
	Wed, 15 Nov 2023 20:34:09 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 38AC620040;
	Wed, 15 Nov 2023 20:34:08 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:08 +0000 (GMT)
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
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH 01/32] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
Date: Wed, 15 Nov 2023 21:30:33 +0100
Message-ID: <20231115203401.2495875-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: VJX97QA9qh-kHNZwqS0JJ63zRqdAobq3
X-Proofpoint-GUID: t5KbkiQ6ScFLylCeNY0jbVA7We_XpEup
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 phishscore=0 adultscore=0 clxscore=1015 mlxlogscore=999
 mlxscore=0 bulkscore=0 malwarescore=0 spamscore=0 suspectscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Wy5tAH2Y;       spf=pass (google.com:
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

Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 kernel/trace/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
index 8de8bec5f366..dfb8b26966aa 100644
--- a/kernel/trace/ftrace.c
+++ b/kernel/trace/ftrace.c
@@ -7399,6 +7399,7 @@ __ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-2-iii%40linux.ibm.com.
