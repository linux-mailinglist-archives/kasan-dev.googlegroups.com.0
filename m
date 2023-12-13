Return-Path: <kasan-dev+bncBCM3H26GVIOBB5X75CVQMGQE5QXM7TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 70E348122E9
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:23 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4259f4aa87csf51571cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510582; cv=pass;
        d=google.com; s=arc-20160816;
        b=DgtHnv3HC9CkAJstXHqlbC9oPMaWraH/D2W8dL121z4+pZFFYsW4K4Tyr3lj8UFGYx
         nBaspdI8cgjWNCu8chlUdIhRS/nzKjcpdjw5YGzgi5yyzW/HLCm02Ko2FkoujSr2eUZx
         UeJCs/DnPEZIYmgdKUIBH7Lb6OPtlXBQTAyqyxSHElPigYivW7o0doEdf9MVgkfdFfCv
         TuHIL9Hvarx1rR7Ee9ejeHAAur3b14aa+0EMcNAiMYgi9eD4gvcbKj5arcDK9yY0qXgS
         mHXJ1zQ4E2bDTAkiGbPbFz1bPA7QwK89ynNp1dtBBenmpGBdTYjgNprVXd1jRXWzlAgA
         SE7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=frBR0ThQjxMtJbzhZKhX5zKqxcEXWF+YiwfW++H0ipU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rh/1JSWx55zN7LLchL79cR6Rt7Wyf4yLmQ7HSb4WxFxJA8ChCVh0NK4hhS5+xlB8Hx
         gXaMymL6+4Whd4GUtxfACWzhBbtN14f6fu2enZw9bQvxQeTYbIUX52Q1i6cbzkqb2Oyw
         w6sUwt1GilFpjBWVejz0F1TyVfNwJv5Ov+IE9uxSmXdahy57ibyBoVeNR5hmzFhkKml8
         N34xqF3ozCu+irjmnx2gGTqvHnSM78LnKdSlssyvL7f/dKwup2x6M6oX5snnRMHLSwD7
         Ra+dLXBBXFeTp3AMJxRdK5bo/TxAOP/sOmnZSHlC+jjBFQqaWuEvLAlX54na1/I+qUUc
         8aAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=K18a8ymh;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510582; x=1703115382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=frBR0ThQjxMtJbzhZKhX5zKqxcEXWF+YiwfW++H0ipU=;
        b=ssP5YsRNsIIOycpWWZDro/WO5rsIrzCBIgBHyi862aG5VPV1uEXnlVg7Lh3UaWLEyK
         hjh4Y5MwaExJ2+LNurlcX+s08HiRdaUjqc0vY9onVdUCZYLdfLvgVTlgPpVNy9yV00t0
         K7bEVY695N4Hhj0kswsLcsQV8cDsQu123fAgWjNRJCQrjraQJR7IXgQHDvUvkEdZUca8
         FaZmKcU9I0ylClQ0qkedUZucy2zIUsnPRYyfRTeHKoNCAMMQ9Gz3fcv3dNzSiE4q+IEO
         JdHzRnIwDICiZul2sNB/L7pOjuJPRRSytapWunCcx6VdUs9dMQpDru8FAInhspkucP4B
         q62w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510582; x=1703115382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=frBR0ThQjxMtJbzhZKhX5zKqxcEXWF+YiwfW++H0ipU=;
        b=kfj8BwDk2L3NS8LFQG9l3NEikhuku+s4Izg2Ru/AMBHPrVHWyY4fciNrivkhEfR48z
         S1mbuhm7Oqy3B9OcUnApr930lvf/I/KCB5MyBGH6r9nU+QLzDYQ9J2vSvZ6zAO7Rq4CA
         tu0yr0y1qJbWT7Rx5uO3t3i5m2M7RkwN183VedRNL4OwFwnqjIJdchwvvlCLkTgvh8Gq
         U47l7W4FMZlEw9yeUSBNsQXRSfUt7QSsOtOmHVpbjTxxmoKriOlZwUpLw+4q4bH7PaS/
         tWtTiO65mFlk2y2JVPHDY60X4MPdvmGX2H9uvmmv1liVWbeHN9Nfz/FwSExsqkKNG/Jh
         dB8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxXt5uU/c7fTrtnITXmrAzZ66ZYElrjJKwXCDiS8bd+ka3BJdcL
	ghf9rrxqjoQyQU6cJqY6i/0=
X-Google-Smtp-Source: AGHT+IH4v0DD3prXgJPntK2BEdUDBL0xRmo0RxncsZSKs5TBXFqp/2hy9nMasBzXOkaGR2aFapH79w==
X-Received: by 2002:ac8:5708:0:b0:425:75be:ab3a with SMTP id 8-20020ac85708000000b0042575beab3amr1623708qtw.0.1702510582188;
        Wed, 13 Dec 2023 15:36:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:49c9:b0:203:1826:df23 with SMTP id
 ty9-20020a05687149c900b002031826df23ls1202709oab.2.-pod-prod-08-us; Wed, 13
 Dec 2023 15:36:20 -0800 (PST)
X-Received: by 2002:a05:6871:3a2a:b0:203:d18:6700 with SMTP id pu42-20020a0568713a2a00b002030d186700mr3105196oac.21.1702510580115;
        Wed, 13 Dec 2023 15:36:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510580; cv=none;
        d=google.com; s=arc-20160816;
        b=ZEHwk50VpBFRoRUq/bLH41nSZea3iwoHJzltYtW/O/jRt5mUEt537Hp8ZFFMtY72A1
         w9SjtpcJ97YtvbGWAY2xO+Hq9juk99y7MIyEO/bjpvEWwDEEFvnzHhV5TsebBgQh14hv
         CfSRkUGLXn0xnoE4SyVtx0Kp9EIfPygA6zMG6cP9C4hM19qUVX+PzlsnKx+8Ti8T/YYJ
         I76cuNx5SBtou9HZHRaOMtsFMF1QVo+zN9mHoDjHNJFQpNMhJUKdEhwtD45xurudzrxv
         9XrSx6eJo5sWeW06T0Ivp8To1e9TtltnKbQ5+4qLPgJYnwpIEjEjQMNzCI1In5FZl26D
         loTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HCJ4ovbZnIIhG/tz7ek6pM+enuYe8MKDEM9fD4TOUak=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vFyv4r1xRLwm6wrC+gjYh0KquTKV2205AHAC8Eof888ulcotPUGyuq+XSyBwYMi8iy
         SHfklhVtyYvESZoQvVLFS6egjVsVW348a811bsAKb7f5gSqYathZt/7ob9bBGpIt5mym
         Bp7O+IIV435TNUA2cD4C8pn5c022QWiwfp4gGq3TQQqBHcrUoA5JCD49wZ1e2d1MCkTd
         WIhF6b9mratwr+P6ivLq3zqebTzJ7IMW/Aad8ReuQ/9W76BClcSE+vjdtM04gyqGOVoY
         /tPPDLH5K+DHq4mGkS5NvMTbMxqObdqqLVTqilRz+vT3UsF3hQqaMwTNFE61nPDNdMNJ
         d/kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=K18a8ymh;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id he25-20020a056870799900b001fb044ebe0bsi1442834oab.0.2023.12.13.15.36.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:19 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMNOxK009329;
	Wed, 13 Dec 2023 23:36:16 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1crg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:16 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNNrDs011977;
	Wed, 13 Dec 2023 23:36:15 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1cqt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:15 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKnidd008455;
	Wed, 13 Dec 2023 23:36:14 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtmvjg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:14 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaBEJ45220106
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:11 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9C28020043;
	Wed, 13 Dec 2023 23:36:11 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3484320040;
	Wed, 13 Dec 2023 23:36:10 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:10 +0000 (GMT)
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
Subject: [PATCH v3 01/34] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
Date: Thu, 14 Dec 2023 00:24:21 +0100
Message-ID: <20231213233605.661251-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: vwgPzb35f7_0sFL9c7WaIyD4dFBVqbRG
X-Proofpoint-ORIG-GUID: DHoU4-V1fZhM-XryCwlBGJOxj1RlRN2I
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 clxscore=1015 bulkscore=0 mlxscore=0 spamscore=0
 suspectscore=0 impostorscore=0 mlxlogscore=999 phishscore=0
 lowpriorityscore=0 malwarescore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312130166
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=K18a8ymh;       spf=pass (google.com:
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

Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
Reviewed-by: Alexander Potapenko <glider@google.com>
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-2-iii%40linux.ibm.com.
