Return-Path: <kasan-dev+bncBCM3H26GVIOBBEUA5GVQMGQEMCVBFFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 34CB98122FB
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:51 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-425927c274asf100276921cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510610; cv=pass;
        d=google.com; s=arc-20160816;
        b=XLVgxOwG/ZJCi4fPWgMoUst++eQWyM6jvqLyz83FyztlJqKLXU7GmrE55QW671B1Cf
         WWsu6r8pJqj89Z+sPRIqbLeHptozwfG3l2IMptp03LpsbvWannhTOafQxWZbb811ukOd
         +IDFDoYV39oq3FllYhPQTQowUtVljtVd8XhML4+aMV2z5Ubho33j04xzGglYSOpMWW8Q
         yqo+HBwaPZjNfGjFfLLHbXNip94Kz4PSKKjPX80eA9kDa0L583Eb00tpetaaf0qLznLk
         GiNjAqqBvodzj7ACOD9+KdQFd33G3EcKm0bniHwzzeTXtEFN4pcHo0/jlrFMXzhpmFFr
         Ddzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MovPzcbtr/aAacIgSRWRRD4FXUNj6/F0G7LSExOL2vs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oZwOIhMBxLSpgBLAQCZM7fFpvplkOLgjkbX3JivgssXEtj7YtSMZRNLucu+4fo62sV
         Yw+sA15SpmuX6n8ccta0OTZ75251vSHHpUxMqvjmgRDPDbUvjC+nG1mVhS5RdyfUd+3d
         2uaMblQdlys8TGpZgrkc7yG+jZKG6NwpmojCwelzTSsjPVTmYEQQB8mgMosB9k7khjvl
         hxDEnl3nhrr+zAxcZGgTiMnZPNP0JxjzNbcvm9AX8G0xfNTqihzUlds87Hek7n8unz8/
         KSY0o3phJre4xtwQ+/Rpsrik0X1dPuaUEMl4O9KVzL2mdw0gStEU6umW1FRyS4WBUfPf
         UPaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iR+7Or7Y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510610; x=1703115410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MovPzcbtr/aAacIgSRWRRD4FXUNj6/F0G7LSExOL2vs=;
        b=HBXunRTY5OYbxgFa9xP8svNMTivz17Rg/VjixJqQ72I0r1fMkgvNq+3tsSo9kRhD7Z
         XALVsRrCAYba8jygQroCGLabLW2NC3QlzCSdcSYjooQRURBGHz1Y+sW/+wqmcJZe/O/U
         MNI4qGO5HYwt01iavkywOywGBD89Lmsw+tsG5y8Gb4we2Ccx4J0Re91HUx1ONU2x123J
         q7ttrxiQ6P89ycsDih2CjCyq2W+XlgpK1/eggvMCluIorNMCXpn7gfbSDMXF66vN4LVg
         0ylCOCG7PUaZc3+Q9b+cKcKG593grX+y/Clt5SehAE/KMJTuWe7N4NoeuBaWZdgpJ6wX
         LrQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510610; x=1703115410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MovPzcbtr/aAacIgSRWRRD4FXUNj6/F0G7LSExOL2vs=;
        b=VySV8mvV8vloYWTcpyKKX9qtRt8ulqHquoXGIGmcC8PNa7SvKVkHSx7sK7e9F6cM1S
         9ZKyWutywBSJK7NNAv7djUnfRMA8/8a/0WST6YQgvxSQDaI8GezfaKmCeDrXonglaE1Q
         Oan5dzs1cvL7c05oIQnGzEtd2Df5ZSQKhhu8uu5M+iev+qHDIfLN103Ncoz+8UefgMJk
         pS4uZIEXTe1unmi7ZoCN8QuGrAm4i0KpwLI1SOBXfcJJEE69ABsRXCn0fhkbl4HDyY3R
         joS13ibV7DRuA8aweiGUa8Ll4j2cAybolt3FrmvbzI7wssFRqCpHgT8p7PxJQ7QujcTW
         dNrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxvCyN8xDXbHfY0RZ+INe9FMQUk5lg3+1arcRJ74aV9zURIQW8d
	jeZtFX8Lmrg6+6Jct51fQ0E=
X-Google-Smtp-Source: AGHT+IGs9SIAKmsvcYt2Cofs9NBdJqkh2C9PS9iFiH9Ir/bDkDfuXBf9/6VVtZQMs9wHVXQTyvbg+Q==
X-Received: by 2002:a05:622a:93:b0:425:9122:bcd0 with SMTP id o19-20020a05622a009300b004259122bcd0mr12861307qtw.27.1702510610117;
        Wed, 13 Dec 2023 15:36:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a20:b0:423:731a:7859 with SMTP id
 f32-20020a05622a1a2000b00423731a7859ls2983666qtb.0.-pod-prod-09-us; Wed, 13
 Dec 2023 15:36:49 -0800 (PST)
X-Received: by 2002:a05:6102:1612:b0:466:1d22:5b46 with SMTP id cu18-20020a056102161200b004661d225b46mr4821465vsb.35.1702510609396;
        Wed, 13 Dec 2023 15:36:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510609; cv=none;
        d=google.com; s=arc-20160816;
        b=bJJ+UeFqsBIVwsAoYV3iLDGUF31kg4oh9EahrkV0/cNp/wc6gJ5ShvWTaJWufH7Xjw
         n7gugW94xxKBrt1pDu5SbB3Lg4GxoxKmDV+yMQsatNBSHr1o5Xkwu0No+oSDSRQsyHHS
         76/fMdJn16wkMBaqtNafSr9OwWqtmSyVjUtyc65mpRbPAmTLQcoU2+ZNXMa3x7dv0VXk
         O/fnq9fjXJdE1cM8cmKJ+6p+3F6hqIWzqxtnrqJDpxJKrjTaZxRcErn9KB0ovNK0QWBa
         zS+rLG+2cDcDqK1plqxvUkrslQ3LFmGmDUex/spRgQuJT99YcipkwHYHbykNXn/Aoris
         +PYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=N2VaTm6j283+4VwN//hURwYHK/YhopDpRgkaZ9Xc+7w=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=leDDiyZI85VQ7MI+cdYo1qFRwKe0XPEDumlRI7nh3OZ1mTwqa2wpTCh2fFa0Za/mn8
         wKgZxBUXiFfOsxkUU84vPO88RhJlIwaYjcV1piL4U03rihZjYEwnswG41neBHCy36pSl
         v+MWVLSJ8ydCAjundw09a7/gwiErp7WJKCg1F1jympYpuYYcxjIa4MCtJPkLGUV5gcmC
         f7uoS4Fk5RFBeNOIZLIHKnMeWlR62NIsvZ221yiIesCOSQ9NZ6MqkODOupGScA5ybyLT
         485Vt5PUBRwCdRPheu93oXgBhbxICOTbKz73vJIg1q1ggYGHYiRAtxFmJO0FLWWqhQIt
         N7eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iR+7Or7Y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id i13-20020a0561023d0d00b004508d6fcf6csi3168822vsv.1.2023.12.13.15.36.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:49 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKfjZw013021;
	Wed, 13 Dec 2023 23:36:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg35xnc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:43 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNSl2V015630;
	Wed, 13 Dec 2023 23:36:42 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg35xmw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:42 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDN0HV2014803;
	Wed, 13 Dec 2023 23:36:41 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1xp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:41 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNacXs44237494
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:38 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E859120040;
	Wed, 13 Dec 2023 23:36:37 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7C47620043;
	Wed, 13 Dec 2023 23:36:36 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:36 +0000 (GMT)
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
Subject: [PATCH v3 18/34] kmsan: Accept ranges starting with 0 on s390
Date: Thu, 14 Dec 2023 00:24:38 +0100
Message-ID: <20231213233605.661251-19-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: cPCpBguRX25yk0cY5HbnO3wP8bPYoaUi
X-Proofpoint-GUID: tWEK5BHWwLFqmCkK5VSnrvyWkz9szQAT
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 priorityscore=1501 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0
 lowpriorityscore=0 mlxscore=0 mlxlogscore=993 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=iR+7Or7Y;       spf=pass (google.com:
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

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390. There doesn't seem to be a
Kconfig option to describe this situation, so explicitly check for
s390.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index ffedf4dbc49d..7a3df4d359f8 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-19-iii%40linux.ibm.com.
