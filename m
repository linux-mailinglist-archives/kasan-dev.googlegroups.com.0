Return-Path: <kasan-dev+bncBCM3H26GVIOBBLP2ZOZQMGQEAYHEUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E6FD90F29B
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:51 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-70ab3bc4a69sf3332819a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811949; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eajj1GV7BK5axtcqjATkUy5Z4jvVbi6DBok9fijwXOEkp316HHkn0ENtd8mkwB1Yxi
         RhL6d9iJGCCxIaF3qEnmwtqVetePD8rYIp2ja/b2OaVYjOBNnhJCaQkObr/wufG1eski
         W+/8+4sw6C0HCNKtAZGQunUJ0H7LJTtjBX+CyaAdC4z0MSEREkOgOldtP4RgjVCHYYs2
         GXsIIog+XMsiMEIwJ1ltEfk3acw3U7YRMPvOgpXk+bL076nUhYli4KO/y2U7KfkGEd0h
         FZUxaCPZpov1/BK1+8kmB3OWYlbfQl+zHq3YgNsPCj9GGVOLA1pDeM4YTCz794AJ06a3
         Ab1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=h7+AJTMlkicDeErRSdZ6LOksDFKaJ5EpYulvw/T7Y7U=;
        fh=DiBTYnKRAFzw5J7vgHqHoVCsikaFattJRfLLOqame7M=;
        b=w3hGlhw9vHU7p7urYyMRfFd1AXxjIZqi6vmN/lAKWna8npAdgZjNN6XF3z0cGHnIRD
         1qpJ4+Gag8xAW2ivGZcp8sN7VKSjt8nTiCv3/Qb6NCwH4BjT3nv/5KhAH/I2HzSdbrNO
         FCUCHayBhaSHjqIssiUaFdA2JZtfn0kgERMooG2DrqjOJCUx9uLDENRY52zFBGRTKk3q
         IquiEcxz2VA3p6VlitIekiyp3jnitbljEd8H6SMJJfeGU4JIh3RsCz5o8E6tFLPuFyjV
         jFrTNNPIsA3R5cxRBeal8vzdmhG6jo8b56nnzAaWGgmYZsX7L8XOIh4ilpmg6GbJ8Os9
         w00w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hvmOutBK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811949; x=1719416749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h7+AJTMlkicDeErRSdZ6LOksDFKaJ5EpYulvw/T7Y7U=;
        b=BEFSwiQy39/sbCRlGl6gCWVH0fQHU7+IWO+8clhHQCcCDo0t3Nk3rgJ8C1g5ug+nPa
         715b724DMHFPf1dqRK1uvTameMPzQ3QI30VyPi8FtMT0F4fjad5ILxHrUvu1A/6c0v7N
         bL0UCMaPxbDgrj2DaRucqL7GXB//hCnEdxL0Wnteo9TeEMCSHjNLOOZO7moqACLgSLHF
         ngVtwdNcmUlcjY7PGPne8VKzQxoTMeFQhKeOKUoBirgr0RKGdP9vgT5kecetJ5+guBTP
         kn/qIM67W7Yhrzk8UnA01UWKI3qudxcVZ+mxzhdkdBBG9q/ThgWW4BGGTQqTnRx8Lj9j
         35uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811949; x=1719416749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h7+AJTMlkicDeErRSdZ6LOksDFKaJ5EpYulvw/T7Y7U=;
        b=Ghxdm79fb+OmfWWZQErXTh6eGVW/kmVERkn1Jeght772FWlXWTMrURfEWU/FYVM9cV
         /BZ3Rpz1di3UOzdHD/Q/EpnGc5Eeba1lSo3O/YTwyDngycJMFOXUgSd/hKegmIiT63HB
         H6LX7kwsimv1V4gJqFC9Suqvsu7hQoOn1ThWqWNLg+LrucIJiznHMhcPzCwq6mHiGAQI
         8mrdf9fIcpMVkoN2PD9GmnVO/mt0lisTnbigOKviNPJobIJ3NQNSGRzIteONTowgYepx
         QBcsEioQFpeLkvwOxgH967wtKVXNnwaPyPuBogLreVjpmkD0ZrGuWc+LIWd+elo1jMgt
         VMtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZN39uSCjnM+6A3HyRTQ3OPuJv1jCd1kRU5wAA702DWLil+Nm22OYBSVfL1BtKU2lNDmU2u7ebK5YRWZOuNmEBs319ZnnvgA==
X-Gm-Message-State: AOJu0YyKNZQlyugxkwJPmrz/Kyw3Ift2FdKr589zbCHfdNbjJZSX9a7M
	5clzEQ8LyOMlpw67xY9fZtVoDI3ANfFI5ry/0d+ifI1pI+Mhee7I
X-Google-Smtp-Source: AGHT+IGhTvkp9KLgavYFeYwplt3momM8Kg/Wn89aSbGugMVkoVv9yGPPLf+esL8kbjDH/UaGgObhdg==
X-Received: by 2002:a05:6a20:4d91:b0:1b1:ed95:c9b1 with SMTP id adf61e73a8af0-1bcbb6539bfmr2845151637.40.1718811949315;
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4f85:b0:702:8289:fa03 with SMTP id
 d2e1a72fcca58-705c9456d20ls3388698b3a.1.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVR3vy8pC995zm75sYfryuyX7b5d8RvGdn24fluSOcjDgxjffdDSPvlRuTeB9Heoa3YsjPk6dpDvDGHce4Np2CRe1cgGZYC48YUWw==
X-Received: by 2002:a05:6a20:3f06:b0:1b8:b517:9c0a with SMTP id adf61e73a8af0-1bcbb451913mr2687113637.5.1718811948059;
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811948; cv=none;
        d=google.com; s=arc-20160816;
        b=OFdKMiEzt6CNi/fLT4UyH8bqAveaEi5ZOKT599jVVixrLo3M4SZccGggJDEhPflxQV
         3e2hZu7ojvf0eaukKLuV1MPTedGu/BSs8bzmmoOUoCxQtC2Q8M6BgmmPnfqS4fvcVoys
         T6rQAOiuCP6AUTu2jGmvjGPOqyRcDQSws5ZRBXCsXXgd50ZbxH0aQgJRnKzRjZjriiQg
         zv7hOUY04XfTBZ5Yw6oVTFCN7gKe3dspILjDDQM5nQfSRpibRWNG1aZZvkf5m/VrNFqq
         XDCpznJxPHykK3Ms8YL9ZtyJJNooCDir6ZKOybje8OWIk4IUibqh2JpjV+yXh1Lm7Vk5
         s9Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1qF7H4bGHDZ6iOOMBP071rdyF1q1YAWA6gRStiWbHSM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=bPIL09/ChpPrhTNMU8rE1eEDMoqmMVS01UuCTjSdsPcDkKvrmW74EKz2TuPs/kx7Gp
         g4PEkKcytLHvITL3DSZc+XTWJgM5cr74YXkGoLGDXWcUWHlbzcmrw3gIv4RzpRmgZ7Qf
         wXUVpMu9ORbx/hl3HFeUjv1CNls26R8/IuiH3w9pidXpLLOYwqr5QALjheQfRB09p4S3
         7rVnd2Z9OX5ESndMQP0SRaJunJfscfYDojHGA2OOX08ZxcR7oIeZcPe5vJc6XwFbQNP7
         GgbcOjPS7DxpE2WBi3lE1DGTf5fNA5yxsxXCvux+2w2mbFAztx4pG71Dgb8H6ul0FgDb
         Bo2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hvmOutBK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705e3b26323si472002b3a.3.2024.06.19.08.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFSlP0014399;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1g7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjfNU008972;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1fx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JF4mVa006189;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8m3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:41 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFja4l53674268
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:38 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E8F7F2004D;
	Wed, 19 Jun 2024 15:45:35 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9B26A20067;
	Wed, 19 Jun 2024 15:45:35 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:35 +0000 (GMT)
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
Subject: [PATCH v5 06/37] kmsan: Fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Wed, 19 Jun 2024 17:43:41 +0200
Message-ID: <20240619154530.163232-7-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: qRm9eekwUFL-ZYmqnJkIgVJiLG7mMaWA
X-Proofpoint-GUID: AjSxN3rM0zXkl3-FbNY4IIca87Zn257c
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 bulkscore=0 malwarescore=0 lowpriorityscore=0 adultscore=0
 phishscore=0 suspectscore=0 mlxlogscore=799 priorityscore=1501 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=hvmOutBK;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Assume that we are handling user memory access in
this case.

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 22e8657800ef..b408714f9ba3 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -267,7 +267,8 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 		return;
 
 	ua_flags = user_access_save();
-	if ((u64)to < TASK_SIZE) {
+	if (!IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) ||
+	    (u64)to < TASK_SIZE) {
 		/* This is a user memory access, check it. */
 		kmsan_internal_check_memory((void *)from, to_copy - left, to,
 					    REASON_COPY_TO_USER);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-7-iii%40linux.ibm.com.
