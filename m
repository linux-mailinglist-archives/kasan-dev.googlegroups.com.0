Return-Path: <kasan-dev+bncBCM3H26GVIOBBLP2ZOZQMGQEAYHEUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ABA890F29C
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:51 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1f9a756952esf14526495ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811949; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q0uYSen8AP6cMr4wd++H1h8+Gh6Z5cbB4Tbb7SviMBIF6+kBl1Y5+2ei2F6fPopslI
         0e4aV0Rd3XS22biBJoDe1oG3iEvBSzlP0R+NqctShZ/BC8E55C9R9XQAou30YOszOwG9
         413ngqDO8eNseq1brZF6UQRmvqwq7eVcQLNoZ+Sk6MX0LBzqjCKJzEuk24UZCqxdB2lV
         abNOlCU5bbuJfZjLM9H8zs/Sb4zQesCPWTifiGeT2mujJMRUeUbnVpcNbA9JjzkA6xkJ
         ZovKEA3E2QH0o1gLBdpMGPv/+XiS8pljUQgxpggmA6reUW1rXPZzL5orimLr0CJIdJnm
         Ao+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vuC+dRkBZFj89NAIFv/JzwT7Ks5kW9hWZB+CtUegSUY=;
        fh=MxXSuhjvJTqAmlTLmHonCQuXYil580gK3jO+g3tOPB8=;
        b=ffXIVQZM4PsMhVhr6yswj7aGHG8Y2PbINApg+6D8qvyC9SIMYqz77eMLsaDrSsni1i
         J7n5qmUv51GIScZjOeJAzgH2PqGdhLeqgLiUwQzUhmwHRjM2WRRKB0Fip5gnfNUt6hEn
         bHK8TmVkTfod995/wOACjXCgbFm0Fq4MXyeY1v0Ps+29HnudHg/NJhh/bLfrTZj2pHkC
         P5+wiBP5YdtlwTbHeE853Z2sYp3uUFHMhWlYg7FtXq99GSSznXbSHBp89i6Rf0DKbT7n
         YZ6ra5dhOPwtGA0FeOQXyFWUME6n6L2vfmkXd3RUBJGAWGgrzBdjWVTKBXk+hw5E2uyv
         BaHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=flExNqPw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811949; x=1719416749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vuC+dRkBZFj89NAIFv/JzwT7Ks5kW9hWZB+CtUegSUY=;
        b=XrL+DDN+3ZWM6OszhmfHLc0rHon/H06PTyWopVM5VCWoiXPu+TxmG9a3yuE8GSSt8C
         XcJCxZOzKth9Ql5wwHqWtgnAZ223FUdcBNKOre/0aKHpMpoI0FOe9FEAkWelPec96mNm
         GxOl+EygiYqzNvpbCP8w9/OoPGHrTs9wVURZw3SOyBk2HbZ/8heWpdHcCgjIoq9DhZtX
         nAja5o/JWxd12QivWEcJ5u16n1NP9cf1FPxt2LILFfyEIdCZUB17Hs+315jBXU0gMfJ0
         Xjyq5QKeA35gn4xzPiUtwRUALYjJRP00OG8U+YQoaaBmPYs71jEHDw9uwBY+ZTV2NChD
         aayA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811949; x=1719416749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vuC+dRkBZFj89NAIFv/JzwT7Ks5kW9hWZB+CtUegSUY=;
        b=rchr9RiTTuf5DzCdWAhYZLOhr9RC0wKfvIRCsqp0xUn0HY1u6dL2WlJML+yGJbMwOP
         OpjNkYfpXYxotv4cGYmBFkvYpKtqlDCgDxGPj+N/JzrGeaoRGE85aRSbhSy3l3hG7gcK
         bO4A27u3wI9E2UXoH8fwg7w7p9/PKY+btPfJpGnQ/070Bj7LzCtoJAhG5BW8/cV3ab6+
         i3jUtcYEWfD0QW2tq7Fcz7hMjOncqkweR3uPFLAph3NpbD/yLmO0rMSZkT1B4CDyz2UW
         b+1upqvYyR4yX8jr1VmIZWuhWa/RfwDuLhFu/sn9mA3k8Su0uv/hLodxzA4+9aESoXtw
         OZyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV7ZIjcYgYp+gxKWBJMZZXdOtST8/pSKLh7sd+H4Rr9/ewdGT59ydQAM1Q664OwciEGXvtOaeqDUWJutw3n5kWj4ifw7/OxWA==
X-Gm-Message-State: AOJu0YyOOnm8EXBomCOVPWXlRiDt33O7eslodlWZ7DvvJaAJGPoQOkuw
	WFJd09lPRl4566z740jlHtU1jjaxiXQypMRMgCZ3Vo7072vPrsU9
X-Google-Smtp-Source: AGHT+IF6UnWintlUlUs38GYVNF6QSw1WupHd42KeGOZ2UpS3OOl4RCYexTGSI6e9Bn/C04qysmd+bQ==
X-Received: by 2002:a17:902:e74a:b0:1f6:2269:1067 with SMTP id d9443c01a7336-1f9aa480200mr34809435ad.53.1718811949633;
        Wed, 19 Jun 2024 08:45:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:3d48:5906 with SMTP id
 d9443c01a7336-1f9c4ee6708ls51935ad.0.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVOlg9Tt4FeFoNVl8Dl/rE/wVvApexLwgH33GAcNVRjzx27CFG8VgD4D87sCta1rI8KX1vR+340fENbsCaZfkF25+NxP/XXaIDq+Q==
X-Received: by 2002:a05:6a20:4f8f:b0:1b1:d31d:c0c5 with SMTP id adf61e73a8af0-1bcbb5cd527mr2661868637.37.1718811948441;
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811948; cv=none;
        d=google.com; s=arc-20160816;
        b=z2xYovbuDEX1D8IVrSVV4EZS4tuWdC7gMPTCQo4SyUm79Z1/TtZHt9GrUzBpuI7auZ
         z7UpQ2hxGZn0qbXu4/MfbRIKbgGskjgI9qYj9e/QXhQ1knGyKccc/atD0TQUxFNWBDGa
         0TccgxAOxwGMhvwONpxS1ro3GehPZshCaq8E5bMid66G1w79d2MSLnga780ZDVo/AKH+
         9ILtmmHz6oCYFVV4SB0VOp+EdKono9NrywWvD0tSmud8EoLgxezqdZyysJk5JxM2PjKm
         nJ1Kf9b6Tck6WH8O+WVfcjmvP0JBUXLuYr61wNVHMzbwjNQWpB7sN8KNQU3Q4FlZulca
         4wkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3hDUyT9rvjh/uqttZeOy24s2Df+NNUjOmmqDaE5+6Vk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=A3pOBDtr6ulBpWA/U7YhERxvtOSc4nfOOMNQjJT1vt86/C26/CGw5G08DG4BY2mDQ6
         93KPGjevGPTxUlG29zvZY3xJduPanJYtX/xTIFXbVhsuPNArsIyklCi5a2wINEUVspmd
         AXp55iociz13HZ0I5wOvIbV2E1hIALa4yznbYLE5fCy3CAiCZzPUlnwh+CgK2mO6NrFV
         rP13QsUKRinLRpYFKCX67JaK99Y0Tv54biShRJU5jByBP4bwJKeXv5LBUVrX5mCmdGWg
         K6uFVq+sRXxDlVo0CVlTsBq136lCrmnlfRoLyN0qReQo/V3WtwiCLIoksnNHzhO44x/l
         MhFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=flExNqPw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705cc8cac45si593315b3a.1.2024.06.19.08.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JCx2dF011611;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yuyt98h3h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjhZs015348;
	Wed, 19 Jun 2024 15:45:43 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yuyt98h3e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JE5h8L011031;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yspsndtmf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFja7s55116264
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:38 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4946620067;
	Wed, 19 Jun 2024 15:45:36 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EE9EE20065;
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
Subject: [PATCH v5 07/37] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Wed, 19 Jun 2024 17:43:42 +0200
Message-ID: <20240619154530.163232-8-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: JgxqkCBh6gonQsPsLTHK1eNwNcILiZpf
X-Proofpoint-GUID: bJpX-eo45VEognRyQ2bVdqBxxfq5QhVK
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 phishscore=0
 malwarescore=0 adultscore=0 clxscore=1015 priorityscore=1501
 impostorscore=0 lowpriorityscore=0 bulkscore=0 spamscore=0 suspectscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=flExNqPw;       spf=pass (google.com:
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

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL. The right hand side of the assignment has no
side-effects.

Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index b9d05aff313e..2d57408c78ae 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
 	}
-	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
 	prot = PAGE_KERNEL;
 
 	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-8-iii%40linux.ibm.com.
