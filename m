Return-Path: <kasan-dev+bncBCM3H26GVIOBBQVFVSZQMGQE5ONMZNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E58F19076D2
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:48 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1f851ea7a09sf3149545ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293187; cv=pass;
        d=google.com; s=arc-20160816;
        b=XUJw/eeVCYLKrt+ZFkg1zJbzUulUVk9ONQImAeWXtMdgkPfre/okrDh0Y7Y7XJTB3n
         HhhuYEkFaMOT2e+UkRWt85WjwwLqL3xyMa6SuHdsJ+g0vDwgelKN41dWdKt6Xd6eX0yg
         SAV+tJKMVCLOXQfT+DNEplNYM7JaiVKksz1TcM9StgB7FrOcEqnpiE4nQYuVi6+JI2dO
         /lqT9+sCs77Mi5kyfINP54+odIONxXJcTsoD9edxQDMaYnZvEHrlJDqtwbBgyqXgIblQ
         1K8UDG7yiKc6cYQJOp5T8glZHDc+Jl02HtukoF+ZfhmGSMlDCz1uYdgJjbvoOtTc+56F
         1YOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rnbu/eF5XzmBYXyZhqoYFlJuaXPT4AfdmBCxqX60epw=;
        fh=+kefceNXKyXULKhT9qrL7jycrffXpekF8T5lstCut8I=;
        b=joY5PuPw8EefFsQTgpCQrCadgLdjM+dQWgRaAoTy9QV0cW0vtu6JEO7fJVrCandt8w
         dqVt4bddCYMOq48xQicILm1Ezu2nmt+fY2PtMk8BMK1SMFRQKcnFiUC5UbTvf9LmpXb5
         SRuw4j4IcoZmtW3SPCtAxrhUg8rkONAHbeLHkM1Z/LngJS3tQy9vRhMSbyh4uYvFkei3
         LYfDsVqSSSkWba32dnA4+M8U1MfpUDOGKnGNTdoNDTd0qFe+86Bge+3PJ0j3E9FlYdtM
         4Z7if4KlrdC/qiy1zDqNot9xe1pbp/Pl0LDfBzqIXXZm0VgfPG7W6JGQ5MmIvunJtgbP
         thiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="bWFHZS/g";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293187; x=1718897987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rnbu/eF5XzmBYXyZhqoYFlJuaXPT4AfdmBCxqX60epw=;
        b=mphBYmjsRWAMhg/y3OHoVNcJI+vWYJVo4SoJtYCKdLwHowLfNQaQeefwsiREMZ8FE2
         0a978lt8Tv6ri3JJVlDueW8K+c5GyAdQdAek3Bby4if7t5iDNMfa9fdJccWos8urnL+0
         yhpaeg413jx/j2cMKqGKZs1x611razLaIdX3DOW9UKMnNL9L0q07ykFKl0ttN9HLw11Y
         gNgCvdcrrC8qck80P1XuOeSkBC6K6G5luYSdRguNHkb4Iur4jryvshNDKKgT4EKQOtEf
         qRCH2whKhIOPEq8BZqhovOsuZ/thVIAzUEw8PxhboPOipWhWM9s/17P7EFM98legWxXT
         uE0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293187; x=1718897987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rnbu/eF5XzmBYXyZhqoYFlJuaXPT4AfdmBCxqX60epw=;
        b=wRKi4HVluq049YIzmHeE883YLHYVFQmMU29qHVUa9ZZ3exX3EKURyVkpjgzVFT82LU
         GHaj/HwXHmG9yaR2ZyViIa3tz4nuhfb4J5l+mbPxqMI7Tp3WG2fDU0zjbNvVhkxlB7XH
         oZEyPVBB51mjEzIzR/puLQP45MwEnuQHYyeBqeY6mwO9KA2hIbvbhnA+xvVNmtmJpAei
         vUMSabfxKuKwEwNirRNPDiMzv1T46+EICoX7MxICULia/CfapNzk9xT7D4ubx5vJOUpW
         PIsRfk7IbiJbpYbUky9hZO1jepvjRph2V0yJaf1XYlqULdNFXhW+j/y/ck6yuKnGlYsg
         GLEA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXnBrA60q4UlgzojN31YUMTB0KmMSuIsni0nEtJC2U/BD4g7PcVtLpRz1JJ1uMwvJarfXB+WYEqgjGyzov9pjTzHRvAiEJlrw==
X-Gm-Message-State: AOJu0YytgYxm0Bss4sXtYVgDX2A+DHK1eimigMQji+njYR2BuITMd32H
	gZplsEqPuwuFZr8RyAg14Gcvz9a+xMv+4LLCASoZRUv0YGkWNyiV
X-Google-Smtp-Source: AGHT+IGp5qr41ZAMGk2HkmBdsFPOCbFdShRib+CqzhRk43vprwzVlN2Qm70i/Ww+s1Bd7ODuJs2l3Q==
X-Received: by 2002:a17:902:9894:b0:1f2:fcc3:59a with SMTP id d9443c01a7336-1f85360e2b3mr2958255ad.19.1718293186961;
        Thu, 13 Jun 2024 08:39:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:1704:0:b0:5ba:a73a:6de7 with SMTP id 006d021491bc7-5bcc3e0189als879494eaf.1.-pod-prod-08-us;
 Thu, 13 Jun 2024 08:39:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSa7ZysjJDGupHhzxb4FVm7hEKw7djKW5c58gwo/kAIfZviLAK795GbUf/YaMbR+5X0nC0ZUkC0T5PPKbZLNwLex4AGqM1h0Dwhw==
X-Received: by 2002:a05:6808:1b1f:b0:3d2:27d3:2927 with SMTP id 5614622812f47-3d23e017b75mr6257383b6e.30.1718293185509;
        Thu, 13 Jun 2024 08:39:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293185; cv=none;
        d=google.com; s=arc-20160816;
        b=Fn0JrL3m7f6wJAzTFPqqwTdt4+IsJpbN0t2h6T5by9q7Etit6tsYpP+m6Q0aWkLnSC
         0KYZ9UVPSe0im+i5U7iL3YOM6Wi4yJuFBAv/QiT0326SuR9YTry22zfph/WAb7SopW9C
         fGEuZiuQqQTv/Yo4qt6KeESwh5j4q4CYUThHnjsrbqg/VLfO8pIVBFZQqRP+XaWRWL58
         QiVzbwt89SHQ85soI/WIB50zNniutwnk/bD3JhYje2hHK5oZi9UfJdnp+L1oTSRXAk2L
         BCLdiQfez6Vag6dnlnBy4z0gjs62vYgnOAoX9pbxriod1m3G0a6xa+/98mYW/t4/gi7r
         P06w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L2b4MdNWoGrmhueYrJgLdkWwOUUS/TDjtdF9PAJHumU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=0j0UM/OkvyIPDcoEzkBzMFSbNYJ3GJyUeCO9fu1nGudGSQ4PqFAdZUQvjy0qSxTlws
         l6V/crrUqF6lkWW6OjEjD7m8iR6gorfhQ6pgYTdD6/SrKMiHZJQE4IzSna65hEqhmaMS
         0NDQbk7tkKSxXin/ZC/BTdQBZrYbRjJkvi7C8fUQPmoEAqx36VV4cLXeL33l9cwSRPg5
         EPUUkeEiF3SAx9ncxFopXzx5zBRUN+sLGN4gRJyZSPzGRf7a77rKChjEIfwcwhaqgP7a
         jYXojSz2BH/KK/JfJodSFa1CxkhFIQ77XTFRX2LA8FUVrNjd9q35hujiGFue90N62dAe
         RVHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="bWFHZS/g";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2474fecadsi90343b6e.0.2024.06.13.08.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEQVaB026718;
	Thu, 13 Jun 2024 15:39:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4u236h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFde84009379;
	Thu, 13 Jun 2024 15:39:40 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4u236c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF3D9l020045;
	Thu, 13 Jun 2024 15:39:39 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn34nh0bb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:39 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdXFd34603580
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:35 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6D0C520043;
	Thu, 13 Jun 2024 15:39:33 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EBA3E2005A;
	Thu, 13 Jun 2024 15:39:32 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:32 +0000 (GMT)
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
Subject: [PATCH v4 01/35] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
Date: Thu, 13 Jun 2024 17:34:03 +0200
Message-ID: <20240613153924.961511-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: xm45VOErXn2zx--ADqKb53zaUOSWviMh
X-Proofpoint-ORIG-GUID: Z8_ju8nlqZv5xj4EN8MEBuP8KnX5onjx
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 suspectscore=0
 clxscore=1015 impostorscore=0 adultscore=0 priorityscore=1501
 lowpriorityscore=0 mlxlogscore=999 bulkscore=0 malwarescore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="bWFHZS/g";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
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

Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

The issue was not encountered on x86_64 so far only by accident:
assembly-allocated ftrace_regs was overlapping a stale partially
unpoisoned stack frame. Poisoning stack frames before returns [1]
makes the issue appear on x86_64 as well.

[1] https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-returning-2024-06-12/

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 kernel/trace/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
index 65208d3b5ed9..c35ad4362d71 100644
--- a/kernel/trace/ftrace.c
+++ b/kernel/trace/ftrace.c
@@ -7407,6 +7407,7 @@ __ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-2-iii%40linux.ibm.com.
