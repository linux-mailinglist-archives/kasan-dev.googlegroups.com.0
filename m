Return-Path: <kasan-dev+bncBCM3H26GVIOBBU5FVSZQMGQEEZ5J7AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F5CB9076F2
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:04 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-44061ceb150sf11651021cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293203; cv=pass;
        d=google.com; s=arc-20160816;
        b=P9kD8UsBM88xZbM2dV/or8urNkL2bKGa1yzPi4ZEb2aiKC/eYQFiy1ws9W1H+vpLyb
         YsyLcDmpfP/n8mdNIC3ycAampg+4xn/W6PtBt1ajp4+drwQXcKB6U3xK2009uln3mr3q
         P0aJ2GYj2zb3D+sNuBash/F9u301yHEGuqNKFYphpAUjVLbjoq72roum6mF/bW5rZdiP
         QrN9rdzpRqvQe2BfCMqTSc610t20BZkgUArQazREpRuzFVqFtd1eDVLwvAyMUbULKaNA
         zvCRrA1EuTwE8Kwo187LmRi8C3awn2ojTlW5EQApyhPiwFgo6WWIHPAMEgJQ5IYSMvWp
         y/xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5Gdmq2qjfROZv69D9xaMI8RKjkK89zwHBtmHfuYc6II=;
        fh=WUiBXziIa3U1F/x1FRuIQZn5soTQeGnFz5/rDYYN7M0=;
        b=VfHPN32cBO/2JOIZZpYHNosaTp8JucIo6RVTt5ze4EvCRAadodDjF4Y3/VzQN2hGrY
         eNCVj22wEw+n01lFDcwObG0w60aDw/ORI6ShRsiCPSn2HvMts70cLcH+4uZliFeX+l94
         9hXngl1EvVJaAhiQgYZF6bPirUcgNW8dhuCeb6hVRjy7/2ldO0+owY8CEflxSkcOsdFm
         /D6dpwFR99+SWGspQohg+at0HUyxDrV/4ygyFTA9NgDoGW+cvp/2qgJVOlY6tlXNMPrR
         8o6KYdKrukGCl/c2kRwM51+znqPoVy+WrP0aU0/TQVHJuDg9U+0QTsoj7zXSXNwCaWhh
         oviQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cgRR9XDQ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293203; x=1718898003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5Gdmq2qjfROZv69D9xaMI8RKjkK89zwHBtmHfuYc6II=;
        b=lCy9eoF3jqFT8EzEJD99YfRaciAPV+sISAy1+76rb/oT5bMDY2z9iIh8GRX73WSBxx
         wB17SEHSUs/KkoxXR7L2Xg/WfoN91CmUjoBwYcymq4d/1rAFtWm9G/+GT+yUiSXG3Dm1
         fxCu7tTZVaa1yYNEo1RInOyo0negcyFdEEmd7C4OyQBnMAGQmFnLYcjRIe96TS/pjwp1
         6PdzeVLK41FqKhT+++z34wFWtSkJsDLCF/Ks+mKQFeJtx/wWQBMZVbL7G9kmfxVXIzD6
         CU3NXi5NfBP/CVFSdqvIplvczeAz+SWCSj77H5j2ky3nwhCvPXyYfdHzgX456m/gPck1
         m7KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293203; x=1718898003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5Gdmq2qjfROZv69D9xaMI8RKjkK89zwHBtmHfuYc6II=;
        b=mKuPdn2EgWmpBNeERdhV6vd6dU4gO9YB5QoN6EkYF0pxNti4OJeW0Th4WULPzBuCAR
         s18x6guqAaTVPSXad3QPDS0Y1TJ7LhfXB4ASCgkATRnWO40WujbUfzl1uoNwh01MsmVZ
         3W8iM9Wea7NaJQ0F7Vkhx54v5xhQ+02UAKlObkt3u3j6TsIfn1T6ZUpcHT/eFquLlrp/
         i2QO1zXESk0q4MjXkcfbt9QgsVfU4k5+rL7EgMZPeVWfIpkxO5xrTTNr7wXYh9EoiulA
         qh4ousr92JMKG8rp1LZRJPb2209a40/VxU3aHFWxhfiekv6w1qAA99abmlUD3Lr4hGAX
         1A8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZmHbLXEYiipKDDvABJQzHi26lLgC1quMzuZWgl1i+9GmU87+qshLuaaSXMACzVRHQOvGrtdjtZQPHvrJG9g2QYqTI1RQcAw==
X-Gm-Message-State: AOJu0YxjOEyKk9f8Ks+acoTdY0Jm/Cz4yuiwFf2WpWXcaTirUd6n+tbj
	00m7zgqrZjEKLkjM20WW1OjyanhFP3NDdsVsDM5LG7rrGGNNIXfE
X-Google-Smtp-Source: AGHT+IH/KRlz7BN/2P1bNz0wHGl2DQ0ZdpCvJtXxGp3btCMxtuhfRuxr4XK0dPw9G8NiV1Y7YgUBiQ==
X-Received: by 2002:ac8:5a87:0:b0:440:5ac6:511a with SMTP id d75a77b69052e-4415abc2946mr71934481cf.5.1718293203583;
        Thu, 13 Jun 2024 08:40:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:130d:b0:440:ff43:c1cf with SMTP id
 d75a77b69052e-4417ac238a8ls11308551cf.1.-pod-prod-08-us; Thu, 13 Jun 2024
 08:40:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcUXQSfuVeCpG03r+CSm4+Z1T722xOk+wS2VG1V2IDWkft9DWlwTd2xuUebjv1zRGFpufJtbhKsR6MDIMqh+cjJinuZ8pz+LJzlQ==
X-Received: by 2002:ac8:5a0d:0:b0:441:207b:51b4 with SMTP id d75a77b69052e-4415ac65af8mr49318821cf.63.1718293202799;
        Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293202; cv=none;
        d=google.com; s=arc-20160816;
        b=P/yTukW/oXny/gJ401KvQYp7h21BGYD0l+PhJwo1BcyYTVIY7RLvl6HOPKkMsKSY+I
         Aow1FwPlTVMHHAwbWq8AaKC95xIc2vhIZZwIbIegUawqxCUGDjB5j7LLiCoaLcPqlrKT
         Zx0VtH8e2bYpFowP4k7LkejLs5kkZudS+3I4V2ghorXrngKfQTGo6iX4p3KtkxBwYwNo
         cqOpl0SRRUo0pm1LUmQCXuge+l8YAm7Wpdp8UoZsQwn/hEZ8xAfinDTfxGzlo145S1kg
         Z1yh6FPH+XUWpvW/u9uGq8Tk+Ynd8ee8j8SQ1hZzQ3BSX6+UT4zUF4utF5cLPitabB70
         5n4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FaH0SIlcAdxNd0AxCUElyzwSaf+9XT3DwQzTJtkbdgk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=IdFmfYTuIjoHB9oiR4aT//hGe63nnLpnNW6R3qecDWw633BuslfP5eakvtqo5zbiqC
         dbfiSkV93mKxICu4r/jYAvyfOQ1UUqKdv9uEqUKbXachFIufUHNYkiNscz8xeY7fSjOr
         Engxqh1uRX43JSsSNLunEtqbLCSZXzT5nE2KBsHEST6AhUEhQnJ5tySEMQbIo5cqJLXs
         0KPYuBoqXmJjAePCyEPdA9IIOZjvExPotXDnNr5yH8/r0pzBJahc2RFSUSqcG3AXoJzE
         4zHnazgqb68/409/8POrVDyoB4iOOzhbShBC0JiheMOdpIURWM9U6tAe1e9VzrCLHqe7
         hL3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cgRR9XDQ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4420fefd601si720141cf.3.2024.06.13.08.40.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DC85R0027559;
	Thu, 13 Jun 2024 15:40:00 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw7hv3r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:59 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdxlf022275;
	Thu, 13 Jun 2024 15:39:59 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrw7hv3m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:59 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEbYAC028651;
	Thu, 13 Jun 2024 15:39:58 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1mus9gp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:58 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdq4w17760576
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:54 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 48DA12004D;
	Thu, 13 Jun 2024 15:39:52 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B5F1220067;
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:51 +0000 (GMT)
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
Subject: [PATCH v4 35/35] kmsan: Enable on s390
Date: Thu, 13 Jun 2024 17:34:37 +0200
Message-ID: <20240613153924.961511-36-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 3APcB-1vlHNVWzvKRh0bQQx2ADopofn7
X-Proofpoint-GUID: tPAGx4cvGA2kBxCO71xRcrOJzxrpCF72
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=756
 malwarescore=0 spamscore=0 adultscore=0 bulkscore=0 mlxscore=0
 phishscore=0 clxscore=1015 priorityscore=1501 lowpriorityscore=0
 impostorscore=0 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cgRR9XDQ;       spf=pass (google.com:
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

Now that everything else is in place, enable KMSAN in Kconfig.

Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index c59d2b54df49..3cba4993d7c7 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -158,6 +158,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-36-iii%40linux.ibm.com.
