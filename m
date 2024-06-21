Return-Path: <kasan-dev+bncBCM3H26GVIOBBQER2OZQMGQE5SHNVEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 14693911741
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:42 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3d2180b12e5sf1410838b6e.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929600; cv=pass;
        d=google.com; s=arc-20160816;
        b=p+ulllDwbTx8XAfJH0DpnoNvvyLraUgAplTfPtbQdew9pbMJ0f1J6KQ76/vEeHzSpH
         MkjFskKVgtze3XfVgR00+GKThQ3vIw2wImavSBTMQx/xCTJXpwFyOw/fhvF3KWOd3cTy
         uzt097BAtKy0d8RkkJTmyi2QhcI3OYtNhWjNPVrBF7jp+ldsukP87Z4AViGZdqDLY/6a
         8NyFHMkowfHLpL6OdFbHCCRzDVIpjg2O/s1ewL/CLrD69fDON6EYz2fvUE/tmLerwKV6
         BOiURuf5dZDvM+vOmrNKIBjaZrGeqTefBdRGQuqCXg/63gS4beEUg506qCPkElb5R1FD
         T9lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rfXumJ+Di/Lgf9mgw8guk6mNX6LxIBxaizK4/gB0/8Y=;
        fh=z7orOHNkLGI6+hNZhcerETkCMwSVbX/i+cvkZ27NJSM=;
        b=hHT1nAUl47jd10aVcsSv7hjNcmfb4b20VJ+TgN9MXzRLMp2NX4pMH5wuU3JHTBDVpl
         m75iUMk8Zyv03U5VOybFU+qc4dw2azEAOg4TnCkOjsM6PlDcvz0Q7YlBCzySIZ9TiljM
         GJp50KWRdsRiaFSBTeysxipuJljzgRMXlNCh+n/AakFlhsgqzpn6TSZYu9FVrkSfWcnd
         wK1eR7B4UyRVc+hCDdEb0AnGrmywoNLNiGiLglsgjgOVehi+32UG0dIGSna2TLacLhG8
         +4CzUIgUk7la67Ix0v3iJVLoYyed8++VbfN/CA6UcXdYPdprQnOLUgZxiSi5JxbFJP1N
         +kwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=L6dP68G5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929600; x=1719534400; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rfXumJ+Di/Lgf9mgw8guk6mNX6LxIBxaizK4/gB0/8Y=;
        b=Vn6OE+PAeUlG++d0z/m4OqSe0obMextF9P8Eiq/IS4ErGmUcKBcIQBY6DmipfhTQ01
         sAGilYXuCjvt28qIa8j408LRPmGVl7/89lUvTAqCmfboK1llCRkY3SUpNtVdumIb3Zx3
         Dy2a3WrO7b3R72nLO+bPWQ793JIaOkKzu8KXt1yJ6VZqmrdPBeJ86/m1RNppy5fcDpaq
         gnB/C4j214iqA89R3gCCxMo76WH+3VOWKCOBD13eTD4NLUXNteCoJeipyu7N9clYBKlv
         Su0DRx0VuQ02gDEs+QiQs/xUly6ngfOWAGjxB0d8+idSm5V/y9mwP5aXIMMf9Gt15kWu
         MLMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929600; x=1719534400;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rfXumJ+Di/Lgf9mgw8guk6mNX6LxIBxaizK4/gB0/8Y=;
        b=XbOQLBnNI5Ve5jnG12rHd4LJfV7RUaQ6+1M0OYdKkj4EuLx1610vqL/fuZ+qE0WokN
         zi3DTWgt2kCHroBWiyuhMYB7mlZ0Jm3gDPlITwGwcS8DAzlS/9qEQwMFU5kImlLWrxe5
         aT/YbfzqVIFah98fP4/krqOreEtmWnyCxI1LD7TxEcZRvIRbAaC9Z21FYYVGYZAARcPp
         wFBJ3Yz6V9tNAZXkSys+9knqyKmI8w9z4wdGYPyXydjEejD4WWAP0ALphuAGLvwODmkM
         soTO9unhiKma0kqnvGf9ln6Nu0rR1rRA+yCLCakQ583PzjYZwacM7ib6+sOUospNsp2X
         UWJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUKLvI2a2ph7S8gxjDx0NI3UhfM+1yf8NmoovAZf6TcFKP/DmHt5cx43VuTGCn2V9r/alK3l6hh6PULpfAs5rjAFp/Oa4j+w==
X-Gm-Message-State: AOJu0YzeSt0ovGixUgWyrbT9O2cPN7zzvyB/CnM35hqLUj6FsglgmkqY
	CfCvHzYCHlKabxQOM5s44Ttg/rjaYJ45PGf1KbLWpem2n7YTocG0
X-Google-Smtp-Source: AGHT+IGf2n49yuzkwhutjkZOZ7IgzrXY12DfSjRILDMk0GMfM00xbMKgdVU9IVBCYyGN0cVNKBHkbw==
X-Received: by 2002:a05:6808:300a:b0:3d2:2a17:9208 with SMTP id 5614622812f47-3d51badd4d2mr7119980b6e.51.1718929600152;
        Thu, 20 Jun 2024 17:26:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1ba1:b0:440:29:dfec with SMTP id
 d75a77b69052e-444b4bf510als19395531cf.2.-pod-prod-05-us; Thu, 20 Jun 2024
 17:26:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTIb4HQadiJdh+7aC7Q0reMY4eawG4y+Yfc8lv+o0fqeVn4hpfyCa+qLxcBIc5QlZ0WaX1bEciy55J7/4EHn68/+XS/MV3QVVN8Q==
X-Received: by 2002:a05:620a:4481:b0:795:5546:5d7d with SMTP id af79cd13be357-79bb3e2d846mr741877685a.17.1718929598914;
        Thu, 20 Jun 2024 17:26:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929598; cv=none;
        d=google.com; s=arc-20160816;
        b=DXgQy/NlH49TogPIrGbHh9PGHqc10Yqbj0HTvlYNDByTMTmiwCGMuhm0w/g/IeQDg2
         yuazE8xVZV5qarTtX9dTDpjE3H1inAq/o0SekQKBJESnsnATRqjOQ7n7hdjMu1Pme+mj
         t/mVjImbyq875US4QZ9dxSIDTx/XEm6rN6ZCaiqjYQa9bEtW6UiqgNOxWZzG6tS/iWxM
         MLIr3moG4rx24Py3uhgy0yFeAPDdTMpRBJHZIgEDwTM5yZp2e+XGNNTNLjL3j08Wp2bB
         okSL4vzDwcEfhU68irg04i8kplXVFj4ScMGTtSXs/dk96oXtucitlZlC///BaHbTZVyK
         P/7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1qF7H4bGHDZ6iOOMBP071rdyF1q1YAWA6gRStiWbHSM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=TFDAB6ZGs4rIu5ATpFZDQ+YQiO6Beod7WfwX7MIFRpA+G7kvN45qInEQbamySMdQs/
         nkWtob7Tj/AZfCt1lnQbl37CRhfudROm4HrFz7OaO6vWoMpOKIYDzByOgXTfXt1ZBFlr
         HEA/UoVHVxW1Uc39E39SoRTSFPd0jXli92Ux2BPkdOOdbZr29NfMOsgkIFggTdL0uDKw
         L8EzDeKh4EI8B/k4wgodiMa1X07rSMOifLr3elgJ3D5crlKXyrmo46FnRhE+iKWdQ/qr
         Jjl+YNMJfF4U5eVEBBFh2M6f86AJdGS1r+l7EvGcRaQkEkcSRYWNBTAslwzQfxmbvPWU
         umYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=L6dP68G5;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce92af8asi2312585a.7.2024.06.20.17.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNumLQ003943;
	Fri, 21 Jun 2024 00:26:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07sp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:34 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QXBP016871;
	Fri, 21 Jun 2024 00:26:33 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07sg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:33 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0P271031899;
	Fri, 21 Jun 2024 00:26:32 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspjmxr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:32 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QRvO45547990
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:29 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 56B5E2004F;
	Fri, 21 Jun 2024 00:26:27 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 342262004D;
	Fri, 21 Jun 2024 00:26:26 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:26 +0000 (GMT)
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
Subject: [PATCH v6 06/39] kmsan: Fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Fri, 21 Jun 2024 02:24:40 +0200
Message-ID: <20240621002616.40684-7-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 9s-R0l14yN1P22cOocXjzWylR_7tPsAd
X-Proofpoint-ORIG-GUID: wO35Gyn59K3jEAxcktTf7rYqUMkVl5S8
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 impostorscore=0 adultscore=0 malwarescore=0 spamscore=0
 mlxscore=0 suspectscore=0 bulkscore=0 lowpriorityscore=0 phishscore=0
 mlxlogscore=799 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=L6dP68G5;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-7-iii%40linux.ibm.com.
