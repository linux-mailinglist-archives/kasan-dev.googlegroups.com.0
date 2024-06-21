Return-Path: <kasan-dev+bncBCM3H26GVIOBBCGM2WZQMGQEJJRSKII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 615CE9123E8
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:45 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-43fb05ef704sf22305691cf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969864; cv=pass;
        d=google.com; s=arc-20160816;
        b=xfUtv3TBhu56D4JP22AZpDFTORjN/MSGWQnNL3h0/mc8cRRGrrqbJZsS/wvAlilvmg
         EUKP1ZzI1qiHqAuy+ejHB5r286FOiR4A/M5aX5vA9G6xhBbiDKGuqUeKdVu65XVW2eka
         ZwQuWm1DWlsPCT5KOKR6CvyKx1L0lrUJwn8wjXe9fkK5ACfiMckqLnk/0PuRZJMB3CaK
         UY4upaMJhWN+5EV+hZDpeRz5gxukHfvHmuHV4sfuDig7C3XKLPkJxH+wo+XIKxYqNSoc
         TWkwmasrJve8w8FSmUFSuLON3MfxQbPwxhAqDMi/skySlNkaP8CGvS4Xvdkg+ssxAmhz
         mfRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wUdC1kcheDCxlM+RDKWNXlQojTtg87YNl+O3Opzx8Bs=;
        fh=kOc3uJSOlj0klKPJbb7+mj1U/968qwV5MkFD3UHquNs=;
        b=OUPx3wHtTqWGxiq/rhO2Qmyvxd4I4BMMb0QrTEcE7FF/IZ5QNpJ1ASiXndEbahFmpi
         dIokKBndTWeBDd63khuRMwu5KzK29QmbVZM6mX/fgyipbg0Wu/P/bs+811IXNft3xoNt
         H0qF9u9iOKjbneXRjRIivlJTptvt0xDneT9h6o6P4hD5AjXHR3kMhFqZrJoMwpeonNww
         UPkxgNR0r1ez3YtkqMJc8ALptP8ZE4/GnM0MSJKSF5+oEIlgiByOQTFxnzbpuam+nAAx
         UPoP+5ZIXcDSz+FBMv8iW+bXGm2PQPiAKWQmMacUNH6sz/mHKnx8KzCc9FVLVvMskLBv
         IZPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="acXEkLh/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969864; x=1719574664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wUdC1kcheDCxlM+RDKWNXlQojTtg87YNl+O3Opzx8Bs=;
        b=K0fgHmOZxyBYUhGUtCjHAIubMFhSHmSQr0l7q2PxTqCl2AzSbSNdvqC2MTv0olidw7
         UMHL+kBPKJFzp47WjGUjzMbFbCnzzkgWe9aTNM8gtbLLdhEk0TGh/1pRiiUjUGC2d9Fm
         37Wa609DuuWI/JbmN+R88sXqMyq2eW8LEH1owkbuFQ6HLicjRoqWvHjTKWjrI9sndWIl
         gufdV7YZqADfgW7tdZZJoModJWQnw9NfwZTQ9+0VS3GEaYhIRl5mdRPPLGb3PWMHK7Dm
         L5g4eKF1Y/q0vFZWl+hrJATiMd3eIjhdhN/y+Jr8M5cEHKO3Z/vH0B98WQvyyMYQPVR8
         3SkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969864; x=1719574664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wUdC1kcheDCxlM+RDKWNXlQojTtg87YNl+O3Opzx8Bs=;
        b=LSgaD74xL90kWqun7yoWUX1Os3tvCpEB2vYhkUsyHBaXql5uCr7HnaMo9TMEZESAD2
         Jm/8NkoVcFmomAFEB421WqLtGjuD9yi6rdMUqRSJarJbJ7Es68Jb+IXQkpfJkybgVQNe
         P6hVaQudpBpUN64MzSUD7/Q8VbwPKtUHT3cTDHc9oMQ/J4IXcI7BnZwVoaRaLXlK5zaA
         UezpYUCO9HmS00NbQ8Vo/4dGaTpsHnCn//pk5OFiyQw5C7KylChezFtwBLuGspSSk4mY
         pnxv3Eh8xzlttLmPu8EW30U8zd6qdI3JqBw/+rfwyCNA04rqWQy6ntJonsYgOFPPZzW5
         uHbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVaxujwCiV4Bln3AARm6Do6r58hpx0TlLfgk8jo80bMVVFDCD23rUiVn167kPua5UQ0VPXxMTN/3M83kU7gPuRcs5fQzuMeIA==
X-Gm-Message-State: AOJu0YyLw8YBjkfAl3p8Q2mYCOHjBwzKkQz8vSR1oF/HjzKFiQyI6D/4
	w+wdvmnSHrNQaOrkap3ofKBnGdIvTuZN8mGh1Y761qgMaYHpK+VY
X-Google-Smtp-Source: AGHT+IFqwu5k146r6qxhl9uGgyWhIs5ehoQE3TxqREGUzpgaa1GvM7cdND7FahZ4icuQXhTBD4TE0g==
X-Received: by 2002:ac8:5981:0:b0:440:58c8:49fa with SMTP id d75a77b69052e-444a79aa048mr95401951cf.1.1718969864270;
        Fri, 21 Jun 2024 04:37:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1349:0:b0:444:b60d:34ab with SMTP id d75a77b69052e-444b60d3d4els18450001cf.0.-pod-prod-04-us;
 Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz5x/MKlkem6S2EIOLVg+5CXAPI6hZsQ9u2WMVbPVaYROdpOlFMKojdlckec3cERzbqsr5oIDN/IaBwvtdX46rIHh3GaNDPKsX7Q==
X-Received: by 2002:ac8:7f52:0:b0:43d:fa59:6461 with SMTP id d75a77b69052e-444a79eb49cmr86776131cf.39.1718969862796;
        Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969862; cv=none;
        d=google.com; s=arc-20160816;
        b=s6fV8Ql0yIJNQAbjfgLM/sJKutltrStW2x9GFAF9/VS6FHE3b7SgKqwvAJ0TcVMPip
         z4Wm+sFzjJnHPZC70RiwWoVloEY8x7TGxap6ufe1lPupZX9WnRwQEWFFf0TnJo9eVFlZ
         hUts6/zKJzywAfpzDojk2IB0p6ONZfTWV/sy2vKmNVX6A09xE4HlaYdRRlPrXj+wEmeB
         tHABMCF1ODTVWbTBZoeS4CFQUj6On0JbTMVJVW9Qd//8X99dF8U+vAb2uoll/oZZfTe5
         sBcV2z2GPZd8QL9koHTXyttYxT5vbF5i7t2zSb2oLwssGA52TbjV2kBFPswQPp+mR1mz
         4miQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aLe/3XBqno9Ykh6K8Gazkn5dKq5eSwzJESHfR5NZsd4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=XAuOdgYtzeQUQUfpQjkrRwRGKSkAdSvAezW36sI27j3Wbs5dNYZRe2K5jL0JhzB5zv
         2ESeZSH4IvySZAL7qGciQcdrTcN9hloXZH6g2l1tC/aeYl9j+XWGYCBxLz8rls4uXuTn
         GTuRCNsuB1QNBGDm+SAK4v9uoel6GiKJp5Y0eiMw+ZetWA35v0tiI0HxQxcwosoKfa59
         k38SJaHkMonMgjc//0SDSBfGFIrrKZ8n2AFPOF8NNI6Wn/X5sQ97y5TzA7K4EZyRn4bW
         R07xMY1RP3QWH0RnufJgIVI829oCSKicoWBCWNTESkYhDvLKJfJn3XYCH5LJMuRvmoR4
         v6Eg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="acXEkLh/";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-444c6b931a4si419701cf.5.2024.06.21.04.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LB1wEL032087;
	Fri, 21 Jun 2024 11:37:37 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw49cgpwq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:37 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbaEL022055;
	Fri, 21 Jun 2024 11:37:36 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw49cgpwj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:36 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9BsP1031330;
	Fri, 21 Jun 2024 11:37:35 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrrq6vga-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:35 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbTXu51052840
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:31 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5065020040;
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BB2A720065;
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
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
Subject: [PATCH v7 33/38] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
Date: Fri, 21 Jun 2024 13:35:17 +0200
Message-ID: <20240621113706.315500-34-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 4W3rtCu_nH5X8A2P-hq6iliOp8gXzPKu
X-Proofpoint-ORIG-GUID: AyWyEN58kjthDpoSHixMhSEVTnJKwLw-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 mlxlogscore=999 adultscore=0 priorityscore=1501 suspectscore=0
 clxscore=1015 phishscore=0 impostorscore=0 malwarescore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="acXEkLh/";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
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

This is normally done by the generic entry code, but the
kernel_stack_overflow() flow bypasses it.

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/traps.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/s390/kernel/traps.c b/arch/s390/kernel/traps.c
index 52578b5cecbd..dde69d2a64f0 100644
--- a/arch/s390/kernel/traps.c
+++ b/arch/s390/kernel/traps.c
@@ -27,6 +27,7 @@
 #include <linux/uaccess.h>
 #include <linux/cpu.h>
 #include <linux/entry-common.h>
+#include <linux/kmsan.h>
 #include <asm/asm-extable.h>
 #include <asm/vtime.h>
 #include <asm/fpu.h>
@@ -262,6 +263,11 @@ static void monitor_event_exception(struct pt_regs *regs)
 
 void kernel_stack_overflow(struct pt_regs *regs)
 {
+	/*
+	 * Normally regs are unpoisoned by the generic entry code, but
+	 * kernel_stack_overflow() is a rare case that is called bypassing it.
+	 */
+	kmsan_unpoison_entry_regs(regs);
 	bust_spinlocks(1);
 	printk("Kernel stack overflow.\n");
 	show_regs(regs);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-34-iii%40linux.ibm.com.
