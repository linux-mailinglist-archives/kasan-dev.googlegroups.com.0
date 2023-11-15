Return-Path: <kasan-dev+bncBCM3H26GVIOBB5OW2SVAMGQE6IEKLDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id BE0257ED235
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:02 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-5a7af53bde4sf466017b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080501; cv=pass;
        d=google.com; s=arc-20160816;
        b=sJhLwgCGGyFSJfcpnGcXtolR6P/WbXvaaubw/baTpQon1aVQFFnOctVloVcLcSTsGI
         EL12z1d3iYrdJWLAsH1H4WrCnXFezC/O/RiNpTPPqbveBNn/kMyNgn7B3TE/s6zayOVZ
         /nyk3ZBNHlPc8KGJcYRYvr2VDs+/qO9wTRzxtWXR0dnMyJCTiJwjaGkQVr1YxkOluq0b
         ZsgybDEScKKIap3nFhM3qFtg6gomSf5EUImKpDGfPHhVr356vxWyOJHR/YhA3ZtrpYzJ
         8saus7+1QI21xCFQ/Aj7+7bXcCT8utC+VlBNZe6WHnDll/awwwERYJfOc6a+f6gDkAHa
         mlYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q9ra4jnxIwGTwrzGKXbM5ZiusbVnU8h3BeJ3kfGIWo0=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=QQnxuTdhXnDlkE8r3CHfZXRZ1zuTt9yNcKodV5I2EtIwkNbNslT2S4dgEfIclU9Wdp
         WV1jOZzMkDrnjNruiGuTnpp5bsEI3mMKA9lVcv7PUGdMWtYG31zeC50nZxi4LdUiEECN
         bWqajTzVR/O/RUdvC02rYUOU3ufW4r4QGYbs6Sb6li2KXBeQIn9i9XyRdbNcDjf2/+OI
         1UxJB1WQOxQV9GcsFngnLkY9w0SjEvAEHbSUJNqfpFwifcUsp2hGB7nH/GBRwtkdGbhf
         BzdAiVO0+MtYoEOIxgdWFhWIajKD7dZ4P07i0JVeVDIyWzSLF93XC+zsK/+5j9IYO0YL
         XqFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="J/1G+a2w";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080501; x=1700685301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q9ra4jnxIwGTwrzGKXbM5ZiusbVnU8h3BeJ3kfGIWo0=;
        b=eczfbCOi1/T5SBbjU8tKP14V/F+1fgYXzadvGstbuU6QaUGL67WMGL5oeoDhiPPGUj
         tPZnkinoEinUhnhIeg2riXUjQmkX42K0HFjf65NeFS/ZGh+IrCTkwaprPWD+SZAN05uJ
         J3E306C3ynDHf8WipimxWFOxe9ZiPmihbuhnhS+x7PeFvWb6+BKY+n7vTSHsWJ88OJrc
         pmoPHoikIcncTQ+EpYRDQa+x5zWCVmNn7Az50Wcu0uG6vSE0Osn8SJk70r1X4zBQsup9
         nUC240qOBGXik2uy/o8bNHKtvagmYBUeyKMukMsmFHmTwyKUMQRwWFD9cf59F9sPakH6
         QJ6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080501; x=1700685301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q9ra4jnxIwGTwrzGKXbM5ZiusbVnU8h3BeJ3kfGIWo0=;
        b=uboxNj2ubS5T2sgbGIdL7klIWiUM3zSbo5arWRc/wTJNi6SoZOvcEdB97++O1hnZE1
         EJZwjo5HTDfJhFM5EPtYwhior2hYSBOolpCBV97ZR3KGKUoHb6YFOeHMAm/MtTEcIboq
         jTPfwzslqz/9Sp+6irOWr6mtJI7CBFbQ7OKVOyDo+V7rI9YeGbf83Ltarrh8wDA2MVMB
         kProd8V+wqiPhHXKJeiPR+DEsNBWhfvEpC3ulZ/CqM6RWexEMS5q9g1hc1MI+4Ive/78
         d6AwsgbXCfOV+qwxrlCa8uVa4dwnRVQDUhOoB4kXTquoEnag63lIcl8UxlM80amBo2tV
         FdSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwDzupeEH4ugMcmC1XdUYKZos9EojByx905KEbo0lI1we6cvZ9L
	5g0NrAryzNXLHPm42jUVl2U=
X-Google-Smtp-Source: AGHT+IEN9gq5xmDSxv/9sPmheFOl861S4Qe0/maO+Cs2iEvrkNm2HzKueBguNlJ5Zzu1AphIxyCMCg==
X-Received: by 2002:a25:da02:0:b0:d9c:44:4463 with SMTP id n2-20020a25da02000000b00d9c00444463mr14169368ybf.34.1700080501452;
        Wed, 15 Nov 2023 12:35:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7614:0:b0:da0:33b3:b1b5 with SMTP id r20-20020a257614000000b00da033b3b1b5ls186817ybc.0.-pod-prod-08-us;
 Wed, 15 Nov 2023 12:35:00 -0800 (PST)
X-Received: by 2002:a05:6902:120a:b0:da0:5136:3d95 with SMTP id s10-20020a056902120a00b00da051363d95mr15230765ybu.40.1700080500642;
        Wed, 15 Nov 2023 12:35:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080500; cv=none;
        d=google.com; s=arc-20160816;
        b=UP4DQoHLJDFD5iuTYMEwSdPiRfTLo+Ks+Tyrv0wwhwlVZif8DvOAK8XjIrJe23zAtr
         OA36HbYZwyJ6hl0qEClCUlFC/QX8Q+YPKa4zfcy028BkbJWKbjp6BqJmtMVRe88THLhl
         1vJVFop0f9+Ym32LCR/MLJUBMZilnYwdWcZiJk9qwXs+ibmrz2MWaVIbG98HP7D7gg9C
         3dIb+YAqAyYwL04RGd1BA2l/g6MrUiKeWi/B/AEzN8c6G/FGSTaJiuG6xXUsJgdMbaUY
         GIDY2a3V/9uT2mQ/GqP5Lzk+CaiwmguaKwpqZTU+8yPxPejqO3HhYntMjY7bTS82NJJ3
         QkMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=txn0Nm3A6Bd+5R+yqHglUeHWs3ZVMkuzDYQpRh6ALKY=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=Gak5qZ16JDQYQoelH+rGjtXhyeL+DQ+XtQzDnnognz5fRvEhZP1acprGbPS1lqtLT/
         mH3nBZk0fiiL026nSudhZ86rkEdhFlkOnBGkiHjRxjSPDRAy61zFkyJ5mCS1OciACIN4
         racVOowGKwwgwAvly3de+6tASWSyACnILm1T3jRDiIGuHy/sqruQ1XqzLU6Pa1zUDTho
         hIuCS8JuGYLOO5lfsV8/OwSCbQ+TtPf0WJ6byYp2UL408Fui1altoPlPm3Z+MIV7Dte2
         9gXxJR62vU5IYbln1VlJyMqMs/iKSCJav5zbKq0JKSATbFtB7YVqQIOx14TAosu4O2aD
         CkBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="J/1G+a2w";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id a91-20020a25a1e4000000b00d9caa2a9dcasi713455ybi.3.2023.11.15.12.35.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:00 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKCEIF020015;
	Wed, 15 Nov 2023 20:34:56 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4thgk7k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:56 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKEGqf028390;
	Wed, 15 Nov 2023 20:34:55 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4thgk79-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:55 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ0VO024857;
	Wed, 15 Nov 2023 20:34:54 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uapn1sj9n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:54 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYpww14025228
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:51 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9E23A20040;
	Wed, 15 Nov 2023 20:34:51 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 528E720043;
	Wed, 15 Nov 2023 20:34:50 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:50 +0000 (GMT)
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
Subject: [PATCH 25/32] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Wed, 15 Nov 2023 21:30:57 +0100
Message-ID: <20231115203401.2495875-26-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: SCD-ImPzpNT_UYdLAN09phOADQY1OIx1
X-Proofpoint-ORIG-GUID: MOiguhejUGycxsJ8O1LktBF6RwjZTolL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0
 impostorscore=0 lowpriorityscore=0 phishscore=0 suspectscore=0
 adultscore=0 priorityscore=1501 mlxscore=0 mlxlogscore=999 clxscore=1015
 spamscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="J/1G+a2w";       spf=pass
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

s390 uses assembly code to initialize ftrace_regs and call
kprobe_ftrace_handler(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on kprobe_ftrace_handler() entry. This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the assembly code and always unpoisoning ftrace_regs in
kprobe_ftrace_handler().

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/kernel/ftrace.c b/arch/s390/kernel/ftrace.c
index c46381ea04ec..3bad34eaa51e 100644
--- a/arch/s390/kernel/ftrace.c
+++ b/arch/s390/kernel/ftrace.c
@@ -300,6 +300,7 @@ void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
 	if (bit < 0)
 		return;
 
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	regs = ftrace_get_regs(fregs);
 	p = get_kprobe((kprobe_opcode_t *)ip);
 	if (!regs || unlikely(!p) || kprobe_disabled(p))
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-26-iii%40linux.ibm.com.
