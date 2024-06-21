Return-Path: <kasan-dev+bncBCM3H26GVIOBB56L2WZQMGQES66HE7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 66D1F9123CE
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:29 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-25989b941e9sf2195952fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969848; cv=pass;
        d=google.com; s=arc-20160816;
        b=OlEmHG9t+JFdXQwmRbX0Qryviws3fOpfArFh7W4kBmQgSVOONB4l+1d0uX1brH4bFq
         Y9seE7ifBJL2XzZEEQiLzV4rQHvSj+SLAY2GIFqlZxPsgYwi2J2EndrmxvOqGooe3JRy
         8NBQjvO/iQM+M1a38IskUMBZN1yHfNl33bCAgsvGtzm08azC8nPEcOkKoasffFdw2UIR
         +ixmSl2svzPp4bysAhNJGsaQg/MmvCNx0y+jUvo8FuzVVLcnQsOGcRSkI1vYwK1v9NzO
         jZd+NuJ6U9NVvifn8R8qBgImBpMDd7I/nYhUKrvmAkQiqqiqrzSEOwLZWd6rDetoEv2I
         x3JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xLf9QAAPmz8Unmv49drjBC9VbeL/DoyEIOyjnMW2wTA=;
        fh=4hdoWP2YoULE8TGAI4RZU/1D6PpexZa3eGmYD44EWFk=;
        b=E4ZD3Rx4hn5QjvZJ8R0N3DjTHj5IBXxDowU+gyJ+J9QbGP0PvpOF2h4Vfeu8SyaUN9
         ktf31nTgbcMF9Kyh43eK8ZOmIFplafsn6ln/X86iRwLoaCXb188dQhdSdXCqgis7pPwV
         vvshjH2LWrBOCVTlHkb4d/9ww8BOf3MDsjePrH7WiO07xGe/Quj61gwQI8gkwj+PwFic
         pfNhN4YzonBV+lVmgZyKRjkEQWNPRP1FC0XYhJ7shiIXjJl/A7veY4JROjmTTacBKqeZ
         ghA9r0+i1Cfgf4zy9jQ4QI/YH5+C/GfXtoSJFT6v4IlvJadT6Bv12PZSlX0U4BFTlMBk
         GuQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=bOj7jzux;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969848; x=1719574648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xLf9QAAPmz8Unmv49drjBC9VbeL/DoyEIOyjnMW2wTA=;
        b=kvAHj2a8+ZbdJiu/0E9yjdFBV1u8xp80PWJCYRK9g68L8kNNWHguQJJgdeIRNB2gqE
         PqpHo+zxIPvpxEHJosxnlmghzE+56KIwqoUfBbx4ltZ5wd9E1n7QVOmz/q8XJOJVAgg7
         pdWT9eKKtWQI5Jyi8oAJ+iO5sTLS5jCX8zGdTxUUqF9en8kxKOVzIfqEHppMZhjKKfCR
         yDNxtVjatkNDvRJcxQJuhOyVEXtSihLoVGFa+ebWuRsui9NIODfQb4Wcuz7hOyOM8fLu
         7Xt9uEYweTbDn6/EylWacHMr03SduCnNZvHgi0sjTwMvERkXnPbtm+7gmqZp7I0G9+jN
         IuEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969848; x=1719574648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xLf9QAAPmz8Unmv49drjBC9VbeL/DoyEIOyjnMW2wTA=;
        b=dDUncXIQ3tbnke/zgpJ8wsI7UymO0Ww53D9rbgepbIFPzWo0HUmgCaOhqP0NxBrqrV
         MrBLsQnAivGHivNg1ldMwQsXiwjRtEPuFCZ40vMl6nLt5nYH8iiaSjbC06RGAKRUBzVE
         bxVNeMdFQOtegUa8CV2CEsmAmdMtRVewI1qswTxQRJRCuqhO8GmPeaVefq25qvXFaHnF
         5L301c+HLtH/mxboW7lp/OdDU/OVaEX+iaSDTonepcZlke8tKqn7RypHqUeG0PUuhf8j
         S+8M5zsCpomQZCsbxnqWHmBkjtvMgxegrchS9uUfiNkR+D6HSLp+lGCcROzfqYYPHMEu
         H/2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXm9fm/z87b895R7Ye2+T4UFghR7bNBR5rg8auOp1UpncyR8D259FyW4EIMWoDJVsm0gu3tOLDSD0drBlFjkBLGYlFHtU8MAg==
X-Gm-Message-State: AOJu0YwoDQiZsrsaH8xtwLYJGNGTllyHFQ2SvpfKm6Qq4vxbYMp2Ko6+
	OvH6j5yMi0Ko3RZikdqhQf+DnWhN+rSob5Gp9nfJUr8B3NeLR6ms
X-Google-Smtp-Source: AGHT+IE9MJYNniSKeNcWF3ApQBc/lkU+jmQ2hz1VXXGfC/uQTR5xKcHuRbvNt1HO4Fqix18gaZFJPA==
X-Received: by 2002:a05:6870:a689:b0:25c:a044:bbd8 with SMTP id 586e51a60fabf-25ca044bc53mr3184472fac.22.1718969847757;
        Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8042:0:b0:5ba:6b54:d29d with SMTP id 006d021491bc7-5c1bff406ffls500045eaf.2.-pod-prod-00-us;
 Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvlCrl3EjB9Bm6vxLAe8Yq9zjns7aiXD4+RyL2jJ7AOIPeUbyplP4pICLcNFCUPFHpIX0+3ngFqIAeCq77X2Ejyf7dh1TVDm/nWg==
X-Received: by 2002:a05:6808:1b14:b0:3d5:145e:36aa with SMTP id 5614622812f47-3d51b5d6383mr4234696b6e.8.1718969846927;
        Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969846; cv=none;
        d=google.com; s=arc-20160816;
        b=BU/oXVtRelk/Ddjjy2TOY/b5gt/qpDHhinGq3dPQk/SNc7hp13QS2j3OZmpXNLRvZW
         Bz8nwI2KaHlts3oHxLgGEeHwUvFCREZAPW9+Ade0J536973OOpFhNMByj57a76UEpXt/
         8qlpcdmMvNHNfV/64mUZwjp6LkzLn1f0ShKznTHHFLVlH9dW3g3p7txplz05OM0Mq2Rq
         Vx1Mq6R81wVJS9SFZ/8wc+JhzMNuue6cb+DUfUYpj1GPcfY5tkphQDkp9HDR0uZn4KRA
         N2JeuS7mPIa+AwtGrHFVwtZ8OQLYSFFE/6KBZ+pjSo8jjD5spXtrIaYjrXztDhIUY7xT
         NaTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ah4xfVCHNViASZu9OS8C5bCxAH6NMTO/t1qMSUm0DA8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=mQ7MMWYtOdjT1wbYj6wKUoNa2Czt1iacS8l9gezS9jSfDJNC0tEor64U398IuI3Ai0
         xPQoxEvXKWtr/JezURzMuCofQUf6cuuZUfzwo/CPL35qbiLsj9avUXj4/f/VwQKKrHds
         ZSdlNTquDKB2xRA69DM73lUUOOUeYOY8VMN2F5QpnATmRVPRNyGSEL2t+yXDMruuxUqk
         ysqVkhyzZIMe9Cp/GFqL8eRCLkRnoRGG0txesqxp7hBCvMg4NApcbhu7Po5gvKQ9l0F4
         QVlL7oOhz3vANcLaTqLhAVGbzd0mKzs1WnKgOPiYwfLipW/SDC666622cvpTe1LsS1v3
         x+8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=bOj7jzux;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5344e7c93si56103b6e.1.2024.06.21.04.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQvQs018553;
	Fri, 21 Jun 2024 11:37:23 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09bm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:22 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbMEE002078;
	Fri, 21 Jun 2024 11:37:22 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09bg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L963JL025654;
	Fri, 21 Jun 2024 11:37:21 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv6vyp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:20 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbFMY54657406
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:17 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 44E842004D;
	Fri, 21 Jun 2024 11:37:15 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A7D9B2004E;
	Fri, 21 Jun 2024 11:37:14 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:14 +0000 (GMT)
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
Subject: [PATCH v7 10/38] kmsan: Export panic_on_kmsan
Date: Fri, 21 Jun 2024 13:34:54 +0200
Message-ID: <20240621113706.315500-11-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: E4FeJ2DPMtQURj23PoX2Hu_rIGqy2sFA
X-Proofpoint-GUID: C0x7oDri4w4Z6YRQjvyB2pwalipPRrvm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 priorityscore=1501 adultscore=0 mlxlogscore=999 impostorscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=bOj7jzux;       spf=pass (google.com:
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

When building the kmsan test as a module, modpost fails with the
following error message:

    ERROR: modpost: "panic_on_kmsan" [mm/kmsan/kmsan_test.ko] undefined!

Export panic_on_kmsan in order to improve the KMSAN usability for
modules.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/report.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kmsan/report.c b/mm/kmsan/report.c
index 02736ec757f2..c79d3b0d2d0d 100644
--- a/mm/kmsan/report.c
+++ b/mm/kmsan/report.c
@@ -20,6 +20,7 @@ static DEFINE_RAW_SPINLOCK(kmsan_report_lock);
 /* Protected by kmsan_report_lock */
 static char report_local_descr[DESCR_SIZE];
 int panic_on_kmsan __read_mostly;
+EXPORT_SYMBOL_GPL(panic_on_kmsan);
 
 #ifdef MODULE_PARAM_PREFIX
 #undef MODULE_PARAM_PREFIX
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-11-iii%40linux.ibm.com.
