Return-Path: <kasan-dev+bncBCM3H26GVIOBB5775CVQMGQEIUA74PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 62AAD8122EA
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:24 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4259021e5a8sf145391cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510583; cv=pass;
        d=google.com; s=arc-20160816;
        b=nZ8lgVSy9NrpxxYEWs8DLYC8oWfERuoBRq3xXFAMlCNrNTQdYhsD8m/SRQRmIKEkyD
         QQPQ+O4P8ahhjF7jpctBBrUWRAD2auUFuk5jPA5iLohKJPJgnnWvF4N12ubNxoOBIKQ6
         XkZ7zZ+wPi38d1LgflTmw18J+o9A3tEjdrrGYZNpgRg/By8zmHTAFnAhiD3k+qinSriP
         MoJGlbjLik+sbvYMVrM6ENPJ0eXadY5vKpk3qMNvoPmHjgZhPx0oMVsMlpM+R55fS2AI
         hR7XqqtUdxrnqQ4WeDvgqTZdOJVW/tSrKI1QFR9RK5TcXxI3V9Mz7j1wu5cYDwblgktx
         6/kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=a+JVs1ftWxJczWnScU1hvmzs5G9T6mP+C34p+U7YsvI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=fK3OC0aZ6uu5eQOZ9T3g2WrX6zrk5lsQGbA1E2kQNemAkN70a2Pv1uKTBgysVmbIzY
         6ZlCDziaykKX+Ncrofil3+9RYfAei6x/gcykX/UatvnIbZYUUFNJhGdQeSH2zkVYBJRu
         +OMsIumqy2s2pRhF6S1k7Fdi38jTrN3YH02Rx+Hr+Y1+kzNLFf3IdyLbvXT3FpvAjzwe
         ZWP3o5hU1ZAlEmgfxEfGbqklyBiwa0GsZa+NT36y3gdqq6tX3ZAMeBgWQbe/N8pIqcd4
         at8XiWbIFnSczH0IxeDaKXIcYA5UvFZdKEWntrHSoq++Hb3YuE/dijP+i7Ip6PhFoKnH
         oqQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="mVY/9tD0";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510583; x=1703115383; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a+JVs1ftWxJczWnScU1hvmzs5G9T6mP+C34p+U7YsvI=;
        b=WYHJyh/SYK+L1E7hLSlcitPLxmJHTJaN8SrEkOjSi2ZjYF9QkcwQrAuNUKuVaWbqtp
         QgWnUMi7KuVF2xVBeyblNV+YiNs4E1bN7Z1y4ZL+IN401qZoxJrUb4qiXZZs4Zzs8B/Z
         Zb7cMZMAryXBVOItV0/MVDQFsOhCdYqUmHEKgExtUVKUZRGUmG4XYny4GAlaovKxlmKo
         X5n7f0bQPfYQE9nLkQ7os7+2zb+JC4wHHnNSYyLbIDIUlHgnxGEvyVCP//6ucap4U0fZ
         xbbnIodUaGaplJetM76FraqMfpeQT02e3iQzRna9hTBPFen4cD2TKSZydqoRCdnt+4ns
         RloA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510583; x=1703115383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a+JVs1ftWxJczWnScU1hvmzs5G9T6mP+C34p+U7YsvI=;
        b=drkjrmw+5iKw0heEcW6WBJXYUqvujNb2Rm/xxZE32hY9+RRdKaARzzwFLnNrKjuGRp
         40t1J6wcc58fua1sQGj3vJbMy88XJCqIBx/HXEEbJiQ/QTFzzSPrzmcq5DtXPmIkqs41
         JC90X1dk54qeXugnrOuIJ7pLJrBYps7kUiYHjV07udz9DQsZxSY7GxRVkfKHgNmwGW8Y
         sz2f6D7uE5CdpRhuOcjgbdQiifAd+jLEHHay6hicR0Jgipo4IY64cQAd1E8UwX+wfZ0s
         vfIR54U/dT9Ujdh2LD6BjooegyprfskgMVKEAHa5klG4NH15r9voasHt77G/isbzREdA
         NlpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyqZRPudmeDvMekp/NtnPnkFRJrj85tHFNz0+ja7Sy6ow0j+mIU
	Ft7lq1gJBlAwPS7g9lLYD5Q=
X-Google-Smtp-Source: AGHT+IFPem7CIslJjDFauySF2lsrb0FL8ONbZ1fL2TeykUvAFWf7xwJCzu9q/nqHyDkWDM85j6hyLg==
X-Received: by 2002:a05:622a:1a87:b0:423:8b19:4e3b with SMTP id s7-20020a05622a1a8700b004238b194e3bmr1594050qtc.21.1702510583277;
        Wed, 13 Dec 2023 15:36:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1b90:b0:58d:be21:9e7c with SMTP id
 cb16-20020a0568201b9000b0058dbe219e7cls2745968oob.1.-pod-prod-03-us; Wed, 13
 Dec 2023 15:36:22 -0800 (PST)
X-Received: by 2002:a05:6808:147:b0:3b8:b063:6679 with SMTP id h7-20020a056808014700b003b8b0636679mr8216240oie.112.1702510582453;
        Wed, 13 Dec 2023 15:36:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510582; cv=none;
        d=google.com; s=arc-20160816;
        b=SAwr7s5kTk+Pi22WafUo4oE2V9N4R/C8JQVYe5ZS6NyVUORzl/NAfUu2np85ot/xBF
         PQ5Qbi9B9JrgVKlpW+iVk+JopHz9nQeArwwTWrosz3VSq93jAG5Xdgs/egAyMCgVg6BD
         yGwCrgJcY3rpOdUWSvF75CuEizkb+HfcMGXeX/Wf+G2FwP5kgSZOhz20WU1LBBjT2vHo
         ekPbzvwAiwuvvHuPvpuKu1lCTC1s+TQJkppdXVrvfIcDY3OrckMScxULJvCuDctwg5iF
         wLvJPqn4LsulpZ29tk6XSSAvogtOoycRxfW+OE2+sHnHmlfiEyLs5TVHnGJ1qEKMVFFu
         CbLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z5O8Oyz1u5coxJjuRobnuKDvdBCO6+4EcuvOmOBBFBE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ABZngj+Zjo1odMvHeSu76X+NTYdelI3JIg6jvdsPa7Acv7zyyfQORAWGxEZTU0lMlv
         IYmFwVZ+IQmGaCPWAXnay+AbEmwBLYR/WfdwezfCK/dxARBCiY9RThuJtiPKv2nijHRJ
         ofO3y0wgqZKlDYRfYL5MeSEVKN1k1Q570U0bG3NgnuBs9HcLUqy5xeHtm6nM1pUX9PP6
         MkjanUXs/VM70Ec4G20MjEYTwhaSJNgdraBQXxt2lA8C9IX35s2m6OjCpi+ZiYm8mkBm
         mDSv66CVM5wc4rE2ezoqEaRsKaXsAyA+Nn62jMiyzng0xW5rWevbivsyqNc3MnK68dlv
         168Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="mVY/9tD0";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id h37-20020a0561023da500b004649987350fsi3234887vsv.0.2023.12.13.15.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:22 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMSDm6011159;
	Wed, 13 Dec 2023 23:36:19 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne615w6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:19 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDN8eed015721;
	Wed, 13 Dec 2023 23:36:18 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne615vn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:18 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMmrRV004390;
	Wed, 13 Dec 2023 23:36:17 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skm9v2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:17 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaEqH35586432
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:14 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AC49420043;
	Wed, 13 Dec 2023 23:36:14 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 41DEA20040;
	Wed, 13 Dec 2023 23:36:13 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:13 +0000 (GMT)
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
Subject: [PATCH v3 03/34] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Thu, 14 Dec 2023 00:24:23 +0100
Message-ID: <20231213233605.661251-4-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 9rPRRruputKRP1BekQQbFplEPzlvd90M
X-Proofpoint-ORIG-GUID: W8Hp7aCZKiJ8ZMAB_wKYIX6dD5FMb6mj
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 spamscore=0 bulkscore=0
 mlxlogscore=999 lowpriorityscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130166
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="mVY/9tD0";       spf=pass
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

KMSAN relies on memblock returning all available pages to it
(see kmsan_memblock_free_pages()). It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages. This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered
an error. DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as
incompatible with KMSAN.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/Kconfig b/mm/Kconfig
index 57cd378c73d6..712bcf5f1d20 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -985,6 +985,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-4-iii%40linux.ibm.com.
