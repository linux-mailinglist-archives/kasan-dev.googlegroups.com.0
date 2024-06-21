Return-Path: <kasan-dev+bncBCM3H26GVIOBBCGM2WZQMGQEJJRSKII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D14A9123EA
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:46 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2c7d46d273csf1658803a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969865; cv=pass;
        d=google.com; s=arc-20160816;
        b=kc6QIv5v5b+HcanIO11gxjE9gL1OP8zoQXhQIHdYkaMlICIkCZBJV12FtREg0guOVU
         L2qNw/o8vDXWD3rwGQ3KXt9pcbdhDd1+++0RrQpCERMkfnQUG+Rk3JlpiwI0xIg0g9RP
         rSOsya3WyVv2eU0MI0TgsiW/xG7T3sw52HL4J3N5tIuEmsoEnqeFWlDS//kFB203b3NB
         Gf15f0yggJtc8Rkmazq/4gokfTiSS4jw8nKCYW3uIhF2GAyq7iyckjqtRt6XoQ/nlS1L
         fYMFEjpaSo3nxC+y2aCnUUZf/f8NAnbipxMuVqgCVPJPvaRVJ45Z9COr5DKWry+NrEsI
         nY/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b2Un11SsyyhdUEdB/iOyg+9NQesTPEnjAqXbE7BgCLU=;
        fh=0MLF0ZyXOGWFL2mcArfP6eWlFoQUjwD7Vhy3pYBm/QI=;
        b=INJpr97NirNwiLsEIBITXnR8eBKwfIE2NFv3Lxdxj+8ZxrfN9M10w5M7gBpvWXGbdT
         zyrQPGG8NZZqXgfERax4r76yxLKOj7x+YHOQsC9hppV9RhIIew74ycQjQmMJdPkWw809
         GhAzJREfni8Il6TCL0/z9Q1Ebyg+Ka0YSpfO+AF4rLpaNiv7k6Xnj8KVEpygYpfA5+hB
         nw/OjM5+EZ4jrANkjdHcDGj/Me0MmNW+en/WR67gC93yXQOaa3Tf+lDklgFVU5PZrKt2
         DbDX0SZdk1KdKIynniRzhJpOSKUvwUmCF+xMPqwtMHyvakZdSCHSgdSr+t3oHJ3262ZW
         0whQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=o+J+ZXvA;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969865; x=1719574665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b2Un11SsyyhdUEdB/iOyg+9NQesTPEnjAqXbE7BgCLU=;
        b=mYBAntuIu2kzx771IMAGpgbkcOLV55Xx066pREdDfTCeY8Nwf1sJM89lmEZORPoIap
         VruyjKx9quANLOGWoq/foFUyrrY472hekLkVxnMxVVtz1AxnS4j9jPd6eoXo87yx5TbQ
         RRfbjW5wUdhvSTjkpLjKXHsC3uhhBFeDdwUsfy9BOxxw/NPtAl0iIhBrx+rPO2vVgyzJ
         tz64mqI3Ll19yTf9EsgVK52pVZgj2j8UWpuhBzM6R+JIaEcIfV0ezO2fYQtdX5+ZNVgG
         KjBX293fi8f6GwZkPOyOXNGwlZ+P/LCqBwcJuHUkFlUNaRwAEC9S8THH8krps53s7yeV
         8R7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969865; x=1719574665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b2Un11SsyyhdUEdB/iOyg+9NQesTPEnjAqXbE7BgCLU=;
        b=S6fpQ7MZcXBxErW5cIjzevECzD6VRaZhFkAmQNEQk7hzvHtZz3EU9o5m3efWJkFpo2
         kQV7gzozr09bZksv3PyRDOEfdCmlvkL1RGXJ+8TmfpkWtiUj78Q37wRI/uucnw9szX8B
         /x6zvn19lvU44iKidRb6QyfhNcYMHQoHZ3+8Wx/6y41W2jj2ngZDu3bDmQsFhg5KwNRS
         Pzy0Sl+O9TzKbWSZOqV/huYa8UtjLfq+JXcrSGvOA4G4Rbcni6T+nXfffab6SbZC7S96
         a6q8FMrPfNv+waUn6LRwPOaDl2U1gcOzy8zha/AboTrGU2EaqmVVhnJqaQsQs2rSptXu
         ZXjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjcwP+y2R1olivOCbLrjzx7GoJvvzru8W6AofdfFF1LbohrO8gVdlONfzNHf8SAo0T0fux7SQ9L9irCcEAgYC4zt4q+WrCCw==
X-Gm-Message-State: AOJu0YysFa94Ja5309hzfLC2+e8ZK+YxB9ycZbhQ3Ph41UyfA5j/QLSn
	1lfY9JP6CVLGkvvcHZITYwiv66dHTb2AtJUcIqF2V2zBfxym05Zt
X-Google-Smtp-Source: AGHT+IF0pmxvdy0AcTzHcP+to5fW6bKcBW3Nig5+iEExzh4mKSXn0gfljvWIVlh8l1+mxOjOtZiu2g==
X-Received: by 2002:a17:90a:d911:b0:2c3:2f5a:17d4 with SMTP id 98e67ed59e1d1-2c7b3aa6398mr11597741a91.4.1718969864767;
        Fri, 21 Jun 2024 04:37:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8d08:b0:2c7:a92d:e66a with SMTP id
 98e67ed59e1d1-2c7e14175fels1037247a91.1.-pod-prod-00-us; Fri, 21 Jun 2024
 04:37:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjgCKCm9ndbl+1zIWmBNgDCWUpD1pEb76o0V9sCjKaRShj7vYR6Bys/e/2gxN7fN02c1D4mFh62yTlilXf+4394/XMTF4mA7+UpQ==
X-Received: by 2002:a17:90a:c10:b0:2c2:ee2e:f101 with SMTP id 98e67ed59e1d1-2c6caadcb14mr15707358a91.16.1718969863507;
        Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969863; cv=none;
        d=google.com; s=arc-20160816;
        b=yVytNIO5a8QIA96irjyw/T7EvdG4VpqhyCIP6Kc3HCvQFSVc+hTYOuo8B+72xLlfG4
         J8Umh2FMPbB0x2a9SDYLxy20mZQNp3rZ2cCydfxisks0ZghKfWyYOci8uJmdmNjVazAa
         JpBS0IgeSQQPoN51IbCJEuOneKSTmEfDta9vHguPv18Htnc1in7vt+NTloM/GxXVBj1I
         hUFt1899MbzCp/nugcvkVrrpFukiWQ39MRuBB1+44jOfMzXEq+bWFhR/JZumlbDV6VLw
         eoNMK04kzyM8hYofZ+CG0fzdbi0IaE5D0UrPnMfEsj8SNbGovLAOZfRm9XTYx83sEswu
         haUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IRZnfl5kegw9DdaMeWWbTwWzCErv31wkZ0fJjvxbgdM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oXuSSGCOijiyi3rz+EXa1XVbUZZZuPbuDd02Xwdd6UhYIyY4tig9ikLp7SZCLfqoDp
         Q/OnegA+wx0D+MScCTSI9cEpeksW/toXmxEWBNWeHEZucVAFo6xysOA+0K9KQK/9NK8O
         kQG8lqo7J/tw6gJP8y5EXIw6zsG1PP291HjA9zklnjS2cwwaeMy/1okISXEIFXjR7LaD
         xGI4yT9Z7qWFXsqR3whooNTF8yuBV8a+aAi+OZgZMOWpVZ5MxCoTwx3SthQid60lHkL0
         V9mPSvkLjx6cJAdO6Mr8fGoM/YG3n+ERbB/Cv42dUACN7N8csar7xMPBkUauj6CuidjS
         sAIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=o+J+ZXvA;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c7e945195fsi180538a91.2.2024.06.21.04.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBU15B002875;
	Fri, 21 Jun 2024 11:37:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0m2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:39 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbdav014439;
	Fri, 21 Jun 2024 11:37:39 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0kw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:38 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9Lx4I030885;
	Fri, 21 Jun 2024 11:37:38 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrssxvc8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:38 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbWGZ16908730
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:34 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 61F722004E;
	Fri, 21 Jun 2024 11:37:32 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CBC0E2004F;
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
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
Subject: [PATCH v7 38/38] kmsan: Enable on s390
Date: Fri, 21 Jun 2024 13:35:22 +0200
Message-ID: <20240621113706.315500-39-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: kJ0C__Db83mnTpY44STC6l__kqD4tnRR
X-Proofpoint-ORIG-GUID: 8S2Itk7NRu5jxLYW6HoV5XhtvFWYkSW_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=764 spamscore=0
 clxscore=1015 bulkscore=0 impostorscore=0 phishscore=0 priorityscore=1501
 mlxscore=0 lowpriorityscore=0 adultscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=o+J+ZXvA;       spf=pass (google.com:
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
Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-39-iii%40linux.ibm.com.
