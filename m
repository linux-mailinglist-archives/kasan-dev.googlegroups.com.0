Return-Path: <kasan-dev+bncBCM3H26GVIOBBQ4R2OZQMGQEPJPUSII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 91FD4911745
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:44 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-375e4d55457sf15038405ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929603; cv=pass;
        d=google.com; s=arc-20160816;
        b=HmQ+/aFfRZbJDa+yWNPFGJy+FWNjVFnQEk7IHej1ramHr1n0PmJZyBmc3U8Wn/t92a
         bcPDR9oLwVYrqxRidwGY96O+j5H5WZpJmUbYdkA9pdm1uUuXvCDUMO4tSGIjwNvaVE2q
         6GgVsY2aZ0tfwQ6pMKrrBpZr0YZYufLohuRIHFWOHMhi5DSGIWMuo/oNWXvUM458hflk
         18yoEHymUSVdnXUnjEpEuaqCjgkTI9i8ElHuW44qMWxZrHZimfmrWNs0+dJhf8krSY2h
         mCHwnKPOBN8ZBoCmLmwU1pFH5w80I/4kcgdo09Hmy+k1xHdojttdcyYfuB0r8mY88vM8
         te1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DXSSeHr+GDzn/S91BpaX5wny0icagGVZB7nHqoB4Y9g=;
        fh=MPcxOzgUSZH9h4xZt2JrsT3nY/NGcryXHQTlQu1Qlhc=;
        b=yTEuWczkp9SHp6PpqmLQ7dtSfsMjNUZBNGy0kzyqh3GUVYcOT3uKu09zDijpmW57i3
         NGekNLPMGY8rJqT2RF0ys9tzkVGPKM6VVfJ/WkffcA/Qdp+Jhb57KHbkjqFZtF2FpOh3
         oyug9DeP7DLq5KwxdFBU6OrDW/jXGa0woG7450o9+9ZZp15iR9bAv29uGa09QpgWABEw
         bdaKceZ9KojqX0lq7EFnNHHche/GDHJY881guI+DWCgX0QnIXt5YpqC9XmyYW9atyP+N
         /Cg1+qcwseScb/0srPNSG+Fcc/Tr17m6QDKwJqatBu27bH3ClShMz8SnOuKqk95b701s
         buAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ggoX2Pks;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929603; x=1719534403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DXSSeHr+GDzn/S91BpaX5wny0icagGVZB7nHqoB4Y9g=;
        b=H5QzxPPVYZHkhjDdFcaom4R6FEs1Vvu1XZxBlzO0Tw2Ui2mLIYxSIDPIJSkM04qny9
         X4cwiLiL5VkdtKC2iPUrAQ64WWS1D/59C/2U0riFckQD9bHn8oANGkonUUIrublrW7sx
         H2c0BtxTXRXXLbYI/phrWFq8ScrBnOKKjH+Spsx0nOf4kcGwYFF63tMowopd1b28Lq4p
         ElCzRiBy7dkmxOzR3aCpWSu8RnLVEET7gf8KvnJE7nF9Eq7T7bBkw63znDHZBCliIyTJ
         5fXgdsQ1waP7oyw7KaKXYxdvadb2TTHp3fp0qdl54h1xMbh1CJ4zZbpu2/+9VEf2pU9e
         N6iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929603; x=1719534403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DXSSeHr+GDzn/S91BpaX5wny0icagGVZB7nHqoB4Y9g=;
        b=H6lRVrTU1aRMTxAj/YyH5RsqWjDNXih1QyEnx9DIuuGMxbGUjkMfm0azAK33qi9gH+
         BgtEbpfTKQsfVLwgIA1OU3kgWYJVQA9T/j6MK/KdG0m+tuIqoZA5uycEVTgwEzv+y83p
         +PeAQZzVZyZnstGv0VqiIC2yYo+Uqqk24CmuRQ4CqewBMPaD8pSMBNI3Om5G0GeLjKhh
         7ToQfzTWM6OxfEP/jPWvN+o+UmJU65rAwZIJXk+IEkszMLE1dsuk0MJUVzWOXoLF8Dwg
         WFqGdnL9Krdc+s79YLsPSeQ7cYcgZTRdmnyEp4RTW403dO5iWaNVT4y1A/sTL7y+eePH
         6ISQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrbblXPQFSjcpKuIYeR4BMpGUBU5ROPtVHbJyEODaniwlNvg86yjpX97z42Tkvytx8yqHv7USqWTJ5S3arlbz95KUFWzJuGg==
X-Gm-Message-State: AOJu0YxfnkLEFTXbGBZF0XoX27VLLR9qJINuUDS4DG/Sz+vIBrukvj/T
	NEXJEV+MJNtAiP8DIvxXx9qoH4fmBuey+gJQ7dCDzP2QhRnRkYVN
X-Google-Smtp-Source: AGHT+IFCrA8fBmoOWW2GZTu3B8KsMyVgwVLP1mF1zAZv+uas3UxUmJZdfm4u2P0YKGzOtlRTdjzlvg==
X-Received: by 2002:a05:6e02:b4e:b0:374:9427:6dd3 with SMTP id e9e14a558f8ab-3761d7221aemr70629275ab.27.1718929603404;
        Thu, 20 Jun 2024 17:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12ef:b0:375:dc18:bb99 with SMTP id
 e9e14a558f8ab-37626ae1941ls12041305ab.2.-pod-prod-04-us; Thu, 20 Jun 2024
 17:26:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeztk2wn0rW+WpKS6EJi+ztEc7LH8q5iDuhcNJWGRAvJu0rk2RQWAy3HSEK1kSoxvvi4kk+NUGn/eK7s1SkSECT7uXxIC6xHDj8w==
X-Received: by 2002:a05:6602:1493:b0:7eb:6d0a:613a with SMTP id ca18e2360f4ac-7f13edafa38mr817474839f.2.1718929602711;
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929602; cv=none;
        d=google.com; s=arc-20160816;
        b=qnQN6idhhe2HKta7n0gpXFibuEcaO7ZhVtvs2Z5kAGVEt6ON83hEGV/7zzSLSLUvOJ
         AVrhYTxyclwBB4Zay1VJspsL3yz81kI/LBO+keh1j++aKrK/WfineK5KXS+wuobvE+DF
         TqgxbkwCTKkluGodEgDgFUHjZXNMKVCEObDnqkQVES0yRfwrVdRkIXs6U1Je9Elqz7UH
         m32fYeTcQNA9sa9CQtChHDFrMP58TIDP1l3P51WAfHr5TQpKuZv3fiAmpJwv/A39jp3M
         JlKmbXs1yDLB4kKLMZNeL0EckpmvXrolEnq07P99/31YtMVNbUKqF2ba6yh6vBT2RQuw
         br5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ah4xfVCHNViASZu9OS8C5bCxAH6NMTO/t1qMSUm0DA8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=lBdzp8szYelBh4aKANd5pkqQ/BcE/0v8V3fy1BC3kGpfe1DJOwJ96r/fOJs6mrHbWp
         5CcLz2GThkMTWDGYW89SjbSTFCpMblIh28NlN9FBlE4NUJ1UxJOG3tSzz4GHSQSKj4mG
         z+urtMEr+bpAQqyVFq1BxgO5o4Rp4+TjgKJtz/IQlnwcPOhal1V12vHyXhppftSYiwQi
         HLN9Md/nbYOprvyZUfEeHLV+M40yAJi7d07PKYfUL8kwj0HR9lN0T8Q+B4s3gPZmwxPO
         tp840f0jCN6hi+7O/koM5O7OEfE2uBLikNIIBnxA5lBZSO2AVRzofTrZHzMtrC5b93+U
         MXTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ggoX2Pks;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7f391d4edfdsi1309639f.0.2024.06.20.17.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNufV2003803;
	Fri, 21 Jun 2024 00:26:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07sx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:39 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0Qc7G016947;
	Fri, 21 Jun 2024 00:26:38 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrr07st-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:38 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0FLa7019941;
	Fri, 21 Jun 2024 00:26:38 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqujnwn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:37 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QWMu51053006
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:34 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 32A8A2004B;
	Fri, 21 Jun 2024 00:26:32 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 144C620040;
	Fri, 21 Jun 2024 00:26:31 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:30 +0000 (GMT)
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
Subject: [PATCH v6 10/39] kmsan: Export panic_on_kmsan
Date: Fri, 21 Jun 2024 02:24:44 +0200
Message-ID: <20240621002616.40684-11-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: -Q14BQ2YT5_Te4RHh-dfpK1esFV--JR1
X-Proofpoint-ORIG-GUID: WQTMj1N_z0nQDf3HOEeVuLpEFkVxIMQc
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015
 priorityscore=1501 impostorscore=0 adultscore=0 malwarescore=0 spamscore=0
 mlxscore=0 suspectscore=0 bulkscore=0 lowpriorityscore=0 phishscore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ggoX2Pks;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-11-iii%40linux.ibm.com.
