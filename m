Return-Path: <kasan-dev+bncBCM3H26GVIOBBT4R2OZQMGQEROGE4CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id F1C69911750
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:56 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6b4ff2b40d9sf17133956d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929615; cv=pass;
        d=google.com; s=arc-20160816;
        b=qbNM1dm++rALb6FkefmNXkY3ScS8kGqQzP1hynqHhdnJu4HwKpTVd6ExXT7X6pQMqT
         TYSn1GY2baPRn1526OtUwMT5agm5z4Y99GbYugMchqHzVb5cS90/3gPmvLdA2a4XEPIP
         /1k7KBpfpZ3eLB57mDXVd4GtY7eABsgjbjhYtGTImlCW9v41g5Fv4t2FGlwBClSbjKmL
         E+Ch1H4TkhEN0mepyaGnnzGj/nmvBQH4NW9VYmNRibWtOpg6+8QBwXqDNTY9Mwt2xDtN
         uuzkLXMhTqNfpj7K/rLKzDH3ZeAg6R9Hom+zZNutRlvagMMyM35CVN/gCR36fvTIzu+t
         0KIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G+0VS90QBREk4PSQy2q36KG9Rh+PYkQjO9VBhlDe5oA=;
        fh=maloa2STXEa/ZfZyuhGAb2HAUE2yJvRtsySpq0xDfLI=;
        b=K180pjqYMw0yX/hMU3nXTpgu+VzkUCBsnhwa9cCEtFUDYphd4TD9x0C58rBCETE+av
         lByuIGPTZ/BGg825F6+s2N13BnhM7x9onIqdVbbCC1qt7mxvdPRjuoSp42GD5+J6dwMR
         uofXjFMe98/WUkAoFWNmZNq/lLPRXc3MYRsWmZ2x+/ualmLgjl+YA0ETTErVLD8O2j68
         p3eHT2xXCgTQGAUNYSKmuKmx5HSBo9iwlSh2Q3pT7n1GM48pjK+1ygzdszWBJJBWLlta
         tj/6XKUi7NBZFhTc+V36igFkZuXA/5DXvgGCyLVZCKQq2DtuZhaGSUFa19++FgZ3cXDe
         oGnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tcPUg5+W;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929615; x=1719534415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G+0VS90QBREk4PSQy2q36KG9Rh+PYkQjO9VBhlDe5oA=;
        b=T7Ar7fvX03xLcKOultavbiRUskCmPeJijXZ0V9BFz+QVmeBXDJhNs3mT0p+B0Xjwmn
         ZN4Jzyd7vNM0NErRF35hF4AlqZumA+8faWzPXI2ViHjZc9JqBzUhvwfiKrQc7qja2NjQ
         Po6SheHvwLf5RSQDcUUaxZykbitMPZuz33pyBvvidUK+Bdij1JDBhKcknZTvV/DZDJbk
         rZVokTDORADqk5pxZXlTELxtVa+2v5oj60qW+AvoqzGDqTRlf2e/sw14KN0L7Pl88Pat
         XJsFVSrQcpdL4BztofNwZlyD4JJDvci9IJ8zQfglvcmfR9jHirmqMUrh2FguVl/sABWG
         R5ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929615; x=1719534415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G+0VS90QBREk4PSQy2q36KG9Rh+PYkQjO9VBhlDe5oA=;
        b=AXn9wul2HGvK+46t6A4WZ8GBndnKecRsoTe7NubxtKXwNNTAREoqEqMUx7daUnyKH8
         07tM029h3FQ4Cu8q7ZL6T9rGs5kT4Tx09SjphdDM1DYFicT0d7MGuUYtosAo7E4ludd7
         i9PF7bTPqRoHiP0vqkqATVMlXf802YWV6jhoWFPcuw98HOSROiP1lalECYk1OpuzU4ZV
         6wdzrDSVqXJHRP/YUMzlH+CNElJOB0UZmh/JkvZJtWvbrejKqBodiXa9d4+998SSNKA/
         BT3Bn9Cp3+7vCnelgi2uXz93q+mlamUYEfdmn97D6Q+eOrIAtwREbfEbf8jJGYi9E43d
         jfxw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqAPjVvxYRG8NmfoIKNjkCikohiB6pnMs6mpfbN0371Sl+F+DnSliHDfSJ4RvDvbtxEnb7JfoG3KR3JzFa9wfVodZP01mS0g==
X-Gm-Message-State: AOJu0Yzlm7ZFYZ0Ex02RX/R8MmzquVnmOkAuUvWo6tm5bYP4ZAmOI6wY
	fnLzp/KMkBYmOaQZBv/A9wmh6pSJcsfRzIc/acn+Yqi/x+qy/aqX
X-Google-Smtp-Source: AGHT+IHtotMKMDQloW7EP4ZWWdyAehqfhLKyCTCWj1Y46fU4AwUFLuwLYAD8ctXPVzdX0v7+KqHf3w==
X-Received: by 2002:ad4:4105:0:b0:6b0:74f5:8b1d with SMTP id 6a1803df08f44-6b501e37bc5mr73079956d6.25.1718929615554;
        Thu, 20 Jun 2024 17:26:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5508:b0:6b5:577:fbee with SMTP id
 6a1803df08f44-6b5102e41bdls20229766d6.1.-pod-prod-06-us; Thu, 20 Jun 2024
 17:26:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcCGPPvK1eiWlksllXTfpPMfDuWNNRbNpsCw++S3e+fk4p+zk1Ep/um9b+qBy710g2dZsQjN4Ld6oxi/MYUCE1jvKgx8Y1YeEE4A==
X-Received: by 2002:a05:6102:374f:b0:48f:2c59:760 with SMTP id ada2fe7eead31-48f2c5908a6mr3144084137.8.1718929614480;
        Thu, 20 Jun 2024 17:26:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929614; cv=none;
        d=google.com; s=arc-20160816;
        b=gMyIt7LPFFmz36e2TEMtv0AyGJhf470LyV0QQ6+ZAo7adJNqDo5VQX3eL/0GkFQWF7
         DXE01lfyzeeO129DzpRK1H5QQNvBE3PR0pCZQT4IbXTJFtLm9gItn03jkMGyn69Dv+I5
         AugTjLuKv95MJ7G+FqVBR1ycnxXkpfYv8AObdTqUDBm0VMCqGSkrbD6T7To79RcWw+dJ
         bv3Ey16TddylaStX86EkdYOmh1NNa8xtAAQia/U1tGMOJLyUg02yJnA11Q4YlhPhyALA
         UIDZfRdlfn+tpx/Qg/TAG3GPEWXlGsr2TYO25+jk+eyxzfpq1lgMnTEBlylBCUlP4vmV
         5STA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DjuPcXR1BibZz5Ch991GiPtCxAY119xb/qfTqg6kigE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=F3kV/wdaBADyua+gDn1nPnpH2nVJG6/dwzoi4zRJDiMe0E2yBb6Xj7ayAPS3jPhrbW
         7WR6orOwu+sbAQ+tMnHI8k9GYcalZ4RWeK/8cQrO9e1P/PgzAvNES1KFUwl4C2FdUfQs
         pHDWU0fbZ2stTBnJEq209v72jIJ9x8mq1nZvwyUsvIRKDp8tx9j9t70ZiFU+GXeCB6/d
         bhPLyr9dol1TLONnCJ/746uW4mY3gvIaQXy5JCIOVIfCZrteUBJdxlYoTeAi/tElJgR+
         GI7KYAUvMXpfVKZmRdnCnjQ66Z8+9W7nVvm3B8y2eQT+Sg2SlVwl3oR1oCOQ8tTEInuc
         lylQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tcPUg5+W;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48f331e1743si16394137.2.2024.06.20.17.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QnuZ007904;
	Fri, 21 Jun 2024 00:26:49 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c875u-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:49 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QmWJ007892;
	Fri, 21 Jun 2024 00:26:48 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c875q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:48 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0PD2h031890;
	Fri, 21 Jun 2024 00:26:47 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspjmyn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:47 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QgCm18481484
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:44 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 052CB20040;
	Fri, 21 Jun 2024 00:26:42 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D5F6420043;
	Fri, 21 Jun 2024 00:26:40 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:40 +0000 (GMT)
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
Subject: [PATCH v6 18/39] mm: slub: Disable KMSAN when checking the padding bytes
Date: Fri, 21 Jun 2024 02:24:52 +0200
Message-ID: <20240621002616.40684-19-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: s7hafDy5aFTcRtvqVQpLOtSJKs9sYlpb
X-Proofpoint-ORIG-GUID: 2sowwXNvMO2B8DX6tP-_7374bKZOifoo
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 bulkscore=0 suspectscore=0 mlxlogscore=999 malwarescore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=tcPUg5+W;       spf=pass (google.com:
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

Even though the KMSAN warnings generated by memchr_inv() are suppressed
by metadata_access_enable(), its return value may still be poisoned.

The reason is that the last iteration of memchr_inv() returns
`*start != value ? start : NULL`, where *start is poisoned. Because of
this, somewhat counterintuitively, the shadow value computed by
visitSelectInst() is equal to `(uintptr_t)start`.

One possibility to fix this, since the intention behind guarding
memchr_inv() behind metadata_access_enable() is to touch poisoned
metadata without triggering KMSAN, is to unpoison its return value.
However, this approach is too fragile. So simply disable the KMSAN
checks in the respective functions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 16 ++++++++++++----
 1 file changed, 12 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index b050e528112c..fcd68fcea4ab 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1176,9 +1176,16 @@ static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
 	memset(from, data, to - from);
 }
 
-static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
-			u8 *object, char *what,
-			u8 *start, unsigned int value, unsigned int bytes)
+#ifdef CONFIG_KMSAN
+#define pad_check_attributes noinline __no_kmsan_checks
+#else
+#define pad_check_attributes
+#endif
+
+static pad_check_attributes int
+check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
+		       u8 *object, char *what,
+		       u8 *start, unsigned int value, unsigned int bytes)
 {
 	u8 *fault;
 	u8 *end;
@@ -1270,7 +1277,8 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 }
 
 /* Check the pad bytes at the end of a slab page */
-static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
+static pad_check_attributes void
+slab_pad_check(struct kmem_cache *s, struct slab *slab)
 {
 	u8 *start;
 	u8 *fault;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-19-iii%40linux.ibm.com.
