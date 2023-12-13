Return-Path: <kasan-dev+bncBCM3H26GVIOBBNUB5GVQMGQE6FLT2YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 261F5812348
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:39:36 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-6d7e2edfc83sf11317785a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:39:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510775; cv=pass;
        d=google.com; s=arc-20160816;
        b=J74yXUX5FXY+JWVLN21wBcL8wx8VbUiqZ7xp4DtVY+/6FChahz0veAFr4QiJbrJic5
         +paAaksHgzKFgM8vTOuzp+w9rOyvwq/k7sybUZARtksOgF7B7jpnU/Ks8b0chs27V96x
         N3FJIwPz2lhwTc03nOHWrPqUOFPKeLSwKtGkobM8xnHASw+01E/I7+aFlXVj4th0nYD2
         QnvSRexp6cdpQJlGH4UZjT8hatkGbE6sW5mWRKeDyZbKCeNU7ZZAhiEC9AOJfRvFkoJF
         XZGMq7I+p8DK6n+ddiJ/vddfWc57ZjvqghV4Eb9iaqNNgdkKrpTSM/RIw8KF8LD2eBwh
         e0lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WapZoZjcSHZZcTQzL2U1d46TjDYljA/O3Ypf4GHb2ho=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=X9KNk/mazWDQLzh5ZReeawxvfvJkVfD7+PE0GpBqJg7xmS7At6K40KNsFLyT7ixftw
         uNLfT1oFTQap/ov8d2MhhvkSSAJrVBHQQhbJkfE226/YBM3KXU7heBKz5W4bJI8hj+BB
         RHNSjN8XBQ4obgmXXPYJYesQxt9Xbike4mPDRDd01tHesmWTkTpKfDTYnSzvNzfyECqQ
         pZcpai1G4RYGYpZRs/HVViuwCJfeJFhgtjdWRyoFn4U8Qr3oifASK1UdSaopkFTSn3hq
         DH5eDMl/N201sC3RTaLu8woAecB8LoVVnp5BHeIi+IyJxDLR076unvWHviintpYYrtYM
         l7jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Y2y+vBrI;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510775; x=1703115575; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WapZoZjcSHZZcTQzL2U1d46TjDYljA/O3Ypf4GHb2ho=;
        b=GuVoR7XhlqaJCbNKgxZewGwmrJjenwOtl7iw/ZuJhukyWYrYuJQBQwpK/f3gvgZ9p9
         Z/1xJye1oAu/C/8JqE07CtO1L2/SMjhp6nvPAwAlCgJZpOarAHJKKwVjh+/C2mtIdUTy
         dTpLI/X/JEHbyUx5R3U/h/AuGq8fnTnWOIAZBiK5XpbFBRwwvOrw8e2VyzwqSoSws2ht
         1BVCtju795RJqoDq35mVTRlwCMH6YpsYx+39qsO8AyWsmvdA73qLpa3pn48yvr2ekx//
         Wi4m7R8iHZBplaesQyfvf/qQWjRu/bETmP62JXnYhRlZn2hsvSYAm9Ph/Isf8Hr//PPZ
         h4Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510775; x=1703115575;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WapZoZjcSHZZcTQzL2U1d46TjDYljA/O3Ypf4GHb2ho=;
        b=PLOGy8b1ivz3qqWhQYceDgVQeWd89Zfm3bJ4kvHD7KmRo83fOPUjWHTmVJlnnWMkT+
         Mn78oJnwJWRL0hFvePSog5wog165Z13elJVlU0GxtZDp6mwOI0lCBdVu/wakqUyiAxB+
         hIbrCzPwENtY+BUCEQ4ymRFrqGk8HGsGUHCIiPk7cH2ayHnh164gm8Yq8YqWFG6WVfJS
         hk1079aOiuGcr49N/TJnwfIvyMLGiVAAOTb11hO0Ell7PDkvipTqHtDRo4v3paqA/x6L
         wgbagp+OS3to8nRuYps51U0isqEWrNFWs5BvY4+anxP/yhGj8Nxl+55LO9VKRT/wD4ox
         1hpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwdWV5kag6hswzjMkNuEYR6hu10fJxtJ5HROlSu/fwZW/xvmXWl
	hh4JpsuD1Kh41E40tvErIK8=
X-Google-Smtp-Source: AGHT+IFnuLNXB94GeZkPh6R0chxR2z4EIQl4dMHEJiUOVD2Is8WKFmGQGg/A72R002gO/bRjT94YzA==
X-Received: by 2002:a9d:6185:0:b0:6d9:e28c:28ef with SMTP id g5-20020a9d6185000000b006d9e28c28efmr8024755otk.55.1702510774944;
        Wed, 13 Dec 2023 15:39:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2311:b0:6ce:f522:ec5b with SMTP id
 h17-20020a056a00231100b006cef522ec5bls2299952pfh.0.-pod-prod-05-us; Wed, 13
 Dec 2023 15:39:34 -0800 (PST)
X-Received: by 2002:a05:6a00:890e:b0:6ce:2731:d5d4 with SMTP id hw14-20020a056a00890e00b006ce2731d5d4mr3572716pfb.69.1702510773832;
        Wed, 13 Dec 2023 15:39:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510773; cv=none;
        d=google.com; s=arc-20160816;
        b=V6iUpsI5D0cmE2/9iwhYEMPvWUeObmweFoaHaiEhkDnP9rQxcXdw9RkL6ThPb/2r6d
         +CYINs0zN7/4sUjJpjYZzOvWZi3oDcSfCJXzyiDozlrAofqxVU4sRMdKufvs2F5xY3S+
         j5P8JS44321HLjvP9z04wAzbgeoqvt5y8EErXKItVPwpjM97/hzKNjgtTEeOMrHVcNxO
         qDNK/nQvtWgWTynSRqjqiYKFLFggzE9wo1Gtv4KZm1g+u+f/E/mFwR0l8yQbosgerfCU
         b2x7s/v9R+6GYTSa/Q2RWBoYdccVc2MOidME/HOukgV6RZXn4NN6LJicHwNKBKVoz/mq
         N+0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gYyFgOCVso5JtRE0tmyb4wuw79KiFxJvcJzKqQ9U3hM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=hZ1m35i8+UucmpLqR0+P2pfH21EIsPa5BpR4mLbXL3UP1z2bKPqDNZ27u9aFwv66Co
         SA50fMKeLfY6x7BbPprbrR6ml18KnSpBtN1UWzcrNwom62JqdvIbQyBmS2Ic15Hnjl3J
         Kjfi1g105iyCPYUu9FCF7n7s4ozSNPMBtA0IqKaOhh5xdBFL3y7A5v3lv/WP7WEOdYFx
         djpiH4jopZ1BMb5fXTPD9vEOB53ZGgLK4snVqUmCYyHgfxndc5mXksfnwE7Nr+AKgr3l
         LuGWs+MyVIFVU8BeZU9bZQ+jABmq8XUCHvaii6ZVD8Rg0V+P73Tcc9JxKzt2MlFkd5bn
         ZYNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Y2y+vBrI;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ic4-20020a056a008a0400b006ce3d293cd2si1006366pfb.2.2023.12.13.15.39.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:39:33 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMdHfe017114;
	Wed, 13 Dec 2023 23:39:30 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykvmuvsd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:39:29 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNdSJk015295;
	Wed, 13 Dec 2023 23:39:29 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykvmuvp5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:39:28 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDLX5Hc012593;
	Wed, 13 Dec 2023 23:37:05 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp4ndc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:05 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNb2jL7471776
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:37:02 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7A00620043;
	Wed, 13 Dec 2023 23:37:02 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 153A920040;
	Wed, 13 Dec 2023 23:37:01 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:37:00 +0000 (GMT)
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
Subject: [PATCH v3 34/34] kmsan: Enable on s390
Date: Thu, 14 Dec 2023 00:24:54 +0100
Message-ID: <20231213233605.661251-35-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: CTCQr_1RVlp-5vBpdhAQv5G_JXLdChBk
X-Proofpoint-ORIG-GUID: FOlLAufKv9YIP5YH16oRSkto3lOlE6sn
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 adultscore=0 spamscore=0 mlxlogscore=755
 clxscore=1015 priorityscore=1501 suspectscore=0 impostorscore=0
 malwarescore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Y2y+vBrI;       spf=pass (google.com:
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

Now that everything else is in place, enable KMSAN in Kconfig.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 3bec98d20283..160ad2220c53 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -153,6 +153,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-35-iii%40linux.ibm.com.
