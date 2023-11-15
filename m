Return-Path: <kasan-dev+bncBCM3H26GVIOBB4WW2SVAMGQENYCQUHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A5767ED233
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:00 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-670991f8b5csf22547096d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080499; cv=pass;
        d=google.com; s=arc-20160816;
        b=nWCqHLA1/r8FWS8iwPRz0V5jGBSyTwkenM5l06Q3YKoTAQA1Xu6bbz2EHsgZgfjEG9
         rVBAxCuKGXqbgmcmN92RMlwVw9iW+W2HUdwFJ6EacENcDmPLoat2OSZWdst1DhGVOzdO
         SFxW6k9gzWHS8TmeFXyOsRH30nI38KGx6nvI4xsM8bLCokJfHxAmmhEVhomh/3CM2cSG
         XuN+hVgAqM/ndolCaQ69DgXk3FMBVFHFzBrlMQNzevk2mVwgXzvTX21ZkS1i+FZE8UXO
         LRPX4un2IZYc2qfjUaOEGvl8+2jZ/xuMcqzizPREW/QmQwbMaVRmBk6ZJO2qnSyz+mDa
         ab5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aJNrZFgxVCoNLO+KmJdu4eN/swx2B1iJIlVnvAD3M94=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=pD/rydJhpo7fGd6ZixKWtPcZqgr2EU0yxSK0q7nBKCf44LjmG30GBQcN7znWndby5j
         yr05mfj5j+R0Bj37q+uKImuEHmDzQcESaH2/t/EoCp3dokDPb93uNwSRs9GZKhuXBi98
         xmcExIpscg1ol6iakY5Q/oLbVpQYOWTJ4bGi9dP3vs/gB7c/+/06mwIVF1xCMDy6mtRs
         SpsVCrbD+FYx9by1qVcYhhpWhUTfNTtZKsirnBUWNs9h3cjAo1ksT+dmHDKojzSvCkHo
         jU2q4wMqFWcoQXu34RRBwO1IIwjFbLamHGaKhuH+A+mHv0fplW1TU0bchs8WgjAFAZhP
         ty5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tM5UQApw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080499; x=1700685299; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aJNrZFgxVCoNLO+KmJdu4eN/swx2B1iJIlVnvAD3M94=;
        b=rmQRpHKg3TQbJuFLEsE1FA3TFjmv5qjj5PxvyJXxm+fMyzkbQ2MkbTsHgm7dBOIMoF
         qFJnBbdPFc8T0R6JmLD5DblBtGZt2AM36bkOrPN2/uHAUFc/vz8UirDKRvMGgzcwhg31
         gUkIx1FVs0qYFb67l722nxUZcFjLglDgBORhRUnD6NHkqqbrajDSHFuvB/qn756wn45u
         n6fJ4VXnNM4RX2YU7cNHgKOqcbP9w+x8w1ZeZU1UHcTMwr2nbEXBikKIXIjlIBO5LiIT
         S7pdfsIElWwPqBBw6VesTFeFtfV2FGG1Sgc4Rci+SF/INY024nYSuc8CkbdNy9SdyXCZ
         uIUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080499; x=1700685299;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aJNrZFgxVCoNLO+KmJdu4eN/swx2B1iJIlVnvAD3M94=;
        b=WIZ4kBc1sI1DiQ8trSIDHsDoQBIj00QQ0jQeSPcjODbiWVoBqq/SCxQWnjA18uL5e4
         u8czqyLxfObZ7oh7AHYxKHlOEoKexYXEtfb5S9qcDoGWFQjqAb5ojsa2EdeOzREo9yPG
         gtvkNGyB5KOAniTL7/4mgO8PFmlCZ3hwTTaFpmct5NO7JfFsRm4lqfGLHaR6UBxFWrjQ
         iEsw6E/VNuvu0WZ8V4Q03TYnvFGG4d82UzrhLi2Z1r4leJFv7V8I5CjqYV9cXQWBCWzS
         O6aHQwDN0TD83oLcfNV9/0XHyg6b3a+vHZi/ml8aVWb/zXTZTisf87Te3rQrkSgqMY9B
         y75A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwQmCA9gqi7W/HIgSEMaTOPcCNBGP9fp9DZ3MM6BOG4aP1w7dn2
	tPc3VauAwKWwgYTEn3m/7L4=
X-Google-Smtp-Source: AGHT+IEPf9iRyCwiIAAxknjcfKiI7hqEph8DJfqqIcvv9BACnz3PxTH9Q+KMC8fu3aVjcEcD5AMFJw==
X-Received: by 2002:a05:6214:129:b0:63d:580:9c68 with SMTP id w9-20020a056214012900b0063d05809c68mr8928349qvs.32.1700080498800;
        Wed, 15 Nov 2023 12:34:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:57ca:b0:668:d9c1:f577 with SMTP id
 lw10-20020a05621457ca00b00668d9c1f577ls423260qvb.0.-pod-prod-00-us; Wed, 15
 Nov 2023 12:34:58 -0800 (PST)
X-Received: by 2002:a67:ead2:0:b0:452:6478:3e24 with SMTP id s18-20020a67ead2000000b0045264783e24mr5196555vso.12.1700080498052;
        Wed, 15 Nov 2023 12:34:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080498; cv=none;
        d=google.com; s=arc-20160816;
        b=quRNe2z2B6vGXxitN7ao32AuIrhUonzhh6X41DE0IPG4ThxbDmKd9TOjumODbEIvwj
         L30ZFyUDtYXAvhePMxPHU9nw6Jr5Ubdn86VU8shMy1ltaTUzMQSUj30xo6FTjG/wiIGd
         iZcuXT9pv/5nLmQGY1Jf3a2KHDonGeQ54WsDYrmGDcfjX3q3S/N+0rJFOdLHO37+xshB
         0d5WeqfvoCH7alAuOLyihR+I2RkGIZHs+yQaUVlIn01NygbpyOQMb2W7kVilOnSkCzam
         QiJgKL0MwP8Ts5DzMP8M2aDStB5ktnDZTPY/rgGo6ETIYcp3HWqEyoXTQzacuKvqlWxE
         cr9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6cPRly3Y0R+ewW/cAplLp4HHPc78tqbgSvA9QXIrbXE=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=NMMPMDyVbXpJsYbhTNARS+vLQyP68+cGCxw//R1cFY2jsHdL/YL9Dd9+nXoyBKCu1z
         mZrsTPUVbi26WCI90p4yFovIKJ98fRFcvE1dYUxlVcajnhkCwSi4JL+HuBRhCDo+oq6c
         jN143uyqq05aM0VkpO9n6SFVSmi37e2eCNQwoQZzVSrECqW69z4MolexwCclFdiz9uPm
         +FelF1XpI8xfqBWa3W/i8EYJYCkAPCqZ7N650Q5o157Q9sJV8KwqFkoYfb5P048AqGj/
         hhvPZIkNUL9VKAY7hqNutJTUaSZBZ1ncIING5yH9Purr/jQYHRgDYwLUnn7Ki1JNTFav
         iysg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=tM5UQApw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y5-20020ab07d05000000b007bfc3296157si1085503uaw.1.2023.11.15.12.34.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:57 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKKJKW020415;
	Wed, 15 Nov 2023 20:34:55 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4xc8cg2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:54 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKOWKf032664;
	Wed, 15 Nov 2023 20:34:54 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4xc8cft-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:54 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ47T014688;
	Wed, 15 Nov 2023 20:34:53 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvwk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:53 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYo1122151934
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:50 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F1E242004B;
	Wed, 15 Nov 2023 20:34:49 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A265920040;
	Wed, 15 Nov 2023 20:34:48 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:48 +0000 (GMT)
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
Subject: [PATCH 24/32] s390/cpacf: Unpoison the results of cpacf_trng()
Date: Wed, 15 Nov 2023 21:30:56 +0100
Message-ID: <20231115203401.2495875-25-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 2hiXuR6P650rcR9fEXOk8WJoi9cn7Ipv
X-Proofpoint-GUID: bdGq9jciuCrxPjpJhy4v0KBztKvLqzo8
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 malwarescore=0 phishscore=0 mlxscore=0 lowpriorityscore=0 adultscore=0
 clxscore=1015 suspectscore=0 mlxlogscore=766 spamscore=0
 priorityscore=1501 bulkscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=tM5UQApw;       spf=pass (google.com:
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

Prevent KMSAN from complaining about buffers filled by cpacf_trng()
being uninitialized.

Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpacf.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/cpacf.h b/arch/s390/include/asm/cpacf.h
index b378e2b57ad8..a72b92770c4b 100644
--- a/arch/s390/include/asm/cpacf.h
+++ b/arch/s390/include/asm/cpacf.h
@@ -473,6 +473,8 @@ static inline void cpacf_trng(u8 *ucbuf, unsigned long ucbuf_len,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-25-iii%40linux.ibm.com.
