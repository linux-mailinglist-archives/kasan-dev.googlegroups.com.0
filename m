Return-Path: <kasan-dev+bncBCM3H26GVIOBBQ4R2OZQMGQEPJPUSII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E8EB9911747
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:44 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1f733390185sf12661735ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929603; cv=pass;
        d=google.com; s=arc-20160816;
        b=k+wsZYmoua9wy0M72zILKO3sWxRUtUgnrXFfXpu/325TKWizcZnTj3LNsscKBk2i73
         G7IKQwWK2zEVF/GVyM65KO45Ifs77Dfw3m5R8DH41v2j42LO6BwoAcoCUP78VxCuJini
         ILv1yX+4HcJVzLEOzqx3Clz4bW/eRwaCs1c7O7B1nOyz+XE0LO6tl68SW/pFIX/y9Hs6
         e39vH2vElKAYpuySAjZkEZPEsYMTwLPJhChg6+poT7qp3Lpa7Oo1csIXoN5/KJDgUkOt
         +Ddq3siiyPshpPB1mk6TvbSsYAdUbc0K8amjRpnC/o5qbn9J7/IMiLn5Uq7+/eENDRHO
         zQ+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DkLrr73FxbbcjT2oNPKw1sRvWD3jy6uZtSJMjIOzOOE=;
        fh=wvw665m8p586Pp/jqRk6HaV/uCYnKyCXuqRr/7dCgUY=;
        b=i4E6BM2jIyVgr6Y5Cjv+Rb4C0zoKgh6YmNMyc0uDeu3U2xEjIEfEJ/Na+jSieHGDfP
         6i54IR43JyxnGNClWkwBzV7FdZg6vHOVepELhvBFaFOAdnmkIiP9PcknedSPah7Tnvad
         Sw2DkuQr6zd/ctVO1I3McjAsx1DhFww8BnDZrRS8pD+SAkpFwq7wY/pg7YM7daTfyFNf
         5BZ/ahysXDrZ4MbgvACcpFR516JjY5hE5+vhjMnb7gapkefvu1G7M3CuAqbvR7094a0R
         gGGVlGEWpmPSZ+2Nl4qR6FoWSry+/9bTZ8OvBw5heZeUvdnZ0hFYE9nT2ogUK1nL4TYJ
         S/Qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cp3Nojk1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929603; x=1719534403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DkLrr73FxbbcjT2oNPKw1sRvWD3jy6uZtSJMjIOzOOE=;
        b=r7P7jtHjzA0YcVVbkybbMnfjGL97iBjABMx35ISlaCAowuAFsoIUYPX9/C+JwzXPHF
         LZDQyjGHtfnHcYR5++iEgLFD++bkzFdOPH4n/8IIgJ5tWaHN35FlFxfShgtHQRcG9F+y
         eDzxwr9wUp7ID2IjX1jIUNEgULPml7FsLa5+25lgBtKyL18p9fJ0fw7aGZmfByZdoJYZ
         9uQugkkGc3C6nsF11YaF31yctij64jTU83YfjSxB+Na61jRtStJj1H2ON2kq0zhAPcm1
         2azrH4h9hy0qLGBBW7CdttAAV6B+e0U5MhGFTnUo6pzJb0VwHG/uGQ4d1PPPEkKl2PM+
         VLOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929603; x=1719534403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DkLrr73FxbbcjT2oNPKw1sRvWD3jy6uZtSJMjIOzOOE=;
        b=R3mRwLAmPhUaOM7UMGFD60ZEhqAxHGFWGE8RkJJPSradn8fXZk0HbgrYkxL2DCGpOp
         GsGUfH/3YORvrU+nJUVRN+iFolesBqBu9XDAZTbTXQ4h44ta5Y425uRd0HpdyhLS5dRw
         BrnXO+uG4nB8/3v4fn2LNNy9n2BqgVxSrzTtFjxjmIHoZ7On4fDQQaCaFtqMwXkWqSqu
         T0wcoKRf8qw4wCmBfgybIZYI/+en4blkeax65zouxS3sIGv02ayoRm0hZcPuS6yOgGbm
         TDZpkbGtEtJJmhstrb5XBjOQ9U39QwizmwvAUsHSI+ekqdaMZacjhTj9SkFptvGUqAn0
         4aFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVQ60IEMFrUS+E71AgaC3X0xfx8p8Ua6XwMD6py4RiFuvbVRMNY6ni8aFpG6R83txzGPdHx8TJ84S1+2qSpdXK7QFLV2CWOQ==
X-Gm-Message-State: AOJu0YxB2cSb97D2aXWGIybsYEWfO9ujL5QXI3DL2ArEbhmbrqvjMPPN
	2OJnnKilpLrjWiP8oZ/HAjzUSKVao2fV+wyaL3pi/ASEYvtrdrAy
X-Google-Smtp-Source: AGHT+IH7w7dsIvIZbcLHW6joTWFcG2UNtwe23d5kd1KmxtRN7nScIQyFT5MisJjwwE+xh1rNP+WJOg==
X-Received: by 2002:a17:903:283:b0:1f9:e7b4:5e02 with SMTP id d9443c01a7336-1f9e7b46293mr10037055ad.52.1718929603284;
        Thu, 20 Jun 2024 17:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f7:2780:7276 with SMTP id
 d9443c01a7336-1f9c50e6721ls9906635ad.1.-pod-prod-02-us; Thu, 20 Jun 2024
 17:26:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW52abDUkwG1o7cimnKKcLhlNM1hg4yEG1yHogUQhvDBFKcBYyI0ofqQmjq0ThOus0qQZWXRnC7H3E1Hb/ujKpIiAl0gTtPxeIrQQ==
X-Received: by 2002:a17:902:ce88:b0:1f9:b16d:f97c with SMTP id d9443c01a7336-1f9b16dfcdemr65903415ad.66.1718929602207;
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929602; cv=none;
        d=google.com; s=arc-20160816;
        b=e+Z9VKUvLzLbeBp6b+8L0YIAh/dYdt9ONDURvDrUhCmW77dr9LsOzOCXSiyWlMPWh4
         j/kSsqHSK09WMMG29svfvCHjv3w0oq6fTZHgJQBAsXCrvNIhkFZvNRatNpEJZZPNx9zh
         HSTWVcHmy9V3Z9+9f8OR0KgxOumDNv272aU8eiHiJI0G5kLNriMHtAcSgn3cG2NH8LAX
         AOMr6I8eD2Yh8pdkBwwRplAndjheey1fWDsCVcs7dHmnF327PpPa5jOIRPg2O+pAkyIK
         yw3qTb8S/pf0KnUiTS85etyuH94QBzWhXz1WF8be3f073babDlY0e2aCxMNngOYtYzN3
         LXBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v73BMs0EqfMCwxJniJdo3jdaknlggr5A1qJ50X9w6PM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=sVx1HsJ2JHYTf0IP+hpc8z0agAM07atMiSwF/TPnmQxYqMeF4IcG3cRJAT1Z7pBrgT
         KsvdQPpBmel5Sdg+L77wcM8pQMtBS5MOtqTqaj0QZJ99ErR21D5jEhXm0JTmgXxNVOPz
         48x3XjpVulr3FBExjQ8gopPT3c+MrP/M+HLneJ4MPsBty5JxZW1FGAOmjnsk/veIvqb2
         ivanIK5bDq6eJtZkmWySJja6Ry8hZJOhNNmUzRRyx4ihTmtbWzOBbmHdnf6mo+5tkBPf
         3lqn3Soe1bSmt7yYXKSfSx176Tbe9hdAChEg13TCseudwksV9z1zDCnL93Fp6iRZLqB+
         AOpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cp3Nojk1;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb31facesi155525ad.5.2024.06.20.17.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNQmMG030138;
	Fri, 21 Jun 2024 00:26:30 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c06yn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:29 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QQwd022515;
	Fri, 21 Jun 2024 00:26:29 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c06ye-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:29 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLdxwq007658;
	Fri, 21 Jun 2024 00:26:28 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamn7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:27 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QMWn49742080
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:24 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6DBD22004B;
	Fri, 21 Jun 2024 00:26:22 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4A5792004D;
	Fri, 21 Jun 2024 00:26:21 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:21 +0000 (GMT)
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
Subject: [PATCH v6 02/39] kmsan: Make the tests compatible with kmsan.panic=1
Date: Fri, 21 Jun 2024 02:24:36 +0200
Message-ID: <20240621002616.40684-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: PiMadrv0_ZCFAt1YGkJeTR4kAUvMQsGB
X-Proofpoint-GUID: FRW7TOOkANa6sIxj3Ucz5e72WDq6F4rz
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 bulkscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 clxscore=1015 adultscore=0 malwarescore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cp3Nojk1;       spf=pass (google.com:
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

It's useful to have both tests and kmsan.panic=1 during development,
but right now the warnings, that the tests cause, lead to kernel
panics.

Temporarily set kmsan.panic=0 for the duration of the KMSAN testing.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan_test.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 07d3a3a5a9c5..9bfd11674fe3 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -659,9 +659,13 @@ static void test_exit(struct kunit *test)
 {
 }
 
+static int orig_panic_on_kmsan;
+
 static int kmsan_suite_init(struct kunit_suite *suite)
 {
 	register_trace_console(probe_console, NULL);
+	orig_panic_on_kmsan = panic_on_kmsan;
+	panic_on_kmsan = 0;
 	return 0;
 }
 
@@ -669,6 +673,7 @@ static void kmsan_suite_exit(struct kunit_suite *suite)
 {
 	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
+	panic_on_kmsan = orig_panic_on_kmsan;
 }
 
 static struct kunit_suite kmsan_test_suite = {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-3-iii%40linux.ibm.com.
