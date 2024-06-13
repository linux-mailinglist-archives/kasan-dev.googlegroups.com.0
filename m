Return-Path: <kasan-dev+bncBCM3H26GVIOBBRFFVSZQMGQEEG2APGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 71E0A9076D4
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:50 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-705b9a81f3dsf829297b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293189; cv=pass;
        d=google.com; s=arc-20160816;
        b=WXasfuVCSASxRsYaXJtpWTSqE5OMBV43c2Hh1FPAzli7zEkt7U3zUQxFEe7dRRg28D
         O+jvcTOUmu88K/v6OTpaqCItKHnWjVSfCKcVooeR8veQVyacyJXVtRO3jrtH/vfeC8Xj
         MGO90b2W635br05FPJ60O5jgb5E1fLcqAjoPxZKxyDw31qwHT6JEGoAP3vb/o91Bp3hw
         Y88EKsvdU/5NFHBV6JebvtUDSpbq1a4ncF6GTUO8bQ5uF1WwdwYwLcueyz+vcZWiy929
         tFPeN1IctfyGls1lByU+eX8WdVCOdveYk18Uf9GuxxHaaT2uK67bQIA0nwyrej0vhZHG
         puSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zWYdvq/nstzj3BCw8k0VOy9ZzVkJFE6DK2ZeChP1P18=;
        fh=mtMzpeualpZ0v1jJfz7LEiJoKcZxQWPYg5Dl0bsxS/w=;
        b=vAtjkJp3k1d+n6YzrNWukLK/sUo1VUZMns3x2p5iSWmRvSunjiFxHzZOEiirMbfQVZ
         J6i5nOWaOuunBfG3goPolR0IGjyBKsRmz7B8vn4/0Iip20T7p0xq7+/FWlg0pw+vVe4Z
         a1b/FfYQxKGtZ5tWjypmQc3lS3uWZhKwPxP009ojZgmjnmNkktWt+aih95AAMKq5Ypvr
         N595TbZOsdmD8RiqCiXS+Xr7CiaMRJa7vs9spxqTnwCknxouCuivSnTN/mu/c8nebcEF
         ohOgaftHs4PxcMGvbwo41yvaaGbalbUe/4UNIOh8qcbwapN42x4+vFj1ZeDIaaj7fLIq
         o7rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Xg3HEhtN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293189; x=1718897989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zWYdvq/nstzj3BCw8k0VOy9ZzVkJFE6DK2ZeChP1P18=;
        b=oY6ASD8K6+3s+zS2F6wJS85rfaMkn7xb5WLzW48jnimR+sy1Feze4nt4J2N6TvB4vt
         MGK/TmKMs72tL91TRziUkQ1c0MqoWFCki6iib0MKur4xpoSwZDvRLXW17loj5q90FgzE
         36+sBKmZbGXMoqYZFdgS9X+w2kalhDT+VM6ETyomZY0pbZ04PJpTtPiwQ47AeHO7ooCM
         SWak+32ikOiD2IfHvNg5E1QOufgPv/5c06PHG3dz1gJvI5qhANUVb6tMQIZjwVSwIyRk
         ILSX4kgZ4pXE7LJ/lNLd9LQpdh4bvlKnjiGf/z8SCtOtX7LSkOCi7NEhA/fHilZw4NyH
         V9ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293189; x=1718897989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zWYdvq/nstzj3BCw8k0VOy9ZzVkJFE6DK2ZeChP1P18=;
        b=e2peZCGXTVuvSkZ4IeT1Fz9kbYEsuuZU2V61lSo5m0sjmzqbuXAoc7II2+eWWcka16
         b4uOTKub3gIl881VpALwJoyOI9tB3vCTukUQjD8ouI9vQCvBtStuAU+Xnw9SMAFDhx1Y
         aBdfYH1oAIwpyB5+qU5C+OtYCOoPPKmyWTgUEgkRb6t3mwkCPA94b3T1LVGnM0MIDSfd
         94O9CHw90EVOXfefTKnWZZdtMBXFSl5SbS4kKPKkY+hoYdLaf4dhItV+0K+F5b6+pJZK
         OUY/Sk2a93Aq1WW0lwVkcZRflHoirp5ffNOyIawNddm14mfR1eWrSje9TvuXtVVHcCA2
         mhOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSk5i9zQUqyfSCjY6SqPO5d138HCiePa63oFAekFolfBVWb/gfys8ovbxKUVfuWSxGpRCm1OO33GYruel34j2ny7Bsqehi5w==
X-Gm-Message-State: AOJu0Yx+cu9/IBX3mn3YxGOmCBKZq1YvXGtXhW+RzUUijQDsKfITuoVG
	AH9UIlOP4NG6l4IG1gkxnJ1+WM55FpFsQRXtCnLchZ/0Hm+i3WIJ
X-Google-Smtp-Source: AGHT+IGaDhFpyrCjMr9oI3WthdV/Z0yX6tiiNFrnYQlmfdwkJo2eGg2/AIjFqF/CYsm9G0Uh2TZBAA==
X-Received: by 2002:a05:6a21:339f:b0:1b6:3fc5:d08b with SMTP id adf61e73a8af0-1bae823dbb8mr187702637.40.1718293188579;
        Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:180c:b0:705:ceaf:1f1f with SMTP id
 d2e1a72fcca58-705ceaf2d5bls501115b3a.0.-pod-prod-01-us; Thu, 13 Jun 2024
 08:39:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBJX54/G2Mv/4nYtOy6LusGFVK82JWhExvdGtEi/g5aGEErwqprPpQ1EnWOPFQRNCPgMG121pEM9TY9u8KpcUTTXc2zPQs9+AqTQ==
X-Received: by 2002:a05:6a00:4b0c:b0:704:2d7f:b61c with SMTP id d2e1a72fcca58-705d70e4b51mr43047b3a.7.1718293185833;
        Thu, 13 Jun 2024 08:39:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293185; cv=none;
        d=google.com; s=arc-20160816;
        b=ExXAGB3f49nLIHgJpTIAjdC3hkpK1pcQzp/FjwjfYRVfQqltpcnVnEEUkn/sOJHxfI
         zCjJbAx0b/vJxx4jWpW/xkrJRORZrQgvbaJ02PHEu1D76Q157fhMQt9IirlL4DBql0dL
         qUTwZD8GYB+Fh8pWaqctN3gJ/0+l1tzjo7R+CxELHSVNkiqtodvkf7iE+3yVwFTZvXmV
         +krnqk8o1jJoOZAxd80HFWzBgXlAxj+p/u2uO8JnIeSVbBGDKG12Zmjlsui43okbCETz
         epMPK9S17VLo4n2/m8od7Aaw1jBX78prNxSk38qXf6Bp60DmvApVRgtTr250+TWrwIbz
         IWYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=v73BMs0EqfMCwxJniJdo3jdaknlggr5A1qJ50X9w6PM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=FWGISC5SxTP83UtR7QqYTzc946G6d36MHXTVeup3bhN6TNz6NLfScIe1UXz5C0mpsO
         os/1aoiS8nqbjSPW4Pdx1EQxr3D84VhCpmK3ZsElRdjCVZKEULJw5pT0hSO3XGQeWIii
         nZjEnsoN3aF1na2QyFlPVKdqYN5lpIBfxbrpemznAoFfkM+FGOF1BB8eVPGQyQ4z+evA
         UkOb8Z+N1RAU3x0pdBkuvMqHPOzVrpUZtDCcmjH1DO1CtcaHayRbM6969qzNLDdXVDof
         dQrb7S29pjIY3SFLbchkEAlvpaFD2cvis6G3J8Wm8v3FOIWTXjHJJnFvMjXdZXZXvgMs
         xhKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Xg3HEhtN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-6fede16a64asi83165a12.2.2024.06.13.08.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DES8dv002382;
	Thu, 13 Jun 2024 15:39:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgde1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdeJI014227;
	Thu, 13 Jun 2024 15:39:40 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgddx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEAZNg008701;
	Thu, 13 Jun 2024 15:39:39 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk09-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:39 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdYlL53281258
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:36 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F407F2005A;
	Thu, 13 Jun 2024 15:39:33 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 800F62004F;
	Thu, 13 Jun 2024 15:39:33 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:33 +0000 (GMT)
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
Subject: [PATCH v4 02/35] kmsan: Make the tests compatible with kmsan.panic=1
Date: Thu, 13 Jun 2024 17:34:04 +0200
Message-ID: <20240613153924.961511-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: CdYaY4n1sBSfG-XGjjLpn6owGrgb3SMW
X-Proofpoint-GUID: Y8_1HwUsdyB2-FrEKBSNLoa0NfmRdcsp
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 clxscore=1015 bulkscore=0 suspectscore=0
 adultscore=0 priorityscore=1501 lowpriorityscore=0 mlxlogscore=999
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Xg3HEhtN;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-3-iii%40linux.ibm.com.
