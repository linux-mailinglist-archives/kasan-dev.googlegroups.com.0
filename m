Return-Path: <kasan-dev+bncBCM3H26GVIOBBZ6W2SVAMGQEUS5V3NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 42A047ED225
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:48 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-35ab1b3d271sf778255ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080487; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYQouWuHFqp9ihdWMeJZ4hykei5lSJV2Jrr0M6juJnPpZM0yu06QBBCOrPztRbPCrh
         Mp9hVW/o/kAlMlF3l4hCj5ECF4rfplSi0EUly+pV9aFDxmb1Of+8OR3fUkjm7Qqj2Rt7
         36tkAc03ro40tV+nOy0yLzPF1e5MGcGJ7ie+9ZSfCTHQnJ5fi+o5mhYm3HrrC04SwLgw
         2DKG2LY63Fmu2dS/H8pnjOOZXHC7B1/mWjS1S2H24VsZoQKizI993GhjLSMUjK5LBrtY
         hdgek0DBzW976SPBcdDx5POaK8ItwWY7cDZG6pFLsohMyBlfmnRW4FKPNk4ZbK5k1UlD
         p3Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NyaSlGMLc8NZFnkNmXui8Lj44p49R9KS6MPXXodd3eI=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=AA5W6mmUdE9r2q3RwNJIEyj5y0AMTPf3uwlnTM6vQ+wqS0Kst0z7l0nqYpZEydleSD
         J6432I2fupNsKsjE7rgleQFh5Q/iQwlWjlvOH4Q8UJw4x+CY7yjF0K4cpFMCzBH0VxkJ
         /NxOdUgtd8ZTx3AQFMH5uJJ3iRoUBC+QecnzmSFebOJedXgS1De+k1M7j5oMerB9lhTd
         Yuj61HO12Q4lUTCfJECWXD/B7ZLxADaivwkYanwQWGILqEaLu5//SpGAmo4JQ5mZI4cf
         GHh5Uu9scEX8lIsLb1mORK2Q8PHOsuN7wLk7P6OmGguL6pIr8RmlbWQ22ksSCArw7BkG
         HMiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Fsbw4u7f;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080487; x=1700685287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NyaSlGMLc8NZFnkNmXui8Lj44p49R9KS6MPXXodd3eI=;
        b=SR419VUaLnik/laZ5PaMFuTWIzXo1Wi7pHVG7IwnqlZB1jaFvkFkzea7k4I1Ox5PJ7
         LSRW+P2gtQyIW9tO8djRNACyECOsOfN125wgq80ETp/fZ4fxzhPVPRtH/LTgYJSGviV6
         FCwBf9wDkPcdY6CMLMBRA8tT0dZiAS26eTSz5tbYbM4vavU1Do3b3fZgLM6u0nmUwqEw
         TjsxqwU0oMQU1K5tcLOwgmRKfptMT//82PwnPWPnL6W3SJqQnuafFgQKAONzuhLa1rJ/
         fJrHnHx5FuM+96SlRvLSRfEweh2OmAZindop3zso3Hm6gomFia7iawjUTui1+gKETBGl
         VJXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080487; x=1700685287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NyaSlGMLc8NZFnkNmXui8Lj44p49R9KS6MPXXodd3eI=;
        b=TGepuXK2bUV2KL/U6sOIp4rFdeuwTBNaUKuu8vgidRe10oR/u4c4fJvVGYFNOmszNI
         4l+w1S0lHp94i8mn4Ixe8lqVVw4pmLFw8jAFAgkhxrXtg/7RsXYMALg5OT8ox9sQjrvk
         Y2RBzE89BNIWGKeKwLkwdvxDfvnzVtXterkmPDrIj6QXZ/WWs75EU7esifMWKR6HID/j
         ludnl+zzJZZnehUzVE4PBACTfBLBgg3h0Dq6h+jIDO3byLCgTGuT8iJ0PaBTnzUf/8UM
         r1oCE9kBMJ+UkALyQo29Jedvz/Ga7moToTl3eDIrc7zduvNiiCH426gKYBxwL8cXoEHF
         6J5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YynH/kvXa8hqg15ewuNtz9DZQvkAd/S2o051HnijCKJ5yLcs6fe
	ECGOFcykR7iJh2+CQCJcjiQ=
X-Google-Smtp-Source: AGHT+IFyxocniE6Svrrklp1vB5wFmbQoxjN4NJPlyVm8lYCanR2Aj6I0lP5H2XFK0X584NfGSgSfrA==
X-Received: by 2002:a05:6e02:1c8f:b0:359:cc98:7508 with SMTP id w15-20020a056e021c8f00b00359cc987508mr17252756ill.31.1700080487242;
        Wed, 15 Nov 2023 12:34:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d082:0:b0:346:64c0:449c with SMTP id h2-20020a92d082000000b0034664c0449cls78907ilh.0.-pod-prod-02-us;
 Wed, 15 Nov 2023 12:34:46 -0800 (PST)
X-Received: by 2002:a5d:8e1a:0:b0:7a9:a31e:c05d with SMTP id e26-20020a5d8e1a000000b007a9a31ec05dmr16265365iod.18.1700080486611;
        Wed, 15 Nov 2023 12:34:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080486; cv=none;
        d=google.com; s=arc-20160816;
        b=IQGKXUDDfq+WNiCoxcIMEu1KQiLiEbN7x5Y/nZpUW+CV6YdA1Ey2XPuMOzgi7oVFmZ
         KxAdxWQkfi2QHf1n53uX9UAV24Ms9fqI8qzcPPHTkkFbMk97MCxJfyFXLS+fBIpkpgEP
         LBe51ZdlNayLCd5KxNm8W11ydb6w/hBtE0IP0qBV+Q9muF2qaAOd6JtcDBndpyleoBvf
         AlM0ROkyqdKZwgc8Lr1tlrf6vgxfypuzXIG130rR/Cvik+6BVzB7do+XJqF70nvy++5b
         m2wuHllAccqByIyGVFfz0kCROg5xEY4aV90UMmth7pJYrS1fPE7HlRDEV4v6N+kPzO0Q
         pOTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FBHiR0R3HqDameObtBi5tDwt9B6xgR+xiaoV3r5rhIA=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=NXcInbnUlxAVHTF2BXhzofANcucKwPQ77Je2n23+TZaGFARUczEZ4lJuljgo7pd6Ru
         1tDgwYcL5lA3dRsegaHLyJ/hR7u7YuHu/5IzwUMxd/tylO6QwVDvqUwaeo3YVQefcvlF
         PEaKkbCMrF3LVZqqQgEb3U54vdUrzNDVJY2SCKFH+tv2OR3OIWUAn92ZP8SG9Q6VGa8R
         LZPbghPYCN3TQfrDSgB6IlO+iHW2vYLeohZ/ZoQKqiQ7mr0UJIvtIj/SoAqqKsfcTmIK
         dIYi2uTDyM8qcoF5JR+OPoXuROdOqc0K3AKAsz2ptArOtLUgCRTypK3n8dE6+HviUSwY
         8fsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Fsbw4u7f;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id r8-20020a056638130800b00463fcd15b78si1261184jad.0.2023.11.15.12.34.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:46 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKGBf9020343;
	Wed, 15 Nov 2023 20:34:42 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4ch9bv2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:42 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKGRQZ022066;
	Wed, 15 Nov 2023 20:34:41 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4ch9bun-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:41 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIvqo021610;
	Wed, 15 Nov 2023 20:34:40 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uap5k9kay-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:40 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYbWA23069318
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:37 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9EA3A2004B;
	Wed, 15 Nov 2023 20:34:37 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5288420040;
	Wed, 15 Nov 2023 20:34:36 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:36 +0000 (GMT)
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
Subject: [PATCH 17/32] lib/string: Add KMSAN support to strlcpy() and strlcat()
Date: Wed, 15 Nov 2023 21:30:49 +0100
Message-ID: <20231115203401.2495875-18-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: WE4fc2MWwcSfv1ysVLGFiuvMJSpg76OK
X-Proofpoint-ORIG-GUID: Mee9YG8eX7q6Hn736J-ftydiuuw4ftdn
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 adultscore=0
 mlxscore=0 bulkscore=0 mlxlogscore=999 lowpriorityscore=0 impostorscore=0
 priorityscore=1501 phishscore=0 spamscore=0 suspectscore=0 clxscore=1015
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Fsbw4u7f;       spf=pass (google.com:
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

Currently KMSAN does not fully propagate metadata in strlcpy() and
strlcat(), because they are built with -ffreestanding and call
memcpy(). In this combination memcpy() calls are not instrumented.

Fix by copying the metadata manually. Add the __STDC_HOSTED__ #ifdef in
case the code is compiled with different flags in the future.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 lib/string.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/lib/string.c b/lib/string.c
index be26623953d2..e83c6dd77ec6 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -111,6 +111,9 @@ size_t strlcpy(char *dest, const char *src, size_t size)
 	if (size) {
 		size_t len = (ret >= size) ? size - 1 : ret;
 		__builtin_memcpy(dest, src, len);
+#if __STDC_HOSTED__ == 0
+		kmsan_memmove_metadata(dest, src, len);
+#endif
 		dest[len] = '\0';
 	}
 	return ret;
@@ -261,6 +264,9 @@ size_t strlcat(char *dest, const char *src, size_t count)
 	if (len >= count)
 		len = count-1;
 	__builtin_memcpy(dest, src, len);
+#if __STDC_HOSTED__ == 0
+	kmsan_memmove_metadata(dest, src, len);
+#endif
 	dest[len] = 0;
 	return res;
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-18-iii%40linux.ibm.com.
