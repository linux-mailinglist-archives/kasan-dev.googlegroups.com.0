Return-Path: <kasan-dev+bncBCM3H26GVIOBBMP2ZOZQMGQEMLXPF5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E044590F2A9
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:54 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2500b8a716fsf5737379fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811953; cv=pass;
        d=google.com; s=arc-20160816;
        b=MqwE6xxTDiYC6ui8ytmNoEKgwZkFM/JZuOKHKh2fyvsy7wdQ/XZ1acFdfGMyab2PnX
         kNB/Gq/22r9M5QHrL6RxvqtJA2ajrt6gaNalu/Ae0FvrZDcpezodQ+NoLCRrJBwVTeiD
         ta3L2t5Nv89PLntleANiOqVHCU+J78dBpo7USgYDV01vekY2ej1ZPpwDefMnTjAl7cOd
         c81f7UO9I+0Y14kJ3Jc9/qM8KQrp17/wEjqnKN7hUOcwFrY+uUCRZoDNQ7wuAphL5Nen
         zo2prCBlMnQrYN3ruL9RhxsHpIuk/oo0es5yeo6hzUJVGr0SRO3V9dRKVy6fdDC0e3sy
         vheA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=76u2+ZWTynNXdcBHTuRQFQKtnYWk605K8ZW84hqnDjw=;
        fh=jRCYsQ3y9+1ka8Ew62WOGe35TBXfJo/+eHHLWBW7D5Y=;
        b=pTOhVAU6SZUJKOR671Zpz0wl913Vh3oQ05RaOcGxqEfsmcf1G/GXUvuiDHmUJEM30u
         4Na0VLKx0kcF8PRh4FMfkgSJQKb+diclgPOSc8uMXCY1MEFwEpth9YpMyPlC7f2p1mu8
         20VJiXFRg4wPOrx9sJD1nmP3TRWn7BgBJWqjsNOLSW3XdrrLW+AEdUIL+F+1ySDM4tYT
         bCrde9WPH9wcfHKbS0ZSNKbexDF1JCKnX7lM846xgbEGVMPOAjoyfAh0FIYUmFqytGDq
         2PaMar6uzutNthrmz0ZDTnr1lHeibVHOxcycZjGr8oKh1CszqTIrYvd/dgcSjFQlH0c5
         yQmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=H2rwcfpx;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811953; x=1719416753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=76u2+ZWTynNXdcBHTuRQFQKtnYWk605K8ZW84hqnDjw=;
        b=sXwjdoFFrGo7y8T8XgFxeMqsMQpqeUC1IYTW9/N8ISH9CW6e2EcqqIMmHh5iBXJ9Xk
         05xPGyHLixxSzRpfxuH1Z4xqe6ujYO0s824K22LFLyG3zk9UWRvq2z2nflLZdCCg4IiY
         1bTdWYnrbsBZEaFIZ4exJS50cYCUpxqjOUubQDmhWvfmgx0cn7Nw00BYxBHrodyN1ico
         3G78NLIJUQWhIM4hKQHcP3Yexd8Z3D1Nxre7ZUXZWb6jSsMZdRqf7NFMj5LmKYAM9VPx
         qwqMYRw4beTtJQ5bYnUDdEbpGsli3lttarcP5pLHWGxO2VRDxovIqiEZVy+1ceWlMBkc
         gIzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811953; x=1719416753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=76u2+ZWTynNXdcBHTuRQFQKtnYWk605K8ZW84hqnDjw=;
        b=wbtZMM+XUJf8VHagfttt0wjeZpzu6V+E36QOIfseAlfJut0miK78I6YvESBjlX4dvg
         IpHF0Kkmd11Q26CUwPjbM0oDxQHvHIx8fGEU2kEkOHkzY9UoT0S9q4/au7lHbGvzRcPr
         0eKzj5zB4sbr/lL1UR2QhRPFUE+Vzp47eRW3aZluook4WptJTaWLYi/zSFR+em2M1dKs
         MBBSi7Exjz9ydW3N20Di1jxNLwQxwYfBPGhh4DGjsvpebWHdStrLEfJR6/gOC9GGPtsc
         hzsr4xzTlQWOAsM/EmxDA8MLypkbdYH+6N0alkR2lj5Z6UjM6zFDEq1K76VlPmu0pZO4
         0uZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUPlRgxWKEv1jDA3zqvzBNIUulTvDbso+L/BqveK4So7bqpIZN4HO/Dj1uZxjV1z4mUnzAhxEUjgNk9fk8D6x/EW8FKmXpqfg==
X-Gm-Message-State: AOJu0YwITE9Nn8lVCV3SdhsV9C2sNVRxRNrswg1I79b2i1zf9mR6HEWl
	9ADvx6vxBDZ0+ByptuD/ie0O2hZ7355My+vEsGOEzxVtH0VpfvCQ
X-Google-Smtp-Source: AGHT+IEMvDfwmh9HYwwKXCPr0B7cPbcCfNcUKESBH6gOdmL5171axiE4TeiCLKyGawV2GW33JOXGrw==
X-Received: by 2002:a05:6870:829e:b0:259:8420:8e3b with SMTP id 586e51a60fabf-25c94a1d3b7mr3556705fac.21.1718811953640;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5486:b0:259:8ac8:a82b with SMTP id
 586e51a60fabf-2598ac8bef3ls1863455fac.2.-pod-prod-07-us; Wed, 19 Jun 2024
 08:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuRRd+49hB11M80+ydu7TExuDDvVCqu3U9QEzWd/7d0qQIt8nICY+ZllJ5yvvIlsDeHVIz0h3Cvnw7AigTBdkXnpKyQm5YnfSX9g==
X-Received: by 2002:a05:6358:430f:b0:19f:19dd:9029 with SMTP id e5c5f4694b2df-1a1fd3c8a38mr368792755d.9.1718811952679;
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811952; cv=none;
        d=google.com; s=arc-20160816;
        b=SGbQGkPA4faFrS1cN2703qtdoNrx3GHTnxIpzGwEK4Srqwo9wfecF0y3SLWdhccxWp
         7FsyXNtSh38KCRbDH/W1M+n/YUapas7DRHC70KS3Wjq45Xecm4p1VtOHOLLN16dtB4Dt
         YmLczlnujQbDo8K4Mo2l35eUuUehZo+BRGhARQinBO1HBw2T+FcBTXtJbO/FmSz1qnAW
         7DTDbV2zkgQTjlcyN2iS5Pw3Jb8MVTsFnY0vJ0vdiyvjQ3V2V5XZIAA6jd/W8swWcY+Z
         TCqOt5zivCI4Qm2aeqUg+T7rb2GnY5nufGM7VWtuW9HXp010YrFolPtSAaU5haWgFkGa
         kk+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o5OLh1G5igJ7wfCkEas83RRSlonR9xfZGMUuvDY/DE0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=XNJPkLWMYYD5rRlmyH4Z4yM9uokKBSb5GxwD9ATfGSWJ81p+NP1lTHQOBwNplKLzWy
         vXPAryrjH2IuYB1vByySvpYBa32xDp7d1URc9501Mj+ZoI0gvyvp74gZc+2jaLMVW12P
         JgJ6YSnVj92td2wZiq/kUBUO1DHRxotPhDl45D04HrQLm3cMyHuPYBOCQegY0NoKBC+s
         gS1eGlQzpidQ1PhIYKEHCfvyANEKqvzuAkx5iXkS0QXtAOoXoX+jaqexH0+M+Vr+dJTR
         uLK89SFXB3KQHNfIY4UuQjm3dBUwthtGC+v1y4d0utc+Ea7gEQgQNB3HmjrM2TxDOm5H
         5mww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=H2rwcfpx;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798abe4f369si58636285a.3.2024.06.19.08.45.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JF032v027848;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5bp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:48 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjlSu005782;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5bf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFhSXR023897;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdyqb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjeu751904966
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2661D2004B;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CC37320067;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
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
Subject: [PATCH v5 18/37] mm: kfence: Disable KMSAN when checking the canary
Date: Wed, 19 Jun 2024 17:43:53 +0200
Message-ID: <20240619154530.163232-19-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: avgexdB5NelKVCyWQvNp9eWkYSYTUZuK
X-Proofpoint-ORIG-GUID: TdCHS1L2YRGuiuvHwsDX16Cd7IpCg-Qt
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 clxscore=1015 bulkscore=0 malwarescore=0
 mlxlogscore=999 suspectscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=H2rwcfpx;       spf=pass (google.com:
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

KMSAN warns about check_canary() accessing the canary.

The reason is that, even though set_canary() is properly instrumented
and sets shadow, slub explicitly poisons the canary's address range
afterwards.

Unpoisoning the canary is not the right thing to do: only
check_canary() is supposed to ever touch it. Instead, disable KMSAN
checks around canary read accesses.

Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kfence/core.c | 11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 964b8482275b..83f8e78827c0 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -305,8 +305,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	WRITE_ONCE(meta->state, next);
 }
 
+#ifdef CONFIG_KMSAN
+#define check_canary_attributes noinline __no_kmsan_checks
+#else
+#define check_canary_attributes inline
+#endif
+
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+static check_canary_attributes bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +347,8 @@ static inline void set_canary(const struct kfence_metadata *meta)
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+static check_canary_attributes void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-19-iii%40linux.ibm.com.
