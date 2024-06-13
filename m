Return-Path: <kasan-dev+bncBCM3H26GVIOBBTFFVSZQMGQEAQKQVXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 499349076E5
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:58 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5badb0511b3sf841260eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293197; cv=pass;
        d=google.com; s=arc-20160816;
        b=yd4tswmiz6UM8//b5ORVupcWv4y0w+T0loghksQbpF9mqHZhm40cl4Bc98k58Hp26J
         w/6SpUG6GQbvBSitldkwTc/iSOR1v1lTOB092e3X/QmF+E3S1/Jtb1FjxKd2xLdlrotI
         P+oQEwVG1E66Lg9gw5a6KABG6CmS4m39/6348jIHa8mnHgatfqhU1uvx6/FU0LoRPeGR
         3azOcqNzzaMiBOhzZyyC3xM38m71E9l/5T7ag5Tj+PCjYwzzUlf4GN9tl3rphe1dX/fI
         qpZV4tGpMUE+cFyXVIhCfijIzGPSrjY4H1H0oJccdlheTMyvMWgRVsAByN+mp3C3JBOA
         yYDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/f3ivuZ/yRdcErlVs3D1ivzPgUChntOI6jfbkA8DJ6g=;
        fh=UnTXqIWWvpnV6ukODUnSrkEO2LDem+XdLKrJTdvhovk=;
        b=YHhQlgpGw/XvIK4x6JbjkWrTX5WINOvMDU0nxk89nXwB5GmTEy8AXS/YHl8yH8ITdc
         9W5BF+5P9D2O0cQOwJ+NniMgvLytRSoyMndv7H0WQt60Gdt1YGDowaRceLI53sYlpRcs
         O1ScvIZDSC+nraW9B5gS4b1T0ZJyjSHjMCAmTST81t9i+MFFFDHucalZ9Wtmlx7SX1uE
         a+h3H7nwMnabbdpArsX6RHFFCgZ5dkICksgiHSuqxgpJZOU71od6MYTlacPtnlWCbPdz
         Ymu25vmZXfG4+FH8kwqKQKnIunJWSZszzufnxMEKjqWQjh4scXPhWYF3l0ppqo19uCw0
         ZfgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ILj8Ey+G;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293197; x=1718897997; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/f3ivuZ/yRdcErlVs3D1ivzPgUChntOI6jfbkA8DJ6g=;
        b=sxD5vl6z0hnlbXHUnBtmrpw1UzgN02kqiH53d2sup8RaJffyW8mrqLKmNiqvWnGj9J
         Tbw2hR2AkTbY1MA06n54Sfb+Dj6KW/4om7voTWf3AF20DNbdIwn7OdGYPBz++Ey8FdqB
         2f19IgQDWVIxulUiTTzIdJJQE6F3eeEqwW53lFrBjx2S9wjhJCcMwixxbJA80RkW6SPz
         o2ay7+kLyPnmmCMxvAvIKEZg9JyA0U5gL8T/BnjNCNvST+vltq6NMbgqAcMEf89yjGUs
         lxHEk4ocUzKqNS9FZW6qQXcgCzXVquC40CyeG4hdPmeAwznsmnIbkEjZiko/r+8nSqDF
         5x1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293197; x=1718897997;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/f3ivuZ/yRdcErlVs3D1ivzPgUChntOI6jfbkA8DJ6g=;
        b=WohfJVfdmQSnYsk5L+rsoknX15a0x6hJIJ5aRkL2/ydmjipbMmdUW0oCiUPQrrnh5e
         PVLSrzkkG2wmMaZ2WQIt0gjvm+anBSx5ma/q3Q5bjfgbsOUQO5gAL8kagzIC0plzPZuB
         MTvKhBqelXKLjk/Yf+eD55U18mZBUQBqf2A3nfcRqpR+9i+hSS0dLxUKDzeuQRHG1HKp
         V8tDKiXY0Hn5zTX2UchPE4TDUqm1X7r6asftVbT/SfNTlnF1nc3RzD1Prwff5VNC+SFh
         Vixb7/GnlWDsiOIBJ6+0TQEEDlarIzo8pT0oZvpDUGxWWWYbOVx4BwCz0JGU15Uf0ptw
         +K/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBjKP39lCh9gQ12HL6B5lkfzcPM7Efquw4GbugjnnHy3SURPWQeljw6Rcb0hwNQW6WyP2Hi74I5o5ljsqRYd0/EZWvyOfQNQ==
X-Gm-Message-State: AOJu0Yz0YuWc/+QVmou08nSTA/M3Avvig20H9mqV26BOfw7+oK1lks0Q
	t4X6RkmCiyJQrJtKpQgiJoq4xkjnX7HUI9Z4GQcPVdlXwRXBaAGm
X-Google-Smtp-Source: AGHT+IHB8pGaegnGaDkG7Tvf+Bb0cN9ExyuZMfDjz8QCY1IQVim858cUJ727PvLcQzhkjqT1cbtQRQ==
X-Received: by 2002:a05:6820:1c88:b0:5ba:e995:3efb with SMTP id 006d021491bc7-5bdadc41c9amr19519eaf.4.1718293197024;
        Thu, 13 Jun 2024 08:39:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ad82:0:b0:5bb:16d7:73fd with SMTP id 006d021491bc7-5bcc3e0d0bdls864418eaf.1.-pod-prod-04-us;
 Thu, 13 Jun 2024 08:39:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUN3k5AxMgZ57mLNgQXB5UeM7mzGK2roCsIt/9Qw5bhT+g8WNkAylZUhDXpqwwu9t0GNvo7usb7OdFzzov952BpxdjOWvl+vSUcjQ==
X-Received: by 2002:a05:6808:152c:b0:3d2:2efd:123d with SMTP id 5614622812f47-3d23dfb0965mr5768834b6e.3.1718293195750;
        Thu, 13 Jun 2024 08:39:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293195; cv=none;
        d=google.com; s=arc-20160816;
        b=CmAX7H7cr5bhuJlIEV5mwoxxbOS7xMgxm7Q9Q118vpv670sZgRJk4GwPfs6iFXHvlL
         l8l0LsAb8Beb4YlDomAyrsgvZ2RK5PBDrKOSO1RbHmW1SbHQDrc2U8ioP3RjBPDnOJbg
         vanUwW5uaReplejxrl7pd5RrLCNlFPpyPUcsjf2qBATXpWMrH4Ol8UXnIqoiApNRD6Jp
         NW1P/gkp8VrWnomnbWFfJVgE7ubKOO3hn4iYkoBc0xjvt7e8LW5AQOAvtlUfSJcPHeAO
         1m4ucxwqbJDJC9XZaCbr9aU7w9QeL+EyFkdULqT1rNu+5ol0lWsDlhO0+ulVs36JzVRv
         4roA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uLXUx7Jp3bWbEFcECk7slBB0jNtnowMXhhGygxJBd8E=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=jxVGi6xM61qIrkIhb8/VWnYC1N10QYRiHPYQRWho8zH+miyZOBtpD/K+NoNlzT4dE9
         IflRE5gxOtqhJAfFALWojbtoIIW8p9k1pAe+ZBlQy4T/VZe3h0eqIZS1X1ZNoNZ55ezJ
         tMCWfj4EQdy9fBdPt0wtyY3eBLZWqw/5myXGQNo6+vZGEpp1M81zvzHZkhONZ7QL7m34
         Y1qTufOR8Dm0+EtiZM1kXlAljq69bMbAv2LTYEun+1BUMI2GvGu54nncDfXmsuDjZuxL
         Vbeod2jq9FmhQCl4qSwYHwqM1fKTdNiizf4z4BXIqC2iGjS/Qans7BzSjksVeuh93RYr
         KiLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ILj8Ey+G;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798aac9e6fdsi7308485a.1.2024.06.13.08.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DDoRSf002951;
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqy258xxg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdnRh021098;
	Thu, 13 Jun 2024 15:39:49 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqy258xxa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEAxeS023597;
	Thu, 13 Jun 2024 15:39:48 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn3un0qgj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:48 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdgvl55640438
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:44 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 48EFF20063;
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C9CA52004E;
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
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
Subject: [PATCH v4 17/35] mm: kfence: Disable KMSAN when checking the canary
Date: Thu, 13 Jun 2024 17:34:19 +0200
Message-ID: <20240613153924.961511-18-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: I4PaEB_PP3Cvo4oOH-ZDVke6KXq6_-uP
X-Proofpoint-GUID: X5BX2RWEHptsiw2F2Vy6DfHMQyyCihli
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 spamscore=0
 suspectscore=0 mlxscore=0 malwarescore=0 adultscore=0 impostorscore=0
 mlxlogscore=999 lowpriorityscore=0 bulkscore=0 priorityscore=1501
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ILj8Ey+G;       spf=pass (google.com:
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
index 964b8482275b..cce330d5b797 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -305,8 +305,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	WRITE_ONCE(meta->state, next);
 }
 
+#ifdef CONFIG_KMSAN
+#define CHECK_CANARY_ATTRIBUTES noinline __no_kmsan_checks
+#else
+#define CHECK_CANARY_ATTRIBUTES inline
+#endif
+
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+static CHECK_CANARY_ATTRIBUTES bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +347,8 @@ static inline void set_canary(const struct kfence_metadata *meta)
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+static CHECK_CANARY_ATTRIBUTES void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-18-iii%40linux.ibm.com.
