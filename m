Return-Path: <kasan-dev+bncBCM3H26GVIOBBUOW2SVAMGQEVUWW5ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D159E7ED20F
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:26 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6d315cd0e77sf61334a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080465; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ta8OOImZZLq7yYu/84tYj34zQMd8ZU9ZUPnc6jnn8hSS5Zd04ESP/bX97eG7N+oSmL
         gvSz6Uy2Gqo/yaS68kAp7+aoyU4bfjO8LEG85Xl/JVhuL2uNXDaFMNqHGTzftxYG3cUL
         wPxDqwHxlSMF37+4D7vw3DILV2IdJeZgErs/V/kv6y+tdEtJEC09XhCX0yOXeBUFl5SB
         9eI7T0c9A+2xeJWWevspEDLusoBc087hihjoIin+6F7ckSQ6uKSRjK/Ud0a1S/4zvpf0
         XhQvajzQ2FBvw97y5HWQlPsHYP7sUR1Wqy6agEN8ae9kqgXhQTApHoiUtJ95tAhxWapC
         9mow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OYiw7el9T4x4GzY8K2GAEhpJzWzqDAdB6/Wp1pEQCO0=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=TS0tZW5/vqLuuDaGqIilAUbUdCfktesW0mDM9G0jfPwj6crVEcj0UBPCwLrhrQWXag
         BfIDLqpthM9k2uiKq7heteRC1zqRkPH1UdZ9fGN6nRTBw9AmOmRe7xBzGHtz7FdW/kQx
         EAKEtsVoZVsD9Deg6/nfYi4m0KnodcfiOcjqmu6CEJaJIFzJ2tyx1IMKNWNbpFKWZqBk
         2sMSaX6sH07dEplaDvis+Y6xwqr4gwYNhObgWs3CKiPRBqKXIJh2/IsFjoDUh3XTFfDU
         oaN930zJ8r0zLZZ482kusiL4UnfFom62qv1HcghFZw5+ROw1gt0Vx7ZD4DrTOFfygen0
         FqSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XJj4gqRK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080465; x=1700685265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OYiw7el9T4x4GzY8K2GAEhpJzWzqDAdB6/Wp1pEQCO0=;
        b=xiWpAuLd0ZHtPZNxlrccnp4eBGnCzBx/qXxtxnOopcyFQf1HsWX7QjO9ih7S7tA89Q
         gHOomvZ6ZbkfTNqxuWNoQjQgCHadNDUHb+UVlxRVncy2E2ySkRGvc/etAH5mLBHfFekK
         QzXMuhlmHJvbZqj60MSkaqw+Kf9hPUDginnQYM+n/w8apWC5LVc+6nUcQ9LezxlyxyCJ
         Cy1ZM6xEkvBaO1RA18mOKat6QnRKk8nt3a6E+sns69WcIHsyOJ41+aXsCeSPeuzRtjU0
         LKVowzCEQ2+SmZGC/6w/Zt5sF2TiR+73HwrwHzO3AJlPeQDtaIsTLg3EAum5jI5jLLpW
         rm1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080465; x=1700685265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OYiw7el9T4x4GzY8K2GAEhpJzWzqDAdB6/Wp1pEQCO0=;
        b=CrXDcXhHMJwvhJf+ojRrdGLaQrx6Q26kJVNelSebgCDYpEzymOvlvh+eoEtFg2WADq
         j8mZj8V876IPU7Fe155a8GcWHXh4Y/wJCH+0vNFLJCYjF3wXwODEwj0F8Qlrow6hbBIl
         Oe3APw7OhE7OVxZCWOG8g2A45CRWyB97i+lNGv83YqpLW6O0EfKVjT7hK52QoMk5HANA
         W+Gr/Zvb3D8TgQgyEejNffqiJGjgGlKXF4HSCamGI3oKb6HTegYHyZl5A9XWyeJGT5Jr
         mKaN9SBqMtwsYP8BFkGN/PA5NJXRmp7h4TVxWKrvATJV5vQYl1uw3pwszHrqhImB75ua
         BmSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwRO6kFrr4reEW5gbwjxf0ZVZcCqnj6myyjm4MQYD17+2Ng/2qj
	1cZ79mWixr7SnaY8SUYX3UE=
X-Google-Smtp-Source: AGHT+IEy8MKBuayRelPIVG98f6Hldb60iT0paZ3EsIWWfBqFK6vsYYm7XE7jsfX9sfIaKUJpe1oRQQ==
X-Received: by 2002:a05:6870:ed98:b0:1ea:3746:b7d6 with SMTP id fz24-20020a056870ed9800b001ea3746b7d6mr17466466oab.28.1700080465147;
        Wed, 15 Nov 2023 12:34:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6b89:b0:1f4:bd4c:c8d7 with SMTP id
 ms9-20020a0568706b8900b001f4bd4cc8d7ls206979oab.0.-pod-prod-05-us; Wed, 15
 Nov 2023 12:34:24 -0800 (PST)
X-Received: by 2002:a05:6870:ab87:b0:1e9:de2c:3bd with SMTP id gs7-20020a056870ab8700b001e9de2c03bdmr18953884oab.30.1700080464598;
        Wed, 15 Nov 2023 12:34:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080464; cv=none;
        d=google.com; s=arc-20160816;
        b=nAqqWAh93Lx0jH6/ew895icBFWhbikvgCL/at/m5WyEuEpYp1qz65sMjVjTj88hNPt
         V1Nu+aGwtlgVqbsVbDA/2aTqbqLn+yMbdiVlbSdaZ64S2+W4VBHODvyy7dzPMtZunVIa
         gPzVgBSUrBRKp6KMgT/3qbQniGuLbpNKM+80qbfOLaWaACaGHGdKXbi7D1AkX/ceLMFg
         gW1ud7xC/AZ3abeTBizdRbjQ08rKQyBa5pRs/faufHp1OpeDP4tk81lQeo1AUfPS9EBA
         7F6A4SnD+5B2zs7lwCCmdHOuZRLcf+A4LzS8sIrNeQFTgd9fzcvt7uaAhq7y0pgkghBM
         vOKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/jeu8ikBdkG3zT8cTTXDudBR3p8yyOmYypD5+KnSOCc=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=bdYnR11G9wPDXcExmOUodujvoLKOFXUq/Mn1z5Lbz4munM+WDUy+oaQFKD++A/gvMF
         hdne2Ps9YEoxrR6VGMcE/sERe35WXVUDFjFpYULuc74Ek9pE9jGP6SK4KpeG6gWGvt2d
         u3NGzq1CGICsUKlMtyU+MT0Zl6OW++Gp8eo/5fhyWWl44Vv7c+TRFN2m+gwWxB3un9MQ
         0ADceE6mry4gg/zOQK+fHH8CPBEgzVZAUZGV9YhnchiD7U4U+PXKAusr1j8/OLJGLbBT
         tJT3Qwz2CRvqpFJxwCfWjTiQdu9r3SnjuIzGmCxXDh4PZxTpBHpcfTjd+JswANLzjr5n
         FAdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XJj4gqRK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id pt5-20020a0568709e4500b001c8bbdda1a5si952828oab.1.2023.11.15.12.34.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:24 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKCEbw020024;
	Wed, 15 Nov 2023 20:34:20 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4thgjvk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:20 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKCaZt021252;
	Wed, 15 Nov 2023 20:34:19 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4thgjv4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:19 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIxFi024837;
	Wed, 15 Nov 2023 20:34:18 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uapn1sj4m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:18 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYFGK28639744
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:15 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3A8DD20040;
	Wed, 15 Nov 2023 20:34:15 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E4C8120043;
	Wed, 15 Nov 2023 20:34:13 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:13 +0000 (GMT)
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
Subject: [PATCH 04/32] kmsan: Increase the maximum store size to 4096
Date: Wed, 15 Nov 2023 21:30:36 +0100
Message-ID: <20231115203401.2495875-5-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: iSRl1qDbw0UxpkQf1oYEu1Z8v5dlxZV_
X-Proofpoint-ORIG-GUID: 2IYbA0_0cM-XcK8HWULf9sl6eCYS08q2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0
 impostorscore=0 lowpriorityscore=0 phishscore=0 suspectscore=0
 adultscore=0 priorityscore=1501 mlxscore=0 mlxlogscore=693 clxscore=1015
 spamscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=XJj4gqRK;       spf=pass (google.com:
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

The inline assembly block in s390's chsc() stores that much.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index cc3907a9c33a..470b0b4afcc4 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -110,11 +110,10 @@ void __msan_instrument_asm_store(void *addr, uintptr_t size)
 
 	ua_flags = user_access_save();
 	/*
-	 * Most of the accesses are below 32 bytes. The two exceptions so far
-	 * are clwb() (64 bytes) and FPU state (512 bytes).
-	 * It's unlikely that the assembly will touch more than 512 bytes.
+	 * Most of the accesses are below 32 bytes. The exceptions so far are
+	 * clwb() (64 bytes), FPU state (512 bytes) and chsc() (4096 bytes).
 	 */
-	if (size > 512) {
+	if (size > 4096) {
 		WARN_ONCE(1, "assembly store size too big: %ld\n", size);
 		size = 8;
 	}
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-5-iii%40linux.ibm.com.
