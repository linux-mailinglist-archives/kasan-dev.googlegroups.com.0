Return-Path: <kasan-dev+bncBCM3H26GVIOBBWGW2SVAMGQEIKABSEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E176E7ED216
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:33 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-7a66304e362sf278939f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080472; cv=pass;
        d=google.com; s=arc-20160816;
        b=sXv/VWiD9pwfpvfPgg4+1U3rtmKRjsdByaevCw0cpE3bbzEG13dqawuxzA8VMoodeD
         gUj5yKomdXWHv614RYqvM9MCW7XOmfmbdiHPu2CL2YeGhWm+io0RCXUDlxsGnbF+rjmt
         9bW1XLdqXAD5iHKj8TpRAQiKx25ItxwfTQkOsy3Weky6qerR5vyjgH2e2MRBEaB++s93
         6UU2ZDfncf0Yf57MbXr6cd4jbMl8wD9T7zAfhTwZ7nNUQzZ2ChQQ29xdrZiOMPJjHPMa
         hKfVI9btgCKXWhp6FwxvfnFCN+pDZ0VwuRDnAGBKWuzk/C2Y3f9LBYsVNoppmHGaPyGo
         07kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kcvgL/d2ruPrGb/0w4Z8vaD++FuAnhtXI/XOMj5mv0g=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=rQzgQ7km/8MunQg7Hj466qbZMBvw+cFVZdfxT4EIceO4eMNT/B9ii5aCMHIanAxKX2
         e6eVx1NGn281+RgyXTjw5Zl/AYzV4VP+ShcWmZzzyms566CSckGBcCqKgLRf/vGq+vKj
         1MhvXRIfuRcSS7lPnG2r00pk1qPEwWZ0D0nXIoeCFToljqhwZPuoLM3P0GuLL37s9HXX
         urlIPN45PpgjA710KoUm6sXFSOUUirTfJlEwXyidivb0ncTQRND9rGaN9B3qIpIiLGMD
         Dz7/gbvCkNK/1Y9w1eOcs1arQe4GhYQwA10yByKw2aG32WrCLX5BLp/8Aufbzpo5I/Pe
         ABvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oL5sLjSW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080472; x=1700685272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kcvgL/d2ruPrGb/0w4Z8vaD++FuAnhtXI/XOMj5mv0g=;
        b=P1c/W0TDWMrMx4f1gb24bHJystYLRm7jj34yYfjhMvzQrHK9VrRJBmOn3z+bI/yB6y
         a3lrgQJU10Jiqoa5PJOx/JZMb/PGYh5QvB58zeqUFLxdWv7hjEW7y/FX10bRVMKFopZu
         ZYZFAYLv6AvYIE3iOUSc9dTy9unpYerD0Ds4jdKvV7MMEuobuKe8CCod6NGnmtNj5L/x
         TW2/JAE3Op+1jj9NtmKv4FZtUUn9H97qBDfC5VVh/ckVFBGPKyhjnUGN9VD95X2xLdJt
         CDLmkUuj3yPhh2h5N7PB//1Y2yUvJIGh2oNlrSuXipOh5dL4QLPB6zyv2vf4dkoTFgkH
         S25w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080472; x=1700685272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kcvgL/d2ruPrGb/0w4Z8vaD++FuAnhtXI/XOMj5mv0g=;
        b=dULabQRdfIC9xHEWQOWv7s29avV6Qi+CrY6CWbMeUQPemIfs9ewKOf7RzY99Lbb2Dc
         qMS3943dWJxtNOSL4V1Y7QIcJvhKPmHiIHFanj6cqWzRetFGFTvFvPISNrIxARv6LdqF
         bGL5tk/ED6dnTMaxHpGGAXKbu9fkeNybbt0tKHExukavxG/4haxm7ZhyuUOC3p19uJjk
         9r172n8pTLDzFMAnMcBi4md0piR41GmragqEcXt+sIlMolq7wXfs9nAZEw1lhT3OUhxW
         UPItD9r9UdXXOAx1enL92ksLTUR28KYpMKvltldcLmQAbtJJGGnGStnEjE2ULB35e8vL
         Q43A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzji7Z0hfbcPz1yCN26Zekp+Ts+2XavvzzIOta6TSNUwTEZGqA+
	QySPam6j+vty1K958vPYPj4=
X-Google-Smtp-Source: AGHT+IHVHYIHAnOjhPFttAC+d8cT/ZcJUONfpRNjKMttOPoG2OBvJXFulZOinEUfMiyoo5Bxg+/F1A==
X-Received: by 2002:a05:6e02:d51:b0:359:a92f:6d4 with SMTP id h17-20020a056e020d5100b00359a92f06d4mr6008041ilj.3.1700080472633;
        Wed, 15 Nov 2023 12:34:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ce0e:0:b0:35a:b143:ff12 with SMTP id b14-20020a92ce0e000000b0035ab143ff12ls59782ilo.2.-pod-prod-03-us;
 Wed, 15 Nov 2023 12:34:32 -0800 (PST)
X-Received: by 2002:a05:6602:2c90:b0:7a9:61fa:9605 with SMTP id i16-20020a0566022c9000b007a961fa9605mr20217968iow.5.1700080471566;
        Wed, 15 Nov 2023 12:34:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080471; cv=none;
        d=google.com; s=arc-20160816;
        b=wxrZIcGqNWAbE3Fs/v9Lu65PaSBYHw8IEazUoG59YaeXWXWEzwncufYQB1KAE4ZBfE
         OAs12p34ofqPAvz25Py77rPbEZVUBzj9/WLlHeF8VvuId3O0SBl47VsCLrcVPg54nQU5
         m4msiwiFCcf7utyCuwrkfLybRXcdupD0CjztNlFm8YsU2eSEHAr5U3ngk+hS92xGnNsK
         M+8zs7NpWcjGY2tGnOEcJibRRWJpoPLqyo784QgAVbUXVRBzrslnTYQ+5osSivzEdE9v
         HHdT6YUUef3f/ZkbKeLleUJhYsCmzQoGhtPoBV4F+EDGqdWDFX32IpT6RP5y9JWLQnD4
         jsAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kILyw5cdgjGn5/bq6lT/7Km7hA/yuzYatpUTfjRHTeA=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=ibAL4+YT3kaa1lEdAOzvUzNlnShqT9DgfgVvRomJeaPILmYrULnatd0OtMIuuOok4+
         +O2isQL8gjlUX/lwEnfpMNU60H9AaN4alBfdLdOdfGslIFtK0H82mGwAr2+k2d0w6Kbt
         rMm6MAF7Yn4DGlUaUdPdhJZV8BfwqvZIJveoa25LItCzdVPxSm3DkLBLuP94aJo8/vaq
         d9DywdDtksgF8rxvj7lPVtT3XGQYOxkTo5HOdiax+Lo3P6Q5dDCcVSzh+iWj3paIpuWl
         fsY2WJBe+VCCfCStI2UiZftKxiNNJghXllD+VJnuqvuZnS7ptnxxcfDy2hxZjghvVlhp
         IsBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oL5sLjSW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y22-20020a05663824d600b00457c45edaecsi1202096jat.5.2023.11.15.12.34.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:31 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKTjqx023176;
	Wed, 15 Nov 2023 20:34:29 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud52r846v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:28 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKTkn4023256;
	Wed, 15 Nov 2023 20:34:28 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud52r846e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:27 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ0V7024857;
	Wed, 15 Nov 2023 20:34:26 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uapn1sj5e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:26 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYOMw40894804
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:24 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 039E820043;
	Wed, 15 Nov 2023 20:34:24 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A8BF620040;
	Wed, 15 Nov 2023 20:34:22 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:22 +0000 (GMT)
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
Subject: [PATCH 09/32] kmsan: Introduce kmsan_memmove_metadata()
Date: Wed, 15 Nov 2023 21:30:41 +0100
Message-ID: <20231115203401.2495875-10-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: _DluWkg_or4n634NGc6XmkFZtcUvSsfY
X-Proofpoint-ORIG-GUID: 4Wi2DjioGwv31onDtsbO8JdqEX7Bd4Hn
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 impostorscore=0
 lowpriorityscore=0 adultscore=0 clxscore=1015 priorityscore=1501
 mlxscore=0 phishscore=0 spamscore=0 mlxlogscore=999 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oL5sLjSW;       spf=pass (google.com:
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

It is useful to manually copy metadata in order to describe the effects
of memmove()-like logic in uninstrumented code or inline asm. Introduce
kmsan_memmove_metadata() for this purpose.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan-checks.h | 14 ++++++++++++++
 mm/kmsan/hooks.c             | 11 +++++++++++
 2 files changed, 25 insertions(+)

diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index c4cae333deec..5218973f0ad0 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -61,6 +61,17 @@ void kmsan_check_memory(const void *address, size_t size);
 void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 			size_t left);
 
+/**
+ * kmsan_memmove_metadata() - Copy kernel memory range metadata.
+ * @dst: start of the destination kernel memory range.
+ * @src: start of the source kernel memory range.
+ * @n:   size of the memory ranges.
+ *
+ * KMSAN will treat the destination range as if its contents were memmove()d
+ * from the source range.
+ */
+void kmsan_memmove_metadata(void *dst, const void *src, size_t n);
+
 #else
 
 static inline void kmsan_poison_memory(const void *address, size_t size,
@@ -77,6 +88,9 @@ static inline void kmsan_copy_to_user(void __user *to, const void *from,
 				      size_t to_copy, size_t left)
 {
 }
+static inline void kmsan_memmove_metadata(void *dst, const void *src, size_t n)
+{
+}
 
 #endif
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index eafc45f937eb..4d477a0a356c 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -286,6 +286,17 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 }
 EXPORT_SYMBOL(kmsan_copy_to_user);
 
+void kmsan_memmove_metadata(void *dst, const void *src, size_t n)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	kmsan_enter_runtime();
+	kmsan_internal_memmove_metadata(dst, (void *)src, n);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_memmove_metadata);
+
 /* Helper function to check an URB. */
 void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-10-iii%40linux.ibm.com.
