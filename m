Return-Path: <kasan-dev+bncBCM3H26GVIOBBYUR2OZQMGQEWP4HH5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BB4C91176B
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:16 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5c1a6660f3csf1624827eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929635; cv=pass;
        d=google.com; s=arc-20160816;
        b=K2M6IE1zDi0+cUAHxX7+658aSOwG0xRA147kYe0UpcVCVK5jvJMIJoWFj7JfS7IJBX
         DGWqZUq6bqVFLo08ZXqLKYfOX6hqtZyoD+GnVXyML1EHIsvW4mIu5Mx0TO16lMQt1Oya
         Fb+8w+9W8FiCc5ppkixhN297MJaZ4vzUuHciCwv6nu4skwtHaHz0RGpB+awi9B2nB4RN
         XnRNLmyX480F9ljS6KrxwKCXyuiWzh1tjw0cWLp6tjgyILMEExZi50KaEIEgPPNp4idr
         KriCzKwKt4FwBq0sR3KZsP/dVhgvTeHxlpfCs+60iOf5A+wcPZqJELuSgczKAzbnR5PI
         IZHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MeXxJuWcOHe5ZYo26Ce9134pq3ljcSkG4o4mewxJkFg=;
        fh=5hJTf0S1+FJv6pwSe+n1zZurNWs4BECFPnID8h0oZ6w=;
        b=En8Ql3g4JkZShZOLAJ/cn5kqUR32iesvRW9OyiAnwJxRzfE97tffPTeFyKyfi+F6NL
         RIFbLzJeiL1tBryNhjoZZVRaV8adpQyynmzO+g112U9DQ7EVzsKQ20i4vg4Vv20m6C8/
         m4oce6D+LCwV5LweXalsBm49E5xQzeuTiMYoi+4LG/luPQXR2vPTkDsnZ5rl+GZ+mmH9
         3Fkn5DVN/IgE39kRsZ2HSiUOR6jpS2KCGkUhZKrD6/6INuf87PzKF9s6NGzZYPYtgppP
         yQYjMUIx7IpNA/fk9ghAeGeEnX8ZtHEvrxPf3HnX+zcf3LzQrngzEl9FqXj4N6yidmDR
         K68Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UgclM8iX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929635; x=1719534435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MeXxJuWcOHe5ZYo26Ce9134pq3ljcSkG4o4mewxJkFg=;
        b=xR+3yo+TlhmuLjsPLO+p3kkBwdA/QFT0UMMV29dxmcZzVWYuBL4YeocZrKOQpev2Rt
         C1/bUmi40U6k64O9PCl6Z0KK333iXVBZ0IXOWTwT0glXt+VRfxVs6xgCVVrrmRhh+JP3
         LPDPUa5nVVEwSbcXz39HGD7xIj6YWhbc++t8PRJWH+RaiW7QY2kRjXcD4eLS2YeWt1Hn
         5frbeS4DYp2mmZRmmdFU7FO9C74eINOpMzUbnzX/Iv2QcnuPYLDbMdKqBnlyYXxGuzrU
         /h16AvJViQobCmJP/t8EukttUwHIQpti8nZeEGfwz5pSzUcbZrIQPL5dFyMWmGyXL/Fz
         rQRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929635; x=1719534435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MeXxJuWcOHe5ZYo26Ce9134pq3ljcSkG4o4mewxJkFg=;
        b=T1tNanOsF4z+fyOykhBxLUTVPGUKpWlxZko/dIo8EW8X21FBxM5HZb1mv4GIIq2pu9
         H8B5qAF7a5uOyr1m71sCw5t/ZjyJZTuDsNz3BKeUiRgc22+beBVyZ6ZqeAlgK9Wzw6VW
         BCEvPcFNjWRgLqwuKqR3cWxMpvoDH7Cu37cI3G5vzC07+UbL3+AIFSU6RVCQ76F3X0DT
         KsYInrMZWz7YyxF0ULrXlma6U4jmtuKQkxDeyAfpFhFOHGiBFe7XINoUtGG6gmGDxD8B
         8ThL8tjvmcZRjJ+4GoIYhAMJgeT6qcmHzoAitIzJIo5Xk4RqSAUr50LlMc3kp57fzIEQ
         NCog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGinCAastB5XvrnBDX+Bo7zMv/xRLUrRp5bQ4En+sFR1dUkZ3TEY7AehQ6X6YKGgf8q00diZFvsGQkw7mRR/2MttgQEPG0dA==
X-Gm-Message-State: AOJu0YxM5s8LVWmqMvYel/mulJRDachMs4YU5Tzan7O5Vo2kkQVULCFw
	IHDfTVWSy59SELEOmCmPDxoC83RB8lhOLxMbE0dWgq5XQjUfvH7X
X-Google-Smtp-Source: AGHT+IGuonsf/9kZiW5R9i2F2kalLvi7rQEax/LEsVR5qFDPFVIb/GM+IRok5rd/BUCAIkGqJAHWaQ==
X-Received: by 2002:a4a:3816:0:b0:5ba:ea6f:acb8 with SMTP id 006d021491bc7-5c1adb10d0dmr7036452eaf.3.1718929635011;
        Thu, 20 Jun 2024 17:27:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9284:0:b0:5bd:b810:1c82 with SMTP id 006d021491bc7-5c1bfce58cels1330253eaf.0.-pod-prod-05-us;
 Thu, 20 Jun 2024 17:27:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2Ef/4opxqNUPBF/F5OdO1rtgicOKMkHWAHjJe7hzRjm4q6Rj6vq+b74dW0ZNDE1zmXikEPkbmSWt6tHVd09tDgtx5stmWQU4q3Q==
X-Received: by 2002:a9d:7f98:0:b0:6f9:aa83:bb21 with SMTP id 46e09a7af769-70073a3a507mr6901851a34.12.1718929634330;
        Thu, 20 Jun 2024 17:27:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929634; cv=none;
        d=google.com; s=arc-20160816;
        b=f7F3aQRmCNjmU3fT/TtpnB/KIEdAUq+UoFjuMeoN8OjLHlQFZyXvgbLWS9kDAbLqi4
         l+adByvM8rl7FBt9f50N8NRI7P2l3moIqELi/B+a9ZKkzOUsSWwrZWVxT6mp/9uKYZNg
         wb1RjXoUXn+SptauwTEcI8g0zzTLKK0YA3Rh626Kioi7KeExotbbSR1iYGUMJiTbaDI+
         /w+xrEDxj74gf3fr70DqrQ4V2yhfKojV7vA1aUkIVPVulEho9qTr6GSt+VklOFgzWuhx
         /vuqMOvvo3HEwwYXZtsm0TnWwvgChgWdIOkmNASdnlTsl0NMHBSy9hQhw4IREZ9TcqiP
         3Ysg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8e8PMGe0cxjRcokQIWDPjb5O7pNlgWjHP8CNiuKdZuQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=TkM/TB+T/+PjfwfOIvc8zN/b2vsuhh0urEbeJ45kdUe5UiFL23X6ypjNo9ueQJJMFI
         O3lpW7sWhiNST8eRdANjKPcN9dwwBNsJsvkxvs9M0ex78lQ0syd9IvDPPmKoEQnSewHw
         UlSMgNjzfXdyhk+7W3q8nz9UDowiWQp+JEeGjlF1NQynJDqGhx6j10FcaD943CaAa410
         a4JXVTa45UCgfzrSO1MeECJDkmhMHVJhb4dnLZ3Pjrcl6gbE9pPsiShJ0zH3XwJpKCkM
         +JbD/m5sprxsnMuxODQ6cMkjLFXF/JoXEbYl4YbCCH5gva89z/JdNO/mzf8CbS0xYEYb
         G1qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UgclM8iX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7009c7d198esi21331a34.4.2024.06.20.17.27.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNQaxB017305;
	Fri, 21 Jun 2024 00:27:10 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8bm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:10 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QaaH009416;
	Fri, 21 Jun 2024 00:27:09 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8bh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:09 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0M9iD032319;
	Fri, 21 Jun 2024 00:27:08 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspjn2d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:08 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0R2rS51315140
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:05 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CB2E920040;
	Fri, 21 Jun 2024 00:27:02 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A98D72004D;
	Fri, 21 Jun 2024 00:27:01 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:27:01 +0000 (GMT)
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
Subject: [PATCH v6 35/39] s390/uaccess: Add KMSAN support to put_user() and get_user()
Date: Fri, 21 Jun 2024 02:25:09 +0200
Message-ID: <20240621002616.40684-36-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: FolO_Spe9qM8HL2SnsxPmKJ31SyutMLt
X-Proofpoint-ORIG-GUID: gbHapUn9HCk1zHYd1R8KfEwHyqD-7XQw
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 mlxlogscore=999 spamscore=0 adultscore=0 phishscore=0 mlxscore=0
 lowpriorityscore=0 malwarescore=0 priorityscore=1501 bulkscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UgclM8iX;       spf=pass (google.com:
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

put_user() uses inline assembly with precise constraints, so Clang is
in principle capable of instrumenting it automatically. Unfortunately,
one of the constraints contains a dereferenced user pointer, and Clang
does not currently distinguish user and kernel pointers. Therefore
KMSAN attempts to access shadow for user pointers, which is not a right
thing to do.

An obvious fix to add __no_sanitize_memory to __put_user_fn() does not
work, since it's __always_inline. And __always_inline cannot be removed
due to the __put_user_bad() trick.

A different obvious fix of using the "a" instead of the "+Q" constraint
degrades the code quality, which is very important here, since it's a
hot path.

Instead, repurpose the __put_user_asm() macro to define
__put_user_{char,short,int,long}_noinstr() functions and mark them with
__no_sanitize_memory. For the non-KMSAN builds make them
__always_inline in order to keep the generated code quality. Also
define __put_user_{char,short,int,long}() functions, which call the
aforementioned ones and which *are* instrumented, because they call
KMSAN hooks, which may be implemented as macros.

The same applies to get_user() as well.

Acked-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/uaccess.h | 111 +++++++++++++++++++++++---------
 1 file changed, 79 insertions(+), 32 deletions(-)

diff --git a/arch/s390/include/asm/uaccess.h b/arch/s390/include/asm/uaccess.h
index 81ae8a98e7ec..70f0edc00c2a 100644
--- a/arch/s390/include/asm/uaccess.h
+++ b/arch/s390/include/asm/uaccess.h
@@ -78,13 +78,24 @@ union oac {
 
 int __noreturn __put_user_bad(void);
 
-#define __put_user_asm(to, from, size)					\
-({									\
+#ifdef CONFIG_KMSAN
+#define get_put_user_noinstr_attributes \
+	noinline __maybe_unused __no_sanitize_memory
+#else
+#define get_put_user_noinstr_attributes __always_inline
+#endif
+
+#define DEFINE_PUT_USER(type)						\
+static get_put_user_noinstr_attributes int				\
+__put_user_##type##_noinstr(unsigned type __user *to,			\
+			    unsigned type *from,			\
+			    unsigned long size)				\
+{									\
 	union oac __oac_spec = {					\
 		.oac1.as = PSW_BITS_AS_SECONDARY,			\
 		.oac1.a = 1,						\
 	};								\
-	int __rc;							\
+	int rc;								\
 									\
 	asm volatile(							\
 		"	lr	0,%[spec]\n"				\
@@ -93,12 +104,28 @@ int __noreturn __put_user_bad(void);
 		"2:\n"							\
 		EX_TABLE_UA_STORE(0b, 2b, %[rc])			\
 		EX_TABLE_UA_STORE(1b, 2b, %[rc])			\
-		: [rc] "=&d" (__rc), [_to] "+Q" (*(to))			\
+		: [rc] "=&d" (rc), [_to] "+Q" (*(to))			\
 		: [_size] "d" (size), [_from] "Q" (*(from)),		\
 		  [spec] "d" (__oac_spec.val)				\
 		: "cc", "0");						\
-	__rc;								\
-})
+	return rc;							\
+}									\
+									\
+static __always_inline int						\
+__put_user_##type(unsigned type __user *to, unsigned type *from,	\
+		  unsigned long size)					\
+{									\
+	int rc;								\
+									\
+	rc = __put_user_##type##_noinstr(to, from, size);		\
+	instrument_put_user(*from, to, size);				\
+	return rc;							\
+}
+
+DEFINE_PUT_USER(char);
+DEFINE_PUT_USER(short);
+DEFINE_PUT_USER(int);
+DEFINE_PUT_USER(long);
 
 static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned long size)
 {
@@ -106,24 +133,24 @@ static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned lon
 
 	switch (size) {
 	case 1:
-		rc = __put_user_asm((unsigned char __user *)ptr,
-				    (unsigned char *)x,
-				    size);
+		rc = __put_user_char((unsigned char __user *)ptr,
+				     (unsigned char *)x,
+				     size);
 		break;
 	case 2:
-		rc = __put_user_asm((unsigned short __user *)ptr,
-				    (unsigned short *)x,
-				    size);
+		rc = __put_user_short((unsigned short __user *)ptr,
+				      (unsigned short *)x,
+				      size);
 		break;
 	case 4:
-		rc = __put_user_asm((unsigned int __user *)ptr,
+		rc = __put_user_int((unsigned int __user *)ptr,
 				    (unsigned int *)x,
 				    size);
 		break;
 	case 8:
-		rc = __put_user_asm((unsigned long __user *)ptr,
-				    (unsigned long *)x,
-				    size);
+		rc = __put_user_long((unsigned long __user *)ptr,
+				     (unsigned long *)x,
+				     size);
 		break;
 	default:
 		__put_user_bad();
@@ -134,13 +161,17 @@ static __always_inline int __put_user_fn(void *x, void __user *ptr, unsigned lon
 
 int __noreturn __get_user_bad(void);
 
-#define __get_user_asm(to, from, size)					\
-({									\
+#define DEFINE_GET_USER(type)						\
+static get_put_user_noinstr_attributes int				\
+__get_user_##type##_noinstr(unsigned type *to,				\
+			    unsigned type __user *from,			\
+			    unsigned long size)				\
+{									\
 	union oac __oac_spec = {					\
 		.oac2.as = PSW_BITS_AS_SECONDARY,			\
 		.oac2.a = 1,						\
 	};								\
-	int __rc;							\
+	int rc;								\
 									\
 	asm volatile(							\
 		"	lr	0,%[spec]\n"				\
@@ -149,13 +180,29 @@ int __noreturn __get_user_bad(void);
 		"2:\n"							\
 		EX_TABLE_UA_LOAD_MEM(0b, 2b, %[rc], %[_to], %[_ksize])	\
 		EX_TABLE_UA_LOAD_MEM(1b, 2b, %[rc], %[_to], %[_ksize])	\
-		: [rc] "=&d" (__rc), "=Q" (*(to))			\
+		: [rc] "=&d" (rc), "=Q" (*(to))				\
 		: [_size] "d" (size), [_from] "Q" (*(from)),		\
 		  [spec] "d" (__oac_spec.val), [_to] "a" (to),		\
 		  [_ksize] "K" (size)					\
 		: "cc", "0");						\
-	__rc;								\
-})
+	return rc;							\
+}									\
+									\
+static __always_inline int						\
+__get_user_##type(unsigned type *to, unsigned type __user *from,	\
+		  unsigned long size)					\
+{									\
+	int rc;								\
+									\
+	rc = __get_user_##type##_noinstr(to, from, size);		\
+	instrument_get_user(*to);					\
+	return rc;							\
+}
+
+DEFINE_GET_USER(char);
+DEFINE_GET_USER(short);
+DEFINE_GET_USER(int);
+DEFINE_GET_USER(long);
 
 static __always_inline int __get_user_fn(void *x, const void __user *ptr, unsigned long size)
 {
@@ -163,24 +210,24 @@ static __always_inline int __get_user_fn(void *x, const void __user *ptr, unsign
 
 	switch (size) {
 	case 1:
-		rc = __get_user_asm((unsigned char *)x,
-				    (unsigned char __user *)ptr,
-				    size);
+		rc = __get_user_char((unsigned char *)x,
+				     (unsigned char __user *)ptr,
+				     size);
 		break;
 	case 2:
-		rc = __get_user_asm((unsigned short *)x,
-				    (unsigned short __user *)ptr,
-				    size);
+		rc = __get_user_short((unsigned short *)x,
+				      (unsigned short __user *)ptr,
+				      size);
 		break;
 	case 4:
-		rc = __get_user_asm((unsigned int *)x,
+		rc = __get_user_int((unsigned int *)x,
 				    (unsigned int __user *)ptr,
 				    size);
 		break;
 	case 8:
-		rc = __get_user_asm((unsigned long *)x,
-				    (unsigned long __user *)ptr,
-				    size);
+		rc = __get_user_long((unsigned long *)x,
+				     (unsigned long __user *)ptr,
+				     size);
 		break;
 	default:
 		__get_user_bad();
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-36-iii%40linux.ibm.com.
