Return-Path: <kasan-dev+bncBCT4XGV33UIBB7HD7WZQMGQETWVUETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 16D5D91CAA8
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:31:26 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-25d4f311638sf1359496fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:31:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628285; cv=pass;
        d=google.com; s=arc-20160816;
        b=hY3MjJDYgwRJXPuVJRxNxM6I9w9DzUPCehfj1/+ghiGM6f5Lys6aGgqUkGQJDpDFdf
         LmVzX9bTklU6oOSWqH7MnIFqzMde9oAx70PtznxqdZV45f8TAC9C1wW8kJ5aR3zU2tOK
         utklr5NX6Ymgr4Ug2B3yzS5a1HOaQUstYdIU0ltMBJxEKl9KNh42QNW1XooyrkSR18vB
         Rdw0N9PV1rtWvk6Fl7jtsnOJ17ynhIV/KT3S8wMbSvW/H2dgrzrAusUCoMyjfJEi4PJf
         ddvtHA1mZbCOhoWLbmiD8NrtHz2EhftSTiylM3Pi8qa5+HjxLDzwpd1raDVsGe/W8TQs
         1OHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=yfkBhcF1Ly7TekN0e8E0kLwPfMvlyq2EHSki+4V4K44=;
        fh=QAWK6VOUUINF6Zln9gLlr8KkWV/U/bQUdnxYazzoM5M=;
        b=fSCRnNvK0FKWAusgWbpeCO0w9XaltM5lmdY9xM1CghorSxYsYjK8D5YcnFSEqCR7FP
         raMdK2Hh7WBZQelbOlGliYmeWaRr81OAOeSrz6ReRy4Bmk3X7CqRHGHiUG67BXa5q74M
         VG6juf2qbc7FtDZuPqkavk1+i0GH7PXvGVZhJmR6t44yqLyR7x31/6tdkfRvH95H1yz8
         YRV5jAn4Mhuegi5GjxVKK/MwqI2lhR6RXLFRGMqzHiYL4F48p4I5ehHmzFCYo3zlAdbl
         yis5kEiW3vt9sub1Y7l3k4IZpc++1ughxVbQffYXhVqmXYn3yD34s1QVfxF1RQ9L0B06
         4DKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=x6foJkrz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628285; x=1720233085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yfkBhcF1Ly7TekN0e8E0kLwPfMvlyq2EHSki+4V4K44=;
        b=ppVrloOtEfrSe0dClJ381ekbxjCfcCjq1JlBoLnNjKEjszM+u/u7yfxitIjg3AR9TV
         6pWpiDhMcooWDr/HjWbTw+8xYlIZTMkGoVfKzAsXjIUhKIy4cyYm+wbpR1BYdn5STxlW
         5Yb2H2h8UDxX4Op8TxXkt0dkldvhUIroR2h+H6jTwcgkTXI5/mxZdRljwAMeQH9SsGfI
         mT01K5pujLsk+QA03v80QmteSN+oLtfzYVuqi7aHI3RmHQDJ7uKxC9VoK0So86zdRuEo
         wVFhJTAenLtxYCXkV/GyU5j+8xAtcm/o1MwX9Uluvjei6EwIlcz5WlyfhZT1oNSJ3/OJ
         hpuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628285; x=1720233085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yfkBhcF1Ly7TekN0e8E0kLwPfMvlyq2EHSki+4V4K44=;
        b=Yw6XdHudCvw4rWbA3lTgjtUG0y0uLj2MU+JSB0Y2s+7FzN/O8minEwnPfQeNxaDsBz
         yLvbcnFQbd/qpKaa8sVMa7AeVv8wZxta8aqXsBNfXoN+NHMjdQXMRvcyv8QOR0lvkI4q
         aokXf8dhMuR7Uv7oKQfmh52V0/Sh9SJcbaxdvJYIhYtw96KbhE+Bc/QPP3OTYmWwx7I5
         cpmS+yJBcxWhPG/sPa5W2DJMB+VRSZ21prLjL3Jk3njptZ7LepUrSn2DlV4qD/RFxHvg
         NLCccKEMkiqq5vTNweTbtWmcLtybOs7Ihzsq3vsDg27P5xw5g3KBWwAuRBdFtEAMcseY
         dxLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhDQPnDwoh2aDElsQhB8mDgEDjfTc/b2mVHO+Ef+fyNbt8v+GHr2oYelcT8qYZoAHqC/GsfvXGHPUwAok0Gf4fzALVHgDrPA==
X-Gm-Message-State: AOJu0YxwvzIZfdiaxZTFqIAWIu9dZD/jAi+Itn0dDhDl/irEZlA4T3Hq
	4FvNRxAjV+YQi6117M4ZdKssdaWlM3TzB0hACj4zeS01fln25Y/m
X-Google-Smtp-Source: AGHT+IFG6SlV1xfW5jXnaszhrf7ndXHTEjmTLrr6v07/+N7rOLsBIrmgE2WF6pWrfCrvkPomDJNMLw==
X-Received: by 2002:a05:6870:2050:b0:254:c512:88c6 with SMTP id 586e51a60fabf-25d06e95dafmr18058033fac.51.1719628284847;
        Fri, 28 Jun 2024 19:31:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:63a5:b0:250:719f:50cc with SMTP id
 586e51a60fabf-25d94c7443bls1232344fac.0.-pod-prod-09-us; Fri, 28 Jun 2024
 19:31:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQMbDlD6WYq/dEVikYs/fFHJaC+2JLzZ3409dMj2GG0S9oJd38Uq76q9bK2GnNm1KOorLimb6umLPjgyZPZp+aDCvYaTf6ih+rxA==
X-Received: by 2002:a05:6808:220d:b0:3d5:6569:61ca with SMTP id 5614622812f47-3d56569649dmr10042913b6e.2.1719628283984;
        Fri, 28 Jun 2024 19:31:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628283; cv=none;
        d=google.com; s=arc-20160816;
        b=v32MJDHpUW+Y2l6YGcnYONA6yqEpytOnAuKcLoBhxAmLTT5oH82g7KIpEvaJMaZ7L4
         m2h8a6d7LinQYgbtptEwwfrrDsxsIJwsinqMQUCjN+3mMAAxtLyy6mb7Fhkhbluh3BEj
         J9eCEjHXUw3RGRAuPlK6B/uoTHqm8CMKhedM8f8dyGnY7qb5xt6GPER1hrDcSBQzVWDs
         9E5IA1YmGhvIAM23Ux9qH7RweHMynXRctBq1LGc6aalQtzLKJitP8kwGNO1z2F/bvJl0
         uF2jhdfs5IpukBdvwKBkClWC9hVuJMI2VZNm5c8xcgajDhIVP1Vz59yW9Da0GX5c3I1H
         CGuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=1d3Cxgxza/qfQ7q4Z5PtUb6MGC5V/+cVzqi6MG1zKKk=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=nVlPoN4nE5sC1ipNGGvSlymNCI3b8v81Atro4E3MMIGIgtOe8ZAKNLmJ1qyE6H/crx
         dH5gSj6ben5DpMtbewUn5KRooYVav8ankIEK5dtUSG1nytmc3djhMBBuVq5iIHfWuQVR
         AsjZ1pDhNpFa/catyl7fUMkmZ+OYIUVCwRyS+jDLMzeOTCkDy4ZuuKRK1+UjfGnLGoWK
         DjdhpVWVO9Y1iPeW2ua1FrvSa05dFO9yuLFi+x3ddpXVvID6xmXvelIhjoh/mFK5pKJ4
         /Q91jcW1+2zz7E8liobykTB2r4uAzvrfhf8f3Uj5V9Jzcpm9RzPybErX0S25jm6CZWMA
         zV7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=x6foJkrz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-708044b072csi125740b3a.5.2024.06.28.19.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:31:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id D005BCE4334;
	Sat, 29 Jun 2024 02:31:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0702FC116B1;
	Sat, 29 Jun 2024 02:31:21 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:31:20 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch removed from -mm tree
Message-Id: <20240629023121.0702FC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=x6foJkrz;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: s390/uaccess: add KMSAN support to put_user() and get_user()
has been removed from the -mm tree.  Its filename was
     s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/uaccess: add KMSAN support to put_user() and get_user()
Date: Fri, 21 Jun 2024 13:35:18 +0200

put_user() uses inline assembly with precise constraints, so Clang is in
principle capable of instrumenting it automatically.  Unfortunately, one
of the constraints contains a dereferenced user pointer, and Clang does
not currently distinguish user and kernel pointers.  Therefore KMSAN
attempts to access shadow for user pointers, which is not a right thing to
do.

An obvious fix to add __no_sanitize_memory to __put_user_fn() does not
work, since it's __always_inline.  And __always_inline cannot be removed
due to the __put_user_bad() trick.

A different obvious fix of using the "a" instead of the "+Q" constraint
degrades the code quality, which is very important here, since it's a hot
path.

Instead, repurpose the __put_user_asm() macro to define
__put_user_{char,short,int,long}_noinstr() functions and mark them with
__no_sanitize_memory.  For the non-KMSAN builds make them __always_inline
in order to keep the generated code quality.  Also define
__put_user_{char,short,int,long}() functions, which call the
aforementioned ones and which *are* instrumented, because they call KMSAN
hooks, which may be implemented as macros.

The same applies to get_user() as well.

Link: https://lkml.kernel.org/r/20240621113706.315500-35-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 arch/s390/include/asm/uaccess.h |  111 +++++++++++++++++++++---------
 1 file changed, 79 insertions(+), 32 deletions(-)

--- a/arch/s390/include/asm/uaccess.h~s390-uaccess-add-kmsan-support-to-put_user-and-get_user
+++ a/arch/s390/include/asm/uaccess.h
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
@@ -106,24 +133,24 @@ static __always_inline int __put_user_fn
 
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
@@ -134,13 +161,17 @@ static __always_inline int __put_user_fn
 
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
@@ -163,24 +210,24 @@ static __always_inline int __get_user_fn
 
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
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023121.0702FC116B1%40smtp.kernel.org.
