Return-Path: <kasan-dev+bncBCT4XGV33UIBB3H5ZWZQMGQEHXQ6ARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3136090FAAF
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:59:26 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5bb02b38ea9sf336570eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:59:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845165; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ueg0crQmMaAViO6fcuOqUM/gHZ1/SpI2roGqHOZQY6xqgyb5Ff2aSWcq0BVf6go1Lj
         yUhBpnBD+KeslcsW7taxqibTTWmScyxUQjUpsBsSyFKqFDZfUCw2yZ5W8+6BjDZ+UpF/
         4uJeyo8cGdl+av71oF5yV4TC8PLIe4ae571eZtToP3jrk9B3RJg6oV8IcBpYRxJz/9aX
         7x/ELBBfXcTAlfXpq3L5JFumYJspWB63GDHys1s8Y14/Rjp9uN+M7U1S34L3Uk2h1a0J
         SIaRVoi8lmU2R1RkLsIvML3NYLA2kaaxyLpaJkwgO7pmo2VfcT4C8qWwfVjqjlWx88HG
         uJfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=ZEzTNExsHWWvHtRyQ6IHB3eyQLnE84cTNxBNqpUq35U=;
        fh=Df0kiioGRNcj9GMtZVnxPt5CpvWiXwDHPTXP0wcbuU8=;
        b=vJm52Rl6FjXtiKuG0lXIHHd/EMxmYTB2aQLtxg+fvGe+nevzh67Bm594qtGyeh/Ags
         YN+oMIJS2HBalMzmIy1SEPaS6GNlanAMLSZtEn8cP5iidiBY+RYkhppcSZdLKZYg9TVV
         rjuJTXSZJ/1dtDVY0lWhWTdNYRh9F1jljh5W8auivaEQF4D2AUikcHFjstP1+2uh3rX8
         Ca7fzcv0HEktq6j30ArRPd3CYZL4SbW1lT2yCxultYEpFrQrXyjtlI0svmj5CP+LzUWt
         2uRa+TR+sEF5WgPtK8B5iojwlgAcO0oHU2lwpBsN0GMHur0kW9E2Av17IhEoIxfOy780
         /jVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=eq371Gd+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845165; x=1719449965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZEzTNExsHWWvHtRyQ6IHB3eyQLnE84cTNxBNqpUq35U=;
        b=Rlw7JcjnETUxzDBFsQjHRzwsuFTN5fAIcB2Yx8WJMLxcgdMJgx6+GJmjU37WYoPv+n
         OGcBjl0pM/iASNxeFwwo2PZNEA6XI8/E1kHPFEIlJ+mGje+RrmsNQX6Y6rM1Glo/pw0G
         STjHicmOR1N+WgkrzFpTCvOWlkjcVJ9xxHVGFccmWnrArL079mivoQk7T9LKePBs8CJk
         Gd9f3xvoK/2F0jgFhCKP2gFBuvzguNT59JBns9Jfd7XMnZotNwSkedLAIzUjAZYsyMjF
         4cJBwwopaFoz4N0ynFdzzfCBdK+mmYqIGdID1a2tPpslxIwx+Qfe1x+Kw3ct/O3JiaUW
         dwYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845165; x=1719449965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZEzTNExsHWWvHtRyQ6IHB3eyQLnE84cTNxBNqpUq35U=;
        b=L5HwuAM1gefT4EcbLOLxebLydPIdoAQUYgJNkQWs8/L4EbRlCZVYlLiwBL28PkxcO9
         Pd8S6Vz22JxusFpS7ZYiK2qznjEcaMhpWtAj6kZVYINBC1Jvl31z918UqWrpBo4AACqs
         ZPRgFcrUUWnO21OYhPkr/9YpW4x+xQqwJhBrfDrMJwLTrIwMiyFZD98k5JkViBdej6S0
         K8UIfVMOwDHMExhh/oDjwMvJ6ZiBF8pOXHXDJuf6xOl3Mh+UhhlHng/xKPkYnHVFZkzm
         mBfoztUkwlYkhy03CVpzU+ipFXicgYxLCLAyI76WbZjETZ1zFgc7q26VeYDT9I6YgP+C
         og/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdt29X9xnyKFSJEvqZf5/E95Yr2IB+84djm2wSvAFcUJEPAGbn1+ombWFRNa65SNw5P+euL9oe2myiAEIGrknabj/tZ1EGqw==
X-Gm-Message-State: AOJu0YzVoNecZIsAoQoYX5Oyp2yEc8q4AU7L6nGB14fVssnynm0EX73m
	dyu2iTk/t8Z4Po+/3Nht630IF0MHC5ZZNcZZQpRy/nm9FluIJk+1
X-Google-Smtp-Source: AGHT+IGELp/hIp//ktD2S49DIrzVEwSpolrhsE1bGvZbVo5H6sDy6LI04bbJS32H27r8H3zyK+AEVQ==
X-Received: by 2002:a4a:829a:0:b0:5bd:b862:b216 with SMTP id 006d021491bc7-5c1ad898fe6mr4226791eaf.0.1718845164890;
        Wed, 19 Jun 2024 17:59:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:655e:0:b0:5bf:bc4a:80c9 with SMTP id 006d021491bc7-5c1bff7a317ls324295eaf.2.-pod-prod-08-us;
 Wed, 19 Jun 2024 17:59:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWosRxlJ1Dgf6AdtyaEJ4wv0rTRf55nYrsa7GF1t3wbxQUJMmmCpT5OvQNRrFSmhvKgwFFZabAVicb66aDZ4FlNaS4AOsOVKKQ2Zg==
X-Received: by 2002:a9d:7a82:0:b0:6f9:d351:8762 with SMTP id 46e09a7af769-70076c0bf00mr4606254a34.28.1718845163257;
        Wed, 19 Jun 2024 17:59:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845163; cv=none;
        d=google.com; s=arc-20160816;
        b=Rp2bzadlbX/ElO8V+3ya4ksq2Wlkvj9pF2300dHZl+MkatwVx5GOi1PbTQbcQ3PcrO
         4z4lLC+fCotpfAQlsrhB0k1rIXxs4hezwfu1Yh1+LBKRt6uW1bE1HWceC7GAp4P+/4uT
         aTOgxxhWpw0fBJtN6GBrhellrK80Hl5GR1iHrf5HKPwypoX1rUqh7W6g5PLAjxPxVaQK
         H/aazcHyoLxWzyMk4r5AVjqAkq2gfZ5FJGFbnz8krkCPWpH4mwiLubjcDk/px5KXXoRg
         nNAZ/mMiSUCA5ia+JBwmEjlx+IbAhbqrgl+Qc9ipIYShTkN2hkdO55D1O45uVr1WMY2+
         VM6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=KaZqf+q2JPIhADvYqmC51dFPeZQvU0zY8iU8Nihe/vU=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=darlwDd8z2rkM6U0czYCAo9xv9K+sCaja02C23k1x4lz+qrHjVXHDeRsEtqO99dHf8
         z+MyJRYVlXx46lzMC5jc06CGeVaqnvTrvT1Eo+WZm3BAndXLDhrrkgUUcU8XMi7jZRs8
         OHqw7CKg7Lm6nm0J/13wJDJKzPzA0tJIvHkjZx/Wfpq7LoVLkiEGYqwGIjg9xd87XVOP
         1Z9C19ur1FEkKbr3N53XkSIt54oFcgSDvf9H5JjYhlUOfMdy5dJFUTriu5Gfh5Z/9Wox
         viPch9zpNrCsKfW8DfG/qWaNxpggHC8JNLfbzf8y4D55t9ggM7JGOdKPyA1OwexxYWE0
         MSqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=eq371Gd+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fb5b1b1fd2si607379a34.2.2024.06.19.17.59.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:59:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id F148062064;
	Thu, 20 Jun 2024 00:59:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9659EC2BBFC;
	Thu, 20 Jun 2024 00:59:22 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:59:22 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch added to mm-unstable branch
Message-Id: <20240620005922.9659EC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=eq371Gd+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The patch titled
     Subject: s390/uaccess: add KMSAN support to put_user() and get_user()
has been added to the -mm mm-unstable branch.  Its filename is
     s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: s390/uaccess: add KMSAN support to put_user() and get_user()
Date: Wed, 19 Jun 2024 17:44:08 +0200

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

Link: https://lkml.kernel.org/r/20240619154530.163232-34-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>
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

ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch
kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch
kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch
kmsan-increase-the-maximum-store-size-to-4096.patch
kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch
kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch
kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch
kmsan-remove-an-x86-specific-include-from-kmsanh.patch
kmsan-expose-kmsan_get_metadata.patch
kmsan-export-panic_on_kmsan.patch
kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch
kmsan-introduce-memset_no_sanitize_memory.patch
kmsan-support-slab_poison.patch
kmsan-use-align_down-in-kmsan_get_metadata.patch
kmsan-do-not-round-up-pg_data_t-size.patch
mm-slub-let-kmsan-access-metadata.patch
mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch
mm-kfence-disable-kmsan-when-checking-the-canary.patch
lib-zlib-unpoison-dfltcc-output-buffers.patch
kmsan-accept-ranges-starting-with-0-on-s390.patch
s390-boot-turn-off-kmsan.patch
s390-use-a-larger-stack-for-kmsan.patch
s390-boot-add-the-kmsan-runtime-stub.patch
s390-checksum-add-a-kmsan-check.patch
s390-cpacf-unpoison-the-results-of-cpacf_trng.patch
s390-cpumf-unpoison-stcctm-output-buffer.patch
s390-diag-unpoison-diag224-output-buffer.patch
s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch
s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch
s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch
s390-string-add-kmsan-support.patch
s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch
s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch
s390-uaccess-add-the-missing-linux-instrumentedh-include.patch
s390-unwind-disable-kmsan-checks.patch
s390-kmsan-implement-the-architecture-specific-functions.patch
kmsan-enable-on-s390.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005922.9659EC2BBFC%40smtp.kernel.org.
