Return-Path: <kasan-dev+bncBAABBYPIVLBQMGQEGHNVUOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 97006AFA6E2
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jul 2025 19:37:39 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7d40d2308a4sf323505885a.0
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 10:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751823458; cv=pass;
        d=google.com; s=arc-20240605;
        b=G4+cvOo1NYdl4p9SdsTuXoh0xhyIIdRmRUrCdZmloHa7FNZs/zMHS7ukmTMWBFWgRA
         MjCXKmSf6KV3KKeM/4f9/8J+yI1jiomDE5Ln66LEL6yIzVq1LhRR5x+bVwRFJ2iwcRvD
         GX1J92FJQuiYBhnh/bd3En7opQhxgXYxbqq0WY5x+mM7d2guwKJWQim2/E2ycfeBQNlJ
         MtZY7rc2UkWA8l+NRh6FSp170f0tevFPzku3Wv1OSwQ3SLLRNBfi3fD8fdbXMowGRYV9
         0BCCcazsUVKeF+3ZKRucyZTmXE7cQBdfe82xTzVGKjZ7ZnRHfg7XR+4qNkXNtf9HWK7v
         52Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Pi/y/Pflct0fNavnrEMnyJynhUEzqNXuZ+hqN4/tvY4=;
        fh=b49Li4YVnSWNI9gBTrgsXNcSYo5PEKqnEnAQOrcW7tA=;
        b=drqacphldxCmGB1s7K0YLRU7PXabQRhWE7wIbzEP5KiuOZk5rbwWl9XC3evZBCrPts
         uC4ux5Nd5sxonFXEjX1GoVYVXfj8RnLfhoiVDFbGN2dmWrA+41hj1TDy8SMPl7V/43u6
         3P9Lzr2AgxqhpVA85zY8jsu0/sdfa7L5cdx95JmT91hbppfYooKsxWI1zXEMFgXlnnGS
         CWDBtgmz/iET14two3vPgg7qqI8L6K+gGXWdt84O5UZt+elWfbr9Z+y+1FxTBv9aDAKQ
         MDAKtdhmCW7XBGUVu4kvJXlNNmWPdyMMgNGfPyyth8CsQAlZz3jgLkZlgTFp5B6yvoMy
         KQdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lJgCPADR;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751823458; x=1752428258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Pi/y/Pflct0fNavnrEMnyJynhUEzqNXuZ+hqN4/tvY4=;
        b=YBdbpovcCPOPQQePnkkghau1txfKgD3ZFvVj7wtFLpP/yMjapV0ch7jPTi/9bN1lmX
         37wUjacANUuhtYKSOYBIVgTdzuJliwuAEa39E5VCIL2cuHvQNC2exeadGug2S03r2m/4
         fD/c5VY4JT15KnmkLfYyeszQrzVA4I1Gu3+CnusajPQ4XctjflUqwpo5TEFhYU1ia4jB
         57jVRI/RlpV+SnPse5Wt5E8YBIRzCdfN9ZS4Mv8YxSwoRSSnw1MpdruZH3JrEkhrKXUS
         4VOxvn3UL4xYi/vY/z8K5eiQrBqRQgcpUh1jsTC4Bijb+vSmQ0uznxFt8/CHWmpQD2f+
         tiNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751823458; x=1752428258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pi/y/Pflct0fNavnrEMnyJynhUEzqNXuZ+hqN4/tvY4=;
        b=S1ZPvXQ9jp0BG2taA3wmExxXA3JFKZM7Q4J0b13CZ686huwIOLgRlMHHYB3ee6CHVY
         fx8Nmfv/Ae1HgkNMAqox+VVk2GQoOcfUO4XaXpbrQwVM0oY9X4pIWpQNjOmzVS0JxKwo
         2TyMrIfuyp1tosKZCOR1ngDuWkRV818j16rFAX8O86Q/h77t42h6vnOMdyZLm7M2Z9Fi
         gnIpw290jJWRL/amlTbpTQ+2Hzw1O0yHDMVzy2dGqu4+7eOmKv8e7rrOngAvSsFuyG7D
         L1XntUkDY5+tv16MobIBZAzKdN75JHtALYyFLipOjubXNkPtOusdpIKD3A4202qMXgdw
         ibgQ==
X-Forwarded-Encrypted: i=2; AJvYcCWKmdGBBvOwboyTyIJAsC0UW6ipBJjlf7t/A17cxKHroVtGes7u63RLJL7iZFKTbQGfJuo0mg==@lfdr.de
X-Gm-Message-State: AOJu0YwzvxVw6BsJSqePxxr2yETYM1/yrRNQLRxsWo5eW6nHAZolag/p
	F9a5ALUGNmkr0nIRQCVfuX3B3JIz3/h9C7e418XCaF00yW7/BifZzVmM
X-Google-Smtp-Source: AGHT+IE6pwxUWFSrrjb44dYOyrSWkWKcecJDz2S+zTEmpgofG+lu3djHASR60Y376QVqU1drc1kJ+Q==
X-Received: by 2002:a05:620a:a90c:b0:7d7:32ac:3381 with SMTP id af79cd13be357-7d732ac3392mr426616285a.1.1751823458143;
        Sun, 06 Jul 2025 10:37:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdXm/IjNjW3SpfNyZ64igESdwo4niMfEY7EO5HhPtcR/w==
Received: by 2002:a05:622a:580e:b0:4a9:9584:1444 with SMTP id
 d75a77b69052e-4a99be707b3ls34076671cf.2.-pod-prod-03-us; Sun, 06 Jul 2025
 10:37:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVr6pzMaHPN2T2+25swUFJctkj0DjbtVSRwMyMGjp8L8ydiABfFwNuttZppMUDnYcMIRiS+6dGDFWs=@googlegroups.com
X-Received: by 2002:a05:620a:3713:b0:7d5:c51f:ab22 with SMTP id af79cd13be357-7d5f16ed050mr965012485a.49.1751823457061;
        Sun, 06 Jul 2025 10:37:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751823457; cv=none;
        d=google.com; s=arc-20240605;
        b=GxtN4lSBhxueTyPO8vIqbFBrpn5RXGHYfxxcQK2mjavpgxe35pVQUEqtZYmJD7sblb
         7uPrxfavLd/qgHIFQ3n1bBZsOAWPqEPRplPDW50cLRiarUimp7RORzGOY+hPYi/KD7/s
         CUFU08cHu70EhXzOVJxKS1TfT/6s9p+f+pFNUdf9kHqQ0+mxA+i8hfZfr6Y1ti4r3bgg
         3i002e6G1LlRlPzbsLCNkeCsKuDA8R1qVSXswTnCpxKehuvgvAPPKDItaLUWQuaOxp5I
         QAkms82hdx3snK3sEOWB7N0QKMYlRhZDwXIwLzL4IFnJlNR2+k8Loc33+m3MGR/PRwke
         ybuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+ox21bF4kIjDKl8k0gbtV2JTxZR2UJ8wCg/9TILGXwg=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=OcCuAFGjAfYFu9Zt/mj2kISrdKAyottTPycuO6QA23m2D5Evte4MXPjy9Z1u0gTUtQ
         lHIIl7AzHGpVI0mxXiwHZVKP0O5X90VoT0JVZ/8GvdpUpdiVK9T6QaTI4lsUu1ot/9zK
         hSF/KBTMwsALo/urll3X6B5epOnSfjUzZag2g/+5VKQUsQ6Nv1JuRH8g6YEqrC8/Jv1K
         Y6KgaCtUQIRyZ9rwM8QMadgJ0KSRpP+jfJB/BmXJG79TIYXGCdz1PQVIwYBthDS2Ig0O
         biWs8xMoOlzwYhMlL86rbqcFxfZlKX+qo8eon/GWgarHFTOSLrWt3y6lIPfARzP5C8jG
         p6AA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lJgCPADR;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7d5dbe769c1si28669785a.6.2025.07.06.10.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 10:37:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7BCB95C5716;
	Sun,  6 Jul 2025 17:37:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D591BC4CEEE;
	Sun,  6 Jul 2025 17:37:34 +0000 (UTC)
Date: Sun, 6 Jul 2025 19:37:33 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v2 1/5] vsprintf: Add [v]seprintf(), [v]stprintf()
Message-ID: <64334f0b94d6b853e6104ec4f89bcf910978db76.1751823326.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lJgCPADR;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

seprintf()
==========

seprintf() is a function similar to stpcpy(3) in the sense that it
returns a pointer that is suitable for chaining to other copy
operations.

It takes a pointer to the end of the buffer as a sentinel for when to
truncate, which unlike a size, doesn't need to be updated after every
call.  This makes it much more ergonomic, avoiding manually calculating
the size after each copy, which is error prone.

It also makes error handling much easier, by reporting truncation with
a null pointer, which is accepted and transparently passed down by
subsequent seprintf() calls.  This results in only needing to report
errors once after a chain of seprintf() calls, unlike snprintf(3), which
requires checking after every call.

	p = buf;
	e = buf + countof(buf);
	p = seprintf(p, e, foo);
	p = seprintf(p, e, bar);
	if (p == NULL)
		goto trunc;

vs

	len = 0;
	size = countof(buf);
	len += snprintf(buf + len, size - len, foo);
	if (len >= size)
		goto trunc;

	len += snprintf(buf + len, size - len, bar);
	if (len >= size)
		goto trunc;

And also better than scnprintf() calls:

	len = 0;
	size = countof(buf);
	len += scnprintf(buf + len, size - len, foo);
	len += scnprintf(buf + len, size - len, bar);
	if (len >= size)
		goto trunc;

It seems aparent that it's a more elegant approach to string catenation.

stprintf()
==========

stprintf() is a helper that is needed for implementing seprintf()
--although it could be open-coded within vseprintf(), of course--, but
it's also useful by itself.  It has the same interface properties as
strscpy(): that is, it copies with truncation, and reports truncation
with -E2BIG.  It would be useful to replace some calls to snprintf(3)
and scnprintf() which don't need chaining, and where it's simpler to
pass a size.

It is better than plain snprintf(3), because it results in simpler error
detection (it doesn't need a check >=countof(buf), but rather <0).

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/sprintf.h |   4 ++
 lib/vsprintf.c          | 109 ++++++++++++++++++++++++++++++++++++++++
 2 files changed, 113 insertions(+)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index 51cab2def9ec..c3dbfd2efd2b 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -11,8 +11,12 @@ __printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
 __printf(2, 0) int vsprintf(char *buf, const char *, va_list);
 __printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
+__printf(3, 4) int stprintf(char *buf, size_t size, const char *fmt, ...);
+__printf(3, 0) int vstprintf(char *buf, size_t size, const char *fmt, va_list args);
 __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
+__printf(3, 4) char *seprintf(char *p, const char end[0], const char *fmt, ...);
+__printf(3, 0) char *vseprintf(char *p, const char end[0], const char *fmt, va_list args);
 __printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
 __printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
 __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 01699852f30c..a3efacadb5e5 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -2892,6 +2892,37 @@ int vsnprintf(char *buf, size_t size, const char *fmt_str, va_list args)
 }
 EXPORT_SYMBOL(vsnprintf);
 
+/**
+ * vstprintf - Format a string and place it in a buffer
+ * @buf: The buffer to place the result into
+ * @size: The size of the buffer, including the trailing null space
+ * @fmt: The format string to use
+ * @args: Arguments for the format string
+ *
+ * The return value is the length of the new string.
+ * If the string is truncated, the function returns -E2BIG.
+ *
+ * If you're not already dealing with a va_list consider using stprintf().
+ *
+ * See the vsnprintf() documentation for format string extensions over C99.
+ */
+int vstprintf(char *buf, size_t size, const char *fmt, va_list args)
+{
+	int len;
+
+	len = vsnprintf(buf, size, fmt, args);
+
+	// It seems the kernel's vsnprintf() doesn't fail?
+	//if (unlikely(len < 0))
+	//	return -E2BIG;
+
+	if (unlikely(len >= size))
+		return -E2BIG;
+
+	return len;
+}
+EXPORT_SYMBOL(vstprintf);
+
 /**
  * vscnprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
@@ -2923,6 +2954,36 @@ int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
 }
 EXPORT_SYMBOL(vscnprintf);
 
+/**
+ * vseprintf - Format a string and place it in a buffer
+ * @p: The buffer to place the result into
+ * @end: A pointer to one past the last character in the buffer
+ * @fmt: The format string to use
+ * @args: Arguments for the format string
+ *
+ * The return value is a pointer to the trailing '\0'.
+ * If @p is NULL, the function returns NULL.
+ * If the string is truncated, the function returns NULL.
+ *
+ * If you're not already dealing with a va_list consider using seprintf().
+ *
+ * See the vsnprintf() documentation for format string extensions over C99.
+ */
+char *vseprintf(char *p, const char end[0], const char *fmt, va_list args)
+{
+	int len;
+
+	if (unlikely(p == NULL))
+		return NULL;
+
+	len = vstprintf(p, end - p, fmt, args);
+	if (unlikely(len < 0))
+		return NULL;
+
+	return p + len;
+}
+EXPORT_SYMBOL(vseprintf);
+
 /**
  * snprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
@@ -2950,6 +3011,30 @@ int snprintf(char *buf, size_t size, const char *fmt, ...)
 }
 EXPORT_SYMBOL(snprintf);
 
+/**
+ * stprintf - Format a string and place it in a buffer
+ * @buf: The buffer to place the result into
+ * @size: The size of the buffer, including the trailing null space
+ * @fmt: The format string to use
+ * @...: Arguments for the format string
+ *
+ * The return value is the length of the new string.
+ * If the string is truncated, the function returns -E2BIG.
+ */
+
+int stprintf(char *buf, size_t size, const char *fmt, ...)
+{
+	va_list args;
+	int len;
+
+	va_start(args, fmt);
+	len = vstprintf(buf, size, fmt, args);
+	va_end(args);
+
+	return len;
+}
+EXPORT_SYMBOL(stprintf);
+
 /**
  * scnprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
@@ -2974,6 +3059,30 @@ int scnprintf(char *buf, size_t size, const char *fmt, ...)
 }
 EXPORT_SYMBOL(scnprintf);
 
+/**
+ * seprintf - Format a string and place it in a buffer
+ * @p: The buffer to place the result into
+ * @end: A pointer to one past the last character in the buffer
+ * @fmt: The format string to use
+ * @...: Arguments for the format string
+ *
+ * The return value is a pointer to the trailing '\0'.
+ * If @buf is NULL, the function returns NULL.
+ * If the string is truncated, the function returns NULL.
+ */
+
+char *seprintf(char *p, const char end[0], const char *fmt, ...)
+{
+	va_list args;
+
+	va_start(args, fmt);
+	p = vseprintf(p, end, fmt, args);
+	va_end(args);
+
+	return p;
+}
+EXPORT_SYMBOL(seprintf);
+
 /**
  * vsprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/64334f0b94d6b853e6104ec4f89bcf910978db76.1751823326.git.alx%40kernel.org.
