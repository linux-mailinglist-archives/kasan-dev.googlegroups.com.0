Return-Path: <kasan-dev+bncBAABBQ5LVXBQMGQEAZPCWMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C7F85AFAAB2
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:12 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3df33d97436sf32982245ab.1
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864771; cv=pass;
        d=google.com; s=arc-20240605;
        b=X2ja0EDi5TCcF3Yt8OLYubcqjyWB9oUY5It0WZaKff36zY40U9qeagIgWojk2ykekf
         LPCFkwJzKoAu9tXSDTb+Tn2xUx1P2RMcjyej0MrwKwpGnmmuxJPg4iBdR+/7l//2XkIz
         sPob7OdSQ4+evO13WgA9dbxg7x5O+7IrygLffCH0mVYK83kgyH/tGYaPITjfJ6lmAQVo
         KGOLW1spm5i5T2+5gnMy+KdZ//KAFNVmu9oirR0Kmh/m1jMqgcd8gpaGFKrI0mKONBR9
         0WMKLw0TYqTr1LcoruUbpWB13n3PkG0OnDM3wTPEhnOmXH3k3F22o4aXPMBj1C/RG+Op
         Seyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=g/R343XRU7uP2JhNpqPuqHa7ET2xf+fA+xGC1UhyVSo=;
        fh=spMRVfiLRhTyjo9bqfTnr1IwqeYzYf/dgjz7zJsIXZA=;
        b=i2k7uMDZkhuRvc5y4I56btodePsAa3PUbpp9sYgdRWt4iq5yKB/slLEorqBNF8dkc0
         d6BT91L3H6CkX7mWTRy+zxD0v9H1h1TEJBBIDna2JEzNnXdDDyUjVXqsU6ARPEpvfhPj
         cBQzPE5TMHU0Is6/HzmF+zNu2GUVB98riZzobKhQP5n3RlkG+60/vjZQhpydnnos5KFH
         LkvrCX+r9pmzN4cGJ5nX6M9qppLXTbJ0KHCW8fxTYLfeT+CNQnG9Q3IT7ygv0yU1LnLn
         Ys64HGz7QzYY7cKU/yYlFo0OwwYDIJrhDdrJ5YLZR5+mZXgrDHqHOCGdn2mBYFKlh9z+
         KkUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l4eRU6Zt;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864771; x=1752469571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=g/R343XRU7uP2JhNpqPuqHa7ET2xf+fA+xGC1UhyVSo=;
        b=tcempkZt+qWsK/tue+yC8KggkzFGaBzS7BnGImTJvBiPCczLDLkSH0JEAJfsYrBIzm
         R/4qFqEFZlbakLOxcLBp0O4bfo0ffsCp63Ddz7JIWtCiOCyoAnvF6Q9Xsw1P//F3X+15
         iUcffP1X/MqMGAfpB3uxwunVcgRJOExvEqYlUTJDGDOjQPLGXCxNx55CNfcW1KRzjW2h
         fFW8ha4hKICnBPRRbLBFWDFJKxThYNqDBMWJHShTpnUysoo0P0zjHgdncNJjOaJwVfAA
         PIbllYoz8wzUG4Il7Zf/DxnmHmm5ZUqQRCNvWxaVx+o9wzfkgjm7+W5B3uro6voqFNI1
         0fnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864771; x=1752469571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g/R343XRU7uP2JhNpqPuqHa7ET2xf+fA+xGC1UhyVSo=;
        b=ZOFTVOjm7LK4bOdDhQi5xrS/EFg5ld1au/thlKmREnGenai1eC2untb4JRe//M0rqc
         B6WD1WP1tv31RLbM5S2lnqbAC0lYNs16E8MEYd8aQwmKckptAaLgwdZYvjWMGPssXArx
         BMbEeR+QCTuJjQ+wZXxQMXLXT0WPea14bbg+Czsm2QYIFezGX1qfgIs62rdgnQ17vaEG
         jVoYETc965ChKvxk0LlKh2hvX54suEaAgv1RhlUxvFTIkHf1L7DNxZf4B9n8A+NNWMOz
         NRUiohcRcp3yX8ZtTAEQmolixzo9hrAMyQgGR3XQOQxIVugIBhXFLUmzj0WlqOkTV7je
         D1Cg==
X-Forwarded-Encrypted: i=2; AJvYcCVqk/3WZUnS2XA6jvlndhCj/tJuF53rV9m4BSVLpX+jtdtw7xWkR2OjfCIx6AA1O3KAzC5PKw==@lfdr.de
X-Gm-Message-State: AOJu0Yw3D/yuxf+kn6Sp7MMc2fDSK9qeBYCtXRNaNSS2KU7Q5wFgMlFo
	9FSfsR2wDQpvpQLpgF8dC+5E7u9rRbYW7LJSSnDyxsxlOoB+Zy7mA8+S
X-Google-Smtp-Source: AGHT+IH4FDmrOXGwqRGmOGrFDJQMoGz3NWGlpzQPSl2OqbrX6zQcTHrqnVgSwXPdsQX4w+xGQSPkFg==
X-Received: by 2002:a05:6e02:188a:b0:3e1:433e:2605 with SMTP id e9e14a558f8ab-3e1433e2679mr51889685ab.9.1751864771259;
        Sun, 06 Jul 2025 22:06:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGEm+USw84Nelfs0TqI2icLViE/L9uFSXpdNlMMIcKGA==
Received: by 2002:a05:6e02:1f89:b0:3dd:a103:6762 with SMTP id
 e9e14a558f8ab-3e1391ec5f3ls14779765ab.2.-pod-prod-00-us; Sun, 06 Jul 2025
 22:06:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXijcqU6lakGqOu/RY8Em4hIAh1/Y9AeVhEbPWDsmCNfD4uOVOXXDbdhEcSuy/Ixd4aqaqVmLdjoS8=@googlegroups.com
X-Received: by 2002:a05:6602:2290:b0:85e:16e9:5e8d with SMTP id ca18e2360f4ac-876e0c2509dmr888082039f.7.1751864770527;
        Sun, 06 Jul 2025 22:06:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864770; cv=none;
        d=google.com; s=arc-20240605;
        b=KstJA7mBunPfLqArk5C7MmJOzfU6bzJDLqnqTtUJOUwZRL19trzMO7mBaRl18bJmME
         ig6ul34Gy16JNsF9Y1LXo67zNfwpNWgonJJrPZikj8iWC+qI3J9JKNdhky2JAg3cBgc0
         dbSvtBHHvEKG15T6zwqFjBGyIemvSTqEOMrMewPgkW7jQoim8ZSv8egq/HFJU06x4TDA
         q5oonxtSbWxGHRKSs2aG73SoxYFxSV99nOmFljVPWNmlSrAEb9DSeQzhgmSrxLHoEMpe
         xDn10WJvjMarN3ZdDluDOemMw9f5YicC6fa/KM8RLVj92c2bBqloBcKEd8qNQcshx6KX
         K1HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+ox21bF4kIjDKl8k0gbtV2JTxZR2UJ8wCg/9TILGXwg=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=dCpgSCpPIpUhwFSUVzjl1WT4xvIVCCLlZf0uaGMn5l4ZrVlUifkXhY/o44ebgzq724
         sqXbBoKTQEba8O1Kju6/g4Ee1bOZBKSLzhtgPhDtCN1f6KVslJM8OToy6S/pnQUlrb7l
         rNdy/IPHdc3Ha4JcHemVM4/znIxWbwjJWloRIZemmyjTwWCfSw1ChLB20+fOrobTPczu
         eAlcK/+2WhdtqMLFMC/02zwoUQr5n9hetExHkHvkUUroN+e45DlarQiN1wOrJSEXBCi5
         gFkmCO4ZY/3yY1UjNpK3M3lX2afOLiVeqhKGX1pTVTxQT9yZ7KWcJYiDrqoSM3tcvqNn
         dlBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l4eRU6Zt;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-876e06d052bsi23117239f.0.2025.07.06.22.06.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D7BA5A52A7E;
	Mon,  7 Jul 2025 05:06:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0821DC4CEEE;
	Mon,  7 Jul 2025 05:06:09 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:08 +0200
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
Subject: [RFC v3 1/7] vsprintf: Add [v]seprintf(), [v]stprintf()
Message-ID: <64334f0b94d6b853e6104ec4f89bcf910978db76.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=l4eRU6Zt;       spf=pass
 (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/64334f0b94d6b853e6104ec4f89bcf910978db76.1751862634.git.alx%40kernel.org.
