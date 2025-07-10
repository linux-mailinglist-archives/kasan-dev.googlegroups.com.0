Return-Path: <kasan-dev+bncBAABB6GTXTBQMGQEJES6CUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id A1A4AAFF703
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:48:26 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3df393bf5f2sf5153905ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:48:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115705; cv=pass;
        d=google.com; s=arc-20240605;
        b=H9G7a8xUEq2GUwklAaT0PKeoNXDzubBCLtr+DeHZkYHSy75hm/KRjWEtS70nxyAtiy
         UQ89G/zZ/wUn+/MVLYt0HRgQdmnjdmxwBwMKvCNb9Fg6oqOi5BItNEFvGzndjJlYoh2m
         BNvJX+oHzOhNE3l8mLY8mMNaVfKG+e4f4i/SZDTxYVQOUDNQlnXBPuK1ZrvtSRify45i
         P68qZqX0N2ywyxWYgGN/+lWvybtdWKoZgB9d397nJlq9qq26PtL+g/XU/EcKaags99Iw
         bg7jYmddvuGQYh13tn1mINM3VuFyefrFvpBHCff0BsuA/5mgshVetoi9xR9s+ctPsSXE
         9MIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AcOMFMOpxtZawL0GF5RpevY15Q8LiNxP7Q70Yoe8dBk=;
        fh=GU75kXKqvpsko22zd9k0Pu6K8fdtRYKzX2nO0KmoSFM=;
        b=f9LBWp+EXLTG5L4GwCIaEPLfkkYdfe+M910wTIAs8+0tzIo6p5bYG1JqGW5NNuU8OC
         8sqgvWHGqiVl1q+kA0VwHF+QUmuvE3NupNj9yrHYqFQ6Ed0E8rlRnCSK6Nd1pUJwM48T
         JNqkUWXgvgmXU4yuLY689sTn6d3acve+EnidqTWwHHItPdvzRBFA6a9BPhgD8rQU1xdz
         OeIf00+eWqbJaCig2oHSimqiaTXoy5T/DuGUnNniQ+vA2lnwCflc0l1TNQNzzdE6I9bl
         QUujlxf+fYL4gONKU0OVKZeMkrdQzq1Xxu5iQSBjJlO/Ud07hl3DDCo7/kl5xKxK4bSt
         VVRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="TU/xLkQv";
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115705; x=1752720505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=AcOMFMOpxtZawL0GF5RpevY15Q8LiNxP7Q70Yoe8dBk=;
        b=kukYa/yxddm+BWJh8R5GIg8JKE4EZE4EFA6ffEqf0Kr0DH/AWANST+/mVN9yif+/lm
         2y9KSzKSqkXVcbMt/lrSw13gazbBeHe9MmXR5HKffJowyU1baDNYksEGi40KHyXM2KnY
         hF1Uh7d9UcMtYkXVoodeFMCZZyWPiuB6PLTd9LLMVvS8ATEpSZa/jRGdOMaUWTritOhe
         AfHtZH2dbz9bkMbYFuJH7nv8TLmHD7k4lVmwRWYgk70wFHnWLfEngpBHKUzWbSa6rBEG
         nMGk+v712U5kG3986S3nsHm8BWE8jJCGpGiEnsyffNGTUEM/g0tBI9QXCm3Z6SYhCsWP
         zOLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115705; x=1752720505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AcOMFMOpxtZawL0GF5RpevY15Q8LiNxP7Q70Yoe8dBk=;
        b=YqOol6qpaEKvsH8ubdEqkrKfKulrLW9NZYkSlMvmGCSmEyaKYYfijkPnSFMyVyt+l5
         hlE/Kwco5BsA9KNVtWwAxMqaDBJMzpdMHRhDslwNYr60Ii8Z2QkDUT5jjEanQlp66zMA
         7a2TxBXTplrWYF7RRIBwtQTtI4165mAF2GV7+6l+HNAZuZdnnqSkkHCzLmWtkQ7uk9qa
         ASkJktjAAHrUyf1WbYoi2kk+fXsJ/6xOFxpD8q3BA9LZoj1rlgMT3/eZ4aLsqIZ4icwC
         GI86C3tY5g6DANfkT90XkJB2VUWWEjB3Kg3CQo8Xs37zziLIi+1dhWoCgsjV36NUKI+F
         LukQ==
X-Forwarded-Encrypted: i=2; AJvYcCX786qkcDTbe8aGpLx0rgEBHFN1ScKyglISZSKmUJM/NhI5FJ/ZcMiKc+CEAuX9Wm7zjkET2w==@lfdr.de
X-Gm-Message-State: AOJu0Yywu1/l8rMQQTCet0YmnkEi2mlxNzALzSsrBURCWtDC2DImXKni
	/I9gycfANia+wSdjZZRxBWpitxA0M/+Of935w5O0sC/Q4/WBnN91STr6
X-Google-Smtp-Source: AGHT+IHbQVr0CWAA2LUXMBoAjPbnOH+3CJw3hpvR7TBneoY2u3uQ7Ct7xb6axpyK7t2+btJONSNvmA==
X-Received: by 2002:a92:ca4d:0:b0:3dc:7cc1:b731 with SMTP id e9e14a558f8ab-3e245f95156mr9517935ab.0.1752115705112;
        Wed, 09 Jul 2025 19:48:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdpihw2FRAmTZSSds99wFEhdtA5ApV8Rrp2cGlUfq2uOg==
Received: by 2002:a05:6e02:470e:b0:3dd:b672:7f90 with SMTP id
 e9e14a558f8ab-3e2440de3dels4289405ab.1.-pod-prod-06-us; Wed, 09 Jul 2025
 19:48:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCXfBTiAnOzTOhTzPpy0KWfh3C4HN9ypaDaAo9C1KZ5xN+gxr6jnxBIat8Yk51pasp1XwgHt6uD1c=@googlegroups.com
X-Received: by 2002:a92:c268:0:b0:3dc:8b29:30b1 with SMTP id e9e14a558f8ab-3e2461a47c1mr9789785ab.14.1752115704387;
        Wed, 09 Jul 2025 19:48:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115704; cv=none;
        d=google.com; s=arc-20240605;
        b=dnCMT+HtoeNwzU5FaHoyZiS+y3682tzTdY9FVtqhe5JZzF554zPRArwVKr0mA3Quxc
         fW86LoD1lu5Y45b/1Iuyzrwfm4PUj/hPKDTK5o7MXwgxYKK4SxK2OICURMiwvdQOu3z1
         y0910hBF8BLe/z7o1hdjwZt40LWCfhp8r321b2ywNhVcj6nB35RJzjwzX3fy50290s/Y
         +t/qMfL3XFp5/yv7Ose0AaZfAslXV1QX60wx7j6TS5BdaonIkWgJTA90bs8R69NEROeQ
         2fPlxlLXaaWC0sUSarVQzAacWrSixboh6XtWK77o93osG5Nykix52H0TQevfrdjxHMVC
         4nKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0sUPaBsrRtVECUWOJKm+GE3R6Wlp2E4kocwkF3cjpXM=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=W7jHz80eK/1i0Qe3BHpZwOA4idkB1Hd8P2sZirlYOCR8PGV/lt+4wynQl6xhah+v0L
         8XGOG7HyVJl6DKLkqQ2zpW03pwUOF1sTr5HC80ZfBR71pNPwKAc5te5WLP0c+5FIzekJ
         MrTk9OpnVKKjY9g/L+UsK1g7VU4YCo9/3A1T9z64b2o5/J21Ut2CTELLXWWCyAwnKnIj
         MMNp9drpPDNsccZ+MxmaLQzAWX7T0CgH1G7O93nPTAhocV7dOMaJCURKRDxpzqo81J+j
         hpShrexZeMvQUDZys8Ta6HUtA1sS9NdRF7srFNvSnGYOGVPTiU9hpUJdg5wq/tybSfR4
         irBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="TU/xLkQv";
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50556b84deasi25739173.7.2025.07.09.19.48.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:48:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id B7D21A50119;
	Thu, 10 Jul 2025 02:48:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4C2CBC4CEF0;
	Thu, 10 Jul 2025 02:48:14 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:48:11 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: [RFC v4 1/7] vsprintf: Add [v]sprintf_end()
Message-ID: <2c4f793de0b849259088c1f52db44ace5a4e6f66.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="TU/xLkQv";       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as
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

sprintf_end() is a function similar to stpcpy(3) in the sense that it
returns a pointer that is suitable for chaining to other copy
operations.

It takes a pointer to the end of the buffer as a sentinel for when to
truncate, which unlike a size, doesn't need to be updated after every
call.  This makes it much more ergonomic, avoiding manually calculating
the size after each copy, which is error prone.

It also makes error handling much easier, by reporting truncation with
a null pointer, which is accepted and transparently passed down by
subsequent sprintf_end() calls.  This results in only needing to report
errors once after a chain of sprintf_end() calls, unlike snprintf(3),
which requires checking after every call.

	p = buf;
	e = buf + countof(buf);
	p = sprintf_end(p, e, foo);
	p = sprintf_end(p, e, bar);
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
	// No ability to check.

It seems aparent that it's a more elegant approach to string catenation.

These functions will soon be proposed for standardization as
[v]seprintf() into C2y, and they exist in Plan9 as seprint(2) --but the
Plan9 implementation has important bugs--.

Link: <https://www.alejandro-colomar.es/src/alx/alx/wg14/alx-0049.git/tree/alx-0049.txt>
Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/sprintf.h |  2 ++
 lib/vsprintf.c          | 59 +++++++++++++++++++++++++++++++++++++++++
 2 files changed, 61 insertions(+)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index 51cab2def9ec..a0dc35574521 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -13,6 +13,8 @@ __printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
 __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
+__printf(3, 4) char *sprintf_end(char *p, const char end[0], const char *fmt, ...);
+__printf(3, 0) char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args);
 __printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
 __printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
 __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 01699852f30c..d32df53a713a 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -2923,6 +2923,40 @@ int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
 }
 EXPORT_SYMBOL(vscnprintf);
 
+/**
+ * vsprintf_end - va_list string end-delimited print formatted
+ * @p: The buffer to place the result into
+ * @end: A pointer to one past the last character in the buffer
+ * @fmt: The format string to use
+ * @args: Arguments for the format string
+ *
+ * The return value is a pointer to the trailing '\0'.
+ * If @p is NULL, the function returns NULL.
+ * If the string is truncated, the function returns NULL.
+ * If @end <= @p, the function returns NULL.
+ *
+ * See the vsnprintf() documentation for format string extensions over C99.
+ */
+char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args)
+{
+	int len;
+	size_t size;
+
+	if (unlikely(p == NULL))
+		return NULL;
+
+	size = end - p;
+	if (WARN_ON_ONCE(size == 0 || size > INT_MAX))
+		return NULL;
+
+	len = vsnprintf(p, size, fmt, args);
+	if (unlikely(len >= size))
+		return NULL;
+
+	return p + len;
+}
+EXPORT_SYMBOL(vsprintf_end);
+
 /**
  * snprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
@@ -2974,6 +3008,31 @@ int scnprintf(char *buf, size_t size, const char *fmt, ...)
 }
 EXPORT_SYMBOL(scnprintf);
 
+/**
+ * sprintf_end - string end-delimited print formatted
+ * @p: The buffer to place the result into
+ * @end: A pointer to one past the last character in the buffer
+ * @fmt: The format string to use
+ * @...: Arguments for the format string
+ *
+ * The return value is a pointer to the trailing '\0'.
+ * If @buf is NULL, the function returns NULL.
+ * If the string is truncated, the function returns NULL.
+ * If @end <= @p, the function returns NULL.
+ */
+
+char *sprintf_end(char *p, const char end[0], const char *fmt, ...)
+{
+	va_list args;
+
+	va_start(args, fmt);
+	p = vsprintf_end(p, end, fmt, args);
+	va_end(args);
+
+	return p;
+}
+EXPORT_SYMBOL(sprintf_end);
+
 /**
  * vsprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2c4f793de0b849259088c1f52db44ace5a4e6f66.1752113247.git.alx%40kernel.org.
