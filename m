Return-Path: <kasan-dev+bncBAABBMEYU3BQMGQEWNI32OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CE48AFA1CA
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jul 2025 22:33:54 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-60f3442c58csf1479471eaf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jul 2025 13:33:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751747633; cv=pass;
        d=google.com; s=arc-20240605;
        b=JyBTVuUJ3RGNVsB4ATfJvvBylIY/KAGraCBfYAwSu3prdru5sdquDnB0Bt9TOSOqVW
         OgCT9dpElXlzCxsGJPfHghrdNmA5O1J5guDgGv4hSmseLxql68/n2zd3hPZrfHUWg2P8
         PmfcuzQlk9fnkY9Fln1wuM/0US+8VIBgyAmpqHlATrXvWMwWFGAQHJRhveZupnZP5FxV
         SgOXqPD0VGQrSvNj6gITlI8knax/4dEW8frskiEUxXL++A1EPGItCWaJOtHVEaOOqR0B
         M+RPoWybtfQM/UZoP37AH0qsZRz6ZadA740cqFHjM3lT5Wy7lWndbB56lDWR/sv9v6Vi
         Akmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YKwAc1YNHOjXjqN+ExyhNds/O2NGGc1yErjQqd66+gs=;
        fh=VO6Abt77dReOylI3YzKCdM5JpCeaP6FcZ/loc7mCYAo=;
        b=SURGncNJPTWGoYm4pC5hQzniFl3wY6xLi+LRyBL1iflPMD6YyJjkYOT5emePA62n9s
         Ab8eEY9FztiHhazSgay5vcmLNtKwr5d2jAFLjirDueQ9cptmnZVLNHEe9ImhD8soGPao
         WtfD4XdIZ4eIhb16djpTseeNAFGRnNFr1HWL79u8rcTAjwQhEPveIcV8Lg4YQWQe2YP8
         64dEBgVVmoiN63aoiVvTJsq4xh5p9D1ftYDhImYzexDZPWYwa7nMTw8Fh1VfykkInPnl
         XPWrP9HSgUgP/pYU5j6LWB3V4rsx11LZa9glSdrbk47bxZXu/y3Zk2H/ili/RHH4K3nW
         z0VA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O5hbx9w9;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751747633; x=1752352433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YKwAc1YNHOjXjqN+ExyhNds/O2NGGc1yErjQqd66+gs=;
        b=fWaivUncQJtC3vre3JavRWcP+TuxlkEn9+VvA8TTQyUm4nPQiAAQ2m6ZkzVlBMcL6z
         S2LY3EcvIUryK7L9O0g8Dn2q1BTsvLxq1UFYwSs2xhH3jv9j3GmIUgSBHnm91jPJDrVk
         nEbejjEKkWjqtBgeifvc7ClE/klLV/WYCm00M2zjQLHWuhclT5e/TXGEALeBiW3Ni6jt
         HSCXPytpismB5p36xGQIG6yzjm+rW0uI3JKNIdnc/fhVpB8KfZP3rjb7JB9PZglwgZn8
         SAJo5im66vMi3s1T6TmAtO0IsvoBQMr0rUVFQUVZyEDjhe78KlvWLLW/Zj6qO3FktcNt
         lcjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751747633; x=1752352433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YKwAc1YNHOjXjqN+ExyhNds/O2NGGc1yErjQqd66+gs=;
        b=gKXwAT0F66bQBsHDFDt/SW3c/9/xu+gY43+aqUl6poILN8ELilN5xD3gDfI0zPOVTK
         Ar1ppHHOYQFCl/iekkbgvHEaehUVFxmgXb08v2K0UoDviouHZVL/ybcb+4A9kaBzBTx+
         2oBikwzgIYFBYgTxVdZJ70EFYP0aHEAs+oTHh9/9/pk2N06yOXE323/07rPf0dXEG+V1
         R1UvQ6O3twx1FIbj7KEGNg+uInj1QpaUBolS2M9aAOnEQe2yYDYgLO2Nwm6vWaZ60PMO
         Tsk0FFpnfdh1673tGW4zWNZNrQuQQ7KqzZK6cSKLTM4tUz/71bH81ackbbLD6t/9PQK9
         Wlzg==
X-Forwarded-Encrypted: i=2; AJvYcCVTFO2jMlOkOPUvSDc1C7SE+fKBSZU467Auty49YrLVxInbemm6vRuETuXeDRzhpnk6aAdiRg==@lfdr.de
X-Gm-Message-State: AOJu0YzaBZtLg0y+NSTV8okuKhixT1pqgdE+qf6Z3IzsinMcspBydLiJ
	gyy8dzeBBxVNJ4RYqwMJmD4fDzGQ5GvEz5WM1veWd7Lk6H0BIY5ArEan
X-Google-Smtp-Source: AGHT+IFuFLsRE9cemtN7pHXIHBTB0dN45koRuRZNXkpWtlW+czX6zbD5hKMSuIKhlgOm3g9uGBcXKQ==
X-Received: by 2002:a05:6870:5690:b0:2eb:b6a2:8d77 with SMTP id 586e51a60fabf-2f796d0b41cmr5539178fac.29.1751747632822;
        Sat, 05 Jul 2025 13:33:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc7cIJ3RaxBJdpQbZ0ZXKQ6GFQBzYYTmDb+7ppbOde1pg==
Received: by 2002:a05:6870:b4a1:b0:2ea:72d5:87e8 with SMTP id
 586e51a60fabf-2f79b74fc04ls738785fac.1.-pod-prod-08-us; Sat, 05 Jul 2025
 13:33:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2goh92yISrIlu2/Br2bQmoj4Ir4e9vYIyFp+Ra2Ts21z5zoWY27gPQm4IARgLpgDC8tCXTqtNlxI=@googlegroups.com
X-Received: by 2002:a05:6871:28f:b0:2c2:d2b8:e179 with SMTP id 586e51a60fabf-2f7969c069emr5278959fac.4.1751747632068;
        Sat, 05 Jul 2025 13:33:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751747632; cv=none;
        d=google.com; s=arc-20240605;
        b=amY1FxebVDVoUipvpERD3hSHLsWYde4Vj6RX5ctNuhORSJ9Qv9bacpQxUVTKFuGK9C
         WUrcFtldDnGepGOt84DISqTWLq+almcIMclteOeBsdX5CTwFLQWsKlhqdLuJPUNQ3lIW
         EjxiqZZmHN9jZBhK/3WReEEYS8J5ua18v+P3bt2pbfnG2cXoGC2XELA+nm/JyoKCQ0FH
         Heb8MqzdrizFJt84oWpOChe2hIaEECZjVJEWe5h3rF5g439bs6HupbOAIeNSoKTz/HzT
         MaONQsZnJJXAFXDcEMFWiFrT4/s9q6yG4IhAR4+1JAHOeVhF/3MVMtXBN/byCpUgAaJd
         Tuqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=j2yop7tjrpnvs6mdWsoDaUXdWC6LBa9pXyqPT6BSFm4=;
        fh=ajsM17EAOL6Fxaw3DPHvK/x1BqMY4iRD4b26QdTsiIc=;
        b=eRg/WC9YOVLzL27OxuS8g/5aEIeBN4ikWYWhVo8zdxPGkLfnyveCQs/AyqMkL5KYSP
         M0FZsvUKl1l/B7hMMIEqq7dFA4hS7zis3k60CDk3DIKZ0hu2xROE7J/BoUS4V0p3agyR
         dWDegXJh+mYeKKBj336H//NdtNmIaPJ0Tj0IQUOh4XPZQ44bSvFLVLu/ZkHIOqVu7EIR
         mkZAWNTm8TJxvOTd/zY4ObYTSB+rLPaWy/qLKKewj4f8OTHkc7T1mYHIkjhm7M9+wYgb
         5Pl0oqFeb7i1WgNG3jCjWtZXWAw5Q1r64/ciI1sWK5aLODDdE+z32xm7w2rT0dhsfJ3G
         4oiw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=O5hbx9w9;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2f78f9cb84asi237857fac.0.2025.07.05.13.33.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Jul 2025 13:33:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CEBA35C5525;
	Sat,  5 Jul 2025 20:33:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 91627C4CEED;
	Sat,  5 Jul 2025 20:33:50 +0000 (UTC)
Date: Sat, 5 Jul 2025 22:33:49 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: [RFC v1 1/3] vsprintf: Add [v]seprintf(), [v]stprintf()
Message-ID: <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751747518.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=O5hbx9w9;       spf=pass
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
 lib/vsprintf.c | 109 +++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 109 insertions(+)

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx%40kernel.org.
