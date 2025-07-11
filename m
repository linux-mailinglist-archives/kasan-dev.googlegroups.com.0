Return-Path: <kasan-dev+bncBAABBZO6YHBQMGQEVKOKTQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id C0EA4B01102
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:56:55 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-235196dfc50sf15568105ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:56:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199014; cv=pass;
        d=google.com; s=arc-20240605;
        b=AfbcY9glCtWQ7D5v4EQJ/ma0y2gSL8MVPYw8UHAy+sRaC7firPFeiqPpgzU5Q9ovSn
         A6Nn3UPJ1Fq8Pq5lMHPMiQHaklP6IpLACXBghsAyod2vBdHxTKnfyr0W53o0iH1Loz6P
         vzypJOrm5HzniLSRefbr7J7z6NkYyv/VhBnt6p2weU03IQFC85XkFncd9cwO3RmmVSwY
         wNVD+OQPhHW+ul9fl9ccXYN63IL9dvZWOx7GCc0jelGnbR0hJ31tT1a1FdPsOG7Ca8iZ
         3lz7BSpaU7PjmGw9HUlWE8xg3VgJU8xxuRv9VIOs5DhcUNk7jEawS1t/pqWDUNjhTL00
         YWyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cjVDoJ4sk4C1nB1QujUnuwtDm49952lBOpnv+r7gHjs=;
        fh=Cd/OSKIF+FWlCi7g4GZeffvCBVqhVR+g+f08fXAZgA0=;
        b=C+7Ena/vF0M94x/rNvSTysMMHpuazGcjopsYN8S7tBTZItz974ZXooWuoCyB++iqsn
         FFJ0Dz/B7dbE05XK4f0r8QIfwG112WoG+AkZoMO+XE2Hxdc971fPJ8+B28TyaHv38St/
         UgovmOKgrOQphVUCXapsnEBs+juwLdVCaFpqgig05uhjfSq21yosuUzZ68mxeCO/GGf7
         zyG01InW+hQVKKSYuRAPCkNlWgn2DOzwt3j4sq8ES53ZVRS1Sy7ACe0S5HXnm8I5GGzy
         L8sWe3vpJkQNFFdPqzMyOjxQbM0vTKayth86GiOABS5yNyF86E5pefzKTTYvfTbzDf8C
         GK7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bYvIpIqe;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199014; x=1752803814; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=cjVDoJ4sk4C1nB1QujUnuwtDm49952lBOpnv+r7gHjs=;
        b=nFmNMnxsUIEshW7KcQbqtRzwnZmjgYq++ovLtamDE/lxDZev9Z080c2z9pgDfriTQe
         Zb2Kio4paJbGio8mproRPvNDJOuwBzqbs0fm9akEySk1DtcdS7RTrZF98GOflgkncSo7
         KHhrVJDhCQkvnWnTDQMl/obsDoB5XhuAnxO73kO48arJunThyfMnnBlEDdoalwGdSf08
         GNsgKDqbTtNDRl4zS/mRCcvxDKmMHzx0ljlwiCXX1TK5SUXM2BAKzK7AI71G5a8e7MDz
         qWnF/iDsPhiNxqPaL1qludlYd5dxUlQco7m/G1DaHPCQo1gqwAX7KaFwIcQCpQz8y15X
         FHWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199014; x=1752803814;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cjVDoJ4sk4C1nB1QujUnuwtDm49952lBOpnv+r7gHjs=;
        b=aTbcsgn2otKiiuLqQQTGXSJ5fz3i0JRE53mk1Ns8FTTmYevt84XyTYnxb+wQhGH3/P
         O3n+PWleORGsLvck9c07UniYE1TKt9g2XhZaIUDwaPT6DwYymnj4cba/Xh3nvFkn0mas
         cRpqsEjxPIWnkHmCmqLxLyOCxh27ir3qU8bJT9NDoXyBAYXVz4adxOCHhbdtQNcTtbLT
         fSIoKliPAZhNbTbPQgQb8mbsIZ/i8x3OoE43Mvi8b1kDlX7XDTSEINK7WTQ2z9lQxgbw
         iKRGpZta/32W9hv+I9pXam/WMMHmk+8IRluTwGrVrESLa8Ms7FTmwtRh4kfLospcdVgM
         wOKw==
X-Forwarded-Encrypted: i=2; AJvYcCWIfiVEcrW4DDcLB/Ej+j6rT1H6jhTgPIQnGC1J+722dPPqXZJ8mrr2Bi4xXSCWgwZKWVumPA==@lfdr.de
X-Gm-Message-State: AOJu0YzJsw1mF7CKq60DH0pK/dKU+3HcHKKyzX2xOwv0lta9Y4ZoQGfe
	SnUC3PGAVLS7fhCCC2rZHw1i+ArfqSkyuIS5VV4ETCpdOcPSu2pYqVq4
X-Google-Smtp-Source: AGHT+IGmWc6cjEhzEDZmSe87J/WIunNuJSvhQI9ggw2UwsFCpAS8aVgZ6KJ0g041/codc5wigAFF3Q==
X-Received: by 2002:a17:902:ecd0:b0:215:b1e3:c051 with SMTP id d9443c01a7336-23dedd2121amr17191905ad.11.1752199014093;
        Thu, 10 Jul 2025 18:56:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcSPjhGtZIMCWhjxnNeegtGUNODjvQvsHW/Hw/rDguP1w==
Received: by 2002:a17:902:e8c3:b0:232:3488:eba8 with SMTP id
 d9443c01a7336-23de2e16d87ls7798575ad.2.-pod-prod-00-us; Thu, 10 Jul 2025
 18:56:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXa5FayimTmX4v/STzh2IDDVrYuKaUgoshtMkWDTVDYznQY0+p8VFJ6gv2KZjxbjQHXrkpwBBbhJQQ=@googlegroups.com
X-Received: by 2002:a17:902:ce81:b0:235:f059:17de with SMTP id d9443c01a7336-23de2fc7a8cmr81886085ad.15.1752199012255;
        Thu, 10 Jul 2025 18:56:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199012; cv=none;
        d=google.com; s=arc-20240605;
        b=egmLwe1AMJuIgrZ1hGecZTtwwGMvM6c4cdqDP9EA8mPKzxI2DY8YOSGOmv4SVf5l5s
         ES+EH2Jr5wYCpBMAmCTSX/EvgOaNDGcG5BtuAWpXvDamfNvDxdpHKpsIbE54/bQXUJbl
         hWn37anM2wgc+OcJ4mlhmS3QBBhBRWfknku5/9COGVu+Ae+BSU75Gt2TMcwGbPk7CgJZ
         MZ3ChZf2msacm6R9X2/oNMOnjKhGtxiX+yvr0e5aCrtXrfJuremmMuU6pOhhj+qA/eoB
         H5IvQSnKUvIHLEYRn6QzL9kLCVaH122DvuPkG30sQSR++2Mgx836yijVde8nXDQBKnFz
         O6gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WlDJiD+9QPljnXwhcj9rR0QJGJGIBllO08R2pS4QmG0=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=EPSkAzGpP1d2U7q9NwZqQPdp+YwJoKySCI/pBZEyg/FaJvFExEIHurk4rp5b00EZ13
         qLGh/krLvraVPQdP0pohVLGPqNxlbIAPe+mE3EB86y8Yt3NNYTIdMwKE3JQps6YaERge
         k8MvRwYF+OOZEGFw9YcuPg21c6Bf3++FhiUjYA0jWPLhlJ9f9PBog2sw+imCkht7i3BE
         M6DsTN4WIYCdKtcRkf/8tTcjAh3TX0qbtCPFj+VxlaFFl0fd25hL7r4jd4jvZhVy3cqW
         tXYy61lADOFsSG484LfpShIDaGhigNAjXWiN4TQtpWCT4FlmqqTag9ijfE3NFKc5VMZH
         CgxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bYvIpIqe;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23de4254d04si1244425ad.2.2025.07.10.18.56.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:56:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 36334A54B2E;
	Fri, 11 Jul 2025 01:56:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 52A27C4CEF5;
	Fri, 11 Jul 2025 01:56:46 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:56:44 +0200
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
Subject: [RFC v6 2/8] vsprintf: Add [v]sprintf_end()
Message-ID: <c801c9a1a90dd27789c1eb778ad3a02bbb1e6616.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752193588.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752193588.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bYvIpIqe;       spf=pass
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
 lib/vsprintf.c          | 54 +++++++++++++++++++++++++++++++++++++++++
 2 files changed, 56 insertions(+)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index 5ea6ec9c2e59..8dfc37713747 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -15,6 +15,8 @@ __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
 __printf(3, 4) int sprintf_trunc(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args);
+__printf(3, 4) char *sprintf_end(char *p, const char end[0], const char *fmt, ...);
+__printf(3, 0) char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args);
 __printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
 __printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
 __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 15e780942c56..5d0c5a0d60fd 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -2951,6 +2951,35 @@ int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args)
 }
 EXPORT_SYMBOL(vsprintf_trunc);
 
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
+
+	if (unlikely(p == NULL))
+		return NULL;
+
+	len = vsprintf_trunc(p, end - p, fmt, args);
+	if (unlikely(len < 0))
+		return NULL;
+
+	return p + len;
+}
+EXPORT_SYMBOL(vsprintf_end);
+
 /**
  * snprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
@@ -3027,6 +3056,31 @@ int sprintf_trunc(char *buf, size_t size, const char *fmt, ...)
 }
 EXPORT_SYMBOL(sprintf_trunc);
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c801c9a1a90dd27789c1eb778ad3a02bbb1e6616.1752193588.git.alx%40kernel.org.
