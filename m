Return-Path: <kasan-dev+bncBAABBDHCYDBQMGQEPZUNN5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 5332FB00DC8
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:30:54 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-31220ecc586sf1434386a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:30:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183052; cv=pass;
        d=google.com; s=arc-20240605;
        b=hiYu0ozF9x5kAV4EXUq767FSqRtc9dahjcdO05rue8YFMdWwkxOHZlCw0ybiH7cLv2
         1qMLxufxbhm4305AnresxuB4Kgm2ufK/EyGASWEOI6JHRLgAGV3fMH5qcTI6e6EDebX9
         fUMgzRIpFV8uv1d1JJ+4F7yNl5e/VCtcthgm4gHnXvkUy3ySr7oCQem/urYONz49vdpJ
         dFLZLKuj5U8OhDlbwfGRE3kysLcNhq02BzOL/As223hrYFm8shq+ZDpt/JT2AUTWGfQ0
         KvAZuiXUg8bNkFpnH0vJru3earapLgQ6qfuyWDnIN739tlytZMrX1c4wY/cYLrdEyX0B
         mEGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=f4RjsjG+qtr/TStt/b1HZI9/qDxRffg5+msO+RnHfXg=;
        fh=13ef1Eevim1T1nURC7lw5TaP7fM5Ku9jHqz4VVvcw0E=;
        b=JhTsOdKlG+TQVv9WUit8cnUB8DHXV6BtOUwAPV3b33zxpIC2BwZb3ltTJ1jt+77E2z
         1z9RSHu48FF1uL/O+qjjRpvI1MBVmuayAxkGTPVvD935HCJgCHXBXWXOld64YMHOSZWT
         oV4y3jWCZFGAMAP1X1fK5JpgCA1IMzEGX1penL/s5umy5dIKrWIgvTC+GTO7ScD0BsaO
         UAcOmHGG2TrI6+BUeV4sG3ASh1CVtmqYCg+u1WMMpd8Ipsm90Rmvk2mFlPMFGZqxvXTU
         6v4jwrUkYRWZxOip/4qlrUmIdkFHplJgGYa7pTYj5tnTF+PQTO56SyVdSftwJZ1msFaY
         n88w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dPANN/xW";
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183052; x=1752787852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=f4RjsjG+qtr/TStt/b1HZI9/qDxRffg5+msO+RnHfXg=;
        b=hBjoZWNkfuJ61PDtlp65+94kNQCcn/E8sBZztxMOegIrY7XCK9/zxeWugxLRly+QMN
         Ga6QOFbDmttsoB0i38P1rO6hHazRYnKUfPjVTPy+BHfnXuAELXtT2xoP1MbY15uBn5tC
         v9jykn7MEzcY1NUa74kvXXGLJbJ9oeedwsjLNRiUy65IQq0hCQGNK57Nn1eR0kPKyz67
         MtKmw6xQkv3ApN4hn/jjdjtVlUS/RHUNXTyBbs+y6XGvvIB6qaG/kJG39lMjYHHi0U2x
         dW2HXDxA3yQD96zeK1ZTJlbfUOrpO6ch2RUlVvYVS4wPJpt0ulwD6hWurf1duk1G3TJp
         PkJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183052; x=1752787852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f4RjsjG+qtr/TStt/b1HZI9/qDxRffg5+msO+RnHfXg=;
        b=CPasA8eipQy+2oX9BJGdAKR3vHl4ehKMFSvKEyl2iMlthypilbbSBhGPvUVrj8QAsz
         CKjGpeg+KujPFOtO5U3LGxZikqDWErTX1wovlHlWZPjkF53KyBUWyqNq8p3BlWPBdFNI
         mCzAJopnbiduAZkMxuJidgQbh0xPMdRpXL3h96O2dJVfFuOC5GJDMDh0YMwnxGNYg6Di
         ha/F0iFcFxHDIZURewIVujwCvXqCoDzjD3DhGyKjMnsdUd44dURgPYbvk3lLLVuPsGNn
         ka9NvOLCSm4hI7QJ+vU+gG2U/l8jperncJH7uHovoxYW9pvOiniL/uc0vMtU8xz21W/n
         ddng==
X-Forwarded-Encrypted: i=2; AJvYcCWiEfVkX21ou3kJ2ciZEHeSa+m6PLZQX0YnVnjtDbz6Hv8HMtyy1MCPrqJ51si5KI2Wg8wxIw==@lfdr.de
X-Gm-Message-State: AOJu0YxiPFaq/ALi4eiHVzRnoPZjRBk12UtfK/L9qjvF7EbCRJsWZUpp
	+HxkWJpnPVp6Z7Rw/KqGf0qCPIP6oYQEIt7BgxHg6CHC3ZZZCUAe/jWW
X-Google-Smtp-Source: AGHT+IGasU/7Waymag3436LvR8kUWkYXalu36zNIEgypKVU+T8Zq6y8ikRIcnjAwfnJhmChHzj9g6g==
X-Received: by 2002:a17:90b:1f8d:b0:311:eb85:96df with SMTP id 98e67ed59e1d1-31c4cd73886mr1426495a91.17.1752183052415;
        Thu, 10 Jul 2025 14:30:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcPs5sOabqc9g646Sh8hsCA8uoXm6oTUWgSt55OrMyBTA==
Received: by 2002:a17:90b:4c8f:b0:311:b5ad:42d6 with SMTP id
 98e67ed59e1d1-31c3c5b0bcdls1289747a91.0.-pod-prod-02-us; Thu, 10 Jul 2025
 14:30:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQ9hU/ulRc/Dbb39CAaI6Ljo8whFw24jizGiDkPHiTLvRpaaqHxbD92GeN20nhhfAfKk7PoK6YGSM=@googlegroups.com
X-Received: by 2002:a05:6a20:430d:b0:21f:97f3:d4c2 with SMTP id adf61e73a8af0-2311eb48bcamr1301348637.16.1752183051104;
        Thu, 10 Jul 2025 14:30:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183051; cv=none;
        d=google.com; s=arc-20240605;
        b=cI8NDw8Gl1gmBTvkEIMAXl3WbOrd0QwJrN3uDnmBRwAQvMbbG4GhAIpoI7/NYJEKhr
         ptdIptt8MNySSYu4zJTgrzMFRt6QE0t1r/FGbZGn6/NONeJfhJ6Ot+bigiGgA0rPeKqF
         JMPj4WLXs9jqG0tqhwWpLg+LGiSx+H9NchOvJ2sdMJzHyVPKSH6WrkVVrmbnBeL7XSBe
         ZncPoT9uxrgxeSBsrbzzd9O40esL2irlM8us/f5PzKxYLstdKwMPnMbiYjc1QExl42fD
         +smqkpOJREEBmiXRwN0wEHFeudPKoJH4ellpYCUIGNM/SfTOcRoUYiOYAVwO93Q3PqHy
         MD9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0sUPaBsrRtVECUWOJKm+GE3R6Wlp2E4kocwkF3cjpXM=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=UmkmIPHpUHxgt8JuhsPnVonSQL3JMBIFi9mpMShzao2Fqc0m2CTgnKLFQM6ffyyaVI
         6ZZBMnc/+ZpLszU9fXZOMLs9iGvq8bLRjBYsFurLSFuKmXuDSBptTp9CdRUKnpVYj6Gn
         KbugI6JAJoQ0Ll5QU/MHKncFoqtMpsc3W+8Dplazom1SgzcPFGi1xzo2/Y26INS+ignW
         Fj4fL2r7FdEM5dUe5HQac8wC4ODI+PnkyPOmEHwdh57FZ9jgVEojhhmLfpGPhGjfSl3Y
         SWXho95e31flHnwL33abV1MPpnXBMlSYZozDJ4j/sPn20czK57YjPTYBeVj4BQ36zXrU
         7vkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="dPANN/xW";
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b3bbe6d5146si122082a12.4.2025.07.10.14.30.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:30:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C97C845C98;
	Thu, 10 Jul 2025 21:30:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 15833C4CEF6;
	Thu, 10 Jul 2025 21:30:45 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:30:44 +0200
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
Subject: [RFC v5 1/7] vsprintf: Add [v]sprintf_end()
Message-ID: <2c4f793de0b849259088c1f52db44ace5a4e6f66.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752182685.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="dPANN/xW";       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2c4f793de0b849259088c1f52db44ace5a4e6f66.1752182685.git.alx%40kernel.org.
