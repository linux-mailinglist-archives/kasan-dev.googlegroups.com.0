Return-Path: <kasan-dev+bncBAABBXW6YHBQMGQEZKH2AII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id DCA85B01101
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:56:47 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4a57fea76besf28634861cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:56:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199006; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cwp6LvC0grOSAG9PEVAIX/e1OMZjbnFfik9fvJFmbu9MKZk5Vkyoun/jKKA3NfIFVD
         Sk+gAeyoTTteYrAexM0oijQ3epLpE87EiTa2dk1YKftRk3aMzyrs5GTktDHUL7Ec4sEU
         A5DRMpjCyuFDOJ6p5e/JtHb1Br0U0P//3RpzFIlZ0FRxRKzLKg2kFijQFnNG2hVhsp6o
         TZ/ZrBkaKChOKPpWbUpT1myx6WEkAefUrF+qjHrgAUtGOCxnm+3y+Ir49ilLZWhuvBER
         i5aP6ujBTdmMYexwGz1c3UUah+7sgKVORC1teadC53xUutEuiZY5eCjBh13HaVSdw9Zz
         JpNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=If67xAad2SNkNslPeX4kprPemoLPcAQtlz/U8jtGOqQ=;
        fh=FtTpNxZf6tgrDn38GS4WnW5RZqiU4wP+mVauSgZvs5U=;
        b=Lc9vIWvFwCg1PQiFN2bnI+pvfw5q6b7c3fI8RPBxvhEQ55GgsOYyR/s+wZxPnx/7FZ
         TwiWTlRrztPCrZoAI0l9U3vzn2HI5C0KV40swuhrI+Clf1O+g2EWrvOd3gGrDywR3bzV
         GPq/t68PuEW7Pv6Y6wMPhx9IoJGJqxyD/mBCD1RQCrqZ/xqLB+Mp8uObuWAr09smFlNR
         wua74jo54y32TgRQvnArqqS/UpJFnJvyU9IDDFG8eFdTAgyrUcSWXrryEYhcALAYN+mD
         9Jgbrd10Wp1Z1UaIoIrmCVM2WlMw9vYR3yCuWELc8SeTDdm0tr0vbisTiG/JWjtZIbqZ
         GkdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XCgw+aiM;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199006; x=1752803806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=If67xAad2SNkNslPeX4kprPemoLPcAQtlz/U8jtGOqQ=;
        b=ld8aJ4NKYTnHynm8l+CXgYjcpwUkxjuILLxqhWmqnbqu13oInq4U+RpgGtMm5EZsPG
         WuHDA4EsfMYq48nVLc0l5nbwArWHhtqJC7ZqA66QKSrdXpmIY/Bvk8KMxf/kZv50P807
         60cH2MWwSNvPe74gXcq7fS5qQr8yakkQFg/OVZRDw5hcL4HpCUmIe0G4wRHPG4nRXujS
         Jjd92T5nilEWevwJzHR2NU6NT/2bpCkqbeXo07ofAYvRpns+we6E8ErC5AM2Mnp+tUB6
         rY105WkhI9snQSvEnzRowlDD7daGkm6w/Cy4uSqLlOQlsbPXUcTbLi5Wn4eSL/xjEBfc
         keVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199006; x=1752803806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=If67xAad2SNkNslPeX4kprPemoLPcAQtlz/U8jtGOqQ=;
        b=SajS+9BnDChOoQ9b6R83a7Fw0NHmRmudBa1ne7PeTwBDWv7nr3KTv2IMaq7S13Eifb
         nNgfL4fUHn1WUyy4SWDaRiZbhTeFP8k5L8WJmv+JOlWV8cf1dmWjzAM78zjIUMBYQBZF
         lkjEleCa0A82E3eSzI/wCFTOaJp42JvtcMPVZJVZU9Etr6yFn2odoHoJJPoCoXW9JbL8
         NAJ24rnkRmlAdISlxMSQf9dVh7PxiYiyfI55Ka6ZulEv3jg//VS1Qgs5YmKZL/mMPIgG
         plmBxo5APniimodvKJ5QrS3fNVFiXOh+Ps+v2OxD1RyqwnJbYB8ncPdweNnHf9ZcNwcT
         4B3g==
X-Forwarded-Encrypted: i=2; AJvYcCWukp92Zho5H1TGvfDjc+6CXwEFeCRoeZRc/T8aIxKng70OkUc3DixowAY+LpGKx9Fqs9tKjg==@lfdr.de
X-Gm-Message-State: AOJu0YwHRZx7mYzPQLB5u6bPgybB7Zi5mRz3Rq4hgFs1k8P3pbLI3erS
	6gqzM5biSK+/W36BDQY6I3QF8G+Wq5ctgyYzzd0VBWHrpLxi0wv/+0sE
X-Google-Smtp-Source: AGHT+IHKxHSBRFO3o6ppt7hqPGh40mpz45hVen6RK62lgNbFksxWaS+pav/2pTRGSKS7vTqYgwhPhA==
X-Received: by 2002:a05:6214:5245:b0:6fa:fdb3:587b with SMTP id 6a1803df08f44-704a3518245mr23654626d6.1.1752199006561;
        Thu, 10 Jul 2025 18:56:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfx0wJ3+Kmjjy+rO6RHjNkzWJKu0axioorIfrEG30R9xw==
Received: by 2002:a05:6214:2486:b0:6fa:bc23:a7c2 with SMTP id
 6a1803df08f44-7049572f8ccls25550836d6.2.-pod-prod-02-us; Thu, 10 Jul 2025
 18:56:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRC0BS5DdDyoJyhC9CTsOJ1sTXDW/y+JXkFFB+lih5U1TBL//6FgMyYQqHgMqBY/oJXBuOdbGQTtI=@googlegroups.com
X-Received: by 2002:ad4:5f89:0:b0:704:7f0e:ca9d with SMTP id 6a1803df08f44-704a3885c2emr25595066d6.24.1752199005475;
        Thu, 10 Jul 2025 18:56:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199005; cv=none;
        d=google.com; s=arc-20240605;
        b=VfdgGLZaL/El5U4GUtRQars+9I0UyPct3szMGg6SdhtRTgrfVZw+UMfi2scaHoMgjn
         B3HX+HcDNsX3yo/TH2h7X5P+OQUyiUCCkLtnB+Ml4vCYgTWzOOBeXcLTudEduDveJzlx
         BCMOrSm92/2d3Y5OFE7Tc5exwjhaL/beK3D1s10UAe7/Dwto98nPv2bh9NxJPY198Umj
         66YnPy4BfD/dXNAcIyI4a5JsscsY0J8ZHws0Rc9kZgEaZpBinVGpar3B6zdywuy60T/F
         D+Gp+5NeYtUu37OY9wrpI8tmowLz39lJO467/77l4+v+zDs3EPPP7zJnmNz+z0P0ptTd
         Y7DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ptQtAfYVWHWCm/g8DKYmC6e5IyLjJhC0DiKI4pmKGaQ=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=SYRuyxXaXIsd8TxYhELGv+yqSoFVUAjyxSxT4rxwaa83Fx7jqGKN5YiY+E7zQvJrNS
         BLb6zT9bW1gHPzn370GN1rokH6zRLtfAOa64ojiDTEPdDnGKKjuVKT+2iI5xJkhG5rYy
         3Wce98D9DEy1AMrEykvW92T03H3WN7qbfQYVVbC92QUAywTIATnVGVeH3zj/nX8t7G6V
         mlG5ri6XXjXFtSF/ZJziPZyLykNFRZK4b+Zs+KmetkviFF/JCt5E5DeSej5R0xO9KuUW
         9lgjw6GWyHr+wvYULjTke350teQpR9q/tXrjyQFSua5hiSd6zXR5c9vDivHCh+S77+Mo
         3qSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XCgw+aiM;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70497db8a41si1030846d6.8.2025.07.10.18.56.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:56:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6B03145DEC;
	Fri, 11 Jul 2025 01:56:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B075FC4CEE3;
	Fri, 11 Jul 2025 01:56:39 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:56:38 +0200
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
Subject: [RFC v6 1/8] vsprintf: Add [v]sprintf_trunc()
Message-ID: <dab6068bef5c9db7b89c7f959aea723c40b35dda.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752193588.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752193588.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XCgw+aiM;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted
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

sprintf_trunc() is a function similar to strscpy().  It truncates the
string, and returns an error code on truncation or error.  On success,
it returns the length of the new string.

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
 lib/vsprintf.c          | 53 +++++++++++++++++++++++++++++++++++++++++
 2 files changed, 55 insertions(+)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index 51cab2def9ec..5ea6ec9c2e59 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -13,6 +13,8 @@ __printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
 __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
 __printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
+__printf(3, 4) int sprintf_trunc(char *buf, size_t size, const char *fmt, ...);
+__printf(3, 0) int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args);
 __printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
 __printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
 __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
diff --git a/lib/vsprintf.c b/lib/vsprintf.c
index 01699852f30c..15e780942c56 100644
--- a/lib/vsprintf.c
+++ b/lib/vsprintf.c
@@ -2923,6 +2923,34 @@ int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
 }
 EXPORT_SYMBOL(vscnprintf);
 
+/**
+ * vsprintf_trunc - va_list string truncate print formatted
+ * @buf: The buffer to place the result into
+ * @size: The size of the buffer, including the trailing null space
+ * @fmt: The format string to use
+ * @args: Arguments for the format string
+ *
+ * The return value is the length of the string.
+ * If the string is truncated, the function returns -E2BIG.
+ * If @size is invalid, the function returns -EOVERFLOW.
+ *
+ * See the vsnprintf() documentation for format string extensions over C99.
+ */
+int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args)
+{
+	int len;
+
+	if (WARN_ON_ONCE(size == 0 || size > INT_MAX))
+		return -EOVERFLOW;
+
+	len = vsnprintf(buf, size, fmt, args);
+	if (unlikely(len >= size))
+		return -E2BIG;
+
+	return len;
+}
+EXPORT_SYMBOL(vsprintf_trunc);
+
 /**
  * snprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
@@ -2974,6 +3002,31 @@ int scnprintf(char *buf, size_t size, const char *fmt, ...)
 }
 EXPORT_SYMBOL(scnprintf);
 
+/**
+ * sprintf_trunc - string truncate print formatted
+ * @buf: The buffer to place the result into
+ * @size: The size of the buffer, including the trailing null space
+ * @fmt: The format string to use
+ * @...: Arguments for the format string
+ *
+ * The return value is the length of the string.
+ * If the string is truncated, the function returns -E2BIG.
+ * If @size is invalid, the function returns -EOVERFLOW.
+ */
+
+int sprintf_trunc(char *buf, size_t size, const char *fmt, ...)
+{
+	int len;
+	va_list args;
+
+	va_start(args, fmt);
+	len = vsprintf_trunc(buf, size, fmt, args);
+	va_end(args);
+
+	return len;
+}
+EXPORT_SYMBOL(sprintf_trunc);
+
 /**
  * vsprintf - Format a string and place it in a buffer
  * @buf: The buffer to place the result into
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/dab6068bef5c9db7b89c7f959aea723c40b35dda.1752193588.git.alx%40kernel.org.
