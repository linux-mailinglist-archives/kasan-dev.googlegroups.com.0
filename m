Return-Path: <kasan-dev+bncBDCPL7WX3MKBBKVG6PGAMGQECILSPII@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KL41ICzTnGkJLAQAu9opvQ
	(envelope-from <kasan-dev+bncBDCPL7WX3MKBBKVG6PGAMGQECILSPII@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 23:22:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0819217E3EB
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 23:22:35 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-89700915423sf7512266d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 14:22:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771885354; cv=pass;
        d=google.com; s=arc-20240605;
        b=WKFg5Xal9bPFZSLrzlPEK8HubFLAT3qhBlpIB9vkmqoXIhIUTkeH7WzNRHhxULEy1O
         xF4gLSuanQ4bEUTYUyiFaXu/KQG/0WGjBVn6Ll44h7gRufpsYVGbrRa1LGCg9zxSEebI
         NPRuc1Rf5M0nk8fTiJqSXHC6XKxDx/lhmkygh+0Rems5XKiP9QCLbwoOuELmXb/LHHHd
         0rYUQ37xeI+ZWIihJGfi8bbvIQWeRQAattITI2AK794snBqAK11jo4X8w82jBIt2t9Hv
         Y9QznEM4FjtFeFPUwErify56tNDSjRhqScWnkSxIgz7TYy1C7TdIfoNW5vHbsv+6OkVP
         zFLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=+LhTkkiPbTcyjBsolx/GBPgceaisM4reZWC7c8hfmIw=;
        fh=AGm5p9GsZZRn7xY9CFnjdR1B6Bs7db4WojXsvxyhaB0=;
        b=Vtaza7hxJUmkLZZgatOE1i/pNPgNglzI2YuB0JXmbZGE+uAuq90jokJYzFCNqPpnna
         ZMhR5hA+FPVP7lF2ZopIUev4WMVExVnVzZe440WhORhpPSdqwVXynqHzfImFxrFtCScj
         i89N2YO4Zz636bNw5eLXLwXSV4xgeg86EN0mfUVFlyMH7iJ/qz9ZIygCm8c+1igUqEGm
         ttWAzn4/V9sr/AyIBo3SAcCvSbPj0zloq3fWlkP2OzwkoqNSeQYNjWm5UlNBiV2Mcon5
         AJyBgoREY9l/QW4l3zlI9W+awos3bbgv75kFQK7FkGF3qleJfIlp93T/uPs71IP28Y7L
         D7UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=okXmN25o;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771885354; x=1772490154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+LhTkkiPbTcyjBsolx/GBPgceaisM4reZWC7c8hfmIw=;
        b=aBtLC50QdAYx7JQEyXPQsi7EgMGRstqtIGAdMqPGU34anOIlMLFy23kby/iUIh4SEl
         OkgCV0nMGVfHwZv78Eefuyg8hDB53ikqscZA3ZAWQ3wQcNlf/E0crsU0YZdzgqM9mc4s
         JYh5hjF6xttQhPDhIz/W/B9CyhhLvu3K9/3qaTFUUM7KNPlqx77h6Iv2upru0BDjT0HG
         MlLGfigmgqBkjdoKZuZxhJjTmnPTxMF5zBnWqDlte4NyOi+YMH6/9pSOOZVH9gQE20GY
         VxkhAY9bmJT+eLy+Ws+Uwpum2gIl/Z7UXhaLgxE1KHQ1aH5DLGfnXN5pn1dhctgQCz5q
         B03g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771885354; x=1772490154;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+LhTkkiPbTcyjBsolx/GBPgceaisM4reZWC7c8hfmIw=;
        b=Eu8W5W0DIllRQ2QLhjPRBMWAQ/tMBl8UUncLEazeiOowS7BBBhhwdBrj5xEQWoKHZr
         ZLnmARcGVw27ARj8n9CZpxXU5OlWxNA0uOneJ7yfLxXppErlARESXBXmGEnM5izL9jJM
         PQEBeVPMK3YiDfh/t0tAMifsILYXJrYLmj5QnhBCCEVb8FvLFHDLj01H632biQhgtIsF
         GqSlDzAo8BZ8+VSBV1I0yLqSkyUqNPa3FlFjEn71GEC9SvNv0nQA49a0U4h7bLBHaw98
         wKbADh6e7GndGEOXF2+yxuDMzz/ahfqqLQ+PhSQJqakjIPgh8I129qPmNSFjM2QLRKb9
         u3/w==
X-Forwarded-Encrypted: i=2; AJvYcCUceEfLbJwAMsmOnT21pI9ibFKgsmkIo+1wTyC/52W2fsFprF9tXAoMQdr8t0I0bv0PBePoYQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy9OmRh8qJgv8bWZSm5MfmX1EzaVHKYnUTpOpQJddw8vEhx59O7
	nTLfbJk3mvP/syDkb7s3ZIBvaCr/bpjvOrAxEd6ECmfw4Pq3iYFp8/rK
X-Received: by 2002:a05:6214:27c6:b0:890:247e:dce2 with SMTP id 6a1803df08f44-89979c54046mr158772616d6.1.1771885354305;
        Mon, 23 Feb 2026 14:22:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GWf7M8HzduT7wCmAw17PuhITnHuZ/Vj2NTcd8ulAyKfQ=="
Received: by 2002:a05:6214:625:b0:888:1f20:6a87 with SMTP id
 6a1803df08f44-89729c261a4ls80153666d6.0.-pod-prod-04-us; Mon, 23 Feb 2026
 14:22:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzZMWoIsZ8IYgUHTlVT6qb0D1dtffqFb6hJ6hz8GO+kYoxFtziGVQHx9tfKiilwv6nWtxPEl5yUmc=@googlegroups.com
X-Received: by 2002:a05:6102:2921:b0:5ef:a9fb:f1f3 with SMTP id ada2fe7eead31-5feb2eeabbbmr5542727137.11.1771885353380;
        Mon, 23 Feb 2026 14:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771885353; cv=none;
        d=google.com; s=arc-20240605;
        b=OqSqdabskSxYGaPuOeDSMZtXjg5QRFnoWUCv9zCkgLQglqxwm+wUQ7f2mMkGHoXMso
         HK4f+iShIrxM9q9JoXBJ2ESGeJboV218nU5hnQSUgIuOceblcMqr8VJJTXFS4Q9HE39l
         IHJzVT17K9KYJGSMNY8Q8/QXNn67aRsPHS+hOA0yaER3LYbOjVeA4FOi5T9jkVmIFWoG
         Nkiqxzb6b6MK1IWZX/g8t2/TD5hMI8IVb/DzvygkZKJLtj3ltTOVY/NPZtpc5qzUGZsR
         lGE68H42ZI1MAk2x3lYChvQOipevUIjKU15OqADFLWkj71WQ/bMi7fvcHLBvlsrBnif1
         aj0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=vNPFeX6144DM98FdQYk9lVXz8X7DnGdxk/ldgqQN9dI=;
        fh=VkCe6GoblGgdT+esOVAEvjC2VBqq4ZuyoJMbinIvvjg=;
        b=iY+HRNDSnUecCQYchAUNpPaLPRkW1Ij7gPalBHIIdYbJTkAtjVIxXyxsk5m6d6j0vC
         sh1X5STYkE7UGm9M7zEFivJT4ZEpC2M9inKwHIZbGSMocoo62YsOTemfmX0F3g4hE0eT
         Z4HVClQiv3AuAsgmPwyPT1CvIrnr3/vM+qjmQjUK7ErRJqhcZHE/GnSsrhfaTN0uWleR
         OJ7l6AIqkDdqTYNfUZw6mzeqyBt1QyOTRuRSrvwp8E5qVblaDi7/tS7ZyJ3+ncOUlZ5I
         Lx5UgOQtXC0T8jaf3J5TA9nsQdYwCJdV1QQlFDw+JF1dAnkiZHXlT+2nFwVIQHeAdfOJ
         Lf6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=okXmN25o;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-94dd546ccedsi9825241.2.2026.02.23.14.22.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Feb 2026 14:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 57759407CF;
	Mon, 23 Feb 2026 22:22:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 30344C116C6;
	Mon, 23 Feb 2026 22:22:32 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <kees@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] kcsan: test: Adjust "expect" allocation type for kmalloc_obj
Date: Mon, 23 Feb 2026 14:22:30 -0800
Message-Id: <20260223222226.work.188-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1564; i=kees@kernel.org; h=from:subject:message-id; bh=Ihme3BeQuf5dfeZKKF9RAQvVrJKW09YsEJyzB6dEgSw=; b=owGbwMvMwCVmps19z/KJym7G02pJDJlzLqv19RrJ/TYWDlkYVR+zXew/g4xdxu1JkbPurYvpX pa8a0FSRykLgxgXg6yYIkuQnXuci8fb9nD3uYowc1iZQIYwcHEKwERiLBgZ/kSF3422S/gUKCso 5hTZGT7NZ2P9qz5RFaNLFaXslkcvMjIsna1RfCrP3OmoccHcu8d2svy4csVF3/Wy9lOnvNNL7l5 iAQA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=okXmN25o;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[7];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	HAS_REPLYTO(0.00)[kees@kernel.org];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_FROM(0.00)[bncBDCPL7WX3MKBBKVG6PGAMGQECILSPII];
	RCVD_COUNT_FIVE(0.00)[5];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[]
X-Rspamd-Queue-Id: 0819217E3EB
X-Rspamd-Action: no action

Instead of depending on the implicit case between a pointer to pointers
and pointer to arrays, use the assigned variable type for the allocation
type so they correctly match. Solves the following build error:

../kernel/kcsan/kcsan_test.c: In function '__report_matches':
../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
[-Wincompatible-pointer-types]
  171 |         expect = kmalloc_obj(observed.lines);
      |                ^

Tested with:

$ ./tools/testing/kunit/kunit.py run \
	--kconfig_add CONFIG_DEBUG_KERNEL=y \
	--kconfig_add CONFIG_KCSAN=y \
	--kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
	--arch=x86_64 --qemu_args '-smp 2' kcsan

Reported-by: Nathan Chancellor <nathan@kernel.org>
Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: <kasan-dev@googlegroups.com>
---
 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 79e655ea4ca1..056fa859ad9a 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
 	if (!report_available())
 		return false;
 
-	expect = kmalloc_obj(observed.lines);
+	expect = kmalloc_obj(*expect);
 	if (WARN_ON(!expect))
 		return false;
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260223222226.work.188-kees%40kernel.org.
