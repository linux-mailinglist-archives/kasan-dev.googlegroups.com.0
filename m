Return-Path: <kasan-dev+bncBAABBGPCYDBQMGQE6XYP6YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 24B68B00DD0
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:31:08 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-74927be2ec0sf1925515b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:31:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183066; cv=pass;
        d=google.com; s=arc-20240605;
        b=WUIU9r8jlKIqNmP2Vnc9aqU61eAQPuIjXRGUtYWPA9dPFgjDkRWbwK9yX9koZM31hS
         1RDYC0P4eQOVZrYFInIm0j02159No+lzgVrUbOc9+iGJ09/nx5ZEYqt/ijUbZD9/81uX
         2mWNJ3oJlzfuBoJqBNjfHDJt/6or9pPTtpb8s/Bxoc2M29z7xGyCEsN44r1cSmYAIKgB
         czqbH/f4VhUgRMemZkEF5mF4fiCnM+RNQ0iEQESTPSjP1M7At2c1n5gYXwy1zO+vO8l2
         3aP2++QecGCCrOtqpZLteRa/qHPWDWbaEYBduZzlpCddiabuhmRm/zvvHuob4WeuZgUA
         K/dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=bK6x/dI23HTR88z90KgpA6V+4EQ6i0dBwLI9f7inq5A=;
        fh=a1VcFC+hpwPDPW8BYoaZ+IYhcugQ2PUlLPGaQN/oHEo=;
        b=FjHMJgK09ZM9lr/A4lkkkxrzqlNum/eKQaCwPw4HEGB7XKS9vYd0m/uByYLUHF4l+U
         xkGasLhjuJT/gZozfDJB8CJMr3wBzTGJhiTSF6ngRHuLrTrpuxiP37RtnITJKytI8wWN
         4R5ZcpASwQrIi3qO/7wiYUKKsYUZNRQSCrPubjV2HQC5PdjQ4jumCr1MMillmArETPyZ
         yJ0ABfehaXIToy4yPVcK0rBB/LH8xxmSfV92ZWzRB0eXZbfr2GgiBy/e04230GGHUIgY
         OU2D1XjNpm2KCdVm1/m1Fa+QhlTnRShsuo27Rjan7PDfEOtIl2dNN51JPYonzr/IvW3v
         rZsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Kza/FByE";
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183066; x=1752787866; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bK6x/dI23HTR88z90KgpA6V+4EQ6i0dBwLI9f7inq5A=;
        b=oIsMiAlALE3BEJTMCipZUU6xK9/6smJ3FPe6Yes/kmBXvyTiQgXlsDLCm9BkataIYm
         4huosxn3sHDthOXgP7ATXmUeMj285mYdMPstqtyCoUkxu/mUQYxNfXudhXdQZPOsqlvE
         KxYOjA61taB1q9cUclpK+YEjN+4EWaWHlioKjBH51/cBHoSuqQ6DTy4D2oUSoD6h7LtA
         160scvt+zowe5Y74RzZc4FnP7odqZKGh9+0v3E3/SL9L6e7GEEmZhiFeAKRSfA/Ip3MR
         jJfQFV7ackgJ4TYNcY0vgKN+w/tTM1PuzgciZXcCysDhWWuSZW89DAR++gjTq7sz+WlV
         YbOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183066; x=1752787866;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bK6x/dI23HTR88z90KgpA6V+4EQ6i0dBwLI9f7inq5A=;
        b=TI4aKAW75HMzPyRLJ+9ScRwQ3oVlJNMe6TbCEZY40d9takDtiCO3YKruUh/fGyX5Un
         z9jVjQ2cizbnxm7T0Bg+Ol55jhOpBI+jQgtxQmEHnAeY2a+9hc50lOU46vBZqW26u32o
         oj81TSKyJojoQ3wIJ4rwcf1jjAKpdyMIkdrRfEWQpIkXJHTfaPm1n5W+6ViKrjEVhzCu
         g3AVGwWhs5fKpMaQLgGpLwEVzerZJC+Me0YpweEV9zovm3b3Ds6RRTyDhVM3KOD8bQDt
         KDRKORrsrcizm95Z0d6WRpQN5KhfOFNpKuIldTNynneaR4ca3JWHpezU9ISsvFshEnPm
         25sA==
X-Forwarded-Encrypted: i=2; AJvYcCUYw7mHqRsirWRYZyVCX2nYVKzObjPg11C1uTPBaa+vdRlnubrVNLjk65XoQHVjbkfxs91vEw==@lfdr.de
X-Gm-Message-State: AOJu0YztN5vUvKhgZ4fOFde7bpk3EO92+Kvmn8WKfkfMDqVu1YBAxFlx
	rr1VkR9NO5PtoGV/iLyAB5ZeGae1dqNsdVNvymlCRXysTUDittbxBQQm
X-Google-Smtp-Source: AGHT+IGkiRsVXOI6d++IVVH5OoHDNA1o6IFXcX+ksdHTYh9RrYEIoVEaRXf961qO5cDurT5ZdRyKWA==
X-Received: by 2002:aa7:88d5:0:b0:748:f365:bedd with SMTP id d2e1a72fcca58-74ee2955a68mr629336b3a.17.1752183066212;
        Thu, 10 Jul 2025 14:31:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdx6FfT8l4Uf23bo1Sx3RVIm11kkzqP95PX/+yN0rUwhQ==
Received: by 2002:a05:6a00:2190:b0:736:dc82:1c47 with SMTP id
 d2e1a72fcca58-74eb496271dls1413207b3a.1.-pod-prod-08-us; Thu, 10 Jul 2025
 14:31:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXK01hMpp/2B/NALcS8jz92N8QvaXPx2KZs3Apy/hNSgWo4KSWisrKrbI0zefoVmuiRRRptXRVe7cE=@googlegroups.com
X-Received: by 2002:a05:6a21:9206:b0:220:658:855 with SMTP id adf61e73a8af0-231367633aamr902974637.13.1752183065046;
        Thu, 10 Jul 2025 14:31:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183065; cv=none;
        d=google.com; s=arc-20240605;
        b=ELAIPPZyl3sVbOvCzyEFDfkSkBHFGHLULiqDfY8oXWHtnnHHZs21QpMmpZnrvOfkKX
         z2PGD9+h9TIcSg5czX1Id3Rm08vfbYLfKBzUJclEQ/l8wQYmFh11DFxvfgjdKVW66vuI
         oLFf1Sk1YD8snzw27nFCHd10X7b6K+9wCRdBHXa3BpAtbpErdAZx105AFSt9LZltACAg
         3h2/7go0r1zV+EPuoErRrZHPJbcG5bfJds9sHSZTNDkYjWrPZ1htvYlauHdbIDXQO6lH
         c9iZ0RH1TYDnkC6JvfqlX2cWS1/jjqXeFXFaakX2Mt+trVG/qF0TmM9k61Wq3Qhxgn5D
         Jm4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=++evECV9nwKSxaMYRtG3Dl+zFkiyxCKX7uNVyUkPMKg=;
        fh=+ssjY8gDudDjHil0tj8NfK+xwgMWn4uePyBSuj+F4bw=;
        b=YhXiHz3bo8qQsdBLKfpHGrX5eZeRZymLLJWGh8zcrLPB0D5L54F2DpC74q+jL0KwVc
         bsmAkL/9aium5uJokAgJK2zkrI5g2ynbctio6VXYvS8prs+SXeiwD1Wr00CYIqPG/zTK
         8TSFvGJepHY/gER+a+PnleChuilUFU04lG3QRPI8CV7CH1o8OAwFMh5F5r1JFS0RSgqP
         1TVNVaid6pdn1D40XqQx6uqNMsG+OHcpFpWtXowcWA3cpx41B0wG+HCpb9DPzIylkui1
         i7fUPSkOJWCH71+pCSFIIu3m33fUFBwpHgmavVn34c+euQd3xzi/XvNf77SIxt9Yfbse
         PfDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Kza/FByE";
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b3bbe5a6518si122840a12.2.2025.07.10.14.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D05CB4364C;
	Thu, 10 Jul 2025 21:31:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 27AEEC4CEF4;
	Thu, 10 Jul 2025 21:30:58 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:30:57 +0200
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
	Andrew Pinski <pinskia@gmail.com>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: [RFC v5 3/7] mm: Use sprintf_end() instead of less ergonomic APIs
Message-ID: <690ed4d22f57a4a1f2c72eb659ceb6b7ab3d5f41.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752182685.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Kza/FByE";       spf=pass
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

While doing this, I detected some anomalies in the existing code:

mm/kfence/kfence_test.c:

	-  The last call to scnprintf() did increment 'cur', but it's
	   unused after that, so it was dead code.  I've removed the dead
	   code in this patch.

	-  'end' is calculated as

		end = &expect[0][sizeof(expect[0] - 1)];

	   However, the '-1' doesn't seem to be necessary.  When passing
	   $2 to scnprintf(), the size was specified as 'end - cur'.
	   And scnprintf() --just like snprintf(3)--, won't write more
	   than $2 bytes (including the null byte).  That means that
	   scnprintf() wouldn't write more than

		&expect[0][sizeof(expect[0]) - 1] - expect[0]

	   which simplifies to

		sizeof(expect[0]) - 1

	   bytes.  But we have sizeof(expect[0]) bytes available, so
	   we're wasting one byte entirely.  This is a benign off-by-one
	   bug.  The two occurrences of this bug will be fixed in a
	   following patch in this series.

mm/kmsan/kmsan_test.c:

	The same benign off-by-one bug calculating the remaining size.

mm/mempolicy.c:

	This file uses the 'p += snprintf()' anti-pattern.  That will
	overflow the pointer on truncation, which has undefined
	behavior.  Using sprintf_end(), this bug is fixed.

	As in the previous file, here there was also dead code in the
	last scnprintf() call, by incrementing a pointer that is not
	used after the call.  I've removed the dead code.

mm/page_owner.c:

	Within print_page_owner(), there are some calls to scnprintf(),
	which do report truncation.  And then there are other calls to
	snprintf(), where we handle errors (there are two 'goto err').

	I've kept the existing error handling, as I trust it's there for
	a good reason (i.e., we may want to avoid calling
	print_page_owner_memcg() if we truncated before).  Please review
	if this amount of error handling is the right one, or if we want
	to add or remove some.  For sprintf_end(), a single test for
	null after the last call is enough to detect truncation.

mm/slub.c:

	Again, the 'p += snprintf()' anti-pattern.  This is UB, and by
	using sprintf_end() we've fixed the bug.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Marco Elver <elver@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Tvrtko Ursulin <tvrtko.ursulin@igalia.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Chao Yu <chao.yu@oppo.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/kfence/kfence_test.c | 24 ++++++++++++------------
 mm/kmsan/kmsan_test.c   |  4 ++--
 mm/mempolicy.c          | 18 +++++++++---------
 mm/page_owner.c         | 32 +++++++++++++++++---------------
 mm/slub.c               |  5 +++--
 5 files changed, 43 insertions(+), 40 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00034e37bc9f..bae382eca4ab 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -113,26 +113,26 @@ static bool report_matches(const struct expect_report *r)
 	end = &expect[0][sizeof(expect[0]) - 1];
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds %s",
+		cur = sprintf_end(cur, end, "BUG: KFENCE: out-of-bounds %s",
 				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_UAF:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free %s",
+		cur = sprintf_end(cur, end, "BUG: KFENCE: use-after-free %s",
 				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_CORRUPTION:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
+		cur = sprintf_end(cur, end, "BUG: KFENCE: memory corruption");
 		break;
 	case KFENCE_ERROR_INVALID:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid %s",
+		cur = sprintf_end(cur, end, "BUG: KFENCE: invalid %s",
 				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
+		cur = sprintf_end(cur, end, "BUG: KFENCE: invalid free");
 		break;
 	}
 
-	scnprintf(cur, end - cur, " in %pS", r->fn);
+	sprintf_end(cur, end, " in %pS", r->fn);
 	/* The exact offset won't match, remove it; also strip module name. */
 	cur = strchr(expect[0], '+');
 	if (cur)
@@ -144,26 +144,26 @@ static bool report_matches(const struct expect_report *r)
 
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
-		cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
+		cur = sprintf_end(cur, end, "Out-of-bounds %s at", get_access_type(r));
 		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_UAF:
-		cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
+		cur = sprintf_end(cur, end, "Use-after-free %s at", get_access_type(r));
 		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_CORRUPTION:
-		cur += scnprintf(cur, end - cur, "Corrupted memory at");
+		cur = sprintf_end(cur, end, "Corrupted memory at");
 		break;
 	case KFENCE_ERROR_INVALID:
-		cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
+		cur = sprintf_end(cur, end, "Invalid %s at", get_access_type(r));
 		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
-		cur += scnprintf(cur, end - cur, "Invalid free of");
+		cur = sprintf_end(cur, end, "Invalid free of");
 		break;
 	}
 
-	cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
+	sprintf_end(cur, end, " 0x%p", (void *)addr);
 
 	spin_lock_irqsave(&observed.lock, flags);
 	if (!report_available())
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 9733a22c46c1..e48ca1972ff3 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -107,9 +107,9 @@ static bool report_matches(const struct expect_report *r)
 	cur = expected_header;
 	end = &expected_header[sizeof(expected_header) - 1];
 
-	cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);
+	cur = sprintf_end(cur, end, "BUG: KMSAN: %s", r->error_type);
 
-	scnprintf(cur, end - cur, " in %s", r->symbol);
+	sprintf_end(cur, end, " in %s", r->symbol);
 	/* The exact offset won't match, remove it; also strip module name. */
 	cur = strchr(expected_header, '+');
 	if (cur)
diff --git a/mm/mempolicy.c b/mm/mempolicy.c
index b28a1e6ae096..6beb2710f97c 100644
--- a/mm/mempolicy.c
+++ b/mm/mempolicy.c
@@ -3359,6 +3359,7 @@ int mpol_parse_str(char *str, struct mempolicy **mpol)
 void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
 {
 	char *p = buffer;
+	char *e = buffer + maxlen;
 	nodemask_t nodes = NODE_MASK_NONE;
 	unsigned short mode = MPOL_DEFAULT;
 	unsigned short flags = 0;
@@ -3384,33 +3385,32 @@ void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol)
 		break;
 	default:
 		WARN_ON_ONCE(1);
-		snprintf(p, maxlen, "unknown");
+		sprintf_end(p, e, "unknown");
 		return;
 	}
 
-	p += snprintf(p, maxlen, "%s", policy_modes[mode]);
+	p = sprintf_end(p, e, "%s", policy_modes[mode]);
 
 	if (flags & MPOL_MODE_FLAGS) {
-		p += snprintf(p, buffer + maxlen - p, "=");
+		p = sprintf_end(p, e, "=");
 
 		/*
 		 * Static and relative are mutually exclusive.
 		 */
 		if (flags & MPOL_F_STATIC_NODES)
-			p += snprintf(p, buffer + maxlen - p, "static");
+			p = sprintf_end(p, e, "static");
 		else if (flags & MPOL_F_RELATIVE_NODES)
-			p += snprintf(p, buffer + maxlen - p, "relative");
+			p = sprintf_end(p, e, "relative");
 
 		if (flags & MPOL_F_NUMA_BALANCING) {
 			if (!is_power_of_2(flags & MPOL_MODE_FLAGS))
-				p += snprintf(p, buffer + maxlen - p, "|");
-			p += snprintf(p, buffer + maxlen - p, "balancing");
+				p = sprintf_end(p, e, "|");
+			p = sprintf_end(p, e, "balancing");
 		}
 	}
 
 	if (!nodes_empty(nodes))
-		p += scnprintf(p, buffer + maxlen - p, ":%*pbl",
-			       nodemask_pr_args(&nodes));
+		sprintf_end(p, e, ":%*pbl", nodemask_pr_args(&nodes));
 }
 
 #ifdef CONFIG_SYSFS
diff --git a/mm/page_owner.c b/mm/page_owner.c
index cc4a6916eec6..c00b3be01540 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -496,7 +496,7 @@ void pagetypeinfo_showmixedcount_print(struct seq_file *m,
 /*
  * Looking for memcg information and print it out
  */
-static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
+static inline char *print_page_owner_memcg(char *p, const char end[0],
 					 struct page *page)
 {
 #ifdef CONFIG_MEMCG
@@ -511,8 +511,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 		goto out_unlock;
 
 	if (memcg_data & MEMCG_DATA_OBJEXTS)
-		ret += scnprintf(kbuf + ret, count - ret,
-				"Slab cache page\n");
+		p = sprintf_end(p, end, "Slab cache page\n");
 
 	memcg = page_memcg_check(page);
 	if (!memcg)
@@ -520,7 +519,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 
 	online = (memcg->css.flags & CSS_ONLINE);
 	cgroup_name(memcg->css.cgroup, name, sizeof(name));
-	ret += scnprintf(kbuf + ret, count - ret,
+	p = sprintf_end(p, end,
 			"Charged %sto %smemcg %s\n",
 			PageMemcgKmem(page) ? "(via objcg) " : "",
 			online ? "" : "offline ",
@@ -529,7 +528,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 	rcu_read_unlock();
 #endif /* CONFIG_MEMCG */
 
-	return ret;
+	return p;
 }
 
 static ssize_t
@@ -538,14 +537,16 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
 		depot_stack_handle_t handle)
 {
 	int ret, pageblock_mt, page_mt;
-	char *kbuf;
+	char *kbuf, *p, *e;
 
 	count = min_t(size_t, count, PAGE_SIZE);
 	kbuf = kmalloc(count, GFP_KERNEL);
 	if (!kbuf)
 		return -ENOMEM;
 
-	ret = scnprintf(kbuf, count,
+	p = kbuf;
+	e = kbuf + count;
+	p = sprintf_end(p, e,
 			"Page allocated via order %u, mask %#x(%pGg), pid %d, tgid %d (%s), ts %llu ns\n",
 			page_owner->order, page_owner->gfp_mask,
 			&page_owner->gfp_mask, page_owner->pid,
@@ -555,7 +556,7 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
 	/* Print information relevant to grouping pages by mobility */
 	pageblock_mt = get_pageblock_migratetype(page);
 	page_mt  = gfp_migratetype(page_owner->gfp_mask);
-	ret += scnprintf(kbuf + ret, count - ret,
+	p = sprintf_end(p, e,
 			"PFN 0x%lx type %s Block %lu type %s Flags %pGp\n",
 			pfn,
 			migratetype_names[page_mt],
@@ -563,22 +564,23 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
 			migratetype_names[pageblock_mt],
 			&page->flags);
 
-	ret += stack_depot_snprint(handle, kbuf + ret, count - ret, 0);
-	if (ret >= count)
-		goto err;
+	p = stack_depot_sprint_end(handle, p, e, 0);
+	if (p == NULL)
+		goto err;  // XXX: Should we remove this error handling?
 
 	if (page_owner->last_migrate_reason != -1) {
-		ret += scnprintf(kbuf + ret, count - ret,
+		p = sprintf_end(p, e,
 			"Page has been migrated, last migrate reason: %s\n",
 			migrate_reason_names[page_owner->last_migrate_reason]);
 	}
 
-	ret = print_page_owner_memcg(kbuf, count, ret, page);
+	p = print_page_owner_memcg(p, e, page);
 
-	ret += snprintf(kbuf + ret, count - ret, "\n");
-	if (ret >= count)
+	p = sprintf_end(p, e, "\n");
+	if (p == NULL)
 		goto err;
 
+	ret = p - kbuf;
 	if (copy_to_user(buf, kbuf, ret))
 		ret = -EFAULT;
 
diff --git a/mm/slub.c b/mm/slub.c
index be8b09e09d30..dcc857676857 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -7451,6 +7451,7 @@ static char *create_unique_id(struct kmem_cache *s)
 {
 	char *name = kmalloc(ID_STR_LENGTH, GFP_KERNEL);
 	char *p = name;
+	char *e = name + ID_STR_LENGTH;
 
 	if (!name)
 		return ERR_PTR(-ENOMEM);
@@ -7475,9 +7476,9 @@ static char *create_unique_id(struct kmem_cache *s)
 		*p++ = 'A';
 	if (p != name + 1)
 		*p++ = '-';
-	p += snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size);
+	p = sprintf_end(p, e, "%07u", s->size);
 
-	if (WARN_ON(p > name + ID_STR_LENGTH - 1)) {
+	if (WARN_ON(p == NULL)) {
 		kfree(name);
 		return ERR_PTR(-EINVAL);
 	}
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/690ed4d22f57a4a1f2c72eb659ceb6b7ab3d5f41.1752182685.git.alx%40kernel.org.
