Return-Path: <kasan-dev+bncBAABBNMYU3BQMGQEQKJFAYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA7A5AFA1CC
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jul 2025 22:33:58 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6fe182a48acsf55474786d6.1
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jul 2025 13:33:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751747637; cv=pass;
        d=google.com; s=arc-20240605;
        b=dTv2WKtu843iUnYZzcB5eA0MD+5Tc1CaQQQoIbG4jHsoTMzl9IsHS8utnWG4Yvg3OV
         stcFOEcBmRFFLF6aqJvb3+wy+yQYqPV7Muhm0JqA9rbgp98fiB6guOAyXQvirn/Ogj8E
         /EEACLxPawRjePKj2srZlKjV3JR7aUcb/hQMay924qPHspLbtRpIh3pBDWAMP21lV0F2
         FyFQMqDsBPcx01z0NJYwY80hlEQ+1ZeW3eOPVyvKW/Y5G5R5GBDSwSwB/wHDIBfNr82Y
         HnqyWrEkPrYGahBP62yBuiob3YQ1ICLD7rAb9hwGQ+mZRCQ0NQMZWGHDM4VMntsOJYYL
         lNQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Pv0LyHNrzfvIgPr+xSreItC6OQ6zFZ4rjcE8vbAeK/M=;
        fh=fH8jrDdrUc4tWrdDxaZXc4QmO0/RLYCNHJC8JmJE9uM=;
        b=PobO2sTXdvaj2A4z5dg/MGecwd9OY4ohdiRStcL336uuDP1txsfaF42kmDAGdUHTTV
         0smUujl9dM8zfiK4XQ2wFdF3QSKtZXRKRh5t3jehkCaSUmg8RepBaVUi7vQwmb41UQA1
         mCoSs9c9TRM/kLXdxY0m40ZXOy2LD0HQo/7Yg4kKsOfZRYQbXtcsO2hdj5GCvAF4f3R4
         jas+JvctSD8CoKq5qs4LagGVReRG562bQiE/P/7Z0ImbN0Qhi1BC6WprWYAjjsoSsuPM
         TX9c/2Ji7em5iNZOJuQjfnEFbhHvJ722SHdN5iR+6EarIiIE+RG+5gwdMc15JBBZ6NUz
         5QTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hyxkMuLH;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751747637; x=1752352437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Pv0LyHNrzfvIgPr+xSreItC6OQ6zFZ4rjcE8vbAeK/M=;
        b=AKKNEJfMFuAvalzCw5ztlOcEviir/rzYcT3rcxJJxLjO9NNWFCl5CPHZ0BkKqQ2t9Z
         BV8/gHjYlUWsBhXFDtXh0mAHuaXcJ78MZ/yH9kqPWRB930JKESm3PGZwBj2vlWgpD9Ye
         Hn5+u/UU8CYRzl8/MF1YspLIC/4fyCVO+P+GbVzq3XyMhQ/NfkwkY/bMRZtZKFAkTd5e
         1OLYW3/kYFoqBzsQ2mzgLgykJfOwUJTUDWtghFNdp6IXlAQGiT7OY/e90NirE0L5cSl7
         P/tj8HsRdRrcX1/qNobu9h7U/mGXmZOSZl43f4QGsXjXXmLrRy9zxmGGES9GBPVObmeB
         tJRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751747637; x=1752352437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Pv0LyHNrzfvIgPr+xSreItC6OQ6zFZ4rjcE8vbAeK/M=;
        b=OE+hRJlQz3iASfQH8Yj3W6RojM3ceim+iFI7WTfG5/PlZv9Vwv+tlYLXoqAlsOwGM8
         4bt+A7QdFTGE0SMYLyvvBIvD4sC6+/osN9ohb+x8QJD1bIS7gj2P0OXioWg2MGETJJpQ
         MYmu5OTXqvSXu6SHrLOaGcuGUTBTAZ0DX9dahjZpn7h25vhMefJniZ9kvBXFrw8AJA3R
         zEQ73cVwGm4WJfpmpe5hkKKy6r+3DsJNN6xGG9qbjqmnF7gPXEb0BqPmRa8rLm19R+2E
         IqOPdfLdNXEMwBNfDMOl/lL8LWcwe2J6YXQjV3XEfgskgxtTOHKByI9u+sz6K4J40tdK
         1fvw==
X-Forwarded-Encrypted: i=2; AJvYcCX0qMa09qxTkeDZBurKn+Y4+tQGLxL/CQFbXGfVMdT5XJY+lPxmi4kNoNUcSU3leBOpbiqAMw==@lfdr.de
X-Gm-Message-State: AOJu0YwcU4a7T5sjRoww9WsSKqzA+hWhDlH0/yHCdTGWaWbfkF+WG22Q
	6w3jvbnIzZ1Ud/S4EQKFzXPlcMeDi8/S+voJN3AeenjDRIrwHmNjW78Y
X-Google-Smtp-Source: AGHT+IF/PGi/8E6oXxplcKwoRaFEjFYH68bDY9l/fMZcNCBu1zYLbwqw/6HQwAhRsCI4WAIRFMK/lQ==
X-Received: by 2002:a0c:f11a:0:b0:6fa:c5f8:67eb with SMTP id 6a1803df08f44-702c4e2136bmr109479996d6.7.1751747637383;
        Sat, 05 Jul 2025 13:33:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgUCIYHmzCmVmqM8POdPkSYGo1Y/jZcPbFvkIwRydI6A==
Received: by 2002:ad4:5f4c:0:b0:6fa:bd03:fbf2 with SMTP id 6a1803df08f44-702c9a87e80ls19555656d6.0.-pod-prod-00-us;
 Sat, 05 Jul 2025 13:33:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeEZVD2fQl8na71z0mHwluS+21uMlZ53LJE/uz+c04A1PbFbgjhPaQtZwpoS04P/dJqQ/V7kDkVd0=@googlegroups.com
X-Received: by 2002:a05:6102:802a:b0:4e7:b77d:7fe1 with SMTP id ada2fe7eead31-4f2edd9eafbmr5344284137.0.1751747636714;
        Sat, 05 Jul 2025 13:33:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751747636; cv=none;
        d=google.com; s=arc-20240605;
        b=Nxhz0nY3eituHJ7RdpKfqd48P8SCXBsI5q2PHC0FzVhAbs5bGZmUS4B8T0kZI5OATO
         mPza1L4i3mY68Tm/v/LTLSTPZuSuACULO5zYfW40QHyXMAujghVe/HGYlzQf+5Fihu/R
         HDlFbntLlXqHhr2qq+XvQm7TOFPvFVbqZ8KihW1iH4sHyoye1ei5BoRf/086pamMKe1E
         C0AG0wuNceMrNglIN4f68Kod+jY3/anrbh2FkaFMSQprsifWcbvcU57VTAsozB7xiw/R
         s3QQt9gM6TaMBtYAt4XB6hJ6vbBtJs+tdIYUYQc2L0y02HIHA+IjQNNeHib/CgkOtGp5
         v7hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=SKUhT72pREpFFvTPgusC6Oi417qItSWqjk1WNUt7Xnc=;
        fh=ajsM17EAOL6Fxaw3DPHvK/x1BqMY4iRD4b26QdTsiIc=;
        b=bE5Txu4U8ZmaOyihtcE93QzV856HudHI9/sws6nF70aTLpPUydrvnFZbQdZYSufoY2
         K33AcTk8YE05doarBJx4Mvq/nms2GrmRGbUBA2V5zFBGsQQSHZJHZciAjzuOx1peZDlR
         q6hPY2XU0kP9GNAEftOQbmKICMeKAoxiDB7AoSdyUPn0t2hykDwbMwiwTWkSeD8u03sv
         lesSFC6Cp4nxpLM+UnoVR9TFUPYsYPuqTand0BD24LUn/fNg8NPUTMsPH5fnfDvSiP1/
         Qah+2zb+ydozO7vC5zEz5IM53QYFL1AZkReYAlVUbp3W8OwuFwJNT1ZEQBFHBCwED9DD
         lFAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hyxkMuLH;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4f2ea18d523si171619137.0.2025.07.05.13.33.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Jul 2025 13:33:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id F3CBF61447;
	Sat,  5 Jul 2025 20:33:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B311BC4CEF2;
	Sat,  5 Jul 2025 20:33:54 +0000 (UTC)
Date: Sat, 5 Jul 2025 22:33:53 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: [RFC v1 3/3] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <be193e1856aaf40f0e6dc44bb2e22ab0688203af.1751747518.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751747518.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751747518.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hyxkMuLH;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted
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

	The last call to scnprintf() did increment 'cur', but it's
	unused after that, so it was dead code.  I've removed the dead
	code in this patch.

mm/mempolicy.c:

	This file uses the 'p += snprintf()' anti-pattern.  That will
	overflow the pointer on truncation, which has undefined
	behavior.  Using seprintf(), this bug is fixed.

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
	to add or remove some.  For seprintf(), a single test for null
	after the last call is enough to detect truncation.

mm/slub.c:

	Again, the 'p += snprintf()' anti-pattern.  This is UB, and by
	using seprintf() we've fixed the bug.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/kfence/kfence_test.c | 24 ++++++++++++------------
 mm/kmsan/kmsan_test.c   |  4 ++--
 mm/mempolicy.c          | 18 +++++++++---------
 mm/page_owner.c         | 32 +++++++++++++++++---------------
 mm/slub.c               |  5 +++--
 5 files changed, 43 insertions(+), 40 deletions(-)

diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00034e37bc9f..ff734c514c03 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -113,26 +113,26 @@ static bool report_matches(const struct expect_report *r)
 	end = &expect[0][sizeof(expect[0]) - 1];
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds %s",
+		cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
 				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_UAF:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free %s",
+		cur = seprintf(cur, end, "BUG: KFENCE: use-after-free %s",
 				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_CORRUPTION:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
+		cur = seprintf(cur, end, "BUG: KFENCE: memory corruption");
 		break;
 	case KFENCE_ERROR_INVALID:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid %s",
+		cur = seprintf(cur, end, "BUG: KFENCE: invalid %s",
 				 get_access_type(r));
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
-		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
+		cur = seprintf(cur, end, "BUG: KFENCE: invalid free");
 		break;
 	}
 
-	scnprintf(cur, end - cur, " in %pS", r->fn);
+	seprintf(cur, end, " in %pS", r->fn);
 	/* The exact offset won't match, remove it; also strip module name. */
 	cur = strchr(expect[0], '+');
 	if (cur)
@@ -144,26 +144,26 @@ static bool report_matches(const struct expect_report *r)
 
 	switch (r->type) {
 	case KFENCE_ERROR_OOB:
-		cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
+		cur = seprintf(cur, end, "Out-of-bounds %s at", get_access_type(r));
 		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_UAF:
-		cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
+		cur = seprintf(cur, end, "Use-after-free %s at", get_access_type(r));
 		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_CORRUPTION:
-		cur += scnprintf(cur, end - cur, "Corrupted memory at");
+		cur = seprintf(cur, end, "Corrupted memory at");
 		break;
 	case KFENCE_ERROR_INVALID:
-		cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
+		cur = seprintf(cur, end, "Invalid %s at", get_access_type(r));
 		addr = arch_kfence_test_address(addr);
 		break;
 	case KFENCE_ERROR_INVALID_FREE:
-		cur += scnprintf(cur, end - cur, "Invalid free of");
+		cur = seprintf(cur, end, "Invalid free of");
 		break;
 	}
 
-	cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
+	seprintf(cur, end, " 0x%p", (void *)addr);
 
 	spin_lock_irqsave(&observed.lock, flags);
 	if (!report_available())
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 9733a22c46c1..a062a46b2d24 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -107,9 +107,9 @@ static bool report_matches(const struct expect_report *r)
 	cur = expected_header;
 	end = &expected_header[sizeof(expected_header) - 1];
 
-	cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);
+	cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
 
-	scnprintf(cur, end - cur, " in %s", r->symbol);
+	seprintf(cur, end, " in %s", r->symbol);
 	/* The exact offset won't match, remove it; also strip module name. */
 	cur = strchr(expected_header, '+');
 	if (cur)
diff --git a/mm/mempolicy.c b/mm/mempolicy.c
index b28a1e6ae096..c696e4a6f4c2 100644
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
+		seprintf(p, e, "unknown");
 		return;
 	}
 
-	p += snprintf(p, maxlen, "%s", policy_modes[mode]);
+	p = seprintf(p, e, "%s", policy_modes[mode]);
 
 	if (flags & MPOL_MODE_FLAGS) {
-		p += snprintf(p, buffer + maxlen - p, "=");
+		p = seprintf(p, e, "=");
 
 		/*
 		 * Static and relative are mutually exclusive.
 		 */
 		if (flags & MPOL_F_STATIC_NODES)
-			p += snprintf(p, buffer + maxlen - p, "static");
+			p = seprintf(p, e, "static");
 		else if (flags & MPOL_F_RELATIVE_NODES)
-			p += snprintf(p, buffer + maxlen - p, "relative");
+			p = seprintf(p, e, "relative");
 
 		if (flags & MPOL_F_NUMA_BALANCING) {
 			if (!is_power_of_2(flags & MPOL_MODE_FLAGS))
-				p += snprintf(p, buffer + maxlen - p, "|");
-			p += snprintf(p, buffer + maxlen - p, "balancing");
+				p = seprintf(p, e, "|");
+			p = seprintf(p, e, "balancing");
 		}
 	}
 
 	if (!nodes_empty(nodes))
-		p += scnprintf(p, buffer + maxlen - p, ":%*pbl",
-			       nodemask_pr_args(&nodes));
+		seprintf(p, e, ":%*pbl", nodemask_pr_args(&nodes));
 }
 
 #ifdef CONFIG_SYSFS
diff --git a/mm/page_owner.c b/mm/page_owner.c
index cc4a6916eec6..5811738e3320 100644
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
+		p = seprintf(p, end, "Slab cache page\n");
 
 	memcg = page_memcg_check(page);
 	if (!memcg)
@@ -520,7 +519,7 @@ static inline int print_page_owner_memcg(char *kbuf, size_t count, int ret,
 
 	online = (memcg->css.flags & CSS_ONLINE);
 	cgroup_name(memcg->css.cgroup, name, sizeof(name));
-	ret += scnprintf(kbuf + ret, count - ret,
+	p = seprintf(p, end,
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
+	p = seprintf(p, e,
 			"Page allocated via order %u, mask %#x(%pGg), pid %d, tgid %d (%s), ts %llu ns\n",
 			page_owner->order, page_owner->gfp_mask,
 			&page_owner->gfp_mask, page_owner->pid,
@@ -555,7 +556,7 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
 	/* Print information relevant to grouping pages by mobility */
 	pageblock_mt = get_pageblock_migratetype(page);
 	page_mt  = gfp_migratetype(page_owner->gfp_mask);
-	ret += scnprintf(kbuf + ret, count - ret,
+	p = seprintf(p, e,
 			"PFN 0x%lx type %s Block %lu type %s Flags %pGp\n",
 			pfn,
 			migratetype_names[page_mt],
@@ -563,22 +564,23 @@ print_page_owner(char __user *buf, size_t count, unsigned long pfn,
 			migratetype_names[pageblock_mt],
 			&page->flags);
 
-	ret += stack_depot_snprint(handle, kbuf + ret, count - ret, 0);
-	if (ret >= count)
-		goto err;
+	p = stack_depot_seprint(handle, p, e, 0);
+	if (p == NULL)
+		goto err;  // XXX: Should we remove this error handling?
 
 	if (page_owner->last_migrate_reason != -1) {
-		ret += scnprintf(kbuf + ret, count - ret,
+		p = seprintf(p, e,
 			"Page has been migrated, last migrate reason: %s\n",
 			migrate_reason_names[page_owner->last_migrate_reason]);
 	}
 
-	ret = print_page_owner_memcg(kbuf, count, ret, page);
+	p = print_page_owner_memcg(p, e, page);
 
-	ret += snprintf(kbuf + ret, count - ret, "\n");
-	if (ret >= count)
+	p = seprintf(p, e, "\n");
+	if (p == NULL)
 		goto err;
 
+	ret = p - kbuf;
 	if (copy_to_user(buf, kbuf, ret))
 		ret = -EFAULT;
 
diff --git a/mm/slub.c b/mm/slub.c
index be8b09e09d30..b67c6ca0d0f7 100644
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
+	p = seprintf(p, e, "%07u", s->size);
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/be193e1856aaf40f0e6dc44bb2e22ab0688203af.1751747518.git.alx%40kernel.org.
