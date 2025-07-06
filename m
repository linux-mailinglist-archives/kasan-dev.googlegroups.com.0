Return-Path: <kasan-dev+bncBAABBZPIVLBQMGQEW6OE7EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CCABAAFA6E5
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jul 2025 19:37:43 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e0513ec553sf58750265ab.3
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 10:37:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751823462; cv=pass;
        d=google.com; s=arc-20240605;
        b=AiFTYrmu9usdpEn2m33HimznZs8vK0VwOYsSb38oh81fFRSbrMLDGKGggJXrnQ1bYv
         lxuObKAUoUkfIMENNtOFGA1nDrTROCX5ZDIvTefsR20Xw+KbnTT1x2QSpKoJye5nvoWV
         qWDOqLt5YWNo4MVr1Tx/epQu+fmV0dhBSU4CIowWr7x7Pew5+fuLxzBxbxjUnwMFI9Yy
         hL+ZojXcnzoWB6Py9oQiR6gpfKEZ0AmGTkPB3KmdVTCex9Ec/ZyOSf3B9iDRey90xoYZ
         MJ2Cf8oBDZ7ZGlX2g09cVanxnOkFkcWYko22nMP3D67FAF52pGzgWaZNDQgTBfRG/IsQ
         2kEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Ye53Z03CwiCM/HcxLk81mx5qSka2zkHGN4xfSlk1F+Y=;
        fh=HzyezWPpEUm2g3faIooKLvVTIEayjBNlAVUFtvb2Rjw=;
        b=g6QCS6cTd8yfrkfjcvksVPXyM6vDzG2LxmHV5pCY1bBVIMETSh60llrC1oM9f3mB9Y
         ghKcwXV3H+D/LekLYkUOtlpAZvrlt1aW6LJ+Z0GBX3LorFSvexawvPN4USvQsfxugDG/
         20s1Icd1myPUBCZFxsUVzqSxz8xyAbVdofWqBSO7scePT7l9O9X9F7bcE8pncC2FOBef
         E7AXUW9Dz+8RJDHSNlspXCFl1gp/5b7kKKcNKsr2yo0P2GXd/v7tx7LBnTtsbMWHd6Xz
         4ddx4YQ+6vGbAX+WBm25BNCP4WHBZKrZKv1/sObDTg7fdrfr6H+4PHutz9XR+BZmTJZZ
         gDpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=g1weyM3h;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751823462; x=1752428262; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Ye53Z03CwiCM/HcxLk81mx5qSka2zkHGN4xfSlk1F+Y=;
        b=QIty+Wk/v65iOf2UQsvJdei8UQ/F5MdVl09xf6PNyISZ+u2OKqA2Mw2z4EhqmVKX1C
         pC/nipa1Y9u9d4n/u05IOFszjbSXbAobJVxYVyllht3MuSHaSmcgoi+vAEW/ezWjvAvw
         BUGDuXTh6Ww2UePNgPqyz/vnbn+iHg21EMBO9RjT6+ep3yQ9c5Cikqm9k7fTxv12rnpy
         +zyg7oi5yVcCsLgxuPVfiANC1mfxHvJVjOPyBpm+gRYHMdFiw9qr1LwPmVl7IKOgemS/
         1GduRlMnA8OiMbRJhQD3xZkB4L2IuCnoLXDdZyPYzG4AuJm06ebcY+3nu9HCm5kFLY6C
         foBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751823462; x=1752428262;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ye53Z03CwiCM/HcxLk81mx5qSka2zkHGN4xfSlk1F+Y=;
        b=P+JoqCi6bWVsAeff3kwsIVXVwGAQe2nMfiYqyQlJPJ0P698qbsPwl9ELb8UxQrlRso
         e6JYdgPjG/G/nQC+mptJJ3aBTxyOxl7pTT1Sketb/tsGrHX2pxnHIbXI8qAVyOfbl2L5
         W2lHVB0e6rOZtjJGMsWHsNavva2curN04CYNwDrijwWdeYc8yUBfs19zMVz7sE4UXQ/v
         Jl1W8B4QnP9VpAPXpRKTwIAZ1SWvSVXAEDeGbc0A4Iy8cztHTaSDNHu/srLy/H01lwEx
         6Byp+psvOH0Fe4qfx71Ud5+Pl6TV4LbAjY15DSMvbfK394YZUEJT6dtPAGD8zPg1ezym
         N3SA==
X-Forwarded-Encrypted: i=2; AJvYcCVk1+Mnccs+zxGD9jbWVN3PdVKubNjZbB0sDlcGhZG9XsJHrmHNmUzB5N8sqt9ur8/NI7mSFQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz5AHg4fDKM23BD1Rc2oxl/j2ld41FFyb++uVRPTlMSFMSGBk4C
	lwR2jXTC0lM+75sQ0CkYlmb5rVM5VP5yR+rXU/Po3HZhN80Ls7yiUbDz
X-Google-Smtp-Source: AGHT+IEzCmzpbBbTG4aFXj1ZYJTLYyuUBJs/hjYsFS+DADB2qeQCo1TR/Um3DWUb1/J76Pc4OHkgVg==
X-Received: by 2002:a05:6e02:1c0b:b0:3dc:79e5:e696 with SMTP id e9e14a558f8ab-3e13ef0c7a1mr42680635ab.11.1751823462082;
        Sun, 06 Jul 2025 10:37:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7lSv2UUI5QvcrA2BaD9pXC/I5xwO6Oil/zez+cznMzg==
Received: by 2002:a05:6e02:4711:b0:3dd:c019:a6a with SMTP id
 e9e14a558f8ab-3e1391e5230ls13264585ab.2.-pod-prod-01-us; Sun, 06 Jul 2025
 10:37:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDnEaErfxN9D+REFBdQtFt2pB89gCAurjfrbbUOX/NvU4jOwD86kHkosCf7DRY0AL9bnlMIFVvdVY=@googlegroups.com
X-Received: by 2002:a05:6602:2d92:b0:875:b255:e6af with SMTP id ca18e2360f4ac-8792a50f5dbmr512892239f.10.1751823461155;
        Sun, 06 Jul 2025 10:37:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751823461; cv=none;
        d=google.com; s=arc-20240605;
        b=PWuVcITd+7nHuz/rvpeSCeN+UHC+A4X8APA6XH3aeQPKTyDEmobVyMQAl3wc4todUs
         P/7bPJtrDMed4ZSN4wpPriHNB4w5KzioFVp3/kCCkTnudLHyIqaLORAgyjy2S+ajLtAM
         uJwUvXvR1iyMjQICfeS/zO/rPnydwsrxdUm1x6SPw7DdkDW40hCuWuboBr9t+CRr1RSj
         W8JfVLyO7/VlXA5a1xoupz/171hu85sqDBmJIS+XRc0KXQUweCHGn/8IkzPp/w3iq2EB
         V79kGYx79FN4y/XNEc3nqtUa23v++7HgwkJp0kIRbD0KassQoM6FTrrfyjnaa65fM1g7
         QAOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CQfkzGusDwtQzmnReCw6XndOY9KoVaoA+Gha4lav0sg=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=RzCqf4VOs0ALLkNuE6SrNVxPw9QMY5+K3CFdMYen7UrhT/qfkr+xxkM3TimfVFXalo
         kd1nDcFjIiGMcDC+B8LlZfuJVfQ9HnHwiRoM4HTt3AXVa2o1raPiZ2jMnrVK/Sx5Plg1
         IoOm8Vzx/gLH6r/zrePYMnEDyKVBdbA0NeENJx79xQ1FL17uW5Df/V7Y4G4XYnoOoCZF
         /sGwpKikIEIfJ5F8j1EfPPtL7rN1AxSSEUtVObZJgrkdO2yZiG2/CHy9gQ65W/36BtIY
         rNxnu67CG/EcKfUG0cEJcn+RmOjw1aeMQC7p86CtUprURu+XY49M2a1jGOKFHT+YmIcx
         bZzA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=g1weyM3h;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-503b5bf5b11si299833173.7.2025.07.06.10.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 10:37:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7E6196114F;
	Sun,  6 Jul 2025 17:37:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 34891C4CEEE;
	Sun,  6 Jul 2025 17:37:39 +0000 (UTC)
Date: Sun, 6 Jul 2025 19:37:38 +0200
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
Subject: [RFC v2 3/5] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <e3271b5f2ad9fe1282c8e6892a15984b9e316340.1751823326.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=g1weyM3h;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e3271b5f2ad9fe1282c8e6892a15984b9e316340.1751823326.git.alx%40kernel.org.
