Return-Path: <kasan-dev+bncBAABBR5LVXBQMGQEVTLIWUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id BD025AFAAB4
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:16 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3df3b71b987sf23465865ab.0
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864775; cv=pass;
        d=google.com; s=arc-20240605;
        b=K7evnx+gsndLVFv4S2D7KEkzgfGgrIldtq2swB9z2ao2grsR1i3qwOABNjjNRl7Gls
         pTuMbMtjkNjC4l1bXWle8P6xFkYlanN/faDuJFfaZ3z88DsjqFs4m7DBgdgYaKbuBUbS
         2jMgoXtI2T9FMfWg+lJfM3TlQthDMPjHDj9QzqPBM/amlt8UWEVCIJfhGQqos4tjqyCd
         pnr32I+C5AxrdMheFRSLNkAyTRxWuPan5h0rbMmp/ojMqFdwDT5wRII0t1NoHrAhoQJB
         /v/TdOTdiDkWdlUTAK31GrFBu2gsolLAXjHIC6/1gMRi8C+8td/HncP/SXY/QFt9MVeF
         PQ6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Hua5Cg+RxkKxUD5imu8UupZDUVc7WdjZ6TgQ6G3r+KM=;
        fh=QbE2aXPrtfHDRfOQGzixI9Mjgru4fRsM+T2JHn1D1H8=;
        b=PEyXyNP9sNzR1SiXCOk5pIxeK9smHTVEuvxQxQxVuGmHVe+ni0LJ3TeQGqn3bRdQWw
         tbOYvJvuC9dPYFWsZ5NxH/38lzIUorYWiZ1Rn0wFAunhcyxJBhih/t49m2xrhez435lk
         ix1z45urEjTG6bLjBVUaNpoUaw+q9pDFCNYvnS8wnxAVcEBc0nPFg5Il5G1z+Jsu59KE
         2y0Qx//dRi6ooBn2Lsz0q1GpBPkNMNS/mRklRcaXISeCnUt5iGIwx0mkxJSXWKcNLSvO
         k3xUkfBqOh1+JUIblcCGjxcFR5EXhayvidQCpwoVt+WD6OZVWnSaTQWujwuonszoV3WR
         2vOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BE1I5vs3;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864775; x=1752469575; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Hua5Cg+RxkKxUD5imu8UupZDUVc7WdjZ6TgQ6G3r+KM=;
        b=jwFGUJVMvmYc9sq7qZKZSnhJB1F6mL/ZxY2IzgSOJxMXpdtrI+PnZaugvQpRzRbz4L
         3M6T5M4YaxXmsnkZ6ixmE51unGTHCmtHEN+Q2HvlNNcVdWo+kLIZ1fzMoaimlmRRVxjO
         52nCIarr5dEXca/2xpA8hxpm9s3SEOjNIY+FJSMXHfeB2WpjUmR4mzjv/t9BVzHPsXTh
         0G7jO4UcDC39m/8vYxNeO34OvqVVaBnr/ZBFgQz79iJ9w09qehVGGN5df4SowiwqSQN2
         BPSZF2WKW+lgzwPNImsQnZhTqG1MAOstPbEIc/PS+9Jkae9FKK4zKOlXkv0JLYyo4nbX
         yPeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864775; x=1752469575;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hua5Cg+RxkKxUD5imu8UupZDUVc7WdjZ6TgQ6G3r+KM=;
        b=lqMUWmhj1GccGhiclgE0bW0x7LXRDFqP+Nx8NXsbQPahwCcthpFZ3zv3aMUJudpJhh
         lazD2avCeg7sm/5MTqNFw1WXWY9CGzSJ8b9GIJ54J2rUU6MEKfrllBDgtFiAaGCDqU35
         1TCcNgk2lbjPQ/X7n/RzWSAabfzeV/1P2h/3TLj/jLGNv7QJJmTb11iVbTBn2TawnZQ2
         2L1CjiQt8mVxDYbqQ0y9D2OXAlAMwRK6YvaiEsPejAAk2dOlPUFcASxmib3IxdkncqQn
         Mc3y1ShpEbbKiAIQStLRLtKSPaT7FhjPPjGARF2XzIlBNeHAwEqL3BuUZbgJ+QXeSawI
         Meog==
X-Forwarded-Encrypted: i=2; AJvYcCVfiUByBfyFnNo42v2GLzMnJjSxkHsGgYi9byDLTboNS9bepNEKmUBqNydsfPoZuru0QRs/YQ==@lfdr.de
X-Gm-Message-State: AOJu0YxhLkaAi+zy4c/B0ZrWtA6DotGckoxopoKV3Bi95O9bvyJWSrFj
	ajYduNeaJS4j4H5m78C9kN5VYyse2txpvSULemoup9AJW+W16EBF74YL
X-Google-Smtp-Source: AGHT+IH5+FsFEDvBr/BvWyrUNfFVUu1DWYzoQFHvMdW8xIlKGLSmld7J9dELmNjUpXb1F5PGG5Pw7A==
X-Received: by 2002:a05:6e02:3a03:b0:3df:4024:9402 with SMTP id e9e14a558f8ab-3e136f062c4mr101535935ab.8.1751864775283;
        Sun, 06 Jul 2025 22:06:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZffaR9HBppPAlZzoa7+ECWiXZxCwCUpn0rMXbWuBU2PoQ==
Received: by 2002:a05:6e02:4716:b0:3dc:6311:bf8e with SMTP id
 e9e14a558f8ab-3e139044528ls11060195ab.0.-pod-prod-07-us; Sun, 06 Jul 2025
 22:06:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWX1Wkv+xA8SYTe4Qjiy9Ax652OGokGwHAu3dMwGFyWnfYZQWk7bI3kR+WBoHGNgU5Am0JBKbiVumQ=@googlegroups.com
X-Received: by 2002:a92:ca46:0:b0:3df:45bb:28fe with SMTP id e9e14a558f8ab-3e136ea2629mr98564325ab.1.1751864774417;
        Sun, 06 Jul 2025 22:06:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864774; cv=none;
        d=google.com; s=arc-20240605;
        b=R35NWgYXDnjSSqRQ8Q4ms4sy+BWk/IZ7rd8v6RHflXEct1jKiGI/N5fXERL7aZnDV+
         J2iD5SbkaWTqDMZ4C/ZvnQkgB9amIXC7egwRz+n/FzkJz8hJ0eITe4YPo6PsCwsQxbfk
         RG53oExhx6SYb7e+64LFRM8bpN45rMlV1z7T7lW5DGip5wY4B1BvIVDwzTZlg6unFGTX
         +Zs6sWl8EkDrhBp6R51tysh9DsjMW/ZiNQ9iz+FzAIvWmZAvVh0VafOgznmzTq49DlUe
         gnS14CUDqnwF0lHy7RNaSqMsD68wapF3Bro18GPnLL6aXhtPkOrSJKszWZFq7+QE/W55
         +GeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ztj0qDNZhNlWRMtyHhzvv3mvcpE2NIU47KbWZgKoDV0=;
        fh=lk1MKnsL9jP4Yf3u6KV6iBVNHtNCgmv1n6U58SdB1qY=;
        b=fOW7JMFeQGU5cqSYHCuxQGkuMhCY3FPKOJ4j2yXi8ONQCn2q2tng9xfNVlIu+eTa2k
         uBOcRM7cOBF+BmCdJcub2szUYlk31cPLMeSGpfG0z1dYTSFT0BD0CRgFcRPfFbY8PDvh
         RxXy4ijvZjqc592fCf2NSfVHDVw/vMBD0witw7pIicByW12M83ipr8c9Rw8DmH5SBNz4
         wkdaArTtY9I+gxRBzPhMDBdLKTZs2J14rDwsiTcEDu4AzNZmpyJblqRq2yt8yzPa6kQO
         omhKrzuizm3r6/R8b7PU4FzBV7H7x34gQEhxi8/vGVhI4uJ6qAhtgi0YrAI4Mo6yILMZ
         XZPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BE1I5vs3;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e0f9b657f4si3724325ab.2.2025.07.06.22.06.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C666346170;
	Mon,  7 Jul 2025 05:06:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ED4F3C4CEF3;
	Mon,  7 Jul 2025 05:06:11 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:10 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Christophe JAILLET <christophe.jaillet@wanadoo.fr>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BE1I5vs3;       spf=pass
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

Fixes: f99e12b21b84 (2021-07-30; "kfence: add function to mask address bits")
[alx: that commit introduced dead code]
Fixes: af649773fb25 (2024-07-17; "mm/numa_balancing: teach mpol_to_str about the balancing mode")
[alx: that commit added p+=snprintf() calls, which are UB]
Fixes: 2291990ab36b (2008-04-28; "mempolicy: clean-up mpol-to-str() mempolicy formatting")
[alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
Fixes: 948927ee9e4f (2013-11-13; "mm, mempolicy: make mpol_to_str robust and always succeed")
[alx: that commit changes old code into p+=snprintf(), which is still UB]
[alx: that commit also produced dead code by leaving the last 'p+=...']
Fixes: d65360f22406 (2022-09-26; "mm/slub: clean up create_unique_id()")
[alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Marco Elver <elver@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Tvrtko Ursulin <tvrtko.ursulin@igalia.com>
Cc: "Huang, Ying" <ying.huang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Lee Schermerhorn <lee.schermerhorn@hp.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Chao Yu <chao.yu@oppo.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx%40kernel.org.
