Return-Path: <kasan-dev+bncBAABBC6UXTBQMGQED4B35LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A142AFF709
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:48:45 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e81b2af4f92sf891932276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:48:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115724; cv=pass;
        d=google.com; s=arc-20240605;
        b=iPwNl9faAPnda2mTsbpQqgRY4UbzAxbs9OTtygYS/D0zVsYLy3RT4RR3e8Wh3KbfH3
         5h+yq9nk8nhqIyKaxMh/CmQIrSb84meez9TOY4zFbN6XPlfh22fdjEyqNIeWVXLLXpqx
         lpL9y+Vg/4S3cuObrgEJeSzHoIah8Ryp7stoVjkuAmlF8ceABKM+yF90Y3lGz24h9HrU
         yDEBa5IX1OdVe32qmJ+XylIPJm/f7H1X+dsDAiYmzRYDjtWrwsQyDi03mNjJ6ZjvajmC
         K9AJ+x4Tr+uxnUsMZv0luIZgdYrQwMYcDuf0Vaa0kItuMnGdI5zGNSVmohkPTqrGqAvE
         Kxmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=86GribUVbD+O8BbL4duog+Hw1QsbAaTOfap2OtMDwS0=;
        fh=lrj3qR90exQFKZtgdiv5hZrIeVKtwYlFChVKXeZfOVQ=;
        b=Pkf5CkqVSG3hy44gcJEYCUr0yUq7IFqOztB2EDs1zCpxtjmXWGuM6pTo1frqCsDtZT
         umMcHg+V1qqvc0ulrJRYRjq00KTNE1ktbU6ahAMHh66+fvQ3hGw2YhkiJQ9YyOZooWLF
         s7wMlKnPrnMAMf0Mp9m8M2bIaW0137fDremyUKHkxL/j82/91L9iuzd9x2U7f6w7uWRj
         m0kRfM3PAzOZ7mEag+I9dUXys+zNRCThPcOMlmodhzLnfKZteJXi/1BZ+5Xhr5XGl5Uh
         YiMIlvibhyFDr2dzZqGQaCYl0nJsATeXgPQhVvEEJXnZ2+LQ3Y3IFVSnHWIRgPmJHD3y
         kO2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KoSvo+2s;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115724; x=1752720524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=86GribUVbD+O8BbL4duog+Hw1QsbAaTOfap2OtMDwS0=;
        b=sAzBmqqfwcpgzSQUFOjdPSsfYbJnun8ySiM0T64iUKgqHzW2JeZkUZP01qT1sT2/t4
         9o1mxOppgZuzxP4zND7Aacv6r/MiT9JgPxGzE/XQjSjqBWX4i2TFxdTVcuR0xEu+dmUH
         THwJ3lMNj1VhWtTpcPRg0MECy48FQR+I8kqvSL2SwYYIBN/nyZxd2gIRofS8YB18XOlN
         tC+Qv1IYiFLDSLshTUFkdp3/4K+CJktdueu7BRD/EUfnPLFfZRzmG0M/QXZLD9EHL4eZ
         CI50SqSjMeb1Tw6panlC22crvP7SKrkFgBmhAkp79KN4EHjhra9j2jRZNq0KssDUPbl9
         ramg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115724; x=1752720524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=86GribUVbD+O8BbL4duog+Hw1QsbAaTOfap2OtMDwS0=;
        b=KAU4pjUSKDmN9RPH0yDMIqSgq3afv97HepvJ5wisS6eyqjHbLuYtGE/dkfSWWTzb24
         UDlS7r/I6ouRsAfYCrRnvk9k8bNN9TRkAdNJWHbRU3Xu6PicHkowMnv/oYbQdzO2z+go
         42rlE64FE9A40dyrL1TBMVl4uO4iWALTr0OZdvR9AeQD4VkwhCIVL4325ym0123+hyAC
         d/zM1xwtIZT3DYt1lSfRpDn3XiimCuvX71EJ1/ZaQLiC2dGIGS+J4x66zvGvRVfCEHQz
         xjaJYuGs0qkYnOikKToItUqJTQ12HcrJ/4pmWEFN8urlcUdIBIVs5Jn2n5KGKuc5HqMy
         ljLQ==
X-Forwarded-Encrypted: i=2; AJvYcCUv6oy8Ithawqdn7AfTDgseGXPt7xn8gLM8J5r4McFywDqFwlbx97qx8wzNRW8ehW1gikAkPA==@lfdr.de
X-Gm-Message-State: AOJu0YxY9bhNHb8tbSwBngkpFsVV6TI+Ermbi7BcRQkrWGK4DQJyu5A8
	Qo96c+XGrZWGNwa9sd5XZ74qm2ik72J2ZTvg6CPDKbWzZvI0p+ANrzvH
X-Google-Smtp-Source: AGHT+IFnuMmOzjAPXhFXLmw1BvAHU8ycrjuwiMbSqtkQxrsOsX1aXaO+ThgxfnzlsNPmqV3DrhG4Zw==
X-Received: by 2002:a05:6902:508b:b0:e82:1371:f4f3 with SMTP id 3f1490d57ef6-e8b77ecab97mr1680669276.2.1752115723607;
        Wed, 09 Jul 2025 19:48:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcbXcszdWm2up9erCMkJ5zpDzYoU4NLcZ2aViR4YSGz9Q==
Received: by 2002:a25:1186:0:b0:e81:8384:b258 with SMTP id 3f1490d57ef6-e8b777b5c03ls511536276.0.-pod-prod-00-us;
 Wed, 09 Jul 2025 19:48:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4TQjXVHdBcOKj6qzH3rtYSGWcIpXIfLwWAUYNp8+1OkbvLPleXuoNkwvJH5AcOSK9OVFjbhJR/sA=@googlegroups.com
X-Received: by 2002:a05:6902:10cb:b0:e84:38b7:bc06 with SMTP id 3f1490d57ef6-e8b77dca88dmr2602508276.0.1752115722673;
        Wed, 09 Jul 2025 19:48:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115722; cv=none;
        d=google.com; s=arc-20240605;
        b=fR33bdxLyR4ZGTJi70Xw8JSF8PFi0a4wLPkwIDdiRSKdA1dilUDgmsMMFq58r70/yR
         FJ67qPIoqM/D2k2jPTUo9JBlFhnsW/S0C1Gpu3k/diVLe5Fr+WUIwQ58Iiw7r5sHe1Up
         w4ScthiEgtlHtGtqRZ8asI+pd5rNJUIL6o7V8NTJNdux4fDJGjB4FEJxdpcd4zsJd2U1
         r9nWxFK6RzZMWBN+XQKjQGjN/91jVRwG56wAAPZHbZuZoj7h1ntd6mTs6w675RDLlYJg
         EqaMk0Kr/BOxhgfh6CqFl8UmozUAw4bPh4PQqrsd1rnKrQ6kIJly6qa45/5g58txxZN6
         TxfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=++evECV9nwKSxaMYRtG3Dl+zFkiyxCKX7uNVyUkPMKg=;
        fh=g28aBSZDJmwNZHXyGmWfvgA9tlWawQeqtp10irvlj68=;
        b=E/SKhkMX+2MOdEB9EGHsqWnlgyoXov7TwhtMU5vCMAWUui4SD4DHMti4B3sB1eICCe
         xUiea3r6bJACvcYkhb84FJ41IJQzbSVd3kvIpt6ERtXbDjqV9VQ/ygyUCjaPyMYcx2XQ
         cDBkjP2cG4XmRhOXHP+qAPjFwd5qzk35HthaAXQt19QTsiOJHYTn2kMjwyK/g9XCPDO+
         DBRr5nqJ0/q2lLZP45qIb5OFYpHjqHCV0z8jhJLqExKEFCetvc3/8P+uq86J0ve8TrNK
         lnYggz7rGTJCkgviYx20GjhqgfTqn+1OonkGGYEkIwq4MhxVYe8lNUUg42aOb+h6aBRb
         4omg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KoSvo+2s;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8b7ac04cbesi20154276.0.2025.07.09.19.48.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:48:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id EC7B461139;
	Thu, 10 Jul 2025 02:48:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6195C4CEF0;
	Thu, 10 Jul 2025 02:48:35 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:48:33 +0200
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
	Al Viro <viro@zeniv.linux.org.uk>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: [RFC v4 3/7] mm: Use sprintf_end() instead of less ergonomic APIs
Message-ID: <690ed4d22f57a4a1f2c72eb659ceb6b7ab3d5f41.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KoSvo+2s;       spf=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/690ed4d22f57a4a1f2c72eb659ceb6b7ab3d5f41.1752113247.git.alx%40kernel.org.
