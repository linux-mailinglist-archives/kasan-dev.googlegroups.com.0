Return-Path: <kasan-dev+bncBAABBU6TXTBQMGQEB2Q3MAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id DC32EAFF6FF
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:47:48 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2e92a214e2esf169923fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:47:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115667; cv=pass;
        d=google.com; s=arc-20240605;
        b=DA7j/B45qtozq7wP7s301ZmMHkLmrilH3/djD3q2LX217Fsp0vBNQ0EHOBNm622evP
         icqTR8VBlybrd8SPR1pf28czDM7W9qqi0q+ZK9gzTkhAU/B72TaM30A4M6JJVo3T9Ygq
         vZ5kpr0IVn1y86K4JD8tW4T+aSEw3pdrE9zzXJMd6RReYkUOPOzJIDRmE7VwBsQL8GaY
         uuKjOAuP+eiDgBhYSMx1e0iSVP5qezIEE/z2HVVkEZyoh3NCkTsiz3gWGgcACWDzwjR+
         A2512hbeUl9QVJ5xDDrtYZmp0rtaP1U/S4g4N8GB0kKTLV6yratn9cL0cTwsc0gczcd+
         ipeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=qEp4vucmj2CIXJJXGNwsWwgIHq51qGW3dGmDb9HKa9g=;
        fh=wu5UIUOXwebIQjgw/nUTUhQxeA7G5420xbsp0y84Lfo=;
        b=ijIj49rtsiAy4ueu/XkmtguMSxzPlLjInavtbc9euFhZFkG6nnJfR8XXlZu+jH0Ixo
         lKHdBpG/A2f9fDDim4s71zCYOnX21WjnulI8axusbKlEffxPswpqqjNMr+2RtaqvX8gd
         4rDBXSHiIPVbEFwFj2NnotGNLcEeArN+4/1Tbm/0YPpwLegq+aRarESzTzfE3amgBvJ6
         mMEWhUUFnGmnBMaOOUJPsSyKdfz4vqnFeU+zoYDm9hJDk6L50SXTqX+ZiHf/q5D/nZgR
         CiTzWMM7sPZ6hpgJcZ/iVGpGqY/yxvMceQjqdTs7CyfU6DXslWMCVrUMQlxdgHLzyv77
         wMwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cB5WY3uc;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115667; x=1752720467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=qEp4vucmj2CIXJJXGNwsWwgIHq51qGW3dGmDb9HKa9g=;
        b=DgWC4JPF9W0iWT5Y07GMCwCYGFmTucQBJohlJwnuXIE0aUXmguk5qgU8m02xDXOa3o
         XQK/LJPKhSbjWO3nmtdA/pz1FPe9J2ngH8ILc/lRPS2nR0tXllKroPDQEvZPl4MsZCY6
         nFLHAJBbDUJxgrmCBg3ky5GlFSpxyJ5epY7MF7L0258AP9I2vVgF6zc513dIIqNrASFM
         Ukr0XHZG9qbs6BqJ+hPYI7kua31c1nLSQsp2HE2vlG8qN4yhSztmTaZYwY46z42owFxC
         uJ7LEa5fdQ8h8m6ukENspoNC+k/AO8Z/cZsSz2KopxTjBdqKQLx+lWbVQBZ20gL4tn0/
         v0kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115667; x=1752720467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qEp4vucmj2CIXJJXGNwsWwgIHq51qGW3dGmDb9HKa9g=;
        b=fsAty2EW1XtTf/BHs2n2wX8JW7sZE1pti6jXeMuQAuaQkg9VKfouTxdNDAaPC2yQJX
         t3ulGa1tjuM2mYIds925zez+F8kWND37PUp1E51U6apru1vLHUupEPGX9lb2pHag3rvg
         O1Y/MzOlbRDREcWYL4EMNKP7gNRwSUyO0bLx61oV83M7BCyZB8IQTsg7LLXvU2BBnb4T
         /1u7VQWEJYUrwHcZYQEx/JDxBKMCO+mjGFNqmOv1ucxKZy/Q/e/zKqmlCZPGeUqMEbGu
         ajsHGSWYZu8QoKa6H7Bz+Zhu+PZr9dowzGCj/lkr1k0UOILV/hLxKqSW4tAAwG3by59w
         fEaQ==
X-Forwarded-Encrypted: i=2; AJvYcCXHxBNtPO2/5UTP0DWIW6v5ez7WRm3R+lX6REDx24jqor40ibMrrnewfZQFKYasbsYR8HbI5A==@lfdr.de
X-Gm-Message-State: AOJu0YxM0D4tlfKY1/uh5sgtuJIdj5EZC8leJmePRLXocThoGntWJhID
	nCZSOwP+R3C59vzyniPI+Hke/PRVCYkycAwNvpMNd7vcedN1pCIgGqR+
X-Google-Smtp-Source: AGHT+IEhlZgMTZm8Fz3EDfvV1BZdkOYMZZn2rrm+LXFIrDUFIMkqvCZtwS8wdudX7fB2UISOkxXY7Q==
X-Received: by 2002:a05:6870:9e93:b0:2d6:72a4:adfa with SMTP id 586e51a60fabf-2ff0b9817eemr1607151fac.30.1752115667196;
        Wed, 09 Jul 2025 19:47:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCQeS4OKXdeE+mPX8KtqCibVV/oJV9TSvGSiiKcL1yOw==
Received: by 2002:a05:687c:205:b0:2ef:3864:284c with SMTP id
 586e51a60fabf-2ff0bcde0b8ls165839fac.1.-pod-prod-04-us; Wed, 09 Jul 2025
 19:47:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAhDq+o5I+Rw8JLA+CR9HEcrWu2H33CjbIWnq8RudROY1SwjElW58722FBWJKYuu4gYq+47PAoozI=@googlegroups.com
X-Received: by 2002:a05:6830:2d87:b0:739:fcb4:db1e with SMTP id 46e09a7af769-73cedff3045mr1277853a34.20.1752115666367;
        Wed, 09 Jul 2025 19:47:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115666; cv=none;
        d=google.com; s=arc-20240605;
        b=PD0F82tV2TFN6xVy0w9j0hXx4xX1b1xNb+AWHRso04onANLn7t6fpuIpgeciQs5Bs5
         l7BjOj7bBDQxIA1Eu6fbQCENcIbtP5SwjptmpU4ZABDQY9XkV1ghrLOSauRM+6Cxv0+1
         TIGemFZmSG7m7l23d8amEF9I9e12ASQlJdl+Ac9rVrFfM5neeEJ9RNzIJ3UE5OblUt9a
         Qd42yJzd8M0w/hF9H0oBH/plqkq78RNoNjQKE9MnlFcfBCyhpuwm2C3tk6xDzvjJE0FK
         QI+LMG/B2eShNUf/Z+0RuRpd3AFko6KDm2bWjepCl9sIJvNVoyGcge5kxEbkLvtcjy/K
         uq7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XVKJ35m3KfImHuLlH4xheYJc+yhuwfDBxxT7Nt0olEo=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=MWOXgNonf6BeZmQyxOZgrlpuiyvoC2Zb3GVTbFlrX1KaQUbbLCTz/vI/Twq2hNsZ8y
         rKCqY+Z0fq3xoViLCgaZcMHp6pNsBLN5boY0LFYNReEkiicvmz9F+9Oa+KRj0qgRWzVg
         BKOsOA+8yOCpf7kUsnNs6ot57rjhdyjYJsuW+RdjzCgETsZPz9y7oqlyEquYpyE72qLx
         lzuH6njrAhIu7g00nvVM3WjLYH6Nicu73ftDs0mEtdk67AWwAmP7i69881BP/HaY6zjm
         EjGQaf1f6jqk12mTYgeFYxDC9lFLHDDnyd2Te8mOioqcdPU+yYY4AK5fcIy1rfnNjnic
         o2cQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cB5WY3uc;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73cf1130bf5si20834a34.4.2025.07.09.19.47.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:47:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 9FDC7A53248;
	Thu, 10 Jul 2025 02:47:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7932CC4CEEF;
	Thu, 10 Jul 2025 02:47:36 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:47:33 +0200
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
Subject: [RFC v4 0/7] Add and use sprintf_end() instead of less ergonomic APIs
Message-ID: <cover.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cB5WY3uc;       spf=pass
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

Hi,

Changes in v4:

-  Added to global CC everyone who participated in the discussion so
   far.
-  Rename seprintf() => sprintf_end().
-  Implement SPRINTF_END().
-  Drop stprintf().  We don't need it as an intermediate helper.
-  Link to the draft of a standards proposal (which I'll paste as a
   reply to this mail again).
-  Minor fixes or updates to commit messages.
-  Added Marco Elver's Acked-by: tag in commit 5/7.
-  In stack_depot_sprint_end(), do sprintf_end(p, end, "") when
   nr_entries is 0, to guarantee that the string is valid if this is the
   first s*printf() call in a row.
-  Document sprintf_end() as 'string end-delimited print formatted'.
   This spells the letters in seprintf() for their meaning, in case
   anyone thinks the letters are randomly chosen.  :)
-  Remove comment about vsnprintf(3) not failing in the kernel, after
   Rasmus commented this is QoI guaranteed by the kernel.

Remaining questions:

-  There are only 3 remaining calls to snprintf(3) under mm/.  They are
   just fine for now, which is why I didn't replace them.  If anyone
   wants to replace them, to get rid of all snprintf(3), we could that.
   I think for now we can leave them, to minimize the churn.

	$ grep -rnI snprintf mm/
	mm/hugetlb_cgroup.c:674:		snprintf(buf, size, "%luGB", hsize / SZ_1G);
	mm/hugetlb_cgroup.c:676:		snprintf(buf, size, "%luMB", hsize / SZ_1M);
	mm/hugetlb_cgroup.c:678:		snprintf(buf, size, "%luKB", hsize / SZ_1K);

-  There are only 2 remaining calls to the kernel's scnprintf().  This
   one I would really like to get rid of.  Also, those calls are quite
   suspicious of not being what we want.  Please do have a look at them
   and confirm what's the appropriate behavior in the 2 cases when the
   string is truncated or not copied at all.  That code is very scary
   for me to try to guess.

	$ grep -rnI scnprintf mm/
	mm/kfence/report.c:75:		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
	mm/kfence/kfence_test.mod.c:22:	{ 0x96848186, "scnprintf" },
	mm/kmsan/report.c:42:		len = scnprintf(buf, sizeof(buf), "%ps",

   Apart from two calls, I see a string literal with that name.  Please
   let me know if I should do anything about it.  I don't know what that
   is.

-  I think we should remove one error handling check in
   "mm/page_owner.c" (marked with an XXX comment), but I'm not 100%
   sure.  Please confirm.

Other comments:

-  This is still not complying to coding style.  I'll keep it like that
   while questions remain open.
-  I've tested the tests under CONFIG_KFENCE_KUNIT_TEST=y, and this has
   no regressions at all.
-  With the current style of the sprintf_end() prototyope, this triggers
   a diagnostic due to a GCC bug:
   <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108036>
   It would be interesting to ask GCC to fix that bug.  (Added relevant
   GCC maintainers and contributors to CC in this cover letter.)


Have a lovely night!
Alex


Alejandro Colomar (7):
  vsprintf: Add [v]sprintf_end()
  stacktrace, stackdepot: Add sprintf_end()-like variants of functions
  mm: Use sprintf_end() instead of less ergonomic APIs
  array_size.h: Add ENDOF()
  mm: Fix benign off-by-one bugs
  sprintf: Add [V]SPRINTF_END()
  mm: Use [V]SPRINTF_END() to avoid specifying the array size

 include/linux/array_size.h |  6 ++++
 include/linux/sprintf.h    |  6 ++++
 include/linux/stackdepot.h | 13 +++++++++
 include/linux/stacktrace.h |  3 ++
 kernel/stacktrace.c        | 28 ++++++++++++++++++
 lib/stackdepot.c           | 13 +++++++++
 lib/vsprintf.c             | 59 ++++++++++++++++++++++++++++++++++++++
 mm/backing-dev.c           |  2 +-
 mm/cma.c                   |  4 +--
 mm/cma_debug.c             |  2 +-
 mm/hugetlb.c               |  3 +-
 mm/hugetlb_cgroup.c        |  2 +-
 mm/hugetlb_cma.c           |  2 +-
 mm/kasan/report.c          |  3 +-
 mm/kfence/kfence_test.c    | 28 +++++++++---------
 mm/kmsan/kmsan_test.c      |  6 ++--
 mm/memblock.c              |  4 +--
 mm/mempolicy.c             | 18 ++++++------
 mm/page_owner.c            | 32 +++++++++++----------
 mm/percpu.c                |  2 +-
 mm/shrinker_debug.c        |  2 +-
 mm/slub.c                  |  5 ++--
 mm/zswap.c                 |  2 +-
 23 files changed, 187 insertions(+), 58 deletions(-)

Range-diff against v3:
1:  64334f0b94d6 ! 1:  2c4f793de0b8 vsprintf: Add [v]seprintf(), [v]stprintf()
    @@ Metadata
     Author: Alejandro Colomar <alx@kernel.org>
     
      ## Commit message ##
    -    vsprintf: Add [v]seprintf(), [v]stprintf()
    +    vsprintf: Add [v]sprintf_end()
     
    -    seprintf()
    -    ==========
    -
    -    seprintf() is a function similar to stpcpy(3) in the sense that it
    +    sprintf_end() is a function similar to stpcpy(3) in the sense that it
         returns a pointer that is suitable for chaining to other copy
         operations.
     
    @@ Commit message
     
         It also makes error handling much easier, by reporting truncation with
         a null pointer, which is accepted and transparently passed down by
    -    subsequent seprintf() calls.  This results in only needing to report
    -    errors once after a chain of seprintf() calls, unlike snprintf(3), which
    -    requires checking after every call.
    +    subsequent sprintf_end() calls.  This results in only needing to report
    +    errors once after a chain of sprintf_end() calls, unlike snprintf(3),
    +    which requires checking after every call.
     
                 p = buf;
                 e = buf + countof(buf);
    -            p = seprintf(p, e, foo);
    -            p = seprintf(p, e, bar);
    +            p = sprintf_end(p, e, foo);
    +            p = sprintf_end(p, e, bar);
                 if (p == NULL)
                         goto trunc;
     
    @@ Commit message
                 size = countof(buf);
                 len += scnprintf(buf + len, size - len, foo);
                 len += scnprintf(buf + len, size - len, bar);
    -            if (len >= size)
    -                    goto trunc;
    +            // No ability to check.
     
         It seems aparent that it's a more elegant approach to string catenation.
     
    -    stprintf()
    -    ==========
    -
    -    stprintf() is a helper that is needed for implementing seprintf()
    -    --although it could be open-coded within vseprintf(), of course--, but
    -    it's also useful by itself.  It has the same interface properties as
    -    strscpy(): that is, it copies with truncation, and reports truncation
    -    with -E2BIG.  It would be useful to replace some calls to snprintf(3)
    -    and scnprintf() which don't need chaining, and where it's simpler to
    -    pass a size.
    -
    -    It is better than plain snprintf(3), because it results in simpler error
    -    detection (it doesn't need a check >=countof(buf), but rather <0).
    +    These functions will soon be proposed for standardization as
    +    [v]seprintf() into C2y, and they exist in Plan9 as seprint(2) --but the
    +    Plan9 implementation has important bugs--.
     
    +    Link: <https://www.alejandro-colomar.es/src/alx/alx/wg14/alx-0049.git/tree/alx-0049.txt>
         Cc: Kees Cook <kees@kernel.org>
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
    +    Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Michal Hocko <mhocko@suse.com>
    +    Cc: Linus Torvalds <torvalds@linux-foundation.org>
    +    Cc: Al Viro <viro@zeniv.linux.org.uk>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## include/linux/sprintf.h ##
    -@@ include/linux/sprintf.h: __printf(2, 3) int sprintf(char *buf, const char * fmt, ...);
    - __printf(2, 0) int vsprintf(char *buf, const char *, va_list);
    - __printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
    +@@ include/linux/sprintf.h: __printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
      __printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
    -+__printf(3, 4) int stprintf(char *buf, size_t size, const char *fmt, ...);
    -+__printf(3, 0) int vstprintf(char *buf, size_t size, const char *fmt, va_list args);
      __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
      __printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
    -+__printf(3, 4) char *seprintf(char *p, const char end[0], const char *fmt, ...);
    -+__printf(3, 0) char *vseprintf(char *p, const char end[0], const char *fmt, va_list args);
    ++__printf(3, 4) char *sprintf_end(char *p, const char end[0], const char *fmt, ...);
    ++__printf(3, 0) char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args);
      __printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
      __printf(2, 0) __malloc char *kvasprintf(gfp_t gfp, const char *fmt, va_list args);
      __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
     
      ## lib/vsprintf.c ##
    -@@ lib/vsprintf.c: int vsnprintf(char *buf, size_t size, const char *fmt_str, va_list args)
    - }
    - EXPORT_SYMBOL(vsnprintf);
    - 
    -+/**
    -+ * vstprintf - Format a string and place it in a buffer
    -+ * @buf: The buffer to place the result into
    -+ * @size: The size of the buffer, including the trailing null space
    -+ * @fmt: The format string to use
    -+ * @args: Arguments for the format string
    -+ *
    -+ * The return value is the length of the new string.
    -+ * If the string is truncated, the function returns -E2BIG.
    -+ *
    -+ * If you're not already dealing with a va_list consider using stprintf().
    -+ *
    -+ * See the vsnprintf() documentation for format string extensions over C99.
    -+ */
    -+int vstprintf(char *buf, size_t size, const char *fmt, va_list args)
    -+{
    -+	int len;
    -+
    -+	len = vsnprintf(buf, size, fmt, args);
    -+
    -+	// It seems the kernel's vsnprintf() doesn't fail?
    -+	//if (unlikely(len < 0))
    -+	//	return -E2BIG;
    -+
    -+	if (unlikely(len >= size))
    -+		return -E2BIG;
    -+
    -+	return len;
    -+}
    -+EXPORT_SYMBOL(vstprintf);
    -+
    - /**
    -  * vscnprintf - Format a string and place it in a buffer
    -  * @buf: The buffer to place the result into
     @@ lib/vsprintf.c: int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
      }
      EXPORT_SYMBOL(vscnprintf);
      
     +/**
    -+ * vseprintf - Format a string and place it in a buffer
    ++ * vsprintf_end - va_list string end-delimited print formatted
     + * @p: The buffer to place the result into
     + * @end: A pointer to one past the last character in the buffer
     + * @fmt: The format string to use
    @@ lib/vsprintf.c: int vscnprintf(char *buf, size_t size, const char *fmt, va_list
     + * The return value is a pointer to the trailing '\0'.
     + * If @p is NULL, the function returns NULL.
     + * If the string is truncated, the function returns NULL.
    -+ *
    -+ * If you're not already dealing with a va_list consider using seprintf().
    ++ * If @end <= @p, the function returns NULL.
     + *
     + * See the vsnprintf() documentation for format string extensions over C99.
     + */
    -+char *vseprintf(char *p, const char end[0], const char *fmt, va_list args)
    ++char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args)
     +{
     +	int len;
    ++	size_t size;
     +
     +	if (unlikely(p == NULL))
     +		return NULL;
     +
    -+	len = vstprintf(p, end - p, fmt, args);
    -+	if (unlikely(len < 0))
    ++	size = end - p;
    ++	if (WARN_ON_ONCE(size == 0 || size > INT_MAX))
    ++		return NULL;
    ++
    ++	len = vsnprintf(p, size, fmt, args);
    ++	if (unlikely(len >= size))
     +		return NULL;
     +
     +	return p + len;
     +}
    -+EXPORT_SYMBOL(vseprintf);
    ++EXPORT_SYMBOL(vsprintf_end);
     +
      /**
       * snprintf - Format a string and place it in a buffer
       * @buf: The buffer to place the result into
    -@@ lib/vsprintf.c: int snprintf(char *buf, size_t size, const char *fmt, ...)
    - }
    - EXPORT_SYMBOL(snprintf);
    - 
    -+/**
    -+ * stprintf - Format a string and place it in a buffer
    -+ * @buf: The buffer to place the result into
    -+ * @size: The size of the buffer, including the trailing null space
    -+ * @fmt: The format string to use
    -+ * @...: Arguments for the format string
    -+ *
    -+ * The return value is the length of the new string.
    -+ * If the string is truncated, the function returns -E2BIG.
    -+ */
    -+
    -+int stprintf(char *buf, size_t size, const char *fmt, ...)
    -+{
    -+	va_list args;
    -+	int len;
    -+
    -+	va_start(args, fmt);
    -+	len = vstprintf(buf, size, fmt, args);
    -+	va_end(args);
    -+
    -+	return len;
    -+}
    -+EXPORT_SYMBOL(stprintf);
    -+
    - /**
    -  * scnprintf - Format a string and place it in a buffer
    -  * @buf: The buffer to place the result into
     @@ lib/vsprintf.c: int scnprintf(char *buf, size_t size, const char *fmt, ...)
      }
      EXPORT_SYMBOL(scnprintf);
      
     +/**
    -+ * seprintf - Format a string and place it in a buffer
    ++ * sprintf_end - string end-delimited print formatted
     + * @p: The buffer to place the result into
     + * @end: A pointer to one past the last character in the buffer
     + * @fmt: The format string to use
    @@ lib/vsprintf.c: int scnprintf(char *buf, size_t size, const char *fmt, ...)
     + * The return value is a pointer to the trailing '\0'.
     + * If @buf is NULL, the function returns NULL.
     + * If the string is truncated, the function returns NULL.
    ++ * If @end <= @p, the function returns NULL.
     + */
     +
    -+char *seprintf(char *p, const char end[0], const char *fmt, ...)
    ++char *sprintf_end(char *p, const char end[0], const char *fmt, ...)
     +{
     +	va_list args;
     +
     +	va_start(args, fmt);
    -+	p = vseprintf(p, end, fmt, args);
    ++	p = vsprintf_end(p, end, fmt, args);
     +	va_end(args);
     +
     +	return p;
     +}
    -+EXPORT_SYMBOL(seprintf);
    ++EXPORT_SYMBOL(sprintf_end);
     +
      /**
       * vsprintf - Format a string and place it in a buffer
2:  9c140de9842d ! 2:  894d02b08056 stacktrace, stackdepot: Add seprintf()-like variants of functions
    @@ Metadata
     Author: Alejandro Colomar <alx@kernel.org>
     
      ## Commit message ##
    -    stacktrace, stackdepot: Add seprintf()-like variants of functions
    -
    -    I think there's an anomaly in stack_depot_s*print().  If we have zero
    -    entries, we don't copy anything, which means the string is still not a
    -    string.  Normally, this function is called surrounded by other calls to
    -    s*printf(), which guarantee that there's a '\0', but maybe we should
    -    make sure to write a '\0' here?
    +    stacktrace, stackdepot: Add sprintf_end()-like variants of functions
     
         Cc: Kees Cook <kees@kernel.org>
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
    +    Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Michal Hocko <mhocko@suse.com>
    +    Cc: Linus Torvalds <torvalds@linux-foundation.org>
    +    Cc: Al Viro <viro@zeniv.linux.org.uk>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## include/linux/stackdepot.h ##
    @@ include/linux/stackdepot.h: void stack_depot_print(depot_stack_handle_t stack);
      		       int spaces);
      
     +/**
    -+ * stack_depot_seprint - Print a stack trace from stack depot into a buffer
    ++ * stack_depot_sprint_end - Print a stack trace from stack depot into a buffer
     + *
     + * @handle:	Stack depot handle returned from stack_depot_save()
     + * @p:		Pointer to the print buffer
    @@ include/linux/stackdepot.h: void stack_depot_print(depot_stack_handle_t stack);
     + *
     + * Return:	Pointer to trailing '\0'; or NULL on truncation
     + */
    -+char *stack_depot_seprint(depot_stack_handle_t handle, char *p,
    -+                          const char end[0], int spaces);
    ++char *stack_depot_sprint_end(depot_stack_handle_t handle, char *p,
    ++                             const char end[0], int spaces);
     +
      /**
       * stack_depot_put - Drop a reference to a stack trace from stack depot
    @@ include/linux/stacktrace.h: void stack_trace_print(const unsigned long *trace, u
      		       int spaces);
      int stack_trace_snprint(char *buf, size_t size, const unsigned long *entries,
      			unsigned int nr_entries, int spaces);
    -+char *stack_trace_seprint(char *p, const char end[0],
    -+			  const unsigned long *entries, unsigned int nr_entries,
    -+			  int spaces);
    ++char *stack_trace_sprint_end(char *p, const char end[0],
    ++			     const unsigned long *entries,
    ++			     unsigned int nr_entries, int spaces);
      unsigned int stack_trace_save(unsigned long *store, unsigned int size,
      			      unsigned int skipnr);
      unsigned int stack_trace_save_tsk(struct task_struct *task,
    @@ kernel/stacktrace.c: int stack_trace_snprint(char *buf, size_t size, const unsig
      EXPORT_SYMBOL_GPL(stack_trace_snprint);
      
     +/**
    -+ * stack_trace_seprint - Print the entries in the stack trace into a buffer
    ++ * stack_trace_sprint_end - Print the entries in the stack trace into a buffer
     + * @p:		Pointer to the print buffer
     + * @end:	Pointer to one past the last element in the buffer
     + * @entries:	Pointer to storage array
    @@ kernel/stacktrace.c: int stack_trace_snprint(char *buf, size_t size, const unsig
     + *
     + * Return: Pointer to the trailing '\0'; or NULL on truncation.
     + */
    -+char *stack_trace_seprint(char *p, const char end[0],
    ++char *stack_trace_sprint_end(char *p, const char end[0],
     +			  const unsigned long *entries, unsigned int nr_entries,
     +			  int spaces)
     +{
    @@ kernel/stacktrace.c: int stack_trace_snprint(char *buf, size_t size, const unsig
     +		return 0;
     +
     +	for (i = 0; i < nr_entries; i++) {
    -+		p = seprintf(p, end, "%*c%pS\n", 1 + spaces, ' ',
    ++		p = sprintf_end(p, end, "%*c%pS\n", 1 + spaces, ' ',
     +			     (void *)entries[i]);
     +	}
     +
     +	return p;
     +}
    -+EXPORT_SYMBOL_GPL(stack_trace_seprint);
    ++EXPORT_SYMBOL_GPL(stack_trace_sprint_end);
     +
      #ifdef CONFIG_ARCH_STACKWALK
      
    @@ lib/stackdepot.c: int stack_depot_snprint(depot_stack_handle_t handle, char *buf
      }
      EXPORT_SYMBOL_GPL(stack_depot_snprint);
      
    -+char *stack_depot_seprint(depot_stack_handle_t handle, char *p,
    -+			  const char end[0], int spaces)
    ++char *stack_depot_sprint_end(depot_stack_handle_t handle, char *p,
    ++			     const char end[0], int spaces)
     +{
     +	unsigned long *entries;
     +	unsigned int nr_entries;
     +
     +	nr_entries = stack_depot_fetch(handle, &entries);
    -+	return nr_entries ? stack_trace_seprint(p, end, entries, nr_entries,
    -+						spaces) : p;
    ++	return nr_entries ?
    ++		stack_trace_sprint_end(p, end, entries, nr_entries, spaces)
    ++		: sprintf_end(p, end, "");
     +}
    -+EXPORT_SYMBOL_GPL(stack_depot_seprint);
    ++EXPORT_SYMBOL_GPL(stack_depot_sprint_end);
     +
      depot_stack_handle_t __must_check stack_depot_set_extra_bits(
      			depot_stack_handle_t handle, unsigned int extra_bits)
3:  033bf00f1fcf ! 3:  690ed4d22f57 mm: Use seprintf() instead of less ergonomic APIs
    @@ Metadata
     Author: Alejandro Colomar <alx@kernel.org>
     
      ## Commit message ##
    -    mm: Use seprintf() instead of less ergonomic APIs
    +    mm: Use sprintf_end() instead of less ergonomic APIs
     
         While doing this, I detected some anomalies in the existing code:
     
    @@ Commit message
     
                 This file uses the 'p += snprintf()' anti-pattern.  That will
                 overflow the pointer on truncation, which has undefined
    -            behavior.  Using seprintf(), this bug is fixed.
    +            behavior.  Using sprintf_end(), this bug is fixed.
     
                 As in the previous file, here there was also dead code in the
                 last scnprintf() call, by incrementing a pointer that is not
    @@ Commit message
                 a good reason (i.e., we may want to avoid calling
                 print_page_owner_memcg() if we truncated before).  Please review
                 if this amount of error handling is the right one, or if we want
    -            to add or remove some.  For seprintf(), a single test for null
    -            after the last call is enough to detect truncation.
    +            to add or remove some.  For sprintf_end(), a single test for
    +            null after the last call is enough to detect truncation.
     
         mm/slub.c:
     
                 Again, the 'p += snprintf()' anti-pattern.  This is UB, and by
    -            using seprintf() we've fixed the bug.
    +            using sprintf_end() we've fixed the bug.
     
    -    Fixes: f99e12b21b84 (2021-07-30; "kfence: add function to mask address bits")
    -    [alx: that commit introduced dead code]
    -    Fixes: af649773fb25 (2024-07-17; "mm/numa_balancing: teach mpol_to_str about the balancing mode")
    -    [alx: that commit added p+=snprintf() calls, which are UB]
    -    Fixes: 2291990ab36b (2008-04-28; "mempolicy: clean-up mpol-to-str() mempolicy formatting")
    -    [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
    -    Fixes: 948927ee9e4f (2013-11-13; "mm, mempolicy: make mpol_to_str robust and always succeed")
    -    [alx: that commit changes old code into p+=snprintf(), which is still UB]
    -    [alx: that commit also produced dead code by leaving the last 'p+=...']
    -    Fixes: d65360f22406 (2022-09-26; "mm/slub: clean up create_unique_id()")
    -    [alx: that commit changed p+=sprintf() into p+=snprintf(), which is still UB]
         Cc: Kees Cook <kees@kernel.org>
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
         Cc: Sven Schnelle <svens@linux.ibm.com>
         Cc: Marco Elver <elver@google.com>
         Cc: Heiko Carstens <hca@linux.ibm.com>
         Cc: Tvrtko Ursulin <tvrtko.ursulin@igalia.com>
    -    Cc: "Huang, Ying" <ying.huang@intel.com>
         Cc: Andrew Morton <akpm@linux-foundation.org>
    -    Cc: Lee Schermerhorn <lee.schermerhorn@hp.com>
         Cc: Linus Torvalds <torvalds@linux-foundation.org>
         Cc: David Rientjes <rientjes@google.com>
         Cc: Christophe JAILLET <christophe.jaillet@wanadoo.fr>
         Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
         Cc: Chao Yu <chao.yu@oppo.com>
         Cc: Vlastimil Babka <vbabka@suse.cz>
    +    Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
    +    Cc: Michal Hocko <mhocko@suse.com>
    +    Cc: Al Viro <viro@zeniv.linux.org.uk>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## mm/kfence/kfence_test.c ##
    @@ mm/kfence/kfence_test.c: static bool report_matches(const struct expect_report *
      	switch (r->type) {
      	case KFENCE_ERROR_OOB:
     -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: out-of-bounds %s",
    -+		cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
    ++		cur = sprintf_end(cur, end, "BUG: KFENCE: out-of-bounds %s",
      				 get_access_type(r));
      		break;
      	case KFENCE_ERROR_UAF:
     -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: use-after-free %s",
    -+		cur = seprintf(cur, end, "BUG: KFENCE: use-after-free %s",
    ++		cur = sprintf_end(cur, end, "BUG: KFENCE: use-after-free %s",
      				 get_access_type(r));
      		break;
      	case KFENCE_ERROR_CORRUPTION:
     -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: memory corruption");
    -+		cur = seprintf(cur, end, "BUG: KFENCE: memory corruption");
    ++		cur = sprintf_end(cur, end, "BUG: KFENCE: memory corruption");
      		break;
      	case KFENCE_ERROR_INVALID:
     -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid %s",
    -+		cur = seprintf(cur, end, "BUG: KFENCE: invalid %s",
    ++		cur = sprintf_end(cur, end, "BUG: KFENCE: invalid %s",
      				 get_access_type(r));
      		break;
      	case KFENCE_ERROR_INVALID_FREE:
     -		cur += scnprintf(cur, end - cur, "BUG: KFENCE: invalid free");
    -+		cur = seprintf(cur, end, "BUG: KFENCE: invalid free");
    ++		cur = sprintf_end(cur, end, "BUG: KFENCE: invalid free");
      		break;
      	}
      
     -	scnprintf(cur, end - cur, " in %pS", r->fn);
    -+	seprintf(cur, end, " in %pS", r->fn);
    ++	sprintf_end(cur, end, " in %pS", r->fn);
      	/* The exact offset won't match, remove it; also strip module name. */
      	cur = strchr(expect[0], '+');
      	if (cur)
    @@ mm/kfence/kfence_test.c: static bool report_matches(const struct expect_report *
      	switch (r->type) {
      	case KFENCE_ERROR_OOB:
     -		cur += scnprintf(cur, end - cur, "Out-of-bounds %s at", get_access_type(r));
    -+		cur = seprintf(cur, end, "Out-of-bounds %s at", get_access_type(r));
    ++		cur = sprintf_end(cur, end, "Out-of-bounds %s at", get_access_type(r));
      		addr = arch_kfence_test_address(addr);
      		break;
      	case KFENCE_ERROR_UAF:
     -		cur += scnprintf(cur, end - cur, "Use-after-free %s at", get_access_type(r));
    -+		cur = seprintf(cur, end, "Use-after-free %s at", get_access_type(r));
    ++		cur = sprintf_end(cur, end, "Use-after-free %s at", get_access_type(r));
      		addr = arch_kfence_test_address(addr);
      		break;
      	case KFENCE_ERROR_CORRUPTION:
     -		cur += scnprintf(cur, end - cur, "Corrupted memory at");
    -+		cur = seprintf(cur, end, "Corrupted memory at");
    ++		cur = sprintf_end(cur, end, "Corrupted memory at");
      		break;
      	case KFENCE_ERROR_INVALID:
     -		cur += scnprintf(cur, end - cur, "Invalid %s at", get_access_type(r));
    -+		cur = seprintf(cur, end, "Invalid %s at", get_access_type(r));
    ++		cur = sprintf_end(cur, end, "Invalid %s at", get_access_type(r));
      		addr = arch_kfence_test_address(addr);
      		break;
      	case KFENCE_ERROR_INVALID_FREE:
     -		cur += scnprintf(cur, end - cur, "Invalid free of");
    -+		cur = seprintf(cur, end, "Invalid free of");
    ++		cur = sprintf_end(cur, end, "Invalid free of");
      		break;
      	}
      
     -	cur += scnprintf(cur, end - cur, " 0x%p", (void *)addr);
    -+	seprintf(cur, end, " 0x%p", (void *)addr);
    ++	sprintf_end(cur, end, " 0x%p", (void *)addr);
      
      	spin_lock_irqsave(&observed.lock, flags);
      	if (!report_available())
    @@ mm/kmsan/kmsan_test.c: static bool report_matches(const struct expect_report *r)
      	end = &expected_header[sizeof(expected_header) - 1];
      
     -	cur += scnprintf(cur, end - cur, "BUG: KMSAN: %s", r->error_type);
    -+	cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
    ++	cur = sprintf_end(cur, end, "BUG: KMSAN: %s", r->error_type);
      
     -	scnprintf(cur, end - cur, " in %s", r->symbol);
    -+	seprintf(cur, end, " in %s", r->symbol);
    ++	sprintf_end(cur, end, " in %s", r->symbol);
      	/* The exact offset won't match, remove it; also strip module name. */
      	cur = strchr(expected_header, '+');
      	if (cur)
    @@ mm/mempolicy.c: void mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol
      	default:
      		WARN_ON_ONCE(1);
     -		snprintf(p, maxlen, "unknown");
    -+		seprintf(p, e, "unknown");
    ++		sprintf_end(p, e, "unknown");
      		return;
      	}
      
     -	p += snprintf(p, maxlen, "%s", policy_modes[mode]);
    -+	p = seprintf(p, e, "%s", policy_modes[mode]);
    ++	p = sprintf_end(p, e, "%s", policy_modes[mode]);
      
      	if (flags & MPOL_MODE_FLAGS) {
     -		p += snprintf(p, buffer + maxlen - p, "=");
    -+		p = seprintf(p, e, "=");
    ++		p = sprintf_end(p, e, "=");
      
      		/*
      		 * Static and relative are mutually exclusive.
      		 */
      		if (flags & MPOL_F_STATIC_NODES)
     -			p += snprintf(p, buffer + maxlen - p, "static");
    -+			p = seprintf(p, e, "static");
    ++			p = sprintf_end(p, e, "static");
      		else if (flags & MPOL_F_RELATIVE_NODES)
     -			p += snprintf(p, buffer + maxlen - p, "relative");
    -+			p = seprintf(p, e, "relative");
    ++			p = sprintf_end(p, e, "relative");
      
      		if (flags & MPOL_F_NUMA_BALANCING) {
      			if (!is_power_of_2(flags & MPOL_MODE_FLAGS))
     -				p += snprintf(p, buffer + maxlen - p, "|");
     -			p += snprintf(p, buffer + maxlen - p, "balancing");
    -+				p = seprintf(p, e, "|");
    -+			p = seprintf(p, e, "balancing");
    ++				p = sprintf_end(p, e, "|");
    ++			p = sprintf_end(p, e, "balancing");
      		}
      	}
      
      	if (!nodes_empty(nodes))
     -		p += scnprintf(p, buffer + maxlen - p, ":%*pbl",
     -			       nodemask_pr_args(&nodes));
    -+		seprintf(p, e, ":%*pbl", nodemask_pr_args(&nodes));
    ++		sprintf_end(p, e, ":%*pbl", nodemask_pr_args(&nodes));
      }
      
      #ifdef CONFIG_SYSFS
    @@ mm/page_owner.c: static inline int print_page_owner_memcg(char *kbuf, size_t cou
      	if (memcg_data & MEMCG_DATA_OBJEXTS)
     -		ret += scnprintf(kbuf + ret, count - ret,
     -				"Slab cache page\n");
    -+		p = seprintf(p, end, "Slab cache page\n");
    ++		p = sprintf_end(p, end, "Slab cache page\n");
      
      	memcg = page_memcg_check(page);
      	if (!memcg)
    @@ mm/page_owner.c: static inline int print_page_owner_memcg(char *kbuf, size_t cou
      	online = (memcg->css.flags & CSS_ONLINE);
      	cgroup_name(memcg->css.cgroup, name, sizeof(name));
     -	ret += scnprintf(kbuf + ret, count - ret,
    -+	p = seprintf(p, end,
    ++	p = sprintf_end(p, end,
      			"Charged %sto %smemcg %s\n",
      			PageMemcgKmem(page) ? "(via objcg) " : "",
      			online ? "" : "offline ",
    @@ mm/page_owner.c: print_page_owner(char __user *buf, size_t count, unsigned long
     -	ret = scnprintf(kbuf, count,
     +	p = kbuf;
     +	e = kbuf + count;
    -+	p = seprintf(p, e,
    ++	p = sprintf_end(p, e,
      			"Page allocated via order %u, mask %#x(%pGg), pid %d, tgid %d (%s), ts %llu ns\n",
      			page_owner->order, page_owner->gfp_mask,
      			&page_owner->gfp_mask, page_owner->pid,
    @@ mm/page_owner.c: print_page_owner(char __user *buf, size_t count, unsigned long
      	pageblock_mt = get_pageblock_migratetype(page);
      	page_mt  = gfp_migratetype(page_owner->gfp_mask);
     -	ret += scnprintf(kbuf + ret, count - ret,
    -+	p = seprintf(p, e,
    ++	p = sprintf_end(p, e,
      			"PFN 0x%lx type %s Block %lu type %s Flags %pGp\n",
      			pfn,
      			migratetype_names[page_mt],
    @@ mm/page_owner.c: print_page_owner(char __user *buf, size_t count, unsigned long
     -	ret += stack_depot_snprint(handle, kbuf + ret, count - ret, 0);
     -	if (ret >= count)
     -		goto err;
    -+	p = stack_depot_seprint(handle, p, e, 0);
    ++	p = stack_depot_sprint_end(handle, p, e, 0);
     +	if (p == NULL)
     +		goto err;  // XXX: Should we remove this error handling?
      
      	if (page_owner->last_migrate_reason != -1) {
     -		ret += scnprintf(kbuf + ret, count - ret,
    -+		p = seprintf(p, e,
    ++		p = sprintf_end(p, e,
      			"Page has been migrated, last migrate reason: %s\n",
      			migrate_reason_names[page_owner->last_migrate_reason]);
      	}
    @@ mm/page_owner.c: print_page_owner(char __user *buf, size_t count, unsigned long
      
     -	ret += snprintf(kbuf + ret, count - ret, "\n");
     -	if (ret >= count)
    -+	p = seprintf(p, e, "\n");
    ++	p = sprintf_end(p, e, "\n");
     +	if (p == NULL)
      		goto err;
      
    @@ mm/slub.c: static char *create_unique_id(struct kmem_cache *s)
      	if (p != name + 1)
      		*p++ = '-';
     -	p += snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size);
    -+	p = seprintf(p, e, "%07u", s->size);
    ++	p = sprintf_end(p, e, "%07u", s->size);
      
     -	if (WARN_ON(p > name + ID_STR_LENGTH - 1)) {
     +	if (WARN_ON(p == NULL)) {
4:  d8bd0e1d308b ! 4:  e05c5afabb3c array_size.h: Add ENDOF()
    @@ Metadata
      ## Commit message ##
         array_size.h: Add ENDOF()
     
    -    This macro is useful to calculate the second argument to seprintf(),
    +    This macro is useful to calculate the second argument to sprintf_end(),
         avoiding off-by-one bugs.
     
         Cc: Kees Cook <kees@kernel.org>
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
    +    Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Michal Hocko <mhocko@suse.com>
    +    Cc: Linus Torvalds <torvalds@linux-foundation.org>
    +    Cc: Al Viro <viro@zeniv.linux.org.uk>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## include/linux/array_size.h ##
5:  740755c1a888 ! 5:  44a5cfc82acf mm: Fix benign off-by-one bugs
    @@ Commit message
         'end' --that is, at most the terminating null byte will be written at
         'end-1'--.
     
    -    Fixes: bc8fbc5f305a (2021-02-26; "kfence: add test suite")
    -    Fixes: 8ed691b02ade (2022-10-03; "kmsan: add tests for KMSAN")
    +    Acked-by: Marco Elver <elver@google.com>
         Cc: Kees Cook <kees@kernel.org>
         Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
         Cc: Alexander Potapenko <glider@google.com>
    -    Cc: Marco Elver <elver@google.com>
         Cc: Dmitry Vyukov <dvyukov@google.com>
         Cc: Alexander Potapenko <glider@google.com>
         Cc: Jann Horn <jannh@google.com>
         Cc: Andrew Morton <akpm@linux-foundation.org>
         Cc: Linus Torvalds <torvalds@linux-foundation.org>
    +    Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Michal Hocko <mhocko@suse.com>
    +    Cc: Al Viro <viro@zeniv.linux.org.uk>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## mm/kfence/kfence_test.c ##
    @@ mm/kfence/kfence_test.c: static bool report_matches(const struct expect_report *
     +	end = ENDOF(expect[0]);
      	switch (r->type) {
      	case KFENCE_ERROR_OOB:
    - 		cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
    + 		cur = sprintf_end(cur, end, "BUG: KFENCE: out-of-bounds %s",
     @@ mm/kfence/kfence_test.c: static bool report_matches(const struct expect_report *r)
      
      	/* Access information */
    @@ mm/kmsan/kmsan_test.c: static bool report_matches(const struct expect_report *r)
     -	end = &expected_header[sizeof(expected_header) - 1];
     +	end = ENDOF(expected_header);
      
    - 	cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
    + 	cur = sprintf_end(cur, end, "BUG: KMSAN: %s", r->error_type);
      
6:  44d05559398c ! 6:  0314948eb225 sprintf: Add [V]STPRINTF()
    @@ Metadata
     Author: Alejandro Colomar <alx@kernel.org>
     
      ## Commit message ##
    -    sprintf: Add [V]STPRINTF()
    +    sprintf: Add [V]SPRINTF_END()
     
    -    These macros take the array size argument implicitly to avoid programmer
    -    mistakes.  This guarantees that the input is an array, unlike the common
    -    call
    +    These macros take the end of the array argument implicitly to avoid
    +    programmer mistakes.  This guarantees that the input is an array, unlike
     
                 snprintf(buf, sizeof(buf), ...);
     
    -    which is dangerous if the programmer passes a pointer.
    +    which is dangerous if the programmer passes a pointer instead of an
    +    array.
     
         These macros are essentially the same as the 2-argument version of
    -    strscpy(), but with a formatted string.
    +    strscpy(), but with a formatted string, and returning a pointer to the
    +    terminating '\0' (or NULL, on error).
     
    +    Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Michal Hocko <mhocko@suse.com>
    +    Cc: Linus Torvalds <torvalds@linux-foundation.org>
    +    Cc: Al Viro <viro@zeniv.linux.org.uk>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## include/linux/sprintf.h ##
    @@ include/linux/sprintf.h
      #include <linux/types.h>
     +#include <linux/array_size.h>
     +
    -+#define STPRINTF(a, fmt, ...)  stprintf(a, ARRAY_SIZE(a), fmt, ##__VA_ARGS__)
    -+#define VSTPRINTF(a, fmt, ap)  vstprintf(a, ARRAY_SIZE(a), fmt, ap)
    ++#define SPRINTF_END(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
    ++#define VSPRINTF_END(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)
      
      int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
      
7:  d0e95db3c80a ! 7:  f99632f42eee mm: Use [V]STPRINTF() to avoid specifying the array size
    @@ Metadata
     Author: Alejandro Colomar <alx@kernel.org>
     
      ## Commit message ##
    -    mm: Use [V]STPRINTF() to avoid specifying the array size
    +    mm: Use [V]SPRINTF_END() to avoid specifying the array size
     
    +    Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
    +    Cc: Marco Elver <elver@google.com>
    +    Cc: Michal Hocko <mhocko@suse.com>
    +    Cc: Linus Torvalds <torvalds@linux-foundation.org>
    +    Cc: Al Viro <viro@zeniv.linux.org.uk>
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## mm/backing-dev.c ##
    @@ mm/backing-dev.c: int bdi_register_va(struct backing_dev_info *bdi, const char *
      		return 0;
      
     -	vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
    -+	VSTPRINTF(bdi->dev_name, fmt, args);
    ++	VSPRINTF_END(bdi->dev_name, fmt, args);
      	dev = device_create(&bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
      	if (IS_ERR(dev))
      		return PTR_ERR(dev);
    @@ mm/cma.c: static int __init cma_new_area(const char *name, phys_addr_t size,
      
      	if (name)
     -		snprintf(cma->name, CMA_MAX_NAME, "%s", name);
    -+		STPRINTF(cma->name, "%s", name);
    ++		SPRINTF_END(cma->name, "%s", name);
      	else
     -		snprintf(cma->name, CMA_MAX_NAME,  "cma%d\n", cma_area_count);
    -+		STPRINTF(cma->name, "cma%d\n", cma_area_count);
    ++		SPRINTF_END(cma->name, "cma%d\n", cma_area_count);
      
      	cma->available_count = cma->count = size >> PAGE_SHIFT;
      	cma->order_per_bit = order_per_bit;
    @@ mm/cma_debug.c: static void cma_debugfs_add_one(struct cma *cma, struct dentry *
      	for (r = 0; r < cma->nranges; r++) {
      		cmr = &cma->ranges[r];
     -		snprintf(rdirname, sizeof(rdirname), "%d", r);
    -+		STPRINTF(rdirname, "%d", r);
    ++		SPRINTF_END(rdirname, "%d", r);
      		dir = debugfs_create_dir(rdirname, rangedir);
      		debugfs_create_file("base_pfn", 0444, dir,
      			    &cmr->base_pfn, &cma_debugfs_fops);
    @@ mm/hugetlb.c: void __init hugetlb_add_hstate(unsigned int order)
      	INIT_LIST_HEAD(&h->hugepage_activelist);
     -	snprintf(h->name, HSTATE_NAME_LEN, "hugepages-%lukB",
     -					huge_page_size(h)/SZ_1K);
    -+	STPRINTF(h->name, "hugepages-%lukB", huge_page_size(h)/SZ_1K);
    ++	SPRINTF_END(h->name, "hugepages-%lukB", huge_page_size(h)/SZ_1K);
      
      	parsed_hstate = h;
      }
    @@ mm/hugetlb_cgroup.c: hugetlb_cgroup_cfttypes_init(struct hstate *h, struct cftyp
      		*cft = *tmpl;
      		/* rebuild the name */
     -		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.%s", buf, tmpl->name);
    -+		STPRINTF(cft->name, "%s.%s", buf, tmpl->name);
    ++		SPRINTF_END(cft->name, "%s.%s", buf, tmpl->name);
      		/* rebuild the private */
      		cft->private = MEMFILE_PRIVATE(idx, tmpl->private);
      		/* rebuild the file_offset */
    @@ mm/hugetlb_cma.c: void __init hugetlb_cma_reserve(int order)
      		size = round_up(size, PAGE_SIZE << order);
      
     -		snprintf(name, sizeof(name), "hugetlb%d", nid);
    -+		STPRINTF(name, "hugetlb%d", nid);
    ++		SPRINTF_END(name, "hugetlb%d", nid);
      		/*
      		 * Note that 'order per bit' is based on smallest size that
      		 * may be returned to CMA allocator in the case of
    @@ mm/kasan/report.c: static void print_memory_metadata(const void *addr)
      
     -		snprintf(buffer, sizeof(buffer),
     -				(i == 0) ? ">%px: " : " %px: ", row);
    -+		STPRINTF(buffer, (i == 0) ? ">%px: " : " %px: ", row);
    ++		SPRINTF_END(buffer, (i == 0) ? ">%px: " : " %px: ", row);
      
      		/*
      		 * We should not pass a shadow pointer to generic
    @@ mm/memblock.c: static void __init_memblock memblock_dump(struct memblock_type *t
      #ifdef CONFIG_NUMA
      		if (numa_valid_node(memblock_get_region_node(rgn)))
     -			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
    -+			STPRINTF(nid_buf, " on node %d",
    ++			SPRINTF_END(nid_buf, " on node %d",
      				 memblock_get_region_node(rgn));
      #endif
      		pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
    @@ mm/memblock.c: int reserve_mem_release_by_name(const char *name)
      	start = phys_to_virt(map->start);
      	end = start + map->size - 1;
     -	snprintf(buf, sizeof(buf), "reserve_mem:%s", name);
    -+	STPRINTF(buf, "reserve_mem:%s", name);
    ++	SPRINTF_END(buf, "reserve_mem:%s", name);
      	free_reserved_area(start, end, 0, buf);
      	map->size = 0;
      
    @@ mm/percpu.c: int __init pcpu_page_first_chunk(size_t reserved_size, pcpu_fc_cpu_
      	int nr_g0_units;
      
     -	snprintf(psize_str, sizeof(psize_str), "%luK", PAGE_SIZE >> 10);
    -+	STPRINTF(psize_str, "%luK", PAGE_SIZE >> 10);
    ++	SPRINTF_END(psize_str, "%luK", PAGE_SIZE >> 10);
      
      	ai = pcpu_build_alloc_info(reserved_size, 0, PAGE_SIZE, NULL);
      	if (IS_ERR(ai))
    @@ mm/shrinker_debug.c: int shrinker_debugfs_add(struct shrinker *shrinker)
      	shrinker->debugfs_id = id;
      
     -	snprintf(buf, sizeof(buf), "%s-%d", shrinker->name, id);
    -+	STPRINTF(buf, "%s-%d", shrinker->name, id);
    ++	SPRINTF_END(buf, "%s-%d", shrinker->name, id);
      
      	/* create debugfs entry */
      	entry = debugfs_create_dir(buf, shrinker_debugfs_root);
    @@ mm/zswap.c: static struct zswap_pool *zswap_pool_create(char *type, char *compre
      
      	/* unique name for each pool specifically required by zsmalloc */
     -	snprintf(name, 38, "zswap%x", atomic_inc_return(&zswap_pools_count));
    -+	STPRINTF(name, "zswap%x", atomic_inc_return(&zswap_pools_count));
    ++	SPRINTF_END(name, "zswap%x", atomic_inc_return(&zswap_pools_count));
      	pool->zpool = zpool_create_pool(type, name, gfp);
      	if (!pool->zpool) {
      		pr_err("%s zpool not available\n", type);
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1752113247.git.alx%40kernel.org.
