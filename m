Return-Path: <kasan-dev+bncBAABBBPCYDBQMGQELGZG3XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id BEA7BB00DC4
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:30:47 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2e8f1365181sf993204fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:30:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183046; cv=pass;
        d=google.com; s=arc-20240605;
        b=eoTMd9Bal3cbMJgyhBdAooltk5wiLnFLyks1uqgpQFvg3u6PfCGbY7s/dQkTfFhV9g
         lDT+akcS+DvZ/4530VD6GLSKl/lFl0O88stunn8wUp2PfeoPPwgat1n6N8voAvHXFZCJ
         bztTteLn4wKYwrr50g7qvxSMgTOVG5tzstqu4ODumqi6eWMc8xkmWwqrR0qkqValy3K/
         7V7qriBwq4Jv5n9V5xKw4qSt10L/OYjrrlNJy4wNAMohRfnfxAVa1lU9KVRpSdjl8lps
         PwW3NjjGDfx+3m+/zowyEDrYKnWKd+uEK6zRj3Aj0pQcqfCfeMbVgyPsiQRsrM20KZuV
         bgkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HdrGl9sSl9v2y4XUG3LReOGtM1iMXnYnCc366aJvRZQ=;
        fh=yxuL6UqZ09oIP5vYtJ+OpxWoNOcpN3ZPoh9G67JUTP0=;
        b=bMYwLNSdWCXhQvfhW0xG5QxLhtmBx7zhLyQPEFLeWRdG+O1hB+3wLMvkZyk+ISu6DV
         aQjFDD6wBYNEgcPrOZ7uLluquWwQn/EEb18gKVHWx0GWkMdCts7cqzGM4WOdG2LiNmBK
         Pm665RdW7VaZZWU/ndnmOXDHqtJhL9UYM2/A/JZR2MJevCVHIFNOKsxJ1aNe0X9abEe2
         4R1agFIKuxwxVgD2ub+1u/oMl8FkI/w6Vj4YSX0JDBJJugA9D875UVJUYsAbjmO7+kA2
         T0qs506U/UOdv9RvgOVAMPQcBD23UPIuyH+wANMI8FM4RPjslUEhci2kIi4iAqgubsWo
         D6cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SHxRN2zF;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183046; x=1752787846; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HdrGl9sSl9v2y4XUG3LReOGtM1iMXnYnCc366aJvRZQ=;
        b=vb8doSotuAP7MtCSerUX7/zmqZ4CliFdggYW/9XrBpEb3Kji5roa0k2IxJ1K7lG7bu
         zfAYsNt46iVBkg7N/dyAaXEk/duXD4Ia2izNaVgF/M55xOiajg57cZF4c5zJX0mLplk6
         g9mIOWlUUG1U/5Q+ySEiMaoWRUGzzl1Jbcjs4MBx5r93x+QJcRmhVwq5lvotwaQ7q23j
         e/Q6BTSdxmpTFlHU0GcDLWIIlnqAhFXmo47eHFkW3AqBliVa9FVsWH0K6+fkYcBMam/R
         G+l/VqB5XCY//tcftzy26FRGNstnCcQ74F2JjNn7jHOlK1Nx0gwqMXK7BWqetDlU7vhY
         6QEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183046; x=1752787846;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HdrGl9sSl9v2y4XUG3LReOGtM1iMXnYnCc366aJvRZQ=;
        b=XEBTCoSH8JSykHRoGTtiKcUk5szLuc6CYJ87pV1hKwWWzAXQae9+TPSK2KGMzvQoRb
         MhD1Q0+kdT0b/aGcXYAhPN1g94of5guHJ6J+5FQVHvYdIw7dC9lrGZWD6zpaj98hU7oh
         J2EUXU6ZlT4+mfCV+SchjyshJbbMDKsDC3NsjA1hXZMt9Ojr56YZd/LLBiC9cBvZRQ53
         aeO2v6f711JDFSqgv1iM3aO1YM+iSQrIg0rzhY25Yh+dP0QaW0Jy+SNIQO8Xymc1qCzL
         4o3DpIHkuqrABtAGj9sS2YITy4hAiKIaaPByB+p/NPY4XGuasYbZ47VoKUKOsP5oNMZC
         3BJg==
X-Forwarded-Encrypted: i=2; AJvYcCXhvcnaBS0mauXrVh3phBNjQAGnUtL6omoUVwT9es1Jd3hL4CuLRXM37oapTg1QdfQDBNpd9w==@lfdr.de
X-Gm-Message-State: AOJu0YwfoWA8OZ0fvhrSw8EXdalZnzSQQElj/1HWAajOB8/VDZUDpdbh
	TJWe7xJT+JXYsSwk1giMI3/dh+ewdpzynFucGJNuOLtTCSwDkpfW6Mfs
X-Google-Smtp-Source: AGHT+IHcyxi/2iqfUUl7N0xTmfDPBrncr9wGNgM5u1ouN/KRCppuM01TMsfzUlPkBJ3qL2YuYBZl2w==
X-Received: by 2002:a05:6870:aa8a:b0:287:471:41eb with SMTP id 586e51a60fabf-2ff26e7a7d4mr591020fac.6.1752183046148;
        Thu, 10 Jul 2025 14:30:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdkvIGaT0VdUwMjvfHP6PYE6+wlFSV4cg7Ou9g7u08BRQ==
Received: by 2002:a05:6870:3054:b0:2c1:8546:7864 with SMTP id
 586e51a60fabf-2ff0bcc7901ls488196fac.2.-pod-prod-07-us; Thu, 10 Jul 2025
 14:30:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZ965KzQBI6bOePFgBixK3vrgOX2yOzU+BN6cOvrYgIfz4ny2z6ed20/JO/9zcmrQi7WmMJy+pGGA=@googlegroups.com
X-Received: by 2002:a05:6870:1c9:b0:2e9:735:91ba with SMTP id 586e51a60fabf-2ff27001c8emr490988fac.25.1752183045141;
        Thu, 10 Jul 2025 14:30:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183045; cv=none;
        d=google.com; s=arc-20240605;
        b=LOM4itGREj+vd1QKmWDsEylFtwJpD+AtzAQSjUptaVFyJ+/AJk1kw4EU/NmSP+LK5V
         jqC6batUm6eit+oylk+DWnaR6PlAZwNIvWFZVh3xuizdkyhoXcoK+PgkF9HA3C2LPoEN
         fPRCB3J/2Nr9Hl7ia3i9PRumXL9pN+f4U7unJdzsJjuAM8hKKhqRY3WPSYm/mGgj2WMI
         eIwFj+gpRdnDgtzbIdpRsWd5t3I/gApENX805Rn4yN7dhIZDrGup/v5BPZJZPw3qjEMO
         ykafixtvUR9LFw3p8GTwNCTmm+coF4TGAJkn4UR0AnMu3uCRpIZG/Ok7F+a/Q7utwXSo
         bGgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Z2ExmJthtYwpDpsJZIDGDpDtUQzlQ2X/0+RptXBPkxY=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=MusTBIBRIokZbnnn8X+bHSNa4GyzJu6eZbHdJwBik3RU/l8jtNCunEkZS/lh99sUHI
         VrNiR/1ZdLy84/WLKC+p6XgvfUps1f2yNHJAsL812C2AmwcyDlzB4OQhZndkU5bff7Py
         /G1tC/oDlqhxLM4TBFsaaugkU9NK2TKydDOyJWHJL5ELagcUy14Xi/hvB2jScH6ykadX
         8XZCefS91m/Gzmgc4a4rzl/9BmRtSF8+8nMnm50chOL0M1DWzsOm9lNJVnlOdvI7Do0y
         C1y+EAFrUaTUzP+2dN053rLN2aXDX+Af5EisD0mfWEKQaQ5tBWkbtAJ6SAP9OpL+DLRp
         W05g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SHxRN2zF;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ff1165acd1si146213fac.3.2025.07.10.14.30.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:30:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 689B2A547D5;
	Thu, 10 Jul 2025 21:30:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6F644C4CEE3;
	Thu, 10 Jul 2025 21:30:39 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:30:37 +0200
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
Subject: [RFC v5 0/7] Add and use sprintf_{end,array}() instead of less
 ergonomic APIs
Message-ID: <cover.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SHxRN2zF;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
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

Hi,

Changes in v5:

-  Minor fix in commit message.
-  Rename [V]SPRINTF_END() => [v]sprintf_array(), keeping the
   implementation.

Remaining questions:

-  There are only 3 remaining calls to snprintf(3) under mm/.  They are
   just fine for now, which is why I didn't replace them.  If anyone
   wants to replace them, to get rid of all snprintf(3), we could that.
   I think for now we can leave them, to minimize the churn.

        $ grep -rnI snprintf mm/
        mm/hugetlb_cgroup.c:674:                snprintf(buf, size, "%luGB", hsize / SZ_1G);
        mm/hugetlb_cgroup.c:676:                snprintf(buf, size, "%luMB", hsize / SZ_1M);
        mm/hugetlb_cgroup.c:678:                snprintf(buf, size, "%luKB", hsize / SZ_1K);

-  There are only 2 remaining calls to the kernel's scnprintf().  This
   one I would really like to get rid of.  Also, those calls are quite
   suspicious of not being what we want.  Please do have a look at them
   and confirm what's the appropriate behavior in the 2 cases when the
   string is truncated or not copied at all.  That code is very scary
   for me to try to guess.

        $ grep -rnI scnprintf mm/
        mm/kfence/report.c:75:          int len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skipnr]);
        mm/kfence/kfence_test.mod.c:22: { 0x96848186, "scnprintf" },
        mm/kmsan/report.c:42:           len = scnprintf(buf, sizeof(buf), "%ps",

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

For anyone new to the thread, sprintf_end() will be proposed for
standardization soon as seprintf():
<https://lore.kernel.org/linux-hardening/20250710024745.143955-1-alx@kernel.org/T/#u>


Have a lovely night!
Alex


Alejandro Colomar (7):
  vsprintf: Add [v]sprintf_end()
  stacktrace, stackdepot: Add sprintf_end()-like variants of functions
  mm: Use sprintf_end() instead of less ergonomic APIs
  array_size.h: Add ENDOF()
  mm: Fix benign off-by-one bugs
  sprintf: Add [v]sprintf_array()
  mm: Use [v]sprintf_array() to avoid specifying the array size

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

Range-diff against v4:
1:  2c4f793de0b8 = 1:  2c4f793de0b8 vsprintf: Add [v]sprintf_end()
2:  894d02b08056 = 2:  894d02b08056 stacktrace, stackdepot: Add sprintf_end()-like variants of functions
3:  690ed4d22f57 = 3:  690ed4d22f57 mm: Use sprintf_end() instead of less ergonomic APIs
4:  e05c5afabb3c = 4:  e05c5afabb3c array_size.h: Add ENDOF()
5:  44a5cfc82acf ! 5:  515445ae064d mm: Fix benign off-by-one bugs
    @@ Commit message
     
         We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
         doesn't write more than $2 bytes including the null byte, so trying to
    -    pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
    -    the situation isn't different: seprintf() will stop writing *before*
    +    pass 'size-1' there is wasting one byte.  Now that we use sprintf_end(),
    +    the situation isn't different: sprintf_end() will stop writing *before*
         'end' --that is, at most the terminating null byte will be written at
         'end-1'--.
     
6:  0314948eb225 ! 6:  04c1e026a67f sprintf: Add [V]SPRINTF_END()
    @@ Metadata
     Author: Alejandro Colomar <alx@kernel.org>
     
      ## Commit message ##
    -    sprintf: Add [V]SPRINTF_END()
    +    sprintf: Add [v]sprintf_array()
     
         These macros take the end of the array argument implicitly to avoid
         programmer mistakes.  This guarantees that the input is an array, unlike
    @@ include/linux/sprintf.h
      #include <linux/types.h>
     +#include <linux/array_size.h>
     +
    -+#define SPRINTF_END(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
    -+#define VSPRINTF_END(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)
    ++#define sprintf_array(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
    ++#define vsprintf_array(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)
      
      int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
      
7:  f99632f42eee ! 7:  e53d87e684ef mm: Use [V]SPRINTF_END() to avoid specifying the array size
    @@ Metadata
     Author: Alejandro Colomar <alx@kernel.org>
     
      ## Commit message ##
    -    mm: Use [V]SPRINTF_END() to avoid specifying the array size
    +    mm: Use [v]sprintf_array() to avoid specifying the array size
     
         Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
         Cc: Marco Elver <elver@google.com>
    @@ mm/backing-dev.c: int bdi_register_va(struct backing_dev_info *bdi, const char *
      		return 0;
      
     -	vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
    -+	VSPRINTF_END(bdi->dev_name, fmt, args);
    ++	vsprintf_array(bdi->dev_name, fmt, args);
      	dev = device_create(&bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
      	if (IS_ERR(dev))
      		return PTR_ERR(dev);
    @@ mm/cma.c: static int __init cma_new_area(const char *name, phys_addr_t size,
      
      	if (name)
     -		snprintf(cma->name, CMA_MAX_NAME, "%s", name);
    -+		SPRINTF_END(cma->name, "%s", name);
    ++		sprintf_array(cma->name, "%s", name);
      	else
     -		snprintf(cma->name, CMA_MAX_NAME,  "cma%d\n", cma_area_count);
    -+		SPRINTF_END(cma->name, "cma%d\n", cma_area_count);
    ++		sprintf_array(cma->name, "cma%d\n", cma_area_count);
      
      	cma->available_count = cma->count = size >> PAGE_SHIFT;
      	cma->order_per_bit = order_per_bit;
    @@ mm/cma_debug.c: static void cma_debugfs_add_one(struct cma *cma, struct dentry *
      	for (r = 0; r < cma->nranges; r++) {
      		cmr = &cma->ranges[r];
     -		snprintf(rdirname, sizeof(rdirname), "%d", r);
    -+		SPRINTF_END(rdirname, "%d", r);
    ++		sprintf_array(rdirname, "%d", r);
      		dir = debugfs_create_dir(rdirname, rangedir);
      		debugfs_create_file("base_pfn", 0444, dir,
      			    &cmr->base_pfn, &cma_debugfs_fops);
    @@ mm/hugetlb.c: void __init hugetlb_add_hstate(unsigned int order)
      	INIT_LIST_HEAD(&h->hugepage_activelist);
     -	snprintf(h->name, HSTATE_NAME_LEN, "hugepages-%lukB",
     -					huge_page_size(h)/SZ_1K);
    -+	SPRINTF_END(h->name, "hugepages-%lukB", huge_page_size(h)/SZ_1K);
    ++	sprintf_array(h->name, "hugepages-%lukB", huge_page_size(h)/SZ_1K);
      
      	parsed_hstate = h;
      }
    @@ mm/hugetlb_cgroup.c: hugetlb_cgroup_cfttypes_init(struct hstate *h, struct cftyp
      		*cft = *tmpl;
      		/* rebuild the name */
     -		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.%s", buf, tmpl->name);
    -+		SPRINTF_END(cft->name, "%s.%s", buf, tmpl->name);
    ++		sprintf_array(cft->name, "%s.%s", buf, tmpl->name);
      		/* rebuild the private */
      		cft->private = MEMFILE_PRIVATE(idx, tmpl->private);
      		/* rebuild the file_offset */
    @@ mm/hugetlb_cma.c: void __init hugetlb_cma_reserve(int order)
      		size = round_up(size, PAGE_SIZE << order);
      
     -		snprintf(name, sizeof(name), "hugetlb%d", nid);
    -+		SPRINTF_END(name, "hugetlb%d", nid);
    ++		sprintf_array(name, "hugetlb%d", nid);
      		/*
      		 * Note that 'order per bit' is based on smallest size that
      		 * may be returned to CMA allocator in the case of
    @@ mm/kasan/report.c: static void print_memory_metadata(const void *addr)
      
     -		snprintf(buffer, sizeof(buffer),
     -				(i == 0) ? ">%px: " : " %px: ", row);
    -+		SPRINTF_END(buffer, (i == 0) ? ">%px: " : " %px: ", row);
    ++		sprintf_array(buffer, (i == 0) ? ">%px: " : " %px: ", row);
      
      		/*
      		 * We should not pass a shadow pointer to generic
    @@ mm/memblock.c: static void __init_memblock memblock_dump(struct memblock_type *t
      #ifdef CONFIG_NUMA
      		if (numa_valid_node(memblock_get_region_node(rgn)))
     -			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
    -+			SPRINTF_END(nid_buf, " on node %d",
    ++			sprintf_array(nid_buf, " on node %d",
      				 memblock_get_region_node(rgn));
      #endif
      		pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
    @@ mm/memblock.c: int reserve_mem_release_by_name(const char *name)
      	start = phys_to_virt(map->start);
      	end = start + map->size - 1;
     -	snprintf(buf, sizeof(buf), "reserve_mem:%s", name);
    -+	SPRINTF_END(buf, "reserve_mem:%s", name);
    ++	sprintf_array(buf, "reserve_mem:%s", name);
      	free_reserved_area(start, end, 0, buf);
      	map->size = 0;
      
    @@ mm/percpu.c: int __init pcpu_page_first_chunk(size_t reserved_size, pcpu_fc_cpu_
      	int nr_g0_units;
      
     -	snprintf(psize_str, sizeof(psize_str), "%luK", PAGE_SIZE >> 10);
    -+	SPRINTF_END(psize_str, "%luK", PAGE_SIZE >> 10);
    ++	sprintf_array(psize_str, "%luK", PAGE_SIZE >> 10);
      
      	ai = pcpu_build_alloc_info(reserved_size, 0, PAGE_SIZE, NULL);
      	if (IS_ERR(ai))
    @@ mm/shrinker_debug.c: int shrinker_debugfs_add(struct shrinker *shrinker)
      	shrinker->debugfs_id = id;
      
     -	snprintf(buf, sizeof(buf), "%s-%d", shrinker->name, id);
    -+	SPRINTF_END(buf, "%s-%d", shrinker->name, id);
    ++	sprintf_array(buf, "%s-%d", shrinker->name, id);
      
      	/* create debugfs entry */
      	entry = debugfs_create_dir(buf, shrinker_debugfs_root);
    @@ mm/zswap.c: static struct zswap_pool *zswap_pool_create(char *type, char *compre
      
      	/* unique name for each pool specifically required by zsmalloc */
     -	snprintf(name, 38, "zswap%x", atomic_inc_return(&zswap_pools_count));
    -+	SPRINTF_END(name, "zswap%x", atomic_inc_return(&zswap_pools_count));
    ++	sprintf_array(name, "zswap%x", atomic_inc_return(&zswap_pools_count));
      	pool->zpool = zpool_create_pool(type, name, gfp);
      	if (!pool->zpool) {
      		pr_err("%s zpool not available\n", type);
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1752182685.git.alx%40kernel.org.
