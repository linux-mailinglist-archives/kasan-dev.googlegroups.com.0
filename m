Return-Path: <kasan-dev+bncBAABBWG6YHBQMGQEEHNNRPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id B456BB010FF
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:56:42 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-23507382e64sf15966785ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:56:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199001; cv=pass;
        d=google.com; s=arc-20240605;
        b=NVdBU0tMyZhSIdpKNxytBdCqoAM9/IjHJtKNTft8TylBmcluSrplNhNmTKsbufHRhi
         7HjDonAIpoQxwP79d/goVklTjDe6xC+rDGaHTioFPHF+mZxmtJi3L/gaWjKDAjdrVS3T
         IIbRkfnyYdGo28WTxMzhu92EsfypjlGFt6k//yT1ShgsAPg93ZXMadzBhJm53XPWYaCn
         hwiZzyas4pnrJWKjdU4I+3WFh0Ibj7S5xmEYVrA1TA4y0UDQoKIrCLPgxIaALDA5C4z+
         TfzcgobSu5DD166UYxwSMcw/NbFWXJmkgPLdKc22KhL+A5/Nj0U0F+pGly6TNbyaRomc
         m3FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=37t1P/OyeiYOJL2g6YdHAC8KZaf2gEpvnMGhjcViKeY=;
        fh=P/Y4JKm+hnGVi96jx5ZTIDSa+pdf4gY0y4xMkysticQ=;
        b=dINM0jfG/OdfgRrZDWRR6Ai/5LITrGmxc/Y6zFrjpI/MHSTykQwB2TMYJCB816tc75
         +DLcXJgVxA6p+aEvtJk7aeyaZg15mVXlMj37/6pXago9jbQ0oR3CQhd6u8rnu7WYRCax
         v3cJKOH+xt2L+exLyW6FmkPKiGEmFRoGDQ1NmUniEvis/9oCwhuypsGMxM0PKm/Feli5
         dm++6ydbtKwBsjyupDhMdyhQ5Op/HWMMJyqge4fluJucXSudImzmHM5i2fI4Bahahrbt
         82UZyF7t/PPYYAdtyqJjLHnlgzI00wkN9OjRAepBPLpuwroPfEYGu04IzUmAfC0WHdo2
         Gc9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kZLNgHjX;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199001; x=1752803801; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=37t1P/OyeiYOJL2g6YdHAC8KZaf2gEpvnMGhjcViKeY=;
        b=SdvGyF3x5oLPkHgQimfcqcT7Du4lWrozTJTOQkxe6xtt0wEaRAyC2hMFYqVAqfIs8N
         u0NZZJ0qjH7EBvqD7bmHn3VehGtQ4X3wIWDEv/0OSSK+zQlYdet3fuUAY2RNN7QNpq+Q
         sWYmx6DOOwSvHAKT5+Il4Zg2G2hcNR9v+tudE/oqg0YZpFhr2Uk+Qonjr2l0Dzl8XsmZ
         qviJrNsaQuKMLZOtoCNTZ8UX6TZSf0e+fnXTVJLuCPRPl4yNF3FhLaGyEcnJkFifPqnc
         6GmTw3kyskn7Zm4soV5Vtuic7I3deNPKJ61NwddTWO0xj1i3o2Ekl79wLDTxjmLZVIzq
         6r3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199001; x=1752803801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=37t1P/OyeiYOJL2g6YdHAC8KZaf2gEpvnMGhjcViKeY=;
        b=wHQBtsBmoxHeYvJGwbLwPXwn8OLPOOwvMUY0TElinI4Try3cYUEg+OwgZqgzlGS47z
         bKj2CF/c3aeK6FyMfL2oIyapu5VwOcIH1V5nDkvKQ2LDbk4fe8KEvexnVeojD+CdYZEu
         cxJJrG3w1501mmsv8RtkkMFYWU6T5r+708tQJwg24l/0S4sdU14VWw3BuLQ/bDx7xkjm
         QX4GzskaJTWQZWvpQOgUh/JtISRSVFcW2w8P//gZLZFTHh2BwG7zFwmwsbiKQcUCZHXB
         b1Kl3NlNkCCRPZRpWXdwNsY1ZM+IV3SZSOqetgsZYIg3dZ1XNel9oCPlVRJhaX629nSI
         5kEQ==
X-Forwarded-Encrypted: i=2; AJvYcCUglsEpXYSbYEGw6d5PJnZZhXLXLILjvdNNx0HyYgVz1zKVKi7YbZQi7/MfVdAX9ge9jRewcw==@lfdr.de
X-Gm-Message-State: AOJu0YxxHiHKDxro9yhNX8ivj128xdYvxtk280JBC8V+/Zn+imKtBrEo
	yk7IFpMAR1+4zl5OShV8N1nWhN8R3W8/qkLYU0bDd601Ps1rGUPAx9aZ
X-Google-Smtp-Source: AGHT+IH3Hyd50KZZ9+bzvH+TFSOcnBKa8ZLYsWc8aDMGNEGmQVDW0mnCOHf56TB0GM/+wxjBeNZipA==
X-Received: by 2002:a17:902:e78c:b0:235:225d:3098 with SMTP id d9443c01a7336-23dee3a363amr14474325ad.46.1752199000851;
        Thu, 10 Jul 2025 18:56:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd80/Pp5CR2bITnrInBATMqnoFNBzBG8cPZItnDFGMupA==
Received: by 2002:a17:902:c7c1:b0:234:a07c:2698 with SMTP id
 d9443c01a7336-23de2e0d5a4ls9490685ad.1.-pod-prod-07-us; Thu, 10 Jul 2025
 18:56:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUSQkpgqf5v7hDgsvAMUNiDmgiqt1TsmGsr8XT0V8WGS0fWfet+ba2GxfgGX0ClAUrTb5aO/slyzPs=@googlegroups.com
X-Received: by 2002:a17:902:db08:b0:234:8e78:ce8a with SMTP id d9443c01a7336-23dee3a62f4mr15762065ad.48.1752198999685;
        Thu, 10 Jul 2025 18:56:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752198999; cv=none;
        d=google.com; s=arc-20240605;
        b=Pwi9swUXFe9+3T+Q7+GYF3XpNrOjCBFlVusw+jiSOZlOQPCV4xIKvPO7tV+vNLLOny
         z681Ik+zP7WmCpVKo/J8oG1BkMKLJxaTr8Ir9tyMF5Q0PM9IjiQ6OvGbE9kDyLTSmv/F
         nKzOFCO1yy0ch6A8b2Opr2brD2F9yV0i/YqmX0xwHb4N99tBU9x3KdBCO7s0ocO+3pW/
         LxkpE2UpNxrkXtyGitgqdT7gTRHQGYeB7hwrvmrCXpCa6mJNobvE3doC18O2x4Vfxquo
         MMqAGiG+oZ8x/2i8YMd6vTM3eGM03fd5heGfMBKhzhs9M9ArSwrRRoIuim31HT5ZIAqF
         chug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hklIomL9+Py3wU4DJKozEXEGrC5N+H4xo9VGphGB9eY=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=XDBNbFmM9JUdvThezQYIp2JiuLIkz8smnfIh/LXu/yqn0QUK524uriWHtuJPnEQlW+
         4y1e4wk5j+wQBbnXufkRyPzaBwWa/uCcHM49CnDeC2ZzYfntvZHAzXW7AERoE8LA2/A+
         QMkw4i8QugKAMkgqAF7YD2s99jw3r17WnYbh4mno8TZA5ha00zFiV76sC+KGzqRspDfk
         5WEmTa39RualHB1hyTJpDsTg3ZYXM6W9JQYII4noWmigXtV8BK6Niw4jVUIO4uy71Jb7
         ycU9UQst95SetOAFvjgkdIE/dYE07hyPSycfjU952UOhbr1Sc/2DhCrKjY6oMZ14VosT
         SA3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kZLNgHjX;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b3bbe558c25si123530a12.1.2025.07.10.18.56.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:56:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 72300614FE;
	Fri, 11 Jul 2025 01:56:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2028BC4CEE3;
	Fri, 11 Jul 2025 01:56:32 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:56:31 +0200
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
Subject: [RFC v6 0/8] Add and use sprintf_{end,trunc,array}() instead of less
 ergonomic APIs
Message-ID: <cover.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751823326.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kZLNgHjX;       spf=pass
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

Hi,

Changes in v6:

[As commented in private to Linus, I assume the NAK from Linus in v5
 applies to the macro that evaluates twice.  This is resolved in v6, so
 I send assuming no NAKs to the overall patch set.]

-  Don't try to have a single function.  Have sprintf_end() for chaining
   calls and sprintf_trunc() --which is the fmt version of strscpy()--
   for single calls.  Then sprintf_array() --which is the fmt version of
   the 2-argument strscpy()-- for single calls with an array as input.
-  Fix implementation of sprintf_array() to not evaluate twice.

These changes are essentially a roll-back to the general idea in v3,
except for the more explicit names.

Remaining questions:

-  There are only 3 remaining calls to snprintf(3) under mm/.  They are
   just fine for now, which is why I didn't replace them.  If anyone
   wants to replace them, to get rid of all snprintf(3), we could that.
   I think for now we can leave them, to minimize the churn.

        $ grep -rnI snprintf mm/
        mm/hugetlb_cgroup.c:674:                snprintf(buf, size, "%luGB", hsize / SZ_1G);
        mm/hugetlb_cgroup.c:676:                snprintf(buf, size, "%luMB", hsize / SZ_1M);
        mm/hugetlb_cgroup.c:678:                snprintf(buf, size, "%luKB", hsize / SZ_1K);

   They could be replaced by sprintf_trunc().

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
-  The call sprintf_end(p, end, "") in lib/stackdepot.c, within
   stack_depot_sprint_end(), produces a warning for having an empty
   string.  This could be replaced by a strcpy_end(p, end, "") if/when
   we add that function.

For anyone new to the thread, sprintf_end() will be proposed for
standardization soon as seprintf():
<https://lore.kernel.org/linux-hardening/20250710024745.143955-1-alx@kernel.org/T/#u>


Have a lovely night!
Alex


Alejandro Colomar (8):
  vsprintf: Add [v]sprintf_trunc()
  vsprintf: Add [v]sprintf_end()
  sprintf: Add [v]sprintf_array()
  stacktrace, stackdepot: Add sprintf_end()-like variants of functions
  mm: Use sprintf_end() instead of less ergonomic APIs
  array_size.h: Add ENDOF()
  mm: Fix benign off-by-one bugs
  mm: Use [v]sprintf_array() to avoid specifying the array size

 include/linux/array_size.h |   6 +++
 include/linux/sprintf.h    |   8 +++
 include/linux/stackdepot.h |  13 +++++
 include/linux/stacktrace.h |   3 ++
 kernel/stacktrace.c        |  28 ++++++++++
 lib/stackdepot.c           |  13 +++++
 lib/vsprintf.c             | 107 +++++++++++++++++++++++++++++++++++++
 mm/backing-dev.c           |   2 +-
 mm/cma.c                   |   4 +-
 mm/cma_debug.c             |   2 +-
 mm/hugetlb.c               |   3 +-
 mm/hugetlb_cgroup.c        |   2 +-
 mm/hugetlb_cma.c           |   2 +-
 mm/kasan/report.c          |   3 +-
 mm/kfence/kfence_test.c    |  28 +++++-----
 mm/kmsan/kmsan_test.c      |   6 +--
 mm/memblock.c              |   4 +-
 mm/mempolicy.c             |  18 +++----
 mm/page_owner.c            |  32 +++++------
 mm/percpu.c                |   2 +-
 mm/shrinker_debug.c        |   2 +-
 mm/slub.c                  |   5 +-
 mm/zswap.c                 |   2 +-
 23 files changed, 237 insertions(+), 58 deletions(-)

Range-diff against v5:
-:  ------------ > 1:  dab6068bef5c vsprintf: Add [v]sprintf_trunc()
1:  2c4f793de0b8 ! 2:  c801c9a1a90d vsprintf: Add [v]sprintf_end()
    @@ Commit message
         Signed-off-by: Alejandro Colomar <alx@kernel.org>
     
      ## include/linux/sprintf.h ##
    -@@ include/linux/sprintf.h: __printf(3, 4) int snprintf(char *buf, size_t size, const char *fmt, ...);
    - __printf(3, 0) int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);
    - __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
    +@@ include/linux/sprintf.h: __printf(3, 4) int scnprintf(char *buf, size_t size, const char *fmt, ...);
      __printf(3, 0) int vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
    + __printf(3, 4) int sprintf_trunc(char *buf, size_t size, const char *fmt, ...);
    + __printf(3, 0) int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args);
     +__printf(3, 4) char *sprintf_end(char *p, const char end[0], const char *fmt, ...);
     +__printf(3, 0) char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args);
      __printf(2, 3) __malloc char *kasprintf(gfp_t gfp, const char *fmt, ...);
    @@ include/linux/sprintf.h: __printf(3, 4) int snprintf(char *buf, size_t size, con
      __printf(2, 0) const char *kvasprintf_const(gfp_t gfp, const char *fmt, va_list args);
     
      ## lib/vsprintf.c ##
    -@@ lib/vsprintf.c: int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
    +@@ lib/vsprintf.c: int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args)
      }
    - EXPORT_SYMBOL(vscnprintf);
    + EXPORT_SYMBOL(vsprintf_trunc);
      
     +/**
     + * vsprintf_end - va_list string end-delimited print formatted
    @@ lib/vsprintf.c: int vscnprintf(char *buf, size_t size, const char *fmt, va_list
     +char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args)
     +{
     +  int len;
    -+  size_t size;
     +
     +  if (unlikely(p == NULL))
     +          return NULL;
     +
    -+  size = end - p;
    -+  if (WARN_ON_ONCE(size == 0 || size > INT_MAX))
    -+          return NULL;
    -+
    -+  len = vsnprintf(p, size, fmt, args);
    -+  if (unlikely(len >= size))
    ++  len = vsprintf_trunc(p, end - p, fmt, args);
    ++  if (unlikely(len < 0))
     +          return NULL;
     +
     +  return p + len;
    @@ lib/vsprintf.c: int vscnprintf(char *buf, size_t size, const char *fmt, va_list
      /**
       * snprintf - Format a string and place it in a buffer
       * @buf: The buffer to place the result into
    -@@ lib/vsprintf.c: int scnprintf(char *buf, size_t size, const char *fmt, ...)
    +@@ lib/vsprintf.c: int sprintf_trunc(char *buf, size_t size, const char *fmt, ...)
      }
    - EXPORT_SYMBOL(scnprintf);
    + EXPORT_SYMBOL(sprintf_trunc);
      
     +/**
     + * sprintf_end - string end-delimited print formatted
6:  04c1e026a67f ! 3:  9348d5df2d9f sprintf: Add [v]sprintf_array()
    @@ Commit message
         array.
     
         These macros are essentially the same as the 2-argument version of
    -    strscpy(), but with a formatted string, and returning a pointer to the
    -    terminating '\0' (or NULL, on error).
    +    strscpy(), but with a formatted string.
     
         Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
         Cc: Marco Elver <elver@google.com>
    @@ include/linux/sprintf.h
      #include <linux/types.h>
     +#include <linux/array_size.h>
     +
    -+#define sprintf_array(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
    -+#define vsprintf_array(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)
    ++#define sprintf_array(a, fmt, ...)  sprintf_trunc(a, ARRAY_SIZE(a), fmt, ##__VA_ARGS__)
    ++#define vsprintf_array(a, fmt, ap)  vsprintf_trunc(a, ARRAY_SIZE(a), fmt, ap)
      
      int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
      
2:  894d02b08056 = 4:  6c5d8e6012f0 stacktrace, stackdepot: Add sprintf_end()-like variants of functions
3:  690ed4d22f57 = 5:  8a0ffc1bf43d mm: Use sprintf_end() instead of less ergonomic APIs
4:  e05c5afabb3c = 6:  37b1088dbd01 array_size.h: Add ENDOF()
5:  515445ae064d = 7:  c88780354e13 mm: Fix benign off-by-one bugs
7:  e53d87e684ef = 8:  aa6323cbea64 mm: Use [v]sprintf_array() to avoid specifying the array size

base-commit: 0ff41df1cb268fc69e703a08a57ee14ae967d0ca
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1752193588.git.alx%40kernel.org.
