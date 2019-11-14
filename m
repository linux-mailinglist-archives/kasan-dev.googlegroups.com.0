Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFFOW3XAKGQECXFR7XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 22A91FCC7C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:06 +0100 (CET)
Received: by mail-vs1-xe3f.google.com with SMTP id m15sf992604vsj.22
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754645; cv=pass;
        d=google.com; s=arc-20160816;
        b=EoZSaF2Y+qqAqUjUuTawSsc5TW58jQgzGo+WPWqDimdiEtI27VcymdRE/8zkgiDSni
         BXizJUuoz061jwxPYwbHw7J8206TZnu/5ZxM12A6bn7NxHIQhwBOwGwy/Pw0o7jX9td8
         xJL67kngC3y1DePkf4Y2/sqco/BKgoZsGUzIxgprcwPxN9i/mw/V5jEJrAAVq6LXGNSq
         oCCyDk4ObcVOxmEH2p9bwL+R7Jw+z2Jwkrpw3hFg/67lL3ENEbb1OfQ1v6lJHAGBqpry
         1nduhJPPBdwIZrgGKmqGdTyM5MRNb/H28pdbHQDQNnZaq4tzyZKwRV05RtlA+IUW2xw6
         Q7hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4yy9Cgyt39h4Nj6YANMpDrGNgQJYGwKLsGuyW0u0ZQo=;
        b=k5s8bj/2i5c9eQWdUluDSHEbvKx3N0HtQkrRLwMHFIJbXHt88q1/zz657GwfxzFhh1
         leb4E3gNl+CPK0G7VKCWb+39i24bLP0U5JK+SYODuss4dZeRtHe04TID/bH4evxzwlol
         R1NTfsO72vdNKFEKGoX9BMNet/BT13SkkcORLuY/ZhbT0MkP3odgh2dPI+YWSqoeLY0V
         kgIfc+QMoaXFySt8sST4Lfzs8brWtOVC33DwPwCZz/NpbKEft0nBRY0lK5lL211NH9Jv
         jtvFqUHoMAXH/pOj9YQUWoYLDc2acMFPYbtzEoDHznZC4LeYtvXaIE3lJFHqSTkYWVvq
         K8Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HvmXn12w;
       spf=pass (google.com: domain of 3e5fnxqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3E5fNXQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4yy9Cgyt39h4Nj6YANMpDrGNgQJYGwKLsGuyW0u0ZQo=;
        b=B8z9SnSWkMKm42nbR4H1yCJ1nOPiD63pu2vbMFciCwMFP9zHelDZaN9hbPLbKBTehy
         2TMoGLCaOwmLcwvQ8H9DbLVuwgZYy3NLRMvECDZ71PEO5uzlS4Jyy2VhgDWKNCi3iG8+
         n1JQJWSDrCsJ8L5MaqSx+thFGXo4bR/d1afnr1HchWdriehThddHIjhLWH1bR/ixlFg0
         F8ixXofSqj0Z85wh6TpQ6sosuSRtN5LxnAe8aHYj6dm7QTzRaGQnEXkBt1QEasKbIirn
         ri3khjlSawqj4HU4PesEFc4e3GYW4W+5yQjqmFVnmTayLarnBt6oJ+ov2+uYom3n+v5N
         QOuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4yy9Cgyt39h4Nj6YANMpDrGNgQJYGwKLsGuyW0u0ZQo=;
        b=IBTFlhkYBU/TYiuXthX/Ofwa7BqQS8ROZdt0tEM38RyGgmqQx3rSwrZ05MV5l4BP01
         OlTUiXvAyqdjmzRxdGlTmQFV4eAdib5X2SHCaGCEZ3bhy+IXiDuRAkTqmnte33eYrhyX
         rEjwaKn1G8UhLTXQgCIDHwHqcHeQ/+PXKQ2ITRgjknKAgK0v7dMS9s7tNrEgGCa85f9T
         3WZTG+QEv3mcUP7Dx4rwKISWTyVDcdKZ7sOz7zzkNZKp7hK+ej3CMkK4zFZpBJZWysWH
         DlXzuPXX2C7n99dI/p4hfdWYD2mjG0TGlQVL5ZDVtWXLJV1Sh1jO7tEmuNTnjeZSFiSv
         jVpg==
X-Gm-Message-State: APjAAAVMXkMKBc9HHHx3pWDFYh+Up+hmf6MpTSlwHct1vhQvzF7KzPzq
	4i0qQZXCMuOc4K1RU95NvT4=
X-Google-Smtp-Source: APXvYqxZOUwO9TkR+SdqIUd+/L2pTUBUvXGtbqsxgHk0bRcmeup7DTe1mVmyzukh18KRU8a4tlIn9g==
X-Received: by 2002:a67:3195:: with SMTP id x143mr6363218vsx.74.1573754644984;
        Thu, 14 Nov 2019 10:04:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2c0e:: with SMTP id l14ls172550uar.7.gmail; Thu, 14 Nov
 2019 10:04:04 -0800 (PST)
X-Received: by 2002:ab0:5a41:: with SMTP id m1mr6171328uad.85.1573754644590;
        Thu, 14 Nov 2019 10:04:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754644; cv=none;
        d=google.com; s=arc-20160816;
        b=R//2jYGnGENe+QTJIRj3wRHP6AynTKHYOSsGzGSH6j4vi6MR9aE5iNS2AoNXPoR/re
         uZuKJKnUj4RJnNy0R46piwYcfMFnMi+S0+iMSsEORSEL0q4hJRPmPaXE5pThjiKpDpzj
         TCtVxRpWkEGU9PXOrgZiPU9dzBvzihXwokR2YNIhCwPYj6SzoEUgzfDorUt4O8DAkv9e
         Q0tb6Le7lZKHZQKnackAvCWSdn7ycNF6Ca++x+snLy4WLP/H6+frAoxyjlnLWwK1M6sB
         tJ5hJYrSVRykZEyHRVeJMrdt9hBbqYmT6KNq89YZNaUdcFsU9bY9J/njPFzbZJUO4qrZ
         MPhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=c5ZdhZ0YGUmz1p5pK6AEd80tJtC02zu3w0ESO5REMCw=;
        b=ixrD61vUlZRZXvF7aHheGZWPeKwr3NTG+UZGjBCCijJCuJ6bnPVz+2KtqpAHanbx8X
         IsYHkoBdmiGJ276FdKlee1HSssnvk3wUDoMkjbK8fy8xQtTjFtmVK+Od/3/fNRdqG7P5
         r8G3HhP5yTcAhcQ73iRryHLQia9GQHuSZnUPUJJN/abmPmF+k7MCj2CnQe5g5lS5kUl1
         74iHwr94X8XtrgwsaQuOqy1mhflBI+hPdzitQ4/hQFxWoQCQxnf6QCcjybGWM/k/mEcl
         FZC3OnaFyue2W69MMqPj4uwoxr8mTxdaTq5XzNUcy4kRw1CWMAyy+7Ke4kBIIk9B4D/N
         P6TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HvmXn12w;
       spf=pass (google.com: domain of 3e5fnxqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3E5fNXQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id o206si392142vka.4.2019.11.14.10.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3e5fnxqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id a13so4478526qkc.17
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:04 -0800 (PST)
X-Received: by 2002:a05:6214:1332:: with SMTP id c18mr7908552qvv.213.1573754643719;
 Thu, 14 Nov 2019 10:04:03 -0800 (PST)
Date: Thu, 14 Nov 2019 19:02:55 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-3-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 02/10] include/linux/compiler.h: Introduce data_race(expr) macro
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HvmXn12w;       spf=pass
 (google.com: domain of 3e5fnxqukcwwovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3E5fNXQUKCWwOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

This introduces the data_race(expr) macro, which can be used to annotate
expressions for purposes of (1) documenting, and (2) giving tooling such
as KCSAN information about which data races are deemed "safe".

More context:
http://lkml.kernel.org/r/CAHk-=wg5CkOEF8DTez1Qu0XTEFw_oHhxN98bDnFqbY7HL5AB2g@mail.gmail.com

Signed-off-by: Marco Elver <elver@google.com>
Cc: Alan Stern <stern@rowland.harvard.edu>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Paul E. McKenney <paulmck@kernel.org>
---
v4:
* Introduce this patch to KCSAN series.
---
 include/linux/compiler.h | 20 ++++++++++++++++++++
 1 file changed, 20 insertions(+)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index c42fa83f23fb..7d3e77781578 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -310,6 +310,26 @@ unsigned long read_word_at_a_time(const void *addr)
 	__u.__val;					\
 })
 
+#include <linux/kcsan.h>
+
+/*
+ * data_race: macro to document that accesses in an expression may conflict with
+ * other concurrent accesses resulting in data races, but the resulting
+ * behaviour is deemed safe regardless.
+ *
+ * This macro *does not* affect normal code generation, but is a hint to tooling
+ * that data races here should be ignored.
+ */
+#define data_race(expr)                                                        \
+	({                                                                     \
+		typeof(({ expr; })) __val;                                     \
+		kcsan_nestable_atomic_begin();                                 \
+		__val = ({ expr; });                                           \
+		kcsan_nestable_atomic_end();                                   \
+		__val;                                                         \
+	})
+#else
+
 #endif /* __KERNEL__ */
 
 /*
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-3-elver%40google.com.
