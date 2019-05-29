Return-Path: <kasan-dev+bncBDV37XP3XYDRBMWMXLTQKGQE3WJSEXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE4F82E120
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 17:33:06 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id v15sf711294wmh.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 08:33:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559143986; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGk59ARvfV4TOKWY9XpsvJvppDUn1Izd9SyUkoIilTSzaCpQbtbFyPyvRmDoQ/kNEB
         xxGT9xBVRokgtnnltV6iaKcIIJ2wv8Uw6zZHMw9C5tpvgsRpU3p3VhIes0EWsA4Utvl/
         vgKYOE4lBHqVrbnNT8Irk59bod3cCy29UEfPwm2W3Nb4+FN/JZS3WGKfpAavTroh+XXI
         rmYLfH4vjJycO9FgOD8dYmGOmlZmzuAnm7hEj5eKewuVtMNP1nYz/ZRS8PseWMm4LkN5
         EV3B+Rdfy6jY8AsVtW5gPLM5gkX0vKqglhQ/RipjMOOWiabv0P0SQaiTVyUJrQqO+Wk5
         HU5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=qsCXUBwkOpfjQsLWR+QN5/5+K8uLoPuH9srNRI6VfH8=;
        b=mP5JepAbYbst0vN2EpRavqet40bVCIflJzabUpnr1ppX1bn9FaBttFuXFJfdcCkTsp
         3Zk0LEV0e8q4MUyMqO4HoxF7js5n4No67fOuzKhrpNXxLRm0I+T/CWFGnmFb4dChUPSv
         GcmnQQN3GbKYBd7Qz+sUx9drTO+Nd7mPsMY2OihO9YLvpJE60qQC0TqHjf/xOLzVo/7j
         qfH3i9naWjA0/R6Nl+9gTCb9hfYCTHn66gVpKGCf8FkNp3yEhZQngSdcrEyB33f+F7LX
         kY2hG7uUWeVqWSSDbW9IktqPdcHnevvWrXW20YZXUQYEVAjJPXJvFEOybiXCoJOe5cK+
         inkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qsCXUBwkOpfjQsLWR+QN5/5+K8uLoPuH9srNRI6VfH8=;
        b=juF+jaKSM/o7BqfHzbh7iqA948dhFnGq19fGLNPKsZTLyxrjy/94Re0qdmTW76Zabs
         P1zZPOPM5h4Y80ZOwvtNbICzZkoxDztMMKC13haQRmWo43oXO1OMKyOxmJFQz0KymZzH
         EGl5/j9eE8AW1KNEC6Nv1mAnHpuNwA1zH2PJyKrHuC+MR5N1ib61lQHYn1H5u01agdcQ
         HeQIaej0IDLAgDumeSF3nyPzRjqB0svRpy044G/6XjDtnHzPJmXOpY0svFrz5kRV2Jxy
         DQgswHa7C8aqybKDJAmvsIPd27iCWzxR8GxFnwFHz9bFzK2fuspPkzZZnigb1g5lVCKa
         XBqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qsCXUBwkOpfjQsLWR+QN5/5+K8uLoPuH9srNRI6VfH8=;
        b=f2PQLkscZ7gYd5YMAKiZ4u9M+hHel8hfe+xHocx3ttvoZ79QLEj2M8EyWmCkz+t6n2
         t69oSFzbIx80Gagr4/wjuYAnlc9k8JIc/xfSdfAQmtXY/l5ERFSXLXniuz49HhoDSukJ
         DXx1X5VYJjWPEX5QP5TqHGXjpNLXkBZH45OfIqcz+gK7ZfM+j8ZoPPAKZSQoWmcbH+S4
         7XQ7U9ca8X81KK5U8X1jPWYaKJ/1Nn80nyJPBO1m/iJf+qv1/G7ZRGjUsDx0h25kvNub
         UO4UEAfQ6Mwk+0+GGBjWNGXj2kwAYAKwx5LCAFf5LPEvPPAZKJVGeXsYQqdcg1ERFiEF
         a80Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWgmnArvhbfUMNJ+e81BezqsLn01yk6yhGuOe+l5LMRw5Xbk4/O
	PS72fXoVTfDJ+9gKH96O2GQ=
X-Google-Smtp-Source: APXvYqyaVl2MqBlRe5hYsKnXE9wtpkcsuGLYoL5Ha83KthCZlggZ62JXvdKu+1mtK7oaHtJ7QDY7Cw==
X-Received: by 2002:adf:ec0b:: with SMTP id x11mr9225589wrn.88.1559143986688;
        Wed, 29 May 2019 08:33:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:b484:: with SMTP id d126ls226448wmf.2.canary-gmail; Wed,
 29 May 2019 08:33:06 -0700 (PDT)
X-Received: by 2002:a1c:7503:: with SMTP id o3mr7783658wmc.28.1559143986123;
        Wed, 29 May 2019 08:33:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559143986; cv=none;
        d=google.com; s=arc-20160816;
        b=f/kqpVfskgTvkvlXyEK9FUrZICn1yDnJ4xEHzNNUVYalkxryZfG/211eW1AsEW6kVl
         OXN8ORRfQQZp3VjKsmaMfUdELpY+MZwC2hPkQbBoKNYBCvQcDIoT8CByATnstkMGKFmp
         E9ESumK8cLsLYMXqooXa7doudmxi/Za/YpHnC++HGPCMWFV/0FxKfK6TUPdWF1BKQ9uS
         N2fGfXceP9zIXE6rOMwzK9vAaSGp8EuyvGK9Jap8hRyJuh74ljTzd/RSyXzVU1Pn8KBl
         VcbJrG73DXwn34SGIoqfrno7Yex3lfh61CUPgjCkWPzCTwvkeXHK64XVfL1Bc77J0lyS
         hegQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=OiOzk4nH6Wb2vY6i6L/t6H3YcPWyTSk9nXzi1PzeXd4=;
        b=iM29sKQEYhZiaXW2B2Cbx21gXYZ+r1mvMwdQOoTnQVr8th/7mQ8qV2ib2IjNj31uPQ
         ej3m3AO62a1hHbBlMoHIMJ+bgDGAfEdbOv14VCCghkTL/I1JrUzqvh2ly5XInaiS0jHK
         mDVThVY6oOxRfBl+JUl4skUXrPpwxWtyKzY9BeNhmiWbu0E4+eC8RITQ90hAAiEoqcnG
         WoKOX8+kB95O6hmhhTdYbp8QmhmV9+gMiYh+aUfMkrSifwgsqVde9tk33lcYU5iM2Rl6
         TMb9rt6V9e6TUe/dEA1np+t1zCrDSRZIQYYBtjsR5FifHqJevKG1Ta1y2U/wW6XL+sAz
         K0KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.101.70])
        by gmr-mx.google.com with ESMTP id d140si49965wmd.1.2019.05.29.08.33.04
        for <kasan-dev@googlegroups.com>;
        Wed, 29 May 2019 08:33:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as permitted sender) client-ip=217.140.101.70;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.72.51.249])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 004AB341;
	Wed, 29 May 2019 08:33:04 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.72.51.249])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0BEAA3F5AF;
	Wed, 29 May 2019 08:33:00 -0700 (PDT)
Date: Wed, 29 May 2019 16:32:58 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>, peterz@infradead.org
Cc: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, corbet@lwn.net, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, hpa@zytor.com, x86@kernel.org,
	arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 3/3] asm-generic, x86: Add bitops instrumentation for
 KASAN
Message-ID: <20190529153258.GJ31777@lakrids.cambridge.arm.com>
References: <20190529141500.193390-1-elver@google.com>
 <20190529141500.193390-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190529141500.193390-4-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.101.70 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Wed, May 29, 2019 at 04:15:01PM +0200, Marco Elver wrote:
> This adds a new header to asm-generic to allow optionally instrumenting
> architecture-specific asm implementations of bitops.
> 
> This change includes the required change for x86 as reference and
> changes the kernel API doc to point to bitops-instrumented.h instead.
> Rationale: the functions in x86's bitops.h are no longer the kernel API
> functions, but instead the arch_ prefixed functions, which are then
> instrumented via bitops-instrumented.h.
> 
> Other architectures can similarly add support for asm implementations of
> bitops.
> 
> The documentation text has been copied/moved, and *no* changes to it
> have been made in this patch.
> 
> Tested: using lib/test_kasan with bitops tests (pre-requisite patch).
> 
> Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> Changes in v2:
> * Instrument word-sized accesses, as specified by the interface.
> ---
>  Documentation/core-api/kernel-api.rst     |   2 +-
>  arch/x86/include/asm/bitops.h             | 210 ++++----------
>  include/asm-generic/bitops-instrumented.h | 317 ++++++++++++++++++++++
>  3 files changed, 370 insertions(+), 159 deletions(-)
>  create mode 100644 include/asm-generic/bitops-instrumented.h

[...]

> diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
> new file mode 100644
> index 000000000000..b01b0dd93964
> --- /dev/null
> +++ b/include/asm-generic/bitops-instrumented.h
> @@ -0,0 +1,317 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This file provides wrappers with sanitizer instrumentation for bit
> + * operations.
> + *
> + * To use this functionality, an arch's bitops.h file needs to define each of
> + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> + * arch___set_bit(), etc.), #define each provided arch_ function, and include
> + * this file after their definitions. For undefined arch_ functions, it is
> + * assumed that they are provided via asm-generic/bitops, which are implicitly
> + * instrumented.
> + */

If using the asm-generic/bitops.h, all of the below will be defined
unconditionally, so I don't believe we need the ifdeffery for each
function.

> +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> +
> +#include <linux/kasan-checks.h>
> +
> +#if defined(arch_set_bit)
> +/**
> + * set_bit - Atomically set a bit in memory
> + * @nr: the bit to set
> + * @addr: the address to start counting from
> + *
> + * This function is atomic and may not be reordered.  See __set_bit()
> + * if you do not require the atomic guarantees.
> + *
> + * Note: there are no guarantees that this function will not be reordered
> + * on non x86 architectures, so if you are writing portable code,
> + * make sure not to rely on its reordering guarantees.

These two paragraphs are contradictory.

Since this is not under arch/x86, please fix this to describe the
generic semantics; any x86-specific behaviour should be commented under
arch/x86.

AFAICT per include/asm-generic/bitops/atomic.h, generically this
provides no ordering guarantees. So I think this can be:

/**
 * set_bit - Atomically set a bit in memory
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This function is atomic and may be reordered.
 *
 * Note that @nr may be almost arbitrarily large; this function is not
 * restricted to acting on a single-word quantity.
 */

... with the x86 ordering beahviour commented in x86's arch_set_bit.

Peter, do you have a better wording for the above?

[...]

> +#if defined(arch___test_and_clear_bit)
> +/**
> + * __test_and_clear_bit - Clear a bit and return its old value
> + * @nr: Bit to clear
> + * @addr: Address to count from
> + *
> + * This operation is non-atomic and can be reordered.
> + * If two examples of this operation race, one can appear to succeed
> + * but actually fail.  You must protect multiple accesses with a lock.
> + *
> + * Note: the operation is performed atomically with respect to
> + * the local CPU, but not other CPUs. Portable code should not
> + * rely on this behaviour.
> + * KVM relies on this behaviour on x86 for modifying memory that is also
> + * accessed from a hypervisor on the same CPU if running in a VM: don't change
> + * this without also updating arch/x86/kernel/kvm.c
> + */

Likewise, please only specify the generic semantics in this header, and
leave the x86-specific behaviour commented under arch/x86.

Otherwise this looks sound to me.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190529153258.GJ31777%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
