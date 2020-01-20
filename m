Return-Path: <kasan-dev+bncBCMIZB7QWENRBMP2S3YQKGQEZ7N2UFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1132E142DF4
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:46:11 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id b68sf13009642vkh.21
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:46:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579531570; cv=pass;
        d=google.com; s=arc-20160816;
        b=H+rLrIQhK29ZdlVThy2bLmhpxDYrgh1XP1mmuL1aoxS/aexMIKjSX8AuZx76aGOupK
         W09ySX+PCDZM6Wiz1+E4hHVGtNzGg2IP4scxaXLmBTbmPUUe2XmgC+sQHbh29wKO8Y+R
         /Y/SPp1Vq+2G2gtJfCTDCCb4qvjyuTnLUo4xWTGcN9zW4qH3n56bL/Oztmc41eCs/MEF
         BEQoDlEKGnPqadfDEqv37/+z/c3XbHevmgXer9oyT1oewlEOPNqXL90S60CkcAUPvtZ3
         gFLlf38qaKh8XOCkvheHbwbpEDcnxMYvl2u3E/BZivkWEnCFhHXDl3TxQPp2Jp9CazM5
         5OXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DTqs7bd/TMC7ekLkv8udbMwd4Kmjf1pOMQ1lOY2ogG4=;
        b=ita/e82bn7buLow8+M4JcYGiIoULmKyXhUvU85cKfz05PzjEmitbDtQJKnc9XUHXKZ
         Ptjp14M6wYmcbwAuZoojjwitAbVDrJOC0kUtpHOrhSQznY4QPfx0xYCRfV58NcuwmtpX
         SQwl3/WmNH2yW3OxSEXGQXViy5HL7o/MIALvY+zJ08ybCxPkWOMe6/Qn71QZUSEn3dYi
         Zlz+DCAezJ19/i9/CQJIhUgL3mQ3TkqP50sEwT7MGlyFg1+6pu3LYznJnOM0l/G9IAGc
         S6HPOygJxM/fdrDYYLm5X/Dd88hMZCsTHUSEoRjFXwl+4W8J3mQ8miW2SWJwH3X1u/7A
         0m2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="smPgCG/V";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DTqs7bd/TMC7ekLkv8udbMwd4Kmjf1pOMQ1lOY2ogG4=;
        b=drwnGQ+4tCwYOhm4OXnc0aXMXnaiXwyWGSFzDZg9QYLjDTravSd7CbsrrkRdlmfvlO
         r0mJjXhSr135uRUTkGiwyvXDyMibbRH2ViJDmFK8yVbJXADK491EKJFcyiZGYSUA/v1D
         lNUwwKfIiTOviiU2LKTRuvUN1OI5bL5jpg+iZZxSg8nGMqCkGEjEm0MvTSsw1wiGQkim
         6fBPqs37MgQ4G98+ogu6OD4Bq9+zmenb9+8oRJQ7Pl+QDWVWN0xzYsdHH5t+X3+X0LvL
         0fbFHbnNKqMYKL/CIesKdOi9bt+gc6yTrFd/VWEc+5IuHyUJ9pAsta1oLnjXv+rhHAq/
         RIEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DTqs7bd/TMC7ekLkv8udbMwd4Kmjf1pOMQ1lOY2ogG4=;
        b=Oz7o4lz68DWTKxnYzJooqtMaiNx0mLzuu/1tUcw9HCzopoGeJEvAU+cMM+G8UL/prA
         eioAxGH0ahNCSMRDYOS5vi9QdOeALRNMgWWPdU/llTEiIVA20j0AXA2n5Eh84ilUyVmU
         gd8O/lxtZeD0jQhrhCfcWodVVTeiBWz3rmF31U//cW8wXo37vf7Rb0o1+GPBRkJbQ8ur
         EBshlLJ+G8o3Vk01MOpFZPKvfpGV/u7A1VAJJgvt/wHVWRtaMBQMCk7gSgmT6I61i0s8
         K6hHS5ns1ZcbuX4d8LeAoF1wbWLaIaDhd7klh1csqbyU3o+dPW2tJnHE+ldg2pNae3g7
         p2PA==
X-Gm-Message-State: APjAAAX+wi0+3KcBCP5/9MR6/+jVE/R2/3MdJa5OelvnjM8jRT1zvsdG
	/iCKpTqINh9CrRV6+M05mJg=
X-Google-Smtp-Source: APXvYqzL5NJDIkpPq7q1dSUpRAxbwNHAofmJpOQMpt5Fp15PFaLM/wcT7pu/Xm4mZ6oiV032WkxYQA==
X-Received: by 2002:a67:fa4b:: with SMTP id j11mr12667709vsq.168.1579531570053;
        Mon, 20 Jan 2020 06:46:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:27c5:: with SMTP id n188ls2854011vsn.8.gmail; Mon, 20
 Jan 2020 06:46:09 -0800 (PST)
X-Received: by 2002:a67:e98e:: with SMTP id b14mr12838170vso.0.1579531569609;
        Mon, 20 Jan 2020 06:46:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579531569; cv=none;
        d=google.com; s=arc-20160816;
        b=hkPB0XEnt88s2sikFLE8DI/kAd/mET4yYOGxFAAWsnpCBrdw/czX1n1cQNLUCMFzXQ
         uqNsP44GagT15TXRmPCvF3kaFOic0SDny/FSjViTHf7S1x6aB87yvc9dmBLl7PYyyEdU
         +crm+WId7n9FZNQekJx4V5Ep/npGf18WWIQfYF0ZHm/QIlRTZAk6ABq0yazUDYIvChLJ
         aYgg4pKszIrEAMuPW9snHvAGZ2LXnoDiTCjVqOEwzTkvjhHiQ8ncfWBwFzT7qmYg8yPQ
         ezxJexP0pDcnOc+MqAT8dYUqwjuJyR4N6PIHwuvgIpuErW+v7BbFtU/f3qzl+qq6v4Pm
         TOvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3mOQDsNsMEMdcvwZ9EOVAmI2Aq9GLe7RdHuUtWY0eg0=;
        b=j5gZDfOHZJd5ok+iOgwqescLodNFCmbVQIkt4+7w8kItwC7xRp6VKrD7d0zSbuRzR4
         S2aLyYZC4px6fPc28+FGRV7PmT0BAxCcAu9FyiKXokFVLIxPRHVkBnzc5/WO78rgFS7u
         jxKln4rV0k0MeHE+A+GG1432rp7LcF+PCCbcXb46CoavZMfELHOoJHFtfRl3uQM83LO6
         4WtzOzEYazegmMUHQocSaByEMXWAgyfbsXk23mT8BtN5WOWupAcLnvhUEDTkSF9y+v2H
         NuTYntYahOMQyGgfgP3kA4uWDgq1hwQOqyFqQr4sgnciGZRol9mbMmXw6lkz6ZWkY48U
         Gp1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="smPgCG/V";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id k26si1543506uao.0.2020.01.20.06.46.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:46:09 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id x129so30273726qke.8
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:46:09 -0800 (PST)
X-Received: by 2002:a37:5841:: with SMTP id m62mr50539398qkb.256.1579531569022;
 Mon, 20 Jan 2020 06:46:09 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com>
In-Reply-To: <20200120141927.114373-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 15:45:57 +0100
Message-ID: <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	Michael Ellerman <mpe@ellerman.id.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, cyphar@cyphar.com, 
	Kees Cook <keescook@chromium.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="smPgCG/V";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
>
> This adds instrumented.h, which provides generic wrappers for memory
> access instrumentation that the compiler cannot emit for various
> sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> future this will also include KMSAN instrumentation.
>
> Note that, copy_{to,from}_user require special instrumentation,
> providing hooks before and after the access, since we may need to know
> the actual bytes accessed (currently this is relevant for KCSAN, and is
> also relevant in future for KMSAN).
>
> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
>  1 file changed, 153 insertions(+)
>  create mode 100644 include/linux/instrumented.h
>
> diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> new file mode 100644
> index 000000000000..9f83c8520223
> --- /dev/null
> +++ b/include/linux/instrumented.h
> @@ -0,0 +1,153 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This header provides generic wrappers for memory access instrumentation that
> + * the compiler cannot emit for: KASAN, KCSAN.
> + */
> +#ifndef _LINUX_INSTRUMENTED_H
> +#define _LINUX_INSTRUMENTED_H
> +
> +#include <linux/compiler.h>
> +#include <linux/kasan-checks.h>
> +#include <linux/kcsan-checks.h>
> +#include <linux/types.h>
> +
> +/**
> + * instrument_read - instrument regular read access
> + *
> + * Instrument a regular read access. The instrumentation should be inserted
> + * before the actual read happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */

Based on offline discussion, that's what we add for KMSAN:

> +static __always_inline void instrument_read(const volatile void *v, size_t size)
> +{
> +       kasan_check_read(v, size);
> +       kcsan_check_read(v, size);

KMSAN: nothing

> +}
> +
> +/**
> + * instrument_write - instrument regular write access
> + *
> + * Instrument a regular write access. The instrumentation should be inserted
> + * before the actual write happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */
> +static __always_inline void instrument_write(const volatile void *v, size_t size)
> +{
> +       kasan_check_write(v, size);
> +       kcsan_check_write(v, size);

KMSAN: nothing

> +}
> +
> +/**
> + * instrument_atomic_read - instrument atomic read access
> + *
> + * Instrument an atomic read access. The instrumentation should be inserted
> + * before the actual read happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */
> +static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
> +{
> +       kasan_check_read(v, size);
> +       kcsan_check_atomic_read(v, size);

KMSAN: nothing

> +}
> +
> +/**
> + * instrument_atomic_write - instrument atomic write access
> + *
> + * Instrument an atomic write access. The instrumentation should be inserted
> + * before the actual write happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */
> +static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
> +{
> +       kasan_check_write(v, size);
> +       kcsan_check_atomic_write(v, size);

KMSAN: nothing

> +}
> +
> +/**
> + * instrument_copy_to_user_pre - instrument reads of copy_to_user
> + *
> + * Instrument reads from kernel memory, that are due to copy_to_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted before the accesses. At this point the
> + * actual number of bytes accessed is not yet known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + */
> +static __always_inline void
> +instrument_copy_to_user_pre(const volatile void *src, size_t size)
> +{
> +       /* Check before, to warn before potential memory corruption. */
> +       kasan_check_read(src, size);

KMSAN: check that (src,size) is initialized

> +}
> +
> +/**
> + * instrument_copy_to_user_post - instrument reads of copy_to_user
> + *
> + * Instrument reads from kernel memory, that are due to copy_to_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted after the accesses. At this point the
> + * actual number of bytes accessed should be known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + * @left number of bytes left that were not copied
> + */
> +static __always_inline void
> +instrument_copy_to_user_post(const volatile void *src, size_t size, size_t left)
> +{
> +       /* Check after, to avoid false positive if memory was not accessed. */
> +       kcsan_check_read(src, size - left);

KMSAN: nothing

> +}
> +
> +/**
> + * instrument_copy_from_user_pre - instrument writes of copy_from_user
> + *
> + * Instrument writes to kernel memory, that are due to copy_from_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted before the accesses. At this point the
> + * actual number of bytes accessed is not yet known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + */
> +static __always_inline void
> +instrument_copy_from_user_pre(const volatile void *dst, size_t size)
> +{
> +       /* Check before, to warn before potential memory corruption. */
> +       kasan_check_write(dst, size);

KMSAN: nothing

> +}
> +
> +/**
> + * instrument_copy_from_user_post - instrument writes of copy_from_user
> + *
> + * Instrument writes to kernel memory, that are due to copy_from_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted after the accesses. At this point the
> + * actual number of bytes accessed should be known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + * @left number of bytes left that were not copied
> + */
> +static __always_inline void
> +instrument_copy_from_user_post(const volatile void *dst, size_t size, size_t left)
> +{
> +       /* Check after, to avoid false positive if memory was not accessed. */
> +       kcsan_check_write(dst, size - left);

KMSAN: mark (dst, size-left) as initialized

> +}
> +
> +#endif /* _LINUX_INSTRUMENTED_H */
> --
> 2.25.0.341.g760bfbb309-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg%40mail.gmail.com.
