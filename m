Return-Path: <kasan-dev+bncBDGPTM5BQUDRB6XIUWBAMGQESKI6KOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id C12D93369CE
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 02:38:03 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id l19sf9976009plc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 17:38:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615426682; cv=pass;
        d=google.com; s=arc-20160816;
        b=rxZaK8dzp2RZ4kL7+6YEGSzdqKvqc53hAN7lm3iLQqoWoa3gporn54EUagbjt1nRnh
         XAlUow54cSZFnqDz60wEry2X5X0zQw6EzDWFfFW5Oegv+B8HtWDBYPpSa0I8Uomua0aS
         Ns608XOrX/DLF37LX05RzobyI/uM8LmuXUt7jyqwbGpCEEq4WXkfVItaE0LfSHAszqxo
         0V2UhSx2OP0wvmUUaN94GmrQTVHl3zpd5++hzh9OVw8qVkuUGiXMlYbyDYuej+FOl4Xw
         9e7QP8c6SVhaKOqQ3ig+WDgaUufVfuYV8V19NUC/vuEV3lXXiVbWpx/xddORTLgeLTuK
         KQ5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=hWDaZjeNNuG3hIMZdfjF0hF5v6hX3nYrF9c3sAEunRo=;
        b=aZY1jaOPurufM/XYeSithwpoD6t8PX4gDCIwaCGSGLbcaqY4eehgQMySr/UJ3cifE7
         haqnucxqYbsu6TFUIlRL28oPWqy7VoizoxeK7rrc0M/i+Ry15FaFfvop8UPz46Z4+8Bt
         OZ7ijPyGgnghJ9kZXXNUZHcxC4e/P0ZBXYdL9jn/Fz7Iosp/cN9Ub5gsaDhwwveYATMY
         9x+55rcfcZ72cc57RV4np5TrLEm5jYY8tbW4a1cuC9pPNQFQbkHjh0RR3Nea+Km2waTW
         Q8BDgpZAdB5muy5ssY5FFtXtqOo6d5Lv9eX5FlF8iCxlISCxfWAtnfYvwaTAo0uTY0Va
         FHLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fiiYEY4j;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hWDaZjeNNuG3hIMZdfjF0hF5v6hX3nYrF9c3sAEunRo=;
        b=Dx9sUPpk2CyH+0nnYWEzMvaQN68dEnDW5NJWbSX6U219felN+FAuKMRZnWBZZtBHTN
         MLHhAs9KfcZ071kCmbxeZz3Ufv95nXGVlXtS0csFv3VsZa+YhJuyjtb6nQ0AdaHBBoF9
         1j5mgUOqkMo53qjBkrK9jGmNOLIlIklGHA2CuAvlj1mO6hhNgL32sOsJlBaN1RuKHWp/
         Q39DCWNf2ju7b/WiT9earSeNqmVeCvRti6FIFaVRG99YS0oTV1k/rEQ5MnSkPMUNRmSt
         0Xd3qwiu7nniDrb8px5IccHKDk8x6jd8JT+ZrprK39xr4OuvrBNLeGrKMwlJ7/GLXQ8S
         SFsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hWDaZjeNNuG3hIMZdfjF0hF5v6hX3nYrF9c3sAEunRo=;
        b=PQKQWDR3Jj0P0kE3xxU9oDexjJ75/hIQ45AD3WUz9BzkT3FIqb3otfncTFH2zho/O5
         eeZj3JkjxXfEy7/Zci3841ns+PZTfKd9JicfNVPVvTFLdo+LGvXjX800RN1S9DA+LPdy
         T8TseztyjcppN8hbZTjJOIxtbRz8nBvo5AuRjkhTw79dAAOFJxLq3WHvxuGGMdsjQZMK
         5SivngSsZeCEgluWKF82RpjJZLwt4zQdxiXQqmXNROR55ahAnT1nh8m+UIv3LkWmUcDd
         flxWJr1S+AEe24Kop2om1wZu15fr5T5jl+8U7wnLOh+GSm2BnkI4lO4shIUYsNSYP1ob
         /3tw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Klna5QCGoKeBwkCDsIAbh9+R+MeKL7OxPbzq7b1C9ml8AcTRI
	GR82s/zb9YDURG/2TRcaMqg=
X-Google-Smtp-Source: ABdhPJzc3zp+vJEGH2YcIZoGLyGUBUC7ljmo6wk+nvIGrw6MeIJWABQDsfg4KspFAnMlsaNADNxa7g==
X-Received: by 2002:a17:90a:a106:: with SMTP id s6mr6350650pjp.146.1615426682328;
        Wed, 10 Mar 2021 17:38:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eb43:: with SMTP id i3ls2189948pli.7.gmail; Wed, 10
 Mar 2021 17:38:01 -0800 (PST)
X-Received: by 2002:a17:90b:4c08:: with SMTP id na8mr6750726pjb.70.1615426681740;
        Wed, 10 Mar 2021 17:38:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615426681; cv=none;
        d=google.com; s=arc-20160816;
        b=ghhRQ3fRCZAHvrcKR7gW9o7riwzGOlPy4v54kudnK3PBVHix2ynDr2mT3YlDE5VWnf
         4N1pqI/JelfjjUeBziDWIp2jhnu+Ql/4SCeqD4McSQa8dqBpwqFV3zyWr0tB7NG6XY5u
         f19+2OQGXnt5Jnk6W862PkOfvf0BG/ZK03Lk4qTGssI3Yqwndhx65FviLWqR2vpLGJ/d
         XkPf+kAUGvIbNIDfvCiKIePjn1vb5R5jYVknVZ8RINhcBkANw/NO/j6YtJnb41z/a6Mx
         G+MN6oPOdzq+p/T6IHmr++5pe2R6L5m4mdLYkPtlocOvtUmRbCxyZNQfzEXTXiOn1p2l
         3naQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=XEghooLt2sbP0TcI8ia1WGtbusXI3SQZoYYSMtDBNdo=;
        b=yBdxy9IU6Y+CaNqKnJmQqEA80ORy+CBTfh+PamtJCOla02YEkIRK7MLFhBPL3k9Etq
         fPiYUgEIHiTU9WXw3nSlRC1dq69fXy3h10HbYzXGcfbyiwxiLNw2LzgIqyO4q5wlDJAB
         juUeRGOYiXgdkF2DJGgLqSztuEGbmWmkR8pYRC8IOKveQDaB+dMIgvsneR986DQ85CZf
         pyoSuVpvHx18aFkyXb7fBekJdlski+0TV1dzseNcrbDvuQFuDnfFEOFyQkkN4J4uQwwU
         sxtJ83qdeRa2XikiQD3dSFzGth68CPp9CN4OqHH9ItHVjb3ySSGwbfm/Sk7n7PES1tFr
         UDZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=fiiYEY4j;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id e7si69187pfi.1.2021.03.10.17.38.01
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Mar 2021 17:38:01 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5a436781a20242e39969b677e4765551-20210311
X-UUID: 5a436781a20242e39969b677e4765551-20210311
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1619678216; Thu, 11 Mar 2021 09:32:47 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 11 Mar 2021 09:32:45 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 11 Mar 2021 09:32:45 +0800
Message-ID: <1615426365.20483.4.camel@mtksdccf07>
Subject: Re: [PATCH v4] kasan: remove redundant config option
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Nathan Chancellor <natechancellor@gmail.com>, "Arnd
 Bergmann" <arnd@arndb.de>, Andrey Konovalov <andreyknvl@google.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>
Date: Thu, 11 Mar 2021 09:32:45 +0800
In-Reply-To: <1614772099.26785.3.camel@mtksdccf07>
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
	 <1614772099.26785.3.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=fiiYEY4j;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Wed, 2021-03-03 at 19:48 +0800, Walter Wu wrote:
> On Fri, 2021-02-26 at 09:25 +0800, Walter Wu wrote:
> > CONFIG_KASAN_STACK and CONFIG_KASAN_STACK_ENABLE both enable KASAN stack
> > instrumentation, but we should only need one config, so that we remove
> > CONFIG_KASAN_STACK_ENABLE and make CONFIG_KASAN_STACK workable.  see [1].
> > 
> > When enable KASAN stack instrumentation, then for gcc we could do no
> > prompt and default value y, and for clang prompt and default value n.
> > 
> > [1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221
> > 
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Reviewed-by: Nathan Chancellor <natechancellor@gmail.com>
> > Acked-by: Arnd Bergmann <arnd@arndb.de>
> > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > ---
> > 
> > v4: After this patch sent, someone had modification about KASAN_STACK,
> >     so I need to rebase codebase. Thank Andrey for your pointing.
> > 
> Hi Andrew,
> 
> Could you pick this v4 patch up into mm?
> Thanks.
> 
> Walter
> 
> > ---
> >  arch/arm64/kernel/sleep.S        |  2 +-
> >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> >  include/linux/kasan.h            |  2 +-
> >  lib/Kconfig.kasan                |  8 ++------
> >  mm/kasan/common.c                |  2 +-
> >  mm/kasan/kasan.h                 |  2 +-
> >  mm/kasan/report_generic.c        |  2 +-
> >  scripts/Makefile.kasan           | 10 ++++++++--
> >  security/Kconfig.hardening       |  4 ++--
> >  9 files changed, 18 insertions(+), 16 deletions(-)
> > 
> > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > index 5bfd9b87f85d..4ea9392f86e0 100644
> > --- a/arch/arm64/kernel/sleep.S
> > +++ b/arch/arm64/kernel/sleep.S
> > @@ -134,7 +134,7 @@ SYM_FUNC_START(_cpu_resume)
> >  	 */
> >  	bl	cpu_do_resume
> >  
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >  	mov	x0, sp
> >  	bl	kasan_unpoison_task_stack_below
> >  #endif
> > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > index 56b6865afb2a..d5d8a352eafa 100644
> > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > @@ -115,7 +115,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> >  	movq	pt_regs_r14(%rax), %r14
> >  	movq	pt_regs_r15(%rax), %r15
> >  
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >  	/*
> >  	 * The suspend path may have poisoned some areas deeper in the stack,
> >  	 * which we now need to unpoison.
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index b91732bd05d7..14f72ec96492 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -330,7 +330,7 @@ static inline bool kasan_check_byte(const void *address)
> >  
> >  #endif /* CONFIG_KASAN */
> >  
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >  void kasan_unpoison_task_stack(struct task_struct *task);
> >  #else
> >  static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 624ae1df7984..cffc2ebbf185 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -138,9 +138,10 @@ config KASAN_INLINE
> >  
> >  endchoice
> >  
> > -config KASAN_STACK_ENABLE
> > +config KASAN_STACK
> >  	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> >  	depends on KASAN_GENERIC || KASAN_SW_TAGS
> > +	default y if CC_IS_GCC
> >  	help
> >  	  The LLVM stack address sanitizer has a know problem that
> >  	  causes excessive stack usage in a lot of functions, see
> > @@ -154,11 +155,6 @@ config KASAN_STACK_ENABLE
> >  	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
> >  	  to use and enabled by default.
> >  
> > -config KASAN_STACK
> > -	int
> > -	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> > -	default 0
> > -

Hi Andrew,

I see my v4 patch is different in the next tree now. please see below
information.
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ebced5fb0ef969620ecdc4011f600f9e7c229a3c
The different is in lib/Kconfig.kasan.
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/diff/lib/Kconfig.kasan?id=ebced5fb0ef969620ecdc4011f600f9e7c229a3c

Would you please help to check it.
Thanks.

Walter

> >  config KASAN_SW_TAGS_IDENTIFY
> >  	bool "Enable memory corruption identification"
> >  	depends on KASAN_SW_TAGS
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index b5e08d4cefec..7b53291dafa1 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
> >  	kasan_unpoison(address, size);
> >  }
> >  
> > -#if CONFIG_KASAN_STACK
> > +#ifdef CONFIG_KASAN_STACK
> >  /* Unpoison the entire stack for a task. */
> >  void kasan_unpoison_task_stack(struct task_struct *task)
> >  {
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 8c55634d6edd..3436c6bf7c0c 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -231,7 +231,7 @@ void *kasan_find_first_bad_addr(void *addr, size_t size);
> >  const char *kasan_get_bug_type(struct kasan_access_info *info);
> >  void kasan_metadata_fetch_row(char *buffer, void *row);
> >  
> > -#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
> >  void kasan_print_address_stack_frame(const void *addr);
> >  #else
> >  static inline void kasan_print_address_stack_frame(const void *addr) { }
> > diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> > index 41f374585144..de732bc341c5 100644
> > --- a/mm/kasan/report_generic.c
> > +++ b/mm/kasan/report_generic.c
> > @@ -128,7 +128,7 @@ void kasan_metadata_fetch_row(char *buffer, void *row)
> >  	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
> >  }
> >  
> > -#if CONFIG_KASAN_STACK
> > +#ifdef CONFIG_KASAN_STACK
> >  static bool __must_check tokenize_frame_descr(const char **frame_descr,
> >  					      char *token, size_t max_tok_len,
> >  					      unsigned long *value)
> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> > index 1e000cc2e7b4..abf231d209b1 100644
> > --- a/scripts/Makefile.kasan
> > +++ b/scripts/Makefile.kasan
> > @@ -2,6 +2,12 @@
> >  CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> >  KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> >  
> > +ifdef CONFIG_KASAN_STACK
> > +	stack_enable := 1
> > +else
> > +	stack_enable := 0
> > +endif
> > +
> >  ifdef CONFIG_KASAN_GENERIC
> >  
> >  ifdef CONFIG_KASAN_INLINE
> > @@ -27,7 +33,7 @@ else
> >  	CFLAGS_KASAN := $(CFLAGS_KASAN_SHADOW) \
> >  	 $(call cc-param,asan-globals=1) \
> >  	 $(call cc-param,asan-instrumentation-with-call-threshold=$(call_threshold)) \
> > -	 $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
> > +	 $(call cc-param,asan-stack=$(stack_enable)) \
> >  	 $(call cc-param,asan-instrument-allocas=1)
> >  endif
> >  
> > @@ -42,7 +48,7 @@ else
> >  endif
> >  
> >  CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> > -		-mllvm -hwasan-instrument-stack=$(CONFIG_KASAN_STACK) \
> > +		-mllvm -hwasan-instrument-stack=$(stack_enable) \
> >  		-mllvm -hwasan-use-short-granules=0 \
> >  		$(instrumentation_flags)
> >  
> > diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
> > index 269967c4fc1b..a56c36470cb1 100644
> > --- a/security/Kconfig.hardening
> > +++ b/security/Kconfig.hardening
> > @@ -64,7 +64,7 @@ choice
> >  	config GCC_PLUGIN_STRUCTLEAK_BYREF
> >  		bool "zero-init structs passed by reference (strong)"
> >  		depends on GCC_PLUGINS
> > -		depends on !(KASAN && KASAN_STACK=1)
> > +		depends on !(KASAN && KASAN_STACK)
> >  		select GCC_PLUGIN_STRUCTLEAK
> >  		help
> >  		  Zero-initialize any structures on the stack that may
> > @@ -82,7 +82,7 @@ choice
> >  	config GCC_PLUGIN_STRUCTLEAK_BYREF_ALL
> >  		bool "zero-init anything passed by reference (very strong)"
> >  		depends on GCC_PLUGINS
> > -		depends on !(KASAN && KASAN_STACK=1)
> > +		depends on !(KASAN && KASAN_STACK)
> >  		select GCC_PLUGIN_STRUCTLEAK
> >  		help
> >  		  Zero-initialize any stack variables that may be passed
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1615426365.20483.4.camel%40mtksdccf07.
