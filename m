Return-Path: <kasan-dev+bncBDGPTM5BQUDRBHPP337QKGQEP4E3Z7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A0682EEAFB
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 02:38:38 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id g17sf13556862ybh.5
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 17:38:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610069917; cv=pass;
        d=google.com; s=arc-20160816;
        b=IhtUByDcycggshw+NPm/O2/V/8pP/ue2OHttcREnZTgpL41HQ+TmgmilR26CCkg88q
         8uruqQtr+T+Oiq9gpoHgq4G0KbvdCiE8+y6pXIp4SNft9d1Hp9xxx3fbRa3VhI0EKOWP
         O/C7eBpY634HLib/frq6QXC3MSRUMemJv0beKAkJXsjQcUOXAMaGKZRD3ujtLYdia/Vc
         fNpv8icZnPkoIs0EXmp7utz195lxxgGgT2k9MwAVZfGXojyJalissvPn7O/4H4Q94Gxr
         vewVt6l2jD31AwDJmBM41ywQBvxU2D8cVlvSvjcD+3tvkmXZ308cNVCVlmcAH6JeCUmX
         P/3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=RcJ36EJqM0TrDBuwYZehIXWIAzlFXbhf30p5PneEq+Y=;
        b=X8/f1GoLdtv3eUbjemWT2V+ChniiBHJJ8ecTI1QodxCgf52nwlIWGPspufF/8bIJxG
         Bl5fTWZcdey8UOKCbPOGBsu0HuqO8NzO91OrIAcbW5W3jUf7w7k44EEnZEY+GNHky8jI
         iQxAjsFYcAINAl/r724Vs//bjqUgoVZ9g5EPPLvA8gyetXihBNbNOnQCB1HYrL3xzxKR
         SusdB+6xH7FHT9j/ugxjxFsGcnSi6kHpxIEnnEky/4nXeKtViAE7rT0Xyp0tqD83Dk6v
         2i0T/gcG6gjtn/TgL5ujSJUbiMl8vFNPpWN2emg5WWRCTMjTF8l7pZwiJ11TYJ8L4FsD
         h4zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cV7EBqGb;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RcJ36EJqM0TrDBuwYZehIXWIAzlFXbhf30p5PneEq+Y=;
        b=OeSrOFRuFWPpeSD7xXrPMi5Sb3jrs3/K+b0oqU914Y2ui3Ku46EzqCVn08Ohlsth51
         t3kWVqAlI6J7vx8VO9vEM0jgvY26hG5xc5qBvjmXfy5Lbn32B4O5FS8HKZ7JyacC6W6Z
         PYwVnophTi3y89YwIxmgOVgXqT0WqAPWYJ9vxtLNc8sA1APJb6Bcv6EbTLChbS091rDO
         WHIqzDAxA6171ibKsGIUuIqh/AwTXsOsduw5698O5Di99gGCn3qonk4DmLRjxjlgH+9Q
         54iIGGYDlV0EykQn1vY1ylbKKDP4LoXgmlFFbQaCCPySobV2j4U2Ou7SNFvck0rw8TVY
         slHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RcJ36EJqM0TrDBuwYZehIXWIAzlFXbhf30p5PneEq+Y=;
        b=pYQIUpWDWCbR1z0nJ1bJW14+s7VGk0AUGG1OcYQ9I4m0/2oX+CM+JIxkZ3tV2hUib9
         cu8yyEc0M2zdF70W59vXET4F+H7inH5IL7g+WIdHAI6J4asnn0WlwEd81bJxXOoDIWs0
         FASeNkiWV/dhCmw/LvGvBCOMqNwFaEf876yE0JFTfD9loIZgQm9lt6mlKhaX4P0Wigsz
         Hhu8fqXycRSe3dmymL4vufWRwPiCE1JfZc+ZPEhlK/9SFtJBi8WKZokMPuwPuBxSKCE/
         ehjsuipMetunBOJfGtSZWBfzXxCX3R7HHKlExFe+5KVKuortXjM7h1zn6nGsk+X0OAC5
         LgHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532voFou/bbny+ubKZaxQbvZDSIADmEscjm7G6YzHcYXwLW6jGpk
	byXRE8uU8LH01wY8Qgukbak=
X-Google-Smtp-Source: ABdhPJxF0WMZyF2Jq05PNQDGu8BKQH/BXhg2QRYmVPjGul0CQirAq/cz8FJ6ndMDCUYR72nCeB1IJQ==
X-Received: by 2002:a25:ca85:: with SMTP id a127mr2327050ybg.432.1610069917446;
        Thu, 07 Jan 2021 17:38:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:41d6:: with SMTP id o205ls4760620yba.10.gmail; Thu, 07
 Jan 2021 17:38:36 -0800 (PST)
X-Received: by 2002:a25:2e07:: with SMTP id u7mr2303876ybu.393.1610069916827;
        Thu, 07 Jan 2021 17:38:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610069916; cv=none;
        d=google.com; s=arc-20160816;
        b=uNlsU2Ro075bzNJV2RJ/RwJVXBjh+zYeWtRfZ5QsOchsGTZtNTLs8phEo6FoeahJ9X
         beuXPSs4p0rXtvVLpF4dGxXkLzU3/QqKLXo6/J/DKcxPSQ9W688bGCC/z/gtNh0T4T47
         OoOb033ULbjhcCvUT5h2lHH/UNafe08u4ep1rXEVxuXVvbwjb9nseZeKImwcN/uL8tGF
         09vjqvG+9BYa2Ew6CfMMEvhFo7i9jR+NSMeQC7vbzoVejF9TDd70gBLHUJ+8wZl/j12V
         H9Eu7+yQvE2f1oRctA7hl4F7BbkocIDI+r8Ac5ARUZNvWN/TXoJBlCOVcU8Vsd4V8h0F
         ifeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=s+o0wQ44oQ0OJjcZVE6WER+igqM6j9ySewzTsgGNyp8=;
        b=h+XBzFSJL8mhrHAxGykh+LBuEemZm9fdgHdCpjUgR9xl1ZwuWh9mJ5CoP/iYgP53Bh
         lcUIpeVg9FMLeCHVaW91Toe2/3VgQq45kK072Ex4kXG+byUGjUWc9fq913QQFaBqqN/9
         ugsqDurr8n84Ipkf6B+Ze7qOdISPRqZrcnnj9jQGLvjffbp/DkpBYp/HePlqZfzl8c5Z
         R+fH7DL3rtk9JPh2okY1xUBx+6DpIk4ppWPGsbCliWdapRtFZOKKiv49vLMNHPBJl+ij
         scP4160zVKa3TChEBjbBkhsCXL/3uBplUkbu/XS0cndKHO+dYmSnDbQWerjRxePHEHbZ
         Jf/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=cV7EBqGb;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id r12si725724ybc.3.2021.01.07.17.38.35;
        Thu, 07 Jan 2021 17:38:36 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 24877376222d4592a23c8e03783fa998-20210108
X-UUID: 24877376222d4592a23c8e03783fa998-20210108
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1771301999; Fri, 08 Jan 2021 09:38:32 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 8 Jan 2021 09:38:30 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 8 Jan 2021 09:38:30 +0800
Message-ID: <1610069910.29507.3.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: remove redundant config option
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Nathan Chancellor <natechancellor@gmail.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, <clang-built-linux@googlegroups.com>
Date: Fri, 8 Jan 2021 09:38:30 +0800
In-Reply-To: <20210107210045.GA1456581@ubuntu-m3-large-x86>
References: <20210107062152.2015-1-walter-zh.wu@mediatek.com>
	 <20210107210045.GA1456581@ubuntu-m3-large-x86>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: CFE1FE589981CD48E25B11BC0CC153010BB4FBB961CFCB681BFAFCF0AF1E593B2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=cV7EBqGb;       spf=pass
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

On Thu, 2021-01-07 at 14:00 -0700, Nathan Chancellor wrote:
> On Thu, Jan 07, 2021 at 02:21:52PM +0800, Walter Wu wrote:
> > CONFIG_KASAN_STACK and CONFIG_KASAN_STACK_ENABLE both enable KASAN
> > stack instrumentation, but we should only need one config option,
> > so that we remove CONFIG_KASAN_STACK_ENABLE. see [1].
> > 
> > For gcc we could do no prompt and default value y, and for clang
> > prompt and default value n.
> > 
> > [1]: https://bugzilla.kernel.org/show_bug.cgi?id=210221
> > 
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > ---
> >  arch/arm64/kernel/sleep.S        |  2 +-
> >  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
> >  include/linux/kasan.h            |  2 +-
> >  lib/Kconfig.kasan                | 11 ++++-------
> >  mm/kasan/common.c                |  2 +-
> >  mm/kasan/kasan.h                 |  2 +-
> >  mm/kasan/report_generic.c        |  2 +-
> >  scripts/Makefile.kasan           | 10 ++++++++--
> >  8 files changed, 18 insertions(+), 15 deletions(-)
> > 
> > diff --git a/arch/arm64/kernel/sleep.S b/arch/arm64/kernel/sleep.S
> > index 6bdef7362c0e..7c44ede122a9 100644
> > --- a/arch/arm64/kernel/sleep.S
> > +++ b/arch/arm64/kernel/sleep.S
> > @@ -133,7 +133,7 @@ SYM_FUNC_START(_cpu_resume)
> >  	 */
> >  	bl	cpu_do_resume
> >  
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >  	mov	x0, sp
> >  	bl	kasan_unpoison_task_stack_below
> >  #endif
> > diff --git a/arch/x86/kernel/acpi/wakeup_64.S b/arch/x86/kernel/acpi/wakeup_64.S
> > index 5d3a0b8fd379..c7f412f4e07d 100644
> > --- a/arch/x86/kernel/acpi/wakeup_64.S
> > +++ b/arch/x86/kernel/acpi/wakeup_64.S
> > @@ -112,7 +112,7 @@ SYM_FUNC_START(do_suspend_lowlevel)
> >  	movq	pt_regs_r14(%rax), %r14
> >  	movq	pt_regs_r15(%rax), %r15
> >  
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >  	/*
> >  	 * The suspend path may have poisoned some areas deeper in the stack,
> >  	 * which we now need to unpoison.
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 5e0655fb2a6f..35d1e9b2cbfa 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -302,7 +302,7 @@ static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
> >  
> >  #endif /* CONFIG_KASAN */
> >  
> > -#if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN) && defined(CONFIG_KASAN_STACK)
> >  void kasan_unpoison_task_stack(struct task_struct *task);
> >  #else
> >  static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index f5fa4ba126bf..59de74293454 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -138,9 +138,11 @@ config KASAN_INLINE
> >  
> >  endchoice
> >  
> > -config KASAN_STACK_ENABLE
> > -	bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> 
> You are effectively undoing commits 6baec880d7a5 ("kasan: turn off
> asan-stack for clang-8 and earlier") and ebb6d35a74ce ("kasan: remove
> clang version check for KASAN_STACK") with this change. This change
> should still remain around so that all{mod,yes}config remain mostly
> clean for clang builds. This should not change anything from the user's
> perspective because this option was never user selectable for GCC and
> the default y keeps it on.
> 

Ok, I will remain this.

> > +config KASAN_STACK
> > +	bool "Enable stack instrumentation (unsafe)"
> >  	depends on KASAN_GENERIC || KASAN_SW_TAGS
> > +	default y if CC_IS_GCC
> > +	default n if CC_IS_CLANG
> 
> This is implied and can be removed.
> 
> >  	help
> >  	  The LLVM stack address sanitizer has a know problem that
> >  	  causes excessive stack usage in a lot of functions, see
> > @@ -154,11 +156,6 @@ config KASAN_STACK_ENABLE
> >  	  CONFIG_COMPILE_TEST.	On gcc it is assumed to always be safe
> >  	  to use and enabled by default.
> >  
> > -config KASAN_STACK
> > -	int
> > -	default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> > -	default 0
> > -
> >  config KASAN_SW_TAGS_IDENTIFY
> >  	bool "Enable memory corruption identification"
> >  	depends on KASAN_SW_TAGS
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 38ba2aecd8f4..02ec7f81dc16 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -63,7 +63,7 @@ void __kasan_unpoison_range(const void *address, size_t size)
> >  	unpoison_range(address, size);
> >  }
> >  
> > -#if CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN_STACK)
> 
> Isn't '#ifdef CONFIG_...' preferred for CONFIG symbols?
> 

Yes, I will fix in the next version. Thanks for your review.

> >  /* Unpoison the entire stack for a task. */
> >  void kasan_unpoison_task_stack(struct task_struct *task)
> >  {
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index cc4d9e1d49b1..bdfdb1cff653 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -224,7 +224,7 @@ void *find_first_bad_addr(void *addr, size_t size);
> >  const char *get_bug_type(struct kasan_access_info *info);
> >  void metadata_fetch_row(char *buffer, void *row);
> >  
> > -#if defined(CONFIG_KASAN_GENERIC) && CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
> >  void print_address_stack_frame(const void *addr);
> >  #else
> >  static inline void print_address_stack_frame(const void *addr) { }
> > diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> > index 8a9c889872da..137a1dba1978 100644
> > --- a/mm/kasan/report_generic.c
> > +++ b/mm/kasan/report_generic.c
> > @@ -128,7 +128,7 @@ void metadata_fetch_row(char *buffer, void *row)
> >  	memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
> >  }
> >  
> > -#if CONFIG_KASAN_STACK
> > +#if defined(CONFIG_KASAN_STACK)
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
> > -- 
> > 2.18.0
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1610069910.29507.3.camel%40mtksdccf07.
