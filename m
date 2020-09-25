Return-Path: <kasan-dev+bncBDDL3KWR4EBRBOWPW75QKGQENDSK5WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 342982787BD
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 14:51:07 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id u206sf666694vsc.15
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 05:51:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601038266; cv=pass;
        d=google.com; s=arc-20160816;
        b=jNDXJel37vL8qKJINHb6Yyde9QEBpwiu2DdtfshgnQ+mwB3SZX4SrRyiZGzCcJYpep
         oHX/uiCLFqO3U6C1yrT2bgmCQlRTXIaAKstKCAmVnD0V3K8459cW+9Oz+kjBDg1o/L9k
         i1wCWk1C2Jb3uAgYBmGgV6lTK/tlYeavUvUrm/hcCPfMgDWGa2pnBmUW1ZdPgmNO51pN
         E4XbyBSL6T/R7gX4Yxb4B9zBQxuBOZuvE5/WO9CE1fVgzJaUyNoX8X+28+xwD3WHWTjb
         QBXhXFBc7qLv46HYsL+JCyEYSH6Y434d16YxwRIDVJSmQvfx77KbUq6sau4m3P9lokr3
         fEcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=XNTUnZZLAnMnqUx2pSTn20iwNiYKCxYNnTVf14+k8rU=;
        b=f8mgk0uzp6xJk9ODaq/1426V3vgJ0HKNdBLAvMejziWaQ7G1f65EFDCX7tlh99UDv7
         z7Skje40rEBtZhPYfHA3AukHURtVcBcmlV9/Tu3cIBClMi8OQdLLxDOO8e5c+soqO7s7
         2Q2myVlRhqIJwEmqauMCr7ZrpCuflp2XELKueLGaB9FCbyJlSI66oUUQLn1pCpd473w5
         OgybWFukynlP+x19hplWSkpvOIXabsKtCmuYnAu9RJgSTZp1pgnVfbTMQByX3MkCwonC
         wLEEo8y1PXZTK3qaeAbfx/26czHoKy3yog6QF6cTx6XR5z+KcS6MRCAbtSFgM8Kp9B2c
         e/tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XNTUnZZLAnMnqUx2pSTn20iwNiYKCxYNnTVf14+k8rU=;
        b=BP1nxxj4dbB0AEM9XtK4jAkbkbPDvfEb6ae1Bomv5BQ9iOul2Ii5aLF29JjDV+vvKy
         dpO+Au1+PUtkZRsxFOTgzRv40pGb1VFoib845quY0q+a3amIjFNhdeAw+mSXZWIY39zU
         27M85HTDo/qtAKz0PJG5jX5C4jX0PRB/Hdnfy4swoxN4LLBu7gXf5eVEea1ufPSbkaBC
         yH3q45qSd95LjK5EepldJZWwIX1TZXbFR6wsuR1xVDBzA8A0hny6oX073dNqNJHDzcQJ
         fRMA5snLn1WCOjzxBwa4WSbnQj2v6GEP8qgLDjqlpbOJJpeScE7ak8UIEzcrZhAzS7A4
         el7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XNTUnZZLAnMnqUx2pSTn20iwNiYKCxYNnTVf14+k8rU=;
        b=IdUJgcZZSlANBQvS8jq9fjTimuxc7mXqybis7JvwsmWh05tnhQLjZ4puFxDvUirYRA
         YZ63tbiFoTxJ0JxLpuumNsa83jJaXgiz4ynKcCr9E+CB2+yMNF/n0BOxDgCWacUOdyUR
         rff1LXNhOZTKMMR5uHGrzjlaLsiRWDryl3h0qbbGv6GUbtVydM6oIpr7wwTfM9p941PS
         WQngwovSsrQ/p9Oi/Las+tPp/na6k21BaMe4zSAWJTgQ50rOsC2EGtaFdCTd71aj6OzN
         /atveJ8lIkyR8MP31lW/I0vLD8R7n6774GgMV0PxKbq63Kurqf59TrqDwE2ad9npEu7z
         nXwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hOaW9a5Rt7JcTuhKo4MQcbFgYuO3FtJESVLzopGAXuR5BVnxx
	Ux1XIUuA/r6B0ULVAReo1mw=
X-Google-Smtp-Source: ABdhPJxCkeaTINQ6a/4NPNB1hOSL4MlqJLSabzkRXOiduepAiKBv9pl8Op9DU1wr+28tW/W/NlR9kg==
X-Received: by 2002:a67:f90d:: with SMTP id t13mr2676868vsq.60.1601038266251;
        Fri, 25 Sep 2020 05:51:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1f6:: with SMTP id 109ls215619ual.2.gmail; Fri, 25 Sep
 2020 05:51:05 -0700 (PDT)
X-Received: by 2002:ab0:31d8:: with SMTP id e24mr2263695uan.38.1601038265536;
        Fri, 25 Sep 2020 05:51:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601038265; cv=none;
        d=google.com; s=arc-20160816;
        b=NbAfzoTachSkXqvuzm/UBZ+SqnHFWbEmauCsLna7yu4ZOg1J5uWkLxNTSARLpSPhw2
         7z9DzgruJKA6+sO0z9ah1tLjI/xMpcQ7gtGnDe4Q3s6B/ixSbLkKukmGk90roXLyJ41x
         B3qSw2Qm8hAta+y00jDnCGvNMWnU7XSkfNRiAa+VmJ9qZluI+zVN9Pn8+AmIwQz0BFeE
         EaGn29UacLnfM5taskuImEpxxir0Yqq3IZQGHK+mwr5enUBveDSDUyVL/Tv23x2dPuFn
         FDMP4BOB7KXWzr3JY0TqllYLEMZOAvFR+SG2OAtZ1PK/0XX1fcY0bYY3BW7vkGkp80mr
         McKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=8YeqxkNo3X+TdLYP22Tv5nXPM21hCcMg5S+xq+WWnpE=;
        b=PjRh+GvFl/quYzJGAfLJuEqkQ24kGsU/2FJEhUa1T3iPKswCE43QwXnmO5DrG5o35T
         tMk7hFlALShOu4tGd0Ps8dg2QCGLkjSdU9fgaydxu+xPvEP4NlNPfw2s5s52kzfwxmbG
         E5/VFxsX1z3rW7tdLF1yGNs/Yenvc/n+DWwe0Gw6wnu9pm2a9nOmME3Yh6V0lZx5yBnJ
         aa2lOSnWPW0LUI/2UGGKhkHylc4CmTW4G7ieVeW4wDAdtMAEV9j6jAzrGsY6LRlry9Ea
         2xQNeZZanwAvAmFs7JlyfmqH4RMZy3R3OjWzTn87XhDGI+DjoFZziPFZ58rKAP9UJVIK
         GbDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s9si193689uar.0.2020.09.25.05.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 05:51:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 049DF22B2D;
	Fri, 25 Sep 2020 12:51:01 +0000 (UTC)
Date: Fri, 25 Sep 2020 13:50:59 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 24/39] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20200925125059.GM4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <ae603463aed82bdff74942f23338a681b8ed8820.1600987622.git.andreyknvl@google.com>
 <20200925101558.GB4846@gaia>
 <e41f2af1-f208-cc99-64f9-2311ad7d50bf@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e41f2af1-f208-cc99-64f9-2311ad7d50bf@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 12:28:24PM +0100, Vincenzo Frascino wrote:
> On 9/25/20 11:15 AM, Catalin Marinas wrote:
> > On Fri, Sep 25, 2020 at 12:50:31AM +0200, Andrey Konovalov wrote:
> >> +u8 mte_get_mem_tag(void *addr);
> >> +u8 mte_get_random_tag(void);
> >> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
> >> +
> >> +#else /* CONFIG_ARM64_MTE */
> >> +
> >> +static inline u8 mte_get_ptr_tag(void *ptr)
> >> +{
> >> +	return 0xFF;
> >> +}
> >> +
> >> +static inline u8 mte_get_mem_tag(void *addr)
> >> +{
> >> +	return 0xFF;
> >> +}
> >> +static inline u8 mte_get_random_tag(void)
> >> +{
> >> +	return 0xFF;
> >> +}
> >> +static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >> +{
> >> +	return addr;
> >> +}
> > 
> > Maybe these can stay in mte-kasan.h, although they are not a direct
> > interface for KASAN AFAICT (the arch_* equivalent are defined in
> > asm/memory.h. If there's no good reason, we could move them to mte.h.
> 
> This is here because it is not a direct interface as you noticed. I tried to
> keep the separation (even if it I have something to fix based on your comment
> below ;)).
> 
> The other kasan implementation define the arch_* indirection in asm/memory.h in
> every architecture. I think maintaining the design is the best way to non create
> confusion.

I'm ok with asm/memory.h for kasan, no need to change that. You can also
keep these functions in asm/mte-kasan.h but add a comment that they are
only for the kasan interface defined in asm/memory.h.

> >> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> >> index 1c99fcadb58c..3a2bf3ccb26c 100644
> >> --- a/arch/arm64/include/asm/mte.h
> >> +++ b/arch/arm64/include/asm/mte.h
> >> @@ -5,14 +5,13 @@
> >>  #ifndef __ASM_MTE_H
> >>  #define __ASM_MTE_H
> >>  
> >> -#define MTE_GRANULE_SIZE	UL(16)
> >> -#define MTE_GRANULE_MASK	(~(MTE_GRANULE_SIZE - 1))
> >> -#define MTE_TAG_SHIFT		56
> >> -#define MTE_TAG_SIZE		4
> >> +#include <asm/mte-kasan.h>

And this include should be replaced by asm/mte-hwdef.h.

> >>  #ifndef __ASSEMBLY__
> >>  
> >> +#include <linux/bitfield.h>
> >>  #include <linux/page-flags.h>
> >> +#include <linux/types.h>
> >>  
> >>  #include <asm/pgtable-types.h>
> >>  
> >> @@ -45,7 +44,9 @@ long get_mte_ctrl(struct task_struct *task);
> >>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
> >>  			 unsigned long addr, unsigned long data);
> >>  
> >> -#else
> >> +void mte_assign_mem_tag_range(void *addr, size_t size);
> > 
> > So mte_set_mem_tag_range() is KASAN specific but
> > mte_assign_mem_tag_range() is not. Slightly confusing.
> 
> mte_assign_mem_tag_range() is the internal function implemented in assembler
> which is not used directly by KASAN. Is it the name that you find confusing? Do
> you have a better proposal?

I don't mind the name, just trying to find some consistency in the
headers.

> >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> >> index 52a0638ed967..833b63fdd5e2 100644
> >> --- a/arch/arm64/kernel/mte.c
> >> +++ b/arch/arm64/kernel/mte.c
> >> @@ -13,8 +13,10 @@
> >>  #include <linux/swap.h>
> >>  #include <linux/swapops.h>
> >>  #include <linux/thread_info.h>
> >> +#include <linux/types.h>
> >>  #include <linux/uio.h>
> >>  
> >> +#include <asm/barrier.h>
> >>  #include <asm/cpufeature.h>
> >>  #include <asm/mte.h>
> >>  #include <asm/ptrace.h>
> >> @@ -72,6 +74,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
> >>  	return ret;
> >>  }
> >>  
> >> +u8 mte_get_mem_tag(void *addr)
> >> +{
> >> +	if (!system_supports_mte())
> >> +		return 0xFF;
> >> +
> >> +	asm volatile(__MTE_PREAMBLE "ldg %0, [%0]"
> >> +		    : "+r" (addr));
[...]
> > I wonder whether we'd need the "memory" clobber. I don't see how this
> > would fail though, maybe later on with stack tagging if the compiler
> > writes tags behind our back.
> > 
> 
> As you said, I do not see how this can fail either. We can be overcautious
> though here and add a comment that the clobber has been added in prevision of
> stack tagging.

I don't think we should bother, it may not even matter.

> >> + */
> >> +SYM_FUNC_START(mte_assign_mem_tag_range)
> >> +	/* if (src == NULL) return; */
> >> +	cbz	x0, 2f
> >> +	/* if (size == 0) return; */
> >> +	cbz	x1, 2f
> > 
> > I find these checks unnecessary, as I said a couple of times before,
> > just document the function pre-conditions. They are also incomplete
> > (i.e. you check for NULL but not alignment).
> > 
> 
> I thought we agreed to harden the code further, based on [1]. Maybe I
> misunderstood. I am going to remove them and extend the comment in the next version.
> 
> [1]
> https://lore.kernel.org/linux-arm-kernel/921c4ed0-b5b5-bc01-5418-c52d80f1af59@arm.com/

Well, you concluded that but I haven't confirmed ;). Since it's called
from a single place which does the checks already, I don't see the point
in duplicating them. Documenting should be sufficient.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925125059.GM4846%40gaia.
