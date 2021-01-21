Return-Path: <kasan-dev+bncBDV37XP3XYDRBGGFU2AAMGQERXCFLBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id ACD602FEF6C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 16:49:45 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id t14sf1392742plr.15
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 07:49:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611244184; cv=pass;
        d=google.com; s=arc-20160816;
        b=DRm8VnBEz3t3H5QD0p//hHDMxxxb6JwoxinxP1/bE4d1EiC1EuJpr3lcYuNoJCH/hM
         aNKNRBeDpY4ua9Y1WZvDo91YsqA/P6UBGfTwBHaEvn5ZAE27QTaS0p+HRhmJOfOl8pDr
         7oUxod4cg6MYY4HAectJH6vH1o6CDlcGZn/buTCUmzv9eINYvruOgpQ/rSiM+Z/ydjRM
         BPsgkINt3E/R4tZGkDw1zIY+d1mLI5jJaY6zvrvYoMgYW0GclFtj32TRyVgpd3SA7xDr
         We43878RGL+XF68qh2vQWM6TSwPzAjIA9MTjew9lFVMkO0A1pIqR26zXoEYyVFPizJ2g
         WXlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9RI5/pQy4PCz0Np3Ol4H29NmqPneKrQI65KsFmiZumY=;
        b=Bbe/fnoBjPU8Mim2dm248CP2py0ab8dI9nQZDnpoo5szhdxeDm8tPa0DxbcWCr8L1T
         2ZxDbecGfygeBdOGb+Vy8O7OYrdvYpv6E9bFE9DM7TUs9b68MFo8HYMvi1Quzny6pZ/6
         p7dMHH0DGKO2Norpm/lHWnmsjOmyiCSJbfzxqac7jfb5s0vc7XtHbH0Aa1Z1a0Brf2Ug
         R7OwzhbuVbjl3SFdY4PCATmodeuM3pXHc7SqPtf7/HbSTS3Vluu3uK6VXuKVZxKukMPC
         PJEq/xeJViEib70THWAWA88YNsxEuwZRPbi0GpaORy8ue6AfJ9+3rnDBYTwUTwnI0VVa
         g0wA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9RI5/pQy4PCz0Np3Ol4H29NmqPneKrQI65KsFmiZumY=;
        b=H8VjALPLuRffp74j7qq6GvmxPg4E89gaz3icYOkWC4KNadH0oxRY3Q+9eugDSZnbqI
         zgwCGRfKqu4dt1cm8rVx2mn20Qz/N86tQBcY1Cn2qyJq4NfY3kBvrNalfJt3+kpdDai0
         cxt9fSCfiiw1K/qLhGbK5i+sE7u9br0Bg9bzJx2DjtWK/tFP6meT+NZJemTRLPjMn4Sz
         qIyKymYUylDbP6tSd3FVeLJ1Bof41+EAcVbqxmTn8pLFoJsRQqMhLmq7UN31VAWGt+sp
         Ki17Z/lcRSt7vR9AIQLiFbvfiWRCzd+1NoVQRmd71q7sLZBW7dT2c3E1RFvH8g/Sq85i
         evTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9RI5/pQy4PCz0Np3Ol4H29NmqPneKrQI65KsFmiZumY=;
        b=jREsNwTG4MPKRol/iCUPe5xcsi/Lw8tbsac+mM1wNiIcOP5SfXCWdhdBhCLVkvOPjm
         ngfRx4zDSN0tgu84mzKX9OdTTnXl9yJpfi4W/yINz9dwIza42Nz/cLlQwDat0b6mriOf
         M+cBa8Pw0d4IKvabGDk3/zPUXzIFrfF8A2TqEx9qIfF2FZp/dP6dAbNVcRr1sfxbHTNy
         mbMPJ/zyMaGr3R2lE/OL9tltAk1/mqivVLS7ITxyztwK4NezIT9sDUD2YJzZgu9VrWzO
         7ff/Y8AXvJFrGLuTtWmJqVUSzJeKxQ8bzHNmNszPQ1YewWmO2VrUoeYt9WCw0H3qAKxO
         NkCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305s7y2SHBEGoFf1B8Nj52N9u93fEBHKQcTS+PytfkFEwihlt1a
	PpNHa7HvOlL1HPCVB9/3+kI=
X-Google-Smtp-Source: ABdhPJz0sf2Lhsm7nhQVYODKlMdnI0i7v23v3M+yiJwMvdgpO+k40ZXeeSZKEUcJUzy7O1szJyK9ig==
X-Received: by 2002:a17:902:c40b:b029:de:2f1e:825c with SMTP id k11-20020a170902c40bb02900de2f1e825cmr16841plk.64.1611244184417;
        Thu, 21 Jan 2021 07:49:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1e5a:: with SMTP id p26ls1003533pgm.10.gmail; Thu, 21
 Jan 2021 07:49:43 -0800 (PST)
X-Received: by 2002:a63:4b0b:: with SMTP id y11mr2713700pga.118.1611244183772;
        Thu, 21 Jan 2021 07:49:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611244183; cv=none;
        d=google.com; s=arc-20160816;
        b=EPK4hRfgh6Xf8nE3rem9JRMAYrnv8G7f3uqj0uUPetHYgp+MJRM9zBRYU1bGjTM0oN
         JtShE/oOgGiM3ITNJ/IEbwRjgfFallcXPuFSdiOKAHk+AeKJ0LH9phM4cvVPb4REHBPS
         rzJ1joiClhWMjO+eJO5JOa28etDzTV86GshxTVBDHDeQVrpplUv4OsVjTRDLJ9MVkJfq
         CVPvXCt8EoNcJwceEoMY6v45KVN0Cx5knkFQM7tNUSXQCxfBpCQ8DGUkF5oz5+0cXRYW
         W403ULoM+uRvGrJRgtvvcncnGWbfEJ9qJPbP+mS4MNFzPcStuyAq8XfdF3aDBsUzEsmE
         1r8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=3CjvG3Jdu24Ju9s45mGadbXN6lzixUxfLa3EMmiAnzI=;
        b=hZVePVBdd599zUnwRgxGYYGhM049CWJA71F9z6kuBcXAy0VgEn634o9M0DLvPtfI5x
         Td06LVsjdmI1fAhrKaD2HcTju+3cRmiksMxEvXZwTnwl3wqt6rG4Rry0+cux3GifQXHu
         b/TGW80olP6pLONHgO6lx+HkgaL+xymbNfq8pIl4wbzmyrohD0ZPFDS84mrxlQooNTDy
         R3VaUIg+nI/62FptC8P73ZAG0bjJ4obgYW80EsbJ3r1/a3vv5QV05Z1KbKbzxN6m2vbP
         MbQ/1yVtZvnzsfQBCg/PDBt3rKqWxxcdMf4q+djZHWooqXxnsfmi8OWIqszWIreEWbkP
         sM1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z9si430135pgv.2.2021.01.21.07.49.43
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 07:49:43 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3F9A111D4;
	Thu, 21 Jan 2021 07:49:43 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.35.62])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 519AD3F68F;
	Thu, 21 Jan 2021 07:49:41 -0800 (PST)
Date: Thu, 21 Jan 2021 15:49:38 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrey Konovalov <andreyknvl@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>
Subject: Re: [PATCH v2 1/2] arm64: Fix kernel address detection of
 __is_lm_address()
Message-ID: <20210121154938.GJ48431@C02TD0UTHF1T.local>
References: <20210121131956.23246-1-vincenzo.frascino@arm.com>
 <20210121131956.23246-2-vincenzo.frascino@arm.com>
 <20210121151206.GI48431@C02TD0UTHF1T.local>
 <95727b4c-4578-6eb5-b518-208482e8ba62@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <95727b4c-4578-6eb5-b518-208482e8ba62@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Jan 21, 2021 at 03:30:51PM +0000, Vincenzo Frascino wrote:
> On 1/21/21 3:12 PM, Mark Rutland wrote:
> > On Thu, Jan 21, 2021 at 01:19:55PM +0000, Vincenzo Frascino wrote:
> >> Currently, the __is_lm_address() check just masks out the top 12 bits
> >> of the address, but if they are 0, it still yields a true result.
> >> This has as a side effect that virt_addr_valid() returns true even for
> >> invalid virtual addresses (e.g. 0x0).
> > 
> > When it was added, __is_lm_address() was intended to distinguish valid
> > kernel virtual addresses (i.e. those in the TTBR1 address range), and
> > wasn't intended to do anything for addresses outside of this range. See
> > commit:
> > 
> >   ec6d06efb0bac6cd ("arm64: Add support for CONFIG_DEBUG_VIRTUAL")
> > 
> > ... where it simply tests a bit.
> > 
> > So I believe that it's working as intended (though this is poorly
> > documented), but I think you're saying that usage isn't aligned with
> > that intent. Given that, I'm not sure the fixes tag is right; I think it
> > has never had the semantic you're after.
> >
> I did not do much thinking on the intended semantics. I based my interpretation
> on what you are saying (the usage is not aligned with the intent). Based on what
> you are are saying, I will change the patch description removing the "Fix" term.

Thanks! I assume that also means removing the fixes tag.

> > I had thought the same was true for virt_addr_valid(), and that wasn't
> > expected to be called for VAs outside of the kernel VA range. Is it
> > actually safe to call that with NULL on other architectures?
> 
> I am not sure on this, did not do any testing outside of arm64.

I think it'd be worth checking, if we're going to use this in common
code.

> > I wonder if it's worth virt_addr_valid() having an explicit check for
> > the kernel VA range, instead.
> 
> I have no strong opinion either way even if personally I feel that modifying
> __is_lm_address() is more clear. Feel free to propose something.

Sure; I'm happy for it to live within __is_lm_address() if that's
simpler overall, given it doesn't look like it's making that more
complex or expensive.

> >> Fix the detection checking that it's actually a kernel address starting
> >> at PAGE_OFFSET.
> >>
> >> Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
> >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >> Cc: Will Deacon <will@kernel.org>
> >> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >> ---
> >>  arch/arm64/include/asm/memory.h | 2 +-
> >>  1 file changed, 1 insertion(+), 1 deletion(-)
> >>
> >> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> >> index 18fce223b67b..e04ac898ffe4 100644
> >> --- a/arch/arm64/include/asm/memory.h
> >> +++ b/arch/arm64/include/asm/memory.h
> >> @@ -249,7 +249,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
> >>  /*
> >>   * The linear kernel range starts at the bottom of the virtual address space.
> >>   */
> >> -#define __is_lm_address(addr)	(((u64)(addr) & ~PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
> >> +#define __is_lm_address(addr)	(((u64)(addr) ^ PAGE_OFFSET) < (PAGE_END - PAGE_OFFSET))
> > 
> > If we're going to make this stronger, can we please expand the comment
> > with the intended semantic? Otherwise we're liable to break this in
> > future.
> 
> Based on your reply on the above matter, if you agree, I am happy to extend the
> comment.

Works for me; how about:

/*
 * Check whether an arbitrary address is within the linear map, which
 * lives in the [PAGE_OFFSET, PAGE_END) interval at the bottom of the
 * kernel's TTBR1 address range.
 */

... with "arbitrary" being the key word.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210121154938.GJ48431%40C02TD0UTHF1T.local.
