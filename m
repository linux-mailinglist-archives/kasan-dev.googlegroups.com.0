Return-Path: <kasan-dev+bncBDV37XP3XYDRBUWLSWAAMGQEDQW6WLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 52EB52F9CF8
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 11:41:23 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id k192sf9124456vkk.9
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 02:41:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610966482; cv=pass;
        d=google.com; s=arc-20160816;
        b=brAh/Inrcy+tJ02u3DKjoC7HOzQ2vVxpSRpymZvLsgEcKoHJFgFeGezkcBuOnWior/
         XRjHvvlWadK/+lMKo2s/riDpSZBv8NrPSmDx7rMUDfG/P4dpokKKx9S5jV2gPs3pS8eD
         fD217Lz2nW344oXQ2HMAUU7GRjkmjijXF+QwNmmYKFhQfPf08gd/KLsUqf6hRH4qIZ6N
         4ZBsIoHwTGYBKDw1qOAONqVg+raxXGrOmKcnV31wi6hC26Yagvc2jhP2am20KJgYnZON
         pcLn0497sFcfnrXH+zxfSY9DReK5elGLUZf1/vtQPeF1b/PIkKgXTDk2bcy78zO9omlN
         g3NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=b9mN4tIlra/6jNXh1TGnbafbr266AaLDznOG41YLSaw=;
        b=SVZsV8/ssZrfROYAk+0ZBpSje8u8vx4ej/EGJ/xwN8AbOTL2Y2pZP1mB8BkQG/0AYM
         AfQ6njqva8kMeaiQQC/J4vnT1P7CW4VXo8d3q9fShAm9cNWNqwmUnr0Q5Y8OrnpLX9HH
         KNW+zPY5yZMrkww0onT/ZxpbaOIQ+b7sJaAq90FjVg4Ptv56m6URLL3MLZXqjn4QMAnb
         EhExPk2q26yNjgAHmpRUPh1flilcY2Y/xKLdxFiFcrcH4SkRPk7cigi0///FqRPtKJP5
         AylXuA3aOrK0H/2DCB7gbKDz3h2wYvRSGNSQuEhsoTN7N3N613vS5EqpOyvmvJDhT1Gj
         o1FQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b9mN4tIlra/6jNXh1TGnbafbr266AaLDznOG41YLSaw=;
        b=hNmYPZ9LDyCLASwJmrx/aFhAPpvKPtt2u94+sy61FaPHu4LLHHLzi8LX6xjIpGchJi
         if8LqQ+qyGFv6lomO9owVD1rREWFw1HpZGNjOEnUltwp4tG/ywKPWfrth/ARfsaX36oe
         WIBQDDUuwVy9h6svhPMhhDTP4EFTkj4eI2pr+AgsU8thS+I1kMMtEtKK62gactk9uPwa
         OkYojvAj/jW1YWJe0yxFJGvv+eylMxYZqghQpjmpMZrRpLJlxFwu0TjZdh4bn2rowiXd
         MjJWlvcYwVynTQGOfkzkPNrHOe8XkLLxW+ZPEIYcHzgHFiqi0b4LqircDI7HWbG8KJxu
         Yrvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b9mN4tIlra/6jNXh1TGnbafbr266AaLDznOG41YLSaw=;
        b=FlCQqDGgMcx3AxwYdtBZFa+9LgNNQMXT6DwzyQdD461sDYmSyN5RI2tIXdS+fI4Xrx
         sOcx+ZI8gno3daLJzbGPOk7Bt1GDfvT4Iq7b51VPdHYc9PrBI6XjkNd7gTzJHaeaLStW
         tXl21SXail7ctxsdyyJ8DvGP3pOnEQuseNpiyXFWRdSRb5otYunpeB//joB17YhqCigI
         qdQb4JT2OR+VZcxBJ2ndmCZOdEVZ1bMNV4GgLLfPBJA1yMTlEOvq2xUMEDl2RYVIsNEv
         IKLPKqTYWwpyvzbYk4RqIqFcpcvK19Mw4A/ko+TOLY+x26pkX2YBHcFDqUWJJBgdaZMZ
         xrJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Xm/MYiMWf3JJIT2QxJzDIiKe1+7Mo67zAfgUYn6r+9VdfpwtZ
	lFH3wMlge/xiAWmQXI9Aoyw=
X-Google-Smtp-Source: ABdhPJxgRkSfw0gN4RMJxHwpWRooiV5UF2FrsEPCC03PajNMEhZnZrGZAf5t+S4RJGu5uymc7DYh0w==
X-Received: by 2002:a67:9c1:: with SMTP id 184mr7662117vsj.41.1610966482369;
        Mon, 18 Jan 2021 02:41:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:214e:: with SMTP id h14ls2286079vsg.2.gmail; Mon,
 18 Jan 2021 02:41:21 -0800 (PST)
X-Received: by 2002:a67:2bc2:: with SMTP id r185mr16754637vsr.15.1610966481850;
        Mon, 18 Jan 2021 02:41:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610966481; cv=none;
        d=google.com; s=arc-20160816;
        b=C4BLimtA5jfBvx9AqBE/dOM8IQ3+5+vDUgJ1gwQfT7YpeZo+DFVavakh5009kvjocW
         w6B3rLpnpvYsUTA/si77XaN7gvfrThGEfzPv8Kd9MnioihAyMFrmBpGczGCAwna1ryNO
         idd4D+W8w6xEXtPABDC6SiV+JHjJrvJVgwFCDk8AC7bwqCozmrk4/BhPSVejwmM8yKdr
         4K9KYMX+LthRzi+kdExVAGiMJEB3X6GqcnWAPku+FD1VoeiWfu38LAOZ9m/ijIxUZZ5C
         wryLpoJeqeMnQdJ35vlTCDJN7td8WYP05iDQYqgOpWp+Ih8bkc2DHqAtsFnsiXUx8zbh
         aJow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=sGSU0YQEM+FsgsG6wsEJVFjCm8C9KvuMq0btjNKEF5c=;
        b=lHl6sOENc9YYsjOdmrUEgqDY7Hf8xUmxYvNLUZIIyX5w2kbIpzXQeXJuRqna5f3KAd
         BOZPFtkJRnEcWVnNbbqczgyVxnTjM3+XWSmlWs64+MBFP1Y8/5uk/D3jm1yjiPFfPCq9
         Kl/RcpAdDeeEoJwymVoVNigqDrJokBwJvjHpUtiev6TEffO7rvRFTRoPfino13Iakrgm
         zR/iqQkGWRjsQGvhreceG0PKTdjM8CIarmnMZjCtBUeJ1A6AITGAaDaCOAu+8dXqjj2/
         ASXY/ZWKdhonRjdHs3ulvZxuQvQA3YYBvrhmvBCgfx/XwMuYu8JGGY0W8hUas7wXJw6b
         qqUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q11si296487ual.1.2021.01.18.02.41.21
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 02:41:21 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F3DDD1FB;
	Mon, 18 Jan 2021 02:41:20 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.39.202])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6D6733F66E;
	Mon, 18 Jan 2021 02:41:18 -0800 (PST)
Date: Mon, 18 Jan 2021 10:41:16 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
Message-ID: <20210118104116.GB29688@C02TD0UTHF1T.local>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-5-vincenzo.frascino@arm.com>
 <20210115154520.GD44111@C02TD0UTHF1T.local>
 <4b1a5cdf-e1bf-3a7e-593f-0089cedbbc03@arm.com>
 <0c1b9a6b-0326-a24f-6418-23a0723adecf@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0c1b9a6b-0326-a24f-6418-23a0723adecf@arm.com>
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

On Sun, Jan 17, 2021 at 12:27:08PM +0000, Vincenzo Frascino wrote:
> Hi Mark,
> 
> On 1/16/21 2:22 PM, Vincenzo Frascino wrote:
> >> Is there any chance that this can be used for the last bytes of the
> >> virtual address space? This might need to change to `_addr == _end` if
> >> that is possible, otherwise it'll terminate early in that case.
> >>
> > Theoretically it is a possibility. I will change the condition and add a note
> > for that.
> > 
> 
> I was thinking to the end of the virtual address space scenario and I forgot
> that if I use a condition like `_addr == _end` the tagging operation overflows
> to the first granule of the next allocation. This disrupts tagging accesses for
> that memory area hence I think that `_addr < _end` is the way to go.

I think it implies `_addr != _end` is necessary. Otherwise, if `addr` is
PAGE_SIZE from the end of memory, and `size` is PAGE_SIZE, `_end` will
be 0, so using `_addr < _end` will mean the loop will terminate after a
single MTE tag granule rather than the whole page.

Generally, for some addr/increment/size combination (where all are
suitably aligned), you need a pattern like:

| do {
|       thing(addr);
|       addr += increment;
| } while (addr != end);

... or:

| for (addr = start; addr != end; addr += increment) {
|       thing(addr);
| }

... to correctly handle working at the very end of the VA space.

We do similar for page tables, e.g. when we use pmd_addr_end().

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118104116.GB29688%40C02TD0UTHF1T.local.
