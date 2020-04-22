Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBDPXQL2QKGQEXQZFQ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0686A1B4F94
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 23:47:58 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id y23sf1461881lfg.23
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 14:47:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587592077; cv=pass;
        d=google.com; s=arc-20160816;
        b=CLM1kwlCUFnjDuQl14H9+oxReLOKacWbb+SLtHZFrfbfoZbnJCQd0KYt+yiSQEJkcx
         fOvuFScHr4LuuIr1KiglZmcUZcuvtXZVSb8qOYTCO1at1EuaXG26yZv/qLUTt1Ch++89
         JDtxeB5hg95oYhZjnNlJxuOIapVf12fBmX1HXFwQy08rmSTdvBRAod6q//t0ILS82ijd
         nJkhmM280EHcFaf4aHLTmC08e9sGLHYXKqYQ875JRTveDpIdicktfOab4PVQX84FJ+Pw
         +eK4n6OxQ/k2/EaOm0uyjyOTEEVFLVQxkLj6AFvzHW0AXDKD4pIwtMmpeid6Ai1ywZLJ
         v65w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=hxfji1xFs1uQW5PNXDQVNOLESCJbtf73Q9h2IYyNf5o=;
        b=y3t1D7l8rMzj3BfDieydwbg5of7NOuqyPzwO1bE4KznIraj1BTUKgqQE8vqrKW6XfK
         rqYwPHGQb36YGdtinqfeWTPo6OStxzA0VGEr44yw1wo0HNAdjzVMFA5jNX60F2pixGwF
         vVDI22D3rDvBayE/Qu3GvwyDZ60JmJi/Ri7KJ4MMTAbEX45wEellr+Fkhu7m3OS1Nv5i
         7obqpECgcFdN9aWsQ0SIiZCqxSUFCAjuGoF1HpoaFDdt+XFqg2+jg52i5NAHxsIVkhgr
         BZTu50ii4H52KLCXxFDfSjBSHxYAx+covcp8Zzrk8F7qQSbJ6dPU09hc4+yM25wivK1U
         cZAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=QSaSRN8r;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hxfji1xFs1uQW5PNXDQVNOLESCJbtf73Q9h2IYyNf5o=;
        b=hCuOBzixilsqrvZT89CTRE8iGZFlV1N24c48wWgIJdQgCqbq6QWnyLq8WxC44OKieC
         eozRU/m0vukU7v1+B53DJdGJv0AFTlhZ6duC9KMCgngcAcC+UWYIj1zdx1yoA3PdC90o
         DkI+HIiF89OxQLnmhBhYnltOSpSwJprmRhnD217ezGzdN3BQjoMJo50DHnURflz6c0Yn
         5FAHzeg62FR8/Of+L9SnJLniyB85lTpyvXESzL5N1ovWyxQXOR9QV/V+r5Vx+8Jz8D0T
         bEHf/BlLy3pq5ygP2ZYER6kDZsY9NCfAwf/KP2ff3Yu0KYHOMeFw/DAruHQuM2Zb5lAx
         2T/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hxfji1xFs1uQW5PNXDQVNOLESCJbtf73Q9h2IYyNf5o=;
        b=l/A5TkQaVb1320DqjM8ljDvvUxIpFoxzkjqRSuSfFJhHbq+6LK2RVcmeCry1FzWeUO
         z6QrwVlDH8ynNuhyeWqSd1TldKqLLvD80Zc73LIWBMg5LbZb8U0ZTR0NTh/0LQmYbM6D
         9bDNmHjlMMBmKm/oIZm8ybE7vaw65DGsfeYiI7UkAq5jsJ0VF+E+uwvFlp3dA/241dhY
         A2kKBJlyyAD+LjhEcQFRMhuIT+XoM4XBZp0pt9zI8XxjTy+s1UggDWG5c4L2bbqqBFgt
         8KVlY4dBgedplhmTOAi4RArJK6n5Znspw0FXN3qaDWdHSICz615CTZInCN7xSV+hblE6
         ecTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuY0+lmomybxvl8mLg921M0XAItmCIqPx9l9txh2s/wwuaQZF3Ct
	XZjy+mReQQSIh4Gg852kw80=
X-Google-Smtp-Source: APiQypJtSVnbf+9GgsocscnjOEkrgTfUZjgeIIiAqqN0SL3ZjQtRHobjPVZsF6hKoQnMQp2ZNEO74Q==
X-Received: by 2002:a05:651c:287:: with SMTP id b7mr548385ljo.82.1587592077501;
        Wed, 22 Apr 2020 14:47:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:55ba:: with SMTP id y26ls880607lfg.11.gmail; Wed, 22 Apr
 2020 14:47:57 -0700 (PDT)
X-Received: by 2002:a05:6512:1c5:: with SMTP id f5mr387812lfp.138.1587592076966;
        Wed, 22 Apr 2020 14:47:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587592076; cv=none;
        d=google.com; s=arc-20160816;
        b=VU7NKlTHwt8A1p97NJ1cH0Cgb0yAZOuWK9MOb9sMAEf8aZpMJ4JlgiDKoBXkIz5hG/
         JYMOBZfm3GMe/iebXiIj3nN22dqiIEADHrE5jYyao3G5dvxRjeiG42RkTh5MC4q9/ljk
         Vo/A5kCOwiQ0BO9KMtq3FWQ3F22PI3KjZP7f6UzTaNvKnBD9D58ACvpeBKul/FaDm/O/
         dkGL3FxWh9ugULBzEhE4agMpgVeeKDthgVl1/yERlL48BbjI1++86nHTVuVQZyqjviMz
         cbxcjhr5bhWicfu7d1HVDyQFEuH9bE5YR6LfCmlz8SKAYrf55arXQWo5U6zX7kkFQN+Y
         P02A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LhNefsMKhteFQFie49WXS2AmS61Op0pGlnLmbupfJJ8=;
        b=lo/h5bdhheH7mSXXp4jBnwO7mkwa8pBGh9+1Nba5VcffZWgPSzvo5U8VrjLBwZyq+D
         xDxBMo0vqNvSqKvOOql697k4wh3AAGfFnVIiAKBkSr75zZZuNWggP6puVT3IbniBsV8U
         UrsBiGBO/XU5aFy858XMltPSXjKBWgC4s4GiwZtBICDzlRoDmlbpNTAPro5wQwgD1SyT
         TbReuVD30D+aQvUNpJzUh/YBNma4f9vM25909iFvE7CgDMoCtlBJJHSopZCkohjbRme4
         l1/9uwf217a7nu++Vxq+ZuAkuY6/K9CohYMfA/e4hlK3GnKnvMnpcxryvErFwM5d6g3i
         O6kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=QSaSRN8r;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id q24si36983ljg.4.2020.04.22.14.47.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 14:47:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F0DC10034799E0EEF8349F9.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:c100:3479:9e0e:ef83:49f9])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id E71891EC0D40;
	Wed, 22 Apr 2020 23:47:55 +0200 (CEST)
Date: Wed, 22 Apr 2020 23:47:51 +0200
From: Borislav Petkov <bp@alien8.de>
To: Qian Cai <cai@lca.pw>
Cc: Christoph Hellwig <hch@lst.de>, Borislav Petkov <bp@suse.de>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	x86 <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-ID: <20200422214751.GJ26846@zn.tnic>
References: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
 <20200422170116.GA28345@lst.de>
 <2568586B-B1F7-47F9-8B6F-6A4C0E5280A8@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2568586B-B1F7-47F9-8B6F-6A4C0E5280A8@lca.pw>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=QSaSRN8r;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Wed, Apr 22, 2020 at 05:32:00PM -0400, Qian Cai wrote:
> This fixed the sucker,
> 
> diff --git a/arch/x86/mm/pgtable.c b/arch/x86/mm/pgtable.c
> index edf9cea4871f..c54d1d0a8e3b 100644
> --- a/arch/x86/mm/pgtable.c
> +++ b/arch/x86/mm/pgtable.c
> @@ -708,7 +708,7 @@ int pud_set_huge(pud_t *pud, phys_addr_t addr, pgprot_t prot)
>  
>         set_pte((pte_t *)pud, pfn_pte(
>                 (u64)addr >> PAGE_SHIFT,
> -               __pgprot(protval_4k_2_large(pgprot_val(prot) | _PAGE_PSE))));
> +               __pgprot(protval_4k_2_large(pgprot_val(prot)) | _PAGE_PSE)));
>  

Very good catch - that's one nasty wrongly placed closing bracket!
pmd_set_huge() has it correct.

Mind sending a proper patch?

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200422214751.GJ26846%40zn.tnic.
