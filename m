Return-Path: <kasan-dev+bncBD22BAF5REGBBF46RCBQMGQE6XHHXCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B334934D611
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 19:32:08 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id o14sf11471996qvn.18
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 10:32:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617039127; cv=pass;
        d=google.com; s=arc-20160816;
        b=fNmoYxK7T1r3fzLZVTPguW2rwEOW1jc4HNw6i/dxGB1pb435dEQX+rIeUcRokuSCQR
         E9u8NO0iqU/X8NgivnIb3vCfBtcFD2rPYkMuFarfX4TgqOM12Q+VwLJUNdVjbyQWek9b
         2ak8pdo09P4M57WKDqE/fao0CiW4mKYm6vDGHtUONksrUzSVbJ/znUt+NRUbyVkiRt4i
         NGiLyKqI7x463Bf6uV7HbiXb8s+yG4jISAMGWgigI9mF2yb0mexqeQ8mBwBqnxTwGww9
         cIZN8QA7iOt3N3sAjVENRTibmbzP4h6JavA8PWwG1yMthcydGbzbKYiGsmUZk2h1uM8U
         vX+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=0ZMGxBQ/Cmqh8+ZwHldTYdQHxDzxBoGkcrgS6RcMjGU=;
        b=Y7xcTHGH2wzN+7UidscC1dE5K1xTHpWGrC4Mb/N+Rddy2GZFwhBVFDERNDr68LKoDx
         mHxKNAXq4av3QFK631AyftbtzkHYfA9BxVY2D27YASnfsRRPFVbb3B2AcKLbmSjmIovN
         SgeEpAL9lklHJ1vgyJQRnO9DWmh7rV6qjkV4VyiqH+oisidzK9iDqfQ4MAb0TBv5jcGv
         kxuUCPRDBOXzLSaC3ee4bodZhbB1iTb8GMzRLPoPvACKfiK/H3F/qnPANwbZa6dJ4Fo4
         J5q20OvzD2CQxAt4RlIif4aRBD6fAuYhIK6iEHQpiBuUPIi07arryQnqrcHn71YGH+u4
         uc6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0ZMGxBQ/Cmqh8+ZwHldTYdQHxDzxBoGkcrgS6RcMjGU=;
        b=DbrD1cKa13YaDm17SJ3lCO/yfG3fyrsec9/9Pq74VFhabN2qtnmzm50771966SAxI4
         bdme1Aa3GomlqLLelw7pYKVESvOHjSOLnuMyy8TUaVHL4hOEOoc2SK051vCJEENiVGJM
         3a35xxYJLVZz2ar7FD7/tmyql+idiATsIag+FYuFhyxfoEK75GJjKkaobdgfArbiwQg7
         E1VqF5zwLbhBhGiiEsXdvx9JQKa1ojVHN4QnbaV2AUG/AwFSRMDFL85cVtNgugT+dqPM
         jWa19ajq+CcmuNo9KEUXW6t0TfctsxVbyQhoQFyQIiF74F5Hwd7BCdnsgW8OmkJqfnhe
         YiIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:subject:to:cc
         :references:from:autocrypt:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0ZMGxBQ/Cmqh8+ZwHldTYdQHxDzxBoGkcrgS6RcMjGU=;
        b=GdwAofT1iEUS1hTP61uA+kTvUhnmRqUS7VPocAR/b/Tuh0NtHal+twtW5qAUftz9mg
         3g9D9z9a6exVUPJtBXYxhCAuQKxuugPIIN5MNeqWNjabJkw9/kyvbVHo3954lcoGhaJf
         /f7GxvTP5qV0c5rjglMJDZ9ZnLjsyCd6Hnxi9tVbFWFn98fU4lev865ptZZi3orvu3gl
         FTXQhG8WaWJQaOlKICugoCLrk05cUKHPvqsvPcX0zsU/SrI8Qj6kCcXXh3u0jD1nx1v7
         YPCBSlWI+c6vVPIzZ1JgJDgiu2gW3O6EQ7ERBXAA1Y81R0rBJyzmTfQhehbZqE7Zt4GK
         iIrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EN3eEmpSN6541cdXLUx3p0DzPwxhXP1R6VPaVRzQNDRT3FdFd
	RxxQ06bJO+HAWcA0yBae40I=
X-Google-Smtp-Source: ABdhPJxY+S7jWsCLFcIkoXS/9eTfHjsRfZjQeQbq8MXvtKj0359sL/57EzfyhKJD9ghn3LfWA1u1ug==
X-Received: by 2002:a37:6c6:: with SMTP id 189mr25830028qkg.478.1617039127423;
        Mon, 29 Mar 2021 10:32:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:400e:: with SMTP id h14ls8906219qko.11.gmail; Mon,
 29 Mar 2021 10:32:07 -0700 (PDT)
X-Received: by 2002:a37:a9cf:: with SMTP id s198mr25242807qke.143.1617039127028;
        Mon, 29 Mar 2021 10:32:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617039127; cv=none;
        d=google.com; s=arc-20160816;
        b=BKEvFs3gbZiwSqjEjQ6Y2bA5ikEChquRWXTgUO5zkrxCL+kczrOvY/8SqFCKQgrR/4
         OIwCpnfe9bh9/cPKr1PZdpcpYGSXWUw47RpmdSwqQaykcHwsAN7QpEWGt+/44fpoOvTr
         /+Trb8Lg288TRA711orVnfW16SmFlIBtvrF8zh1BF5Iaq1yQsWtSWtsKWmCFT7zQcZIo
         FYcoqNEyPruivTiM+YC9HdwGnuKXOf/MCXYB1QcotPK1x1CAn6yZJN1oUOcUsxor87No
         gSdUQlInDDcevsyiC0qtIpk/WRR+LQcAdpHVoHZMVsdi7+PteGWCu4pMLimdPBGu3WTA
         3qUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:ironport-sdr;
        bh=04tj17zmv4xAghPNj+71zQc3KjiukcSCDa0XpMUIhWk=;
        b=LffBC+DzdkmvG9SwW1Uqe1I9oNCQN2plKXHDX6rjAI55RmmBCqm6XmpknxFSl8m6Zb
         dlh5ryMvl1O3sDLIEThMcwKCK5PMOKpUGw8UcDcN4XwuV9Gs1u0ZmM1w/pivy19v5iNV
         WedkqynM/AwJhni3eltaNU2ZTunpEvX1p/czYe77k683YJQZdy7ksZou9wx3qk6ZhgKC
         NlEuIwU97vKPQcfT12EviYJRCgabvd8eYLkGrkZu+kbzWhZk+PvvxKUK+7+ivikeX3kI
         CcPFiicYpFdjjL9hcS1CqLflyhrT+Z07OmXLd/pHHWlti1AI8oqyGyfzWuUhPYedHmvq
         Wp3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id w22si1033560qtt.0.2021.03.29.10.32.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 10:32:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
IronPort-SDR: /keaU3Oad/8doBgD5vuvP+5Ihw9jM1pmDcL1mgVJRq0uliPvOZpZ9tRLsCCLAQPjsq7AOrZi2Z
 LcImOsxQ/U9g==
X-IronPort-AV: E=McAfee;i="6000,8403,9938"; a="179135757"
X-IronPort-AV: E=Sophos;i="5.81,288,1610438400"; 
   d="scan'208";a="179135757"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Mar 2021 10:32:05 -0700
IronPort-SDR: dOgo06jeRJlSM+BgD1dcoC59nLgsXdxPiTuCuCv8j31WCEfvDhRNo7vW6kR+bXqwfDk51GCNI8
 O9nAHiVQ3CAQ==
X-IronPort-AV: E=Sophos;i="5.81,288,1610438400"; 
   d="scan'208";a="411196206"
Received: from jmwolcot-mobl.amr.corp.intel.com (HELO [10.209.158.84]) ([10.209.158.84])
  by fmsmga008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Mar 2021 10:32:04 -0700
Subject: Re: I915 CI-run with kfence enabled, issues found
To: Marco Elver <elver@google.com>, "Sarvela, Tomi P"
 <tomi.p.sarvela@intel.com>
Cc: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org
References: <d60bba0e6f354cbdbd0ae16314edeb9a@intel.com>
 <66f453a79f2541d4b05bcd933204f1c9@intel.com>
 <YGIDBAboELGgMgXy@elver.google.com>
From: Dave Hansen <dave.hansen@intel.com>
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
 z5cecg==
Message-ID: <796ff05e-c137-cbd4-252b-7b114abaced9@intel.com>
Date: Mon, 29 Mar 2021 10:32:03 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <YGIDBAboELGgMgXy@elver.google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.126 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 3/29/21 9:40 AM, Marco Elver wrote:
> It looks like the code path from flush_tlb_one_kernel() to
> invalidate_user_asid()'s this_cpu_ptr() has several feature checks, so
> probably some feature difference between systems where it triggers and
> it doesn't.
> 
> As far as I'm aware, there is no restriction on where
> flush_tlb_one_kernel() is called. We could of course guard it but I
> think that's wrong.
> 
> Other than that, I hope the x86 maintainers know what's going on here.
> 
> Just for reference, the stack traces in the above logs start with:
> 
> | <3> [31.556004] BUG: using smp_processor_id() in preemptible [00000000] code: dmesg/1075
> | <4> [31.556070] caller is invalidate_user_asid+0x13/0x50
> | <4> [31.556078] CPU: 6 PID: 1075 Comm: dmesg Not tainted 5.12.0-rc4-gda4a2b1a5479-kfence_1+ #1
> | <4> [31.556081] Hardware name: Hewlett-Packard HP Pro 3500 Series/2ABF, BIOS 8.11 10/24/2012
> | <4> [31.556084] Call Trace:
> | <4> [31.556088]  dump_stack+0x7f/0xad
> | <4> [31.556097]  check_preemption_disabled+0xc8/0xd0
> | <4> [31.556104]  invalidate_user_asid+0x13/0x50
> | <4> [31.556109]  flush_tlb_one_kernel+0x5/0x20
> | <4> [31.556113]  kfence_protect+0x56/0x80
> | 	...........

Our naming here isn't great.

But, the "one" in flush_tlb_one_kernel() really refers to two "ones":
1. Flush one single address
2. Flush that address from one CPU's TLB

The reason preempt needs to be off is that it doesn't make any sense to
flush one TLB entry from a "random" CPU.  It only makes sense to flush
it when preempt is disabled and you *know* which CPU's TLB you're flushing.

I think kfence needs to be using flush_tlb_kernel_range().  That does
all the IPI fanciness to flush the TLBs on *ALL* CPUs, not just the
current one.

BTW, the preempt checks in flush_tlb_one_kernel() are dependent on KPTI
being enabled.  That's probably why you don't see this everywhere.  We
should probably have unconditional preempt checks in there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/796ff05e-c137-cbd4-252b-7b114abaced9%40intel.com.
