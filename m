Return-Path: <kasan-dev+bncBDDL3KWR4EBRBKFWQD6AKGQE3TN53YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id A6C2D2884F3
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 10:11:21 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id l12sf5862543qtu.22
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Oct 2020 01:11:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602231080; cv=pass;
        d=google.com; s=arc-20160816;
        b=zTEh64BI/q159Tl0t7LcuCuEYbx+XhDTxB/SZoEbFIXzVFMHoZ8WgI9F9P7T/zFxK1
         XtHp1LfkKXDZD3H4voKQNOC0HJ5n5KeAOEQOd0zyqdv8dmSAZvj1a/9xFpwX3soaEEnq
         2+nmMkV6MJrCI4iFR3WnO6Exqwo+gTyDWeOiEJV5Ap6fZSnHn21KyCjD8lxEW2KjsuzU
         4myMd0AnnRJ/hxLY06LoIIBgU5prAqOl/mHMIK0EQnKMz+Rrvqnum4+k0o5+aAwPs8q+
         VTKEScaoDN6HOuEORsTKJE5TqJJAsuJjXRfeGWEhT/FaIMVYnabdo33GJGNn6wUuPySK
         Y5mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=x2XD2blKtumaz0ROUeeQ4Cqc1wsuF03IJhHFMZeBnvE=;
        b=zMMoawGBdLk65zVSH5jCG5U6BeCmxyECwKu1xFJdkp10LpDzss4DQXggKicgatsSQB
         ZoW373jy7lyoG9Zo5J9WZzTnKh7QUJFBGwkdRZm1Itp2Sugcwpu5ZD6Yg2krjtj5E/JP
         Ehkg8EGZQ1jErSLCDHjb38zfZHIK6uYBWRD2pc+Qgb/uTJtrmETA4XvDi42zHt/+802Q
         TmCIyyY3NgB19YmsbJqEbqa2VQQnGbX/nF8A/ij+kSyzSW5NQqq+0trM4t02OOydWYJZ
         yEY19JPabfHbGaQgpvLRQKKpYPGT3LIDCy4KT2mGyezACF6cQ8IK97aVHdByuXcbWiFI
         Cu8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x2XD2blKtumaz0ROUeeQ4Cqc1wsuF03IJhHFMZeBnvE=;
        b=n2w3MnuM0kI9gyjoKmXOAfJ4VgJOgEe82DoGyxFFstR7oiA/OxMt07zD9gK5QaQMjG
         jieeFegfOWAm+Oyozs7VHDFcWXST/mcAyRKEDEa25+qnJi9aHAdiK2p42TLs7XIil6pC
         ZZKYDI8gh2whV7cC2efDzwlJ3Qc9WAHwTO7fUK+RhVC/YCt398tHAKTT6Iv/IG+i7eri
         ntYyujDQEXUfLMRktQBTxCGReLCmmvdev1kKlFkj0Twa8IGLLUGGX0BzaDu7shc/ouRj
         0SNnhai3s8w7Rbk+U/rmSWBToIjRpFEQW61Ezz9K2KVIvStLiYHz8ZClYV2gIBKOqIYX
         KHZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x2XD2blKtumaz0ROUeeQ4Cqc1wsuF03IJhHFMZeBnvE=;
        b=uY7gQ9g98KfRv2POiFzrhM8jJsxRvWXF/yA0aThfN5ANfHaq5TjEKv+2Z+YYOHroX4
         Mt/4p8dyACaSwNSyNe7Z8RagxnIwQjEkIJEnXfADJidGARk4TyTW2sKX8hl+k4BLJ27h
         zHVAphZVYBliWB8xmSc2ZV5g+6bqrcSvqYf83HdfcZG/57hJbQqDBv5lAfMn/sE4hxL3
         JSJCVSyUat5cgsE+RgfiCI/1JyXIU+QU+TGG0ekdJcjlbLpGXmLiaxpkLzOmojowMLOi
         pgAv6cb71B6OD9M0rmYSwvoArI5N7u1Ho6Vf3cy5cr/43rEvPjKZLUXD7FrtsFc/EBXG
         PxCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53044wqCjo9MBcyE+TDsaxB+imksJdh+P4sS+Br5HimOh8X6wHWD
	TdzoxmJAbQWKsJGsXxck+rM=
X-Google-Smtp-Source: ABdhPJwl+FQaq2ZK4aKZ2LgqAb8mf9kliRGEV+KE0vvJ23IK8gX8DebTh/bErZx4h7iUbyurF5JrQg==
X-Received: by 2002:ad4:544a:: with SMTP id h10mr12010736qvt.35.1602231080503;
        Fri, 09 Oct 2020 01:11:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e00e:: with SMTP id m14ls4287848qkk.3.gmail; Fri, 09 Oct
 2020 01:11:20 -0700 (PDT)
X-Received: by 2002:a37:7104:: with SMTP id m4mr12207399qkc.252.1602231080046;
        Fri, 09 Oct 2020 01:11:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602231080; cv=none;
        d=google.com; s=arc-20160816;
        b=OT457/bZiaKGrt248F9LcsaHQVucTblTuYgPA/apabra3d+Ug4bCXM6gLiwmiqZ4x3
         DRnBvZsFWwP+3ZHnMEAb/gDgFyllNLKRt5nTcsDHsMEKFDZANsOJ0xHUt3Tp/zh1g+m+
         bIFCHAQmSf3yPMsHnIKsBVERLh61uK6gef08TB8mYkG8bVaYWKrr82frTtNnQ879OaIS
         OXC0Y9DFQDIkyLT89JW03FoeKfmx8xXC0RxZIl8otVfP1FuRZiDJfbQXxtlSEU1tgd4J
         kWkMtdkQMXFgcX53Uu5ODbpG3Chjv8B9JeL3GgYoivRouubmKmDgc3bfhZjoksxlgtPl
         HMbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=qX2UOoe63x1/MSVX/TCL+8868KodLaJh2RXI8/9Y15A=;
        b=LBknjcmzTaOq1G+RuyQzq8JFnAXbAKqRlTQboBptRZsEy2Z63PjRLlz1GQk0J1zupf
         A1/OxY1/cmwShQArYm+XsJF3AfhsN+oZVrWBZMesaD1fvF5ArClTerNXfbhpPmrdAdG+
         Ipfwy3wyU5stoZ2neX3t3oYxAoUMnG4/JwnNsGzTF3qbs96qe89/1uB7a8z2xCPIC+Ku
         4mQbiPaZJqvKlMIlOHIFjsnIawVhRhxAcWQN8l5OQQAdXSdtfFthFU6kX0AZhTIsoirj
         tHpYrB3PdLbP/LgQZEtTYGKL6HaULTCnzVhFObvO6AdBHEXKBQAO7Wh0Ry49pRJgy5gV
         SICw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h18si550288qkg.3.2020.10.09.01.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Oct 2020 01:11:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.149.105.49])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2E2B221789;
	Fri,  9 Oct 2020 08:11:16 +0000 (UTC)
Date: Fri, 9 Oct 2020 09:11:13 +0100
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
Subject: Re: [PATCH v4 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20201009081111.GA23638@gaia>
References: <cover.1601593784.git.andreyknvl@google.com>
 <1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl@google.com>
 <20201002140652.GG7034@gaia>
 <1b2327ee-5f30-e412-7359-32a7a38b4c8d@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1b2327ee-5f30-e412-7359-32a7a38b4c8d@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Oct 08, 2020 at 07:24:12PM +0100, Vincenzo Frascino wrote:
> On 10/2/20 3:06 PM, Catalin Marinas wrote:
> > On Fri, Oct 02, 2020 at 01:10:30AM +0200, Andrey Konovalov wrote:
> >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> >> index 7c67ac6f08df..d1847f29f59b 100644
> >> --- a/arch/arm64/kernel/mte.c
> >> +++ b/arch/arm64/kernel/mte.c
> >> @@ -23,6 +23,8 @@
> >>  #include <asm/ptrace.h>
> >>  #include <asm/sysreg.h>
> >>  
> >> +u64 gcr_kernel_excl __ro_after_init;
> >> +
> >>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
> >>  {
> >>  	pte_t old_pte = READ_ONCE(*ptep);
> >> @@ -120,6 +122,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >>  	return ptr;
> >>  }
> >>  
> >> +void mte_init_tags(u64 max_tag)
> >> +{
> >> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
> > 
> > Nitpick: it's not obvious that MTE_TAG_MAX is a mask, so better write
> > this as GENMASK(min(max_tag, MTE_TAG_MAX), 0).
> 
> The two things do not seem equivalent because the format of the tags in KASAN is
> 0xFF and in MTE is 0xF, hence if extract the minimum whatever is the tag passed
> by KASAN it will always be MTE_TAG_MAX.
> 
> To make it cleaner I propose: GENMASK(FIELD_GET(MTE_TAG_MAX, max_tag), 0);

I don't think that's any clearer since FIELD_GET still assumes that
MTE_TAG_MAX is a mask. I think it's better to add a comment on why this
is needed, as you explained above that the KASAN tags go to 0xff.

If you want to get rid of MTE_TAG_MAX altogether, just do a

	max_tag &= (1 << MAX_TAG_SIZE) - 1;

before setting incl (a comment is still useful).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201009081111.GA23638%40gaia.
