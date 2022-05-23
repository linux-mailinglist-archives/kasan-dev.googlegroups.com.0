Return-Path: <kasan-dev+bncBC7M5BFO7YCRBNVSV2KAMGQE3FU46QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id E275453114E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 16:24:55 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id e11-20020a25d30b000000b0064f6bcc95e4sf6981536ybf.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 07:24:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653315894; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCJXiJAteNB/+/tLToiirA1ANPtkV18+Y04LS3pVhitS4j1fCMyGvK1HE4Fef+kN1g
         ex4W/B0tM2qoG2KHmTDGcNWxaYuU1Fe6jwydLzOjTJ1h0bDBjBoFWvJMom46hAmKgsPv
         Ul2sHATV6e7DwzOeOak89hgbdftvo8KYQcASXxd0K5nFQocsZ7/5W+xWkqGuSvvqEX0u
         rsju8Lx6XPf10RrU5kNAWvnBD1XO1XbBzfdBGnCAM2J/XEAGFk0upxY78x7W7c8ywsB6
         DF8Ryc+/urzfhthayU+NtZ/UM4HmDCs1PDjK+uOwej4NCxnTHqoNH76kslH1MT8fMe98
         HxpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=A/FG/T12kHCq8RgLlr5arrgwfhxsvcdehdYhHlXaMPY=;
        b=SrlHsFsUrI7q+aXM3HZxpSMXIGJ6y0T12pgZNsbdPUObcgAEF2SjrFeSckFCN/JlR4
         WF0Wop1fgq83iCxrrLDkYxSY3xLUkLB78CRT/MaSuytol5rmWXxp6dPeNIrqbNPw/bYg
         ndcbVZdF2OrZVRaIVQJ7ssz+92bFdPG/rpInkftsyLK3QuXGakiUQUbbdjgmzLLj8d94
         /BYbr5a6+64DCZ2MDhwjaPCAiRQgSAD4QAx21Dtvw7eUjriTYGdk/6UB3kj2aEXEymrX
         +0hsrm7Z7cBb9r9/IdPFXc2olpHOCu8eA9UbAAbTHccNX7yslCcjDADxlhmZhQYS9kLZ
         eCaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=nFxf6Aif;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A/FG/T12kHCq8RgLlr5arrgwfhxsvcdehdYhHlXaMPY=;
        b=m4f0CRsiZGZfHbnPljqtIrRQfVE/0GS9rEF6sBcCFL9ANwvyO/Rpk5hRcWU3cmWVB0
         aEhV4udVRL2kDxUhGr71UYF6BqyMyP825clP+IFBnVJ5RdSA+fQLx4ZwHW0UkvmVm4sq
         RN1SbdTWV9ckf/wgeVKANep11X8R5fGickL+3ps+fhww5VNoMoJNQn9vB1yTWi+yMf30
         ZW0tXzF8XCZeTd8FGM4mHgDwf42WEJEJPzX8uf2k6kGDcVLTsgcIdOI8x3m+/6zJS3fI
         XNbRX7CZhmsGXIEpX+C7bXkl29WPaIw4aXVCVDX0Yj8SJgd8GjDIHLVpVcMZer/3R9U+
         tIFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=A/FG/T12kHCq8RgLlr5arrgwfhxsvcdehdYhHlXaMPY=;
        b=ByyhFkHVAcu1VoSX+uaRPeIHbHFblSeM8TyWzVhYsrIaDY8ImzerQOmZubRNAOqjBG
         PjMkrf3nonLqKEnJcUmffJMZ8m/mPEBnTc3G0A2M2xQm46RrUKvBIjp5YcQIOX+Jwxjt
         9q7a6VXabaHyPctpkViBP7njlp4CV1uc7KC+axxdOwL06s8qlMApY8WxMjDqjLlenZ6J
         ft17Kh6I50D6pnaWEOpf4EKHfwGHM+m8ul4KVgr/FVxUITzkOqwovaDrUyTMUDgJXjpr
         BO2j3drZdz0zPJKOYbft2+5YhMWUGvFxWhpAWi88b8Jy5K2ZBH3vur56fWITjLj9ggpN
         qi2g==
X-Gm-Message-State: AOAM530+BC/X9pHeSdmd5Er7Yx5G32oPzPWbl+l+M0S/wshyzW5eYlDC
	IzF7VY5lNb+Ui7//knPBwjU=
X-Google-Smtp-Source: ABdhPJy+16B/86Y08msfg7ICXFfHFxpJhZxGNPJZ14juI8mkFft1n+fv33qOCnuispzcqTHSfIwxMA==
X-Received: by 2002:a05:690c:584:b0:2fe:f299:e057 with SMTP id bo4-20020a05690c058400b002fef299e057mr23090188ywb.227.1653315894795;
        Mon, 23 May 2022 07:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:af0a:0:b0:2ff:64d5:6e06 with SMTP id n10-20020a81af0a000000b002ff64d56e06ls5699873ywh.7.gmail;
 Mon, 23 May 2022 07:24:54 -0700 (PDT)
X-Received: by 2002:a81:70c3:0:b0:2fe:c68c:aa1d with SMTP id l186-20020a8170c3000000b002fec68caa1dmr23327377ywc.431.1653315894116;
        Mon, 23 May 2022 07:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653315894; cv=none;
        d=google.com; s=arc-20160816;
        b=wXjVIVRTOmyJH9WKK9koVIqROGgg0k94du5hdOcx+buphX0eGFLdhKbBVtgoBfWNmM
         Th7I/FlYLCMF2rVtxtKeIfJ/aVHXKZen6l2zuSLsQnra4ufyAHMJPFyBnPCNHWL6d/k0
         UogoLTEXPfryt/T9+udr7IZZS3z8H6ImVmAn65FAdBqP8hRaZf2BN0xPbri8cYJoJYVl
         dgm+EzcNTMYxY6MFRUOzDB6JAYFhebHXhxtSG3OQMoYZjHsRAQ2zHDmWcNkT00pSeYqY
         +HbO9R8krzd8tQ+RWTu1nZ+bqlLSrdtpvNVTbO+dAt5nDLt8G2B7Fv7oDSpXST9DCgsd
         rT1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=4OpdJcTXXlsXGiX1+XWS8FUX7vG0MIs+nKrykIWk69U=;
        b=dmFPZVS682835e8nk2o9/oG2N6uD5LifRRJQGRzLXfHUYoe2yRktL4ux/oiu/10Ufu
         gBeSF3X/xXfRFsdCRY8JDSduajUB3mYPm2+S/OpNCY8w1RFLUtFuFY5N20nvyHBj0f8A
         A6PZGdySpG66VmnzwkRnc5OlTeD1IaoBSMURFued26qyjDiZXYVdQjJ1aTGKp2Rc0ZXz
         zoytjlqZjQhluoGmwxqAulVrC7bnsgZHbWRe3lJC4BKRiJJZ1CS89RDKnuYNoniTfFv7
         6ZDfNCqwEpArOkD7B4AzIhGychTh7IQCeZ1JuOeT6hK1Bo3KEV+FH8d48svbCsR9Wv2k
         c6Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=nFxf6Aif;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id q14-20020a056902150e00b0064f8ca35089si269270ybu.0.2022.05.23.07.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 May 2022 07:24:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id e189so17970822oia.8
        for <kasan-dev@googlegroups.com>; Mon, 23 May 2022 07:24:54 -0700 (PDT)
X-Received: by 2002:a05:6808:1a01:b0:32b:1edc:9c4d with SMTP id bk1-20020a0568081a0100b0032b1edc9c4dmr4175160oib.279.1653315893783;
        Mon, 23 May 2022 07:24:53 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id b124-20020acab282000000b0032ae369c25esm4149529oif.53.2022.05.23.07.24.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 May 2022 07:24:53 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Mon, 23 May 2022 07:24:52 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	vbabka@suse.cz, penberg@kernel.org, roman.gushchin@linux.dev,
	iamjoonsoo.kim@lge.com, rientjes@google.com,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v5 1/2] printk: stop including cache.h from printk.h
Message-ID: <20220523142452.GA3164183@roeck-us.net>
References: <20220427195820.1716975-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220427195820.1716975-1-pcc@google.com>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=nFxf6Aif;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::22e as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Wed, Apr 27, 2022 at 12:58:19PM -0700, Peter Collingbourne wrote:
> An inclusion of cache.h in printk.h was added in 2014 in
> commit c28aa1f0a847 ("printk/cache: mark printk_once test variable
> __read_mostly") in order to bring in the definition of __read_mostly. The
> usage of __read_mostly was later removed in commit 3ec25826ae33 ("printk:
> Tie printk_once / printk_deferred_once into .data.once for reset")
> which made the inclusion of cache.h unnecessary, so remove it.
> 
> We have a small amount of code that depended on the inclusion of cache.h
> from printk.h; fix that code to include the appropriate header.
> 
> This fixes a circular inclusion on arm64 (linux/printk.h -> linux/cache.h
> -> asm/cache.h -> linux/kasan-enabled.h -> linux/static_key.h ->
> linux/jump_label.h -> linux/bug.h -> asm/bug.h -> linux/printk.h) that
> would otherwise be introduced by the next patch.
> 
> Build tested using {allyesconfig,defconfig} x {arm64,x86_64}.

But not powerpc:corenet64_smp_defconfig, where it results in lots of
build errors such as

powerpc64-linux-ld: fs/freevxfs/vxfs_fshead.o:(.bss+0x0):
	multiple definition of `____cacheline_aligned';
	fs/freevxfs/vxfs_bmap.o:(.bss+0x0): first defined here

Reverting this patch fixes the problem.

Guenter

---
# bad: [18ecd30af1a8402c162cca1bd58771c0e5be7815] Add linux-next specific files for 20220520
# good: [42226c989789d8da4af1de0c31070c96726d990c] Linux 5.18-rc7
git bisect start 'HEAD' 'v5.18-rc7'
# good: [f9b63740b666dd9887eb0282d21b5f65bb0cadd0] Merge branch 'master' of git://git.kernel.org/pub/scm/linux/kernel/git/herbert/cryptodev-2.6.git
git bisect good f9b63740b666dd9887eb0282d21b5f65bb0cadd0
# good: [1f5eb3e76303572f0318e8c50da51c516580aa03] Merge branch 'master' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git
git bisect good 1f5eb3e76303572f0318e8c50da51c516580aa03
# good: [4c1d9cc0363691893ef94fa0d798faca013e27d3] Merge branch 'staging-next' of git://git.kernel.org/pub/scm/linux/kernel/git/gregkh/staging.git
git bisect good 4c1d9cc0363691893ef94fa0d798faca013e27d3
# good: [a3204ed0fc565fc76901c67dfc8e04c91a5c8ea4] Merge branch 'for-next' of git://git.kernel.org/pub/scm/linux/kernel/git/rppt/memblock.git
git bisect good a3204ed0fc565fc76901c67dfc8e04c91a5c8ea4
# bad: [ca228447682904bc749c0702695681543b5dc709] Merge branch 'mm-nonmm-unstable' into mm-everything
git bisect bad ca228447682904bc749c0702695681543b5dc709
# bad: [c0eeeb02d9df878c71a457008900b650d94bd0d9] selftests/uffd: enable uffd-wp for shmem/hugetlbfs
git bisect bad c0eeeb02d9df878c71a457008900b650d94bd0d9
# good: [0a7a0f6f7f3679c906fc55e3805c1d5e2c566f55] hugetlb: fix wrong use of nr_online_nodes
git bisect good 0a7a0f6f7f3679c906fc55e3805c1d5e2c566f55
# good: [c9fe66560bf2dc7d109754414e309888cb8c9ba9] mm/mprotect: do not flush when not required architecturally
git bisect good c9fe66560bf2dc7d109754414e309888cb8c9ba9
# bad: [97d482f4592fde2322c319f07bc54f3a0d37861c] mm/damon/sysfs: reuse damon_set_regions() for regions setting
git bisect bad 97d482f4592fde2322c319f07bc54f3a0d37861c
# good: [54205e9c5425049aef1bc7a812f890f00b5f79c7] mm: rmap: move the cache flushing to the correct place for hugetlb PMD sharing
git bisect good 54205e9c5425049aef1bc7a812f890f00b5f79c7
# bad: [9994715333515e82865e533250e488496b9742f4] selftest/vm: test that mremap fails on non-existent vma
git bisect bad 9994715333515e82865e533250e488496b9742f4
# bad: [d949a8155d139aa890795b802004a196b7f00598] mm: make minimum slab alignment a runtime property
git bisect bad d949a8155d139aa890795b802004a196b7f00598
# bad: [534aa1dc975ac883ad89110534585a96630802a0] printk: stop including cache.h from printk.h
git bisect bad 534aa1dc975ac883ad89110534585a96630802a0
# good: [dfc7ab57560da385f705b28e2bf50e3b90444a6b] mm: rmap: use flush_cache_range() to flush cache for hugetlb pages
git bisect good dfc7ab57560da385f705b28e2bf50e3b90444a6b
# first bad commit: [534aa1dc975ac883ad89110534585a96630802a0] printk: stop including cache.h from printk.h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220523142452.GA3164183%40roeck-us.net.
