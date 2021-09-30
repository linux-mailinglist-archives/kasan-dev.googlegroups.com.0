Return-Path: <kasan-dev+bncBDOY5FWKT4KRB2HL3CFAMGQEVGUGWEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E56441E3AC
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Oct 2021 00:10:49 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id h6-20020a4ae8c6000000b002adb82e3332sf5727269ooe.16
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 15:10:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633039848; cv=pass;
        d=google.com; s=arc-20160816;
        b=MPs84QUCMFJPZk96YG2foEmgCHBiQqp+y9RUW9h77LYmKxZJrL/9nw1vpJcDPi3W8D
         YOrGfev3c9p+x5xMbwuhxyMKxJz4S6zDFiBJEkylXzuV1tL0r3CF0mgM7jJ9MA4OA65l
         qOkyONioCrNYVqgYgdh1yW2F03TVOgmAymIErOlrcg4/tAkWvZItSK27ZM8Zbq/HNBRJ
         oKU7UCGhzSoar1nbZVswiN58+8ahdoLqvJlvqYVRdAC5L+Heriz+XgsuQDVWvvL68c0i
         CFkmUlrOrbEd6HBaK+b9LUUYVSachQupE7+C0lGW/mRBexSwlUJSUtjBg9XLLgNJXoFg
         8+pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C5G0likm8m87LIkTpstyaQ3Y73djrR7Xn5xUZZyNtI0=;
        b=Sn6Zxhsz9u7YuL8kz1ojw35OIVgIyJHjAPxTxA5wKlSKbWOHpWy1y6s1AgWJiSVp2Y
         C1Amx8CYkdB6bZsr0b7ppnri3KnbP327RZF3utw5RCh0jwPhcae+s9bV5JY3Urbm9Tnu
         R7miBCq5ZNIGdOqjnOLCpTesXhXXU2UeQ/GBvUg1l8rb/qfXr9+29kSbC2fZPu2uLTC8
         K4yBYVGqDI5nOcCQfe6XoqQQYUFfBTD4YV+n/eOe3g23ylKmUCrucAbHNdeTgs1L1lHg
         fyQfZkvcjOxRgl9dvPTN6LBG1zaBEGtLzQ9bxFbGlELuHZhR6s5N60qhaPCXtLRtQmZi
         QFRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VMFkm4a+;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C5G0likm8m87LIkTpstyaQ3Y73djrR7Xn5xUZZyNtI0=;
        b=YXKjK1+eCAL9cEEf/FpxYgSvX+cbzs4EbLecgDVDT6nTXQUjqVNQBawajBDFyRiu0f
         P/bSX/DbDe9Mfv66oT4252G8WcivfDQD1uOhRRONV1nhF3CDjR9u/1ptDEuFIsCvFL47
         UIji1Vb5lzbkYNo0VjHbZy9uxfPtaU7sift5DVg4QhM4nGpXISApCX0lzU4SWcnqgk9D
         hnCE2aCJNeZtDvavxPGXI1dZ9UiDXLXif96iMrSZp3EGgwgLfQQlvjR5Lc3jYGBysM3C
         pG57Mqr6xtRLNhlVheT7XcCHwjysZzsIKu5EwH0PBdK/ho3c+oW5xvcNxKC2ZmpX+eD6
         +Bqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C5G0likm8m87LIkTpstyaQ3Y73djrR7Xn5xUZZyNtI0=;
        b=5DZRcl9xWjWvUy1aHf8cIJpSejVqTH5cS6TkXbkHgkd0rWt/1mbeufLJ3X1dqgxaNU
         v4enf1EpF+ybIA14aGyVThRtR9DFhjxToDsoK4eaGtlwwhNNcOd2QtkgQUm6Ikm+SZlX
         gXM1JmVVBvnGju5CaqvIvf1bRrDfmQVew1bnLKo2XGuo4AV94uZtuaTmUESd3uqjoabD
         DMqIl1/dj3GmlxeO+wBxmR/0oqw5RJZuj/ZmFtevxg4+TyD91dEF9TV7RSLgkP+J/GBE
         GaSm7EU755TbeL2rWrq/r41/dPK+oO6g5oV4y3Wn8nG5upBydMvoHRM4j2Y1/YsYtM6R
         STrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302riDjcWmNExXoMUY9iHXT6tsQx1LAvgUiMzYFbc6sEzJThI79
	fCmaO8ak39NysVrCjaRGSW4=
X-Google-Smtp-Source: ABdhPJz3ycXRVqa7iSZdhSd1jExNPeVOJ40FnGbqBYVfh5wum9xeYrDa3NdIAk7ZVOQLpjZQuB0D6Q==
X-Received: by 2002:a05:6830:1442:: with SMTP id w2mr4297223otp.76.1633039848769;
        Thu, 30 Sep 2021 15:10:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:48:: with SMTP id v8ls2472796oic.11.gmail; Thu, 30
 Sep 2021 15:10:48 -0700 (PDT)
X-Received: by 2002:a05:6808:13d4:: with SMTP id d20mr1291927oiw.107.1633039848444;
        Thu, 30 Sep 2021 15:10:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633039848; cv=none;
        d=google.com; s=arc-20160816;
        b=can3SBaYI2NTWGKQ6JsyvYlQf39aRfpUfwS63Nt9seAPFrJ2pgKD2vH5rJWqlypbwU
         V0bJpYmFRmrUuSAvSvxqh58IIE1Z3Hg64UDkncTm7f1HFM5s1phL3QNGOHQJjHJZTf8a
         5D7oBqlYHt4Ruq6G0a2M0ziU/DiChKby9nmt/VaeWDD4+XYYVCgvg+3MdHtx/LZtS8TB
         P3mNLa+wo/Afg6MFzSIMY9VF4jl4FHqTGzaz4TC9r8SQ85wwqZJdqBRRkIH9gXgoftcK
         7ksp7y2bcnOpBfKhdIfYv/6O5npe9Lqt/BMJEQgpFyKTocQNuJE3chQui7fst1R1mXo5
         Tx4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vA/AljI0AdEcZYtoxkFDlglyhW9o7GBGgLYN18ut5XQ=;
        b=DXlyzmjfYWtlXyraGcxgnmrpKas+Bug6G0nvED+95q7mVHv5LcuIpiAtVDZI3kv++w
         XSaQyJJyMdi101irr1sxXoNMlybxkDdVZCKdbMQ74ZDo+a3BlBP+z2in1Nu2OWqmak6j
         fBuwBbEcPfLEwIPJ8BJvNjpDKFaN8mhis8UiAsM47GZc+TTjAAGWriXZnSLvU55enqkF
         WbgYF8f7d893qyL/uZ71YJFf1M3wkWrVLEIO10ujRkHwoj1vl85wm3Q465aLMcZBxzdG
         nziyP6QJQouxicvniYnQ6YT9iukGfVmXPkxOSl5UbKd9lH1FicAhsxmhDZa1LyU8Utri
         14tA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VMFkm4a+;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bd5si770391oib.2.2021.09.30.15.10.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Sep 2021 15:10:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 965D361390;
	Thu, 30 Sep 2021 22:10:47 +0000 (UTC)
Date: Thu, 30 Sep 2021 15:10:46 -0700
From: Mike Rapoport <rppt@kernel.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Juergen Gross <jgross@suse.com>, Mike Rapoport <rppt@linux.ibm.com>,
	Shahab Vahedi <Shahab.Vahedi@synopsys.com>,
	devicetree <devicetree@vger.kernel.org>,
	iommu <iommu@lists.linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	KVM list <kvm@vger.kernel.org>, alpha <linux-alpha@vger.kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	linux-efi <linux-efi@vger.kernel.org>,
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	linux-riscv <linux-riscv@lists.infradead.org>,
	linux-s390 <linux-s390@vger.kernel.org>,
	Linux-sh list <linux-sh@vger.kernel.org>,
	"open list:SYNOPSYS ARC ARCHITECTURE" <linux-snps-arc@lists.infradead.org>,
	linux-um <linux-um@lists.infradead.org>, linux-usb@vger.kernel.org,
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
	linux-sparc <sparclinux@vger.kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v2 0/6] memblock: cleanup memblock_free interface
Message-ID: <YVY15nd56j8x8udh@kernel.org>
References: <20210930185031.18648-1-rppt@kernel.org>
 <CAHk-=wjS76My8aJLWJAHd-5GnMEVC1D+kV7DgtV9GjcbtqZdig@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wjS76My8aJLWJAHd-5GnMEVC1D+kV7DgtV9GjcbtqZdig@mail.gmail.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VMFkm4a+;       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Sep 30, 2021 at 02:20:33PM -0700, Linus Torvalds wrote:
> On Thu, Sep 30, 2021 at 11:50 AM Mike Rapoport <rppt@kernel.org> wrote:
> >
> > The first patch is a cleanup of numa_distance allocation in arch_numa I've
> > spotted during the conversion.
> > The second patch is a fix for Xen memory freeing on some of the error
> > paths.
> 
> Well, at least patch 2 looks like something that should go into 5.15
> and be marked for stable.
> 
> Patch 1 looks like a trivial local cleanup, and could go in
> immediately. Patch 4 might be in that same category.
> 
> The rest look like "next merge window" to me, since they are spread
> out and neither bugfixes nor tiny localized cleanups (iow renaming
> functions, global resulting search-and-replace things).
> 
> So my gut feel is that two (maybe three) of these patches should go in
> asap, with three (maybe four) be left for 5.16.
> 
> IOW, not trat this as a single series.
> 
> Hmm?

Yes, why not :)
I'd keep patch 4 for the next merge window, does not look urgent to me.

Andrew, can you please take care of this or you'd prefer me resending
everything separately?
 
>              Linus

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YVY15nd56j8x8udh%40kernel.org.
