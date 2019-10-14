Return-Path: <kasan-dev+bncBDV37XP3XYDRBYNHSLWQKGQESNRMCVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id EEF63D6613
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 17:27:29 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id f3sf2945627lfa.16
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 08:27:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571066849; cv=pass;
        d=google.com; s=arc-20160816;
        b=ePsXUh1WNEms2GJVQChinqXEySdiShyEMA8sKHQg9wYhM9mB8w+iCHva7PCRMJPGAO
         BRyhc5qT6969t4Vcvqu9Nguq3qmpsSnLcWMG2XEofmIKpVX0h7qGkM4dmBYT0EBGqzTG
         7GrgaFZp3vKAK3+BIggP15Fd9dR8TmfB3BsXn8uiI62x8UuFS8IvZJrF6LKY/NK33+3P
         VtDgroE3XcT/oiotj4+Fqko+5mX6iwD2H6Md+QQ/zlTeZ9vPEsA30915hr0hGi1ikbom
         EWvRaRhU0C6JajP5n8OYuQVwdR25JB2p6hxYz5oAglg3IFwh54ZJPWmdcdoDuv9+fx7x
         H7nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4bZy7EnalGx6QMBSQNkziZmdgIQpamF72WwRnv7xL+w=;
        b=uhREsv+PYQuGbPAFZvYZLIWer2rMuJ5Xs/+aB0CzT8fAUo7W8Ynkr1UDstMqLrEXhx
         87Zyg5NEsCg3YZDjAIB5prHvDg46bGVcfQmci3r9fhOt1uYRXhyHdPjGSkllTO3DM2P1
         SmI+YrBFjeRPjFalJcWlY/ZqJdGRwRCb1GQgkVDb3Wgl7D9RAvPJM/tR5JZ9DAgY06I7
         0hU9fZVxbBeKTpUqybi7BY9rzN9BZnWnGARUvaVGRM0mkyQcmNNcC6TI8D2F7+PggcHi
         JtDT4Uam8I861HWjjfgSn0QbbzdVQq+UCulDuNMao5V/FG6gQQ1raMpN2A3OGvfAUbzI
         qhKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4bZy7EnalGx6QMBSQNkziZmdgIQpamF72WwRnv7xL+w=;
        b=Q9f7OtwzE+ME/qPU2TrYEdJ6Q27SXv/FKPFNsP7SB0fUr+bOdZZcN5Qu0uZ16FriI9
         m2QbSd6ouylFhiIE+V320GC0zQ14aAfg2+RC5EfkyPA7PPVZr6YgciHxHcB2YzK1ZGLA
         HFBfCaalR8DcCwIPNFaQBqHDZfn7GvKjrtgn7awM94kk8rbs25/UPbHp205Cwre6Nyhj
         7ip/K++i2fK/8YZajVRbAtbKBVGVhqOi28yKFD62sIa5U+Rg/q+e/R7I4+qzbAZ4oUiC
         oR3ndvgtWStTUwDuVt8QQZ1WsoVS1Ts2cvmQqRkWnuS9HSef5Ugz0tcNwZK9dQuYjNna
         yCHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4bZy7EnalGx6QMBSQNkziZmdgIQpamF72WwRnv7xL+w=;
        b=YtIoL76VKpG1ZRGL15wjg5CIVHUPsi9Xn7vK/FCX/W16AxxR9jRQHARYssYQx5cq9H
         y5G/mosxcT9sgFCwqqZ7wKLA7XzXu1VZdqZiqq6i52dUMt0O1qLEklEaA5IZyJwI4D3t
         WBF+tc6Y8ZGe77+d/RUM5YUIakjowRctwKaoQsnlCswU9od4nKGFYbZfc4fB95PviEpA
         yefua2R20kjQmDoa6DaoeM9Sjjry3QQqA+Z/EctQb4/ZiMFCUvCudV/bBxPuQlMWesRd
         nIPfW+tW3yYg3bC84QZVgLkW1eKmAqZ0kGUKoi+5L7mz/9yynKvuYLVeBL05JccsuXwG
         7EBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWDiNsNnN2RMeQIfAh2+3N5SNdizOMIkc690vUDClroobl2H7YF
	tqHaRV7pEuTHyFc2jdqennA=
X-Google-Smtp-Source: APXvYqwQrAvWlGaV4lRAcSeJo8xDpWLnQLRyrxu+cXhvNchTbOKNT3Jji0rwDZ/K5SRBvOH+FV7rLg==
X-Received: by 2002:a19:4344:: with SMTP id m4mr17628333lfj.71.1571066849496;
        Mon, 14 Oct 2019 08:27:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8915:: with SMTP id d21ls1857307lji.0.gmail; Mon, 14 Oct
 2019 08:27:28 -0700 (PDT)
X-Received: by 2002:a2e:750c:: with SMTP id q12mr18808596ljc.138.1571066848814;
        Mon, 14 Oct 2019 08:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571066848; cv=none;
        d=google.com; s=arc-20160816;
        b=Q99uusa9ZKLEnbAA1UqjpgzED5YwOSJKuT5zI8XgOpGAxHGOW9g2/0oO5o2xhBu7VM
         CUTFqjcW8qlMTZcKGUC5UnOVgb6lKOt3UEehfqe7ZCTEQ6ZzqQ/8nLwkM2/18YmbvyXD
         /byBvlx2zcdGcEQyYEh8hfwIi8Uh+cA7SsVlofhk8xExwm4JnDQ2UwEwh8IKLtyqDfrZ
         FnHQleEMGR6Dx31x3QmwvqI2tYb90LsE/BM/3QydFIrtG+b759O3NJm9gtvdHybSMvpb
         V0mD236+/Va6hf3tF0MgIBXtoiGM4aaj+gfwEy45pPU7LA1C7TtVBeKn3z2i0IjObpdl
         bJ4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=tvD8s3MAz5vKA8mYloT52NO0ZiIEPbiMMzSqUQ7mR9o=;
        b=YK0xRZ7qhOnzfS0GRchj5saBTHtPeKXt3Tkn3zTVFqEcXbt8i1sTU3DG5e7YsBo02Q
         q3oZuV3QHkHADCFk0pvNhLKwN8JW+puvvv/pNzWkKF3v6Hg8Ub1Q/nij0fLuFlomjz67
         Xair6d8nG8xhtKvchX8lHzP2lQa2QixLiZUYOdN0H2qothWv31zUOFU98IcWsaoj3iJM
         MonNLNk99DG/AQPtcDDD8t2EmovhHn+2YhxqZAihMr02Jn2cQpt+GkUkJyfyB7Vga4UI
         SrGFmoyTHtYuOND8WPxHv1wuNK6saaCZBaETN5CNGM08F79/8dy4nY/K7bvDWO/KscGp
         l7zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a9si748994lfk.5.2019.10.14.08.27.27
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 08:27:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 236F728;
	Mon, 14 Oct 2019 08:27:26 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 886913F68E;
	Mon, 14 Oct 2019 08:27:24 -0700 (PDT)
Date: Mon, 14 Oct 2019 16:27:17 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, x86@kernel.org, glider@google.com,
	luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com,
	christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20191014152717.GA20438@lakrids.cambridge.arm.com>
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
 <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com>
 <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Tue, Oct 15, 2019 at 12:57:44AM +1100, Daniel Axtens wrote:
> Hi Andrey,
> 
> 
> >> +	/*
> >> +	 * Ensure poisoning is visible before the shadow is made visible
> >> +	 * to other CPUs.
> >> +	 */
> >> +	smp_wmb();
> >
> > I'm not quite understand what this barrier do and why it needed.
> > And if it's really needed there should be a pairing barrier
> > on the other side which I don't see.
> 
> Mark might be better able to answer this, but my understanding is that
> we want to make sure that we never have a situation where the writes are
> reordered so that PTE is installed before all the poisioning is written
> out. I think it follows the logic in __pte_alloc() in mm/memory.c:
> 
> 	/*
> 	 * Ensure all pte setup (eg. pte page lock and page clearing) are
> 	 * visible before the pte is made visible to other CPUs by being
> 	 * put into page tables.

Yup. We need to ensure that if a thread sees a populated shadow PTE, the
corresponding shadow memory has been zeroed. Thus, we need to ensure
that the zeroing is observed by other CPUs before we update the PTE.

We're relying on the absence of a TLB entry preventing another CPU from
loading the corresponding shadow shadow memory until its PTE has been
populated (after the zeroing is visible). Consequently there is no
barrier on the other side, and just a control-dependency (which would be
insufficient on its own).

There is a potential problem here, as Will Deacon wrote up at:

  https://lore.kernel.org/linux-arm-kernel/20190827131818.14724-1-will@kernel.org/

... in the section starting:

| *** Other architecture maintainers -- start here! ***

... whereby the CPU can spuriously fault on an access after observing a
valid PTE.

For arm64 we handle the spurious fault, and it looks like x86 would need
something like its vmalloc_fault() applying to the shadow region to
cater for this.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014152717.GA20438%40lakrids.cambridge.arm.com.
