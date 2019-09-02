Return-Path: <kasan-dev+bncBDV37XP3XYDRBQW2WTVQKGQEMJ4TZBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FB63A59E2
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 16:54:58 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id m81sf322965lje.4
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 07:54:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567436098; cv=pass;
        d=google.com; s=arc-20160816;
        b=AhRBHCDn0f7hKLWWj8bbVuYqnVhFlgD3G3XEdrH0VRpx0iVO7MKLnjaKh5wY32gFGT
         Auo9iWtuu3SJ4aCvmjmPX6pq5KwtEMatDZx478+1MFIMAjQHtV6DETnIlk9tuFgJMRXi
         jY+8tHRLIDQ637CB7jI+1m6d723okpDlnARHRkoCJNp05miEe/COemr9Z/E2C/KSmarS
         FEV0Axcw5iJXOMYigbdJrOb4XnukkNgHl8HF2Y1GHHLuKa5xisfA5cYE4lFy3NpdRFuF
         rzkx69W1I/8RZgFOQTFX9QGTSJ9sQgRZIJ0ihaKqKMR1W2bw/VOTtMwPqPI84h1LjEqE
         sSXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=v8rja5g8Z4ZoHBlC4nJZvc5pXYMi8tGP/WYEaRO8e10=;
        b=zfHGctRfAXSfiW4mzNwrRAKxQxsXYffi+e1KOC3X1jJGCjY5kk5VSMnnZn32+v8lrJ
         fDV9yhGx/0zrThNUuL0JMLgm9H6hEoDdGZ7xBx6LQa96bgiMm4RW2urUzkl2YaFcj1xo
         o1Wpeap7WpzHRmNNNE+1+jd0ExkESzGD8Q2tLCxIpMJoDHnrPvBiSbHvLxMkg9EGmxoL
         /1TGpOuO9QjW3U4ueANKFcAkfjQ7TaquiCJTsR9dQPHoovnsWcwMl3nPYAd8H7oeOX2+
         4NXgh13s0tcJ7EHQmYhdDrI1YRz6b6YVh70/Vg+1T3ICb1HYQwyhHv3PMzZJCSRQ0HW5
         HlmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=v8rja5g8Z4ZoHBlC4nJZvc5pXYMi8tGP/WYEaRO8e10=;
        b=Y9zFbDNxjl7tyXJPdfmR3go/VQ0tifI3vEs3fiXE4eje1pzi1MP7A6eM8xdy5zKe5m
         bgktmTgNO11FC7Yfxd9++HK4GP1OrC8o5sZqPldcSifZnbAnbVLaQ9aNj+ythAmSnS5S
         rvs9qA8gqqphMeizJu9rQZG8VNUfwy3wJ2NXQaPA7PSrIrdSO0fRCHs1nK+OFQTDxUYU
         VPsorbch6czk1JRx7bM/ZwwBl6vHRZEIWjXIQtN6jKn7FQ0aRkbRskaJpAE3eRkaYpjN
         7BYIog8hYyYpwhBJ0//RtHF+7k5dQ4aFeHkS6TyCX2egWWZXpS9/ko4bjzqZ81Q9/Igf
         8MiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=v8rja5g8Z4ZoHBlC4nJZvc5pXYMi8tGP/WYEaRO8e10=;
        b=Zjg993jheuEEzJ0sxY2RedNhTvFW3Hk7CR6RSSUxL0szkNIK5jMXzvKhmI+CJ5mWgr
         ciAhLphShkB0zr/LusnjIAWb74JULRgp9YSXI3e3p7TqJfwtOsDhVsqLuCvnFJbRFpkp
         pK5BCqDyAN0xsll9+0PyeV5TDL0UENahT0URnzZDP46FV1hTkKjEmE6IhYA/lpI1t9Vx
         oXPR7Esi33bGdCdY2tqH1Q5QfLYqfL/MQh/GkUJdfzSqX0/woBlfh6vrY+NgdghvEL1b
         m3PQ4F+UoPPJWcHtP+35aArxWN89na8E+OnFSqeajmdSz7KWb5BxN7Ap5v4QlpfLU9BK
         Veow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVWlxozc1XZAa+Ip97Qvf3oVpTvWuVAy6wFJ6hLLIt2n8xqFFVj
	qLCgZETiY4Y8VK5tMc4o7AQ=
X-Google-Smtp-Source: APXvYqwB3KRnDDo7gJPuNZMLGk/FI2u1kWLZeQLPvu9Z3viXTlQv3CSh0EILJ+50NyNS4txVTDffZQ==
X-Received: by 2002:a2e:8051:: with SMTP id p17mr2795275ljg.222.1567436098204;
        Mon, 02 Sep 2019 07:54:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8586:: with SMTP id b6ls750976lji.12.gmail; Mon, 02 Sep
 2019 07:54:57 -0700 (PDT)
X-Received: by 2002:a2e:90c7:: with SMTP id o7mr2514457ljg.73.1567436097561;
        Mon, 02 Sep 2019 07:54:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567436097; cv=none;
        d=google.com; s=arc-20160816;
        b=b4D3njNwrVBkzn9znQ88ofg05mOUwiT+5tl7mDv2G0UNgz85D+wn4hI4tdhz5JlZ0h
         OnKJgmH6KHyNtfnaPHpj4JX8clloYwvkFSRuyCD6Q/Xmcn9ibR2dYt2VYQi6Ls85heLy
         4nlpxhvHmgXuOq8HVKtQ8sjCmhbxmyl8xdFsrj23YX1CzODMHCvm0J0GyCV8ky/abjq3
         cUXVgYyrldEVAqY53IOJ+OlcG0fWYWgjlR9t7ZZE6ncNrSNnJba0ogZl6dRBK9VTBnao
         5UrWHzr86UMtXw0TijYC8z9P/DpS/O8TvSTk9/BwxTSLeuCufrNXGmdhakU5XTzuPnMi
         WwTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=l3v8JxhnbPn430uqw6/VpTRs5JgoYuKp+Z8MgqbDlkg=;
        b=LENMqSulVRGaN68rFSiOn7PNxGRG9jbn+6aBYLHDlOOyth/fLbpl0ccgYo4Ky0NsQC
         OkSGQpuBaGZ1FotM/65MBGieT8lC26MXg6difCZBQSSB50EdP6OvaCggMdzYkM09kqXH
         KEfNgBHoGsHb6xEqE0PzZGW0riEmHRhQOfjPy5qoevyBbuTwsGcyHuRhSYF/GNxJIwbP
         ZbQM0yCpBdI9RF85Vaexw4r5enAaJH9Yx49w+WG1xnEotP/345Hb0q6sGxqfEDBjMoVe
         nOIQykNJWcTWB6w+CzbsjZLytbNaySzWrCyDHomBiCYj/QkLQ1vuQ92DZjXELw2PLbrv
         r8NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c8si312262lfm.4.2019.09.02.07.54.56
        for <kasan-dev@googlegroups.com>;
        Mon, 02 Sep 2019 07:54:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B66DF344;
	Mon,  2 Sep 2019 07:54:55 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2BC303F59C;
	Mon,  2 Sep 2019 07:54:54 -0700 (PDT)
Date: Mon, 2 Sep 2019 15:54:45 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org,
	aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org,
	linux-kernel@vger.kernel.org, dvyukov@google.com,
	christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com
Subject: Re: [PATCH v6 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20190902145445.GA12400@lakrids.cambridge.arm.com>
References: <20190902112028.23773-1-dja@axtens.net>
 <20190902112028.23773-2-dja@axtens.net>
 <20190902132220.GA9922@lakrids.cambridge.arm.com>
 <87pnkiu5ta.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87pnkiu5ta.fsf@dja-thinkpad.axtens.net>
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

On Tue, Sep 03, 2019 at 12:32:49AM +1000, Daniel Axtens wrote:
> Hi Mark,
> 
> >> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> >> +					void *unused)
> >> +{
> >> +	unsigned long page;
> >> +
> >> +	page = (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> >> +
> >> +	spin_lock(&init_mm.page_table_lock);
> >> +
> >> +	if (likely(!pte_none(*ptep))) {
> >> +		pte_clear(&init_mm, addr, ptep);
> >> +		free_page(page);
> >> +	}
> >> +	spin_unlock(&init_mm.page_table_lock);
> >> +
> >> +	return 0;
> >> +}
> >
> > There needs to be TLB maintenance after unmapping the page, but I don't
> > see that happening below.
> >
> > We need that to ensure that errant accesses don't hit the page we're
> > freeing and that new mappings at the same VA don't cause a TLB conflict
> > or TLB amalgamation issue.
> 
> Darn it, I knew there was something I forgot to do! I thought of that
> over the weekend, didn't write it down, and then forgot it when I went
> to respin the patches. You're totally right.
> 
> >
> >> +/*
> >> + * Release the backing for the vmalloc region [start, end), which
> >> + * lies within the free region [free_region_start, free_region_end).
> >> + *
> >> + * This can be run lazily, long after the region was freed. It runs
> >> + * under vmap_area_lock, so it's not safe to interact with the vmalloc/vmap
> >> + * infrastructure.
> >> + */
> >
> > IIUC we aim to only free non-shared shadow by aligning the start
> > upwards, and aligning the end downwards. I think it would be worth
> > mentioning that explicitly in the comment since otherwise it's not
> > obvious how we handle races between alloc/free.
> >
> 
> Oh, I will need to think through that more carefully.
> 
> I think the vmap_area_lock protects us against alloc/free races.

AFAICT, on the alloc side we only hold the vmap_area_lock while
allocating the area in __get_vm_area_node(), but we don't holding the
vmap_area_lock while we populate the page tables for the shadow in
kasan_populate_vmalloc().

So I believe that kasan_populate_vmalloc() can race with
kasan_release_vmalloc().

> I think alignment operates at least somewhat as you've described, and
> while it is important for correctness, I'm not sure I'd say it
> prevented races? I will double check my understanding of
> vmap_area_lock, and I agree the comment needs to be much clearer.

I had assumed that you were trying to only free pages which were
definitely not shared (for which there couldn't possibly be a race to
allocate), by looking at the sibling areas to see if they potentially
overlapped.

Was that not the case?

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902145445.GA12400%40lakrids.cambridge.arm.com.
