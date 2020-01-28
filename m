Return-Path: <kasan-dev+bncBCV5TUXXRUIBBS6NYHYQKGQEUAT6GMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 5328F14BE0D
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 17:52:29 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id y15sf8934923pgk.20
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 08:52:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580230347; cv=pass;
        d=google.com; s=arc-20160816;
        b=ssd8WLkDFnDT9KOzLV4zcnRhEiw31P/gCwkIVl0jxZwi8OTDs3YJKA+s+KMbGeq5cA
         ak+bbSgtn2oX3b0pn9WuIybgEux5mdh53g9/oYKYi0whuzvm6Q7Vl0ywKyOl2Fe1drDr
         b1Tzw7divHpR9Jxf5PXpUQ5jTOI5KOJMnrmG/z5/Sb33ZRkyy3eeci9DUGESu8FVzUJD
         R7pW9LsmxIYY7s/XwFBWXA0cUI5UuQNnK5o2J43C5ErBvq2BYmJVlN4kanhaqTuvN6nu
         rQ8iv2fPSPlCIahDhm1D4WLe+ODjBCWFHEC140CKmGfUToj+Ai0tGGAA2eBjpG9nPOLe
         pmOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=mbhcF/kUyoT5k+ozxjEYXaAolnTRl6Q+HX5UKNERwao=;
        b=eUpQldi4oeFLqObWE4tLFlrtsGrIQaI5JeyTpgswoM0cnOGMavkdbFJRxzxF6JAJzi
         AOTkjPBfk87L7iA4oBn8et9hB0hK87qCeqmv7wMtTkw4n3qb7N0KI4OGpEbA3vIwY27U
         p9C911vTUasMQ2SN56g/2ue3nog6nR451rm+/4QSa6DJmtCK//2mGVCfR5g0qHkDs0kI
         ZxL6cRazjZFDH4hAK6svmUXrrH7fYpQ53bOMYhsEeYFzBaWcg2dmGpPUk9+glSCNiidC
         dnuzd+32O6YpaTX/8XXm7Uu6FvPxKoLOHPTIH0pC4s6LzrCyy0UxP/lJ9d3+jWUj9Oz2
         BWYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=1VZRq8GW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mbhcF/kUyoT5k+ozxjEYXaAolnTRl6Q+HX5UKNERwao=;
        b=ZvlMpqZQDxtAfLJkFFCfdUuQJfxjBiLq8+i6n18ZZMr/r9oDG10xC+hRANr3r5uOSa
         cOQiTLImJNzwRpZMWQL2rY7BafpmeFoUMhGVJg6C17P9XWBTiNAb7wOv3qNs8hHYh7Xc
         FW3iIUyWEoZ1DrGL/kadB1HxdiiHbHTiMBPC2g22Fl8jSZoLSO9ksDTQguu4rvNk9wGy
         ZPcaU6hh6xUMvVt6HVzJMDW58VX06KNxsVj6JwDnhBt0WxOHyA5aRX6XXM+j5c2sKuQV
         47hgLYKSk13MZX8UglP4S7+sPLrUtKm6iR2A2+c2OEVLxbO8R8NoJmKXqr7AG1iQb9u3
         E2ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mbhcF/kUyoT5k+ozxjEYXaAolnTRl6Q+HX5UKNERwao=;
        b=ZTFulnqzEUDdLTQI1laW1vhvRIIYBSbagz65lZm98SUWR0wtxTH3p+vaXizRQ1tX/W
         irjQNn+8NWlxM7AAN8rxGwWucVrFp1qsFqnVU4sMFtvz+1BYA+MlWkEFIxg6Ulendz/C
         WVW0ZMYhfpd83QBNlwL5mYNAioN58fyksH9EJIaa2UnqsT8HmWWmA/kmLtTbbXhEoEcm
         Xdjvz10lPafJrOExzVLgJ+B07LYLLz8RKh8jTo6du9RqF4kKdiZP5zqNaGJTjmYoe/vs
         UeJxlTDB+QVAuFr3wgVaQgzzbuL83ZZbK1lrqq7wuHpXq96DAsxT0TBwAlDb66UUl+ut
         yf0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXXj3oQNs50DPySqJ0VTM9qru+jkrSsgU8nFnzNY4vNriV+szWh
	RCDyUr9wwYf7ym30SHvTdbY=
X-Google-Smtp-Source: APXvYqxFp3OQMNj4zdWB3Ve0hkXC6goJLkHxCFxh0OkFA3Nm7hx2BT9eBP2+szJkfggRp6HITDOIeA==
X-Received: by 2002:a17:902:b107:: with SMTP id q7mr15990763plr.343.1580230347459;
        Tue, 28 Jan 2020 08:52:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a701:: with SMTP id w1ls6052390plq.7.gmail; Tue, 28
 Jan 2020 08:52:27 -0800 (PST)
X-Received: by 2002:a17:902:5a85:: with SMTP id r5mr24253494pli.222.1580230346999;
        Tue, 28 Jan 2020 08:52:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580230346; cv=none;
        d=google.com; s=arc-20160816;
        b=eVTeL43ybFHexY1FDEROR7hCLB5uJJl0ch0vf0aDs8f03Z/wuQykH1y52nQlpL8zyU
         Z3g7KVPXCpbz02XgGNjW0zll67GqF9dM0DAH5UOEm4dY7+JakrgFsyZSY4J81/qNVmBa
         /C1AbR9aOihFhK2dg9fG1TRqQcdaWwf+rQJrZRaR8TBVYNgJI86l/SeLaehE2Cz31gNr
         hAXq3AAdn8xA5lBUUmi6jaTHyAEDrZLcD+45qwV0toCIQmCoHpDXictuK369JByiR+J3
         wCcO1tFezsGC5s4GvGC5wbVrtmHc0RuIv+46awuk7IADCe0US+lmHvghd8cjvx6oqNse
         U42w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=65hiUb5MefbH8f+PDl0IMq1gSfIHpN1RqmM1DlOSyZU=;
        b=n3/X2lkrrN4R+MZpkWxcXKQ4AvGga/TkcOiS9UwUnF4xTvS0wPYY1s+nnJkaKjwVQR
         8jgA3FU815M5AQytdhMC/cdEr0UvPjiKYL4mxhh3OEXRMBsbhNrW0UXvBRgP0nHXCpg5
         8S8zODIXHQNr1v7zB9DAIWebwTVMdlf1fJRwylwsiKzR9O4LAHBaE6UG/wKZBDMfC9J0
         p/iqi7BwbnyICZlc6/Fb3gPACj8Azn2hpXqqN54eH9tAoCYjvF8b9NUv5H35HQrXao8i
         bmUjebQK+SiwNsp4eW0Eobl+oubnqjf2FNlwWgmJWnwh5pFO18i/EBL+6mu4hHcEOxA9
         gqVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=1VZRq8GW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id 82si600647pgg.2.2020.01.28.08.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jan 2020 08:52:22 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iwU65-0001Gy-V8; Tue, 28 Jan 2020 16:52:18 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9720C306012;
	Tue, 28 Jan 2020 17:50:32 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 083A42B7159FB; Tue, 28 Jan 2020 17:52:15 +0100 (CET)
Date: Tue, 28 Jan 2020 17:52:15 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>, Will Deacon <will@kernel.org>,
	Ingo Molnar <mingo@redhat.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	"paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
Message-ID: <20200128165214.GL14914@hirez.programming.kicks-ass.net>
References: <20200122165938.GA16974@willie-the-truck>
 <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=1VZRq8GW;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jan 28, 2020 at 12:46:26PM +0100, Marco Elver wrote:
> On Tue, 28 Jan 2020 at 04:11, Qian Cai <cai@lca.pw> wrote:
> >
> > > On Jan 23, 2020, at 4:39 AM, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Wed, Jan 22, 2020 at 06:54:43PM -0500, Qian Cai wrote:
> > >> diff --git a/kernel/locking/osq_lock.c b/kernel/locking/osq_lock.c
> > >> index 1f7734949ac8..832e87966dcf 100644
> > >> --- a/kernel/locking/osq_lock.c
> > >> +++ b/kernel/locking/osq_lock.c
> > >> @@ -75,7 +75,7 @@ osq_wait_next(struct optimistic_spin_queue *lock,
> > >>                 * wait for either @lock to point to us, through its Step-B, or
> > >>                 * wait for a new @node->next from its Step-C.
> > >>                 */
> > >> -               if (node->next) {
> > >> +               if (READ_ONCE(node->next)) {
> > >>                        next = xchg(&node->next, NULL);
> > >>                        if (next)
> > >>                                break;
> > >
> > > This could possibly trigger the warning, but is a false positive. The
> > > above doesn't fix anything in that even if that load is shattered the
> > > code will function correctly -- it checks for any !0 value, any byte
> > > composite that is !0 is sufficient.
> > >
> > > This is in fact something KCSAN compiler infrastructure could deduce.
> 
> Not in the general case. As far as I can tell, this if-statement is
> purely optional and an optimization to avoid false sharing. This is
> specific knowledge about the logic that (without conveying more
> details about the logic) the tool couldn't safely deduce. Consider the
> case:
> 
> T0:
> if ( (x = READ_ONCE(ptr)) ) use_ptr_value(*x);
> 
> T1:
> WRITE_ONCE(ptr, valid_ptr);
> 
> Here, unlike the case above, reading ptr without READ_ONCE can clearly
> be dangerous.

There is a very big difference here though. In the osq case the result
of the load is only every compared to 0, after which the value is
discarded. While in your example you let the variable escape and use it
again later.

I'm claiming that in the first case, the only thing that's ever done
with a racy load is comparing against 0, there is no possible bad
outcome ever. While obviously if you let the load escape, or do anything
other than compare against 0, there is.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200128165214.GL14914%40hirez.programming.kicks-ass.net.
