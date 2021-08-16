Return-Path: <kasan-dev+bncBD6LRVPZ6YGRBY725GEAMGQENXW2E2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B88B33ED959
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 16:59:48 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id n14-20020a5d824e0000b02905b010868ff0sf5670105ioo.10
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 07:59:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629125987; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMqNE1zu3GB3uLOJewf3mPr8uxJP9mMwPNUzM8EJybZrXP4PcFrOTz5Cqm3P1y/xx5
         dBh4jYg62pU4t16XKXkQ0cXtTOqgydJirpP17voHOdID5/1naOZ+YenJtlIFXNfvLLA4
         tiBrgO6yYKLvLi9Y26I5ooFJ7w0x1JwOAiS/6qVICjHFalFh9WuMtyDMbgl9XTLNwmUK
         65vzPUy8p3VUW8xRJV+ma4JLYItlZbp5T+NMAZeVzGlAClXzMBJh7ZHnoA3dpgjGwrOQ
         VRQK+wWJFBtJPhXNiNbrVaprITPlYmFxi3Bu6Kt2b0elhoNeNH4cy7HD/qDGnMeeUCpL
         6TYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=eRbuOYsPc1ZL17g1oQ1cw6qnOoe5T3VjxahdljY1uFg=;
        b=x5dparrErVW5dA9fKN8/mLopucPVH0N6kzxPCvPmshxV61WCM9LQuLYT/sDLbCkr+t
         eyrUulGpBpXPzs3gLNTLYayaLakDTRMll9RmxWlxeuRmoVEDgi+ELZpKXH3Ohf4vf861
         rOLEtYfoCRgRy97UWvBvhYw/4L9YdcWuW184pAy6kiFFg3V/VUaV5vgPltI8uN0Z3Yt2
         uC2gyWJbc4rIKVTk+z0qVzy1eCB53RMFlyhe6Az2Dz1+DePXtA2tUJYQW5k3FVFOjlWE
         nrCE2d7PEW71zTZ9Yy5xD/UBWtQuZrdP3I75mkr3Yb/zDRTw6xHe44ALeWzB9ts4FlVj
         uILA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+6109fa88@netrider.rowland.org designates 192.131.102.5 as permitted sender) smtp.mailfrom=stern+6109fa88@netrider.rowland.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eRbuOYsPc1ZL17g1oQ1cw6qnOoe5T3VjxahdljY1uFg=;
        b=f6gpF7ltjPMjOAJSDSSyPcK19196nv5oxh9MXdBz2XWK8rq68wjDnUe+sfjrpLZN/9
         HOddJOMPqkT9ApUrb9zXf6QsLw0Z3h1ldeMg+d46gNIyxV55eFCyll4Xf+n+dGbwCkxs
         P5Ix/r26EdjPKUDCFfB3WDSjyugHKemRp3NSrtmrMREYOvEcuRBoBxlB18viHF2wLmzQ
         zrDiK/apVh0B1s+nG8VwZI68LJuRcivZjP2aBQxJIYDsDqBdqXhBcjUJ+bSadE0TYYcU
         Sdn6Bb782wiPybysb5gNetyO2F/UCnQN4jOFYedJ2c+4zJ/HATGafXZ6eo3exdqR1SC6
         +9rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eRbuOYsPc1ZL17g1oQ1cw6qnOoe5T3VjxahdljY1uFg=;
        b=EZS1ds1Fx03Etr77EJgZpHrmA53XZwrUvy+/OgnUaELo5CrJYFS8mgAAPnmlhQUwq7
         LP9fti+IffbXzhKpVJ4tVLKnZ74biuwt4C7Nk+DZdg1HZKXdN87SW4ynBPqon6k6HI60
         X/SsZaTJScKMORaQPtpPDBiOXisgZNktmg5GTEpjp0okJ6SAqkmVH+SYMXhfnTEMzD2S
         cLQbd3dWQ8GP5kRRaKQr5iJRXyw/rAonUylng0ojTTVTu0Y+893kKtiEdjPBbOfL3MTL
         Bsdvl+V1y7srmiqe6VtyXA795Dj3wuNh9KQ5rGX4l5F1KRsOMsDVT6cP+7eC8gP1+UnI
         qTSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310KBv2TD9bqCtJyGUpCJCqIHtsn75Vc/eI4G0fk4OTlYeSqOz/
	xDzTC1pXTvK3tRHHh97E9yk=
X-Google-Smtp-Source: ABdhPJxzRpvNLq+FHnzG/yPV5B7LllB4TuG6A8cieaGRhaGewQp3gu8NC/ByLVpKLFHnqq7hiO8Vpw==
X-Received: by 2002:a5e:c808:: with SMTP id y8mr13465893iol.108.1629125987556;
        Mon, 16 Aug 2021 07:59:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:94ca:: with SMTP id y10ls1342047ior.1.gmail; Mon, 16 Aug
 2021 07:59:47 -0700 (PDT)
X-Received: by 2002:a5d:9e45:: with SMTP id i5mr13190523ioi.69.1629125987149;
        Mon, 16 Aug 2021 07:59:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629125987; cv=none;
        d=google.com; s=arc-20160816;
        b=qyCF8aYk0hoLYhbY//pA2ssAFldMovsF3FIXTwLgTV4Tq7+ODYaF87Pr99TNZYMMxO
         pNgm+jkvSryz9bj/S9DtsxiMWoyNbV7jNkPIsUsqd4/ggGbwXnVL/ug9Jxr4kiVfWbn9
         0VxaFHNtDgBQ1KUt/b1LRnllsOPBDQTWLuFPl2Hjhv5yIoCxwxRQ0NVUBZi5AKA7yA+M
         3ii3C6QKJC5X1cY0RKBsOBm6X+6jz3VCoMcN9CbBSfgl9zxefCLZpSsNnfFJ3bSB/5AN
         vFAuOJ8I2tou4Ak5h9/nlEfXva6EdgMrSJHs24mrKVs6iofoHRQaj5YxHbZxsmdgXCfj
         kGWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=466uhexf3+a3aalsfbho08vk722ecuCrP97jPYiZLdI=;
        b=XEp3QrFd920IRhM0TKQQmVRKGS8Gsg+XqgeyMJFrg9YkR6pRNyo/EDacvVVI9F5GPr
         RH7yDRY94VE31RvS/aS3E7mFoY9YsuK7Deo5rHrtvEolCoUgTCAF0jvCO4P9DB3/XwUR
         OJ+xE6SBs+KcqfY7h/UF/RouQCxnGQuJjDUn1zSPOCeJrCd+nL2Vi2lTZyRA8XtK70Wr
         Hl2oHA6lHTto+6vQtzFeN69VHz/WTM9m8SdZkAKY+20kL74rG6vsVqB0cCCQ5UAI4JYl
         Ck+8RzJ7qzmXoICFPqb+o4RrvL2Oem/4hiqXZ8rka2TC1x3Ihqhsz03s+olyqyeMhWr1
         0AOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+6109fa88@netrider.rowland.org designates 192.131.102.5 as permitted sender) smtp.mailfrom=stern+6109fa88@netrider.rowland.org
Received: from netrider.rowland.org (netrider.rowland.org. [192.131.102.5])
        by gmr-mx.google.com with SMTP id y16si364389ilc.5.2021.08.16.07.59.46
        for <kasan-dev@googlegroups.com>;
        Mon, 16 Aug 2021 07:59:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of stern+6109fa88@netrider.rowland.org designates 192.131.102.5 as permitted sender) client-ip=192.131.102.5;
Received: (qmail 123487 invoked by uid 1000); 16 Aug 2021 10:59:45 -0400
Date: Mon, 16 Aug 2021 10:59:45 -0400
From: Alan Stern <stern@rowland.harvard.edu>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
  Boqun Feng <boqun.feng@gmail.com>, Andrea Parri <parri.andrea@gmail.com>,
  Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
  Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
  linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <20210816145945.GB121345@rowland.harvard.edu>
References: <YRo58c+JGOvec7tc@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YRo58c+JGOvec7tc@elver.google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: stern@rowland.harvard.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of stern+6109fa88@netrider.rowland.org designates
 192.131.102.5 as permitted sender) smtp.mailfrom=stern+6109fa88@netrider.rowland.org
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

On Mon, Aug 16, 2021 at 12:12:01PM +0200, Marco Elver wrote:
> Hello,
> 
> Commit c58a801701693 added a paragraph to the LKMM:
> 
> 	+Although we said that plain accesses are not linked by the ppo
> 	+relation, they do contribute to it indirectly.  Namely, when there is
> 	+an address dependency from a marked load R to a plain store W,
> 	+followed by smp_wmb() and then a marked store W', the LKMM creates a
> 	+ppo link from R to W'.
> 
> Defining that certain _marked reads_ will also be ordered by smp_wmb().
> But otherwise, other reads (especially plain reads!) will _never_ be
> ordered by smp_wmb(). Is my understanding correct?

The ordering is indirect, but yes.

> I am asking because KCSAN is growing limited support for weak memory
> modeling and memory barriers, and I'm trying to figure out if I'm seeing
> a false positive or genuinely allowed race.
> 
> One caveat is the case I'm trying to understand doesn't involve just 2
> CPUs but also a device. And for now, I'm assuming that dma_wmb() is as
> strong as smp_wmb() also wrt other CPUs (but my guess is this
> assumption is already too strong).

I'm not sure that is right.  dma_wmb affects the visibility of writes to 
a DMA buffer from the point of view of the device, not necessarily from 
the point of view of other CPUs.  At least, there doesn't seem to be any 
claim in memory-barriers.txt that it does so.

> The whole area of the memory model that includes talking to devices and
> devices talking back to CPUs seems quite murky, and need to confirm that
> I either got it right or wrong. :-)

The LKMM itself doesn't include anything about device I/O.  So you're 
already going beyond the known limits.  :-)

...

> KCSAN is saying there is a potential use-after-free read of an skb due
> to the read to 0xffff8880077b5570 potentially being delayed/reordered
> later. If the memory was reallocated and reused concurrently, the read
> could read garbage data:
> 
> 1.	The e1000 driver is being instructed to transmit in
> 	e1000_xmit_frame(). Here it uses the data in the skb in various
> 	places (e.g. in skb_headlen() above) to set up a new element in
> 	the ring buffer to be consumed by the device via DMA.

You mean here the driver reads some stuff from the skb, right?  And 
various writes depend on the data that was read, but these dependencies 
aren't evident to the memory model because they all involve plain 
accesses.

> 2.	Eventually it calls e1000_tx_queue(), which seems to publish the
> 	next entry into the ring buffer and finally calls dma_wmb().
> 	Until this point I see no other barriers (although there's a
> 	writel(), but it doesn't always seem to be called).

And potentially those reads from above could be delayed (or repeated) 
after this point.

But you're missing something.  What matters isn't the dma_wmb.  Rather, 
it's the call which transfers ownership of the buffer to the device.  
That call must certainly include its own memory barrier, meaning that 
the reads must complete before the call returns.  We don't depend on a 
dma_wmb which might or might not be present to enforce this ordering.

Unless this buffer mapping is supposed to be coherent, of course, in 
which case there would be no ownership transfers.

> 3.	e1000_clean_tx_irq() is called on another CPU after transmit
> 	completes, and we know the device has consumed that entry from
> 	the ring buffer. At this point the driver then says that the
> 	associated skb can be kfree()'d.
> 
> 4.	If I interpreted dma_wmb() (and smp_wmb()) right, plain reads
> 	may be reordered after it, irrespective if a write that depended
> 	on such reads was ordered by the wmb(). Which means the
> 	reordering of the plain reads accessing the skb before it may in
> 	fact happen concurrently with the kfree() of skb if reordered
> 	after. For example reordered to the very end of
> 	e1000_xmit_frame() (line 3282) as KCSAN simulated in this case.
> 
> Is the above result allowed by the kernel's memory model?

This can't happen, for the reason explained above, if the buffer is 
non-coherent.  But if the DMA mapping is coherent, this does sound like 
a bug.

> In practice, my guess is no compiler and architecture combination would
> allow this today; or is there an arch where it could?

Probably not; reordering of reads tends to take place over time 
scales a lot shorter than lengthy I/O operations.

Alan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210816145945.GB121345%40rowland.harvard.edu.
