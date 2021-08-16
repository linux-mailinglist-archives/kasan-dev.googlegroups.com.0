Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL565KEAMGQEDCQXXRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 134C53EDC58
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 19:24:00 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id q9-20020a2e9689000000b001b964fa10b3sf2188669lji.18
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 10:24:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629134639; cv=pass;
        d=google.com; s=arc-20160816;
        b=emYg1ep56WR4I/pkL0ldVjFCF4OCgwE1Jh+dVJQlDm+djattL8+R8eJP3/d4vxIF4S
         CtqmkdSZzHqcgDldWGMSS9lgRBy2ZEs7EMV+w6i34k3P8mBLYZdMW5omR34Llb97YTv7
         2oJK3LonXeNbTIS0MGcjILc5WL/7VXChUroeqgKTAuvPnwyK24YNeWeCZnzDlDWSrcgH
         20dJByCrodc5bURbOBU3Msav3lia8cXGtW/Bx6GnbOAlxWipqa8pB48rpF4y2h0COZPf
         nT2V6DeQS3RLrxWf/ZWi7UAHwjSLIlRELn73bVAjCwLiJ7FQJmVqFCKZsxF1b6EgrAWQ
         HHLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ZVhMcYeNSNL8RoJOeq3hdCAs3O2joOSDOZFJtk1Mjaw=;
        b=zY+cp7RQGf5Hqw2UNxJPPbjKofS4+4/zarOiIMBplS7JEuISwhlbHUDNLcOtu8qqSh
         J3Ppgtmst8aea9u/KyvUYx923UQ/T6wRdV/vR7UbOK4IQr/AZ4HwAFXqYF3fQxCR4soM
         YWNXClo5g1GRRZ7mwosqqkpWBQVgWLpYPyQ2PHB/CXvtq2dwyWUjaWjViJOKK7nG4Mui
         aY1xt8mOm5bJAdaMkf7bcN7gDF/NMCWwixH3nDjy0EsPU6xtwofYTUbL5kmroS7dbMWF
         swYmKpEbsPBTzhtOQua2i3OLWBtiML8B+mpjPXTbwCvV8NljpQuAVyc2yAk7QvNV2X95
         5X+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EnEZK2cQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZVhMcYeNSNL8RoJOeq3hdCAs3O2joOSDOZFJtk1Mjaw=;
        b=a8HSzIeiVP0mXWIdX4o8QUMh5+BxxwcWrlhLAFhE/+RbuRMZWP0Yx7FOS25YsO6/dz
         XTTcb6xX0AVlfENCCZmfUepnAoApOcSjIPsTpsFzZ2OhQA8MesvYxiXG237MziM1Rgop
         kMvJhxHyZLUYQDGYd8de6pNzPLqBvYvRjyPH/uEUETOqNEGE5tawnxfKYIsJI/vUg/Ta
         dUBfzPqoC2ZZn0tva1g92OWGrr8+574nT7IYclviEZhCzSu3G7TxaDstHCQFtnkEMb6C
         maVIAe67emM12wygxMyhY7cVnqyCc3jDjFxhNGD/Gr2j5cXtIaw/qdZjTCwt+0A6EKCn
         UD2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZVhMcYeNSNL8RoJOeq3hdCAs3O2joOSDOZFJtk1Mjaw=;
        b=m7SrGkUTqXjgqTzkEi4GihjnJ7Lg+g6zRRdiD0UmjfDIJciS6WPJ84SmC6I+cswq/w
         h6FYAMkPWa4PBm5J/LzM/uXGjM0nMN2KtyV0oGqGJQdqzdpfzpFFqhXUQPOH9g9TaHlQ
         vjhW2S/CucwsD6sS6Gu7FUqJOnk2R/TYy7Sej4v/M7x+z7zOyp3BqMh6hS1rhJYqBJcV
         IJW0bFX7EUP5gY0PGg7TY5u/yz8kH0ahOq/Bq4BzHNca0XSja6M5AJHl5ktt6nTsuLz2
         slvh3DRqp+06GbM2h+yhEuUXFDoieSNfE77g01bhWwS+7UaqJeDr4e4ubZqeSOD0X8GM
         Rcjw==
X-Gm-Message-State: AOAM531/PBsD05kgnUPp57LyQKQJSsrv3FJxd+pL0jJyEtNdkLq0YLmQ
	WR+ubDw5G11I1+vJTxQEHcU=
X-Google-Smtp-Source: ABdhPJxfP4SYbfwSVG0oO2G2Y22TnNoUzBTu8EhWqWONfsl8Ookvt32HW81taci14Iphyhddygmt6A==
X-Received: by 2002:a2e:a275:: with SMTP id k21mr9302033ljm.228.1629134639608;
        Mon, 16 Aug 2021 10:23:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8652:: with SMTP id i18ls505555ljj.1.gmail; Mon, 16 Aug
 2021 10:23:58 -0700 (PDT)
X-Received: by 2002:a2e:8504:: with SMTP id j4mr11128502lji.352.1629134638474;
        Mon, 16 Aug 2021 10:23:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629134638; cv=none;
        d=google.com; s=arc-20160816;
        b=H7k4omh1cbQS5KADpT/BbFjzLeR4efZvgkc768Jf+F/MjlBElonUhs2XS8H7yhSTGy
         o6mUmj1SvuXlFHef93QEG/Eq2ewTfbO21uWD2dcTkARd1zJR6SNnHvPPGsY58y0IEhHe
         JMQXUU/LgiY2TEmzkRRfDAcYryU74zixHvZ8N9/QEO2c4J+GtPWQJt4ovZrxZctFgGRf
         7HJdt56HXTLXw8oBnHS9Y/QGfKdLf8OcXikzYM5HdKmBsXc2drpphkKmIa8B38s32DuB
         TgCpYJykVwgWDzfTd1kZETVUawhQsWg7mdv+gg/fUt0cAYLY/o+NXJ3yTuAw+/DlWAlz
         sURA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Q4xb7GT62H6SH9N7ILRbjnxbiy5piEQLOJSGos0eCQo=;
        b=RAK8InVipFThn9IWnOUsjvw9AmUyFRrIVA7oua+YNob2VfhBngKYInSPowmDTh93KD
         RavZpAuxqcwYT4CUra/LAa3z1mVXuz0j1DZo0A0lOLpJ7dRDfuztVnBvFLRGcxSOxcJE
         bJONzWnakmPa2viQdxal1DmWdD5+fczagx79Kb4q7HxTsZT5cgeW4HP+uFAMZp89heUU
         10MVIabZkz1E3Grag07RjvKKcg6cOQ/zLRaZaETTpgPq02apPQxUCOGpyiDzpVcABOdF
         yKjJkUZ7txNuu+WEszy9cxoUt7/dTAls20isKUHVQ+W1UmSTGNjsYJpyfx244oZ8AP0v
         1NSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EnEZK2cQ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id h11si610739lfc.4.2021.08.16.10.23.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Aug 2021 10:23:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id r7so24788645wrs.0
        for <kasan-dev@googlegroups.com>; Mon, 16 Aug 2021 10:23:58 -0700 (PDT)
X-Received: by 2002:a5d:4ec5:: with SMTP id s5mr12809049wrv.267.1629134637607;
        Mon, 16 Aug 2021 10:23:57 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:4ab8:21c4:bd1f:eac2])
        by smtp.gmail.com with ESMTPSA id p4sm14175973wrq.81.2021.08.16.10.23.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Aug 2021 10:23:57 -0700 (PDT)
Date: Mon, 16 Aug 2021 19:23:51 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alan Stern <stern@rowland.harvard.edu>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <YRqfJz/lpUaZpxq7@elver.google.com>
References: <YRo58c+JGOvec7tc@elver.google.com>
 <20210816145945.GB121345@rowland.harvard.edu>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210816145945.GB121345@rowland.harvard.edu>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EnEZK2cQ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Aug 16, 2021 at 10:59AM -0400, Alan Stern wrote:
[...]
> > One caveat is the case I'm trying to understand doesn't involve just 2
> > CPUs but also a device. And for now, I'm assuming that dma_wmb() is as
> > strong as smp_wmb() also wrt other CPUs (but my guess is this
> > assumption is already too strong).
> 
> I'm not sure that is right.  dma_wmb affects the visibility of writes to 
> a DMA buffer from the point of view of the device, not necessarily from 
> the point of view of other CPUs.  At least, there doesn't seem to be any 
> claim in memory-barriers.txt that it does so.

Thanks, I thought so.

While I could just not instrument dma_*mb() at all, because KCSAN
obviously can't instrument what devices do, I wonder if the resulting
reports are at all interesting.

For example, if I do not make the assumption that dma_wmb==smp_smb, and
don't instrument dma_*mb() at all, I also get racy UAF reordered writes:
I could imagine some architecture where dma_wmb() propagates the write
to devices from CPU 0; but CPU 1 then does the kfree(), reallocates,
reuses the data, but then gets its data overwritten by CPU 0.

What would be more useful?

1. Let the architecture decide how they want KCSAN to instrument non-smp
   barriers, given it's underspecified. This means KCSAN would report
   different races on different architectures, but keep the noise down.

2. Assume the weakest possible model, where non-smp barriers just do
   nothing wrt other CPUs.

> > The whole area of the memory model that includes talking to devices and
> > devices talking back to CPUs seems quite murky, and need to confirm that
> > I either got it right or wrong. :-)
> 
> The LKMM itself doesn't include anything about device I/O.  So you're 
> already going beyond the known limits.  :-)
> 
> ...
> 
> > KCSAN is saying there is a potential use-after-free read of an skb due
> > to the read to 0xffff8880077b5570 potentially being delayed/reordered
> > later. If the memory was reallocated and reused concurrently, the read
> > could read garbage data:
> > 
> > 1.	The e1000 driver is being instructed to transmit in
> > 	e1000_xmit_frame(). Here it uses the data in the skb in various
> > 	places (e.g. in skb_headlen() above) to set up a new element in
> > 	the ring buffer to be consumed by the device via DMA.
> 
> You mean here the driver reads some stuff from the skb, right?  And 
> various writes depend on the data that was read, but these dependencies 
> aren't evident to the memory model because they all involve plain 
> accesses.

Yes, correct.

> > 2.	Eventually it calls e1000_tx_queue(), which seems to publish the
> > 	next entry into the ring buffer and finally calls dma_wmb().
> > 	Until this point I see no other barriers (although there's a
> > 	writel(), but it doesn't always seem to be called).
> 
> And potentially those reads from above could be delayed (or repeated) 
> after this point.
> 
> But you're missing something.  What matters isn't the dma_wmb.  Rather, 
> it's the call which transfers ownership of the buffer to the device.  
> That call must certainly include its own memory barrier, meaning that 
> the reads must complete before the call returns.  We don't depend on a 
> dma_wmb which might or might not be present to enforce this ordering.
> 
> Unless this buffer mapping is supposed to be coherent, of course, in 
> which case there would be no ownership transfers.

I think it's coherent:

	txdr->desc = dma_alloc_coherent(&pdev->dev, txdr->size, &txdr->dma,
					GFP_KERNEL);

and then in:

	static void e1000_tx_queue(...)
	{
		... writes to desc ...
		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		dma_wmb();
		tx_ring->next_to_use = i;
	}

used by

	static netdev_tx_t e1000_xmit_frame(...)
	{
		...
		e1000_tx_queue(..., tx_ring, ...);
		...
		if (!netdev_xmit_more() ||
		    netif_xmit_stopped(netdev_get_tx_queue(netdev, 0))) {
			writel(tx_ring->next_to_use, hw->hw_addr + tx_ring->tdt);
		}
		...
	}

My best guess: as long as the device is fetching from the ring, the
driver can just append to it and does not do the writel().

> > 3.	e1000_clean_tx_irq() is called on another CPU after transmit
> > 	completes, and we know the device has consumed that entry from
> > 	the ring buffer. At this point the driver then says that the
> > 	associated skb can be kfree()'d.
> > 
> > 4.	If I interpreted dma_wmb() (and smp_wmb()) right, plain reads
> > 	may be reordered after it, irrespective if a write that depended
> > 	on such reads was ordered by the wmb(). Which means the
> > 	reordering of the plain reads accessing the skb before it may in
> > 	fact happen concurrently with the kfree() of skb if reordered
> > 	after. For example reordered to the very end of
> > 	e1000_xmit_frame() (line 3282) as KCSAN simulated in this case.
> > 
> > Is the above result allowed by the kernel's memory model?
> 
> This can't happen, for the reason explained above, if the buffer is 
> non-coherent.  But if the DMA mapping is coherent, this does sound like 
> a bug.

Makes sense.

> > In practice, my guess is no compiler and architecture combination would
> > allow this today; or is there an arch where it could?
> 
> Probably not; reordering of reads tends to take place over time 
> scales a lot shorter than lengthy I/O operations.

Which might be an argument to make KCSAN's non-smp barrier
instrumentation arch-dependent, because some drivers might in fact be
written with some target architectures and their properties in mind. At
least it would help keep the noise down, and those architecture that
want to see such races certainly still could.

Any preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YRqfJz/lpUaZpxq7%40elver.google.com.
