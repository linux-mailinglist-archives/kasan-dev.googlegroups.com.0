Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6PT5CEAMGQE7ABL6IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E9F03ED1B3
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 12:12:10 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id e4-20020a05651c0904b029018bc821fd31sf5767086ljq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Aug 2021 03:12:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629108729; cv=pass;
        d=google.com; s=arc-20160816;
        b=NEk1LzZyETPPXihKJJNFd12rvs7d/hz5f1jRBgUeY03hw+4Ah2VZs9UF0QNMSOnwCi
         tFWozdtrbDTQtECFkFs8uPbqPx4Uy5AFXVEv/ZnEVtKRkz288YDvFLM7mWJWYNtg6rZn
         ozKe7K6fqXPj8Frvv1yxBi6dmAF9nyvjpLBerHHjopWLEu+I13i7XsE83+87dMJx1GvY
         U9En2m5a1QJdkBVVpgsXLz0s8XuBGONfnSNg7VBV4o0ZAy3RD7aZZ5DEwPuDFnEw2GqH
         tUF+lYbV+b7wloHmeJJNi9Soui7u/pK3lNyhYhzKsQ2iDjJyWbFlHt52JyIsxtPdLqrO
         vb3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KQz4L3eneMpL//YVKtxSE+AB1FKu17uQXyPd5+cYqoQ=;
        b=Rlc4fwj82BnjILB9cRgiP2c/eQz5MJ+VmEFGx343hXGWVdbJ75KYhKVYS8p57XVUpW
         wSoPaH0RdPDsfEcwocVT+/2stqoikzYWOLCYa6QWPJBA/zAB6x1cy/nJE6YTuiVgBLZL
         VsVVwr/nWTjW9XZ4W5QOUuxDKfy+6pFhFthE4861iZ/gxuKWIry0sEHp8sXhFvGCKGlO
         6LVwLdeclKzSdbGU8JNVwlBBtoGMQu4GER9MXAoj0+aXtVKw7+9x/i6BIp28ctaGPHu5
         JVjxP61L9GKiFEzmBPdoXmBbV3Vz6GVl2JMpDdf7wYepYcNL/Raq37zkHSUex0bOjU4f
         qFDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r4q56nvx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KQz4L3eneMpL//YVKtxSE+AB1FKu17uQXyPd5+cYqoQ=;
        b=RhnZNre1AEnjiqskOy6g/ZwoEfLnO0CN59JPWwk6ixqNwdFco7iuHnpYUFwcb1Gu9I
         FzqLAdAh3edWaVirE1L19zDzbiUz64xKrYpdfrlSsuPttKX+v7Su+VA6G37XcL/f7/LC
         818dkNNhHGmKoKGCXjgtXfGP3wYovJC1d6eoIu3NPFt/zxq7JE9O9stRtbYdt8yZr+Tw
         bBw5CiLdzySR2pVyORTXUglL7DXrntAI9EYpCMRzYiLnih5Pa48Cpu/zdF6gJPhdavvH
         MXu36SJIVkV0UdyMBxAySYHTYU+KwvUP0zhF+OLqKWBMJ2uf6DyWm+zFdP7sJZC2l2TG
         5ASQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KQz4L3eneMpL//YVKtxSE+AB1FKu17uQXyPd5+cYqoQ=;
        b=K0qIZ7uOS9UhN8QvaoKoIJFz09T0YSmXFGCmZ1SDUpqifg0yxL4BnPz0GK+ji5fjFb
         Mz+RNaX1NJU3wyc/tBFCPKQ9rSks50eD9JMmmocda6/GiqK2GJPZmQ+3hjWeQM9gkl6M
         o72RA3SHEW4I11j1pttlNhu1bUs2/etcbxgcoXgLmOM56AmuZSKbtJTLQB6D5cXrxO5F
         3K66W1MWhm+Em5snwbPymXwEOTrRouGY75Ut7mpVLfpFb7C9wxaJ6dDs0C522zG4m3r7
         cB6R7KfeJ3+AKKqmCTnJbsWS2eSdEibLd5HoCawSsAi38d38db49aNxXfeT/T4yb5ruK
         +4IQ==
X-Gm-Message-State: AOAM5309LwL5H1BSNBkf5G0kr9lTFAgTbUzh4B3DyBcoCiHeIwA3IHzF
	+Pk8edrwvHuSmUiFc+gM7xs=
X-Google-Smtp-Source: ABdhPJyT4ne5vebHCxWc3sCnz1i7E9jYfjjqi5Z7X024TJnFweH5Kw9SGJwQl4TtYO/aBnnzcwzFRw==
X-Received: by 2002:a05:651c:1064:: with SMTP id y4mr10609968ljm.74.1629108729714;
        Mon, 16 Aug 2021 03:12:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b24:: with SMTP id w36ls734749lfu.1.gmail; Mon, 16
 Aug 2021 03:12:08 -0700 (PDT)
X-Received: by 2002:a05:6512:2291:: with SMTP id f17mr11133805lfu.593.1629108728552;
        Mon, 16 Aug 2021 03:12:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629108728; cv=none;
        d=google.com; s=arc-20160816;
        b=WU7UVOvEj8ZPG9L3jzGyblsvbLxlI1HZ2VkcVZZ7i1vdhDjQmASKmkFlfDWYU71GkX
         spEklw/Qixgcg2zG18CBaU5zpt17uZvpSGhtDD1L+W4Y2ffiOIBUQs1vrvjaeKto4up9
         oVaS8ZANQjSU0XVcT2OeMaHdLhnMFhAB+6kX2FQO0Z6bsgGePnPerzQGOaQ30maXOtaU
         OBm0JQnPs2nSuq4MRMzVnQKX6b95/oHdPkwwEAS6scDZrc2JBRY/jL7idvXrfif4QqDy
         tvtE58pLKBDbkIQwtKWyW/eV5qNuqZ4Rr8DRxmrh+bTc/ZZkM9DNCsiOpu/9oquMfmzL
         X4lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/Xw0w3UumgW2mMQhotzUeGKDXtTAf814g5ImZXZMSUU=;
        b=cDuN7nZ202jWfZPhq0hQVHGy2W793NeNH6adi3j47NAspbWkYuCZvlCncZ/SLSDxYG
         01w5t+bXCrc1ToPTAhPs3Jgs7b3rsVJCKUajkbCEVxAUDqjfm7ppqUzvy6YsTBUdS3xY
         DRldGv2aCxMO/DFt44oHFuAxwGEZJH5t6MKFZJdMbcWYGX3TAepkbukNJL6bEZAhUJmn
         A5m9yZohetDDw8/sCgWhhVXIwoUFewP3EnsWMUqbv4nQVuDKFTTMq5qyanCpV7ilaTzF
         TTwr3ltNH2DFdtdtiGc8TjRggTxrSYmR+QRx+dvbKiFhS5i38erWCDtTkXc7opefdhbz
         whow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r4q56nvx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id j7si584669ljc.1.2021.08.16.03.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Aug 2021 03:12:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id q10so22803384wro.2
        for <kasan-dev@googlegroups.com>; Mon, 16 Aug 2021 03:12:08 -0700 (PDT)
X-Received: by 2002:adf:e507:: with SMTP id j7mr18100703wrm.113.1629108727841;
        Mon, 16 Aug 2021 03:12:07 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:4ab8:21c4:bd1f:eac2])
        by smtp.gmail.com with ESMTPSA id q17sm10702152wrr.91.2021.08.16.03.12.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 16 Aug 2021 03:12:07 -0700 (PDT)
Date: Mon, 16 Aug 2021 12:12:01 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Andrea Parri <parri.andrea@gmail.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: LKMM: Read dependencies of writes ordered by dma_wmb()?
Message-ID: <YRo58c+JGOvec7tc@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r4q56nvx;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::436 as
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

Hello,

Commit c58a801701693 added a paragraph to the LKMM:

	+Although we said that plain accesses are not linked by the ppo
	+relation, they do contribute to it indirectly.  Namely, when there is
	+an address dependency from a marked load R to a plain store W,
	+followed by smp_wmb() and then a marked store W', the LKMM creates a
	+ppo link from R to W'.

Defining that certain _marked reads_ will also be ordered by smp_wmb().
But otherwise, other reads (especially plain reads!) will _never_ be
ordered by smp_wmb(). Is my understanding correct?

I am asking because KCSAN is growing limited support for weak memory
modeling and memory barriers, and I'm trying to figure out if I'm seeing
a false positive or genuinely allowed race.

One caveat is the case I'm trying to understand doesn't involve just 2
CPUs but also a device. And for now, I'm assuming that dma_wmb() is as
strong as smp_wmb() also wrt other CPUs (but my guess is this
assumption is already too strong).

The whole area of the memory model that includes talking to devices and
devices talking back to CPUs seems quite murky, and need to confirm that
I either got it right or wrong. :-)

The report (explained below):

| assert no accesses to 0xffff8880077b5500 of 232 bytes by interrupt on cpu 1:
|  __cache_free mm/slab.c:3450 [inline]
|  kmem_cache_free+0x4b/0xe0 mm/slab.c:3740
|  kfree_skbmem net/core/skbuff.c:709 [inline]
|  __kfree_skb+0x145/0x190 net/core/skbuff.c:745
|  consume_skb+0x6d/0x190 net/core/skbuff.c:900
|  __dev_kfree_skb_any+0xb8/0xc0 net/core/dev.c:3195
|  dev_kfree_skb_any include/linux/netdevice.h:3979 [inline]
|  e1000_unmap_and_free_tx_resource drivers/net/ethernet/intel/e1000/e1000_main.c:1969 [inline]
|  e1000_clean_tx_irq drivers/net/ethernet/intel/e1000/e1000_main.c:3859 [inline]
|  e1000_clean+0x302/0x2080 drivers/net/ethernet/intel/e1000/e1000_main.c:3800
|  __napi_poll+0x81/0x430 net/core/dev.c:7019
|  napi_poll net/core/dev.c:7086 [inline]
|  net_rx_action+0x2cf/0x6b0 net/core/dev.c:7173
|  __do_softirq+0x12c/0x275 kernel/softirq.c:558
| [...]
| 
| read (reordered) to 0xffff8880077b5570 of 4 bytes by task 1985 on cpu 0:
|  skb_headlen include/linux/skbuff.h:2139 [inline]
|  e1000_tx_map drivers/net/ethernet/intel/e1000/e1000_main.c:2829 [inline]
|  e1000_xmit_frame+0x12fd/0x2720 drivers/net/ethernet/intel/e1000/e1000_main.c:3243
|  __netdev_start_xmit include/linux/netdevice.h:4944 [inline]
|  netdev_start_xmit include/linux/netdevice.h:4958 [inline]
|  xmit_one+0x103/0x2c0 net/core/dev.c:3658
|  dev_hard_start_xmit+0x70/0x130 net/core/dev.c:3674
|  sch_direct_xmit+0x1e5/0x600 net/sched/sch_generic.c:342
|  __dev_xmit_skb net/core/dev.c:3874 [inline]
|  __dev_queue_xmit+0xd26/0x1990 net/core/dev.c:4241
|  dev_queue_xmit+0x1d/0x30 net/core/dev.c:4306
| [...]
|   |
|   +-> reordered to: e1000_xmit_frame+0x2294/0x2720 drivers/net/ethernet/intel/e1000/e1000_main.c:3282

KCSAN is saying there is a potential use-after-free read of an skb due
to the read to 0xffff8880077b5570 potentially being delayed/reordered
later. If the memory was reallocated and reused concurrently, the read
could read garbage data:

1.	The e1000 driver is being instructed to transmit in
	e1000_xmit_frame(). Here it uses the data in the skb in various
	places (e.g. in skb_headlen() above) to set up a new element in
	the ring buffer to be consumed by the device via DMA.

2.	Eventually it calls e1000_tx_queue(), which seems to publish the
	next entry into the ring buffer and finally calls dma_wmb().
	Until this point I see no other barriers (although there's a
	writel(), but it doesn't always seem to be called).

3.	e1000_clean_tx_irq() is called on another CPU after transmit
	completes, and we know the device has consumed that entry from
	the ring buffer. At this point the driver then says that the
	associated skb can be kfree()'d.

4.	If I interpreted dma_wmb() (and smp_wmb()) right, plain reads
	may be reordered after it, irrespective if a write that depended
	on such reads was ordered by the wmb(). Which means the
	reordering of the plain reads accessing the skb before it may in
	fact happen concurrently with the kfree() of skb if reordered
	after. For example reordered to the very end of
	e1000_xmit_frame() (line 3282) as KCSAN simulated in this case.

Is the above result allowed by the kernel's memory model?

In practice, my guess is no compiler and architecture combination would
allow this today; or is there an arch where it could?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YRo58c%2BJGOvec7tc%40elver.google.com.
