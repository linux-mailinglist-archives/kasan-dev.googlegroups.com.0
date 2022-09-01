Return-Path: <kasan-dev+bncBDBK55H2UQKRBLGEYGMAMGQELQZSVKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 95FE65A9094
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 09:41:33 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id r10-20020a1c440a000000b003a538a648a9sf9462338wma.5
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 00:41:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662018093; cv=pass;
        d=google.com; s=arc-20160816;
        b=yXTh1Su7jsi0fn/tCCkkizoH+daLWqlLjlHBqMH8Yb46u8Q6m2b9vniMUCwa+kCj16
         L3yw8prc713TD7Nr4ujIxiuXGW2nFuLibDW1EPW/OnQRGtEkGZT5vPNP4CAy/0yGAMFU
         xsfBn1pgez47giSL6QTZFBJUL651Ury4MOuNHv2NU8xo8Q3oDYkQmxPHVspboCUR4MQQ
         X0KikxdsRdFYo2EyzccuvbW7S7Iv8W5cQ7H1/9UpUpI7wGZ+C7x9iOUVg+Q98/ROP2n7
         asrO8dCykjR7ZHHSyofFjEllMG8UaxDw7bFoNeLq0oT09dcCDg3aoZwswFHLyOu8xP7z
         ELdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1CdPJmY/qxH5jrFXc9U8PbWaCSNajOrFMLVvE/lbeW8=;
        b=XYN4uFbYF/35kkkpDiLZeSBa6CsbYaGdxGW+HD3g7ZheiX+MF54Vi+SoDtJRQ6N4tY
         P7fF0XzOXexWdn11UW6oVd6RdsGuU4/CAfYH5/sSFzz4Avph80iLPMXI6EoByiO7v786
         Z9P7lJPndIWOlALPeMaMwxsZzlIIa3p0qP4Zqj33syZZRNRr/RnXUXx77ahXjiEI6A5Q
         gqRUzWjL6JP/tIKEUpz15RWh23w1cnEiEjswUOKQJ2oTtc+WMrcMDRe6pZUUOQQld3ex
         tXLbVbruhLxfmojO8dgKg+FCE7R3c+TAy/KdHQ4Tto6iBrOTPIHzSaR8jUI7nb1azQGF
         bnww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="JPARXCy/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=1CdPJmY/qxH5jrFXc9U8PbWaCSNajOrFMLVvE/lbeW8=;
        b=CRXse0ohr8JXryTvCwvE4EzDZ3NfUtwJrVBKjEpCbFo+iAR4xZGtPriF6Ey22/Uk/9
         m3tGZYj20X7fFOTAJmKPrhmsOeVkqd3vViuHuhyV5Q6s3LRVguMvRkPtkvhrunSM/I+7
         srEYPdkudNq8Yv7untHb7wCMo3ExexXFXrBXXsoUGU70YrrzQRAXOADKsj6uce+CGT/Z
         NJO9z9OmicxJDBhNxUd0PnM+B4nvG6BHaZx/tqoM3GdB0h/DO4c2lvjouaQWLe6Peyw0
         XlQ9kv7antOE7QuPR9daWZ11wX3uwsfxz+xo7M8Kb2O6AELIVa5EF3JszU3qOgTCKX5A
         +oxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=1CdPJmY/qxH5jrFXc9U8PbWaCSNajOrFMLVvE/lbeW8=;
        b=isU+stcnE5+xFyK7gMdCWjBQY8P21A67TQr89Zm5fQuzyx11WWn+ID/v3XArnA8FYU
         8fMiEhQjO3/mpkn6GUXwIRDuiPijCSub1cvFz9cEYNalri3wdRhtdSv/YkMi38bg+9ho
         WiafO8vaTjifHxpWq37QxoaD8gxPGRGQR+40ziHbZLmXMIDPFb0ezt0E6bE+tAkwL4tC
         fYvnX0z9A2/XWrIMUkILInH9Ww9gUnqIMHiFVP2Y9mI5pgS6j81HPVDrCyDPJCoh0oQ+
         K6p5RLChCg5ciCedf5e851901rHkG0jDTZkhB/zKg0r0QLci7U5EkFd2S8mF/ahCngJh
         ggzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1UnRVPrz+TTnbGt16EGOTS3o6iYwjuBuQ4E/0BVIz6yi3dEwFe
	Uw/Ibp7QdzWaRdUtTZe/5jI=
X-Google-Smtp-Source: AA6agR7KgIJQQsKFaWR1BdIhfsajfJc/AMKtj2ZA9TkcIV0DKGf6S+1tFX5CZyfaefuHTnid5HmILg==
X-Received: by 2002:a5d:6dad:0:b0:225:6dc8:e453 with SMTP id u13-20020a5d6dad000000b002256dc8e453mr13783960wrs.64.1662018093076;
        Thu, 01 Sep 2022 00:41:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:247:b0:221:24a2:5cf with SMTP id
 m7-20020a056000024700b0022124a205cfls1672117wrz.0.-pod-prod-gmail; Thu, 01
 Sep 2022 00:41:31 -0700 (PDT)
X-Received: by 2002:a5d:5248:0:b0:226:da8b:eafd with SMTP id k8-20020a5d5248000000b00226da8beafdmr10713292wrc.452.1662018091843;
        Thu, 01 Sep 2022 00:41:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662018091; cv=none;
        d=google.com; s=arc-20160816;
        b=QfzkasBhKUtLYBPwJ4/vfhYYptGDlQg2ivCH4tgd6I144HALNoQhv6kRyYQGae3EBU
         AbZ7ZOqrLxaPuaeWNVfEbmgpP4vNc62hfkkRzfYFNBuxEOGzam7xKUvGH99ezGCEtBgo
         0dGg5msu5C+1jCMILkyQSZX0X/DdTp/6Sw+4tgTWlKapBw/oIkCirNNWmtfioA/QmeHp
         ykzPmLckPUVLb2unojtDY6otGHXsAXhR1WkSTiX9RhJHOPtlcxckfBKQY7m6CBkRjcuT
         ldts7HzNfEWI9fDLnvyfAxz36WZQDoGckuYdUjMHpi3O8lWggFmJUI3h7rGb7ELYlcLI
         iIhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qqD5irythXcXnrZi3fFnP54DNBcaxZAOs7bCGWArgiE=;
        b=V4UHKD5NAKfGmQWZgjdEilkFtwX0Q7lc6dDi8DcopOda04LX47L7onqDIBbFbLJLcW
         DGwEukCsqkMKqjgtNcGW/FRYEw7U3pUs5P2nRqvZUoBDaJ0X0+xB1q5CZIlXF8qo6muL
         bBJR0KTX4LsjaHUArtVxulzY6CAxBndhEWU6keKmqxoEQpGKb9aXi1ybmZ1yGTW84I2N
         Oo1IUhfP7KPLkt0fMymyRsEN02d1Cm//sAZtzmvFCg8xY/mRmJgV+3DfzWHZ9BDZ/78t
         O4wxyCshTvkiTpuLbcKUaObXCH/o5oiLGqLiRaL2020DuMEZ6uNya7L+MGFyFSFaKIW3
         Luuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="JPARXCy/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id c7-20020a05600c0ac700b003a83f11cec0si305376wmr.2.2022.09.01.00.41.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 00:41:31 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTeoz-008LsS-Eb; Thu, 01 Sep 2022 07:41:05 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B9A783004C7;
	Thu,  1 Sep 2022 09:41:02 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 925E52B871FC0; Thu,  1 Sep 2022 09:41:02 +0200 (CEST)
Date: Thu, 1 Sep 2022 09:41:02 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Mel Gorman <mgorman@suse.de>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 10/30] mm: enable page allocation tagging for
 __get_free_pages and alloc_pages
Message-ID: <YxBiDmmhn4wlwIHC@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-11-surenb@google.com>
 <20220831101103.fj5hjgy3dbb44fit@suse.de>
 <20220831174629.zpa2pu6hpxmytqya@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831174629.zpa2pu6hpxmytqya@moria.home.lan>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="JPARXCy/";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Aug 31, 2022 at 01:46:29PM -0400, Kent Overstreet wrote:

> Because all the counters are statically allocated, without even a pointer deref
> to get to them in the allocation path (one pointer deref to get to them in the
> deallocate path), that makes this _much, much_ cheaper than anything that could
> be done with tracing - cheap enough that I expect many users will want to enable
> it in production.

You're contributing to death-by-a-thousand-cuts here. By making all this
unconditional you're putting distros in a bind. Most of their users will
likely not care about this, but if they enable it, they'll still pay the
price for having it.

Even static counters will have cache misses etc..

So yes, for the few people that actually care about this stuff, this
might be a bit faster, but IMO it gets the econimics all backwards,
you're making everybody pay the price instead of only those that care.

Also note that you can have your tracepoint based handler have
statically allocated data just fine.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBiDmmhn4wlwIHC%40hirez.programming.kicks-ass.net.
