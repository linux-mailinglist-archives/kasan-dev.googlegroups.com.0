Return-Path: <kasan-dev+bncBCKMR55PYIGBBGX5W6RQMGQEXEJWIPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id A01F070F5ED
	for <lists+kasan-dev@lfdr.de>; Wed, 24 May 2023 14:10:03 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-96f46e5897esf95050966b.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 May 2023 05:10:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684930203; cv=pass;
        d=google.com; s=arc-20160816;
        b=uAMvuOdEuzydrVTiVhS93F38ipQK62hEN6COExLJDHs6K/sPy7k6kwXoYQm2EFnry7
         aPridD+NZ7T0CZY2ipWriAzL2f5yfXjDasxEhayr+zC814WcfQcX3KOaJ/oHn43x49Yq
         bUs8M0E1Ojddb9gSg+NZ2oyJFEZ/GTUsUcTFv6ifHpxaenriwzzfrzE7+a5Ml44jr/U1
         z4y4Y5/V123Z7jB/4JLWyuHj806UP/GoVd05JhF8Rv58tVArhQFAQ8piiVowd5oFdINd
         OkkIIbvYmaAKScDxYWhjM2mqvKq3LzzKk5DXftl+I6Xqx0dJYZKMQdJqQ2b+kdvT/Eft
         F7NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=gu1yFWAxySI24xHVG6ke/WBmUoC45btcpS+5SQt62h8=;
        b=oAZHh6jCP6CHIpyRZHgVrQUh33DjfIJQlrYY0A9QP4Fi3d83RwTl2EwLbvhlEu9ulx
         J3E8gCMfmw9nmGdIgcCD8bHfuDV+24FOrX0O5VP5sEwejPEuNV0JfcbrFxZJsyW9orgA
         HMTYxoHHCDEeWyLZJuWCv5bVCIAg7dNXbkUY++53IEOUw5hy7YU8F1nHGTbhSg4IuQqf
         gVQrBKZ4f0EcXToNa4slhdWof2J4XjyUD+2GKyQ1L1iOFWGk5xyRH3sDKkc1ryk34JkC
         XN+OqGew7VRu3x8zC96a5PDOpE9XkRFE5r/z6W3XaNkQ+MqCplU6/B4ztF/FY6+FThgv
         BMbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=iwA8pBLj;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684930203; x=1687522203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=gu1yFWAxySI24xHVG6ke/WBmUoC45btcpS+5SQt62h8=;
        b=Iq3LJOuYaT0y+2UpamcV5tvqVnDjBgGvRvuSOij+m2VJ5VgG2SpIBirnKlZF9GxApF
         q8Eyxfh+oV4UfiKZFjZ/ReF9XhQofMntybhhC7c0gohjOHAIflbAg79uxrnU2BNj876k
         6/eU1KlYodSi6001S1K2jitSthY1WsamWzHY1kFdIhnEPCJ/b31NO3gOd4lgHt3cYLev
         im9E/hxlIbmaCqXvmufO0kGdTrs8506k/HEhDFyPluIT7JrXAc6xSuAtBnF/tSl9BUE0
         fHS6421Cn/PCy3J6801p/p/jg8C0VxYZEjQNG6RojDTnHhcaoVDJ4SmqTTqa35WvOUJb
         cFyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684930203; x=1687522203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gu1yFWAxySI24xHVG6ke/WBmUoC45btcpS+5SQt62h8=;
        b=h2Z5+M1GPFvFXF0npsJTguWY5Ba2jwxZ4oG4WwVk14Gp+/atcyGjXr3nCUE4vwZJaE
         Fn3VfUUFfz5CxYzmGbiKjROOXd/TPeTAuWwXswbv4W1Wfb0yixR+b+dswgl+9mvcDVig
         zSeqOzKyNzyaEXr/4zbiKSKO5AqAZYFIFsEtVGZRpEu1K6HP/i6zQK8guD8863jCTHwT
         QDHj7jyXi+iz23jAA+9/jWt9dMINTBFmwTJCbcqXx4+e1sKNQKzvIGPJgRItMaY2ZTGO
         asPIA5FEAKQ7WoEYbwpYsVLiV9BfyRhLG9xoRz75hIGu/suZToKar0KhHeBjUPxocm4X
         ptzQ==
X-Gm-Message-State: AC+VfDzj6Be2OTV7FgsRk+MZuTGBORNZDF9BJcPCsOgHIXEJP7ACTcMa
	2BnT9isNLr57RpbzI/HuB8U=
X-Google-Smtp-Source: ACHHUZ6xS0Kh7yOwov+pZYY9BHjiY5QLzFAXaNrnhTGavfrTjhKESF0StAeooxbIKyRnsHHED3QuyQ==
X-Received: by 2002:a17:906:dda:b0:966:530c:5278 with SMTP id p26-20020a1709060dda00b00966530c5278mr6463968eji.8.1684930202781;
        Wed, 24 May 2023 05:10:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:eb46:0:b0:50b:d7a3:3b76 with SMTP id z6-20020a50eb46000000b0050bd7a33b76ls62052edp.1.-pod-prod-08-eu;
 Wed, 24 May 2023 05:10:01 -0700 (PDT)
X-Received: by 2002:a17:907:3f16:b0:96f:48ad:73be with SMTP id hq22-20020a1709073f1600b0096f48ad73bemr22300888ejc.44.1684930201134;
        Wed, 24 May 2023 05:10:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684930201; cv=none;
        d=google.com; s=arc-20160816;
        b=otPhaEXH9B3VGAqOTALE73jlTYpHcwzy1S1fH/2a1hpyv6IPLl2KKU2gxTDF3ePYcf
         7skq7EXhslWgAqtbzHuyJoV3FXZONGrkMS3C5GtQQ4suZP39W4gckuDBq297owwi37S9
         zzcIcgLMrDd0gFm867IW7/6jDHPdyBjqhZyquFPNtCfjjJY0OFN/m26im+VN6nSMshDp
         ptnw1kwqqVXy9HeNXV1g8SXyNn9CLu0bStBReWwxpTG/Tb3jPh6AZvzNBdzRuz98fiSR
         sPcxT0q7UoWX0JZblitWQqWmteeFmZWnesyOHWe+ZWg7p14TFDYEjeQMXJ+vD2rjL27i
         zFQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zLYVfPUqC5itE9Z1gpOugKKlSVBzS5/R2EGbMjp6o2k=;
        b=S1zdTo+SlG3DJhwzD+sr1t8vPbKS77cZ8/mxphlcw9mGSfDejYtLqICtUdmmVfTW+w
         ioSgiUvRAOncD1BPvzwlIeYk0fOxjjYFUdmhBv4D8KIjRzH+ps9fd8YM6Y7qIKG5O4Uc
         59LU4j0Kb/oLueLL75vbLPtQ5iB5VMODhUPP6GbBMOba3un1hjg8uJ8EHseZWi5k6Vi/
         ewaerEqkIB5+m3eN/ZgX1fgM6ZBY34XkMY42Z3TSxPPEB7qk9xeRjzVvuBky6ktVzMKH
         Vi5pBJlbk/YBU+4sFWNHgqtwe8lN0i3nr/HXVpA07oYslRqY9pHH0sfESXUxwLvhH5TO
         58UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=iwA8pBLj;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id g1-20020a056402320100b0050bd0abf2b4si1049760eda.3.2023.05.24.05.10.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 May 2023 05:10:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A8C561F8B6;
	Wed, 24 May 2023 12:10:00 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 898C913425;
	Wed, 24 May 2023 12:10:00 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id UTa0Hpj+bWSAXQAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 24 May 2023 12:10:00 +0000
Date: Wed, 24 May 2023 14:09:59 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: "Huang, Ying" <ying.huang@intel.com>,
	syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
	syzkaller-bugs@googlegroups.com,
	Mel Gorman <mgorman@techsingularity.net>,
	Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-mm <linux-mm@kvack.org>, Johannes Weiner <hannes@cmpxchg.org>
Subject: Re: [PATCH] lib/stackdepot: stackdepot: don't use
 __GFP_KSWAPD_RECLAIM from __stack_depot_save() if atomic context
Message-ID: <ZG3+l4qcCWTPtSMD@dhcp22.suse.cz>
References: <000000000000cef3a005fc1bcc80@google.com>
 <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <48a6a627-183d-6331-0d8d-ae4b1d4b0101@I-love.SAKURA.ne.jp>
 <9c44eba9-5979-ee78-c9c8-626edc00f975@I-love.SAKURA.ne.jp>
 <87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel.com>
 <0471c62b-7047-050a-14f5-f47dfaffaba7@I-love.SAKURA.ne.jp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0471c62b-7047-050a-14f5-f47dfaffaba7@I-love.SAKURA.ne.jp>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=iwA8pBLj;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 22-05-23 11:47:25, Tetsuo Handa wrote:
> On 2023/05/22 11:13, Huang, Ying wrote:
> >> Any atomic allocation used by KASAN needs to drop __GFP_KSWAPD_RECLAIM bit.
> >> Where do we want to drop this bit (in the caller side, or in the callee side)?
> > 
> > Yes.  I think we should fix the KASAN.  Maybe define a new GFP_XXX
> > (instead of GFP_ATOMIC) for debug code?  The debug code may be called at
> > almost arbitrary places, and wakeup_kswap() isn't safe to be called in
> > some situations.
> 
> What do you think about removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT?

Not a good idea IMO. It is really hard to achieve real locklessness in the
page allocator. If we ever need something like that it should be pretty
obviously requested by a dedicated gfp flag rather than overriding a
long term established semantic. While GFP_ATOMIC is a bit of a misnomer
it has many users who really only require non-sleeping behavior.

> Recent reports indicate that atomic allocations (GFP_ATOMIC and GFP_NOWAIT) are not safe
> enough to think "atomic". They just don't do direct reclaim, but they do take spinlocks.
> Removing __GFP_KSWAPD_RECLAIM from GFP_ATOMIC and GFP_NOWAIT simplifies locking dependency and
> reduces latency of atomic allocations (which is important when called from "atomic" context).

I would really like to see any numbers to believe this is the case
actually. Waking up kswapd should be pretty non-visible.

> I consider that memory allocations which do not do direct reclaim should be geared towards
> less locking dependency.
> 
> In general, GFP_ATOMIC or GFP_NOWAIT users will not allocate many pages.

This hugely depend on the workload. I do not think we can make any
generic statements like that.

> It is likely that somebody else tries to allocate memory using __GFP_DIRECT_RECLAIM
> right after GFP_ATOMIC or GFP_NOWAIT allocations. We unlikely need to wake kswapd
> upon GFP_ATOMIC or GFP_NOWAIT allocations.

The thing is that you do not know this is a the case. You might have a
IRQ heavy prossing making a lot of memory allocations (e.g. networking)
while the rest of the processing doesn't require any additional memory.
 
> If some GFP_ATOMIC or GFP_NOWAIT users need to allocate many pages, they can add
> __GFP_KSWAPD_RECLAIM explicitly; though allocating many pages using GFP_ATOMIC or
> GFP_NOWAIT is not recommended from the beginning...

As much as I do not really like the long term GFP_ATOMIC semantic I do
not think we should be changing it to what you are proposing for reasons
mentioned above. GFP_NOWAIT change is even more questionable. Many users
simply use GFP_NOWAIT as a way of an optimistic allocation with a more
expensinsive fallback. We do not want to allow those consumers to
consume watermark gap memory to force others to hit the direct reclaim
wall.

Really there is very likely only a handfull of users who cannot even
wake kswapd or perform other non-sleeping locking and those should
currently drop __GFP_KSWAPD_RECLAIM. Maybe we should consider an alias
for them to not bother with the low level flag. Maybe we will need
GFP_LOCKLESS or something similar.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZG3%2Bl4qcCWTPtSMD%40dhcp22.suse.cz.
