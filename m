Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAGD335AKGQEFU2FMBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C3F2B26136C
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 17:21:36 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id bm14sf6406063edb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 08:21:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599578496; cv=pass;
        d=google.com; s=arc-20160816;
        b=hKQSuYK2XwLTVGsOl6mxHPAjxGZkkc+bPWCX6vDPjnd+iHwEGxRQMxv7UWXfmgHWLu
         ogIHQeZZHC92okh6TxvBAtm6iL7arodqWZl4MExSnsiQ02gjp4GJjAok7T6OYDhhncZa
         UAbOttv4CnPqbEV6o/4adl/RtrO+3IJWjkZ3qoQPjlDGVUtGpr5/cuDE/TXRrwC9jMHB
         dN899UiUIXhFvnrg+fE0NOXbj+JJi1MkqNL2koaO2EuPOZfMc/05fL2L/hZiPR0ygETF
         SrXxWfxufqYISdbn5Imn5fXo/pkAwxtL/YZr1llageePyLb9y7lRR+X9C2EQJ6au49S1
         5/IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+HJLm8/TmNZ6EEx2EYQGYOuLQkrWaHxbbuyzWIX3qIs=;
        b=GTbXMKLgmg+o1/oYCRr/nbW2010ZCt8cIYvNvWUPj+tVzK3EHmwLIMIze48Ml3dm1I
         YDOrQW2bF6WY+6zGKMMgRNFMKdYrTXaLVEWRP+fx/BVH5Sir25mQahmoJyDfxGs9bZG+
         S6xwNL310igJEc03ET8l9g0Bk2I3G2oAyzRfKisbvZTTunLYOdvRtnlSxNNEj74hbwWb
         5T+2ncX4hMswnF00z4aJhwTYY3YmaNNKNzS+TBNifrE+96wKUyDjxlUHoYzsaLXF3hWq
         hftJGyDdtQ0PifbDbxCSvFeEyCoofx92Ktxokmsmw6+1Z84U+1M2tMQmSK8UMFhNUh8R
         BblA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HRIGydaP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+HJLm8/TmNZ6EEx2EYQGYOuLQkrWaHxbbuyzWIX3qIs=;
        b=TDsWI9ZqwEaP5v+GYbnIk60uUFzOJJ87UENMfxljP+A/8y9PyN2oe+74PqfiIdTjgG
         TnIB8dqLZkg+6IZk6pIKxczOcEkNWmVNmpVyQFnjWlygMOAwjxEFPXKakLgbehi/Og8b
         6OvCwhaaD5oZSyhtJkWi56VJFF3fyArRQP+1Inc4+DaeCKyHhzIQl2qmAe36CiG+G7w8
         uHiCEo5HWmF2byUgoD+eDdFLRQmxuuWN97CF2fCFsyd5BSvV7wsqFECIQBzeHrHQ2Rn8
         PoLHyr2HBIRoelDxJhgGtmyMl+zQxCjtFswD9fO01P2h2m1iT+Hxwv1QDQHlB1+4DPFB
         uLcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+HJLm8/TmNZ6EEx2EYQGYOuLQkrWaHxbbuyzWIX3qIs=;
        b=nRQ65zKt+PSaDvRhRnhpHNN9n4Y1Fe+MlqVjic8ldwvD8kHskHGmKdRge7vvPyxNhg
         GewEfspgAt5DrwWyXwWeHX4wyLksA1ZcqzcTwK5TxS/GYrFE0Rp7BXi37hSJ/xOcsGqb
         ZTdkbxaekC8Io+tm6iEVnIsIaKO7XtTg34LZm1dn7RU0iaOXdEHl8kku0+StKOHe2tFy
         6kyVfFxlYV1LWt+RnnnoKoly1lREUG+o1uwB3gtR0dYbDYkpHm4tP9zFz8EERzd8XDxw
         H0BmJvWWGfHS5lb59u5nDhhXzCqDz0ZU/iqdfz2YHZfKb0z73OKW2R0MxpRQ9YyYwuIr
         c7Vw==
X-Gm-Message-State: AOAM530B2MWqQEbEld9IJgcO792BwgktuXTzec8K4vztwBue/7CqNp5l
	gzppc16kBap8cpOizuYr7Bg=
X-Google-Smtp-Source: ABdhPJzRGtK9Z55WzCztr5kJhwWABFImZPivh+HHPeBfSS9xEzF+diKRkoq3fxU4PyNSikanLtD5jw==
X-Received: by 2002:a17:906:a00d:: with SMTP id p13mr27534292ejy.535.1599578496530;
        Tue, 08 Sep 2020 08:21:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bf49:: with SMTP id g9ls3851261edk.1.gmail; Tue, 08 Sep
 2020 08:21:35 -0700 (PDT)
X-Received: by 2002:a05:6402:292:: with SMTP id l18mr22529447edv.6.1599578495477;
        Tue, 08 Sep 2020 08:21:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599578495; cv=none;
        d=google.com; s=arc-20160816;
        b=jglZiauaSz6OQp88bnrewLu3GgU21m5ZQkVH+Qug/NjQWyBi2BEmogOW+JNVnpjLUq
         vrnxik7sigDAjzjHE7T2UebK6OGuCyE7pDwHXJ695Ao7amTTdSEaJeIl4JCFiUPUrxgg
         qvqunOKtyYqUAPooYzOibCNupsxvmeJ4JhWVyJQr/IRynw0GDYbZriD9Gh1eEYqddlix
         2WnJLvy2sVLNekHl89RIKrtBFfZtrKly9wrU9CRKN4XOvPHdP9kA2WO7N5hH9cHraR7D
         5D9uaKbWHPoUb2El/1+2S477p9UFgJ8lmtMqruArnLJd0SNE21zoa3isxPUY3yQOQJ5c
         PXNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UKA8pKnO1XgI5TJnprRPT/npi5cBz+avnhKYxtTWBW4=;
        b=HI2CTjbb6Zmh7whokoltSm1Ck27vG8qYsVRAjqKtasRFkl55x4GAE2a/2pDFVmq0pk
         ctbmwTwlyIwlIUB7dV9npGPmBh2o9DcCNaoVk71RuYq2Rd4C8zJ3os5JIzoWbwVCqL+z
         IZiTIH86AsvSAyZ5FPwCzCvXHiQ1wPZ2SPD5zoZyvZTd7R7ZrCxtWEYLgez7SOjrXZ/F
         DIbqxsQPtRFP1NIHuMlr4N10XMC8ZH8k/cLIXlYQxBZCpAANycYl1kHOXT9fbnwjzMzE
         GT+KZBpkpXs8aBWpSGDSjmXesnX169WlS9KNGS+isV84uj1X0w84NNt3ARyKwf8nYhun
         dlPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HRIGydaP;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id t16si419221edc.0.2020.09.08.08.21.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 08:21:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id e11so14563562wme.0
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 08:21:35 -0700 (PDT)
X-Received: by 2002:a1c:7e83:: with SMTP id z125mr96250wmc.32.1599578494903;
        Tue, 08 Sep 2020 08:21:34 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id c10sm31766553wmk.30.2020.09.08.08.21.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Sep 2020 08:21:33 -0700 (PDT)
Date: Tue, 8 Sep 2020 17:21:28 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Pekka Enberg <penberg@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>,
	paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	dave.hansen@linux.intel.com, Dmitriy Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>,
	Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>,
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	linux-doc@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arm-kernel@lists.infradead.org,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
Message-ID: <20200908152128.GA61807@elver.google.com>
References: <20200907134055.2878499-1-elver@google.com>
 <4dc8852a-120d-0835-1dc4-1a91f8391c8a@suse.cz>
 <CAG_fn=UdnN4EL6OtAV8RY7kuqO+VXqSsf+grx2Le64UQJOUMvQ@mail.gmail.com>
 <1c4a5a6e-1f11-b04f-ebd0-17919ba93bca@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1c4a5a6e-1f11-b04f-ebd0-17919ba93bca@suse.cz>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HRIGydaP;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Tue, Sep 08, 2020 at 04:40PM +0200, Vlastimil Babka wrote:
> On 9/8/20 2:16 PM, Alexander Potapenko wrote:
> >> Toggling a static branch is AFAIK quite disruptive (PeterZ will probably tell
> >> you better), and with the default 100ms sample interval, I'd think it's not good
> >> to toggle it so often? Did you measure what performance would you get, if the
> >> static key was only for long-term toggling the whole feature on and off (boot
> >> time or even runtime), but the decisions "am I in a sample interval right now?"
> >> would be normal tests behind this static key? Thanks.
> > 
> > 100ms is the default that we use for testing, but for production it
> > should be fine to pick a longer interval (e.g. 1 second or more).
> > We haven't noticed any performance impact with neither 100ms nor bigger values.
> 
> Hmm, I see.

To add to this, we initially also weren't sure what the results would be
toggling the static branches at varying intervals. In the end we were
pleasantly surprised, and our benchmarking results always proved there
is no noticeable slowdown above 100ms (somewhat noticeable in the range
of 1-10ms but it's tolerable if you wanted to go there).

I think we were initially, just like you might be, deceived about the
time scales here. 100ms is a really long time for a computer.

> > Regarding using normal branches, they are quite expensive.
> > E.g. at some point we used to have a branch in slab_free() to check
> > whether the freed object belonged to KFENCE pool.
> > When the pool address was taken from memory, this resulted in some
> > non-zero performance penalty.
> 
> Well yeah, if the checks involve extra cache misses, that adds up. But AFAICS
> you can't avoid that kind of checks with static key anyway (am I looking right
> at is_kfence_address()?) because some kfence-allocated objects will exist even
> after the sampling period ended, right?
> So AFAICS kfence_alloc() is the only user of the static key and I wonder if it
> really makes such difference there.

The really important bit here is to differentiate between fast-paths and
slow-paths!

We insert kfence_alloc() into the allocator fast-paths, which is where
the majority of cost would be. On the other hand, the major user of
is_kfence_address(), kfence_free(), is only inserted into the slow-path.

As a result, is_kfence_address() usage has negligible cost (esp. if the
statically allocated pool is used) -- we benchmarked this quite
extensively.

> > As for enabling the whole feature at runtime, our intention is to let
> > the users have it enabled by default, otherwise someone will need to
> > tell every machine in the fleet when the feature is to be enabled.
> 
> Sure, but I guess there are tools that make it no difference in effort between 1
> machine and fleet.
> 
> I'll try to explain my general purpose distro-kernel POV. What I like e.g. about
> debug_pagealloc and page_owner (and contributed to that state of these features)
> is that a distro kernel can be shipped with them compiled in, but they are
> static-key disabled thus have no overhead, until a user enables them on boot,
> without a need to replace the kernel with a debug one first. Users can enable
> them for their own debugging, or when asked by somebody from the distro
> assisting with the debugging.
> 
> I think KFENCE has similar potential and could work the same way - compiled in
> always, but a static key would eliminate everything, even the
> is_kfence_address() checks,

[ See my answer for the cost of is_kfence_address() above. In short,
  until we add is_kfence_address() to fast-paths, introducing yet
  another static branch would be premature optimization. ]

> until it became enabled (but then it would probably
> be a one-way street for the rest of the kernel's uptime). Some distro users
> would decide to enable it always, some not, but could be advised to when needed.
> So the existing static key could be repurposed for this, or if it's really worth
> having the current one to control just the sampling period, then there would be two?

You can already do this. Just set CONFIG_KFENCE_SAMPLE_INTERVAL=0. When
you decide to enable it, set kfence.sample_interval=<somenumber> as a
boot parameter.

I'll add something to that effect into Documentation/dev-tools/kfence.rst.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908152128.GA61807%40elver.google.com.
