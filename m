Return-Path: <kasan-dev+bncBCMIZB7QWENRB2WF7OTQMGQEXWVZ4TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 243DC79A6FE
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 11:50:36 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5029c5f4285sf3223127e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 02:50:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694425835; cv=pass;
        d=google.com; s=arc-20160816;
        b=fk1XWzHXjTF7EqnX9rY2PcwCqh85XIVGQTo/LFqu+Z9fMCWH0bnbIHmAisqU8hNbPZ
         tTZVBPqpHkVKCXnmhOOe8+kkzudvKB8VLWhXy8gax7HPRnwFshLj6mSRWViJCeb/3CY1
         u+XY+rJ8a94Grya3TBZQ9DfbXsAdDUdbatd+UQOpqA/njQjmiigOStg/LoDEXYrWsj3g
         nC6hgRsD7qjF8CUjW8Hh1YqR6cCvqQ9mAmV3BVHGdpDsQ5P6VGlySxioyOhtCUXsOTvs
         vyslYiN4mQRCHI//shxNmHzlynibsWmbsBfbpWvW7l34Vpira7lzPvQm1IaF7HQNKb8g
         x5og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BsbhSv+Ef4+KXcR8Wet9L5rTLR1iawNAicTwd2M/Qw8=;
        fh=V+Qgg7ZTYBE11VJyrtY7wuVROIcCMZ7ewCsxsDaeqlU=;
        b=gsaMQqUR7CQGe1bHSAXe3klqgutDySCZ7/GsOl+lGTZa3x5vBhk5/ZRtHNcFh4zI6Q
         lUxZTiDVLEJoWJ7u7MyAk/bv5WTu41CMRk2lWnqnPqTj4GNZE4SCRTPPtclbJoHhVWnq
         AlxbQs6MtFx07VrFUt98Pc0vrizk+xljDJypOWvFtA76mq/F32ER7Hn7jJGFB5ZMx7up
         JSqsTwfHKgiYzCWgska8KM6OeendAXD0rQgoX6FsvYTE3dDpCbYxEu5sx9Sge8jnTNcK
         NT1VPwOk5kD8DCCWMYQ6zVZtw4ZoWNyfnv6Pr2TdTsBmiohI0Hhoz1JE8lkPic2FTkZt
         kIHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=YGrtXzWJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694425835; x=1695030635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BsbhSv+Ef4+KXcR8Wet9L5rTLR1iawNAicTwd2M/Qw8=;
        b=aWQGyt8ONFh0nwbnGfgCmFWakLbbpnvHYGnyoea5CaEGmHRmgrklgAKN1gRVswAgm9
         +HhXpKfWl02GwQANLH/wMYBMJZJWDNGKUXcmoi2gf4qSjdr6+qBkC8+a6LOwqIYW9pXo
         M4ueZqA6iSg3cdppWRnzEoJnr9YXZc1wGj3AgJ1zLt2LTyuCgXBN5OJIuUF2vTaxnMgh
         sUOih3Kc9OY7g6qZbvUIuNCQGwIbSHFy6DkV2M0PeSJron3u9Z9jOtLRyxcq77Xrxaoj
         mCv2HNxJXvlCOpf0hX5JuFH83S009nlVPkBQ1PVF0rSN5k22m4YYyuzRFUXgMBQGh/ys
         2ECw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694425835; x=1695030635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BsbhSv+Ef4+KXcR8Wet9L5rTLR1iawNAicTwd2M/Qw8=;
        b=IUGPjUu5TbWClkFOC/aO41e2Mc4UyOx+xu4FGuPx2dGGqd55oh059NL09MG68vwCbq
         wmr5uJ9puxI8L2cQ8iyNehVWXFiAkLxDIFKaUa5WnxZvQASChQjwM124tuU8cQL1GcUA
         Mp7+1K6/vMa/sssTweZ0OlOGI/6ZU4adAagH6ejcag6ByQT7dLm2bhEDwKX36CVWFRQt
         rpk1+UdAIeisH3FlOC+4nO897bXKl0ZTuwtoTkaCb14AobvMtcz5DiVq7IbSo5vLtH6t
         5W9hK8KO5fptcABvUvZmFNI7EdTC0y+NvNPRUJ4IG+raCobA3NHXbIvQ8a7uOllxi9Ii
         AD/Q==
X-Gm-Message-State: AOJu0YzB0IPvtCOqpLUai/oA4jflFZS19jZhTpQ5y82uoQDQnA5VrPSr
	EHeh3WNn7oAcs9sYpULaOVk=
X-Google-Smtp-Source: AGHT+IGrMIZRO7kLl1TuZXo9KFwHgeSt64UgQGDglDTVNZu/Hkxp8go3qiTeciFqxuduP7Kop7+ftQ==
X-Received: by 2002:a05:6512:14a:b0:4fd:d470:203b with SMTP id m10-20020a056512014a00b004fdd470203bmr7081386lfo.69.1694425835099;
        Mon, 11 Sep 2023 02:50:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:ca53:0:b0:525:7601:f44e with SMTP id j19-20020aa7ca53000000b005257601f44els1869573edt.0.-pod-prod-09-eu;
 Mon, 11 Sep 2023 02:50:33 -0700 (PDT)
X-Received: by 2002:a17:907:a06d:b0:9a9:e735:f61a with SMTP id ia13-20020a170907a06d00b009a9e735f61amr7450149ejc.35.1694425833391;
        Mon, 11 Sep 2023 02:50:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694425833; cv=none;
        d=google.com; s=arc-20160816;
        b=wp6AP5yZeyvHvjXwlSL0zhrG7pftVnTZ8tauOcz8CuqG8jto+jFW4lZR4X3bvLc7lz
         geUKXczkXmsBgRpmOSA9BBGpBKazVkUuZCNE0RX9YRGB//wEMDabexL5BLLN2OUWjMcF
         s2+E9DQXoGLXFCwGgY3tOxLN1WkqwFtpg4j27VZZY79Zt/msyDGK8ym8qnXi5C3At4yV
         qirzY1IbU36h30szP32U7yfOdJcKDHw7YwAcYa1Xpv2p9POrmxgM5QaTFq6gSMcMRg08
         e8/t8TslKC8Df4EJErr90kL4ifujkpk0bGqnJCR4FgYJUAeO7xOL/Y2glodl2JNzza7s
         BDBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z7Crep/nXO31QV2GDdfwJy1xW9/XIy7CcW7VYLyAKr4=;
        fh=V+Qgg7ZTYBE11VJyrtY7wuVROIcCMZ7ewCsxsDaeqlU=;
        b=NIp0UVbLYzdgHbumXqvfbvbbECMJ+ykMXZ3thmu2VAqVEPY4434hgL7fgl5ZJepQgi
         rwWHSH3ckc7I+SHqyU4MdI+c74c5/dITrsZ/oQ+wdHh7ovMf13RIIFVZyPZrLSkFFxuj
         Gl+R4TSWygrMsvTEQggP4vVSIsWQYFjH94cV/mxQUm8HundYx3VcLb5u1wQ7MEccORLj
         qsKaC9wQj4EHyvKUuSjtEG/yKGayGZp1k1ShjwYmQX8B26hNWUqLPxBenAMLo3BraFfq
         FeBM6buQ69u0k6fNWSic3mpXnPhSxM5mAZk7/MSNCkrkRyz1dzP9N9Pj3v7CjcovSDMM
         rNGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=YGrtXzWJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id d17-20020a170906641100b009a1ed579113si366507ejm.1.2023.09.11.02.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 02:50:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-529fa243739so13649a12.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 02:50:33 -0700 (PDT)
X-Received: by 2002:a50:954d:0:b0:523:193b:5587 with SMTP id
 v13-20020a50954d000000b00523193b5587mr323171eda.6.1694425832864; Mon, 11 Sep
 2023 02:50:32 -0700 (PDT)
MIME-Version: 1.0
References: <20230825211426.3798691-1-jannh@google.com> <CACT4Y+YT6A_ZgkWTF+rxKO_mvZ3AEt+BJtcVR1sKL6LKWDC+0Q@mail.gmail.com>
 <CAG48ez34DN_xsj7hio8epvoE8hM3F_xFoqwWYM-_LVZb39_e9A@mail.gmail.com>
In-Reply-To: <CAG48ez34DN_xsj7hio8epvoE8hM3F_xFoqwWYM-_LVZb39_e9A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Sep 2023 11:50:19 +0200
Message-ID: <CACT4Y+YcBeshE811w5KSyYpBqaQ3S_-aKanOGZcHCQvHWHc4Tg@mail.gmail.com>
Subject: Re: [PATCH] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, kernel-hardening@lists.openwall.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=YGrtXzWJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::533
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 28 Aug 2023 at 16:40, Jann Horn <jannh@google.com> wrote:
>
> On Sat, Aug 26, 2023 at 5:32=E2=80=AFAM Dmitry Vyukov <dvyukov@google.com=
> wrote:
> > On Fri, 25 Aug 2023 at 23:15, Jann Horn <jannh@google.com> wrote:
> > > Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_B=
Y_RCU
> > > slabs because use-after-free is allowed within the RCU grace period b=
y
> > > design.
> > >
> > > Add a SLUB debugging feature which RCU-delays every individual
> > > kmem_cache_free() before either actually freeing the object or handin=
g it
> > > off to KASAN, and change KASAN to poison freed objects as normal when=
 this
> > > option is enabled.
> > >
> > > Note that this creates a 16-byte unpoisoned area in the middle of the
> > > slab metadata area, which kinda sucks but seems to be necessary in or=
der
> > > to be able to store an rcu_head in there without triggering an ASAN
> > > splat during RCU callback processing.
> >
> > Nice!
> >
> > Can't we unpoision this rcu_head right before call_rcu() and repoison
> > after receiving the callback?
>
> Yeah, I think that should work. It looks like currently
> kasan_unpoison() is exposed in include/linux/kasan.h but
> kasan_poison() is not, and its inline definition probably means I
> can't just move it out of mm/kasan/kasan.h into include/linux/kasan.h;
> do you have a preference for how I should handle this? Hmm, and it
> also looks like code outside of mm/kasan/ anyway wouldn't know what
> are valid values for the "value" argument to kasan_poison().
> I also have another feature idea that would also benefit from having
> something like kasan_poison() available in include/linux/kasan.h, so I
> would prefer that over adding another special-case function inside
> KASAN for poisoning this piece of slab metadata...
>
> I guess I could define a wrapper around kasan_poison() in
> mm/kasan/generic.c that uses a new poison value for "some other part
> of the kernel told us to poison this area", and then expose that
> wrapper with a declaration in include/mm/kasan.h? Something like:
>
> void kasan_poison_outline(const void *addr, size_t size, bool init)
> {
>   kasan_poison(addr, size, KASAN_CUSTOM, init);
> }

Looks reasonable.

> > What happens on cache destruction?
> > Currently we purge quarantine on cache destruction to be able to
> > safely destroy the cache. I suspect we may need to somehow purge rcu
> > callbacks as well, or do something else.
>
> Ooh, good point, I hadn't thought about that... currently
> shutdown_cache() assumes that all the objects have already been freed,
> then puts the kmem_cache on a list for
> slab_caches_to_rcu_destroy_workfn(), which then waits with an
> rcu_barrier() until the slab's pages are all gone.

I guess this is what the test robot found as well.

> Luckily kmem_cache_destroy() is already a sleepable operation, so
> maybe I should just slap another rcu_barrier() in there for builds
> with this config option enabled... I think that should be fine for an
> option mostly intended for debugging.

This is definitely the simplest option.
I am a bit concerned about performance if massive cache destruction
happens (e.g. maybe during destruction of a set of namespaces for a
container). Net namespace is slow to destroy for this reason IIRC,
there were some optimizations to batch rcu synchronization. And now we
are adding more.
But I don't see any reasonable faster option as well.
So I guess let's do this now and optimize later (or not).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYcBeshE811w5KSyYpBqaQ3S_-aKanOGZcHCQvHWHc4Tg%40mail.gmai=
l.com.
