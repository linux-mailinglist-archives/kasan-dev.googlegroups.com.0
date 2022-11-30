Return-Path: <kasan-dev+bncBDW2JDUY5AORBU7IT2OAMGQE2NSDXMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FE0E63E107
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 20:51:49 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id r3-20020ab04a43000000b0041168b89479sf9883983uae.6
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 11:51:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669837908; cv=pass;
        d=google.com; s=arc-20160816;
        b=ohfVPL5w0aVeP+kNiihH+MKBWKwANhanJ+T565dzbGyuixpSKqyLkT/llcVxRx4lE2
         LsJJSXezyXOm9PjseNHrz5yxxIZnKB/k1mUORIAnGNPoO2FClebEoylk2SiGMyeHRv5z
         PCe/aBFFfjVPswtTm8njLGGE+tW6vGjEPu8AxvIxrPN0FWOuIQ5vJ0NLL12UQgXwJfUv
         6CkiHm2R16/Hhs32qOUpXZZUGqmxqVjsO+dHBhn1pV75W7vjwupuCPUT6MvTyPVta84m
         rA1J9Mw4HBQPtEu4fznIpZsg1oz03KuuSMU8o5FdanG10SWYuzHOPcLlSe2orTxcoxpf
         L7Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=BE+DomMCzisVM3aE5ybkXAIVwsp9E0SAOMv6U+F3eNU=;
        b=LCMfObjm7VahuicejfV/KT6GC2+caENiB2yasvxFK+CYcJznGwZ21wb46saD8xas4e
         jfkPQ4rwhRaIjOyEzc0xAyrV6XQGAxcGRbDeh/uaxWOnMLcQCLYFH/J5+y2yBqxh4K04
         AHvpmLHXlMgNpfHsN8cqiDRBCSENQcQFukDf0VWgkZB6YrjZVSUcb3WTS3tUuBpasdXy
         zXIFy3o7vKmmOlYkQ/YVBc2CSQqd7Lu0Yv+kXIIrnKXyp6OYiTdlabIkEkFhsLDRIlf6
         Qsqhqm6vL096NJHP8lMnEu4kiPSAPQ0UZu7Wviqw4TYNv9rGkCp39rq0rlDNjR3jX/Fp
         CN1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YPf0G8XJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BE+DomMCzisVM3aE5ybkXAIVwsp9E0SAOMv6U+F3eNU=;
        b=Nyw9TYzeI6g3gN9xm/r9xFviynf7wE6m08RGayoRvFJO45NBF9cv0y7gNS0XTpwlsz
         Q7vRHr24jioCRO5lHmiOd4IhPowunG5PLy1cmltIONzNu11xKH7++7v/Ve1ezhjGfEA/
         nuR/mQVGOsfXuj36QGtarG3iyoCNAe6OFGiDAAJr/zWdaD40gzBn8Y0Unjt7t2KIYX1E
         Od2EbVAco7YuQ9FFrGKF3R8PlFiy9Ca2c6cBzSmHpWnLuRWtQ5GG0DjksxywBk4Vk/Ra
         KLzFflSAwv/6XN3swFKtl03lvgytlALu+f/yOgSz4iRXvIrsnyGxstec3QHtDgIKBZ16
         feNg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=BE+DomMCzisVM3aE5ybkXAIVwsp9E0SAOMv6U+F3eNU=;
        b=PV/cscDKESbnSrGI0egGJTgUpALKlB3bhwpWb9xWngSYV+KY8/5uHPePawcOWL6LQc
         1IQVwY2D7rLbmeCb4D/bKEQaLDhxDT6zvjk6tTJkWXwEXkB6sjo1I6xzLyovKQS+fU/Y
         R/NzrHnyjFGFsWiKnvAqMw2mqd9Ela1HzE8Qi6+lh+73t2gW4FZAY+aENIihQJJ262X5
         5jtrvVGVaKoiYvssTJyM+qAjmnSWyWFKLiMhQcA92NAU1IU8wKID4WxL3BvagtiDFQqC
         wBwHz8CC6i1jneuJshBpo/ansdRnoP894bcCFTCTws1AN9j5SktAARQXAQJ4CYcsAsfB
         LZ5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BE+DomMCzisVM3aE5ybkXAIVwsp9E0SAOMv6U+F3eNU=;
        b=VLyknk8Ltum3chQyR6Rv8oIEaYvCYMvu/C8oiduaG6FhfqJovqngL1UgFcS+QrVQnX
         KnVPAoKqwI2kJGXAL0qNan988Bi8zLb2UUMiEMDNHm8ewuuuDxUbhizfBDTTD6ZDBg/x
         yHKhUnSG3JEX5IFgnWTmnS8/wKzQy6N7Pn5LgGC76XCEjxyT/JWjEfhK/kuuce0Dt08F
         QLNmtuVUa3eWDexJes+L9//5Qhbb3Xze3BDpQo49zuIm7yLspwBwXAcO5cSyZRkfDp8o
         ZZ3VmBTNMsdyc3ezg9w3XEONB5gutN0w5Md5y5riI8w0lZ/ZqUK7nPbG/d3z0X7BcJVl
         xtgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pngCBCU/idQyRlhpfkXnwh+9AkPS5iGUv67vRGuWco020UFqF/+
	avWYWRbbCl4M2zPfCv/xquc=
X-Google-Smtp-Source: AA0mqf6tN7DIFnwH2qF4Zd2WEnBNVRVXsyOlErokICcMZ1I15KbdoDcAWiKeyi9XNkmrmogxQvCjKw==
X-Received: by 2002:a05:6102:3f8c:b0:3af:c64e:c13a with SMTP id o12-20020a0561023f8c00b003afc64ec13amr26994082vsv.39.1669837907836;
        Wed, 30 Nov 2022 11:51:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c51a:0:b0:3b0:e9d9:3013 with SMTP id e26-20020a67c51a000000b003b0e9d93013ls433841vsk.0.-pod-prod-gmail;
 Wed, 30 Nov 2022 11:51:47 -0800 (PST)
X-Received: by 2002:a67:fdc6:0:b0:3b0:7a41:33e1 with SMTP id l6-20020a67fdc6000000b003b07a4133e1mr19557916vsq.2.1669837906932;
        Wed, 30 Nov 2022 11:51:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669837906; cv=none;
        d=google.com; s=arc-20160816;
        b=p5I3YLP5LUjHHeb5tAx52t3R+C63GVtlv+t6mLjhVvFb6bRTq31c2VA/qe+D3Hsh6e
         ZQDDd5giYzqlpWzqBSblGP2fH375ajau5GmpyvfOM0hdUQOmyfNrfVsawBodi90GGGPb
         8smtdTqzOpu+NArNfIvC+uaAdlWDA0GuX9ARj4vfl2KviNmAh+bylfaxS0QU9Mxcht+i
         xqD2acBoH1Mev/zklvMU+cinbbMaevdn5guMZb9Uj97AQxgo/iMJb/VFDQuSPw8WYVvR
         kScLxlA46K1mAXNGqRLe7PGniHi3lw7dkKgA89LmKB7MTa7L1miZz3XVfS/JJolpsL1q
         BXmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rm61ltPf4IuMIek7hP38S0fd3od46k0u59OV/A4SUFE=;
        b=BJ5RbgRQm85+vh1tQXlVI6hxeRlmwaebwt26kf3E7mUSOtofeIcR4CbH6om9AlvZUl
         SzrvA44qyduCLiXbbc1LcwpwsqB+JMxJkMqlHh0OWlwPIIfgO7Xem6/p5MG40Bgjy6Xf
         U8P3T3kZgF8vsPWwGUwSzM1gB5GhPyAJX23w0djos0RL+jx86tv6c4zA8cuhj4FRx2cf
         KcVBJIqm8GBLvUxsAXDA5j/qe7ccUTWmoDjdymcaMNd2vh5SjFSQwZZ5pkDz9N2xvs+1
         1dS6nc05jy+gq4c8Ak0aw3ul58PushlgCj+NNcxisjIHNlNQ13WTb2Z718zzBVX4lamV
         HLYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YPf0G8XJ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id az10-20020a056102284a00b003a96db77ebbsi128315vsb.0.2022.11.30.11.51.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Nov 2022 11:51:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id p24so14006899plw.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 11:51:46 -0800 (PST)
X-Received: by 2002:a17:90a:5298:b0:217:e054:9ac8 with SMTP id
 w24-20020a17090a529800b00217e0549ac8mr73320400pjh.246.1669837906527; Wed, 30
 Nov 2022 11:51:46 -0800 (PST)
MIME-Version: 1.0
References: <4c341c5609ed09ad6d52f937eeec28d142ff1f46.1669489329.git.andreyknvl@google.com>
 <CANpmjNODh5mjyPDGpkLyj1MZWHr1eimRSDpX=WYFQRG_sn5JRA@mail.gmail.com>
In-Reply-To: <CANpmjNODh5mjyPDGpkLyj1MZWHr1eimRSDpX=WYFQRG_sn5JRA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 30 Nov 2022 20:51:35 +0100
Message-ID: <CA+fCnZeuSVKLy7g9mAiV=2J5eTU6XisFA_byMSqKsopKr7EaQg@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: allow sampling page_alloc allocations for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, "David S . Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Jann Horn <jannh@google.com>, Mark Brand <markbrand@google.com>, netdev@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YPf0G8XJ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

.On Tue, Nov 29, 2022 at 12:30 PM Marco Elver <elver@google.com> wrote:
>
> On Sat, 26 Nov 2022 at 20:12, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add a new boot parameter called kasan.page_alloc.sample, which makes
> > Hardware Tag-Based KASAN tag only every Nth page_alloc allocation for
> > allocations marked with __GFP_KASAN_SAMPLE.
>
> This is new - why was it decided that this is a better design?

Sampling all page_alloc allocations (with the suggested frequency of 1
out of 10) effectively means that KASAN/MTE is no longer mitigation
for page_alloc corruptions. The idea here was to only apply sampling
to selected allocations, so that all others are still checked
deterministically.

However, it's hard to say whether this is critical from the security
perspective. Most exploits today corrupt slab objects, not page_alloc.

> This means we have to go around introducing the GFP_KASAN_SAMPLE flag
> everywhere where we think it might cause a performance degradation.
>
> This depends on accurate benchmarks. Yet, not everyone's usecases will
> be the same. I fear we might end up with marking nearly all frequent
> and large page-alloc allocations with GFP_KASAN_SAMPLE.
>
> Is it somehow possible to make the sampling decision more automatic?
>
> E.g. kasan.page_alloc.sample_order -> only sample page-alloc
> allocations with order greater or equal to sample_order.

Hm, perhaps this could be a good middle ground between sampling all
allocations and sprinkling GFP_KASAN_SAMPLE.

Looking at the networking code, most multi-page data allocations are
done with the order of 3 (either via PAGE_ALLOC_COSTLY_ORDER or
SKB_FRAG_PAGE_ORDER). So this would be the required minimum value for
kasan.page_alloc.sample_order to alleviate the performance impact for
the networking workloads.

I measured the number of allocations for each order from 0 to 8 during
boot in my test build:

7299 867 318 206 86 8 7 5 2

So sampling with kasan.page_alloc.sample_order=3 would affect only ~7%
of page_alloc allocations that happen normally, which is not bad. (Of
course, if an attacker can control the size of the allocation, they
can increase the order to enable sampling.)

I'll do some more testing and either send a v3 with this approach or
get back to this discussion.

Thanks for the suggestion!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeuSVKLy7g9mAiV%3D2J5eTU6XisFA_byMSqKsopKr7EaQg%40mail.gmail.com.
