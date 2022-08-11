Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEMF2SLQMGQEFBCRJ3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 561FC58FD4C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 15:22:27 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id e10-20020a4a828a000000b004389399413csf8120758oog.16
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 06:22:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660224146; cv=pass;
        d=google.com; s=arc-20160816;
        b=PXJnP7Ir6eTfQ3URKe4/llU64QGH9CyRGBFryplg285onITn0atK/d/Ljdy/rlE5UM
         VfEljtDn03CoW/OzlE2RmsPNYnwejH9LZ+GAzqGItYkKMsTggnt2ycNxxyqDN4rTGGvi
         mb/DyDAaT6UgW8xn0+9yGSWdQluaLEHBabfjQKp0OtZ5MCB9PC5vogunv/lnAxTKij0Y
         19VbdZq2FhDSONfomvAmnp1sfVIxyRnnRRyAfhTlzul0Eh5y92wCrQ7B6W9BgIJS8T6S
         4FJcY8s24bDhZCcOwUA+iEaCCBC/txfO3sSIJAYCwfQFqIKyq/XWbVOtUUlNJfx6ZRm/
         1GzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RPPgr6mtDM8UZ3o0RPACxkpismRZPGZ2/9LStvHAqQg=;
        b=0gxiMZTXFeBxMOuyrbfRmSVgf9rDQYm058zeLfG4gn3/qgo5l0eHTt1acxpmKzYBE1
         YGd+PVPHHajcMEb5k7vvLCZ83sm5esGuJ5tzCkDuwGu1kPufmoazbAyyPk1KatrxH1BN
         FIKZ/qqeB52yIPxibnT45vaxzIxmhVDGRBDj04S88KmAx6yzuuicQDsGU9Q7Tsd8bQjB
         0J7tKrXnS5cIgDfmXdeBG0aznt0Ij0q8ZD2JECNDUfdWeLLlHFk9fMLy3M2M70qBNX/o
         NBm2dmwSSnVi4EyNvd4ZoRFU4wbYLKUUiz7evEBtROqpdmGys5Jy+I7aUvTjSVllVuLu
         H5wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bqqg6BYy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=RPPgr6mtDM8UZ3o0RPACxkpismRZPGZ2/9LStvHAqQg=;
        b=Yc/jwQX/RC3nSowoDRjb8+XMjPVsbxqNNMpgmPQNvNI+WZrPiquw5rLHmKDb5K1hDY
         rcUS5/NUB0CkwqqDj9WKXgMi/nBlx+7RqTpIVmS2wJMFFxj3nZWw5YqWwdGaVyTctcBH
         lc57C0CDgfEj7eNgJh/oEi6j0kk1VzUMNZ0yOAr+g4PGToj3538v2j+IKeb/pQ9KMq60
         hP1qCJHXYuFg9H/+HUlURoFSKspe654NAZEuxLVd83X0DQ827aPjgHT9eUzN0sGpcBE6
         Z3Xz1WwqKFv9aqZNQnD9HsWAWh/kJEfGYWXzAk8bpLnCWSMwyPM6vEdcvwjkA84r1ogG
         gQxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=RPPgr6mtDM8UZ3o0RPACxkpismRZPGZ2/9LStvHAqQg=;
        b=wc8n4y3x9bB2u4NecZ8xUxFVqR8CDlNhRvJ6y4/r4mKGPq6NHO3jF60XlzMZtk9pdf
         jSDF5gBajsisQxKArXeWl7uLbEATvfjcsmQdQwO4jUWTToPU3OXG2qEES/UsuFXwOdgd
         WhcCaFI/yHp9TWT9w/+XoFYvZAqkBviesl5/mBMn4PZ/VpJAjmxNC9JgzUky6EoclFzs
         jw8r30kWalkKF2LJ4WcfH7DDyGzxUpjyB7G17RbSom84LWN3GFK0jH+h9fj67KfT/i+S
         et70yVpq+ltUaSywYezJhTKW8uyLfNgiHeRERX1LmTcjHR05EInpo4IDspzzjCegu9Zr
         r5Ew==
X-Gm-Message-State: ACgBeo29e4WWlQknW7zxM2j1SQ97PD/S6FI/FydvgGPu76D+Fb7UEApm
	GOJ/OPIHJt0Thgwq0pTrEpo=
X-Google-Smtp-Source: AA6agR4aqw/BuGzj0tA9B9vkEeF8P2aAUVU4O9BkRLcIyi+D1ouyjZPsI5W3ZAy4yiyuCX5yp/ImAQ==
X-Received: by 2002:a05:6830:6108:b0:618:e0f4:d092 with SMTP id ca8-20020a056830610800b00618e0f4d092mr12677672otb.41.1660224145854;
        Thu, 11 Aug 2022 06:22:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:264e:b0:619:fa:4857 with SMTP id
 f14-20020a056830264e00b0061900fa4857ls229096otu.1.-pod-prod-gmail; Thu, 11
 Aug 2022 06:22:25 -0700 (PDT)
X-Received: by 2002:a9d:4604:0:b0:61d:ad8:ba1a with SMTP id y4-20020a9d4604000000b0061d0ad8ba1amr12057780ote.332.1660224145338;
        Thu, 11 Aug 2022 06:22:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660224145; cv=none;
        d=google.com; s=arc-20160816;
        b=ao03jp8tbUfj/91Nd7Bx2ltM/OZ4ZFe+veoiFEaoYKdBnbYxgx/cL5wuVHeClEdWhe
         Q7Ar7sfjeWhuTEzSGiCDSFWFMN2dhbzh1IUD2mVBuy0WcfROvqPzxBr3NEbA6qkgAPhe
         SVmwk9YkOJgArygOWVcZYNN5rc7JCjUa1dWPJZYEXxU5iqt5o7A1vsulL9euFjjdwsIT
         S7dW32p++Uq7OXH00hFXFiGwTbimjUFX+hbdzkTXBizbA0lkYQy12MBgvD5yx9aWm3M6
         TzqMWxJWRiYczScPGkd9IbwWRsToTuTHaRaprtzUGw4UMNKNrOPDDES0AzU+1hCZEs5t
         hr9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Eb3rnYYvtIKOzVfVgbxd4mjo9Ht+qE4u6mbe1XaOMUQ=;
        b=rFmYTZq3L5RjTHzx4yT6EVhfhai/AhcFjv14b67AVotdsTGfY8OpdTs3j+zrz6dZWv
         f9U3zidsBBTzp1oQLmeShXkePowPf4+ex8ONQ9sqK+T1sFu/JhipoYo27jQkPXlvPSBw
         jZvpb4y1F+t4ua1NMQ7f4BTDOno+2rhqWfhPGSJSmMicGnpPA1+OxIo4F2ReP3X/XRK1
         zSERGeRn14Trqv3OFVuOjvNx0YbtMAh0LIREmnIwOT2ZMUmVUT+OYtFmk64QO+Nvp/uu
         qKF+Rowle+fFKwi8COYoli4Eo7wF5b8f1CV6xhyFVHK5QHXDyLwbAA6h7qShI9JkrHYt
         N2kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bqqg6BYy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id z3-20020a056870d68300b0010c5005e1c8si1892200oap.3.2022.08.11.06.22.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Aug 2022 06:22:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id 7so28244515ybw.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Aug 2022 06:22:25 -0700 (PDT)
X-Received: by 2002:a25:ad16:0:b0:671:75d9:6aad with SMTP id
 y22-20020a25ad16000000b0067175d96aadmr28012031ybi.143.1660224144897; Thu, 11
 Aug 2022 06:22:24 -0700 (PDT)
MIME-Version: 1.0
References: <20220811085938.2506536-1-imran.f.khan@oracle.com>
 <d3cd0f34-b30b-9a1d-8715-439ffb818539@suse.cz> <CANpmjNMYwxbkOc+LxLfZ--163yfXpQj69oOfEFkSwq7JZurbdA@mail.gmail.com>
 <6b41bb2c-6305-2bf4-1949-84ba08fdbd72@suse.cz>
In-Reply-To: <6b41bb2c-6305-2bf4-1949-84ba08fdbd72@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Aug 2022 15:21:48 +0200
Message-ID: <CANpmjNNC3F88_Jr24DuFyubvQR2Huz6i3BGXgDgi5o_Gs0Znmg@mail.gmail.com>
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
To: vbabka@suse.cz
Cc: Imran Khan <imran.f.khan@oracle.com>, glider@google.com, dvyukov@google.com, 
	cl@linux.com, penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com, 
	akpm@linux-foundation.org, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bqqg6BYy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as
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

On Thu, 11 Aug 2022 at 12:07, <vbabka@suse.cz> wrote:
[...]
> > new flag SLAB_SKIP_KFENCE, it also can serve a dual purpose, where
> > someone might want to explicitly opt out by default and pass it to
> > kmem_cache_create() (for whatever reason; not that we'd encourage
> > that).
>
> Right, not be able to do that would be a downside (although it should be
> possible even with opt-in to add an opt-out cache flag that would just make
> sure the opt-in flag is not set even if eligible by global defaults).

True, but I'd avoid all this unnecessary complexity if possible.

> > I feel that the real use cases for selectively enabling caches for
> > KFENCE are very narrow, and a design that introduces lots of
> > complexity elsewhere, just to support this feature cannot be justified
> > (which is why I suggested the simpler design here back in
> > https://lore.kernel.org/lkml/CANpmjNNmD9z7oRqSaP72m90kWL7jYH+cxNAZEGpJP8oLrDV-vw@mail.gmail.com/
> > )
>
> I don't mind strongly either way, just a suggestion to consider.

While switching the semantics of the flag from opt-out to opt-in is
just as valid, I'm more comfortable with the opt-out flag: the rest of
the logic can stay the same, and we're aware of the fact that changing
cache coverage by KFENCE shouldn't be something that needs to be done
manually.

My main point is that opting out or in to only a few select caches
should be a rarely used feature, and accordingly it should be as
simple as possible. Honestly, I still don't quite see the point of it,
and my solution would be to just increase the KFENCE pool, increase
sample rate, or decrease the "skip covered threshold%". But in the
case described by Imran, perhaps a running machine is having trouble
and limiting the caches to be analyzed by KFENCE might be worthwhile
if a more aggressive configuration doesn't yield anything (and then
there's of course KASAN, but I recognize it's not always possible to
switch kernel and run the same workload with it).

The use case for the proposed change is definitely when an admin or
kernel dev is starting to debug a problem. KFENCE wasn't designed for
that (vs. deployment at scale, discovery of bugs). As such I'm having
a hard time admitting how useful this feature will really be, but
given the current implementation is simple, having it might actually
help a few people.

Imran, just to make sure my assumptions here are right, have you had
success debugging an issue in this way? Can you elaborate on what
"certain debugging scenarios" you mean (admin debugging something, or
a kernel dev, production fleet, or test machine)?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNC3F88_Jr24DuFyubvQR2Huz6i3BGXgDgi5o_Gs0Znmg%40mail.gmail.com.
