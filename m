Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPHDXOQAMGQEQU54PUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CE206B7320
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 10:49:49 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-176249fbc56sf6908796fac.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Mar 2023 02:49:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678700988; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iq3+PA09XIYwU8/rXZa41NO3LsvQEEomFLZHtLB2OPSCwx+bdPaj4Eo2J7HdQnEWDT
         q4/pcWGcj+IGwO3RIhfpcqAOHPjPnGb0sdcmhr2a+J6YvfGWWjcv/IqwwX3acS7Z31u5
         u1TOUXTBSPCLazJcDIb+A81pxmfx7MZ9VajVor1/4i/NCSbAZHmwlbTSIpX0JdJlz5n1
         5hnWTF/m8qNNu1MLxu0zhewyyyaEd54as5u1v0iPLBroGIM0954zh2uQaNJaTC0E8L4f
         BvScLJuhSikdn1nJulXpK5LPm2lwNXLJns4rvFHsLuQi5+lgOdJ6imhfGhnxjH1sHVqh
         nP1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BJVBcsikjn5PEFAWn11AmQBr73rEeSJfTjKId8SZRuU=;
        b=hM1j7bLnsE8MRAV7dwt7Ua2qp8P2k2KI0TFaRSWRzvojKOVVa1F1JSqkL6BxVCmRNs
         Og6PHaGoEuRnKo/igkCYaUVyoRUUVYM4qKjUKy97/gBlSJ9P8vV84aR7eQtRbvAl8yNm
         tAsIoCELyYxxCTcPqjvPK0Aw1qzDttiP1x7Cxow5qdk+gNZ5BeCywl0uZIDZcu5xIWSA
         32tXh134PyObwNeTEQWxoGWKzQl10+VldL1QAhwxZlhYlU3BDkLVRcA3ZP/QdFfhZrqK
         wYUkO7qO7CODIg8p9qognivH3/nDNm9wW9Ccvzhb5fxZ+n1bdTMASXVyZ3xAlx6ynvRZ
         Ftvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sCcGOy6q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678700988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BJVBcsikjn5PEFAWn11AmQBr73rEeSJfTjKId8SZRuU=;
        b=IiaZyqJPg4cFHvakHdlJJwHZ4YelGhGA8iNQ1ydJSOH62zGSDzrSalZ8iRWtugy+B3
         lsvaynNikC9dQx9AhLgINnC49nfEti2Lh/6ZinDDs9vhWOdKU2eNTMhZquWWPSwp4D3I
         QulQ2q2D8R1G9Rtnsl4o/3o8VRMi4fLaNwRmG3TELpmkQtFAu34ffgBHK0SmrAgH2oBq
         C34fzp0OdeWOmRZlBlGD7J22/a8vgXhnE/1PnYSanZP88tShbKqON+HRBnYCM1/qoz0D
         jCpbBF3OL1J6Jv5D866b/pfj7SM8UE59hrlZYEaZ80JoQX1CSwBsQGn6JklArYu/Y5AC
         +dlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678700988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=BJVBcsikjn5PEFAWn11AmQBr73rEeSJfTjKId8SZRuU=;
        b=f6TPQ8I2z1coFZwEggQYlS+m7QMJ5Nhl/gcl0/yQ3TgBaR3UmIldIA8dAVN8dkDik0
         0CufTHn4mDXkcXTcKHH/gPLRkimeZKQwpzrPjReZFUmlvIkIYCe04NiS2PnLqVXaG8X2
         XKP+agVttqMqE8P8Ei8a1R2Xkq+mQ0pCS9ARuKSz/Ti/XOX0oefgO8UzX0IkuDi34NYf
         TLfgir7dDTbksex9TSaor86yZAvbbSmDbrROjvlmX0hmiCwJhzJSKzAstE4bhUt5sRNZ
         cGVhj0VJeRFBvK9pMMBeZ47JgM3kUg4B4JpIY3MqKcUvh0Tbhcqc4tXf5RIVd5M6E3xA
         z9Lw==
X-Gm-Message-State: AO0yUKVgPhHJdmF2uB398O6kqup0cRCUFwKu2xQMtjTbgqDfNGy2278j
	VCDqadbJsi3pcrChWDUhIus=
X-Google-Smtp-Source: AK7set81iKvsOSuXo3Xb2H0ijVkCPLP4Y6pW1rDOMUK0Iu0kagjDNua5wl8gF3M9WZ2mJEn9L/4b2A==
X-Received: by 2002:aca:d19:0:b0:384:d02d:5f07 with SMTP id 25-20020aca0d19000000b00384d02d5f07mr8211369oin.10.1678700988144;
        Mon, 13 Mar 2023 02:49:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:7c5:0:b0:37b:7b50:657d with SMTP id 188-20020aca07c5000000b0037b7b50657dls3962907oih.8.-pod-prod-gmail;
 Mon, 13 Mar 2023 02:49:47 -0700 (PDT)
X-Received: by 2002:a05:6808:187:b0:384:23f0:21b7 with SMTP id w7-20020a056808018700b0038423f021b7mr17970941oic.14.1678700987509;
        Mon, 13 Mar 2023 02:49:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678700987; cv=none;
        d=google.com; s=arc-20160816;
        b=dP/dQU8SsI7ZwAtTdwXqdYllSVqlXkMFnzMqStJDJYuMQYC6mtlI13jMdEuRnyur76
         0VLpmYIw0+kBEvcZpLvC21jxZZa6dQrZ1zI+7ih6sVUC+hn1ZU3Dy4rnhCCli/3xJZOz
         cRTvWzF15/5UQUEBeX9Yg68JnitHmoa03DX6NFzeYMf1Z4gQFddqWSP/uJWNsvk9TYwf
         K+Top8rSeoTLjNJZkFpwnRuB+UNUP7AKKG+o4tSFs13A0njxmJDsY5AHOSJVUm54Z2Kq
         YBZ+YP9rXufDNYjV/AajVhXt95ftATkZcAQBfQK1z5hrwEhFnkhRsnTXl+m74fLRhZN8
         jwxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AECH0PFKZyEMTjHkgiwjGaTvNaBtToW0575sLXnAvi4=;
        b=B4/ISsiuppiv+FTT3rJpuf8PaFKeMFHg4Za8W9znJgG+HSzCPFMt2t532rpNeAzpAp
         PaZYihSTLRjqRAbv/f6KNaOeSn4Fis46POQUEtsttNBPRbmDKSGIPzFpSCMoLAzEszW1
         JBmojYzsYREQvA/Lx3/BuHJWN9V9CZww6jLXcu0DPnbHdvvhKHXtN5jHLkt/xaMP8Jjs
         Lg2wg2cvwZfUGl7e9QqXSu80JK29w2vAmRdwVIvwerdXWFCMUXsDMHGFpbvRpjPi6wF6
         e95OubZOjwmxgfBQc8nw9GoPWApxDQEEyTUSuLmus6pu6sbzqrOY20yi5oHzjwQ+FnvX
         Abtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sCcGOy6q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id z2-20020aca3302000000b00384e4da7e50si371208oiz.0.2023.03.13.02.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Mar 2023 02:49:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id l9so3555307iln.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Mar 2023 02:49:47 -0700 (PDT)
X-Received: by 2002:a92:cccd:0:b0:323:45f:681 with SMTP id u13-20020a92cccd000000b00323045f0681mr1572016ilq.4.1678700986962;
 Mon, 13 Mar 2023 02:49:46 -0700 (PDT)
MIME-Version: 1.0
References: <1678683825-11866-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNNYgP+4mAdQ1cVaJRFGkKMHWWW7nq9_YjKEPDZZ_uBOYg@mail.gmail.com> <8b44b20d-675c-25d0-6ddb-9b02da1c72d2@quicinc.com>
In-Reply-To: <8b44b20d-675c-25d0-6ddb-9b02da1c72d2@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Mar 2023 10:49:04 +0100
Message-ID: <CANpmjNN6sQ+sWBVxn+Oy5Z8VBCAquVUvYwXC1MGKOr7AFkHa3w@mail.gmail.com>
Subject: Re: [PATCH v5] mm,kfence: decouple kfence from page granularity
 mapping judgement
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: catalin.marinas@arm.com, will@kernel.org, glider@google.com, 
	dvyukov@google.com, akpm@linux-foundation.org, robin.murphy@arm.com, 
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com, 
	wangkefeng.wang@huawei.com, linux-arm-kernel@lists.infradead.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, quic_pkondeti@quicinc.com, 
	quic_guptap@quicinc.com, quic_tingweiz@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sCcGOy6q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::136 as
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

On Mon, 13 Mar 2023 at 10:05, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>
> Thanks Marco!
>
> On 2023/3/13 15:50, Marco Elver wrote:
> > On Mon, 13 Mar 2023 at 06:04, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
> >>
> >> Kfence only needs its pool to be mapped as page granularity, previous
> >> judgement was a bit over protected. From [1], Mark suggested to "just
> >> map the KFENCE region a page granularity". So I decouple it from judgement
> >> and do page granularity mapping for kfence pool only.
> >>
> >> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
> >> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
> >> gki_defconfig, also turning off rodata protection:
> >> Before:
> >> [root@liebao ]# cat /proc/meminfo
> >> MemTotal:         999484 kB
> >> After:
> >> [root@liebao ]# cat /proc/meminfo
> >> MemTotal:        1001480 kB
> >>
> >> To implement this, also relocate the kfence pool allocation before the
> >> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> >> addr, __kfence_pool is to be set after linear mapping set up.
> >
> > This patch still breaks the late-init capabilities that Kefeng pointed out.
> >
> > I think the only viable option is:
> >
> >   1. If KFENCE early init is requested on arm64, do what you're doing here.
> >
> >   2. If KFENCE is compiled in, but not enabled, do what was done
> > before, so it can be enabled late.
>
> I'm fine with above solution as well. The Disadvantage is if we want to
> dynamically disable kfence through kfence_sample_interval, it must be
> mapped into page granularity still.
>
> >
> > Am I missing an option?
> >
>
> Another option is what Kefeng firstly thought and I had proposed on
> comments of patchsetV3, actually I wanted to do in an separate patch:

Please do it in the same patch (or patch series), otherwise we end up
with a regression.

> "
> So how about we raise another change, like you mentioned bootargs
> indicating to use late init of b33f778bba5e ("kfence: alloc kfence_pool

Please avoid introducing another bootarg just for this. It will
confuse users and will cause serious annoyance (bad UX).

> after system startup").
> 1. in arm64_kfence_alloc_pool():
>     if (!kfence_sample_interval && !using_late_init)
>               return 0;
>     else
>               allocate pool

The whole point of late allocation was that the entire pool is _not_
allocated until it's needed (during late init). So for space-conscious
users, this option is actually worse.

> 2. also do the check in late allocation,like
>     if (do_allocation_late && !using_late_init)
>               BUG();

BUG() needs to be avoided. Just because a user used the system wrong,
should not cause it to crash (WARN instead)... but I'd really prefer
you avoid introducing another boot arg, because it'll lead to bad UX.

> "
> The thought is to allocate pool early as well if we need to
> using_late_init.
>
> Kefeng, Marco,
>
> How's your idea?

I recommend that you just make can_set_direct_map() conditional on
KFENCE being initialized early or not. With rodata protection most
arm64 kernels likely pay the page granular direct map cost anyway. And
for your special usecase where you want to optimize memory use, but
know that KFENCE is enabled, it'll result in the savings you desire.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN6sQ%2BsWBVxn%2BOy5Z8VBCAquVUvYwXC1MGKOr7AFkHa3w%40mail.gmail.com.
