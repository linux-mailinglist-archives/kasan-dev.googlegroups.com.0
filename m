Return-Path: <kasan-dev+bncBCCMH5WKTMGRBP4F4SPAMGQERCVTEQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id A07D6682C14
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 13:00:00 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-4fa63c84621sf166443297b3.20
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 04:00:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675166399; cv=pass;
        d=google.com; s=arc-20160816;
        b=0tjV5AQVykT3iCoDq2aUSf7ig3XaAVjqFE1gpZ0x9i4DLxsGPxf+xPMwh8Na/OUKZ5
         t1ZIyoYXlVtTRu8m8ycwkJSpxKxMqkFv/C9pJwBAa2/VujGRdiL1Yp5OE3qqGtAHymHP
         yS1EN37fsUO5JcUVkeLwM6Z0wPmxwOdnpXzzlYVHDSXzgMfp8RDcVyNVhU+q8E3ntZgB
         svx+5IK89khpxJWhHSgojEyQKBWpkUGwPM7caXXrmjvjDQ33dHQS+70UTakd3GBQAuAu
         3b2cwMY1RuA7qSiwX/QSdscdLqxcZuM5SipctD/GD+XB7gOZpLmA9kw0ef6UwE7LQCyd
         eaLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fRG653nfL1jHwgC3v0y7/koqJtZkpP7GTOiE9t8KsCs=;
        b=rV1U+kWLmPMXZVeuzdN18AtMQgYShYPKUEi/uhjrwnXlbe598IW1MvUf54LxsvHObw
         OZGorZmRWq8PNtTzZbdX+XVxmHPXPR3rf8a3Dg5YIxMp2KYctM1Im8IvNdrgFhXDojBw
         loD+pXGkI5dKPjOPQZ7nSWNc2IOyLQgUFEnphtWY1DaVCIPj8RskYMdTXyV9792ticVx
         SaX24nIQLa9v1+D+WhZeLeTZ35bioj+lLq6LtfPk7EWW9Wwb0A6HOPBKuUKyaWTVIWnQ
         i4MCpx0IYsb7Z8hG5VTlfw8dtj5l2F6A2JeEHxar+AiiWtUDpoTfHdQdck9cTLFNkPEY
         1yfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S37DVRqq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fRG653nfL1jHwgC3v0y7/koqJtZkpP7GTOiE9t8KsCs=;
        b=HhvEtRZ9fCwkh65OlrDduVR1Yv6VvSYIVCpBpjlfBGxxzb2O/VSjw+WhbNgvdGAYxa
         GU7DzwD5FNaXG6cMLIZccq36HMTdwKB517NMWsjc6kTRWzQ+pRAdNQ06wJKPDVphp+p6
         jadk9Yda2UJlqsqRzAwcoIvVnDymRQPgeGS9LHhnMKVTjGxTMZvn8fzYSPzJSAyJwc5G
         XhjbE7KH0yFtf5GLBn4QroNFLO2s70QV3wlSGvrV0Gr3vFqUJ7ORZBQPUiAEAVM/ESPs
         TxKBiAeW35WNTvIBjCDPyPvUsa6Kc/Cu+Hq3BiaS80NM69Whw5oVt1Gvg63VzR87fpET
         8osQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=fRG653nfL1jHwgC3v0y7/koqJtZkpP7GTOiE9t8KsCs=;
        b=HYLzJbJfQGJmBgdS0pX3YYQQaTnZNEOvLUxgjCsEF0v/2Ai6M3gGashucXWyX00v7h
         x0rLPKcusy10D/XClMEYD3/k5aj3y35A5iNXaKm6DepZOFDA5VoByJq6kxSNvN3Scbzo
         JP0LFo3TZO+wgQ2H7tXNwTmbqqA8ZfEFC98giG5ayNQ04QMLxsbtKFyYqEhog6qQ2xs9
         XsmJKmKsiWBTuMNOy7MMdcGduOJsg90VKFtL7HnGKpfiY2UlgDxMDb47eXeAV8xLJ3Nb
         Dg77w5qvr0JOkCep0FRZVKA3R7eeCnjPUX7okn0ntXHy8fkimYwscaYv4akA7z4Hs77H
         Ai7g==
X-Gm-Message-State: AO0yUKWCJdVd1x6jvGjPhu5ikepSXN1mQtK0BYX3CtrP29E9ik0Tx2Rt
	eRDOXbZtRX1Obed0z8RfYJI=
X-Google-Smtp-Source: AK7set/prjcbh0xpZLiHz/qf/FTX9w7L4OekprEgWaR5FUYaPdDoGDpEaxwwGj4Rz9RuKiVaLng6fg==
X-Received: by 2002:a25:3142:0:b0:827:8002:1dc4 with SMTP id x63-20020a253142000000b0082780021dc4mr539598ybx.209.1675166399418;
        Tue, 31 Jan 2023 03:59:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:7d44:0:b0:506:83f5:16c0 with SMTP id y65-20020a817d44000000b0050683f516c0ls9971116ywc.11.-pod-prod-gmail;
 Tue, 31 Jan 2023 03:59:58 -0800 (PST)
X-Received: by 2002:a0d:e645:0:b0:507:b797:f1d with SMTP id p66-20020a0de645000000b00507b7970f1dmr17193096ywe.11.1675166398816;
        Tue, 31 Jan 2023 03:59:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675166398; cv=none;
        d=google.com; s=arc-20160816;
        b=kYPuiqwUKpoaWZ9XKyxKwGPm5N+tO4hme1ijbMOBTTNMbEjXtKBph7zt6Jru4ir6iP
         v1nUkvMoO1I2LVJB52AwQTuEmALfDw2H6HXBeeKFbC0cS+tdpLCZPrfDzQXP5xPAJDOb
         Sv57CganvGzhyFWRW2tHeUnPr++cvPcxNpKxqBlG00nsY8Jkfww0//5SvsJX+1yag0wC
         2ldWM7Xum6pjzRPDQ/kkuRact1BAkReji6CEZxVq3+K7M7SezJ68Akg2WqwE7O84bS59
         eAoETLHvFuahue+/81O+H9/cvo9TRnDGyAhqspC1MGmlfM9wMksGBvtzDSySP2PVbHx3
         1Jfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JZNhUAAi0ovc+Tuqz6CKcgSZC8r4ue4xEaiyWw4VTF8=;
        b=gtdbVjkry0r8Rm8tEvOhymiFLuo4e6DFUpqfrs3cxVfG4556tjJCAdP3j5HJO1t/Y5
         5R9NAaUJMrOfu7/U5Otzox/ERoWj+hYGwQ8fFTLfPzQvYkTbE/fawZULyjUt7XEOp539
         MEsbWj0LnogduZ1hC3j6VJ9+MnpX/bN+PMq+cTrwnou+dqVE0fyCyJP5q4AStBuDLxfI
         VW10ujCLQejwc28bKV6I4mF2va1vyDougWusBv1fY5WGh5DblSJxLqkGGY+yhFbJOM0d
         awTNbRm8XUrXdEuDTmPxW4DQIBI3Lw5nbnS/5gg7NHm/vYO9DDYZ01KLu7+Ow/ZZkUIi
         Z+sQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=S37DVRqq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2d.google.com (mail-vs1-xe2d.google.com. [2607:f8b0:4864:20::e2d])
        by gmr-mx.google.com with ESMTPS id bc29-20020a05690c001d00b004fa49c05aa9si2686167ywb.0.2023.01.31.03.59.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 03:59:58 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2d as permitted sender) client-ip=2607:f8b0:4864:20::e2d;
Received: by mail-vs1-xe2d.google.com with SMTP id a24so13684862vsl.2
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 03:59:58 -0800 (PST)
X-Received: by 2002:a05:6102:449:b0:3fc:3a9e:3203 with SMTP id
 e9-20020a056102044900b003fc3a9e3203mr662988vsq.84.1675166398494; Tue, 31 Jan
 2023 03:59:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <fc73ab8b1469d476363a918cbdfe28e1388c043a.1675111415.git.andreyknvl@google.com>
In-Reply-To: <fc73ab8b1469d476363a918cbdfe28e1388c043a.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 12:59:22 +0100
Message-ID: <CAG_fn=WxZf_kfn8-G8hvoxvUT8-NKNkXuP5Tg2bZp=zzMXOByw@mail.gmail.com>
Subject: Re: [PATCH 11/18] lib/stackdepot: rename slab variables
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=S37DVRqq;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Give better names to slab-related global variables: change "depot_"
> prefix to "slab_" to point out that these variables are related to
> stack depot slabs.

I started asking myself if the word "slab" is applicable here at all.
The concept of preallocating big chunks of memory to amortize the
costs belongs to the original slab allocator, but "slab" has a special
meaning in Linux, and we might be confusing people by using it in a
different sense.
What do you think?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWxZf_kfn8-G8hvoxvUT8-NKNkXuP5Tg2bZp%3DzzMXOByw%40mail.gmail.com.
