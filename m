Return-Path: <kasan-dev+bncBCC4R4GWXQHBBZ6Y6D5QKGQE5YJUR5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id C6EB82848AD
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 10:35:52 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id d21sf6626182iow.23
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Oct 2020 01:35:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601973351; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2VgBfWaH4yXxykvkzqLp8BjKppWaks5KItleSdW5aODMITkg5Z4dg9A0u5jQ30R3g
         wMKug//WNFEA006cEWxVvsOCzUiK1OrFavUpYb7sNnLP4JfYboVD3iNlx7KC6wtKlEsX
         hY/G5klOwO7bkXCBanaMAQxB2wUe4u+kzfD/wLMn41L8xgi9l1herdlNWmw47e2z2mnQ
         ZtqkhE9sGXAVsl87Dl0NRslrdks/MQf9FpsDvLj7Shklj1s2+69YeQk6zCnfdwrDy51N
         4b29W058aUwXOiOamVAaMt6G/GDw5D0biS/M4+IaP+831v+sUJ5e0JW5jiMJFKqzF/6E
         XHWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=b2kBgSh6a39YqNdW+UF5Uqd9eFJLCiaZXsS7OCP+4Us=;
        b=f5yBXkwnR09mHwjaj8Bn6/h39HtFmTydTJeDpKwQJmeI5n4KeicbRz8PsvM/pg01By
         E/Ac1gdmpx2lUIKVSXgq9Q22vh7oaFt6naAIohhGd8I3UVmubJi8nK/05cTWPVTsYuGe
         csKRSgvYjcz8Fl/GHNRFUgobNuiy1xaTF3ZdTp2TMeQhYvQn9h7T8jGUKPjg5oHJt1qC
         oc87clzbSuPLdadIjA/GuaFkJQRC8imfxfECsEnXQGwi5N3VHa/x3ija+/96xxr2uG6d
         OAJ2wEWVjpzp6bLyy+C9FetEjtj0xuRZg1qa/UPUiittITI2umiHcLmMgg4JsAxK/2Y0
         VyxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b2kBgSh6a39YqNdW+UF5Uqd9eFJLCiaZXsS7OCP+4Us=;
        b=koNIlEutnj5oGQrKFjCm9oEP1dkkgD4/jcGLVcxSzNPTwkF/8Vgqe6SRq4q2X7nRh5
         tFBAxHjaoY/HCy+qF3Lr1FVSojsMyv2NiTijD6fpT+VN+XLWAk8lE8ZEpiyMgnIlxpoZ
         tINOIA84ZCGqnlgPoEeHplKaMRIK3dxU1P9u+CiZeUNcX0XG1VmwJ9MY+oX3HJFiQMJ5
         gF7XmyHI3aGNyvvvu/o5GgYj5HMhE62RanZv3Rxxy7ZCDx9FC61fOAYp9vK9km+DU02M
         P7IHHbJAv09VPoAlqB0jB5eGiTnQiXDToiT6uYnhNgSfE5Vj55IbSVv2A/ymnnx50Yaf
         MvJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b2kBgSh6a39YqNdW+UF5Uqd9eFJLCiaZXsS7OCP+4Us=;
        b=jHdRJncRnf5Sbs5I7Dt2ijSJXamfWyBokWtwb/p643aP6xCTTJFFK+smOG3pB5VXrP
         tgdyT3iH6JwTq33m6c/I8XHxCYFOPSMRPSHCYSYMafeII6QdE3rqENQsaJ9D2+uvovRF
         J5s1/tORKz5lBgmYGlGspNKD7ztmiD+O7E3eWYo9WnTT/keyTMNv7hHTPzFURZsCsiku
         55Y0pnUh39/550jAuLsFek2fdDXry8vNBinrYdaE7CXYhk39cv6DPRHLm7SFon6zPLUH
         znJVdBAtPn1P2LJsfXXRFYpOxN24cuEMpds5Rk3qL9QoimG0wN9oKbpJU0Rudv+4ryOz
         /Zzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sJYLwTW9pAZDl9nReXEsJiF2TFYrPIxWdO76JFcRMguySCdGO
	CUAmTP/ZdsKZdLGwFs6cCfg=
X-Google-Smtp-Source: ABdhPJy7sGrHfCI1NFPDWGIlWLlCitGr1kA0HvuKFzy2HyMtMtXoAYtunx77uVAK7+QhXyciBh1kcA==
X-Received: by 2002:a92:d44f:: with SMTP id r15mr2725219ilm.236.1601973351253;
        Tue, 06 Oct 2020 01:35:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ca8:: with SMTP id 8ls1651659ilg.10.gmail; Tue, 06
 Oct 2020 01:35:50 -0700 (PDT)
X-Received: by 2002:a05:6e02:925:: with SMTP id o5mr2765450ilt.20.1601973350845;
        Tue, 06 Oct 2020 01:35:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601973350; cv=none;
        d=google.com; s=arc-20160816;
        b=zslhHylUcAqj5CEwsac+2ah0AQZGBQfhZEf6VXg9OZ423zbtJpT3cspFeeDCaexV2h
         1bsMGc8e0IPxc4ZO2z/ZkS2S5NIFr08mmWZtlA+ptvvXfgDG9TqveWmqiEwEWsrCY4DM
         xoIJVzsiPlY11J85kmKaPljrU8l5aiQXUxzMEambJY7C9CcAP2l9etQlrv2XS6k1vwTl
         GALq6YHMJj8jtXj7S96VLoeEHzJrzCTpUCr4+WHKIGYd7A/yxybuVN4aIDyjuFcmfAJd
         HopOR/S3O4Ylvnx1VW5+3D3N3RsviCEYeBlNTmRLWetUVWVeiowMoAeByBs6YROHlyRr
         b2IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date;
        bh=RFesPh/TNVv45QUUwmEg9lGXtkytEHe7dV2VHPbQx3A=;
        b=M/VMre3K98Rehn6FK9Avx09d2SY1ahttuytFHmNEm2Z+7ArrLqJoyxwGjNxaC9Un/E
         giNmkaPunHCzDBw1hOK++xi7Z8AcqJozakkEC86l/0T23KfxhWXMQPQ9EaZ5X+d+yc2B
         fCRHX6a1x/io8wtod+6GmFMUlOfY1CdVGILcYAKJDgjhWmirnXJ3hR/YratrqoTRI5jn
         b/DiTPxLblC3RmdUAP3VMvSSoYyrmHxeFny/06tgTbPWVHR7Gzuy6YTEMtcMii9bStDX
         js/dgnFuEO96n2RZCP4NTYqdyKT97Hs0NAXSf5sB+f5Vx43QaKHsM/TiZcswRKCmAVmm
         IzHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
Received: from gentwo.org (gentwo.org. [3.19.106.255])
        by gmr-mx.google.com with ESMTPS id y1si222895ilj.2.2020.10.06.01.35.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Oct 2020 01:35:50 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning cl@linux.com does not designate 3.19.106.255 as permitted sender) client-ip=3.19.106.255;
Received: by gentwo.org (Postfix, from userid 1002)
	id 7989E40ABF; Tue,  6 Oct 2020 08:35:50 +0000 (UTC)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id 76A3540ABE;
	Tue,  6 Oct 2020 08:35:50 +0000 (UTC)
Date: Tue, 6 Oct 2020 08:35:50 +0000 (UTC)
From: Christopher Lameter <cl@linux.com>
X-X-Sender: cl@www.lameter.com
To: Kees Cook <keescook@chromium.org>
cc: Matthew Wilcox <willy@infradead.org>, Jann Horn <jannh@google.com>, 
    Alexander Popov <alex.popov@linux.com>, Will Deacon <will@kernel.org>, 
    Andrey Ryabinin <aryabinin@virtuozzo.com>, 
    Alexander Potapenko <glider@google.com>, 
    Dmitry Vyukov <dvyukov@google.com>, Pekka Enberg <penberg@kernel.org>, 
    David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Masahiro Yamada <masahiroy@kernel.org>, 
    Masami Hiramatsu <mhiramat@kernel.org>, 
    Steven Rostedt <rostedt@goodmis.org>, 
    Peter Zijlstra <peterz@infradead.org>, 
    Krzysztof Kozlowski <krzk@kernel.org>, 
    Patrick Bellasi <patrick.bellasi@arm.com>, 
    David Howells <dhowells@redhat.com>, 
    Eric Biederman <ebiederm@xmission.com>, 
    Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>, 
    Arnd Bergmann <arnd@arndb.de>, 
    Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
    Daniel Micay <danielmicay@gmail.com>, 
    Andrey Konovalov <andreyknvl@google.com>, Pavel Machek <pavel@denx.de>, 
    Valentin Schneider <valentin.schneider@arm.com>, 
    kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
    Kernel Hardening <kernel-hardening@lists.openwall.com>, 
    kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting
 use-after-free
In-Reply-To: <202010051905.62D79560@keescook>
Message-ID: <alpine.DEB.2.22.394.2010060833000.99155@www.lameter.com>
References: <20200929183513.380760-1-alex.popov@linux.com> <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com> <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com> <20201006004414.GP20115@casper.infradead.org> <202010051905.62D79560@keescook>
User-Agent: Alpine 2.22 (DEB 394 2020-01-19)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@linux.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=softfail
 (google.com: domain of transitioning cl@linux.com does not designate
 3.19.106.255 as permitted sender) smtp.mailfrom=cl@linux.com
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


On Mon, 5 Oct 2020, Kees Cook wrote:

> > TYPESAFE_BY_RCU, but if forcing that on by default would enhance security
> > by a measurable amount, it wouldn't be a terribly hard sell ...
>
> Isn't the "easy" version of this already controlled by slab_merge? (i.e.
> do not share same-sized/flagged kmem_caches between different caches)

Right.

> The large trouble are the kmalloc caches, which don't have types
> associated with them. Having implicit kmem caches based on the type
> being allocated there would need some pretty extensive plumbing, I
> think?

Actually typifying those accesses may get rid of a lot of kmalloc
allocations and could help to ease the management and control of objects.

It may be a big task though given the ubiquity of kmalloc and the need to
create a massive amount of new slab caches. This is going to reduce the
cache hit rate significantly.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.22.394.2010060833000.99155%40www.lameter.com.
