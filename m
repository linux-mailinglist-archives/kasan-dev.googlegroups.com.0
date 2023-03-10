Return-Path: <kasan-dev+bncBDW2JDUY5AORB2EAV6QAMGQEWVTA45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D03E16B55D2
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Mar 2023 00:42:33 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id x23-20020a05683000d700b0069438ae848csf3083139oto.21
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 15:42:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678491752; cv=pass;
        d=google.com; s=arc-20160816;
        b=EbJbeCliZK0QTYepWEpQBVsWNMt06gUCAKOy5rmRyoyITl4dNYexjxZ2cgQnEbggge
         IcEMhJYNKlQgJXoOaRFg+tlTK2STxlT2nGRgD2ixrfGWatIR57sgxKlCbVXvPoPJs8zA
         OGSdO4LN22L64x5DtBU+P67qFrNE8ZJTOzfnJYSaNLOfAFbcP6FUrs7UQsLfUXhlcHHa
         Ct/KH8bKRemjdqcuo+W6/VBErKk70Cd+/EwAgchsR6aBhRfvO5+Wm06BjAGsdWyp01BN
         CJmX12BIZtKU5Sz+uVtyXo0J5Je5TpiRDeIZQV4v0B2qU0VPePweha6ES5y+NhoDV9aD
         Pe+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8KHCm5MefTsC8RNvldEdzYarhzgSHqJCDfBKzG+Okeo=;
        b=DR8Q/9oxGETsn6yt46UKtXPBp81zEf0FkeTTrwLezTJt7uYJjMkkhMJoMXWpznJyHE
         RlhB/QLdVisBEdOC7n5Kcc2Z1mKyQ0gaYxu1n4OyV6IOL14OgXItaIHArY7YPO3pGUgo
         GV5AktMYpo9Uzu369fLqbGQjJXFt+9BwmBta2cGSoTomwM+ZBXtNsjWWXLEBisUfucI1
         Z2YhKPLEb6KTtoHhCLRiS+FGNopOR+dZhS+yP2L4cQDl7rb5oTxDwaTkOK1F2lI0EkKV
         qi/fV21kYN2mQW6UH6PcykMyEuzc9GDx/12zGc85DUyJQfnR9KZZbdzy4jj/+jSj6z2R
         HNMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Ox7KVgJB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678491752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8KHCm5MefTsC8RNvldEdzYarhzgSHqJCDfBKzG+Okeo=;
        b=JUBczW82HI7flp3hYTc+hebM1V50mWqaruDNdHY/huACdPKU57VR2lsg0kE31p6tzj
         s3/K+RIReXvDycjDGlPb5tnZe4H5epbGDyocptKGTGewAXJscazvU4K5TcG3MFP+n6TZ
         dllKIGfW6tyFWBlyxx76ItlCMM848rKVEoW/4/tr9m6DE/QROsnBg0llZwc1D4zXj5tI
         AaPruUoar+NtPTo3nvbkYRdEXLjoM9CTwbRtMplZ3H+hlDv3sTiW05pmyT4SDP2OVANM
         mCnDc6V+V4d4lKrjea1JFlpS5XfR6O/mp2C7SXjzgOeP8ELfhnD9DI4T1NJTN6mdhclH
         kxPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1678491752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8KHCm5MefTsC8RNvldEdzYarhzgSHqJCDfBKzG+Okeo=;
        b=hjSIfdeAY3udFKZZptl5LDZYAPCpEKZRwdcP/Dt2NkifdvospkpKStKJezG05LKj/b
         P8r1tIotc6qeHzSPozbAOjESbUtAFFU4rpYBwII0cr6zaW/ThILiZ8VlqvCcn0cRB7yn
         L4vVFAsUj5tZbMjUfRcn1kE6CU6BT2TvUvt+1eEq0HTk24Nb+sAuP+fZvLTdNIQc2/Qk
         8CmU6FEZ31cs5wrffojUBC6EjrzYgybauZ+BaHuB+72BXCCLguXrn6fac8ktRpDxawIm
         riR5H3XIWPzqrDQlbE0I+gqbT1ZxLzGbkQ+U3FRIovPPsTdtBl9PwR9xSuQPBD4fw+WG
         VAGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678491752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=8KHCm5MefTsC8RNvldEdzYarhzgSHqJCDfBKzG+Okeo=;
        b=ELtUIQIzgyNS0J8koNWWeV4UPOdRRSQlTyQ+qHTfOfh824PiGj2FMDPCxqo36CdxUK
         7sXZkY5f4chvP9voZnX7MjiLzfz7TDiO740W3VqNWICZuhW4RUgtFTebc3thZEH0ciiq
         F3bdFbYsQjI4HXerq9GXkJJDLoor2l7i1McAmRV5Om1Vr2NY6+5ZKCFlQOcXFwnQEQDM
         nss/O5nFOJlZMXEqAhaEQ8Y7rnX3mU6demmr3/e18+4m+4Y8tHyP4MuGftvwB+bqL2/W
         EzrxigOvGkf2PeVd8TWhh5hbVzrY25wRdq+4xWp2kyM1bf+u3m43ajixWa0UY7f0ZEmN
         +j1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVEuk6Zw/wyxAn9pDjGbmvPZ4jqEw7mir6B22FCUbGAQpJ1NXW0
	e+OQd6QSkebixIIK8Rnd3Cw=
X-Google-Smtp-Source: AK7set9nDK52uckfMxnpiy4EunA8h1kJJtnADvSxY1JqK4EclwfCSl+Iff0jmHXKZubN+xKYo6LY9Q==
X-Received: by 2002:a4a:d798:0:b0:525:2b47:93cb with SMTP id c24-20020a4ad798000000b005252b4793cbmr9241038oou.1.1678491752159;
        Fri, 10 Mar 2023 15:42:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4c03:b0:176:5561:8f44 with SMTP id
 pk3-20020a0568704c0300b0017655618f44ls2734921oab.11.-pod-prod-gmail; Fri, 10
 Mar 2023 15:42:31 -0800 (PST)
X-Received: by 2002:a05:6870:d10f:b0:176:36c2:ed22 with SMTP id e15-20020a056870d10f00b0017636c2ed22mr16808117oac.24.1678491751627;
        Fri, 10 Mar 2023 15:42:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678491751; cv=none;
        d=google.com; s=arc-20160816;
        b=qr7BYqttpzbKhtDkYOste/CmyEI3jfDay4PuX9YHroxpD353Xpp9U4as6cdKdvNK9D
         jY6UZbmjQRRVyqB6ORw4nRNsvLz2LHoA/TR2RlKqP/i4S6G1LmczEoDxOk5h1BZtdPma
         pe3JyeL7nsy0SlksHO9tQk6xxlOq5uJFRwDHcDX9XO8jANUvqjFpFlE9a60QOqnu/YOI
         +RQz8dSIgxKyvjDjpGCQFinFcmixcF0Jh1xYxM2AApGdhTjHSgncuQPe8yyQsdQG63dW
         ADeXJkcjlH39cUabzaB7/FMfGDEfhhWRZPEQ0Mqsg+x8CBo3Al7m8hFHuIZ1JpcGpe9H
         fxcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wv3F+wk4tZoGruUyDBY8Tbrsyth/dVYvCaYEldiyh3Q=;
        b=V4OFZWbIxvXCBKLz4+KMrWF9K2j/DPpJU6uxXVYacO4N7l1O8LDSzkU9AzBu8QhbT0
         VB/MviKnGzwpLwthVs4ycAejYHBIvOZRwR4NIigB5E1KMYbmY0j9XpQw430aAPyn6vOP
         wL4eoLB4i2MHjUbb6cJSGyqe5aQWxt/zjgR+pNLv4795drDlDbJd8HkahMwI9lwh+814
         U4ANj+0sPTZCKt66M7mhIXz2nnafbuB+bnZECbHSEyByvxUIccGSq7KSwSxHYSY/WIN7
         eOJth/NugYc6t2MWGSuAjQH/wlRi+Af4Rmqv2qhYVrhZTl6wvtB6xpsRnvPmyH3VcWQO
         6gmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Ox7KVgJB;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id oa11-20020a056870bc0b00b001762cd3225csi240647oab.3.2023.03.10.15.42.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Mar 2023 15:42:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id me6-20020a17090b17c600b0023816b0c7ceso11482293pjb.2
        for <kasan-dev@googlegroups.com>; Fri, 10 Mar 2023 15:42:31 -0800 (PST)
X-Received: by 2002:a17:903:2581:b0:19a:8bc7:d814 with SMTP id
 jb1-20020a170903258100b0019a8bc7d814mr10009307plb.13.1678491751206; Fri, 10
 Mar 2023 15:42:31 -0800 (PST)
MIME-Version: 1.0
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com> <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com> <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
 <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com>
 <Y/4nJEHeUAEBsj6y@arm.com> <CA+fCnZcFaOAGYic-x7848TMom2Rt5-Bm5SpYd-uxdT3im8PHvg@mail.gmail.com>
 <Y/+Ei5boQh+TFj7Q@arm.com>
In-Reply-To: <Y/+Ei5boQh+TFj7Q@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 11 Mar 2023 00:42:20 +0100
Message-ID: <CA+fCnZdFZ0w33GcUWRfWhNmYkhszQ0gwVKGeY0uSOzBEJJe27A@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
To: Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>
Cc: =?UTF-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	=?UTF-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang <o451686892@gmail.com>, 
	=?UTF-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Ox7KVgJB;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033
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

On Wed, Mar 1, 2023 at 6:00=E2=80=AFPM Catalin Marinas <catalin.marinas@arm=
.com> wrote:
>
> Yes. I'm including Vincenzo's patch below (part of fixing some potential
> strscpy() faults with its unaligned accesses eager reading; we'll get to
> posting that eventually). You can add some arch_kasan_enable/disable()
> macros on top and feel free to include the patch below.

Ah, perfect! I'll send a patchset soon. Thanks!

> Now, I wonder whether we should link those into kasan_disable_current().
> These functions only deal with the depth for KASAN_SW_TAGS but it would
> make sense for KASAN_HW_TAGS to enable tag-check-override so that we
> don't need to bother with a match-all tags on pointer dereferencing.

Using these TCO routines requires having (at least) migration disabled, rig=
ht?

It's not a problem for KASAN reporting code, as it already disables
preemption anyway.

The question is with the other kasan_disable/enable_current() call
sites. But as within all of them, the code does either a single access
or a memcpy or something similar, I think we can disable preemption
for that duration.

On a related note, I recalled that we also have a bug about using
supporting no_sanitize_address for HW_TAGS KASAN. And Peter suggested
using TCO entry/exit instrumentation to resolve it [2]. However, we
will also need to disable preemption for the duration of
no_sanitize_address-annotated functions, and I'm not sure if it's a
good idea to do that via compiler instrumentation.

Any thoughts?

In the mean time, I'll send a simpler patchset without converting all
kasan_disable/enable_current().

[1] https://bugzilla.kernel.org/show_bug.cgi?id=3D212513
[2] https://bugzilla.kernel.org/show_bug.cgi?id=3D212513#c2

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdFZ0w33GcUWRfWhNmYkhszQ0gwVKGeY0uSOzBEJJe27A%40mail.gmai=
l.com.
