Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVORGIQMGQE5FNPO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C5094CDBF2
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Mar 2022 19:15:24 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id bj8-20020a056a02018800b0035ec8c16f0bsf4905311pgb.11
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Mar 2022 10:15:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646417723; cv=pass;
        d=google.com; s=arc-20160816;
        b=lg6HCal2h98mRVdS5SpGo0xdEMYm4frdhoTdixYd2gnq6eFCJEIp0Jf5wwJAubs76d
         CBqrK8gF34PlO+/eHI3BG7FDrMAu7nwxm5SYQjtO1CNJAEeM1BDc67cuAwMvUheedjVQ
         J79gCrpnJMzQmTCb4NJTzCEkchv8UBfMWCUhkcAzwb8beJy9w6c+6/x2qVKWoBAK4MF5
         szwGVaeMu2UQ+n6OiwnWSsAwoP+XXJNhaK/A8EiKfRJBRnrYlpw6AoYxxzBlDC2mTd0E
         /WlDR8OK2Rrd9dhsgrCo+om1+JAY7v9T3OasWZmCE9dA7WLjh+fvPpkxdF7ElZItWeyk
         Zibg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xSPi9ndv6DP4xB3w2G0GwsR8lEDpLneN16ridTYRSvY=;
        b=IZuO1V9P+S4R74fInwB34+X58hpB12YN1kLXPqMCVmabHmuhumS8xT+WDlDqkimsqI
         wcy3zTH3z+YHoBvHCNtBbd31hJn1GpcVvXCDmZqDIK1G+kGVWnvjOhjqym9rfaZ6Om0+
         /CPDXU5/5+fEFyNn2HCKdx4GgkHq8XmosmImdIgJGsvZesW8e4zCtNYcMI8LHW6swXHR
         UTVkapL67+1b2Hnul0n2pQvMb/yP1O/AHRy/CyflGEKyfQ88pOE07AvM503ah95YOX9b
         WgssMDFNMlOg4GZ2ehNZlsAHXnof/iF1Bce/OGFReMUQG5uCe7LJnRAi+MY9OH8NFqCX
         6hUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n0vwTpqy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xSPi9ndv6DP4xB3w2G0GwsR8lEDpLneN16ridTYRSvY=;
        b=sXvhh2ouwtvUxgwFwaFN1chfN8GunMudW8xMFRi0JzfZOiLGZZasTziB6U2j/6XwTz
         XQeMDRnYbf0yjk40UOXtPCvC0l5wTGBpehYoHgDQA1D+RoWTZgfoQg3fug49l1M4WxRp
         Iv0FyApmuli86/y7yX0X2SAQm5pi4uQiflkHOjtCfYCVZOE7ARStUK4jPryPP7ij6eHh
         dd87lXCa86RL4AvbpybJooenJzYkz4fxEKUctB5CKPboFxBykrEfXf41qXpYPrJ1B7SU
         nNBwEFD6FgcykPm3d9Vzzegb0MTEkOWk+8CXhA61MsXnue3U4rYd87S2HM5Gg/iWnxn6
         E5YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xSPi9ndv6DP4xB3w2G0GwsR8lEDpLneN16ridTYRSvY=;
        b=Gai1QV33rQcXi4OcFQakW1qzgiA8IjONUuUtXZZEPG3VByvfy7+dTZ+COLb9GWPA6t
         18LcmlTwvuMFWU7+YCo9GtyxpioA3hqYv6eUPPOfEyJ/IvmASVqdhfR4B8HIVYFGIu4H
         gYoCMyZw1UHVW4i+ATsoIC42wGU/lZ3Q2Wd5ZNo8+b2fqIqusgstzbnosYgi4TjZU2YA
         BE37/B+tzpk7SNpqD9pg3kw3wqOjbwjF5c6HLyUY+APT1aikYTUysW0Pt5DzQ1SiP92G
         anH+uGYN0V6JvVRuzfvXSwTNz7V5KiR1n709qjQ2zZeRs+ihahalwjbFceF4gKrsg2rd
         Sl4w==
X-Gm-Message-State: AOAM531RHH2YfBjuTRLJiypPJtyj8x5vpf+C5/Pkmvn5mSQcNzQYULF+
	oFF2C6g5BjUzdyycywJ7BIo=
X-Google-Smtp-Source: ABdhPJyKePhT5xL9MjdyZ7KHMmReth9SbTAEH+fe50SrXYgqV5YAuyhoNFN+WToFcYyCqd8oJdD38w==
X-Received: by 2002:a17:902:ce8a:b0:14f:fd0e:e4a4 with SMTP id f10-20020a170902ce8a00b0014ffd0ee4a4mr43175417plg.47.1646417722818;
        Fri, 04 Mar 2022 10:15:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecce:b0:14f:d9c5:79c0 with SMTP id
 a14-20020a170902ecce00b0014fd9c579c0ls5058511plh.5.gmail; Fri, 04 Mar 2022
 10:15:22 -0800 (PST)
X-Received: by 2002:a17:902:b485:b0:14d:77eb:1675 with SMTP id y5-20020a170902b48500b0014d77eb1675mr42198904plr.147.1646417722203;
        Fri, 04 Mar 2022 10:15:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646417722; cv=none;
        d=google.com; s=arc-20160816;
        b=QmDBRNLc2y72d2hqs/+vlxzDe+XlYdqGjiWtBUm1CS88vW1KkP3/vFcKgrq4QPImUJ
         eVxU3IJQ7N9r4dLQZ0b//XfEFLzRRS+S26q0+we0Go4HhUX5UCaSAcnBI+cmVLnAOH8g
         8vgkIAs94cYM9onN0gLYfhhurJYxPxxgphsz+7QmquMt8+SJhJx+LKSnK5zQAsS4H3JK
         O6kanxLwlCOOVxe0g1eXukyjVLFz8SI05UYHZxanRjJI3LgCzk9LpYRyXlfbA+cBLS/2
         95jwFXNGrggEfv05ME8ZEME1npOtpnPW2VOb9jylQ7dSGNQd5j3Pt7mJIHDQ+XfUp5uO
         x4kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KUxn8JdSU+FAiz+Yz45U+PNiIfEjVkTsbOETITn3KvI=;
        b=OKy8kn7VhtRapDG0jDbM2JYBRMn+pYoS79P0PdyJ7HLmrM/y18EoelyshBChpg0QA+
         N88KGsaLq+iecvzhCKmFvjhHbxsYc+OfpBjvJMw3nA/+8KEliBkxDxeQbPHaflseNG6X
         8O6b9de89OekjhiuCku4Ux+aCGUIIlKtdIZ169T6NPo9d0f0SoP2FJF7cnwcjDtTiOuO
         ygqI2JmYcbZBHvJwCqjdQhGu9hffvjUX4qhbAe1Y99NLjpFuymJxXktshby5Eu5L1z6f
         LhrtE7WH03nTTYoNAe9HHf8ZQFeyWrYsqmJlD2mm4FKYvSa3bwCVyk4Cng6gSSPPZ38J
         V5Bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=n0vwTpqy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id jx5-20020a17090b46c500b001bede07ed67si166025pjb.1.2022.03.04.10.15.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Mar 2022 10:15:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-2db2add4516so100836267b3.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Mar 2022 10:15:22 -0800 (PST)
X-Received: by 2002:a81:5549:0:b0:2dc:2826:e6ee with SMTP id
 j70-20020a815549000000b002dc2826e6eemr11829422ywb.327.1646417721537; Fri, 04
 Mar 2022 10:15:21 -0800 (PST)
MIME-Version: 1.0
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
 <CAG_fn=Wd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMRZ_3w@mail.gmail.com>
 <CANpmjNPBYgNMzQDKjNYFTkKnWwMe29gpXd2b9icFSnAwstW-jQ@mail.gmail.com> <7c14bb40-1e7b-9819-1634-e9e9051726fa@linux.alibaba.com>
In-Reply-To: <7c14bb40-1e7b-9819-1634-e9e9051726fa@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Mar 2022 19:14:45 +0100
Message-ID: <CANpmjNN5RN_BtOeJx12iEWs5tZvk7yHQR39Ms3JQC+nzEA-7gg@mail.gmail.com>
Subject: Re: [RFC PATCH 0/2] Alloc kfence_pool after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=n0vwTpqy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
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

On Fri, 4 Mar 2022 at 03:25, Tianchen Ding <dtcccc@linux.alibaba.com> wrote=
:
>
> On 2022/3/3 17:30, Marco Elver wrote:
>
> Thanks for your replies.
> I do see setting a large sample_interval means almost disabling KFENCE.
> In fact, my point is to provide a more =E2=80=9Cflexible=E2=80=9D way. Si=
nce some Ops
> may be glad to use something like on/off switch than 10000ms interval. :-=
)

Have you already successfully caught bugs by turning KFENCE on _in
reaction_ to some suspected issues? We really do not think that
switching on KFENCE _after_ having observed a bug, especially on a
completely different machine, is at all reliable.

While your patches are appreciated, I think your usecase doesn't make
sense to us (based on our experience). I think this flexibility is
nice-to-have, so I think the justification just needs changing, to
avoid misleading other folks. Please see comments on the other
patches.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNN5RN_BtOeJx12iEWs5tZvk7yHQR39Ms3JQC%2BnzEA-7gg%40mail.gmai=
l.com.
