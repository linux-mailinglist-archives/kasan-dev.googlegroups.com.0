Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXEQOBAMGQEGCD2YSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8433232D597
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:44:04 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id x20sf6913663pjk.4
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:44:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614869043; cv=pass;
        d=google.com; s=arc-20160816;
        b=FWyuR2Mr/5r7xYQ8izHwLiBURCSdEzkjizBMLDCXuxpbqlW/oAyqotzbpVMzWMpT1h
         BNWcu1gAFj6vwAPYQKhkNn+VRIY59T/Ji1wOHrz6gEQipvHCtsYY66htv03Izd1lpnm0
         uNCjI0f4qwZ2eh114KBX8DtUWq309UUUo5bcMmgHZATAsB09jWFKW9jANrgpm8SA22y7
         ip5IfUtNAZkivV08y1WeJIKSy8Jr7raMmaCw2o5vZ/eFdR9v6Icpqi7QbraX+Ge/rnm7
         Xp9/9u4yhQEI/6BnmdGZRtQx2yLHq8XMyupeZaVustqLq8OVXixJ+kkiW0+EKbr9BYR7
         Uq2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vw5gLh/9txGFu/fesV2yN/RufPjGNsnarSrC0PNaL4k=;
        b=OaR1FV1BvpydzSqSGCgux9yNjxfTvVVtcFFmJ7AmqfXXe7QM42S+5xYRhnQm/hez9r
         REiIzebYgnL+q0INyPHC18fxebWqkGZRvjo4neg8dovHgEPWOYLIeVJF9dVokQRiCqYY
         XX6T5SvDivgK+BcFvUGv5pTGuo5dFV0UpvNOt/HIC6K9dX/nw50hNiDBWr2BhmvkzWZ+
         yg0jD7eZ38ytzu+nhMbTBWSZViKUwOc7KOKhggEiFVbesuj8iUpdr0rXLaC3JFEac/df
         LWC+OGmtJdia043bZfc+tP0U1fwe7YkzOUSqTXXcZYbtVAhUKVnl90jGL9R4/TatDw3z
         lMHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y27+nz8+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vw5gLh/9txGFu/fesV2yN/RufPjGNsnarSrC0PNaL4k=;
        b=WkDyHgrKPaatiPVIGHvXlath6zzwn5ILhBCuDoMrWkS2K7hiJpx7WvgTIgFiDKIZSr
         7q0vzYNdcQ8zu6YEXgkVEeuOpj9sGtn580GZ5WpTJE8Zz2sEHcf2VIKfMC9y5nzLEjbP
         aDYbMyJ3GOs5vh42QBW0SQtxihMp9uAO6S4a0ORzSn/t0A0HxEiRsnj0r9zq5af4kdrT
         JMIOhssgzPwKPJlFzL8dOKTCluV/HhxqnEcnQRiRKEBMYrkZFbsInp5Tf4WIDgSpF5l4
         760APPp17tGa6/7wEhCsnXcCsIo+8QYOXqs7dRZbiVYg9IToK6jK52ERF0VHBinR9ZR5
         BMWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vw5gLh/9txGFu/fesV2yN/RufPjGNsnarSrC0PNaL4k=;
        b=QODWhRsdCEZ12BXLS7epxUJG59M8vtjdY26/YA2vMpqqftUouqcDTjnx86SA7FZiaZ
         aNotJekao9bv0GfeF5x+1MCtCeJeCmsEiLuhY0cmneJkJW0bXTuwZrwonJbvpvcYZDS8
         Rsp0HBSE6s9QP1xaURu3MuvUzGaa2dhOI3R1e2v+E945ttDKdB41H9JM4U8e+4rbkbeh
         hLf1paf4KleTuaYYLaLjxpuPRfr7GDey/E6OR4ffYw++0TtKxPbgY/KfPUp4M94RFi/Q
         wysGMnFGJ+dIUlRhYfxip/i4Wf0ucFSEnK/PrgPsk+1lmM5Z2VJruMIfWVmCBjXDdVHK
         ST8Q==
X-Gm-Message-State: AOAM532Rk9X1Ognc9T6pUeIsXepVDIjuGIuMEvqfJBwcCq15ASmSToJ7
	SKhiXM+9pyc3X+vPP2m9GK4=
X-Google-Smtp-Source: ABdhPJy8ReLTP9zKvSYRxlU27pj5QeI33NcrdL4gJS+DXq0MYY4cOLgqBmZRwZ++dIsGL6qsmhFlxg==
X-Received: by 2002:a17:90a:ab09:: with SMTP id m9mr5220370pjq.122.1614869043139;
        Thu, 04 Mar 2021 06:44:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba17:: with SMTP id s23ls3474762pjr.3.canary-gmail;
 Thu, 04 Mar 2021 06:44:02 -0800 (PST)
X-Received: by 2002:a17:902:b08b:b029:e4:deb:69a9 with SMTP id p11-20020a170902b08bb02900e40deb69a9mr4079977plr.35.1614869042534;
        Thu, 04 Mar 2021 06:44:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614869042; cv=none;
        d=google.com; s=arc-20160816;
        b=dSHHm4tvXhEQr1Y9uS9rJ8HpzLID709Mzes519tP5GcDLQOFC1urRUR5B1ObEEHyVC
         Smsj1oVPKguwPSQkAGXG/yB32rppbDyOarn7tQNd/yvs/wXQO3VyxbnN6kEnaM2woE8V
         ssdFCCUtCvUacFNMUwAPDgLeVUtXVhV3ZK5YxbJfWI6EmNP3cEDwnbEern30UM5FkpPd
         UsneNKwZYEnFq24AgyGCd2k1T2hhbTNv/SCWI+HrknIYLifYNaz5A9UIbh39ob942blp
         OyKjs9CMl0ce5Iq8ZY4GSr5WoW+b0VelCNH/2KiKRgAGz0/P7hGQimfWo4zXs1HZgnLd
         K48g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2LI2p/if8xEFXIC8BcXuJlVrjYr1uk8YfFxNJskajiE=;
        b=m4NxAoIIJh0k9ajSVu68zU17B/7we79EPFGajYs/OyDQbo6ZG3aqnNvM8UF3f1lWVs
         3H68tTwkHPv31OkL42CmLM95HIlja34yZEPZiGJNF75wM2gJa1zHqkHSBWsrJqGM9405
         8hSxPgSEYt7Srq5k4hpcu7hu/9e2O2JmpJ7X/H5mSll0HB2OFb6p4TxtMIcuRpCizACI
         zx6gjKPWgfAYnnltLmFsxwQDOev3nVSzvasocljiqH+EO/QiPyJ6BtuU763EAe9XM7Yz
         hl7E/+P89Opo2bx3GmKEzhJVVSrfOO07zvGVSVjRACKaCGvdiI1bahrWSHSp2yZ+v4sx
         gQcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y27+nz8+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id g7si767573pju.3.2021.03.04.06.44.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:44:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id e45so27410957ote.9
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 06:44:02 -0800 (PST)
X-Received: by 2002:a05:6830:1355:: with SMTP id r21mr3742038otq.17.1614869041680;
 Thu, 04 Mar 2021 06:44:01 -0800 (PST)
MIME-Version: 1.0
References: <20210304144000.1148590-1-elver@google.com>
In-Reply-To: <20210304144000.1148590-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 15:43:50 +0100
Message-ID: <CANpmjNPk0GYuiz1YZddJ1GjZuUXUrXFVZujoaH0UKDknpc-vgQ@mail.gmail.com>
Subject: Re: [PATCH mm] kfence: fix reports if constant function prefixes exist
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jann Horn <jannh@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y27+nz8+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Thu, 4 Mar 2021 at 15:40, Marco Elver <elver@google.com> wrote:
> Some architectures prefix all functions with a constant string ('.' on
> ppc64). Add ARCH_FUNC_PREFIX, which may optionally be defined in
> <asm/kfence.h>, so that get_stack_skipnr() can work properly.
>
> Link: https://lkml.kernel.org/r/f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu
> Reported-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Tested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
> Signed-off-by: Marco Elver <elver@google.com>
> ---

For further context, the corresponding ppc64-enablement patch is was
just sent by Christophe:

  https://lkml.kernel.org/r/afaec81a551ef15345cb7d7563b3fac3d7041c3a.1614868445.git.christophe.leroy@csgroup.eu

But there is no strict dependency between the patches, only that the
stack traces that KFENCE prints aren't as pretty without the
ARCH_FUNC_PREFIX patch.

So it should be fine to take them through different trees, as long as
they both make the next merge window.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPk0GYuiz1YZddJ1GjZuUXUrXFVZujoaH0UKDknpc-vgQ%40mail.gmail.com.
