Return-Path: <kasan-dev+bncBD52JJ7JXILRBIFKTKPQMGQEQOQXV5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D256692604
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 20:04:01 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id x12-20020a056512130c00b004cc7af49b05sf2601460lfu.10
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 11:04:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676055840; cv=pass;
        d=google.com; s=arc-20160816;
        b=PyQgUxfj5E/V4QbavR2gTR4Ao4SqriECzEL+TeDZ9nGsS+YqNFsCAuEQ+IxspHMQnm
         df3K5NERgO34vJced/++wAGpVzipHXhFU6+yNXtfu+uax40nMITzLnvOX4zLriB5VkJk
         JVdjGgyHlZ+o+3bCJJ3Rc3pfw8IlBGNqYkLPqengo4RXpPcWZXPSgchsMiwVeifKbHKt
         7nGzxQQj8DSTd+CGOsPEJf0SP1NQv4fJjSlB/NoyAdj63tA7eM1d/v728hca/uWO9ukk
         48VHWHK1pWAGbkrI+FNymsEQPA4aTOHVKPNiXft2EJLEgh0rg0E865rYNUVSk/TVri73
         sjjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FgMrDJKvzV/wNebWeNZt4cPObiHoV/ux8N2J4w4Fdv4=;
        b=x3p3nJAWcm+H+qbiiUcEZgTmsiq2MZ+/+9HqD7N2S4ZPf8jMd9Z64054AnzCANIBb1
         ObJiQOQx27UBm71aZH1dCra1089Vv4N+ysRTOWMjfKtcvQjPqgiZKNWL/fe+c5ELbXRl
         9f5gAMREMf+F1Vvn3j28QfT6vzyvf0RJKZqGyoXIHW7oWIMuGQ3fcoNq0kLfsX/jkT03
         lQV5WwzK504AjoQyX6kSSuZ7cPNyLb+bMK24PdLW8fHASF3kR3zlyYW4/Ay72OUXAniH
         H+SvfebMDTiGZEUlOKm6uVY/9la4QDkgHg5O7oCSYivEOjhuqJO6n6DKE16qFpJyXuoU
         4z9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F0LPuzdB;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FgMrDJKvzV/wNebWeNZt4cPObiHoV/ux8N2J4w4Fdv4=;
        b=s+CIi5wxe9zsZ1T49Jz9iniBiTsI0NVR0us5IDscvCCykOvtRXWSR0RpzPNJ4vz0jt
         /XHwQA7riMKHiQfK8C15+n+DcQ63VCVD6P74g8zYhblDOQCcl0E2NhcpW6j7NWP5uaW4
         ZDdhO2s+edvLYRSnT7fOyGAtVb2nhFc+jZjqmPDZtfpbFszuknoUzuX84RZGRhPKAmLE
         2vvlvmoXN2sVtZlnzaJPO7nfwHjqKCcSPyuL/w65E/4wsKXQ1qxvA/wuWSO6/6F50rqC
         29N+FmTwFZrew0aFfY7/89s07i9jEntWGzJMIathE9aL64iEjD1tkAyNvRYAL0CiMZYB
         bfSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=FgMrDJKvzV/wNebWeNZt4cPObiHoV/ux8N2J4w4Fdv4=;
        b=Ce8JjprE5S7OctLHZEpnqhR3Q5KxgPHCzAG951iM1ldfmV1G0dRvCllfIIDLiAYCfT
         ldIc/hUkZSe3I4AkeqezRzbFn0/Fw1ABodY4+9liK9dJT8IjxvhucIZjUFygdvj6U810
         qBxNYMUHPP3u/Ag24/FOEhGl39+z6gfGt5dXx/nV8AWVOWCa5+W0Ayyp6GJr3r/dPB6j
         kzRUh9r8/rRLf3m4UwPOVHy06ge7v2sSCDhOZgmpubIJLp3Hcpl7J/dw1auN6XQrGwrm
         CeehuyVp5FNxILdng7h98eDS0IOypUMWp32OUS2q2D18JoSt+V4fNJT0HrDhxZ0psGVu
         Qx+Q==
X-Gm-Message-State: AO0yUKX1HssWzo/g33wLJ7QjS2pfh1MYaL6R1gLTlAcvmMMOocAAPkLA
	bvBqs2YeBtXoemObLjyZsXs=
X-Google-Smtp-Source: AK7set8JhQ2o+TksR5CIVsZ7lORA6rxLljR/Nv96fwkf1em0WuQmb/Z5/owb2N87SBGuw/L0DRY5BQ==
X-Received: by 2002:ac2:4211:0:b0:4cc:7876:9f35 with SMTP id y17-20020ac24211000000b004cc78769f35mr2921815lfh.125.1676055840345;
        Fri, 10 Feb 2023 11:04:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2526:b0:4db:2bf0:d4b5 with SMTP id
 be38-20020a056512252600b004db2bf0d4b5ls1284377lfb.0.-pod-prod-gmail; Fri, 10
 Feb 2023 11:03:58 -0800 (PST)
X-Received: by 2002:ac2:5455:0:b0:4db:2ca9:f3fe with SMTP id d21-20020ac25455000000b004db2ca9f3femr269031lfn.54.1676055838881;
        Fri, 10 Feb 2023 11:03:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676055838; cv=none;
        d=google.com; s=arc-20160816;
        b=O8ThQrxzINzYxLpOtrAxXOUu1B9wTrpNV28iafp0xEAgEuuQVxGJEXiQ3mHlQj2v51
         gwtmGiy7UDMTphYlHbOA5sQKTIdASc6ubkfEsMb6Qa1gr3I9Rp9xweTNFzxzt/4J61Wi
         BaQnvT6v8nKEPYjzf+e99DRqvnlGTqG9j/PMBESqDSrkLhXh56fY9r4JtSr/ERm997oU
         toIpqiVec/6tOJuG8Z4PsSkmLm9WqzdhpEWjeRlkA2QlbFlwOaxVlOLO7ja0mtWe/7Ea
         MfkUsHF5YsbejUWNBJN8cd61qbIyS88U8Z2O95fC/WlfhfG3MEYbSQ8mayDYCoOLq8De
         N2Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NTv3JGlLIZKXeoBIClnjALsg1EOVt48oB8d6Klv1b7A=;
        b=EfzAyGCqaVbMczGGznanxW9mOC78CBw7PntT7jl3rkgxeXtFdrBbMgD+5DwAH5Tuxx
         IIiWoDAJwbS6bsptYGP97uJp322VCbvRtiZlJqWMLIbSioDwToKwvqKJ5LukjP0sORQq
         A3/7yo9go7aEXwNB2NWwnkK20RvhpfDBSPom6lI46jqUMHzIp1WScz6yOzW/Mo2q4NYS
         DB2ctlxBoqHeG6nshlPluRVaKXuFupX6dzC0+zJb22PBtGBIxS73su87slACrOIz1Zcj
         +y52oT5KBuYEgnIV2YRakFi5PFeYyXyGAiR+SbGh1na2MZ1AfNqf69s3Sb6bFfAGD7/j
         x/BQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F0LPuzdB;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id o13-20020ac24c4d000000b004d5786b729esi286206lfk.9.2023.02.10.11.03.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Feb 2023 11:03:58 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id l37-20020a05600c1d2500b003dfe46a9801so4793678wms.0
        for <kasan-dev@googlegroups.com>; Fri, 10 Feb 2023 11:03:58 -0800 (PST)
X-Received: by 2002:a05:600c:210c:b0:3e0:6c4:6a11 with SMTP id
 u12-20020a05600c210c00b003e006c46a11mr998294wml.114.1676055838478; Fri, 10
 Feb 2023 11:03:58 -0800 (PST)
MIME-Version: 1.0
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
 <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
 <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
 <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
 <Y+Xh6IuBFCYZhQIj@google.com> <Y+aMvBozFxma3A/q@arm.com>
In-Reply-To: <Y+aMvBozFxma3A/q@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Feb 2023 11:03:45 -0800
Message-ID: <CAMn1gO7Xw_txFx_XEqbDQHk5BSfQaLZjKi6=9rQzE=Wm6YMM7w@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and page->flags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?R3Vhbmd5ZSBZYW5nICjmnajlhYnkuJop?= <guangye.yang@mediatek.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, "will@kernel.org" <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F0LPuzdB;       spf=pass
 (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::329 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Hi Catalin,

On Fri, Feb 10, 2023 at 10:28 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> Hi Peter,
>
> On Thu, Feb 09, 2023 at 10:19:20PM -0800, Peter Collingbourne wrote:
> > Thanks for the information. We encountered a similar issue internally
> > with the Android 5.15 common kernel. We tracked it down to an issue
> > with page migration, where the source page was a userspace page with
> > MTE tags, and the target page was allocated using KASAN (i.e. having
> > a non-zero KASAN tag). This caused tag check faults when the page was
> > subsequently accessed by the kernel as a result of the mismatching tags
> > from userspace. Given the number of different ways that page migration
> > target pages can be allocated, the simplest fix that we could think of
> > was to synchronize the KASAN tag in copy_highpage().
> >
> > Can you try the patch below and let us know whether it fixes the issue?
> >
> > diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> > index 24913271e898c..87ed38e9747bd 100644
> > --- a/arch/arm64/mm/copypage.c
> > +++ b/arch/arm64/mm/copypage.c
> > @@ -23,6 +23,8 @@ void copy_highpage(struct page *to, struct page *from)
> >
> >       if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
> >               set_bit(PG_mte_tagged, &to->flags);
> > +             if (kasan_hw_tags_enabled())
> > +                     page_kasan_tag_set(to, page_kasan_tag(from));
> >               mte_copy_page_tags(kto, kfrom);
>
> Why not just page_kasan_tag_reset(to)? If PG_mte_tagged is set on the
> 'from' page, the tags are random anyway and page_kasan_tag(from) should
> already be 0xff. It makes more sense to do the same for the 'to' page
> rather than copying the tag from the 'from' page. IOW, we are copying
> user-controlled tags into a page, the kernel should have a match-all tag
> in page->flags.

That would also work, but I was thinking that if copy_highpage() were
being used to copy a KASAN page we should keep the original tag in
order to maintain tag checks for page accesses.

> > Catalin, please let us know what you think of the patch above. It
> > effectively partially undoes commit 20794545c146 ("arm64: kasan: Revert
> > "arm64: mte: reset the page tag in page->flags""), but this seems okay
> > to me because the mentioned race condition shouldn't affect "new" pages
> > such as those being used as migration targets. The smp_wmb() that was
> > there before doesn't seem necessary for the same reason.
> >
> > If the patch is okay, we should apply it to the 6.1 stable kernel. The
> > problem appears to be "fixed" in the mainline kernel because of
> > a bad merge conflict resolution on my part; when I rebased commit
> > e059853d14ca ("arm64: mte: Fix/clarify the PG_mte_tagged semantics")
> > past commit 20794545c146, it looks like I accidentally brought back the
> > page_kasan_tag_reset() line removed in the latter. But we should align
> > the mainline kernel with whatever we decide to do on 6.1.
>
> Happy accident ;). When I reverted such calls in commit 20794545c146, my
> assumption was that we always get a page that went through
> post_alloc_hook() and the tags were reset. But it seems that's not
> always the case (and probably wasteful anyway if we have to zero the
> tags and data on a page we know we are going to override via
> copy_highpage() anyway). The barrier doesn't help, so we shouldn't add
> it back.
>
> So, I'm fine with a stable fix but I wonder whether we should backport
> the whole "Fix/clarify the PG_mte_tagged semantics" series instead.

That seems fine to me (or as well as the above patch if we decide to
copy the tag).

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO7Xw_txFx_XEqbDQHk5BSfQaLZjKi6%3D9rQzE%3DWm6YMM7w%40mail.gmail.com.
