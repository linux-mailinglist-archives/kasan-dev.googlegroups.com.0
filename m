Return-Path: <kasan-dev+bncBD52JJ7JXILRBWOUVOPQMGQEZOEVP5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CA62695636
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 02:56:43 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id f6-20020ab03d06000000b0068a65937391sf2208046uax.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 17:56:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676339802; cv=pass;
        d=google.com; s=arc-20160816;
        b=haT1TcBjOjrjJfQjjYnKNSo+9BKvXyIc1phW3vlNGFK7zOyT+M1UQ95zgGfN9qFQQc
         GnAwW0k9t74U2cWFfRCBu5Sm71IkYaOpM98Gyaka6q+1BB/c/a+1hYvTgk/HsgoId0SQ
         +tXCBOn65rINgmuaeNzuagUlE5ElO1PO4+SL3ge5x0xvZdCtrvR/0WbeCyHNnvVWWfPn
         FeZZQGp0PQfwQGR/WL/pT1oLtliecutIVcIRY8x2jb0r8/iqEiFMR0Xy9wjy+2KRFwEe
         O55Dl3hCG2F4D3SFh1f4C2arYuqARTpBlJBU2ENxbL+vDh/d3yjV18vgTi//Uerat3Yj
         U8Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=l0QccdSYaagrMladcw1Vn+LjvkJZ0zQ5dTYuhjMuXtc=;
        b=cadDBBxKJaSvNvCoE9KUXAl6LC02W4qZI+usOFeIIBO/ooccb5I5WHdB79jZnHnNCB
         6iIcKZta0BTSEfS8fwEeDWa6yK9IQnSVJNvlOpSOoB5iLO5syikf5yMoTi2t1RXIO0ZT
         OXbXhbEaoYNG7uEbbvY6H8QSI+A4nq9FzJebXCGg28Z3S/Xm2ZdnErUZL68VQmHkVPip
         fGDAt2U56sKUqP5ODkaFPwJdZSmUCmDTjSFobebDK5zWnH/8gzuWUtAPLpCJwOsJ19Tr
         fVSFNToxhCAQNEbnpIBPFXZRLVImW95BqAfdCM/dzG42pyJ3rSD9Fl7CxuG0D95tvjGu
         +9BA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WukYlK+o;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676339802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=l0QccdSYaagrMladcw1Vn+LjvkJZ0zQ5dTYuhjMuXtc=;
        b=TFBQ3p+m0rqV3rkZDmtxTRPxijUZJEHL5RlNj0KMCd/o2pp/8jQpB2FeITI9iquOqW
         cyN0UOkE9j6gWJ3+r4gLqACSSuw6C9DsW3rHdQZEawwdNMPEtv/iQX7a8C2yZCm4g/T6
         7WLm4etynkGNJ9ryvfvq89Kpfpf7sMdSi9YX3OUman9PuUNRdTmPZpCy3/emFPWYWiEJ
         pr/woXntjYzBZ5ScvQcp9QnUsQtekifj5PRYsTb6zn1NKbL/LLlHceRhNBp5rdvgrUpP
         mFfVnlhpIkBzd9oryKVG60NmFWYLarSMuMnP2nFo3sawxhNTAZAk5hlQbDWaIlGY3EnH
         4giA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676339802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=l0QccdSYaagrMladcw1Vn+LjvkJZ0zQ5dTYuhjMuXtc=;
        b=TIdjscmqOnKC0QvRrxqbYYJYIl/BbQotbbX0WkHOB8Wf++rHVBeZ65GYn8IqMQ2URr
         CED1wCUm14mITSgjFxnZtGuZUXoJaNG86RKVtHnVeLvPyfdC+hh8AT+jOck+OR8Xb3s9
         hX1BBEiAs68Uzp23yS9dv3LsEH8iXjH04cYFpNdRT3RJdhhnsAk68zVRqNkhfFbNlXxo
         gZl/TlePWYbrLT64c/2G/lFVHqJqWlzITgBBI41qxY1nYze0Y6NxMGv4mKJOo4j/sVbN
         vNKIE5UKg7WmmLdiLPV/jN2ub9ZsghGYc762HHXW9n6NIran0TSqZb6CRi0zCCVnAUG4
         SL2w==
X-Gm-Message-State: AO0yUKXKfI/9EMIeAQ8AXd0Ci8EYHkFDcsjhUk0JdOIt64hpoKOpS/qP
	6mKCrt6mTytK1W0RJ/FeAdE=
X-Google-Smtp-Source: AK7set+6uKAA5DSk9wCb7AOVrsD0j6+Ur4ucVgB34AU3RIeSWzU/NejLPZeoWH6o1X1T4B/58wTc7A==
X-Received: by 2002:a67:d58a:0:b0:412:197b:b3e2 with SMTP id m10-20020a67d58a000000b00412197bb3e2mr75686vsj.68.1676339802005;
        Mon, 13 Feb 2023 17:56:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:ce04:0:b0:3fd:2bb5:712c with SMTP id e4-20020a1fce04000000b003fd2bb5712cls2553875vkg.11.-pod-prod-gmail;
 Mon, 13 Feb 2023 17:56:41 -0800 (PST)
X-Received: by 2002:a1f:1685:0:b0:400:91cc:5c1c with SMTP id 127-20020a1f1685000000b0040091cc5c1cmr784278vkw.16.1676339801310;
        Mon, 13 Feb 2023 17:56:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676339801; cv=none;
        d=google.com; s=arc-20160816;
        b=lIN39z8VENbE6bp5g0S6cGwcFlRjTIsEocQoBCYV0+s7lk4IW08Pi4Z+clTYhIPXb/
         FJ3ic+VGpKOEbw+6/1Ch4TAQR781PcpHDHwyveVT3GAb/PRRHuYHsh3vPn+/xl4enhhi
         Num6HALdSO9OENH2TMdvWDpRQW19+Y/jcCwMxE2xPeD13c32Gel7QSWPbnv34TaRvaSS
         YlbJus7xjWCy9oQHoVyPQKaQTgNMTmTX505mB3+QU05iK4podSTiMxH6DuZN5MpCwvZj
         DYCjvEIghTrG3TzPoI3KaUxzwRZmgG98CO20bAnwnX5wakPGV6/GAlBL/K13oTZWRJVi
         rN+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8JwtFQD8SoayVtxvpf9Tvl5oCjOJCdMofv2mGIfAKNU=;
        b=YlbprQgFm7YT89QhHJCI5BNgjnz6THqlExN8fx97LdrqRGvhWKRC36V8sWg0c1esZx
         SdcFaw06hdWmOJBtG5gUYbxj1adZH70W/QgNC/V0gtg77x1yv9gav+bGFVCYm+ZEHjU8
         Fe2G6QBL5rqMA9g9xbBzY+cDfl/MiwrKd6ujWZAAxFyZ0M3dT4MdMDRIf++VEYTcZ8lX
         lRk1NmBeNFTazQ7XASsmhjyboTQgf9wPjG+znEd5U6QmTgHv/VWB097ye/FpcTTAj4LA
         qizl4gn8QOWoWE2+tW1EJU7RgivSzVlGby+agTkwrLacr2ygPwP+XR2XvDzjHpvWtNY6
         4vTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WukYlK+o;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id w4-20020a1fdf04000000b004016000b6d1si485368vkg.2.2023.02.13.17.56.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 17:56:41 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id n22so3319328vkm.11
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 17:56:41 -0800 (PST)
X-Received: by 2002:a1f:7f1c:0:b0:401:87ef:e516 with SMTP id
 o28-20020a1f7f1c000000b0040187efe516mr86906vki.16.1676339800880; Mon, 13 Feb
 2023 17:56:40 -0800 (PST)
MIME-Version: 1.0
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
 <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
 <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
 <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
 <Y+Xh6IuBFCYZhQIj@google.com> <Y+aMvBozFxma3A/q@arm.com> <CAMn1gO7Xw_txFx_XEqbDQHk5BSfQaLZjKi6=9rQzE=Wm6YMM7w@mail.gmail.com>
 <Y+qF1y4+8kQGaN6l@arm.com>
In-Reply-To: <Y+qF1y4+8kQGaN6l@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 17:56:29 -0800
Message-ID: <CAMn1gO6R=CmQz93zojsfw-pZwnBF-237x2a4drCyGkkE1xYEwA@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=WukYlK+o;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a2c as
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

On Mon, Feb 13, 2023 at 10:47 AM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Feb 10, 2023 at 11:03:45AM -0800, Peter Collingbourne wrote:
> > On Fri, Feb 10, 2023 at 10:28 AM Catalin Marinas
> > <catalin.marinas@arm.com> wrote:
> > > On Thu, Feb 09, 2023 at 10:19:20PM -0800, Peter Collingbourne wrote:
> > > > Thanks for the information. We encountered a similar issue internally
> > > > with the Android 5.15 common kernel. We tracked it down to an issue
> > > > with page migration, where the source page was a userspace page with
> > > > MTE tags, and the target page was allocated using KASAN (i.e. having
> > > > a non-zero KASAN tag). This caused tag check faults when the page was
> > > > subsequently accessed by the kernel as a result of the mismatching tags
> > > > from userspace. Given the number of different ways that page migration
> > > > target pages can be allocated, the simplest fix that we could think of
> > > > was to synchronize the KASAN tag in copy_highpage().
> > > >
> > > > Can you try the patch below and let us know whether it fixes the issue?
> > > >
> > > > diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> > > > index 24913271e898c..87ed38e9747bd 100644
> > > > --- a/arch/arm64/mm/copypage.c
> > > > +++ b/arch/arm64/mm/copypage.c
> > > > @@ -23,6 +23,8 @@ void copy_highpage(struct page *to, struct page *from)
> > > >
> > > >       if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
> > > >               set_bit(PG_mte_tagged, &to->flags);
> > > > +             if (kasan_hw_tags_enabled())
> > > > +                     page_kasan_tag_set(to, page_kasan_tag(from));
> > > >               mte_copy_page_tags(kto, kfrom);
> > >
> > > Why not just page_kasan_tag_reset(to)? If PG_mte_tagged is set on the
> > > 'from' page, the tags are random anyway and page_kasan_tag(from) should
> > > already be 0xff. It makes more sense to do the same for the 'to' page
> > > rather than copying the tag from the 'from' page. IOW, we are copying
> > > user-controlled tags into a page, the kernel should have a match-all tag
> > > in page->flags.
> >
> > That would also work, but I was thinking that if copy_highpage() were
> > being used to copy a KASAN page we should keep the original tag in
> > order to maintain tag checks for page accesses.
>
> If PG_mte_tagged is set on the source, it means that the tags are no
> longer trusted and we should reset to match-all. Otherwise if
> copy_highpage() is called on a page that was never mapped as PROT_MTE in
> user space, PG_mte_tagged would not be set on the source and no tags
> copied. In such case, we should keep the original KASAN tag in the
> destination. Unless I misunderstood what you meant.

I was thinking that it might be possible for PG_mte_tagged to be set
on a page with KASAN tags. But as far as I can tell, this isn't
actually possible (or not intended to be possible, at least). So I
agree, we can just call page_kasan_tag_reset() here.

Patch sent (with stable backport instructions) here:
https://lore.kernel.org/all/20230214015214.747873-1-pcc@google.com/

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO6R%3DCmQz93zojsfw-pZwnBF-237x2a4drCyGkkE1xYEwA%40mail.gmail.com.
