Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIMLRKJQMGQETA6VAIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 52A1C50B559
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 12:38:27 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id y23-20020a62b517000000b004fd8affa86asf5061166pfe.12
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 03:38:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650623906; cv=pass;
        d=google.com; s=arc-20160816;
        b=lwxGzeXzp2lbx1fM6VRWuv6B466oiO78Zqyug+SWRAQA7k5RWRyvSl2Fa+PNpxDIc/
         F31GqTvf4fTQMNPSreOkgviJPwt3T6U90DY7Paf+qn69lYCBGl/Kaks1INLvXE3L0R3L
         e1FE2X/4mh5Itu9Fy0FQhQOtLHmRPek0d7wDX99tlAVnkBQNOBhJqFSB8ArYBggcBrRD
         R95IXVEUui0KDVQM+VYDDlOmcLDhlG6s6uNqkaYpYPB/O1cmwgJXDdUF8Qhv6T23j8tH
         N74DQljobT+bIbhJg1dlwbH56oWxfBBnO5ui495VP8P/cfHxx/fDp6hYkmDuLwQVCOIT
         rHeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wEuLSjE3apihWUH72P1/nOwQr6nYJ/g28yuQJOe6ksc=;
        b=GLaGXgPa/brbLP+pzmZVz/kKiy/NSFDypa3LuGtGRDIsNDloMZ2WNFFZQ41dZYdYMh
         MWLie1uEFaiOq5vUaijShVt/Qgma+GC5O1wktdpxGt5qONjTH5iBTHwdebuazigRs3oQ
         VfEFXCik9G7SCqAWaqtSmsIFrWUaDFSFwbbKsEbn1Ps5FhHYnpBzKqTeyyhsZVRX8v2R
         EZuCnbCuWwQtRsLzoVu+VXRybdP5PK6sFMyHDsUPeAPudplvT2cs9A2Hjuoqbw8FNijF
         XRQM29JUsp9KLj5kwH0U0FF++cVdeneUW5/fcoyfSOEnfV1SQlPN4ewd3qhEwsp3HGcE
         T2iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=svVpZpsC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wEuLSjE3apihWUH72P1/nOwQr6nYJ/g28yuQJOe6ksc=;
        b=fclN+um+E9uLN3WZb8HtJvbKYr+HumYAIlh/cTMAlBAkXW3NY4GwP1dPr8IhgTphtS
         KOQqbjwv7o9CsTwYk/mOotJJhuKPD77EW/fuw0RRd98BHl4ew71OvgeJOwcc+TMFfq20
         DYp2ZKLhbYMHrKO4bgganXohCQnJ9lHr12/QtRlxu6ISCGq4f0uHoW1rbjxx04SxRwBI
         UQBvj8MIaO+U0pZYd0ODpawloqXLBa6EVfV2JM1OQZ8+pVqCS2JeAG1E/Xgj64gYWPVw
         biPQma1WtBWh6bY3G3HCLaw//FvSWbBahJHQT9BVoMoEsygqfIKjGgBB5Ml7IT5W/h9j
         4C2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wEuLSjE3apihWUH72P1/nOwQr6nYJ/g28yuQJOe6ksc=;
        b=VVhSgrH9uhRbkpy1MJt2cLkv8cZWTZW1wm+XMri6gV8xCBI7fVGvA7zcAYlBU5+sh1
         sv6pqjwO+0nA2ECKWBadegSOwXiDxuMdNL6Lp2dAKkU6FXCN9QzbMO26oFaDTjGrqTJi
         w36lUgENu8VI2sZR0JFpHtFvb4fbf52XO9UAfk3eFEMuFt3sJXcldi4AR0d5+2W4NlRY
         Qt0gSKrZ7gR6BRWg536CKaersrylhRbrePVPrXJAHQchvbkD317bAglHvhscDHw7KBiC
         tAklVihyz7VW5jj1uBm95ewyWC/djZxsey0VZjQnIWNXkH0/SkpZxVKiMJt0RBPns946
         kX7w==
X-Gm-Message-State: AOAM532ONhM5UU/IivVNa7ZWn2BGSWxeaSpstjSzR01TpbO3wjIxuVIW
	YpHu8S239qcHKjz5HweMYGw=
X-Google-Smtp-Source: ABdhPJwZE//PFLZ4pc7YfepjaMicQjsCNdGbt5dSx25Wm8cEfCX4qOlut9oymxxLcgo+J6+z60lIOw==
X-Received: by 2002:a17:902:728f:b0:156:24d3:ae1a with SMTP id d15-20020a170902728f00b0015624d3ae1amr3699719pll.9.1650623906089;
        Fri, 22 Apr 2022 03:38:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1250:b0:50a:cb82:10ea with SMTP id
 u16-20020a056a00125000b0050acb8210eals5232431pfi.4.gmail; Fri, 22 Apr 2022
 03:38:25 -0700 (PDT)
X-Received: by 2002:a63:e706:0:b0:3a9:fb93:2011 with SMTP id b6-20020a63e706000000b003a9fb932011mr3398336pgi.259.1650623905299;
        Fri, 22 Apr 2022 03:38:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650623905; cv=none;
        d=google.com; s=arc-20160816;
        b=oqZQJ3+Wn+Q1urdz5F5mt5wDaARK2o5ahTIhsdl45NSjLhHmyMpOVzIBA3nj83kBhH
         sgUUTMvBlKxeImWs792JNamSVdstM5SQ8I4YZW/1yLs/DgvE/vmYRxynZ7YBxk3xD5ss
         AlxMUA7wkxj0k/NRTUdrAJxtRpPGdHx1G9mBzhSxWeD2QLP7KRzYrbppko5ZQ0nImy9u
         62KJQFML6YhAIk1+P+tFiC4Z2wM0hP7COFjBhua+BRgIqvtfvxLgORayzj4B4xuxYWsQ
         XxV2Cm+Y54ZAZ30UsbhnkpThSI9itt+qVmkR3tSpcNGDp2iEX6Vw31m89BIrkU7ZP2+f
         5QdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CsjTxEEAvysZcrGQCgnoFVKXKLqNd9huKoE9KzmmMI0=;
        b=Yl+g/csvsN9j91btEBAmmPK/ASVUqya/YMNK/yQYOegNrJ2H6ZHB2zjYMmXTVUj0jA
         I/zwC9EYH7r5jA4DS9wG3NNYBkSQ0tJXlYHi00Y5XBLeueLHNvBi9+FNRdesOJw1W/do
         xd6bUpLTRqTSheS52K7Htrza/o3XodYupwWaTjyzQYoNGz7LhEBBWtj/q8HXT9egfUHe
         1fSzRIlWOzA1rx8BZUYltGosPop4oVCfyekSv59kBlgSW+daeNlugl30y/rpQ6CIuRJI
         cAhlWpJGdjwJmea6hNgWmUbyD6gNxFpun2AH5MT6bdgT/vSx/jojvvx+8gQiiPKH5UZM
         CFXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=svVpZpsC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id pc3-20020a17090b3b8300b001cb99b8890bsi1042570pjb.0.2022.04.22.03.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 03:38:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id i20so13708410ybj.7
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 03:38:25 -0700 (PDT)
X-Received: by 2002:a25:9b85:0:b0:63d:ad6c:aae8 with SMTP id
 v5-20020a259b85000000b0063dad6caae8mr3527563ybo.609.1650623904827; Fri, 22
 Apr 2022 03:38:24 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000f46c6305dd264f30@google.com> <YmEf8dpSXJeZ2813@elver.google.com>
 <YmI4d8xR3tafv2Cq@FVFYT0MHHV2J.usts.net>
In-Reply-To: <YmI4d8xR3tafv2Cq@FVFYT0MHHV2J.usts.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Apr 2022 12:37:48 +0200
Message-ID: <CANpmjNPyBV8RCXf_=4oOvkLCavmgeLKw9w3M4zQEFcNMG7RCDg@mail.gmail.com>
Subject: Re: [syzbot] WARNING in __kfence_free
To: Muchun Song <songmuchun@bytedance.com>
Cc: syzbot <syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com>, 
	akpm@linux-foundation.org, dvyukov@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzkaller-bugs@googlegroups.com, Roman Gushchin <roman.gushchin@linux.dev>, 
	cgroups@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=svVpZpsC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
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

On Fri, 22 Apr 2022 at 07:09, Muchun Song <songmuchun@bytedance.com> wrote:
>
> On Thu, Apr 21, 2022 at 11:12:17AM +0200, Marco Elver wrote:
> > On Thu, Apr 21, 2022 at 01:58AM -0700, syzbot wrote:
> > > Hello,
> > >
> > > syzbot found the following issue on:
> > >
> > > HEAD commit:    559089e0a93d vmalloc: replace VM_NO_HUGE_VMAP with VM_ALLO..
> > > git tree:       upstream
> > > console output: https://syzkaller.appspot.com/x/log.txt?x=10853220f00000
> > > kernel config:  https://syzkaller.appspot.com/x/.config?x=2e1f9b9947966f42
> > > dashboard link: https://syzkaller.appspot.com/bug?extid=ffe71f1ff7f8061bcc98
> > > compiler:       aarch64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> > > userspace arch: arm64
> > >
> > > Unfortunately, I don't have any reproducer for this issue yet.
> > >
> > > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > > Reported-by: syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com
> > >
> > > ------------[ cut here ]------------
> > > WARNING: CPU: 0 PID: 2216 at mm/kfence/core.c:1022 __kfence_free+0x84/0xc0 mm/kfence/core.c:1022
> >
> > That's this warning in __kfence_free:
> >
> >       #ifdef CONFIG_MEMCG
> >               KFENCE_WARN_ON(meta->objcg);
> >       #endif
> >
> > introduced in 8f0b36497303 ("mm: kfence: fix objcgs vector allocation").
> >
> > Muchun, are there any circumstances where the assumption may be broken?
> > Or a new bug elsewhere?
>
> meta->objcg always should be NULL when reaching __kfence_free().
> In theory, meta->objcg should be cleared via memcg_slab_free_hook().
>
> I found the following code snippet in do_slab_free().
>
>   /* memcg_slab_free_hook() is already called for bulk free. */
>   if (!tail)
>         memcg_slab_free_hook(s, &head, 1);
>
> The only posibility is @tail is not NULL, which is the case of
> kmem_cache_free_bulk(). However, here the call trace is kfree(),
> it seems to be impossible that missing call memcg_slab_free_hook().

Fair enough - we can probably wait for the bug to reoccur on another
instance, and until then assume something else wrong. What is slightly
suspicious is that it only occurred once on a QEMU TCG arm64 MTE
instance.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPyBV8RCXf_%3D4oOvkLCavmgeLKw9w3M4zQEFcNMG7RCDg%40mail.gmail.com.
