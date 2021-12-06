Return-Path: <kasan-dev+bncBDW2JDUY5AORBHXYXGGQMGQE6XDWFZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CD0146A926
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:09:51 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id s5-20020a9f2c45000000b002cfa7164503sf6795146uaj.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:09:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638824990; cv=pass;
        d=google.com; s=arc-20160816;
        b=OT8jq4Nym9tT9fUnDvq1qoOed+hufq33v91VFsTKD6xu56sB0/9hEbKmcjWjgKKss5
         /krcC4krRoO5MNfEJ9XKe5DxTe7VmCtDHMUIFOUEiOFD+BF1PQH/KeU9uZSVNB4wV6Ce
         TxNXiwRK3wE8r5oM2nglYipxEE9PnOPIqsTKZBQTSuLoyAa6SUII1E+Ks/SNmI3VcsCn
         FLxnkjSBq1koUUDh+32UIusjMNpVr2yIpAVlR4bnbf42tzrvbAyXTDbaWO9pqGOZ7n6U
         8j73hrpmkyKK9ly1HY4edgohnRt0JPnrfy5SHZ9Y5dh69gzrPi/tJ/FbVmqao8MhejAP
         fKbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=k6JIk8iRu5PgNtM69iBU9axL12B1reJMlvLtr10kvOE=;
        b=ULEv1kRBW7HRU7UBj4OwCGf5dPHqAfSwl3p2qAjS44/MM7GezID2FQmVQqzYw7Ew12
         g3T89l1uT0d086eC2gPdIdPYjonlXSiGr+tX6NsZPjDjGZGvicpVqc0BGIsNgFV7WTSz
         j5DdNhnaofg95xavmCmpMcCSKKjkd0mbbZLxpqtklLJRvsyku4x5hHxn6g6LDkhyS6Tt
         A9mjLu/15ZnTpwq548+vg74phjHpU7Rh2RYL0YA8W/CWqgOeTPdgJzQki9nWzAJyGxeN
         BBSpZFlyKoJ3PVaKm4Sjlciv9QrtlSgRQ9NjQEWz2MXB0uafb8zcpGt9cSCQXMXYV8eR
         03iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=d8LJ0GCx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k6JIk8iRu5PgNtM69iBU9axL12B1reJMlvLtr10kvOE=;
        b=nvszQv+Jjj+9GaWLuQkaV9LL9uS8oScEeA2fMfwTFD3HILmprjTlY+LO6fRM9kXy4R
         ZbnxrifCFgR8ajb94qJLD6IAdbvjldp+3klUXAvE412d10y4OQWF6fSHFXcBmKb+BChI
         be3I70YmpCxCjQ8eZ1lHNqhhxNo+Wg4q2b+7QecPsIrYh+rHr3fSoKeuEe0UVS2EgXtm
         nYSCWXAHl9wW3P0AGo89b4iXsCr4qcQFmO9F8LuRFJmJpDWIL20O3NWlQRN1oDbY3Ahe
         zR1gmEAsKXkQpgU3hCV3oA2UHs+oHfnrZm1MyAGJ9Nw7JqOIyooZ5HY/i2TN9AVMfQhl
         7zJg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k6JIk8iRu5PgNtM69iBU9axL12B1reJMlvLtr10kvOE=;
        b=bveBpg2m6Ojp34yxgZ+CabomJ/dIlcV8KMTDTUNEzrzfdkR1nhOV+Hkfz0/iUQa0eK
         kKpseYzmWWybJsndGm3m2IfrHeqVswqzV2cnMG/X8OktkF9fABL24TbH8s6nA/LItMEm
         E2fbrlylruDcxFhXbYz8haEEgzNGappe1nIDlRzlthkMSfTJ1F4uEBhDRxqWos0zL3Jh
         xGwMwo7SvGkW43h/SwywNuI22uMn5X9pRWimLaSSjZtjnrXaTWIYd5yf0wJ+sNfwNcpR
         Gq7vmJDnyFKp6axsqPtKCGLPcy8GeRFjehfYTeBrK/nVKDsiCTATkA44vVZszDef8yjn
         VJIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k6JIk8iRu5PgNtM69iBU9axL12B1reJMlvLtr10kvOE=;
        b=7qiS8p176clAutO/JV+rJv1tlRf1Cgttftr1SIL+IWMPzqCxaq5rV1CdcSOpyjM8iv
         DEWfCSm9hXsDk4SlqGZKoo736XDwLq7VD0R175JHWec3m0vEzw5twxjHhgmg00OnQ+Vw
         qLDq5qIlpnkNK2XGVQtOLL7jBIIRHb5EKvtzD2bPscWfi2vfaymhyeDWYsN/+IBx4lNA
         27wVDpZIP3N+CRiq+2vVpLkTs4HOtqtzJoy1j37zIJRrqUP5vioy+avjZ2/fijA0+5cQ
         CpBJ7htBPMTTy80w5eRfCwcSsOeJwWyyMBJmrg4/5nOMQ10Z9DjBbC6tBw77pvJXSFVT
         6UDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Pawq1k4vaCedGiGc0ZXYSkN3lUUfkjKAMx6YV1ZST5PwDDEaE
	JnEZoxjL1/4MM3H3p5gAuV0=
X-Google-Smtp-Source: ABdhPJwbLrNeqbPpJ+UedKUSq7ILi73OviQB/ycXPPn/RIdTgay1v5qepzGNguaz7pwQHuyJfPW/7A==
X-Received: by 2002:a05:6122:16a3:: with SMTP id 35mr44836885vkl.11.1638824990275;
        Mon, 06 Dec 2021 13:09:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f292:: with SMTP id m18ls5444592vsk.6.gmail; Mon, 06 Dec
 2021 13:09:49 -0800 (PST)
X-Received: by 2002:a67:ce0f:: with SMTP id s15mr38779479vsl.33.1638824989811;
        Mon, 06 Dec 2021 13:09:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638824989; cv=none;
        d=google.com; s=arc-20160816;
        b=e2aZMV17klHr95mQpKnWl5IkDbIF1350JdM3YXKJ51NNoT4vQWs8usZVfKfb2tvahi
         dz/VmjKjovQbtG0Ht9W2yLwWkkGh4ME6Miq1K9n1IXTwA059Gahtoq4HQPiLnOxqCAtJ
         wpZ/7Tsm8teLsnMH358C+LLjNjbc15u+2G2RjIQLhe3kEIrDFSFbSQCpW1J0vH+YU8o/
         fXD1O05ZWLgzo9ktevLH4gaQuoLdXqFZvNwm+NhULQVHQ7j+XcokoDqfWDFL0S6IqiXU
         V+WWMCsU6SG5AhANkHCjrJo/te8xftS8WtdVz/JOadGq19FZHEKE7tdGq9pcwEj1bvR6
         AYVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r9EatIR8zw0uiCmcjCpN5nb99oEeaRmy6PPAXAHDInU=;
        b=PHECAibgUNLtU4bwhm+JDnBsSLx5uf8UcoYzmr0HdumhaZAFREwjY911+fWUygWjU9
         6nJ52eLzr+/xV6GZr/1P9/e8nUtFiN4YvNFwD1A9BoLnbn0L8jkvBR3axhD/mvl9uFvv
         FTIrtpclcAx9sSVXiQkKuAhHuLKuO/2m+6s+I5wyDNUj3hDqGPpbZAYcufXkTEjyICft
         d9IXxz3d/GW8zrmhHSxsmU9ukbywufHS79SuklRy4S4uEAwQQwf4Fnr4pRXiFKNNvJqs
         P9ZKDQlPnvUb6mTiIcVLMAYybcqbR5hWv17mlziaNg5d5V01XHGAc/og8SJm6lA/CUua
         EsFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=d8LJ0GCx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id 140si636250vky.3.2021.12.06.13.09.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:09:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id m9so14666621iop.0
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:09:49 -0800 (PST)
X-Received: by 2002:a5e:9b0e:: with SMTP id j14mr37680837iok.127.1638824989563;
 Mon, 06 Dec 2021 13:09:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <984104c118a451fc4afa2eadb7206065f13b7af2.1638308023.git.andreyknvl@google.com>
 <CAG_fn=U71Yn-qCGMBR=_uOt0QCEu9skGzhgRBJjpkQCjZ=dKiA@mail.gmail.com>
In-Reply-To: <CAG_fn=U71Yn-qCGMBR=_uOt0QCEu9skGzhgRBJjpkQCjZ=dKiA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:09:38 +0100
Message-ID: <CA+fCnZfto82vg3vGkZGNxJKOOqsOp_bpmHEd0Z350PfPJ7Y=1w@mail.gmail.com>
Subject: Re: [PATCH 08/31] kasan, page_alloc: refactor init checks in post_alloc_hook
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=d8LJ0GCx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b
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

On Thu, Dec 2, 2021 at 5:14 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 10:41 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > This patch separates code for zeroing memory from the code clearing tags
> > in post_alloc_hook().
> >
> > This patch is not useful by itself but makes the simplifications in
> > the following patches easier to follow.
> >
> > This patch does no functional changes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  mm/page_alloc.c | 18 ++++++++++--------
> >  1 file changed, 10 insertions(+), 8 deletions(-)
> >
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 2ada09a58e4b..0561cdafce36 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -2406,19 +2406,21 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
> >                 kasan_alloc_pages(page, order, gfp_flags);
> >         } else {
> >                 bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags);
> > +               bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> >
> >                 kasan_unpoison_pages(page, order, init);
> >
> > -               if (init) {
> > -                       if (gfp_flags & __GFP_ZEROTAGS) {
> > -                               int i;
> > +               if (init_tags) {
> > +                       int i;
> >
> > -                               for (i = 0; i < 1 << order; i++)
> > -                                       tag_clear_highpage(page + i);
> > -                       } else {
> > -                               kernel_init_free_pages(page, 1 << order);
> > -                       }
> > +                       for (i = 0; i < 1 << order; i++)
> > +                               tag_clear_highpage(page + i);
> > +
> > +                       init = false;
>
> I find this a bit twisted and prone to breakages.
> Maybe just check for (init && !init_tags) below?

I did it this way deliberately. Check out the code after all the changes:

https://github.com/xairy/linux/blob/up-kasan-vmalloc-tags-v1/mm/page_alloc.c#L2447

It's possible to remove resetting the init variable by expanding the
if (init) check listing all conditions under which init is currently
reset, but that would essentially be duplicating the checks. I think
resetting init is more clear.

Please let me know what you think.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfto82vg3vGkZGNxJKOOqsOp_bpmHEd0Z350PfPJ7Y%3D1w%40mail.gmail.com.
