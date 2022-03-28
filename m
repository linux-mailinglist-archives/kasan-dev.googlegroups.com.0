Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCN3QWJAMGQEKKFRJ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id D28A54E8E8C
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 09:02:34 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id w28-20020a05660205dc00b00645d3cdb0f7sf9836066iox.10
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 00:02:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648450953; cv=pass;
        d=google.com; s=arc-20160816;
        b=ezC/5iHDQLmpSSCXjmhzj+/O+4tAWoOfqKITpfG9nH9AmvmIwhSG7q+1UCOaeHSh66
         0DLmYYD0lQHdwzxbNDNz0i8j7b7cONJt8ma3mdE1ZMFPnHFGI1GKeYmzpnQPN8t4MK04
         aqWvUF/BUlQPhkcupGKihm+7gRyzo29M+jeuo9rKcU+ZTBtGPypRtRYcXGXIPZqUqU1w
         oUTYenIHS9Kgs/VIAiy++AV0agKTta+v4XVdGicY0QnUd1hikr41RL6NLkyPzK1IJY5/
         goX5ml9eJS2LX8YOv6WFsID1YWVFaJgu3hBYBZJPU2P63w3ccOiEJOM39NHnrAkqbpeZ
         YjJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h0mlF/jcTdA2XqIoYPBE2FZStexcTXiZf0kPFz0v3wg=;
        b=X996qcThUMsVUWhPjwNDQ5xbajs7792D7C5Q9XMdx38PYM4qSSrGAXTg+DE1d8xfu1
         4r28IAgqHgNJs9uwXN4nplRUnw45p1Gv6MrHGAW+Hx6SfphfWBmv8dLIXhTLpH72wN4s
         TIuPpWK83aNqMStZUl0kArawoEnavVJcC2ZRyXGONXhWmiaoNfXHmDOB8v9fbmduMaXS
         VS9i3yjA/5xadhDwtZB8E4UKQk3VwAES40Sgf1RsZQ/9rV0U7yunaYMTyweesP7JHNfm
         bauMZtCnnVz4lL58o0H7VECpFJzJJwVHwEXsxXWeDawa6tk28ogSFkUKO48w8kDLjXwW
         rpTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oQjYl0VW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h0mlF/jcTdA2XqIoYPBE2FZStexcTXiZf0kPFz0v3wg=;
        b=pzDp9Ou9rmYzCsdRFBlSy8h7j0NJEqjxEesXWgb7Fj0DTBDcqFpKnJ/XUrOuPGns6D
         QHk3Sa0FFICz/Ye0MmHSrKcsN5OTa2l8OteZI2z6bA1LxpmeU4VNB4H30GBzXpSMMzsA
         8FdavoUHFNySgwq+SrzjoW1X1JszRPtPc8P5qkJUfBqK0ZLvIJf7UwYZgvsRyIwNSejs
         mde5IVKVlz50DAw7eSkijgvp0MINGVhYtB8smejCl3HPtNIpvhZKfN2D4WiszKE6lMGf
         hZ8vcVqwA6yWB/LDxA5hxaFxqjeHO7D4VHJr9OA6/lukLhD8oL7osnTbk7agCKcgOHDF
         7iYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h0mlF/jcTdA2XqIoYPBE2FZStexcTXiZf0kPFz0v3wg=;
        b=EuGRdG0OH5ZeFAEj71RrcT82djIuKupVrDYbzl9ittnuY0zTGQ7yijevvPV8mAYrWI
         TdaxIdEYAM5EH+PK6T0dqJJjrdDQtNryJJfdIvyzXeeA/AK5KUDDYP/vSC9jR+KCIG8W
         QDLPgXn5zelcjuCIDwE6pLjFD7FU5O9a4AqfMswNHDJDbN9LCBW7ulxM03Jm3lWldyos
         UMNdC1YFu4hchpHtlYQAEYeKUKlag5can13zI0zLYupjCZF2IeFSIJuzjvcyiNxswp7g
         a7T/S6Maov8WecCNM8+u9YEJjsOGSe+o1GY10FefuPgR+uH+OLclBFVnRNpchuRD9/oo
         deVQ==
X-Gm-Message-State: AOAM533w/eSWAjvvt2BOwSEoBV4GCK6WO5Cwmu33QAkeJwsJevu5Tsit
	gkBsRaXNeGURR0a2C2R56Hg=
X-Google-Smtp-Source: ABdhPJy1Qh+40VtfE2UPFT9hcbJW3sPG6R1FITzl3q97je33rApgLhiWvbSC5sTRyx0087lrVeBYHw==
X-Received: by 2002:a05:6638:24d6:b0:317:cf47:aaf7 with SMTP id y22-20020a05663824d600b00317cf47aaf7mr12231154jat.107.1648450953402;
        Mon, 28 Mar 2022 00:02:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b4ce:0:b0:645:bb55:e593 with SMTP id d197-20020a6bb4ce000000b00645bb55e593ls1528817iof.6.gmail;
 Mon, 28 Mar 2022 00:02:33 -0700 (PDT)
X-Received: by 2002:a05:6602:314c:b0:649:a265:72ee with SMTP id m12-20020a056602314c00b00649a26572eemr5405180ioy.100.1648450952959;
        Mon, 28 Mar 2022 00:02:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648450952; cv=none;
        d=google.com; s=arc-20160816;
        b=gv8B1/dEC8J2OriiwwJY7dAkSebXOYiwxfLSQ0XkS16Zc3YpXeiKFlPZMeoDLZo2SW
         GZIX2QIlmU+5S2Doft2hTfdhUmEuumATJv3U6oxybOzCLcqklZ9srVgjwHLI9T9mjN9X
         wICWcj7rPYttv/MKO7iE6rza3jaDrdu+Aqggfyx5Me3GvlJKB8QgfofzzJQGnwDnXQfr
         1fXnsy7R50/pXyHZMDU381kwfMlbdZga1leLp5QODsoH68EAOLhcDBZu7jlOJF8hE/V5
         OLfvYOcRsxW5EI/3cRFHmgM5B04fqOWG5HcjoosOek2rjitDPQnNrBJx9qAI73ctJF4N
         nWuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nwxetPNc6Y1ndBg59v0qTwqCMW+RX+QXtDxwiYX/QcY=;
        b=bxdsVy91/6+GHRRQHlC02+JSynFUzPoSSInY8B0C6zdmtt7wtrZCz9rtAAWFyw5I9W
         rDmsMIZCOAv4lz9wSdt4e/LeOI9lUpEE0W/gwnnv5Vv4NcSpbq3hPI6zSPOpzxpf7Oo0
         6TPXWXnouPWn6I6Y1/Pwjxg7+PDc1rksRt5JSkoaajF2huhuIzF5OdbBbRkZ3efzor8v
         ZzwoR5t9dcCDQNaaTBcEepW2lZmHUeZ31pVQD8MzInkL3A/bJN8Oh06ZaSlCjs3r+MWr
         EWi/63LYx4xwsXaj1HP8e5CLaaaY+X5fF3/6u+1z0azuhTFDUULShZqweq0wIsQN+NFD
         gY7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oQjYl0VW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id az20-20020a056638419400b00317af1adf67si856466jab.5.2022.03.28.00.02.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 00:02:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id e203so15555835ybc.12
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 00:02:32 -0700 (PDT)
X-Received: by 2002:a25:d08a:0:b0:633:eba2:e487 with SMTP id
 h132-20020a25d08a000000b00633eba2e487mr20846788ybg.609.1648450952327; Mon, 28
 Mar 2022 00:02:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220327051853.57647-1-songmuchun@bytedance.com>
 <20220327051853.57647-2-songmuchun@bytedance.com> <CANpmjNPA71CyZefox1rb_f8HqEM_R70EgZCX8fHeeAnDyujO8w@mail.gmail.com>
 <CAMZfGtXt9xWnVv8hav+zWHYRmOqBGu3WPaasYwGxCb1-MDDwgQ@mail.gmail.com>
In-Reply-To: <CAMZfGtXt9xWnVv8hav+zWHYRmOqBGu3WPaasYwGxCb1-MDDwgQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Mar 2022 09:01:55 +0200
Message-ID: <CANpmjNMf9bwR9Oa-qrHZ5TBnR2pSRufgCuBjuNm0B428GB61Ew@mail.gmail.com>
Subject: Re: [PATCH 2/2] mm: kfence: fix objcgs vector allocation
To: Muchun Song <songmuchun@bytedance.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oQjYl0VW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Mon, 28 Mar 2022 at 03:53, Muchun Song <songmuchun@bytedance.com> wrote:
>
> On Mon, Mar 28, 2022 at 1:31 AM Marco Elver <elver@google.com> wrote:
> >
> > On Sun, 27 Mar 2022 at 07:19, Muchun Song <songmuchun@bytedance.com> wrote:
> > >
> > > If the kfence object is allocated to be used for objects vector, then
> > > this slot of the pool eventually being occupied permanently since
> > > the vector is never freed.  The solutions could be 1) freeing vector
> > > when the kfence object is freed or 2) allocating all vectors statically.
> > > Since the memory consumption of object vectors is low, it is better to
> > > chose 2) to fix the issue and it is also can reduce overhead of vectors
> > > allocating in the future.
> > >
> > > Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> > > Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> > > ---
> > >  mm/kfence/core.c   | 3 +++
> > >  mm/kfence/kfence.h | 1 +
> > >  2 files changed, 4 insertions(+)
> >
> > Thanks for this -- mostly looks good. Minor comments below + also
> > please fix what the test robot reported.
>
> Will do.
>
> >
> > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > index 13128fa13062..9976b3f0d097 100644
> > > --- a/mm/kfence/core.c
> > > +++ b/mm/kfence/core.c
> > > @@ -579,9 +579,11 @@ static bool __init kfence_init_pool(void)
> > >         }
> > >
> > >         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
> > > +               struct slab *slab = virt_to_slab(addr);
> > >                 struct kfence_metadata *meta = &kfence_metadata[i];
> > >
> > >                 /* Initialize metadata. */
> > > +               slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
> >
> > Maybe just move it to kfence_guarded_alloc(), see "/* Set required
> > slab fields */", where similar initialization on slab is done.
>
> But slab->memcg_data is special since it is only needed to be
> initialized once.  I think it is better move it to the place where
> __SetPageSlab(&pages[i]) is.  What do you think?

That's fair.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMf9bwR9Oa-qrHZ5TBnR2pSRufgCuBjuNm0B428GB61Ew%40mail.gmail.com.
