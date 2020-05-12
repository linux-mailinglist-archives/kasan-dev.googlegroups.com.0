Return-Path: <kasan-dev+bncBCMIZB7QWENRBJWZ5L2QKGQE4TDKTKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id F036E1CF660
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 16:03:20 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id t9sf11926905pfq.14
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 07:03:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589292199; cv=pass;
        d=google.com; s=arc-20160816;
        b=btenXzueSyqvSvQfqRTeYfTm5Na7WD6LXXSxAhNxEskZgJkGU1ZDdyixgoANETWPMo
         HJlCmId5WvgjxTyw6yW4ucuCaYg1mZeYlvu3N5hDQYRikz/RIS5NYUTFWHiG1TSJebdR
         R+0plt088SOiWTg5HUWS1WgWylv8PjkDg6lfoVv0kFfSwbbjE4BfDs3iVujbc5eUHH7I
         U0kAaDpND+piWH5WQCt8xmOhsgraziAfmTRAsUxNizrBEevH602QZtuzxYteaqgSVL9o
         l9tQjIyLEWcXw4RIyV+8/3KYJ1rf6rW6S3Zfobo74Apc+skE8wMHGlUfweuoMu5Igmmr
         ZRVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hfiNt8iyCtTOAH045JUFWaEVxa2R1Rl2bFSdSe7p+6M=;
        b=o6Me0kNDiHxHB/3f+5jupo9Xl612BJjPj9zCpWUL6k/6Bx6Jwj4JYqFPs/iVquKjRU
         1Se4LScA0OnRBxJZrzkOxAbsPlR83U/4N/lC8RdwQWgwfhgi2QLwolAg0FL5ziTTpGrr
         aYHK9PepdhY7L9rYfxSzTG6iDFko35HPKjHyvbcLc5q5tW65FmLhYx5vbAEIAyfb7rq4
         j5lZmI28iAzGjRaEXR9uJYQ95zm0MgrhMjtXPEITO5bJh+j/zsmRYO0U1oTyX7y73J8h
         +/PgPvXBYuPtGSH/dremLlLPFOQgEANDWwWiQ2VnqRb4fWOYsgj5MKgM+be195G8zv3z
         QWIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQawiJ16;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hfiNt8iyCtTOAH045JUFWaEVxa2R1Rl2bFSdSe7p+6M=;
        b=epYlOqOdtqqpvYr9SSZD2dCx3gw3Jb9B+GjfvnFeJ05TpNV7GmvlFrmpX/z7orvqg7
         rGDPXNsFxqhJdcQdCGD2V9jdgZ+BoVwsaucv012qdrWDo9O4Hqc9rUiPNu8QXme8u1a7
         UQ5gwx+QZGSyCy1qlOH2X4DKKhsGp5mCcwWfnJZNNvDFpmXpQd4fhu/6GIjJROqoUGq5
         GxKw7KZo2XP4ut3wjXpek1IE8zFDxgOn/8HKM7wOnZDptQARDcdGym6GjQVqhKsEn3NJ
         mwMeoWSXx4kSq0gvGU1wCJxlztgkYp3X8qphuvCW38aI8p+qoGTfe0Z4Vi0iyjSctxHa
         2gmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hfiNt8iyCtTOAH045JUFWaEVxa2R1Rl2bFSdSe7p+6M=;
        b=dlHKXS8alAQaMnGI2dqUrnb/fB5Jw99aOUxks5noM5wc+m4M+JsABONHGArSSMbl1V
         GtZIkXFVLbAQIkHoysocOYUtweyYgE8Y1nQlaWZ4by5JYrzbk+px6bgeo2jjmB8lWggH
         xCZjtBOqTKWhuREbaor9SG7Ncqn3iLLGgFW3cCW5KXGI216pELr5LrymZz561ofPUUos
         2glAaGZtHmLXqbEnnBEltV44URMDDzb45lE9JqOQiQ8VP0Ha0I+9B1HaWBR6SKdSq8Vo
         W3uGAT7GexGqjg/Wk3cLgnwtbJfyq78vLKbFgzglT3ms+IkIg32KKHQ6MARkFuwMBQRZ
         ZNRA==
X-Gm-Message-State: AGi0PuaB0uS39vx2VH/9A0C7ex7bN4rOq45TQ662WoNCs5Pc8/jPzNbD
	E2Hfpis40gdjNxJKRrkRe1I=
X-Google-Smtp-Source: APiQypKXYKwg06fIPQ1efK+a8FTpfdwe8gq2M8ZbZORe58Jdz4eJ7lWJPIAGNBRTaVqbZ9TLN2PCjA==
X-Received: by 2002:a63:1e22:: with SMTP id e34mr20491929pge.427.1589292199042;
        Tue, 12 May 2020 07:03:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f04:: with SMTP id p4ls1451228pjh.3.canary-gmail;
 Tue, 12 May 2020 07:03:18 -0700 (PDT)
X-Received: by 2002:a17:90a:f2c6:: with SMTP id gt6mr27215304pjb.61.1589292198605;
        Tue, 12 May 2020 07:03:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589292198; cv=none;
        d=google.com; s=arc-20160816;
        b=mnKEy1bVj6Feek9t0FTCSwWlF5VHzALWpX5ozZhPgxnmTUBP2tJpHOUIZ37i06JFsK
         R6SenwGbx4gckVgnTornm/c+EST2lEr98gOTd5GyVnHFUzkavSDj7z0rrsto2OOA0fFl
         cM+C/Np/e1bN4sxZlxd6kOlYnK/k1JiFDFuZScoqN5+buRIazHNgPIHCbQbWunqzkD8k
         eZ2dGpXhFStgNWePZ+67b3Z+PcGZ49TgdMvhOMpRqINTVs1eOrowLXcVAjenjVSGOV5F
         QdTHFizCUkbsAjB3h6XNw6t8EI1Ch9ugSlKwR+ENFmVVo4a0ZI5I4r7bkeOmZ9mANQs1
         3r4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HdL0PoelnNwC+IbWuQ/qzw1k9SeDaMleYXr87Z/Ant4=;
        b=yV12GpgHHwfhJdkTQeqEp92TibE+Xg/0xpgdz5XOcCQsPskgl5vRsOcd+gXtsfRwcK
         cWsgygg4YwLq9W/xYKZPshx6vtVekcpgnFjEDvv4DiqKRjDWBlMQ3QG8JJOjdtZrUc5k
         LTkuDvgNFXMeRdSbdHNKzdm3YushvJdisWcuN7WEzzOFzojmhUbMYAX3YoNcPd122Tqf
         Zsj7d6YzuLlgfHFashP2fN96ISEYgpoOqs713n/0/N284an/2wh65Vt9ZB+xa4f8KPXp
         56HIoCIEE2G+mqLTiAteWJ2HnSlW+btAdq/sMG9OORwPkDtY8OmldRFNnqC7zULfsOBR
         lcQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQawiJ16;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id c17si252298plc.5.2020.05.12.07.03.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 07:03:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id ep1so6429198qvb.0
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 07:03:18 -0700 (PDT)
X-Received: by 2002:ad4:4d06:: with SMTP id l6mr21334959qvl.34.1589292197432;
 Tue, 12 May 2020 07:03:17 -0700 (PDT)
MIME-Version: 1.0
References: <20200511023111.15310-1-walter-zh.wu@mediatek.com>
 <CACT4Y+YWNwTSoheJhc3nMdQi9m719F3PzpGo3TfRY3zAg9EwuQ@mail.gmail.com>
 <CACT4Y+bO1Zg_jgFHbOWgp7fLAADOQ_-AZmjEHz0WG7=oyOt4Gg@mail.gmail.com>
 <1589203771.21284.22.camel@mtksdccf07> <CACT4Y+aOkuH6Dn+L+wv1qVOLgXyCY_Ck4hecAMw3DgyBgC9qHw@mail.gmail.com>
 <1589254720.19238.36.camel@mtksdccf07>
In-Reply-To: <1589254720.19238.36.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 May 2020 16:03:06 +0200
Message-ID: <CACT4Y+aibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QQawiJ16;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, May 12, 2020 at 5:38 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > Are you sure it will increase object size?
> > I think we overlap kasan_free_meta with the object as well. The only
> > case we don't overlap kasan_free_meta with the object are
> > SLAB_TYPESAFE_BY_RCU || cache->ctor. But these are rare and it should
> > only affect small objects with small redzones.
> > And I think now we simply have a bug for these objects, we check
> > KASAN_KMALLOC_FREE and then assume object contains free stack, but for
> > objects with ctor, they still contain live object data, we don't store
> > free stack in them.
> > Such objects can be both free and still contain user data.
> >
>
> Overlay kasan_free_meta. I see. but overlay it only when the object was
> freed. kasan_free_meta will be used until free object.
> 1). When put object into quarantine, it need kasan_free_meta.
> 2). When the object exit from quarantine, it need kasan_free_meta
>
> If we choose to overlay kasan_free_meta, then the free stack will be
> stored very late. It may has no free stack in report.

Sorry, I don't understand what you mean.

Why will it be stored too late?
In __kasan_slab_free() putting into quarantine and recording free
stack are literally adjacent lines of code:

static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
      unsigned long ip, bool quarantine)
{
    ...
    kasan_set_free_info(cache, object, tag);
    quarantine_put(get_free_info(cache, object), cache);


Just to make sure, what I meant is that we add free_track to kasan_free_meta:

struct kasan_free_meta {
    struct qlist_node quarantine_link;
+  struct kasan_track free_track;
};

And I think its life-time and everything should be exactly what we need.

Also it should help to fix the problem with ctors: kasan_free_meta is
already allocated on the side for such objects, and that's exactly
what we need for objects with ctor's.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaibZEBR-3bos3ox5Tuu48TnHC20mDDN0AkWeRUKrT0aw%40mail.gmail.com.
