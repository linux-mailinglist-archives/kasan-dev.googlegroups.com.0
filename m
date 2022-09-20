Return-Path: <kasan-dev+bncBDYYJOE2SAIRBDNCVCMQMGQEHSI7LQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id CFA325BED66
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 21:14:23 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id n5-20020a4a3445000000b004728fe7a331sf1645176oof.23
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 12:14:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663701262; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMKUji9QYKt00ZCNVyi5yFHrUrrfIwjyI1bWXe+qGyG3PMBMd3H2c+CiBK7FNjqvK1
         EvaVbxQ3Xh6UkS3klE626qSJeW/SDb0TLfXKM87L2o6zrA/U1DrPyvHNg3y696TvKilz
         5dMrRTwFpfKxqYsvdB/xe/zkeZ4WbM4aBQsqJmVWHTFnUu2UZlyMz30j5fmRN8op6XzQ
         ZBQKghx1t1Do5DnQ0OgTQrPVCx/wuFSmk1FNwl8EsN68Zp4mrvNIW1npwVgjBJXhwPAj
         DRKAyZrpk/SRl1/KTcMGLFrxJU41BWPP6wAVV34en+7U0gz+J81ZZeQH5YtE1SwCLVEz
         yqPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QBjQUBvFxdXCGhq1DqfrbedkeechCIdlDk3TUVqILAs=;
        b=h+ta9soEdPUhoJEwHTtcX+pbv1PE5DHctII6DxF75ywDvIVKqqO3dClDgN2DgUDmEu
         l2LQ8uHZ/CEx/kgZxSJGSibu9OhSyTBOVPeQKHtw+/axTOD9z/UA+dGxc9ZcoPr4ZHhz
         +oLdmRt99ZO9X+MV+2vwubnyYCyyX548W0w4MOVW0BfZJWcwZeWdHToyV2K9ykORsBM7
         VixrW2batm98YxOj7PxfklS4mQgbMYdVvbnzfu1jQrbG//QGH1exNqabvL1B421Dq1gB
         lETAOmG7wEQR6gt2qj34lHMrUwK+IKxFrhNpuDDG6n5lUlvC/ZGLCe18D41ZGcJy5JtU
         Coww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=O9Q67sTK;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=QBjQUBvFxdXCGhq1DqfrbedkeechCIdlDk3TUVqILAs=;
        b=ek7DbvkY3V4q22Pn5Ft+c76CUExfSxTg0Zes63XRqSlHcPeO2foDSCzOsyPTXI3Jd9
         WY+IrTFkd5bzaD6FVefKyL7NanxEaerAYeQlS5V7siruEmIt8Eigc+WXQZYE0DCPugNv
         pMd0NzdESzr0IdGLaXwmSmTMpXkEoDXoNdw4orhRj/pXIO+kLvhDm43ffarHXorEagt2
         d/W5N06UR1ILRU6HAt+nGDl2WlGMbh8uSCGT5YoKLEDypaThE5a+NJZ1rGvpqcwD/RTB
         ALuBy4qKLixkC3HZ3/8a5/J3oM04c+oXiL7L60M67U6djS9nKm5cVcony01EC3uPiU8k
         q2MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=QBjQUBvFxdXCGhq1DqfrbedkeechCIdlDk3TUVqILAs=;
        b=O49bATQu5hS479CTDlu1bntSrd4rV6SIzVwqz8vsqEBMNOeVFBNQ5cx/VCD9Lb0wOr
         HFdJ33ORnBCBitgrWPiWl1Ia+tYmw3PLAjDcW7LT+M0JwwikKBXp+uCWkAT1Fkqfo5IY
         BjGL6YLYf5eg4Ad7OikS/kJlydCo59vb79y85guKzBE4AdLAXBVvamyyLSbpmeEtmWXP
         ETJSlNdfLjN9LXZ97PbC2JQkfMwsQlRqqo3eoohqaNcDwxjQXPKEMJhohv7+AtQ2Z+zz
         BHUbsL8UK4LKlwaORNdTysk/J4pzqzzlxuecQgZRD7qRKlL+10XImBcjvVP3tnsSSxJR
         RpmQ==
X-Gm-Message-State: ACrzQf38lJb4cFekIql9+UNCBij0nwbUNTNgIBOg3WpCvqtOFNk8AcnK
	CBrT7nYDygNtnWwLBiU9C3w=
X-Google-Smtp-Source: AMsMyM4iVOOsgwO5gMW+pNJaXjIzLvfOGXx1TxiA2ty1m6XWrU8J8TC3m5d1CgsbhChaEyftJYyyqA==
X-Received: by 2002:a05:6808:2194:b0:350:cb3d:ecd2 with SMTP id be20-20020a056808219400b00350cb3decd2mr2388366oib.46.1663701261775;
        Tue, 20 Sep 2022 12:14:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:542:b0:639:1b8:ca3a with SMTP id
 l2-20020a056830054200b0063901b8ca3als2135805otb.9.-pod-prod-gmail; Tue, 20
 Sep 2022 12:14:21 -0700 (PDT)
X-Received: by 2002:a9d:4d09:0:b0:656:3ab:28a3 with SMTP id n9-20020a9d4d09000000b0065603ab28a3mr10749507otf.122.1663701261257;
        Tue, 20 Sep 2022 12:14:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663701261; cv=none;
        d=google.com; s=arc-20160816;
        b=FySu+ZG9wfsRWlN0oFip0ifIQV00gv3WEyieRgmLTNFD9UQcYgOYzgZcqe7Zl+5MKm
         UnoOX0n3S6eOyr8fUQZFSya0duftPtJUp0/xXBG6K8Z2nMs6UZIAI1IR/t7Q5do4Ct8G
         c7LyG0bGAwmjMHTzGA72xRs9BcIBSnAmDEZ3VlDCpb06OFrnEqsiwUbKJ3emoq4PLxDD
         3O/j8Pnf53giL/NFODhvY/ZokaJbvEDRYOI7Qg87EOY8h//gunpNszk4/BGD3FUbxx8G
         EPSvEZCg8Ei6DMMDC+VRbBT0IMyEvZER4ka9ZELvo0ae+jwv8t/jvWldFfrioOi+BdzW
         0ZqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DYSX+rzfvx6PPE4TbO9ukbYwi6O5v4DOvDShsPehjZs=;
        b=A2F4OHoR4P2Uy9TZdCsLDmB76VgpHzS7ahkDPDcs2qdNVgosdQHplytk1kCAcEVbCG
         Ks/Oz3LI7giN5hbEclgQP2r7C5Q0Ddo0xLmM3EFdOUspf1mfC+c5EFuge4HdT1QtjuqG
         oO0U1xCswdyhFSehnFuxi8IWEKJzlFApmgZ3ZW4QEmPL1lI94cem0spGWza0+MR6Nn5/
         oqk6vpZT27UPaYHm2yMJ+Z0aEb2FjHLgb9yfKDGQtPdss0xwOSCdvsvkQy9fxakiqm56
         MaNmu3PtExfJjLGlXLeCh2Da8oM5VLI/xptm6KniEwsOcx010D1gmRAYCUrURHImlk5f
         F2fA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=O9Q67sTK;
       spf=pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=yuzhao@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe31.google.com (mail-vs1-xe31.google.com. [2607:f8b0:4864:20::e31])
        by gmr-mx.google.com with ESMTPS id r206-20020aca5dd7000000b003504d4fcb12si24532oib.0.2022.09.20.12.14.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Sep 2022 12:14:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) client-ip=2607:f8b0:4864:20::e31;
Received: by mail-vs1-xe31.google.com with SMTP id j17so4239742vsp.5
        for <kasan-dev@googlegroups.com>; Tue, 20 Sep 2022 12:14:21 -0700 (PDT)
X-Received: by 2002:a05:6102:3309:b0:39a:e5eb:8508 with SMTP id
 v9-20020a056102330900b0039ae5eb8508mr5938462vsc.65.1663701260563; Tue, 20 Sep
 2022 12:14:20 -0700 (PDT)
MIME-Version: 1.0
References: <576182d194e27531e8090bad809e4136953895f4.1663700262.git.andreyknvl@google.com>
 <CANpmjNN0jyK0svOOHSFPAfFV9CAEUVUb+y_748Fww-sgf=3pdg@mail.gmail.com>
In-Reply-To: <CANpmjNN0jyK0svOOHSFPAfFV9CAEUVUb+y_748Fww-sgf=3pdg@mail.gmail.com>
From: "'Yu Zhao' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Sep 2022 13:13:44 -0600
Message-ID: <CAOUHufY3E86dZ2SfZgC6X3nOHSm4MVuxsZk5grjnjrfSnaXpkQ@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: initialize read-write lock in stack ring
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: yuzhao@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=O9Q67sTK;       spf=pass
 (google.com: domain of yuzhao@google.com designates 2607:f8b0:4864:20::e31 as
 permitted sender) smtp.mailfrom=yuzhao@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Yu Zhao <yuzhao@google.com>
Reply-To: Yu Zhao <yuzhao@google.com>
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

On Tue, Sep 20, 2022 at 1:10 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 20 Sept 2022 at 20:58, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Use __RW_LOCK_UNLOCKED to initialize stack_ring.lock.
> >
> > Reported-by: Yu Zhao <yuzhao@google.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > ---
> >
> > Andrew, could you please fold this patch into:
> > "kasan: implement stack ring for tag-based modes".
> > ---
> >  mm/kasan/tags.c | 4 +++-
> >  1 file changed, 3 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > index 9d867cae1b7b..67a222586846 100644
> > --- a/mm/kasan/tags.c
> > +++ b/mm/kasan/tags.c
> > @@ -36,7 +36,9 @@ DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
> >  /* Non-zero, as initial pointer values are 0. */
> >  #define STACK_RING_BUSY_PTR ((void *)1)
> >
> > -struct kasan_stack_ring stack_ring;
> > +struct kasan_stack_ring stack_ring = {
> > +       .lock = __RW_LOCK_UNLOCKED(stack_ring.lock)
> > +};
>
> Reviewed-by: Marco Elver <elver@google.com>

Tested-by: Yu Zhao <yuzhao@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOUHufY3E86dZ2SfZgC6X3nOHSm4MVuxsZk5grjnjrfSnaXpkQ%40mail.gmail.com.
