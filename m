Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ5VQSJQMGQEBCWL2YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8427B509B0C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 10:50:51 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id jz13-20020a0562140e6d00b0044c50829dbdsf1053837qvb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 01:50:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650531049; cv=pass;
        d=google.com; s=arc-20160816;
        b=sqHY6Dphb7+eqXGu0Xq2thB16gE6cAt3qZB0LBOPqkrYqg6NKmBDCb2ZI8jYktKtOA
         +m6t0iNL5w+EewWfHk98/4DhJZlHlKUVyxd6sDAtS/NL0hY4DEf2OPo1aeFXa6B0CF+9
         BxhAIxaFplu415c+MaWYHt1NF57N6mGy5HKci4WIJI/JSrPO08gImt45oBrvr8VRe+aZ
         zZT9znHXhV4mYZnAc0auBozH+/h7pTtI4LUgGr8p86vE1Ljegf8iWVnILNYzCxI8hnhM
         vzwRRvNgI65M3c7OBx9uou3fZ+wfsQ102RxsHqn9IZvoYEMgjkatscmAKFyXnsJBj8HA
         5jYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mcjg6tuFPFHb6rP8afDmvnHyO7OiQX0wmQhwICTsiOo=;
        b=nsHhlblTCTfVVxlMnhnFnAQv+H5pLZpXdrDTNxBx2YES8537yZ28v/LyIJdiDJE0zK
         BjWZhJs4uOkqP+Nts63Jl+ys79X6aN3+laEql8mPoOe52rJK8/ykxZ1zOui22wCVbPY3
         i9yhRGG5ZZ548Ipn9pp/6F263CgwIBNq1i0ZIBiixuNV4krATI7UNtC8WAH8N7utbOSp
         rXjZfGUfRNfKqrF+cbLW7PCicGSUx7PCsJSq93rO233SxZ8RtXPYBKFq/dNj6GJp+9IS
         pB/+cswquHKdgUDoZ8bJZQ3Gst1x1YNbbhwVBGeMfhYgmEESU7w+PH0ESpRweMp2p2xv
         asGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=srOPHl+S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mcjg6tuFPFHb6rP8afDmvnHyO7OiQX0wmQhwICTsiOo=;
        b=OfUpxXKJZ4t0FPKat3XXESMQKo9G12eyWUYWvuu51WMgNYG7y1UU7zO9aBzAvNWa/T
         ZJfT1dYSq+7vNBhNHJ4HogoNFR+is1ugklzs/iFY6ujwF0Zf+WU4B07pcGC98Q88lLQQ
         c3KR52VtrF+wFSFgGk256oFtMU71k9b1MHieoHhTmr5ADrXcWPK40aC8jS02j1RAq99T
         KVqrBWQc13KheXNyQ6suTTZFFLO4Vuv20SU8ZdaldL7vFDn4lrJ1L1k8Rl7UoK4FOXTr
         NAEgjvxXZFKrLxzdqqXkiH0q+pINkNKpW8XMz684/fvj/G4hMB+Q9+o9BUFtKcsqclFB
         EW2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mcjg6tuFPFHb6rP8afDmvnHyO7OiQX0wmQhwICTsiOo=;
        b=GXEf6aPSrFsZUuM2ZtI17Hr399/bwDCm7XszScTOKglsnr4AVcFuKp2t5dKa65m0bn
         IZ3HDRywoMER0o5JXasALlPMNzQv4lqghIQxD1cg4RxXyT5YM+cne0MKdp7jQf6m8nme
         22YFdyFzFcwLCvVbkXbC+CLzlPXQfflnhkHoBuKgwbHN1xAZG2ng+ggZHOy4FYuk8eJD
         JfLQ2Pn2UqOboB2MNgzbIClrM6EibBtK7VimjZhbxbwVjbpU+msDHMLBwL3iVOojeuoH
         +UoMECv9h8r6zhVHI/Y75S/9G9EqJy9kYoQikUGuHpHfB7g2+awYbXFr/OrEbpakeQdE
         qvgQ==
X-Gm-Message-State: AOAM53080fbK4GMWt4PD0o0gxHwhsElHyEAG/WSjUO+2ecJP+Eks9grN
	0i22A5qEdNsYMqkiQ5M/L0k=
X-Google-Smtp-Source: ABdhPJxChTR6XvtjKOKX+NFass4gvr1TZbOXHegcgEv/Kz5LotZsC6WC1Z6cMRMLNC8Hpbt/rI60Yg==
X-Received: by 2002:ac8:5f4a:0:b0:2f3:34b7:56e8 with SMTP id y10-20020ac85f4a000000b002f334b756e8mr8748333qta.110.1650531047290;
        Thu, 21 Apr 2022 01:50:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a28:b0:2f2:47a:2ea8 with SMTP id
 f40-20020a05622a1a2800b002f2047a2ea8ls2640893qtb.8.gmail; Thu, 21 Apr 2022
 01:50:46 -0700 (PDT)
X-Received: by 2002:a05:622a:594:b0:2e1:d59e:68ed with SMTP id c20-20020a05622a059400b002e1d59e68edmr16741271qtb.204.1650531046731;
        Thu, 21 Apr 2022 01:50:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650531046; cv=none;
        d=google.com; s=arc-20160816;
        b=vggyg2wr10a2WH7Z8zUxGfuHCc8NP01OmAi85q0w2Fj3Wjbovf7RVi7uPxAA1Uq7dq
         /jNKiRYLyE0ZDPgc5fQOUBhzRXOOq1TW3mw55K0qd/u4gxLi9VIdH8gxIEnP89Ed/FUz
         EldVH/g/vfl8sLshuUx8j53xur6CfxDzKygorNoioZ3nCzSlOeGdDYb6QU73GFc8QxkY
         dLWsTYAlP42yawKl+jQz+vDAO5HKdITuilvjJjcoTGtr1OhGHC30VIJoU4BoLt6vbQtl
         /VL59SbgzCotioa4voZ75tg3upq0lYokRmtDLFIJrjxWJQcYsMcvkrRTNI7bBIZnuELk
         ZGEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2+Tn3N0Fvpk4WLUjDImpMjWVuIM4JomwqBL2Nlcl6w4=;
        b=XMOx6oFPk+S9gf+ISRN7Qzz6S9UQG6ea3nwBuEAmIkTz954uZz3cZApM4m4Uq0KPtI
         bt0t9YjUgtnNG+8vgGe+WFy55d/4r73a2tqGuQwZ+sHbvVq2An9XcZc08ZAHUq5kkjHq
         qQRZeuXdEp+1t/ohzIwQ9Ld3Pnj2OGPqmAeypTsna64BhD2/IJB20ROHH/FmCHEl9Idj
         9bI8soX6awG7ILt095li2IMwWpM3ARy3ZWOqEUHrBUWi3BEj5cRQF2DrNxR6oINGbblj
         PVvMg8HV7LC+pLM//4V2hffzV6oR6UwOEWKzhYfx9IkDld0geJ0Ni0XpOPkk+/PT2CLo
         icHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=srOPHl+S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id y18-20020a05620a44d200b0069a1403b083si475824qkp.7.2022.04.21.01.50.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 01:50:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-2eafabbc80aso44511177b3.11
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 01:50:46 -0700 (PDT)
X-Received: by 2002:a81:6c89:0:b0:2f1:c84a:55d with SMTP id
 h131-20020a816c89000000b002f1c84a055dmr12785051ywc.333.1650531046192; Thu, 21
 Apr 2022 01:50:46 -0700 (PDT)
MIME-Version: 1.0
References: <Yl/qa2w3q9kyXcQl@elver.google.com> <20220421083715.45380-1-huangshaobo6@huawei.com>
In-Reply-To: <20220421083715.45380-1-huangshaobo6@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Apr 2022 10:50:10 +0200
Message-ID: <CANpmjNMAT_DaiOoz=k6Z13nVR_2A_5fck12h0JKQSmNQRSKwGg@mail.gmail.com>
Subject: Re: [PATCH] kfence: check kfence canary in panic and reboot
To: Shaobo Huang <huangshaobo6@huawei.com>
Cc: akpm@linux-foundation.org, chenzefeng2@huawei.com, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, nixiaoming@huawei.com, wangbing6@huawei.com, 
	wangfangpeng1@huawei.com, young.liuyang@huawei.com, zengweilin@huawei.com, 
	zhongjubin@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=srOPHl+S;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Thu, 21 Apr 2022 at 10:37, Shaobo Huang <huangshaobo6@huawei.com> wrote:
[...]
> > >  static int __init kfence_debugfs_init(void)
> > >  {
> > >     struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);
> > > @@ -806,6 +832,8 @@ static void kfence_init_enable(void)
> > >
> > >     WRITE_ONCE(kfence_enabled, true);
> > >     queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> > > +   register_reboot_notifier(&kfence_check_canary_notifier);
> > > +   atomic_notifier_chain_register(&panic_notifier_list, &kfence_check_canary_notifier);
> >
> > Executing this on panic is reasonable. However,
> > register_reboot_notifier() tells me this is being executed on *every*
> > reboot (not just panic). I think that's not what we want, because that
> > may increase reboot latency depending on how many KFENCE objects we
> > have. Is it possible to *only* do the check on panic?
>
> if oob occurs before reboot, reboot can also detect it, if not, the detection will be missing in this scenario.
> reboot and panic are two scenarios of system reset, so I think both scenarios need to be added.

That doesn't quite answer my question, why do you want to run the
check during normal reboot? As I understand it right now it will run
on any normal reboot, and also on panics. I have concerns adding these
checks to normal reboots because it may increase normal reboot
latency, which we do not want.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMAT_DaiOoz%3Dk6Z13nVR_2A_5fck12h0JKQSmNQRSKwGg%40mail.gmail.com.
