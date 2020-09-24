Return-Path: <kasan-dev+bncBCCMH5WKTMGRBN4QWL5QKGQE2YBX2OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 75EC127704F
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 13:51:20 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id n24sf819686ljc.9
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 04:51:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600948280; cv=pass;
        d=google.com; s=arc-20160816;
        b=ua+fEYzwCMjdqIvks2LAnpRUvfiX2fl0OGlQzkrY7zgJeb015UWE5jAn3Sdee5TZE3
         C3WUavy2M9ez1HcEP/bnJeA7bCa3ZcRQ5s8ZijB5ynkm5AAbwWZ01ckZerjH7tBsjf79
         ePQQTtDzxr6go2DxDN8bdiz2TxkvAjWlLpcWhpWPC68ZsgJ0G5dTi3GRt8xmhaGC8YDn
         ErsXpG/vujBnP7V01zNOvV5BqYmqtC2cz/fIwB6pOHm0VP4cRWvyeQAkKGRuheMGjm9N
         wvuKdPA1tZNMKEjLn0fryIqGyGIhqGyN0GxUtbnlOtmECDTcIiMmv/z6HUvnMijKTq7N
         eISg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZCF5nnQjyG8XMDHw4WGJYrwam6R5IHwss+AT9dNtX6c=;
        b=mcb4d41fBcwnKOKFFuuPaaYsGvcGU9e8j8Few1TemE4YP01ChpBTvh+Yh8rdBz48en
         zbl7KJK6DyDKuPhfvA0ED3wze21V8REEAv/NNODEuKaLAu+coFX/jlQT9CYNH4+KxxJX
         YCRFqqAdD93XnnJle3RG7agMd5tWakL+ATE+eGXYcUk9BRlqHDHGqVus+lORk07vpM3R
         tn9wAvrbsuXF/drXRGzgHTQ5i4cwL04wpFVwGQ9XIrcH51MWbUbbm2auy9rKtGl44Dh7
         YZVzGtAAOkvw1E6V3XbyfcJbdnpB+sg3MnWf9Fd+0O0iY+cMbfFr4nPQdFwVWWWvzyS2
         HrOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SEHt+4r+;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCF5nnQjyG8XMDHw4WGJYrwam6R5IHwss+AT9dNtX6c=;
        b=gsJtT+jfWFciDcluqpS/Cek54vFk9hOjIF/dIkr3tuBDKCcmWuVLKBp41MFZkCu8TY
         /Zo7dEFjonK+TI3c3fVZaBvgE5LAaa/n7wCA9UwKfchQiF4fdiWx9A/DHUCsdqHXKRZi
         rPFD0Rf0df+rQAMDqPbAzeuEA8i3ATSZr5oq4IUOrCbgbtNRtPOFEmHqjnbzIwZQ5e2D
         Kl+84RJM1MSbj9GzC6qx9+0Fd4BQVQSFn5kF6px0+hJmSeyAISk8NjuUyLeArjIgC+Ma
         MiXzACeS2ag7lsxYd+UFEwWImcVQg5rSaZr8rRkYgEJx5UKNn8/MWghbmx+HPw9TNn7d
         RWOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZCF5nnQjyG8XMDHw4WGJYrwam6R5IHwss+AT9dNtX6c=;
        b=di/esiDErZCBBPabUYnNT5nD0LHikcDi+/tU8Gs/i0t1TmwyzMD8OH79siPEV00s3P
         fRAIQ62Eugb6wCS/aGppaZTuOkdVFenQ1iZ7spVy4Ax4DaflFmpUeG+6giW5BbQpQFu1
         HrEQP+uruklAeC21ww9DTMHm64nInCRkUv715czJdaAeOxG8dV8UYAiIyhr2jFOfZ9h8
         2v1uZCcdquYmcqn3/de+OR6buSyqA/sw1WwiCA8rc9DEdA0n+zfu/4yslqK0B+XEN+ab
         AvQ6GjyYZLHR2C9VbySQMShyvoP8Z11V6UdWeVSkraULoICqZLEuSRHeWQzqriNf900T
         GtDg==
X-Gm-Message-State: AOAM531RXluBV9qmI/Ya0xVBcO9FbIRr/4TYtJ2JxmQjYO5SdG3D5XqD
	v9vzgGAT14eHwsGJ2KFHBGo=
X-Google-Smtp-Source: ABdhPJzrtOzjtzPVysFcpbmo5hh+xdySJhPhtstzF2aAcbE3xMBwPx4ewooAOrPje9RuKzH7ASQQmA==
X-Received: by 2002:a2e:8884:: with SMTP id k4mr203935lji.333.1600948280067;
        Thu, 24 Sep 2020 04:51:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls637903lfn.2.gmail; Thu, 24 Sep
 2020 04:51:19 -0700 (PDT)
X-Received: by 2002:a19:8286:: with SMTP id e128mr155022lfd.307.1600948279024;
        Thu, 24 Sep 2020 04:51:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600948279; cv=none;
        d=google.com; s=arc-20160816;
        b=mwwfqSq6X8zcIeNESREqpVjgDlZQFBahSeehpGUirSZfCDn+dHiuMpzDcHwpVXJNKQ
         0oLGsKNvYIDRgSPJhWz0S7JJJxyweuV9iGQmLgfYA/o1Nv2U36T1/M2YBjTnvuq8w7RZ
         GZeJU9TXboBcTNROwaxpQD1CS/57ABbtivtI38OoJrGP0hRFEE5wHw2ED7fdqqoc8oKr
         88wwr7FYltm9jrZEFBGvh3zn1/2KGQ0VBzNjDYQZfaNZhlkma5K8BzKlkoC8nYQXQBbg
         W7fXErLUdMbPa95j6F/fdk3nh6mci+y9UGj7rNDx19OABO/P/HzVN+7PLgDRJLnf1TEk
         cqvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Nij/PwpDmOmT8ZNid9jsa0R9PGd/GWpm5CA06AHzYf4=;
        b=oy885BxfEvAoKYP+2aVcqvHTWoSr6VsSD/ejhUcyAN8F65ZyBqICfI6A8Rf7/8LFvv
         nIngBIZXIup1bZMugTxt5JF47dG9pN0qeKred5N2ww8O66H1A8ED4nFssWVG+AF7kHNB
         y1Xdukkk0NAI+PgCeudVIyhPF5OeOFK1StEvj4zHRdrEDJal6LWriZLxGCO4aD4bapT0
         rtis+Zr3/5fRSX8NvXzTW9IhwfsE5L9IQQgZoy1lph+xGB41PhXBXXkaT0HbPVwYU5AJ
         iMjhrjqDzrZWjhsWKmV8ydvxXpxH1WpduLaY7t18ljI3VOvJOkfFRyrcAW0HCnJbXzCC
         X1yQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SEHt+4r+;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id 143si38232lff.10.2020.09.24.04.51.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 04:51:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id e2so3294027wme.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 04:51:18 -0700 (PDT)
X-Received: by 2002:a1c:b388:: with SMTP id c130mr4322495wmf.175.1600948278294;
 Thu, 24 Sep 2020 04:51:18 -0700 (PDT)
MIME-Version: 1.0
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Sep 2020 13:51:07 +0200
Message-ID: <CAG_fn=U_dshqBB8HBhGyYnn_vScTOcLJX=mfU+8Wi5wjZL2oYA@mail.gmail.com>
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, 
	John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SEHt+4r+;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> ---
> Documentation/dev-tools/kasan.rst |  5 +++--
> kernel/time/timer.c               |  3 +++
> kernel/workqueue.c                |  3 +++
> lib/test_kasan_module.c           | 55 +++++++++++++++++++++++++++++++++++++++++++++++++++++++
> mm/kasan/report.c                 |  4 ++--
> 5 files changed, 66 insertions(+), 4 deletions(-)

While at it, can you remove a mention of call_rcu() from the
kasan_record_aux_stack() implementation, as it is no more
RCU-specific?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU_dshqBB8HBhGyYnn_vScTOcLJX%3DmfU%2B8Wi5wjZL2oYA%40mail.gmail.com.
