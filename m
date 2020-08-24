Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIMJR75AKGQEVFGWEII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D0C024FF43
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 15:46:10 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id q16sf6596883ils.19
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 06:46:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598276769; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMy4+LzfD2Q1xd1EYtd9dL8fL4cxmNhJPzHULsu1NMXDrPZJMekzwkLUHeW8kGgSTi
         VEcgJGJQ5AF+ZLtCB7vRC4vVUXD7SmxtrkhGnpex0SY/hiroPgIIgHEdbrj/3HAC8VLb
         XsuO5hYG1trW25S1X+1VEs+wFoMj6+LCgCgu4sPmVH0Rx5LmvzGjoTH48/OPtHzu62LF
         2tnck7C574xA7xNI/GMujrbEWdjZvUwXv4tcZCGSj2XhNKmOk3mTPwt79KsbinflsU/3
         aErlj85ChZwnWqdgLmA222khYhDKOrS4I/PF4unKryh0psqMh3ksMYKOTQkpXo1UoggA
         7CXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JcC4+JCfXKdw/LIrlkMhA7PlADhVTPWdAcv8J+M5gFo=;
        b=SJaQcYNkAmS3R5BAXIMf9cIp5Y2P164HJ6USRLJ/KbOvO/tb35tGRqLnUGMNsBvBU8
         9j99GY4k6Gy1N8AfILBJOPxXimdEc3FceX8QBIceC74Nc5ZPe9loVu4GR4EQop3saimF
         h3J1w0ZpESysc0GXgVu+oJUMXMxpfXIm0QxoirVm9HKfq6bN7EbPhqDVSRAYnVeZr2Zl
         EmfeDVOoeOEK4IoAufD2C5YvK9KF8JRaX8QnOo/i3FfFZYdJCxwCq6Ewzm/srftIjsi8
         r2Pui9YgYDi3OnDvRDVCICLPDWrWe6Ca1i+Ykh2BY+xmexM0jvI27azNy/rT3eoHcf6r
         S5AA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L4Ekwisf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JcC4+JCfXKdw/LIrlkMhA7PlADhVTPWdAcv8J+M5gFo=;
        b=A20YJ+7MD9IAOAouy6HS/SpJ2YvDyCTdvgv0xXYJmIAinxKsgMl0gs5AxG/IJ8xwC1
         aLflMlYjF7jdBEdLAYV3mObF/T6p9+hepJZGVShqNkqCqp8+YlwyW19SFE3pw74bWtsX
         vMuAQTD6HrTTzxUQOLK4sIN4e+eSMy6ps2GbhLFmNvS+td8ovW8GudbRbyLAD7nKKws1
         upOuhRb31wfk6oIhuZ31G4HCZS8eclqSrj+83wJ7PXXfy1gcvfaksvHBsGVZeYtCPp7j
         EWArG1QvOL5XspLPi8M77PQFF7/SvJbwfjMrgax/WVfheG97d6LuVhNgVvx9/W/Y39Ls
         mBfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JcC4+JCfXKdw/LIrlkMhA7PlADhVTPWdAcv8J+M5gFo=;
        b=sjk7Cjo/rCyRXWkrUW5WRZioAcMKstwTcVthQ+UR3u6z5Y2TgZr0YApD8PSN+HzDcr
         5Y8Ak918wLaPY9511T+M54YIosXhVXRcgh1YDTUW4WfkzXAdlHBEWEeXm3ZLtdd5IKfu
         1fJuqg8cKdUO9bs/Fb8H4uayuRUwCjz6hfrUrQ6zd8u5IUkIjI0bXd4NnPoAiL36QFd4
         0hXVh8zqe4s8ltac9aBas5ggaLpNfqyuIF/56+W0Yrd78EghJis9ENHCW1jlmRKz2kEo
         BV0sqt45Ip2XBuip4dvmu8GtoCS5bfzQajWXm5oVxtvc9TKeLMTsJgkoewqIESAI41G6
         yzTQ==
X-Gm-Message-State: AOAM532DdvxXHJ03LSs2pWOkdkbRBMKqacd9K/sFUT5lvayHOULLNOGz
	Z703HDP3MGn18O1KklcsTNo=
X-Google-Smtp-Source: ABdhPJy9I8JK/QOwBnb9CYeHBgRiy+CBc/yx9dQbczwAQ5GjdkRLaf1jJiM/dnv5ZW7QNQ4TnmJ62A==
X-Received: by 2002:a5e:c305:: with SMTP id a5mr5080151iok.142.1598276769110;
        Mon, 24 Aug 2020 06:46:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:12a4:: with SMTP id f4ls821382ilr.8.gmail; Mon, 24
 Aug 2020 06:46:08 -0700 (PDT)
X-Received: by 2002:a05:6e02:c2e:: with SMTP id q14mr5228240ilg.286.1598276768809;
        Mon, 24 Aug 2020 06:46:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598276768; cv=none;
        d=google.com; s=arc-20160816;
        b=Qj+PgF6K7XH4yFIlMrInP1p3fVG/QSh4ikuY3tZSFgP8s2orJEF4koi9gY4BaLEuvf
         JUITJt53wnk5BbnxSxzCrKnSSDxvi8iEWrxm2TgmgdJ0f1Qg76Eab8ZR6rphL//oaUAF
         jYw22b6mVRVB0rrSOx50B9RdLh7g4UTfgJ2FE2k0bxGWwWG/7u+ugxNbe9T/2VCRy/Kx
         8nPWPZ9tpb5+L09O++SchizuRpcVecebbfMn6NHn0QwC/0FduhI3Djv1Kyw0XxAoeP83
         BqfIjjerb2kB9OfQck+XN5XXgifoGG/8aW8Uyk0HSt9/p8yLnDgGs7EsA/1AzYD4kwng
         ibxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kCkJ5WyjWp/vo15sfOy04O9dC6dPdDe+nxNNjru5ZGQ=;
        b=Y3vKEa3zTVUkmZkJapGzPm6dA89QqFqPjYUARt8rMMbOh4B98FuiVDVLoJWDlYhhGM
         7VbfsXijz6O/yaXS4bhgxP+Mf/5j8X7wFfiSDw9RxQf7gsLfccakXSwythqXnmI7tBfG
         MDsB3Hb6bc1uAFo0xCNfodsn/gtmqINZNnv5kWQWFGMgolt0ZUqcYkWRyThlqOLOfedE
         zBk458NNZpgGDJow5lC/5weC32KzMNHgNpLS9FhS6THkxE5iK8FCA3OayOKk8JgT6Ftq
         RG6AwXQ1a2H2GMI4RSJPT0ybmInBktdbySmOThXvL9pkWnKeEPDfBDNfpSyCMdHCD7lE
         BDqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=L4Ekwisf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id j127si397836iof.4.2020.08.24.06.46.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Aug 2020 06:46:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id h2so4261988plr.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Aug 2020 06:46:08 -0700 (PDT)
X-Received: by 2002:a17:902:6944:: with SMTP id k4mr3098268plt.147.1598276768239;
 Mon, 24 Aug 2020 06:46:08 -0700 (PDT)
MIME-Version: 1.0
References: <20200824081353.25148-1-walter-zh.wu@mediatek.com> <CANpmjNNf5pr=0hKVo92M9fEnCy7sYbv==6Bv_sVSmn=rZi7JEA@mail.gmail.com>
In-Reply-To: <CANpmjNNf5pr=0hKVo92M9fEnCy7sYbv==6Bv_sVSmn=rZi7JEA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Aug 2020 15:45:56 +0200
Message-ID: <CAAeHK+w3n3f4iA_WmAKAr+mKRxu+0Trfs7mGD=i2SWodfF448A@mail.gmail.com>
Subject: Re: [PATCH v2 5/6] kasan: add tests for workqueue stack recording
To: Marco Elver <elver@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=L4Ekwisf;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Aug 24, 2020 at 1:49 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 24 Aug 2020 at 10:14, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Adds a test to verify workqueue stack recording and print it in
> > KASAN report.
> >
> > The KASAN report was as follows(cleaned up slightly):
> >
> >  BUG: KASAN: use-after-free in kasan_workqueue_uaf
> >
> >  Freed by task 54:
> >   kasan_save_stack+0x24/0x50
> >   kasan_set_track+0x24/0x38
> >   kasan_set_free_info+0x20/0x40
> >   __kasan_slab_free+0x10c/0x170
> >   kasan_slab_free+0x10/0x18
> >   kfree+0x98/0x270
> >   kasan_workqueue_work+0xc/0x18
> >
> >  Last potentially related work creation:
> >   kasan_save_stack+0x24/0x50
> >   kasan_record_wq_stack+0xa8/0xb8
> >   insert_work+0x48/0x288
> >   __queue_work+0x3e8/0xc40
> >   queue_work_on+0xf4/0x118
> >   kasan_workqueue_uaf+0xfc/0x190
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  lib/test_kasan.c | 29 +++++++++++++++++++++++++++++
> >  1 file changed, 29 insertions(+)
>
> These will majorly conflict with the KASAN-test KUnit rework, which I
> don't know what the status is. AFAIK, these are not yet in -mm tree.

I've asked Andrew to take those in 5.9, but that didn't happen.
Perhaps we should ping him again after Plumbers.

> I think the KASAN-test KUnit rework has priority, as rebasing that
> work on top of this patch is going to be difficult. So maybe these
> test additions can be declared optional if there are conflicts coming,
> and if that'll be the case you'll have to rebase and resend the test.

Yeah, either waiting for KASAN+Kunit or separating the tests sounds
like plausible approaches.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw3n3f4iA_WmAKAr%2BmKRxu%2B0Trfs7mGD%3Di2SWodfF448A%40mail.gmail.com.
