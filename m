Return-Path: <kasan-dev+bncBCT4XGV33UIBBZ4USCBQMGQEOLUKMDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B03434F84C
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 07:36:41 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id v6sf756935pff.5
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 22:36:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617168999; cv=pass;
        d=google.com; s=arc-20160816;
        b=c+GwVLV44/SA7MNDW8sP8Y+oy3JEg7m6xOvBp1tUAYM8pYZlcZorgZcx3XYP5osQbC
         uA92VA0xdcbL22uSa2L/wNTio35UdPCVWSnkV0KqDGfjEY2fB00p5O6DmTe3LRaRggcp
         d5OlI4AVD3jr3Pl41WpM8LLpbj+1BgJ2ZdQA5fWuktfu1UeBVfti8hhcO/jaXbxvpxMT
         pVnrNfWcbdOtQ3KFTCBVBh8C2aUO01Q1dvw1CTi2g2rS3wsztOiwmcHIn/5TjY1bNvOU
         nDZUX5Obmv0ZovNxae4xKdK6P5LkKwmmXDTsPu0xnE/PvVM9nwO3+jkXrlpXi7f5QmaK
         40yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=cMTke8qSk7u+Gv0Cs+0QQvODbYxoQAw3O22cR8351kg=;
        b=jznq3HP3vwmdm5aQRyyAgclW/RK+FFcWci4Bz8n3KqKVzzEXJMo9tP8QfaVQO/l51U
         hogssp2tQZgcWHtd2byfrt/DK9pRH1jFXsfClFwnGqRmYLltrGevEp7Whbcpmu/WTpPO
         wYDI2XFwgNFjn/hoSN9ZEAiDQM5bUeX+TTzSpPdbhEVimjHNhPnvhNHROOmRk6zicUsZ
         q6N6j1BfJAFrC8/AZiDmvSVyq43nD9v5YDtHv7ze05gVqBV2SmIjMh/p6J88majbh4bR
         X8YlEs4IcpNn2WINb2bydXGy236hoHb7sO4ah03N8YtuLT466RMAGPEbq1Bjj5An/A7K
         zwag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cBwsi3ns;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cMTke8qSk7u+Gv0Cs+0QQvODbYxoQAw3O22cR8351kg=;
        b=jBqlrz8zqwbm9jXx3GjFRLL2QljhaQ7ZCbRInwuI4kMfww+6kvsjd6717Iz7DmeX+p
         yKYujMINoM9WJ9b4UnIdW9gQE9GbM4vMS+WuSaK5aIbXerskD3v0/PsfdPdE4LH1D4ap
         Q1guhmny9fHLZrsy1kosgjfFDG54ip3NkZg984UrxoFQ0L8fctrNOmNK9dMIgG4X4z1F
         2plQh1jVelVdMGaoJtJSFbJzxaEDtwuLAFugbm/n5jIKGVUxMocBrpRIkXhDbGGU88R4
         M14TCIFdW5TNTfti8abtoRRNPWU6TnUpzrNtwoYyKCw/NARyu/PHULz4XQ2yOjOvbYJj
         jyfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cMTke8qSk7u+Gv0Cs+0QQvODbYxoQAw3O22cR8351kg=;
        b=fRG4IX7vj8BaC08oe2FuNEkGeCCqIbyU2enkaXgvZu0jVAcBDLg3CFXRJNf3BDdqC/
         xZXuog9DzYXBzsfbfVETgF+CpoBX7E3MZKQdKUxAgkCDLoIFqzoLRIWG0pWD0xCHOagn
         jhJ7TiOy0apxOfgNyLF8JFIc0+ExcmCHh59BQJPdWUj1hWeHp8s9Sg27fZvGLE1wlYZG
         +Z58UAy7BWozRRZr7PhUGkCZyqWmNtJ6cipMxGhwUNL0ygvAe0ch5nw8djnpSM4/jPL7
         z9NoWUX4XHzRxCwPG7HVLrnRm6DLDPKUia7r90SVHe2r2FAQxTJNvgQVuHOY0HUAlIYe
         u7zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ANIhPBFxieIIA7QxHBxeg3wBgGJHF7xnTOJcPx53nqRY16tww
	qcvdpO0Tw0ngMOjhxBOrjno=
X-Google-Smtp-Source: ABdhPJwdEmH/apb3kxPtPxPPkuiXgFYf0mOaQlPMaLnnfabARPGgUEot9V2G2qyu/INM+xHKcxUNgQ==
X-Received: by 2002:a05:6a00:2292:b029:214:7a33:7f08 with SMTP id f18-20020a056a002292b02902147a337f08mr1348798pfe.15.1617168999676;
        Tue, 30 Mar 2021 22:36:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:f212:: with SMTP id m18ls439070pfh.11.gmail; Tue, 30 Mar
 2021 22:36:39 -0700 (PDT)
X-Received: by 2002:a62:ce4e:0:b029:225:bcc4:4ee with SMTP id y75-20020a62ce4e0000b0290225bcc404eemr1337592pfg.13.1617168999041;
        Tue, 30 Mar 2021 22:36:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617168999; cv=none;
        d=google.com; s=arc-20160816;
        b=gNZHDbaZDQQktEtAZqwGUJ63sdSb4XrDyqqBeqAatWwDt8N0MYQ2eyzWasrpEoNMrA
         rMyUsZ27hNBOVl5vkVokZcPUGvUVCSneBjb8g2ZHEi1FPs+unbvpEMWj8Zso8yvi6O29
         z3Ontkf+xb0I7NQ9PalXcpyCr2sIj0Hrner+0k/NZVdHlwpo9EkB9wK5IbV9KK1SA4my
         r44oK0ciYa6HjGEq/gZd9pUSTjwKGn3lzMwF4nnFAO3/+QLX1WTmDJH/wyU6HIgNIZqt
         fQ8/h81hbKuC1JCeVYOIm8TwyY4v4Sfk7Bgj5JckvO9P0z6OwRjzE8iZbLD+pvHT/Yvk
         i34Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=t2PGCFgKjsWaFFbsCEFT3bjB101Ig/yu4ezVqbjG7W0=;
        b=xj5CEwJa36D8u7ztMPKzJtJNOmdMjjwwnbNFoPnTCq0UyYMZ2t5utx7yrTYRlY/wqY
         Bflj1u3JXOx0bCKlcAocOEuL9x8fDpvdSXRugUnfgrSYyhzAbS3MOrEUUOtELnMWc2o3
         0DBSxxW/Mnt9Z15fY64H06Lh5ZZNR8oHpr9Xp6jW5GUr4iJH0nCiFEdEqf57N8OmRipd
         q9dwiIkat/OLH0dCmQH0Fp4Xf7H/O/22Hpiu+ywYaS+KgZjg/vX0ofO9zMl5+lXwRumN
         GMB7GfFb7xeNtCThQTz9rCOVjKxUPzRGguWCzi3MrdxI/CldUqrfqI1n/jcVd5JojlDp
         MtJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cBwsi3ns;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g23si101459pfu.3.2021.03.30.22.36.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Mar 2021 22:36:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 47026619D6;
	Wed, 31 Mar 2021 05:36:38 +0000 (UTC)
Date: Tue, 30 Mar 2021 22:36:37 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Nathan Chancellor
 <natechancellor@gmail.com>, Arnd Bergmann <arnd@arndb.de>, kasan-dev
 <kasan-dev@googlegroups.com>, Linux Memory Management List
 <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, wsd_upstream
 <wsd_upstream@mediatek.com>, "moderated list:ARM/Mediatek SoC..."
 <linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH v4] kasan: remove redundant config option
Message-Id: <20210330223637.f3c73a78c64587e615d26766@linux-foundation.org>
In-Reply-To: <CAAeHK+zyv1=kXtKAynnJN-77dwmPG4TXpJOLv_3W0nxXe5NjXA@mail.gmail.com>
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
	<CAAeHK+zyv1=kXtKAynnJN-77dwmPG4TXpJOLv_3W0nxXe5NjXA@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=cBwsi3ns;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 29 Mar 2021 16:54:26 +0200 Andrey Konovalov <andreyknvl@google.com> wrote:

> Looks like my patch "kasan: fix KASAN_STACK dependency for HW_TAGS"
> that was merged into 5.12-rc causes a build time warning:
> 
> include/linux/kasan.h:333:30: warning: 'CONFIG_KASAN_STACK' is not
> defined, evaluates to 0 [-Wundef]
> #if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> 
> The fix for it would either be reverting the patch (which would leave
> the initial issue unfixed) or applying this "kasan: remove redundant
> config option" patch.
> 
> Would it be possible to send this patch (with the fix-up you have in
> mm) for the next 5.12-rc?
> 
> Here are the required tags:
> 
> Fixes: d9b571c885a8 ("kasan: fix KASAN_STACK dependency for HW_TAGS")
> Cc: stable@vger.kernel.org

Got it, thanks.  I updated the changelog to mention the warning fix and
moved these ahead for a -rc merge.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330223637.f3c73a78c64587e615d26766%40linux-foundation.org.
