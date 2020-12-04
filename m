Return-Path: <kasan-dev+bncBAABBUV4U37AKGQEKCZWIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id E6DAC2CE5AD
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 03:26:27 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id 99sf3285098qte.19
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 18:26:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607048787; cv=pass;
        d=google.com; s=arc-20160816;
        b=aOkyC9o074IND3m68RZdCm/g4ENcfMTB4IAhVVHmkH43kZEldSr4hjwXyF/a15BFiq
         InHpLrdvS+4/Jx7p9EqTsnP4Lww3UL1VONsUkPyJBiHV1+8sjgqZ3VEpdbavDO7rJ+gK
         INoM4ryd0pIPsnq9hpLOddWmSStVgDEgz1rQdca2pQyKFRCcReMYr4Af7NKR87Cr7BbR
         Vu/kckfMW6ja9KnZRwQdWafEAyiWk4e+MAusa96robZB9mvdZLnUw8sTEs7VFhtk5mlv
         eC/csTK6RcSaMczN2CWKryOCq9RWOFJJm8Wg7BDm5BObaFRuSvjCzQa/1+QobUnS95vt
         QSSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=+cqVdSOHEON01dcrkIphs8CpYu8GlGRuxlhUSpNKezU=;
        b=noJUPyHlyuA4yXuYzBsI8pX7wkHhidVYq9y8g0Ud+dgb+IkmIDtzMgbgvwv014MIUl
         7f6wCN45IsxgUWP8Cu8CSFFpl6iIyFLF5Sc2BBkvwy4Cw9sDKphz30fCL93bXiH2isaT
         nKbCR4dQ4IR4JtPnkCM8FJQAdLi8bBauYJRoJK1ftSbMzdW6wih2E8AYZ7n+ZXiAi3kQ
         a1uruWndbgmzpmfhraWAZP2RWZQjAH5GTJvBB2eVyEaRigaBWjEvU95UuB6UHssaXIes
         /PJOxZgvkwKc0OXNLtDhrp91aIodLMYc1hJmkSLheMl6QQ8wnOZYCh/6MySNvQofGBZW
         OS2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=TPJiHHmF;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+cqVdSOHEON01dcrkIphs8CpYu8GlGRuxlhUSpNKezU=;
        b=KoK23RmRLKUk7Y+9ljNQ011S0/qas4PLvBEzW9BCxg4UIz4fnKT3IV6h+Zi5F5WhLz
         IJp6QireeVrwxPz62IQsmMWZikJmGKbMJnpMyNei8DC18oWi/0h7JHWfsSwkiVptqU+l
         NqPQU9GUPZ8UcEfudvuiQvOSIjmTXmN6Tpw3ICPdNOuTaZKnaWFVqdCfUkP1ngVNVtBQ
         2IlY7caeh2PfqTWq/UjeFPfaOkp2ACJQgQY4qwbg0zW0I6c6181WpTRqYu+5qeoRE4AK
         hNi0ml41Q1U55vIPYmXC4+i8IQYkrDmXBW2jr5gWqgDJzEjkumFgVmQLrXYkhx49PaWs
         733g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+cqVdSOHEON01dcrkIphs8CpYu8GlGRuxlhUSpNKezU=;
        b=np/zzJYLIFM9cbtvMxnIo41yKfCxDu6Q/tYd3OjsTpdRGHOACMyCxqpvmZitTLMgLk
         bnA7UDAMXvpY4KqDwu8vGd+rHAVDtHKi40A7KH79mTWX5sTSlPQ+1I5fRfZ0axVVV6xV
         h4HOOLjfSHORQjH/lnd1qKhUeVIcHoVnF992xqFyPFvoREFeBYfJ462JmAsVp4yAPEnk
         m+muYwcEdk0wpGEWsAyhE/deskHkxTDtT1wRskCWuBoHzHkoOvy6fDb6MHDyD4nJ8kjw
         V4Bl8DoOTyDUZya5U4glTUtioYrYjo/OUmeKNwZOfYVe252D4wd1ONYcLSWZKapee7zM
         JJxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AAzNLrQzpAsqa6xVCXdkYb0v0pOMKr8tz1LnRGjTmIX7tG2F+
	ZTDgmEVNAfqMB6SYVbzW1hY=
X-Google-Smtp-Source: ABdhPJzdlvfEB/V50im2zNGggegybuixZGPvdajyYSjHizpOQ8nSPtKhRMBTvZVjzZocomm2Lw8Dnw==
X-Received: by 2002:a37:9a94:: with SMTP id c142mr6207857qke.480.1607048786945;
        Thu, 03 Dec 2020 18:26:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:572:: with SMTP id p18ls3500059qkp.0.gmail; Thu, 03
 Dec 2020 18:26:26 -0800 (PST)
X-Received: by 2002:a05:620a:4f4:: with SMTP id b20mr6251123qkh.312.1607048786475;
        Thu, 03 Dec 2020 18:26:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607048786; cv=none;
        d=google.com; s=arc-20160816;
        b=o91ETLi5LjJ5AJUkC977dESJZys2o2v10pzhYufkTG/nsNGvzyycZZniU3ESOh0n1U
         76YzcaERhxO3Ooy+ckYiS3YD9Wx9nrO/9HYRvcoemqNvSwBXOdTbioBETlFJ2DWRYRy0
         xyS8/TKiKTGmcKkNnaYyvv1Gqabh8XY/UrP3R+QLzJvOKrYIRPKNZbpR8D1YyAa8OSuO
         tPeEEZMq1x2mGFS7CYRLm5wymokOF+hvJeadSP7Ssn++IEEse8sDPIXeoewtsyC0Ki10
         4ictr8MvgJiC0qY+N2i6xh3tDCjB/+C4QPIHiSEny5gbR2aS/JtvWfIIDB/S5FHpERWj
         61Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=poyb6ODY1nzdJu4VuolCu6hZIv/6rIbs3USR4sHKncU=;
        b=c552q31zTQ6pJX77/8wegQD3BlDG7E1nSVID12ppDu/xAWC0KM2cQrH5wHQRezN4bj
         SpjyRC4oFhV8M86MkQgyWy9HmPacGbdoAS5vMD9DYQ1Q71jl1d5r1sriSZREj+ZySPJx
         tvKAjw4zs8TJAf3nb7qg8r/AnDDrRp0DpLNyIof17INvrvyZ00acm2j8qVqmVuYINDaH
         oPNYgFvyhO0IuSSHJ/lnuzkqwSc6+YSrG2E+eupRLypS7v8YA1zfIyWkqiTaMwv1XyBZ
         Gm7IoZtI2bJKtkafVtjbOW1Zspeof7zs3O7BuGMTvx6/SOKmmZDrPT9k4o378xW/I2qr
         rc/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=TPJiHHmF;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id k54si246155qtk.4.2020.12.03.18.26.24
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Dec 2020 18:26:24 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 5475effd1b334f3181e2e48d1848a4ad-20201204
X-UUID: 5475effd1b334f3181e2e48d1848a4ad-20201204
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1902959308; Fri, 04 Dec 2020 10:26:19 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 4 Dec 2020 10:26:17 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 4 Dec 2020 10:26:18 +0800
Message-ID: <1607048778.15817.2.camel@mtksdccf07>
Subject: Re: [PATCH v3 1/1] kasan: fix object remain in offline per-cpu
 quarantine
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>
CC: Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	Nicholas Tang <nicholas.tang@mediatek.com>, Miles Chen
	<miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>, "Linux
 Memory Management List" <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Fri, 4 Dec 2020 10:26:18 +0800
In-Reply-To: <20201203122854.c8d5ed270ec9cfc7c17569d9@linux-foundation.org>
References: <1606895585-17382-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <1606895585-17382-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <CAAeHK+z+DPNysrUwfeu27h6sKdn5DDE=BL4t96KiF0mRBNPs+Q@mail.gmail.com>
	 <20201203122854.c8d5ed270ec9cfc7c17569d9@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=TPJiHHmF;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Thu, 2020-12-03 at 12:28 -0800, Andrew Morton wrote:
> On Thu, 3 Dec 2020 13:46:59 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
> 
> > >  #define QLIST_INIT { NULL, NULL, 0 }
> > > @@ -188,6 +190,11 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
> > >         local_irq_save(flags);
> > >
> > >         q = this_cpu_ptr(&cpu_quarantine);
> > > +       if (q->offline) {
> > > +               qlink_free(&info->quarantine_link, cache);
> > 
> > Hi Kuan-Ying,
> > 
> > This needs to be rebased onto the mm tree: it has some KASAN patches
> > that touch this code and rename the info variable to meta.
> 
> Yup.  I'm taking care of that.

Hi Andrew,

Sorry about that.
I will fix that conflict.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1607048778.15817.2.camel%40mtksdccf07.
