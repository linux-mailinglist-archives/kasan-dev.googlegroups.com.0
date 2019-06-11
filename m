Return-Path: <kasan-dev+bncBAABBXF373TQKGQEETTTIOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B98E3CB3E
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 14:26:05 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id u202sf3249750vku.5
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 05:26:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560255964; cv=pass;
        d=google.com; s=arc-20160816;
        b=hO1EwzbeXRKe6SkVQjMcz/kedfk6Qi0yT4OM6IzNVCC9key+IFPumN6Y9trYxpXovW
         nrjI2+cAMUdYsCIaB5bNMlFkogW/ZDDzAiOQ8VYXRLpvMqiwlGBM3LxBOU7bMRSgxeQW
         ylS/+l0b4T9Z19/xUdQGWugB/TB3cXdFQR5eDcyXJgJ5E6Mbxj1yEM8eTKae8aJXvVrK
         uXDxafOwbJ39XWctlipbl6LhQdNFH4QeC9gVbzVg1ZILuu974iFet8aJjCkv6OajhYxR
         CtS0suxo6mVkHc/aFKFl248EMNj5tehfbT/Zz+Cdy/zURSessc0+0krlg6bzjXN2tiYq
         BgRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=kgGceuI/v7e9mMk2fbNFgBrJMi0Lnd04qbdrPUAcWDU=;
        b=nSeKor7bylN6c+PD+FwiQ+VEaInVzMKju/HoYM3RdsZUy+JrHJMj45Owq6iKvA8Uzs
         4u42G9qPbULvb/LFy434maupIL8qUZNIiBkUJ1c1PDAd6jA1YJw8ZTyVUTh/epESpc7d
         I99sz+9g16Rski0cE93azoyBlzRv+ehjNdLnIgFRtVnJxe0Fr0HWoYGwbJK3iJSZFbQS
         v+MQXhMe/caTBgVmXbPNOyOWx7U/OCa+HvcRhuMLGBCQJ4hQdemvGRC/pUAn0d8b9UsB
         tVGS0sRGlJ3cO2wTmN++Pt8B81AWIXtOm3M0a2MgyVmkV5GSevWX+3P/Vt1ew9AiFznL
         HrkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kgGceuI/v7e9mMk2fbNFgBrJMi0Lnd04qbdrPUAcWDU=;
        b=T13KoevVNvq11UqMo4t+NYhj4zl7DvwTzu40W/8kxxBDMhTgu8CMfRVjH68ekyLF4p
         dmP+yXVAzniUabFo4jkTlQW+Og4BUGXC0XfGRqlJCv6OOvGOnof3aAggsNf+B9m/zh/1
         PrdG8n1vE/VVdP6OZy6wxdfuSBmPUNZo+t3vmzzvwL2J/5fiP4/Lj/FO0rn+zCVgBsAw
         5rCOBfJY/72AiN3Ub32iClEb7bbWRu3IYyZzE/3PrQ//YxD4IgZ3BYNh8eqs3HyNb6xK
         mi4+g7u9R8C2A9NQCcbNwt+Ry4GruA1RpN/9QeBnjjVYijH3giDpyFdivZNPnGbqFjrx
         0UaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kgGceuI/v7e9mMk2fbNFgBrJMi0Lnd04qbdrPUAcWDU=;
        b=uMHT943cosoa4aQ5ONJaVGvbrApoHBzMBOS/VycIrgqaTYaJTgSKDuIwz5IGqEQ93c
         mWIKZ+dpbHzNHmoh/gDLWCvHeVDQ29exu6VhVJb9spGdKW9snAF/n5WZDlJCPD8cRAtE
         aFNs+NFqZ1pQ5DqlRjoCqjuYJ17V4lCFFJg/xVudi57qpgxkg/OgfkUafotENCfrx5co
         cGKle+DYrMY3pvjBYibVb0IMcDAIObFRfGnmiFOEsLgnb/rAs/PCtimm2W89LPysLdoS
         dEI58UjU2ejM2m7apFFIH9LkzZpeLQ6+526GEBgVMUvGC0CMfQ0jsAY4gG/wGFbAoi2E
         yHKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU7YNsMtwMeTopXno637C11s51QXEEJ42haa8AnWilxqyKIM1mD
	p77xmobRKi+bl5RPwRO5M04=
X-Google-Smtp-Source: APXvYqx0Gd0481CbB7DUhW49Xf02ZojHPYZQBRYrSoz3qgqldDLaC0FbLMpIRRkbB4XiIRqQ/7qPRg==
X-Received: by 2002:ab0:2395:: with SMTP id b21mr37903588uan.108.1560255964384;
        Tue, 11 Jun 2019 05:26:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:185f:: with SMTP id j31ls1228215uag.8.gmail; Tue, 11 Jun
 2019 05:26:04 -0700 (PDT)
X-Received: by 2002:ab0:69c8:: with SMTP id u8mr225945uaq.132.1560255964173;
        Tue, 11 Jun 2019 05:26:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560255964; cv=none;
        d=google.com; s=arc-20160816;
        b=UQqYj19SE6kA2R0LjC5PGX2ND++dcyP3Ttdpkmk0hWJaO/0pWsTRfIG6aEDf2s/wxZ
         nq3GZ/tnNUPtyBDwgetxkfu/j6foSmjrZXyBggPIX2OYTuvHcDH0fJzvZvmCVnAep9N7
         16XomThACUQ8y160MTIGjL3L+znsNwA4BGaQ+Z40VAleDKxfu7OtpxvRGkbJOJK0liRx
         6j6NrOEal3ILnfFSiNrp+3u7/yElUrnITY/4Hgo3HcKIF5aB2KFia4aG6Ot5QP3MWGTJ
         RPExy9UTERuAbOlDN5x/TKvTb10tPLX0vXXSSDrGzYQ3DVZTfeFZqh1DVI+f48bb0yuM
         +tEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=Jyb8YM8lArG+/Y8fk24IqbWjw81Z+P7IptrzCzYSy4Y=;
        b=MX8cdusbWc7qByl6sK3WekUobiRtyipl6Tz7wKg+Uk6Cio93USBhqbU9dKcshjpvGN
         IGaaZZ62QP9tg6rGH8C6mWniP+o1fdwkkqBnyvLDWiFYzGRWcOwhUv375M2sjoThXE6B
         vD7KZb2n8xeVxBp0QBzab8i7G6qIvJJ9AFeHLnxNZ0K8GxAqVXttHq0ndKEgQrPX8xIW
         95ZQXkJsNVQfXlxVgSviXOPcr8UGlrAKoD8Kyebqmqzrg00uHODkox3/i55jZnvf38Dj
         q7yWrxAeJ4lTJvD1fPWzNIOuZjOSw1VfeHtY6W4dle5ZaAkd/vfqKrHSVhcv+Xzi2Y5D
         xnWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTPS id w4si537499vkd.1.2019.06.11.05.26.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jun 2019 05:26:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 8fc4afafc8034cc59a92651ab0d17e0e-20190611
X-UUID: 8fc4afafc8034cc59a92651ab0d17e0e-20190611
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1205233393; Tue, 11 Jun 2019 20:25:56 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 11 Jun 2019 20:25:55 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 11 Jun 2019 20:25:55 +0800
Message-ID: <1560255955.29153.20.camel@mtksdccf07>
Subject: Re: [PATCH v2] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A. Donenfeld" <Jason@zx2c4.com>, Miles Chen
 =?UTF-8?Q?=28=E9=99=B3=E6=B0=91=E6=A8=BA=29?= <Miles.Chen@mediatek.com>,
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Tue, 11 Jun 2019 20:25:55 +0800
In-Reply-To: <CACT4Y+aXqjCMaJego3yeSG1eR1+vkJkx5GB+xsy5cpGvAtTnDA@mail.gmail.com>
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
	 <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
	 <1560151690.20384.3.camel@mtksdccf07>
	 <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
	 <1560236742.4832.34.camel@mtksdccf07>
	 <CACT4Y+YNG0OGT+mCEms+=SYWA=9R3MmBzr8e3QsNNdQvHNt9Fg@mail.gmail.com>
	 <1560249891.29153.4.camel@mtksdccf07>
	 <CACT4Y+aXqjCMaJego3yeSG1eR1+vkJkx5GB+xsy5cpGvAtTnDA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Tue, 2019-06-11 at 13:32 +0200, Dmitry Vyukov wrote:
> On Tue, Jun 11, 2019 at 12:44 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > On Tue, 2019-06-11 at 10:47 +0200, Dmitry Vyukov wrote:
> > > On Tue, Jun 11, 2019 at 9:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > >
> > > > On Mon, 2019-06-10 at 13:46 +0200, Dmitry Vyukov wrote:
> > > > > On Mon, Jun 10, 2019 at 9:28 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > >
> > > > > > On Fri, 2019-06-07 at 21:18 +0800, Dmitry Vyukov wrote:
> > > > > > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > > > > > index b40ea104dd36..be0667225b58 100644
> > > > > > > > --- a/include/linux/kasan.h
> > > > > > > > +++ b/include/linux/kasan.h
> > > > > > > > @@ -164,7 +164,11 @@ void kasan_cache_shutdown(struct kmem_cache *cache);
> > > > > > > >
> > > > > > > >  #else /* CONFIG_KASAN_GENERIC */
> > > > > > > >
> > > > > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > > > +void kasan_cache_shrink(struct kmem_cache *cache);
> > > > > > > > +#else
> > > > > > >
> > > > > > > Please restructure the code so that we don't duplicate this function
> > > > > > > name 3 times in this header.
> > > > > > >
> > > > > > We have fixed it, Thank you for your reminder.
> > > > > >
> > > > > >
> > > > > > > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > > > > > > +#endif
> > > > > > > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > > > > > >
> > > > > > > >  #endif /* CONFIG_KASAN_GENERIC */
> > > > > > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > > > > > index 9950b660e62d..17a4952c5eee 100644
> > > > > > > > --- a/lib/Kconfig.kasan
> > > > > > > > +++ b/lib/Kconfig.kasan
> > > > > > > > @@ -134,6 +134,15 @@ config KASAN_S390_4_LEVEL_PAGING
> > > > > > > >           to 3TB of RAM with KASan enabled). This options allows to force
> > > > > > > >           4-level paging instead.
> > > > > > > >
> > > > > > > > +config KASAN_SW_TAGS_IDENTIFY
> > > > > > > > +       bool "Enable memory corruption idenitfication"
> > > > > > >
> > > > > > > s/idenitfication/identification/
> > > > > > >
> > > > > > I should replace my glasses.
> > > > > >
> > > > > >
> > > > > > > > +       depends on KASAN_SW_TAGS
> > > > > > > > +       help
> > > > > > > > +         Now tag-based KASAN bug report always shows invalid-access error, This
> > > > > > > > +         options can identify it whether it is use-after-free or out-of-bound.
> > > > > > > > +         This will make it easier for programmers to see the memory corruption
> > > > > > > > +         problem.
> > > > > > >
> > > > > > > This description looks like a change description, i.e. it describes
> > > > > > > the current behavior and how it changes. I think code comments should
> > > > > > > not have such, they should describe the current state of the things.
> > > > > > > It should also mention the trade-off, otherwise it raises reasonable
> > > > > > > questions like "why it's not enabled by default?" and "why do I ever
> > > > > > > want to not enable it?".
> > > > > > > I would do something like:
> > > > > > >
> > > > > > > This option enables best-effort identification of bug type
> > > > > > > (use-after-free or out-of-bounds)
> > > > > > > at the cost of increased memory consumption for object quarantine.
> > > > > > >
> > > > > > I totally agree with your comments. Would you think we should try to add the cost?
> > > > > > It may be that it consumes about 1/128th of available memory at full quarantine usage rate.
> > > > >
> > > > > Hi,
> > > > >
> > > > > I don't understand the question. We should not add costs if not
> > > > > necessary. Or you mean why we should add _docs_ regarding the cost? Or
> > > > > what?
> > > > >
> > > > I mean the description of option. Should it add the description for
> > > > memory costs. I see KASAN_SW_TAGS and KASAN_GENERIC options to show the
> > > > memory costs. So We originally think it is possible to add the
> > > > description, if users want to enable it, maybe they want to know its
> > > > memory costs.
> > > >
> > > > If you think it is not necessary, we will not add it.
> > >
> > > Full description of memory costs for normal KASAN mode and
> > > KASAN_SW_TAGS should probably go into
> > > Documentation/dev-tools/kasan.rst rather then into config description
> > > because it may be too lengthy.
> > >
> > Thanks your reminder.
> >
> > > I mentioned memory costs for this config because otherwise it's
> > > unclear why would one ever want to _not_ enable this option. If it
> > > would only have positive effects, then it should be enabled all the
> > > time and should not be a config option at all.
> >
> > Sorry, I don't get your full meaning.
> > You think not to add the memory costs into the description of config ?
> > or need to add it? or make it not be a config option(default enabled)?
> 
> Yes, I think we need to include mention of additional cost into _this_
> new config.

Thanks your response.
We will fix v2 patch into next version.

Thanks.
Walter


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560255955.29153.20.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
