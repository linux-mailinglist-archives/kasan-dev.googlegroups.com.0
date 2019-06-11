Return-Path: <kasan-dev+bncBAABBHVQ73TQKGQEPEPMCUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id EF2A03CAA1
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 14:01:35 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id s3sf8992812pgv.12
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 05:01:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560254494; cv=pass;
        d=google.com; s=arc-20160816;
        b=agV5UXLvOXqUnL2Cn0M78YQVU9Scx8ENeAlcuclY8G8jnVsr7MYdZH5+/uNYqcCXQW
         Dnzpc9FDDOlavnNeuWsDJ2AC2v4g74+q1i5Wxy+AETzVVBBgKIEz/J1E42n23IWT8kcD
         klTwaRn6/QCY9n43HxtH1WQmmkFvkn6vmcsyRO41McwU7SKHlNFWhcNF/mEgEvO4Yhnh
         KL63TUHc2cbTNXDR1Fq0nKDZbEfQSyGoTFU7Cmm6Mx4jl2XZplHovuOLsGOUMj35f2Ms
         XTImaUwK3NhdlyUJsyRGdNaz85vqEllHxVcN+C+UGyiXrFD39zJttHRJCmtE4xARbQps
         VVAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=FQx9JTHYkkLtgrHDYf3Q1TRe4osQTQF2JP65ht5VH2o=;
        b=PZZ4XMeyKLNnRdjUE2rtaoBSRXaXfYW3uvu5fIRa8aETjRNEPmRu/R4y/0wPzvUn+H
         eogImw+KtlVzstxVFQEg80oJTuy1/d0OrM7UQKp/T7StDr+1I1cIM2oy5FRVaZkiOQZm
         gfvCGMA4NK1ai4grI2OrtHMCTaHHIe+VZmIqaVWnubexDZ7avq6IIpXuUdu85sh1okCC
         T27dMYFv+SX0Vw9th5uFiwgGXpmh0B6kIJHCt3xfOWhhD8vGxLn56OpKwVDWNOmR8M73
         oGPFnm0k6ODDu4AL+38Ws+c3J+GIGxBTZQTmuYljT8bjE0RrZlHyDeXTQma+KROtXl+b
         OTTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FQx9JTHYkkLtgrHDYf3Q1TRe4osQTQF2JP65ht5VH2o=;
        b=Fwz2375L4z204/rhRjE67ldzmOVy3OkHQcQga7mX53nblEkATnjP8SrFVU01VJSO0l
         nZO+2ZL2VHmiSGiTb7MlwiOWcFgRVHQzCK/on8imQppHrbWFaJWpLgFDqBh3quiD0V07
         hEUInsO1oY2/tRBeYs2SS3K3VeF5IFYOIwmzlwDxosYDrt/FaehlZYqQ16/DqLQA8Wri
         guiWqkr6tceHBRN0NHEmaM3q/x9aHMo8tCteAYVrCwVpHY4G7smhqiipCc+GzORDEoB8
         utAhsDAH8QIJfOYefDZjWwa52CbtsFsvFkBOHejXwK7cm53vRy3xRCO3gvOLi20spYuX
         GxJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FQx9JTHYkkLtgrHDYf3Q1TRe4osQTQF2JP65ht5VH2o=;
        b=cqhjakxw5NsXoBcyolNT/VRIkXVrchtjgDU87cfFWttw2QESxeprOF/PMey4RP7EPn
         C/V2FZDLpHqyvJ1DJ5JTNtfrxdVbrmwcVRwqPEN5ScP5KRKyI9Ci1bxKJdCmpMEsgH/T
         43yNyfVlOwUwe3gJdn7b+yaffDcypIMcU1aIxafpcWR1qr/dm/+f8n9/cCELm3altg+4
         cefJUivmSBtVEMNx84W8UpPhYIkHx0GvSG3a2anw22Da9CYfpAHQhNK9nrYEfhsexSNx
         jni97D1yKEuEiIguu7W93GZDlZdFgptZqj1KmBoOrRZXTfXNS1noQtTsd0AKW5P1EdBF
         W7Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9fB/LpMxI9BakpCtJVPpG7FAsyrw5998gzhlR+Haw3p84jmdP
	2AuFhiGmazdtheeayJyVLpo=
X-Google-Smtp-Source: APXvYqyRCURbtzHD6gBEMp7kD1fxr5+NJDRg6BktZU6uRS5IRmiaiit6DKVB4xjZTnul5fGmra5/5Q==
X-Received: by 2002:a17:90a:17c4:: with SMTP id q62mr26966569pja.104.1560254494466;
        Tue, 11 Jun 2019 05:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:be09:: with SMTP id l9ls4402730pff.16.gmail; Tue, 11 Jun
 2019 05:01:34 -0700 (PDT)
X-Received: by 2002:a63:e317:: with SMTP id f23mr5836931pgh.142.1560254494090;
        Tue, 11 Jun 2019 05:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560254494; cv=none;
        d=google.com; s=arc-20160816;
        b=Ee8II3lH2J+6k4hI3Z/vbsgNsTLICZZtaZ3R4opYC/ts4HOmoUjTdfhfPT5f/U+hM7
         ZHO9dWzc05XBIMSZ2J4SlEUA2awDkbZF5CDbfTKLAPe+j5jC+UjQa/RjQb2xuydwRVUW
         NjpHfWLJ4rU+5QSG6guADeJtDGCL+K8Dx8kC2DvR3iONFqdlSLTaeELAIspzaMq42pDd
         /oB5xnK58pPuOjRWz9Lrh4HjKDy/mxOAK/f4TEM/qJ8FYLshbimd3VWFq/nIaZQOAr1g
         bfoLwjF+DYlbCQ/SoAkkmGbV6+JWqKfti9iZmvvO45bRtqk+BeOiDrZfcJ4qJG2862le
         +o/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=y3qEW99X8qDv4zMEhNnW0MjANT2Pq4iB9vRKhS9RMHA=;
        b=fukz5iavsMwB3L+PgfhHD00DBqmu1QAHMnTMsssXQLGoN2L/LMm7deFasMVnmhym5k
         Eco+rPlMRXbRKU1ZVjvNsE1CCV2Z6lwAE/ZpRGukYXUvEdJRr4rgeUlLuYRULpNyZX5A
         L7nCXFVZXxIwV51fyhWpHfDanwOagJwXo9/TeucpFORsNgyFPIlFIgyCy+IMAAS2/5Cl
         vhsk6VK8nACWaNFq7/eZoNC+M0KEMmGsKGuegP7EAh1CoX3svkAHtH9qx9X+uZypSxeC
         /AOaoDJzX6hXi8tYHvgQuRmxeT5uxSQy0K95+p77Gv/MtVqJIpAyLBm1FoAwp9H/XHH9
         6Yqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id g18si558452plo.3.2019.06.11.05.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jun 2019 05:01:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 1f96f75078614a5b9e1f0250f0a67e06-20190611
X-UUID: 1f96f75078614a5b9e1f0250f0a67e06-20190611
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1348057515; Tue, 11 Jun 2019 20:01:15 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 11 Jun 2019 20:01:14 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 11 Jun 2019 20:01:14 +0800
Message-ID: <1560254473.29153.16.camel@mtksdccf07>
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
Date: Tue, 11 Jun 2019 20:01:13 +0800
In-Reply-To: <CACT4Y+bNQCa_h158Hhug_DgF3X-8Uoc6Ar7p5vFvHE7uThQmjg@mail.gmail.com>
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
	 <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
	 <1560151690.20384.3.camel@mtksdccf07>
	 <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
	 <1560236742.4832.34.camel@mtksdccf07>
	 <CACT4Y+YNG0OGT+mCEms+=SYWA=9R3MmBzr8e3QsNNdQvHNt9Fg@mail.gmail.com>
	 <1560249891.29153.4.camel@mtksdccf07>
	 <CACT4Y+aXqjCMaJego3yeSG1eR1+vkJkx5GB+xsy5cpGvAtTnDA@mail.gmail.com>
	 <CACT4Y+bNQCa_h158Hhug_DgF3X-8Uoc6Ar7p5vFvHE7uThQmjg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Tue, 2019-06-11 at 13:39 +0200, Dmitry Vyukov wrote:
> I should have been asked this earlier, but: what is your use-case?
We need KASAN to help us to detect memory corruption at mobile phone. It
is powerful tool.

> Could you use CONFIG_KASAN_GENERIC instead? Why not?
> CONFIG_KASAN_GENERIC already has quarantine.
> 
We hope to use tag-based KASAN, because it consumes more less
memory(1/16) than generic KASAN(1/8), but we also hope the tag-based
KASAN report is easy read and able to identify the use-after-free or
out-of-bound.


> On Tue, Jun 11, 2019 at 1:32 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, Jun 11, 2019 at 12:44 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > On Tue, 2019-06-11 at 10:47 +0200, Dmitry Vyukov wrote:
> > > > On Tue, Jun 11, 2019 at 9:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > >
> > > > > On Mon, 2019-06-10 at 13:46 +0200, Dmitry Vyukov wrote:
> > > > > > On Mon, Jun 10, 2019 at 9:28 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > > > > >
> > > > > > > On Fri, 2019-06-07 at 21:18 +0800, Dmitry Vyukov wrote:
> > > > > > > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > > > > > > index b40ea104dd36..be0667225b58 100644
> > > > > > > > > --- a/include/linux/kasan.h
> > > > > > > > > +++ b/include/linux/kasan.h
> > > > > > > > > @@ -164,7 +164,11 @@ void kasan_cache_shutdown(struct kmem_cache *cache);
> > > > > > > > >
> > > > > > > > >  #else /* CONFIG_KASAN_GENERIC */
> > > > > > > > >
> > > > > > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > > > > > +void kasan_cache_shrink(struct kmem_cache *cache);
> > > > > > > > > +#else
> > > > > > > >
> > > > > > > > Please restructure the code so that we don't duplicate this function
> > > > > > > > name 3 times in this header.
> > > > > > > >
> > > > > > > We have fixed it, Thank you for your reminder.
> > > > > > >
> > > > > > >
> > > > > > > > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > > > > > > > +#endif
> > > > > > > > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > > > > > > >
> > > > > > > > >  #endif /* CONFIG_KASAN_GENERIC */
> > > > > > > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > > > > > > index 9950b660e62d..17a4952c5eee 100644
> > > > > > > > > --- a/lib/Kconfig.kasan
> > > > > > > > > +++ b/lib/Kconfig.kasan
> > > > > > > > > @@ -134,6 +134,15 @@ config KASAN_S390_4_LEVEL_PAGING
> > > > > > > > >           to 3TB of RAM with KASan enabled). This options allows to force
> > > > > > > > >           4-level paging instead.
> > > > > > > > >
> > > > > > > > > +config KASAN_SW_TAGS_IDENTIFY
> > > > > > > > > +       bool "Enable memory corruption idenitfication"
> > > > > > > >
> > > > > > > > s/idenitfication/identification/
> > > > > > > >
> > > > > > > I should replace my glasses.
> > > > > > >
> > > > > > >
> > > > > > > > > +       depends on KASAN_SW_TAGS
> > > > > > > > > +       help
> > > > > > > > > +         Now tag-based KASAN bug report always shows invalid-access error, This
> > > > > > > > > +         options can identify it whether it is use-after-free or out-of-bound.
> > > > > > > > > +         This will make it easier for programmers to see the memory corruption
> > > > > > > > > +         problem.
> > > > > > > >
> > > > > > > > This description looks like a change description, i.e. it describes
> > > > > > > > the current behavior and how it changes. I think code comments should
> > > > > > > > not have such, they should describe the current state of the things.
> > > > > > > > It should also mention the trade-off, otherwise it raises reasonable
> > > > > > > > questions like "why it's not enabled by default?" and "why do I ever
> > > > > > > > want to not enable it?".
> > > > > > > > I would do something like:
> > > > > > > >
> > > > > > > > This option enables best-effort identification of bug type
> > > > > > > > (use-after-free or out-of-bounds)
> > > > > > > > at the cost of increased memory consumption for object quarantine.
> > > > > > > >
> > > > > > > I totally agree with your comments. Would you think we should try to add the cost?
> > > > > > > It may be that it consumes about 1/128th of available memory at full quarantine usage rate.
> > > > > >
> > > > > > Hi,
> > > > > >
> > > > > > I don't understand the question. We should not add costs if not
> > > > > > necessary. Or you mean why we should add _docs_ regarding the cost? Or
> > > > > > what?
> > > > > >
> > > > > I mean the description of option. Should it add the description for
> > > > > memory costs. I see KASAN_SW_TAGS and KASAN_GENERIC options to show the
> > > > > memory costs. So We originally think it is possible to add the
> > > > > description, if users want to enable it, maybe they want to know its
> > > > > memory costs.
> > > > >
> > > > > If you think it is not necessary, we will not add it.
> > > >
> > > > Full description of memory costs for normal KASAN mode and
> > > > KASAN_SW_TAGS should probably go into
> > > > Documentation/dev-tools/kasan.rst rather then into config description
> > > > because it may be too lengthy.
> > > >
> > > Thanks your reminder.
> > >
> > > > I mentioned memory costs for this config because otherwise it's
> > > > unclear why would one ever want to _not_ enable this option. If it
> > > > would only have positive effects, then it should be enabled all the
> > > > time and should not be a config option at all.
> > >
> > > Sorry, I don't get your full meaning.
> > > You think not to add the memory costs into the description of config ?
> > > or need to add it? or make it not be a config option(default enabled)?
> >
> > Yes, I think we need to include mention of additional cost into _this_
> > new config.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560254473.29153.16.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
