Return-Path: <kasan-dev+bncBCMIZB7QWENRB25F73TQKGQE3EB6K7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-it1-x138.google.com (mail-it1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id EBEBE3CA2A
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 13:39:24 +0200 (CEST)
Received: by mail-it1-x138.google.com with SMTP id b5sf2110311itj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 04:39:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560253163; cv=pass;
        d=google.com; s=arc-20160816;
        b=moN7JBkHKiOc1Fb67R7LNtfPdIDMW567mXfG5+idI6sSfgQHyWmi8WIMpENvQnPFsL
         6Vb2/oR2oekwOjQ0E2TPhnHraRZd+1VW5SjAfiKW1EU4erPv5Zjjdj5F9wgx+kJsjFYm
         5z63LrporcpJUMnCvo18fruMx8foLYTY4++VeKdC2aJIOY+gyRztFwCPHuzLkhB2PrTl
         9AgHnpnrro5zUa4VpNpX5NcZcaKjRDqgNiixgUVJxwLyvvlmWUbf8WkYzipNBKG/S8L9
         Cldrxic7AaFoHuKjuDLwPFIf01qv3zjIINIX5mprThYcCCdFRHoLM1vz1XayrecGIYhm
         /McA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+ZABvYNmku42nkrKWZOeXoejdUCqhdms6seXpGpeZ/c=;
        b=AqMo5qvfmDyeZy+UnszVO4BLxqM/WEDKsTRWHpdbZmF2UKGVXMZm22OgoaWW1Pbiax
         CpKR36ibU9ilqoNPCUfc6hF9ghAAyibPWca9Md7c1lof5CtDr1BEXW6Y2oWjg4fv/Z8b
         tWAV1q5NjvLH2KN59pN39jCqpB032ARB0UtGdzsDf7jOHzTUITzh0lg8cPKDUamTwVog
         cPUSMpMbE2uAQg3YP1i0+aIvYOczITJO1dtkbgNhpDfhQYQ7cyw8RrXpqNmxYa3Ddskz
         /d3PvxzSMqZLt01eYH453t0PY++RTmRVsiXQQQaZoHOBFIZRF9aGyXfuk888SANZShgY
         /Nig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HjkPP0rM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ZABvYNmku42nkrKWZOeXoejdUCqhdms6seXpGpeZ/c=;
        b=K/wpRgQ8M9fb3ttoaDhlx0NJol8DIVU+hiKsvZAsIwqmgMPBPsGzV7jBw0LfUjCeht
         TVjxez62sz6wy6EcPXM626eZzM/RAkohuKypFe4Kylx0TtGYoKeUr1XAomQqkNKapMoR
         dctyDY+6/CcClYq0lwOHlyjKnW4PT8rIL3pdKHjEMDTfZTZ8bvID4twMCQjJh5XqTY9D
         wh0VT7lKwhGEkLRhhXEtEpto6Zp4+pfW5TDwhlvaOa4Jbbv0U9t90CuqIMC4h1QAivL8
         tRBm/cdvJpcELgxui5TxL3/hxgYWydKWz8L+7xHLKEemLwSIne8wEL5qKR6Qluz1YDcG
         WzxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ZABvYNmku42nkrKWZOeXoejdUCqhdms6seXpGpeZ/c=;
        b=ZIHOyZFt4P5/UR4oq1yQzjojS/amsEVtvVoAT+t/ZmdXDG4XBJVNy5lWAaEWtYA8eD
         T78D9DuHiKMINF5QjiQULt8MlRqr2JrXZGMFIpj5U4lGbrVTzRP5HMvgkCyBYcZ+jrOv
         eaLUl5PPGk1YyCn//FEUIeaMWVjjbQ1QWlTrW882u53dIBZkEPFvEhq1jb04zRF8N8cc
         IG5I2TQOXZJOmwaRsZtwGCcids9J3X+Dr61xiniVJdGDgwF4AV8zhOxJCSALjIlsw2uO
         mCWWjgf6FlcfB3YOJsnuFMnW2kZf/T6KdaewfNM/AJjBfkhNdxdYIO/jMbhPtwTMS4br
         Yd6A==
X-Gm-Message-State: APjAAAXyDLGgc7kTAB/PS0vRorFqqPWxmr+6VWfzJ9yWD3vDyqwlWeT/
	q9VliSBqBghik/kwOOS7CFg=
X-Google-Smtp-Source: APXvYqztLzHzmF9x3g+ldfHqB2xC6gDd6g2VTp37XNz+hPHtSagEmkDDNXousrEtXPptZpIo82P8pg==
X-Received: by 2002:a5d:8416:: with SMTP id i22mr17498059ion.248.1560253163552;
        Tue, 11 Jun 2019 04:39:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:e00b:: with SMTP id z11ls3007789iog.9.gmail; Tue, 11 Jun
 2019 04:39:23 -0700 (PDT)
X-Received: by 2002:a6b:38c3:: with SMTP id f186mr4018209ioa.187.1560253163208;
        Tue, 11 Jun 2019 04:39:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560253163; cv=none;
        d=google.com; s=arc-20160816;
        b=mW1E3ZLgslVwvTUQtServJpw0lH+4oCevum06SR06riQABLfI8fzQsZA/RgJXfgMWG
         tPadbz1eODahT/sYSdZJsrlYM/gMuwVG8sbsoz97XRkE6EfLzMGuE/Qu6zwV2aQ30g+j
         NSxbBro6Ngm9cD1ubPUR6aKrXm7BRDSqLn1DLQeIkFaS8CyVdGXJrXR/axTamdUCN96V
         5gVt3V9Kh/jk0kNqi0aSELlLiAQYhoPkYuvwqjfSRGmnbZuzb6yvQGPQrhsN8QJcU5/V
         RqF4lOMxZlQt7aJe89er847I+Ui4fmNy81CszmN2KzBLU0sRTptdwDD10iiSJkrwmQcs
         xVmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=efKaC7Y7c8Vr7TGFSTF+nZFI+Dv5FKl3QaIWZEc3/K8=;
        b=mBwdmdQcYjmI6QBrcWkvrgmPItYq4ZOQu+mWBJ0er3oajzK4ORBUDBbhqlLA/bsu0z
         iGh4MLOd9xAlTteSeabApyd70clPCTsXx8Jq/cd+bT0t4xNQ8gobugm+IXSe/HbeGphY
         o7CjtEfJ93ryiSJ6xYa2ixc5+782sBboRAKMTkf3fNSmgSGCpf1ET57ZvuapyaXORfm1
         bjeUAo9S/JWWZWk8UhWb2q6xMmHOsa5hU3PmRln79fMPaYuJiC8iPikG8EgoJpk0rIdw
         DbM9FApUev/RC7UYR1WWEgsxRS78ouEkGWzT+H1WwOp4FxtIRT6FP/J2EMmDJ2ISfopb
         p91A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HjkPP0rM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x129.google.com (mail-it1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 200si64533itw.3.2019.06.11.04.39.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jun 2019 04:39:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::129 as permitted sender) client-ip=2607:f8b0:4864:20::129;
Received: by mail-it1-x129.google.com with SMTP id m187so4295565ite.3
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2019 04:39:23 -0700 (PDT)
X-Received: by 2002:a24:9083:: with SMTP id x125mr18085676itd.76.1560253162633;
 Tue, 11 Jun 2019 04:39:22 -0700 (PDT)
MIME-Version: 1.0
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
 <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
 <1560151690.20384.3.camel@mtksdccf07> <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
 <1560236742.4832.34.camel@mtksdccf07> <CACT4Y+YNG0OGT+mCEms+=SYWA=9R3MmBzr8e3QsNNdQvHNt9Fg@mail.gmail.com>
 <1560249891.29153.4.camel@mtksdccf07> <CACT4Y+aXqjCMaJego3yeSG1eR1+vkJkx5GB+xsy5cpGvAtTnDA@mail.gmail.com>
In-Reply-To: <CACT4Y+aXqjCMaJego3yeSG1eR1+vkJkx5GB+xsy5cpGvAtTnDA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Jun 2019 13:39:11 +0200
Message-ID: <CACT4Y+bNQCa_h158Hhug_DgF3X-8Uoc6Ar7p5vFvHE7uThQmjg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"Jason A. Donenfeld" <Jason@zx2c4.com>, =?UTF-8?B?TWlsZXMgQ2hlbiAo6Zmz5rCR5qi6KQ==?= <Miles.Chen@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HjkPP0rM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::129
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

I should have been asked this earlier, but: what is your use-case?
Could you use CONFIG_KASAN_GENERIC instead? Why not?
CONFIG_KASAN_GENERIC already has quarantine.

On Tue, Jun 11, 2019 at 1:32 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbNQCa_h158Hhug_DgF3X-8Uoc6Ar7p5vFvHE7uThQmjg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
