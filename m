Return-Path: <kasan-dev+bncBDDL3KWR4EBRBE5V3KLAMGQEYEET3SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B454F5798C2
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 13:50:44 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id h11-20020a92c26b000000b002dd0139d9dasf658111ild.20
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 04:50:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658231443; cv=pass;
        d=google.com; s=arc-20160816;
        b=pTVUD7cA4ArEXVjrXW5J+4iKoyBsV8Jbu5/kq3vepiT3xuRranklro/A4sAZrQ9xAw
         d6cjZWv3H3FZzm9OdGvzUWFzxjSPwrxA4eoBG1hNvKP6aSHfUyJGSBjgTuBfBBx3rSyP
         LAGae7A3wYmjbgcVvVx92nDw6iY5rAd8gX7LCRebpH67LIuNwPKpRNreRfSWraoPZntv
         fvzh+nH5JqsGs9n0uId35g+cOmx89LWWWlCK10L3xF5aoz1egf5Ffr0p5ePrIZ51qcL5
         cYNwCikyHxtsADwZnkyjn7vK5yG1YUZ01/PlquCkYYZY52n2vqn0/mtLzodaVPRPp0ew
         8KqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Fg15PXPRGuqKRYWj2DijQPVrazWUN08sSznLaJa9TW4=;
        b=hBz0OPE3B2ipTOmxgJGGUT+NizMiSIS56cgFJes1+7UPPyEezgj0UJwgtGskjeTg4c
         aFnzWJ7CIASg+csicFRv9pqXYVD9BBl1sHYFcORNFUWCUk7sDFPYBOhFxNpxCK1srXVq
         SOcYs4qJS8ioijWl+ktAKNzuJTWvp+ssFSQaAX398YyiWOUQWvnU18SX505BczJ1Bx5Q
         cS9bdBeggMT0h7EyGPXCIBGnGrAnAg1zAHyeuoNUcE7cfdei2easCANmpQgGQPVKgkaC
         uFeLfKGtk1tqZIvlS4dxQ+StUD+0DvYe+mU44r+eSgk53u50XoXv9SDYcaXGBKg8wiuA
         NQ0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fg15PXPRGuqKRYWj2DijQPVrazWUN08sSznLaJa9TW4=;
        b=XiyiejS5lyYAlp4BXz8Vjpf3rWTWbd3yXQArawd6Z5no6KWUMXjKhowzLvH5dS0miJ
         0f2lC8X18ZUKalrR63KQMJYbIvSXS+uVTsDcdA691fke+gIMNlTtLOzmvCibzMeAN+nK
         bcbnTO/DI6l/LywRPCruyODAnWQcLinUkjHqVjdokgYvGq1UoQyn4uv6/86b4yiowcuJ
         3BQXaUKjxKlib09l6Mke1CFS9H/QsUeJBmIk94Atz11b8fu4I5353ykCjr1po7PsyF4Y
         Q1tdabLnIxZZZaxuXnG7hxPBAASgCVPRsPqqKczWmvbdisV489eUZVbU81pUH4HM2A9x
         baXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fg15PXPRGuqKRYWj2DijQPVrazWUN08sSznLaJa9TW4=;
        b=X1Jzx6SwM1+DAbvMVboyIEm25ypHx0jStaUO0MyutawOltP5VYsXVW2iTgyJ25ENF3
         c2+tas34IGYZIZOFe0L8rbLe4tFBYFGr2yTK3b06o5BXTHCEffd12P+dihGnN9exEgVF
         ZrXNrkrgZi85FbHnFGJpdjhtHnyNhCNuqw6kR0QGxz+rcBosczJGY1+sXJCOA0lzpLjn
         hSDy3xlzn7ixfYCN0j1mI4hPrljK+xHpzul8XWJidNcm3yg2ccRUPpxDwaKt1KbaSBbU
         180ewl5XV422gq0YgB4PPSSrEgFRuXSB3H3LCFBytiMFV+qoK/q5NM7VYMrgYCWd+uSw
         Tc6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+9q/rBDJgGliCInOsFhhhaFwt/NXSp7gEhqzKKKo5a0sTszNfy
	Xw4aMZrUI30gKNaEjVzim10=
X-Google-Smtp-Source: AGRyM1uwDYtO+5wUOY1AYbwsFunI37Waf7s2V9lFKF0sKyo48gPPPC3zKGMIPbsummhGYKQIqDZLsA==
X-Received: by 2002:a05:6e02:1a0a:b0:2dc:7a5e:5869 with SMTP id s10-20020a056e021a0a00b002dc7a5e5869mr16111867ild.90.1658231443285;
        Tue, 19 Jul 2022 04:50:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1106:b0:2dd:613:6330 with SMTP id
 u6-20020a056e02110600b002dd06136330ls31951ilk.3.-pod-prod-gmail; Tue, 19 Jul
 2022 04:50:42 -0700 (PDT)
X-Received: by 2002:a05:6e02:17c6:b0:2dc:1d37:5133 with SMTP id z6-20020a056e0217c600b002dc1d375133mr16808573ilu.297.1658231442765;
        Tue, 19 Jul 2022 04:50:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658231442; cv=none;
        d=google.com; s=arc-20160816;
        b=b5fLkMUsQGz1C2RzMlVoIKwizZa8h9OQurLWc0nC/ur0to4Xa4Y7ck98D0u8c6sl7H
         dx9eQIoX5ScGVe3hUz2OHjuGss0i1U129CiWub5qv8cTjOtANPVK9nyjIVnZkgaD3tvE
         zKq9+zk6ZtI+oPS4IqzhGrHkxrp8z493FXVRYXmp3RPes5SoxNcxGpHiSm4LKX3WEiKu
         BO0T23s/EoeWoQKOwfFDGVoGqE61rDcXdxfC99ri2i6QG9PcEYQVxkopfvsss3WvRpFr
         D3rM+hi6bng1vic9pRNua7+GCfJRj2RShdeREAulrlVfsjLSzGD23K9KPG9GSp273IRP
         Ad3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=OLuSjFfvcEuEmaQo9SbJ+jxYDKXN8EVDEVD/m4JEzVU=;
        b=lQ559+hcFUgmvfJGum4rFE/ALzyVcL7nYpF1W5pIzhZXeTegQzm65+fkli/NBEX51U
         xDai9XWhk4noBByZZ3t6Opw4IQC/hd00s1Uj/RfmJwy4yXZ5vzzoKWO//PZAQnbVLu9d
         YqyUHqDS6yGaawVecvTFBHkyTC1YY6kzRgDIDozdNAkgjllzAx+eb+C73SiwZTikEKeh
         DDEWs7ugwLxdyNf2XWP2QTVD7BYj0GRpfoyZ3ihrpPLu2cvuk2m714OSUtqjGRfyVqZF
         fwGcBZcahbAOTxs2jVEGNLLooMtIqcyJL1hMbQvjTuiOikw0r6DMhgo1c4R3e0N1w6SK
         0lGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g18-20020a92c7d2000000b002dcda4e18bfsi432196ilk.5.2022.07.19.04.50.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jul 2022 04:50:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4A3DF6162A;
	Tue, 19 Jul 2022 11:50:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 39A21C341C6;
	Tue, 19 Jul 2022 11:50:39 +0000 (UTC)
Date: Tue, 19 Jul 2022 12:50:35 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, yee.lee@mediatek.com,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	"open list:KFENCE" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
Message-ID: <Ytaai+yWz0JG4a6O@arm.com>
References: <20220628113714.7792-1-yee.lee@mediatek.com>
 <20220628113714.7792-2-yee.lee@mediatek.com>
 <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
 <20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org>
 <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Sat, Jul 16, 2022 at 08:43:06PM +0200, Geert Uytterhoeven wrote:
> On Sat, Jul 16, 2022 at 1:33 AM Andrew Morton <akpm@linux-foundation.org> wrote:
> > On Fri, 15 Jul 2022 10:17:43 +0200 Geert Uytterhoeven <geert@linux-m68k.org> wrote:
> > > On Tue, Jun 28, 2022 at 1:42 PM <yee.lee@mediatek.com> wrote:
> > > > From: Yee Lee <yee.lee@mediatek.com>
> > > >
> > > > This patch solves two issues.
> > > >
> > > > (1) The pool allocated by memblock needs to unregister from
> > > > kmemleak scanning. Apply kmemleak_ignore_phys to replace the
> > > > original kmemleak_free as its address now is stored in the phys tree.
> > > >
> > > > (2) The pool late allocated by page-alloc doesn't need to unregister.
> > > > Move out the freeing operation from its call path.
> > > >
> > > > Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> > > > Suggested-by: Marco Elver <elver@google.com>
> > > > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > >
> > > Thank you, this fixes the storm of
> > >
> > >     BUG: KFENCE: invalid read in scan_block+0x78/0x130
> > >     BUG: KFENCE: use-after-free read in scan_block+0x78/0x130
> > >     BUG: KFENCE: out-of-bounds read in scan_block+0x78/0x130
> > >
> > > messages I was seeing on arm64.
> >
> > Thanks, but...
> >
> > - It would be great if we could identify a Fixes: for this.
> 
> IIRC, I started seeing the issue with "[PATCH v4 3/4] mm:
> kmemleak: add rbtree and store physical address for objects
> allocated with PA" (i.e. commit 0c24e061196c21d5 ("mm: kmemleak:
> add rbtree and store physical address for objects allocated
> with PA")) of series "[PATCH v4 0/4] mm: kmemleak: store objects
> allocated with physical address separately and check when scan"
> (https://lore.kernel.org/all/20220611035551.1823303-1-patrick.wang.shcn@gmail.com),
> in an arm64 config that had enabled kfence.

Yes, I think it fixes 0c24e061196c21d5 since after that commit, the
kmemleak_free() no longer worked as expected on physically allocated
objects.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ytaai%2ByWz0JG4a6O%40arm.com.
