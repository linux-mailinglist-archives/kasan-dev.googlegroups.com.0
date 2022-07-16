Return-Path: <kasan-dev+bncBCQJP74GSUDRBSENZSLAMGQEI4F4SNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id BF6C95770C9
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 20:43:21 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id j17-20020a056e02219100b002dc4e721203sf4712038ila.22
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 11:43:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657997000; cv=pass;
        d=google.com; s=arc-20160816;
        b=LZ4tBYxBdTJFvj0Ro2iz5wjYASE5yuupVIY2tzTqj8bSak2MqfYZ5bSmIce/c3ozGI
         7ygPyU0LGvHKRzQI+mDx6nRYn+ie6YIdKOpwrKhGwoeHjtDG51rV5tC+NoseaeKK4vaZ
         uRMIwCPeJvXENyzMhy+HqCI1CHLlImBNaEHtTuV7WqnUehMM3C+UAMGwHjv0PxbWgX4O
         1C9ZsFsw7gJvX8V3ME/bV2T2AqXWgObRsJwwn0lAVWamlSzzst7+u6rZ0Giu+/XfpxbT
         09fr1EGylISFvCmm/Z6dUrmA+acDylQ//p5lJL4FyMYZBSKdj4iTIx1I+pBE5NPBBMHY
         PJAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=q4Dzwy5P0I86m0e9FVaDyxVi6UjyvbRjOTH8z6lBO7U=;
        b=x+1CFz69/+GiIkfv7+rGLqUnqkOIomiwz8JYmCF9rTLkttClzwJmykUefCCs0LqGsN
         52m0U3KVpauSSeAlz9jE6UNiTVbkLm/abRhvjOZ+EW5+HTsoP1fAZWSo8Y2b42tuWY7b
         4PUZH2pXToyRDe1q2DZ74/jbX3OoBCfVx+KEoCJY3zDt9+9jMg/vpFg/LjdeQBBZNUNW
         F3dEXs74b+oxLJdjxD0rP3r8dOwtk2CZrZBzVZibcSdvlyKM7Bgcksq4Vjf+h52dIZXw
         NjLDqKSS08nY1LjVJ4ATvnMoTj6r0UzF0eB03hzGjJUlQfIAy0PttzgEgCSlj7o7eZ4A
         GWBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.43 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q4Dzwy5P0I86m0e9FVaDyxVi6UjyvbRjOTH8z6lBO7U=;
        b=tDeM4fVLue44b4R7mnqhnmapSJdwpIL9Rd8gt5XJBdqFcC16Y/SIzIXzhxeoK9UyNr
         F+mn7xeR0BoW+XVwzGmhpXp6ovT/sCDyniJXQW9XSlTiZnN1hH+j5Iqzbe510W6rCDNv
         AfpHJzB6d+I3yvcHVE3h7A8WKrrhUX2g0dIMTzTOzEwxDhc4b0EFjghg1LcA6J03SPL2
         87dZlLYN++7eE8RwKuabkI+O+l6ZW82MgMSpuTKdPtjcs52SmgXUMWoh3kvu1MyT5CjB
         wu74W4uViByR1Q3iKhAZTG9yOjsgaHdpCFWpz80Kwc/8FmJ01nRYuh8xDkdMU5bIBVKO
         pGBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q4Dzwy5P0I86m0e9FVaDyxVi6UjyvbRjOTH8z6lBO7U=;
        b=kw9TmV2E4WAkPBxblsW2w0KuvVtkj/yqKbBCCR2lqe+c+Yan03XEqpDa+uUprLkgeQ
         okkCX6T+y3S7M9FYLfK9vgpELcpwzk5iBvlicMirjXomk9XAoBOv8H2UmaIYaCYNwMUO
         X8pT6OCcSqusvZoUyYrjRSk1Nu0hb1k0K7mCSAhDWntf8SMbh/WDv7kE9pVewYwEc4Et
         YWBbZXJ+vAaMWkf1Ty9st8S+YJ8nKi3e9D74Edo3Og4oLde/cDcc7+QlQbCdwd33Ku49
         goBN8IhsYiwZNMHztl1HO/H0X84fqu8+tq6BW0lUmCRuWGN1lkLG/zp3SoLk+ojlTV0D
         3ZvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9SaGnCzVgBCGmyYfeGa1B5ZJ5nc0cBYKvrImG3uI9TVJa9AU6U
	4ks7SDBsyX0evFtudxK6FuA=
X-Google-Smtp-Source: AGRyM1sqOTj6NCLkR/DyVH2J8fsGaB57tH3lJgyl/Ofcc+yc3rlE2lRVV/BvdkIK6Gc1WJyHtIhwcQ==
X-Received: by 2002:a05:6e02:1bac:b0:2dc:8162:2848 with SMTP id n12-20020a056e021bac00b002dc81622848mr9891545ili.295.1657997000354;
        Sat, 16 Jul 2022 11:43:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:168e:b0:67b:9a05:a906 with SMTP id
 s14-20020a056602168e00b0067b9a05a906ls1492572iow.1.gmail; Sat, 16 Jul 2022
 11:43:19 -0700 (PDT)
X-Received: by 2002:a5d:9da1:0:b0:67b:e960:b348 with SMTP id ay33-20020a5d9da1000000b0067be960b348mr3398441iob.18.1657996999722;
        Sat, 16 Jul 2022 11:43:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657996999; cv=none;
        d=google.com; s=arc-20160816;
        b=1F7k5FuWZiY8WPc1soE0v6I7SxdwF//9FShVE5QxXORCNai2uxGzLztvwG7PTFFIQm
         zAFgdwYSVNaLtQZcxO9cY630Cxfg7rParp6R/N5KxClYf103GT0hFOcBdSPc5OfdHZSM
         IES/d9BsDdCEHTIZqhWPUgmsFdkWTpI9+WqvFWhX6y7W5RXEU/K0rTL8YSZRqTbqfY5W
         /2GeFkFgB2h4AEaT2PByK5fsl/dPSHFwhxNnE//M6UpJrKhOQpQPkKbpoWki6Jboua5A
         DwGTzzBA3zDjLAyUR9r8Qb69uO1ul2034rz2J1FVHTKtFvpR/rpM0RpDKr4rZ51nDGDQ
         X/4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=WsEhwdLdNfwHR9LCxaWkzLk9jCaKVkk47P3wBYbLRH0=;
        b=fRgRIvIx05OyI4XsGIJ222cv2bKsBnVUKMmOiLXduuAN7tueHN3foKsVrv5J1kr+AM
         vZXjSemPo1hj9PVI4c0HCtBQkJ7p4mu9YdKGaJlprNfT55D6XuDILuGkSF2pygXY8tDE
         Ho59AS68k4eqIjH+C+T/Go++7+qHniTexby/UyLBLIXGKkoX50AZcnSqCWfTWWluvvwR
         6d2SOp4fy3MbuiN4oMjYkUs99fKxHHBWtM4NRrJZRTd9xUG3zndF9i7wHvBYVEFQHw7T
         jnE7PUqRzmcE+s9SV2emciI4qfCLvb9cbSL5kkkYL7PvtxVI4y1svc3Ns16xPbKETAq7
         FMWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.43 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qv1-f43.google.com (mail-qv1-f43.google.com. [209.85.219.43])
        by gmr-mx.google.com with ESMTPS id g14-20020a056e021a2e00b002d77420723csi256999ile.3.2022.07.16.11.43.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Jul 2022 11:43:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.43 as permitted sender) client-ip=209.85.219.43;
Received: by mail-qv1-f43.google.com with SMTP id m6so5959126qvq.10
        for <kasan-dev@googlegroups.com>; Sat, 16 Jul 2022 11:43:19 -0700 (PDT)
X-Received: by 2002:a05:6214:d41:b0:472:f5cf:1fa6 with SMTP id 1-20020a0562140d4100b00472f5cf1fa6mr16376851qvr.98.1657996998601;
        Sat, 16 Jul 2022 11:43:18 -0700 (PDT)
Received: from mail-yb1-f170.google.com (mail-yb1-f170.google.com. [209.85.219.170])
        by smtp.gmail.com with ESMTPSA id br40-20020a05620a462800b006b59cf38b12sm7025889qkb.126.2022.07.16.11.43.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Jul 2022 11:43:18 -0700 (PDT)
Received: by mail-yb1-f170.google.com with SMTP id 75so13903930ybf.4
        for <kasan-dev@googlegroups.com>; Sat, 16 Jul 2022 11:43:18 -0700 (PDT)
X-Received: by 2002:a05:6902:1246:b0:66e:ea31:8d05 with SMTP id
 t6-20020a056902124600b0066eea318d05mr20988380ybu.89.1657996997798; Sat, 16
 Jul 2022 11:43:17 -0700 (PDT)
MIME-Version: 1.0
References: <20220628113714.7792-1-yee.lee@mediatek.com> <20220628113714.7792-2-yee.lee@mediatek.com>
 <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com> <20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org>
In-Reply-To: <20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Sat, 16 Jul 2022 20:43:06 +0200
X-Gmail-Original-Message-ID: <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
Message-ID: <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
To: Andrew Morton <akpm@linux-foundation.org>
Cc: yee.lee@mediatek.com, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.219.43
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Andrew,

On Sat, Jul 16, 2022 at 1:33 AM Andrew Morton <akpm@linux-foundation.org> wrote:
> On Fri, 15 Jul 2022 10:17:43 +0200 Geert Uytterhoeven <geert@linux-m68k.org> wrote:
> > On Tue, Jun 28, 2022 at 1:42 PM <yee.lee@mediatek.com> wrote:
> > > From: Yee Lee <yee.lee@mediatek.com>
> > >
> > > This patch solves two issues.
> > >
> > > (1) The pool allocated by memblock needs to unregister from
> > > kmemleak scanning. Apply kmemleak_ignore_phys to replace the
> > > original kmemleak_free as its address now is stored in the phys tree.
> > >
> > > (2) The pool late allocated by page-alloc doesn't need to unregister.
> > > Move out the freeing operation from its call path.
> > >
> > > Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> > > Suggested-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> >
> > Thank you, this fixes the storm of
> >
> >     BUG: KFENCE: invalid read in scan_block+0x78/0x130
> >     BUG: KFENCE: use-after-free read in scan_block+0x78/0x130
> >     BUG: KFENCE: out-of-bounds read in scan_block+0x78/0x130
> >
> > messages I was seeing on arm64.
>
> Thanks, but...
>
> - It would be great if we could identify a Fixes: for this.

IIRC, I started seeing the issue with "[PATCH v4 3/4] mm:
kmemleak: add rbtree and store physical address for objects
allocated with PA" (i.e. commit 0c24e061196c21d5 ("mm: kmemleak:
add rbtree and store physical address for objects allocated
with PA")) of series "[PATCH v4 0/4] mm: kmemleak: store objects
allocated with physical address separately and check when scan"
(https://lore.kernel.org/all/20220611035551.1823303-1-patrick.wang.shcn@gmail.com),
in an arm64 config that had enabled kfence.
So I think this patch is sort of a dependency for that series.

I had cherry-picked that series after bisecting a regression to
commit 23c2d497de21f258 ("mm: kmemleak: take a full lowmem check in
kmemleak_*_phys()") in v5.18-rc3, and having a look around.

> - This patch has been accused of crashing the kernel:
>
>         https://lkml.kernel.org/r/YsFeUHkrFTQ7T51Q@xsang-OptiPlex-9020
>
>   Do we think that report is bogus?

I think all of this is highly architecture-specific...

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdWSsibmL%3DLauLm%2BOTn0SByLA4tGsbhbMsnvSRdb381RTQ%40mail.gmail.com.
