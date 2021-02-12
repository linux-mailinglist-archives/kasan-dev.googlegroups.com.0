Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX6GTOAQMGQE2YBUCYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id B7B5831A5F0
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 21:21:52 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2sf414538pfa.17
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 12:21:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613161311; cv=pass;
        d=google.com; s=arc-20160816;
        b=LQxvan/dKyUDVc4alK6Bl8nYhWSFiOL4ewsAtW9zjj6yrMNMwxe8vY/S0MWxp1PIoi
         LkzMgguM+zapru6OdOggUaQP6DK28A9REQYBxMsCb4avE5zo330hcWuNrW0xhDKoKLos
         GUKBLFtx6olctaAKlYxJ6wdaxvA1XoAn3Elt6vZzgaifoscICb9iqRpWK8pCQh+WIwF8
         YTzFE+km1O7UP7MmABgmmfViyZAwa7TDpzBwPLiLna2qtHQ6yrf4cmfzdn6/uv70cJcx
         BU3PTibf/j8AdP14Hg5JdcVDCfZ4dCUjfsgX/jz6KliyFrYTRnnyqI3ZcTuzJJ/5Elx4
         WrxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0kc2ZEtsMOyt8prhLyX7kiAmDOiUuyydL7yW1qn1QM0=;
        b=M60eZbFCwxP8L3uaLKOrvyK+6I0W+9WFqCJ1CyZFi/zs4ETWSiKhBuPkT+vEYAR9SZ
         ND+S6xQdPMM39SU4Z1vgbmDMIb+kelBmo2Fdd9VBbLZMwpO4sph+kSWW+JQlXKJT4XFn
         hCx1c0HhSQUVWw7Huyr7BrfXmUnlfz6XQUF5f9XPp1u54qOV2UBmWMGIrN4AGQyhmCYK
         cBGypB1Sfwb5lrvjZwjKvfzLc8OLNG6cct+BpnGWcoonZkyHLitR8gIERp7LapMVTZDK
         YGKpGRpbHi27kjVbvYi7Whoe6f41XYjPWzPn3EsxI3Uh71KM7Cy5YqFtENGXNxL5YOEb
         Xibg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l95kKpXY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0kc2ZEtsMOyt8prhLyX7kiAmDOiUuyydL7yW1qn1QM0=;
        b=J647FDBKnV4rqC62wLuMhv3aHqydZFY5mC3/2ymEz9lepmpgx3hic6Df5sTbrcpkvd
         ILQv49M1EIkV4YyYtIKHagapZH8pUO7AElEIyfDyhxIpMZWazA1BcnObbk5SEOEg0nrz
         4N30YJaupCnsgWPkTVm4+ceH9j/Wr229zELY/qKE+3lE+qRiXZExtHSa2DWmvt1YOJ3V
         oUywbZp2Pxw/VmS9Sy3SxAAgkY3N6CBbu2EPUjGwRuUXMHBglj6BRRnVNq0IgbU2UnGd
         vs4nIOH05ZrJB+nfgsf8SKJLpLJIVtH61R7Q/MskiFlc2+qUvWU+EirG5BX/JLaX99/9
         X+bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0kc2ZEtsMOyt8prhLyX7kiAmDOiUuyydL7yW1qn1QM0=;
        b=mRklMc3Dugr34CHfLt3C7k46H/WNfpcwpatOQ1yUHMpcSxPT7Q4Md6XIGDmtvYyreV
         fk9nIIok6mbkLOBQQ+TWkQBIfVFFm5sxJIDy3hDYChJPIKjs3wUCJGwso0xNtxXtekSS
         eNsWBiiIKEh2GogG2iTLgHQ+DV3f2SXq3tlSAc4UqcEhuLLobuOLEm+6JQBhF0azlWfd
         N2LRCgto++qrQ3AlzzWCOsvs+X6hC0Vuxb5SogyrxQpwjyCl5r5BO3djm4uKfepsaSk9
         OJe86BuI5Pj+Lpg4to+XTKS6gCY55ry+2Vd8YNgPgZJ9/ZjekGRAnSmyuNxfOWFD5z5S
         jwTA==
X-Gm-Message-State: AOAM533SQ+nExn5GPv8ttDvYhWl64RnLmEEawziOfmLAmCBJjyK1KV/w
	MhK/LvhujY7ervI3NWKcjk4=
X-Google-Smtp-Source: ABdhPJxrRv4CVgPtYKGkR3uY4NL7nfIRdbZgzb4xXaEt6QYz8jTr6oq41eQWxgGEZtXdyGEXd4VEnQ==
X-Received: by 2002:a62:b410:0:b029:1a4:7868:7e4e with SMTP id h16-20020a62b4100000b02901a478687e4emr4612671pfn.62.1613161311472;
        Fri, 12 Feb 2021 12:21:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f40e:: with SMTP id ch14ls4899158pjb.1.gmail; Fri,
 12 Feb 2021 12:21:50 -0800 (PST)
X-Received: by 2002:a17:902:8687:b029:e1:601e:bd29 with SMTP id g7-20020a1709028687b02900e1601ebd29mr4265749plo.47.1613161310846;
        Fri, 12 Feb 2021 12:21:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613161310; cv=none;
        d=google.com; s=arc-20160816;
        b=MjkMs43PVsW1QxWeCjCUrl1d+uc35DFpZpH83m6/NqfQkBmWPuk26XTmB9UH3BLNTL
         lyURwLd2bnNBUjzLBlnP5RrrOzqvuInCbiNW7mFz4hera/LVoUMVQ4gvRIXRGgBKRrXe
         doCIl17QRBD2MqNGHxGCQaaVl65TUkgTRcMk4bwq/pctSgA7cVARIn8C+3aut5h/bjIk
         Q9OJwlM2Ln3lB8fU7FxlDBjh8jO5+b9SeC0xiAPIW9MZTiMkOHCJad3908ARY8L4fLr5
         Cqr02wnq5V3zmdkI5vpcWh5dPzB1GEWlmbtShcXgJGsuso0SOF9GMD6loRlmgyvUMXvf
         p5AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zqHGpHlEVtMfxaAYSRUeoJtPJMW39eSW7LQpfFCRpGU=;
        b=c8liMjEpvirCP5hVuvaQPSmZGVeCr0iYm2iUQQ/ahNASP667lEWGufrZHRv+j5tB6M
         RVQ2MSFP/0GK+87kxpRHtAcS4L6DHiI+fmMIYKZVD2cEwkhGf2fFFi6HlllDqz0DyQl7
         VXSuyNBWp8WYv+JofZQkYVfDsiZM8af52AVXlcCcSBKrbtnlkdLDOkOUjHVBB5Soia7S
         /QOSrBYiJ8XzX7h1o8QLF6j7u9QI/Ux2k0d621VwpKLT0Af+Sy/92oWYWXpmuwHqno6t
         I67mSZm/fcULnqfTrKkRMTtE8FNXcc36Q5b3lMvyZxd2auhKkW9MDKzzcrLot0fhydic
         rHYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l95kKpXY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id p10si539280plq.0.2021.02.12.12.21.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 12:21:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id k22so436656pll.6
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 12:21:50 -0800 (PST)
X-Received: by 2002:a17:903:31d1:b029:de:8361:739b with SMTP id
 v17-20020a17090331d1b02900de8361739bmr4221474ple.85.1613161310340; Fri, 12
 Feb 2021 12:21:50 -0800 (PST)
MIME-Version: 1.0
References: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
 <20210212121610.ff05a7bb37f97caef97dc924@linux-foundation.org>
In-Reply-To: <20210212121610.ff05a7bb37f97caef97dc924@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 21:21:39 +0100
Message-ID: <CAAeHK+z5pkZkuNbqbAOSN_j34UhohRPhnu=EW-_PtZ88hdNjpA@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: export HW_TAGS symbols for KUnit tests
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l95kKpXY;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b
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

On Fri, Feb 12, 2021 at 9:16 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Fri, 12 Feb 2021 21:08:52 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
>
> > Currently, building KASAN-KUnit tests as a module fails with:
> >
> > ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
> > ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!
> >
> > This change adds KASAN wrappers for mte_enable_kernel() and
> > mte_set_report_once() and only defines and exports them when KASAN-KUnit
> > tests are enabled.
> >
> > The wrappers aren't defined when tests aren't enabled to avoid misuse.
> > The mte_() functions aren't exported directly to avoid having low-level
> > KASAN ifdefs in the arch code.
> >
>
> Please confirm that this is applicable to current Linus mainline?

It's not applicable. KUnit tests for HW_TAGS aren't supported there,
the patches for that are in mm only. So no need to put it into 5.11.

> Today is pretty much the last day for getting material into 5.11, and
> this patch has been churning somewhat.
>
> So I think it would be better to merge this into 5.12-rc1, with a
> cc:stable so it goes into 5.11.1.
>
> For which we'll need a Fixes:, please?
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212121610.ff05a7bb37f97caef97dc924%40linux-foundation.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz5pkZkuNbqbAOSN_j34UhohRPhnu%3DEW-_PtZ88hdNjpA%40mail.gmail.com.
