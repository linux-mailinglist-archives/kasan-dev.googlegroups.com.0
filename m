Return-Path: <kasan-dev+bncBAABBC7B5LVAKGQETHP7YWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CA3F9267F
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 16:22:05 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id p9sf2102938pls.18
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 07:22:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566224524; cv=pass;
        d=google.com; s=arc-20160816;
        b=DQG3Y/ykQXW8cdNx5Ot55A0VZFhjSwN2/rXt/a8b9EY06HiSYosbhcZz1wYTK6O5y1
         4CG/udxMVfhSa+txed1oSlKH8ax/nvs+kqO+1nXOBCCf1SAM+DXT41YHp3eUozDAqhL9
         sh8mSfA9YShsvF23xxuSFanBtoPzdB7xXi8VCJmtRpUgaUKyusURo16jflsQrZiOUnJh
         v3xk0t839J1RtjivBLY05pzNoy2+fCzuFajeMWu7veoIcOU3a9bhQacWch/os0v1bFMV
         ykuRK089SNftEGF+LhmuhuWyufvaYrcsj6f0kf1nCak1OFF4dWEorVYMwEbsX7ZZIQke
         s8vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=sorwAWb8PIDVvdU4yp8FZq6tk3dcZK++W4BNGrExsH4=;
        b=cFHsB+sNwZHqLmuYARnw44DQgVpu1YX0pLJhwh08bLAygYfJlbDfIA+ogG+X0EdQh5
         /bVPnHQZp5qE6FvFvzImk8DuvBeJqpQASnwCD5SAgnr3cyubTuLhvaTG8WOhcSezXRul
         6cNBxhrEqFqtXr4++0c5zZHrw5SKL6FTkUtpjdfsBDtLnm/2BLOieS9+kZF6Hy9b/IOF
         atdNNBKYSlQXp8PQJ31elgjXdEZaFoI0ja7vUETjZwYX2J0TXnQZjdsnZ3BfEeg7MpED
         gh4qxoSnG6J6maULz+5KePlVz2+v2KKqSFxpnVOY2i5Yd6bsVDdcjTqgu+QIZStT6702
         /1bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sorwAWb8PIDVvdU4yp8FZq6tk3dcZK++W4BNGrExsH4=;
        b=a+PJOHCFICtJ6LO0EIkykc1DKeVe2ahcYl5dF0kff9UtZdy3eIotyFMCkc9E1YeAIt
         mc2wYXrxG4T5SjK5aohB7DJuMkFF0ru6gXPBIycRsDP23MxH37iaIEJm6feoDN43CdLF
         E/FkaVn78O/Mb3UZ8AKtuCl/urGRDO1hl8yVc8Vy2iTkmH7z6V+8QgPqZ7RWH7lfivDM
         SRvVYKsJpGRUXiW8iP2XJM6JN3gwXSmnbkDfNJlEHdp0UzoJiYu/DnlhtcLP2HYZuzBm
         v758GiOdhYz/yezrey0C4H9Lw27InZVY9rcuAjJUnJi9QOPrN4G6sPbRGIh84PHOPojk
         jP9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sorwAWb8PIDVvdU4yp8FZq6tk3dcZK++W4BNGrExsH4=;
        b=B31Oe83biPEHNBRLgp8vE25sbS8e+fndL2sTALz+jJMv1zaEPCB93p4w4zkHKXuPlJ
         2iGhrfUP7NnupanmkGWGy7ZQnlj0P5xWr0a7ppWCFmWUmXnmHD4XNcdF3oTx+/OlHGk3
         C9+fMvJ9Kro4CVrkq4BQ02IrG1O+cZ0+V2ppGvQ/5YfqJ69dvMXV1RsssEuNJVxmMWT5
         ypgWIJXuCjF1qQ2Hcajdq5FWfKmo4NvRpEUoOXyHMEQSEoVvmuQMctlprtGtBI7VFQGi
         YNgqK4ZW1ef1lTWijw9g7IkROH//GPfA0edwMsT1Sr3sT2x6X5X+EWPnj0Wub2fJLziF
         WoVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXNIdHE3Ihxfe3lhCn6Xr8xQ+W/wxR55MzVj1pSgcpOAgjkjiHc
	k8o7h0h/v0kOWbBZtwR8XZA=
X-Google-Smtp-Source: APXvYqwusdyWVTwQFvN7xKQNZW7XuuqIQsV7FmPNRzbwyhqgw2vgwUS5FcFyhaIVaoDsYaiNyLg75A==
X-Received: by 2002:a17:902:145:: with SMTP id 63mr10693963plb.55.1566224523850;
        Mon, 19 Aug 2019 07:22:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4809:: with SMTP id a9ls1006pjh.1.experimental-gmail;
 Mon, 19 Aug 2019 07:22:03 -0700 (PDT)
X-Received: by 2002:a17:90a:f012:: with SMTP id bt18mr20437909pjb.10.1566224523466;
        Mon, 19 Aug 2019 07:22:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566224523; cv=none;
        d=google.com; s=arc-20160816;
        b=Kmny0HlIMizRgcTEvG49jHiyb+nSnRB59IfHpwAZVt5YQNWAxwBjnxutX4PU0PAmv8
         t0y9PUXlqT9nwjFy7uawTzYTr/c/uMwiL6GMP1KSSFYlxLXNYwNFXoExvE48hmfdt9fY
         3joYj45HnTYXv6nU4et4GDhb73wl++yLK+YDeqYe17RSrCdk2qtYvTTSMH8cTZFGm39w
         opHamH1ju68uy15nj9Kl6pLwFSCoaWoCXU2FP0mbmPQJ3c2ISDJD+sNknvUXxn4QK1u3
         P5m9WwVVj0sY3C474H2Cc+CPKK0z8pL6JVcIsxTtypNgBIlwMMQVkih/FC+XPJhX2uuK
         2Leg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=4cMpTZ16GOk/C43E6VA9WSr5CJh+d5BfID7frTiEBlY=;
        b=vuPufBV91dwlusLPyvOW4IWk+i26WB3sg9MQL/iZ2VHuC/OrITF7C1GWWasJORkWhf
         MuLiAsr6Mv2UmEjPMzuhiOePP6l/tlo6dvkh4qEvUg5m+YCMD8j4DxTBcUZnLJILKhFC
         v7+PnBBAEa3KeDWsq4Gkm6rYNdwu8bVWaBvQB6IdGp3E4w++0hGC6NJ5o/nUCciQjs+k
         QgT4PM0L15TdgnBF/nUDsuo3u7Yp2Abg3uZ27pFFg0lKtud6EkLZnYMc4xLGQrxOvZt0
         QXSHyk/h607aOvVT7tTxBsJZ7cjxynS1PH+v1+r2by9f9HVcT+bOFYxx0Hpr6yKpeORc
         XYTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id c11si530535pjo.1.2019.08.19.07.22.03
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 07:22:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 8c89e3d18e8d4292afa7d8bd1e6b4842-20190819
X-UUID: 8c89e3d18e8d4292afa7d8bd1e6b4842-20190819
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0707 with TLS)
	with ESMTP id 42098201; Mon, 19 Aug 2019 22:21:54 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 19 Aug 2019 22:21:56 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 19 Aug 2019 22:21:56 +0800
Message-ID: <1566224517.9993.6.camel@mtksdccf07>
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>, "Will Deacon"
	<will.deacon@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>, Andrew
 Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>,
	<wsd_upstream@mediatek.com>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mediatek@lists.infradead.org>,
	<linux-arm-kernel@lists.infradead.org>
Date: Mon, 19 Aug 2019 22:21:57 +0800
In-Reply-To: <8df7ec20-2fd2-8076-9a34-ac4c9785e91a@virtuozzo.com>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
	 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
	 <20190819132347.GB9927@lakrids.cambridge.arm.com>
	 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
	 <8df7ec20-2fd2-8076-9a34-ac4c9785e91a@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

On Mon, 2019-08-19 at 17:06 +0300, Andrey Ryabinin wrote:
> 
> On 8/19/19 4:34 PM, Will Deacon wrote:
> > On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> >> On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> >>> On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> >>>> __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> >>>> but it will modify pointer tag into 0xff, so there is a false positive.
> >>>>
> >>>> When enable tag-based kasan, phys_to_virt() function need to rewrite
> >>>> its original pointer tag in order to avoid kasan report an incorrect
> >>>> memory corruption.
> >>>
> >>> Hmm. Which tree did you see this on? We've recently queued a load of fixes
> >>> in this area, but I /thought/ they were only needed after the support for
> >>> 52-bit virtual addressing in the kernel.
> >>
> >> I'm seeing similar issues in the virtio blk code (splat below), atop of
> >> the arm64 for-next/core branch. I think this is a latent issue, and
> >> people are only just starting to test with KASAN_SW_TAGS.
> >>
> >> It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> >> virt->page->virt, losing the per-object tag in the process.
> >>
> >> Our page_to_virt() seems to get a per-page tag, but this only makes
> >> sense if you're dealing with the page allocator, rather than something
> >> like SLUB which carves a page into smaller objects giving each object a
> >> distinct tag.
> >>
> >> Any round-trip of a pointer from SLUB is going to lose the per-object
> >> tag.
> > 
> > Urgh, I wonder how this is supposed to work?
> > 
> 
> We supposed to ignore pointers with 0xff tags. We do ignore them when memory access checked,
> but not in kfree() path.
> This untested patch should fix the issue:
> 
> 
> 
> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 895dc5e2b3d5..0a81cc328049 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -407,7 +407,7 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
>  		return shadow_byte < 0 ||
>  			shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
>  	else
> -		return tag != (u8)shadow_byte;
> +		return (tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte);
>  }
>  
>  static bool __kasan_slab_free(struct kmem_cache *cache, void *object,


Hi, Andrey,

Does it miss the double-free case after ignore pointer tag 0xff ?
and please help review my another patch about memory corruption
identification.

Thanks your respondence

Walter



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1566224517.9993.6.camel%40mtksdccf07.
