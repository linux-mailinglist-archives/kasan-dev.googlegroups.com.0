Return-Path: <kasan-dev+bncBCD3PVFVQENBBJVGWTWAKGQEGPXQWEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id DA9F5BFA2C
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 21:36:07 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id f199sf1462360vka.17
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 12:36:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569526567; cv=pass;
        d=google.com; s=arc-20160816;
        b=U1yiooB0SUjRaByAiMnjDXSxxDPg890K5o1R+4AEfncjLKgx9XvDew/D4SA+VgvZ0I
         LtA+9yxaBbSA5NI6+GN1TfM9fqSXlgAw0R9XuRAt5E/d1WWd9H+M8uAN5UykJaRH0pHm
         2SDRVqudKC3e9B5TKPQouSTcxnsgEeIu/OYVGUXs0BKznmO5csbVQK9j6ZNImCJhCgiD
         v4+xppU24yawHvbwO8yXgT2lfEHdFVKoUmKczbk2hh90hWAV09ggf7FMvuTCHbPAEEC5
         zNkni0No5MXQKkDnyEXuvyMyvT3+FVVhrifFzeRrIIiaG/RMVspYXlRnhUZbNaaekUTG
         zI8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=hBmPkxvAQOedvS5iWF1x1CCk0AA/57SER1cgfW+8e3A=;
        b=gvnm8BbD7VMFi+SrTKyeKjO0GEPFk3OyxGM1TfzrYBcg11eW3NU8GYTOinw7NiMj5m
         M+Yczo0fjjcs3HK9vpnlm5Y8ZbOGhJkhAhV/fVySldpV7c7QiymPOFE4mKAuD5xOjcyM
         e2DqhXfcnqHwLC1YRetrREtpfB8/69zACmSWuPFKOjETdEjdB27JCJmwSu32Yafxf8OM
         BfPQggHgP/pxmZs3dqn2chPVt9GQpdIGPn1HC7PFUvaN8UzOT8eDeLbkPRMj1jrsEgwF
         NW6lVGeiqEn9DKNy1j2UTL2lpDaYBQoWnv8mcS77DlssWjImDceH0G9l9rS98T+bg1na
         RVgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lFVH4DJZ;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hBmPkxvAQOedvS5iWF1x1CCk0AA/57SER1cgfW+8e3A=;
        b=n+nePAMygxwBr46YvO0lSjx4Mxdn8oJhd12R1yw9PobCHcKsd5UOiyDybWXl/Tyj92
         qh3c8JOQUdDdmN4h8/pwzfnIStL1JrzWe60Z15WeVI/C2D5IBx4UJn7QIaFq5AmXYHSe
         Cf8gORBTqmASovge4+bctLZHqDLqtb9Ks+iFA65kCQLfuEOdTbTAyZjBGr3jRCQizump
         QE7mTTkycuHtKk+DHWI2X8kIBbF7NgSDO9NqgFK1xkOW0a5NzDAn3KU8DudEAfnegKOx
         Pt9JksiVgYzC5b5rniNHN+lElkgVAhvUoJgywXsXPrKjMMEk1HKo+kf+fnK5FxAidT5E
         nLRg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hBmPkxvAQOedvS5iWF1x1CCk0AA/57SER1cgfW+8e3A=;
        b=hapOIHk7IArmhhoGwWVYTAuj/c9NktFfdgYrLEEsBEyi6PXyA+Evrk129Wcw6ZsOry
         7lmueeGM7XDa/0adkVvXIB+dRMzQA2+Zg5uqvE5N5sJSO1uPjdHKA8BhHbIyoGMdmffq
         ROhXwFk+VPgN98K1qQPGnbPbkakiSObxIjB6PUX5Cwu53wVxOB89/LuSoJbi8zTt5ETn
         vL9o/W4ggmkBK+8+rOvpOP+5h+ZYYNvQ9GRVpIrX+Qlw7AuCaOijg75UrXodB+eJk3R1
         IutrQNLp11tIQiQtvHzMj3pCSQHJB6RrSugBUQTZSZFfewY6uPJlC1FNEdvBTRnYbjB4
         +WjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hBmPkxvAQOedvS5iWF1x1CCk0AA/57SER1cgfW+8e3A=;
        b=n9T7cfHRR70k9nnJNp6pHL82QOX5Xlf3Mjqrfxb/MTrBZvjpZ8u4qCMwp29ANuNe5y
         C6oha3Jpw4E72ciyR+d7CVMZLFTSIEHhCtHIpTI9qGK+EfFlkfsFWoNXqcjVIfplRTh5
         02XDBer3HOZ4pwokjIcqux94TTiA5aFfxpVqKa3UROfQk0i6qqa/LP/jFebFksnjLyr/
         gg//cLd4jlqYx4U/D/z1Y8oqO1NvNkmUVYymKIbIdAPADLRM2ojg9DGA/ZMblXdyQhZ0
         RqUlG+nLdZDJ8kAMy2AsU5zsFU7Bv+W9DwEbsQ7wU7kF6g3eey0fsjT4maxOviphZTHs
         h3nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWV/UVZvshmqJtO5l2RtGsOwrlP2dG2nsNjZBA0IxfSKJEXNkp0
	cPC3jIm6QdRuSLC28oiP4Hw=
X-Google-Smtp-Source: APXvYqx73ojdVHU3h+aiSz/tB2y1PyGPNxbsxQCUwEqdOUeGdEXVdpadue0ecOslOKISovO0vI1fXg==
X-Received: by 2002:ab0:e0c:: with SMTP id g12mr1306231uak.50.1569526566721;
        Thu, 26 Sep 2019 12:36:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1e81:: with SMTP id o1ls149394uak.0.gmail; Thu, 26 Sep
 2019 12:36:06 -0700 (PDT)
X-Received: by 2002:a9f:3e04:: with SMTP id o4mr2970823uai.28.1569526566397;
        Thu, 26 Sep 2019 12:36:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569526566; cv=none;
        d=google.com; s=arc-20160816;
        b=cR7HWw8A5fKMNto7dH16xEg+Pv9tyia/W617MuA1xhMbKCaKI2uFyr+hbf3XSMQA4Q
         4YZV2RfjUoi6vNtV4uPUbeBMmJXq077ea3Tkl+iztNvDct0s/F3t2/hdTExoJTX6ZIOi
         +B7adVn5keulL0nHKTFUNX3Y2D6bqHohtv0qWPt0BvJ141eoeTkOID/DzI+vQ1SPKnTA
         lqmaoJ/k4HIKp9JsLw0Lg8QCEvNk5sKTeyopdfIEqKETqP7i0IvY37D5OnMNXa9IZgJY
         UjgVkk1iRRPeDQlbYl58jKv3aSXRCMf/XFrdWY2hpq48WnHlYgJNbao862K0h/PYESy7
         4yew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uv8sypDhr4ui+8J14AcrUpiwkTC+Ius1tZ05+vuLNHk=;
        b=zR0OpTbQBrJyklybJOfkFzmbQxeC2NTR1uBtKM4vPIsjIIva72VpMs5OP6xsMnfenQ
         QSnMHyr/fJnyAPyFQ1Vb0hFYF4A/zjq54HUMPDb4jIbzudFVHuP6wlM3KMOe+JUvdzzf
         6jEO0Sw84OLBwYc5ExLJVAAR3/IOfApU7ErvhEsWuigWj5myWtyrgyYtwlp20M8sGoTX
         wuDxxrL0yFvr24FWbFH2SHv6Tfn4fZMMVm5t4qNtMAofPwNqPuc0PGa+rHEONUHkr42O
         E1R3aE30iR1fF8ajJWalyOOjYcDI0VzGCoNRo8Hb4pqrQDmxg1+yZqTMYqVICit0P5BC
         MSzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lFVH4DJZ;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id 136si212653vkx.4.2019.09.26.12.36.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2019 12:36:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id b19so9675755iob.4
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2019 12:36:06 -0700 (PDT)
X-Received: by 2002:a92:9912:: with SMTP id p18mr378753ili.78.1569526565531;
 Thu, 26 Sep 2019 12:36:05 -0700 (PDT)
MIME-Version: 1.0
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com>
 <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
 <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
 <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
 <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com> <20190926160433.GD32311@linux.ibm.com>
In-Reply-To: <20190926160433.GD32311@linux.ibm.com>
From: Adam Ford <aford173@gmail.com>
Date: Thu, 26 Sep 2019 14:35:53 -0500
Message-ID: <CAHCN7xL1sFXDhKUpj04d3eDZNgLA1yGAOqwEeCxedy1Qm-JOfQ@mail.gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: Fabio Estevam <festevam@gmail.com>, Rich Felker <dalias@libc.org>, linux-ia64@vger.kernel.org, 
	Petr Mladek <pmladek@suse.com>, linux-sh@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Heiko Carstens <heiko.carstens@de.ibm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Max Filippov <jcmvbkbc@gmail.com>, 
	Guo Ren <guoren@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org, 
	Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org, linux-c6x-dev@linux-c6x.org, 
	Yoshinori Sato <ysato@users.sourceforge.jp>, Richard Weinberger <richard@nod.at>, x86@kernel.org, 
	Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Mark Salter <msalter@redhat.com>, 
	Dennis Zhou <dennis@kernel.org>, Matt Turner <mattst88@gmail.com>, 
	linux-snps-arc@lists.infradead.org, uclinux-h8-devel@lists.sourceforge.jp, 
	devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	linux-um@lists.infradead.org, 
	The etnaviv authors <etnaviv@lists.freedesktop.org>, linux-m68k@lists.linux-m68k.org, 
	Rob Herring <robh+dt@kernel.org>, Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org, 
	Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>, 
	arm-soc <linux-arm-kernel@lists.infradead.org>, Michal Simek <monstr@monstr.eu>, 
	Tony Luck <tony.luck@intel.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, USB list <linux-usb@vger.kernel.org>, 
	linux-mips@vger.kernel.org, Paul Burton <paul.burton@mips.com>, 
	Vineet Gupta <vgupta@synopsys.com>, linux-alpha@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, linuxppc-dev@lists.ozlabs.org, 
	"David S. Miller" <davem@davemloft.net>, openrisc@lists.librecores.org, 
	Chris Healy <cphealy@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aford173@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=lFVH4DJZ;       spf=pass
 (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d41
 as permitted sender) smtp.mailfrom=aford173@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Sep 26, 2019 at 11:04 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
>
> Hi,
>
> On Thu, Sep 26, 2019 at 08:09:52AM -0500, Adam Ford wrote:
> > On Wed, Sep 25, 2019 at 10:17 AM Fabio Estevam <festevam@gmail.com> wrote:
> > >
> > > On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:
> > >
> > > > I tried cma=256M and noticed the cma dump at the beginning didn't
> > > > change.  Do we need to setup a reserved-memory node like
> > > > imx6ul-ccimx6ulsom.dtsi did?
> > >
> > > I don't think so.
> > >
> > > Were you able to identify what was the exact commit that caused such regression?
> >
> > I was able to narrow it down the 92d12f9544b7 ("memblock: refactor
> > internal allocation functions") that caused the regression with
> > Etnaviv.
>
>
> Can you please test with this change:
>

That appears to have fixed my issue.  I am not sure what the impact
is, but is this a safe option?


adam

> diff --git a/mm/memblock.c b/mm/memblock.c
> index 7d4f61a..1f5a0eb 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
>                 align = SMP_CACHE_BYTES;
>         }
>
> -       if (end > memblock.current_limit)
> -               end = memblock.current_limit;
> -
>  again:
>         found = memblock_find_in_range_node(size, align, start, end, nid,
>                                             flags);
>
> > I also noticed that if I create a reserved memory node as was done one
> > imx6ul-ccimx6ulsom.dtsi the 3D seems to work again, but without it, I
> > was getting errors regardless of the 'cma=256M' or not.
> > I don't have a problem using the reserved memory, but I guess I am not
> > sure what the amount should be.  I know for the video decoding 1080p,
> > I have historically used cma=128M, but with the 3D also needing some
> > memory allocation, is that enough or should I use 256M?
> >
> > adam
>
> --
> Sincerely yours,
> Mike.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHCN7xL1sFXDhKUpj04d3eDZNgLA1yGAOqwEeCxedy1Qm-JOfQ%40mail.gmail.com.
