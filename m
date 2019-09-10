Return-Path: <kasan-dev+bncBAABBZ7A3XVQKGQEZGAVLJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id DFA77AE73D
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 11:44:08 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id b187sf531180oii.23
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2019 02:44:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568108647; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECFlhN7TahgGmVSdnGLqj26KybYPq33pWPkczEPhF16lBYkVkSlTWrxaDUOAQQG5Hv
         dhK7hccPK9jEJ7q7b2H6W/W5H8g0vJRpehagT3PawL4bhqma60hoDL/eg1GH+Blqtf8h
         HyGwKA6fxAiI5WIhXlgTtgU479/CGCuQPbizR4nta19yVjkEHP0AnpQK79j1beEB/Ft7
         mDQVkTvKkvcLcbJN85x/3JKgV7CiVX9bAix6KTu19C5tqqYurUHW/hL5Eyhz3C5+fzMr
         MTbnRdEavaibWdtavmuyh87mXGUuJCqyt+7RKDgpGPwrkZsJF55uM9d5cr2GIXKld4wG
         y02g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Aspna8G58ugD7OYZW6dvsotd73VSfaWLavYS2rPILBc=;
        b=eZ67bQ+wAatcrlRMrrgtxV9FjhPdyH1XEeY/1b+aQVSVvQHZ05xMrMMqSfh7jnLH5i
         z1s6lQUY24UesXBiLlBbT56OSOlRHJhtZ4/OIQhDY6Lr0YDt6UtQzH32uNW2d4VmRZDU
         KBonqrELuPFo57RSYvOg8JFVtRPabFrZufyhvuSbf3ZcsAm9AKubTq0aCGhCtAGEM3Au
         Bqa6NwVG+tpgx316zDNSvn0ZR6xruuhSXdTXkgfNdI8nGLZpoa/jh+dQRkImNFMEs0pj
         bGD/MsmDzHqxF1+wd7Tfdx7DupSJmHKCodBQwWQuiUrGTnj9lg0ksidl7rxhWy6O44/E
         nlDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aspna8G58ugD7OYZW6dvsotd73VSfaWLavYS2rPILBc=;
        b=b4d8z141I1POfJrA62lcHDz+elBknx9nJsU6kKFfLzsQkW9KlEPbuThh9WxOtErQVW
         kydOBjmLDgGQRZWLna9wPDj3tGh4MfBVMePqSY46kDb+S8OGtgNcpqC8yaF4B+Czcwdf
         jvJANSRfBq6X1GcxOOtGJ3QlU/ZpI9JYhQxNEL+lP64B7j7yt/Nm+/DaNJT2Bao+84nh
         6v3JeGIqY6+xnNBW9qoRrnfWxOnuDHHWsLDqOdZlkbBnQgi3q4wasYUkbo52xDVmoJwl
         FjPb7Hd5n+V3y/zKPifOi8s7FMeVWb0GZPmhs5FMBYo0gDqo1fz16JyRFmyJreMyjkBh
         s8Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aspna8G58ugD7OYZW6dvsotd73VSfaWLavYS2rPILBc=;
        b=Ck+5H00DLf6JHZSXaIqPiKErtx4cxzIJsJuOElZsaM2hyhlD7nORyPy2QTtS3jvDZA
         KJ61a0YBDHWrgybg9bKFlekFy6NiirJEy91KYMvUAZyZall0FxnjAnw0xnEvVF8jEGym
         X5Tu5qXXjDWFlCCKc7aT25hCx4l9tsimTFZDaizC0c/6C81E7UWihH+joHLC65JBuWDf
         DRHBH/15qTVDqCvSJGIrSsaAVs14NlOwJyDWBU2jYz7XEnj6Phgq/LLgW81CXx6NULWI
         /FKStvlY6aG9wbM+v2XxU7SxeC17TpABCAdzrDNyXNu8rya9mLJ1L7W3MctfeUUf4Kh0
         +f4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV0VmdOufngpDyGFk9JV3FTgBNIcRpNpPhbBd222Y6w1ONwyr05
	b2mFH+nPYRSmcru/8P2b248=
X-Google-Smtp-Source: APXvYqy4XbYGJEDOxKpXcg+Q1p72mk0UM0kE7bAcO8JCTlxlXHUgdDVP/AZZMh9cvLoZaajmtwvL3w==
X-Received: by 2002:a05:6830:149:: with SMTP id j9mr25732447otp.83.1568108647519;
        Tue, 10 Sep 2019 02:44:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:36c:: with SMTP id 99ls3078132otv.3.gmail; Tue, 10 Sep
 2019 02:44:07 -0700 (PDT)
X-Received: by 2002:a05:6830:1687:: with SMTP id k7mr5838311otr.258.1568108647249;
        Tue, 10 Sep 2019 02:44:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568108647; cv=none;
        d=google.com; s=arc-20160816;
        b=tcTDGjBHi4nfb8OCC9kNEPFSyNsEDW+4SiTDDzxVPmoY25iE/C9E2kXxFFGKFgb9DL
         DZumTveco91LLJ/513ftqeafrFvWip1Po24FDFOdxu3J06FcSPoYBc3j2Ro0vtMPtWWO
         i3WnJUMzj8U5/jqGo5S1vOOwjjXz15au9k4rrZOEuq0tmjx6m3qeAQa4d395tZb1dUjo
         SeHvxBH16XJ2JWRnzwpchIwXCFSRJab+D36V4c/T1yUSgVcCjmVAFwxp7eMb5P7X4mD5
         FyKalObF5tUdepqUo86Hhp9zf2mIpJGm4fzRwfY0FL8LyHASimCobEa4pnwEVxQoxTrX
         8XtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=GVqXqK+To+HnYhWL7Xd++TWKNLkn2xHveC9/Z0dPmjA=;
        b=FC5AMnW4XkKaenyn5HEzGznFUaFY8VmHUn/+Gjkn24M1tCm/Ih3EJV8H7qbw4RWxA7
         H/mn/HGUVwtiA9Rkt1E2xlFj0Mr7nX4g1lYiqZiStVsymOJjOB2ZoYPrCfq5Btb4r4J9
         iRWlLaCa5ABO6Dvjkd11x20tw1VFD2GcdhJXwH6O5nRfRBW4Ebu3cnAFvuwCtx1lhuIb
         1B/z1NimUMBn9XXuDYKIuj+t+4vQCwwj2thfDZAUJqsh35l/cnSVbo7GJQVhpMph3tS7
         hM/clhEzxKDqAHhhZAgW1HS7AxCyLw/LGN7mq/CEh944swuvi3YlxFcYpXaJGPHjjsDz
         EBkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id w8si442109otb.5.2019.09.10.02.44.06
        for <kasan-dev@googlegroups.com>;
        Tue, 10 Sep 2019 02:44:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 7db3989441fd4168b9615b951f209fdb-20190910
X-UUID: 7db3989441fd4168b9615b951f209fdb-20190910
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1966950674; Tue, 10 Sep 2019 17:44:03 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 10 Sep 2019 17:43:58 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 10 Sep 2019 17:43:58 +0800
Message-ID: <1568108638.24886.7.camel@mtksdccf07>
Subject: Re: [PATCH v2 1/2] mm/page_ext: support to record the last stack of
 page
From: Walter Wu <walter-zh.wu@mediatek.com>
To: "Kirill A. Shutemov" <kirill@shutemov.name>
CC: David Hildenbrand <david@redhat.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>, Martin Schwidefsky
	<schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>, Andrey Konovalov
	<andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner
	<tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>, Qian Cai
	<cai@lca.pw>, <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Tue, 10 Sep 2019 17:43:58 +0800
In-Reply-To: <20190910093103.4cmqk4semlhgpmle@box.shutemov.name>
References: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
	 <36b5a8e0-2783-4c0e-4fc7-78ea652ba475@redhat.com>
	 <1568077669.24886.3.camel@mtksdccf07>
	 <20190910093103.4cmqk4semlhgpmle@box.shutemov.name>
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

On Tue, 2019-09-10 at 12:31 +0300, Kirill A. Shutemov wrote:
> On Tue, Sep 10, 2019 at 09:07:49AM +0800, Walter Wu wrote:
> > On Mon, 2019-09-09 at 12:57 +0200, David Hildenbrand wrote:
> > > On 09.09.19 10:53, Walter Wu wrote:
> > > > KASAN will record last stack of page in order to help programmer
> > > > to see memory corruption caused by page.
> > > > 
> > > > What is difference between page_owner and our patch?
> > > > page_owner records alloc stack of page, but our patch is to record
> > > > last stack(it may be alloc or free stack of page).
> > > > 
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > ---
> > > >  mm/page_ext.c | 3 +++
> > > >  1 file changed, 3 insertions(+)
> > > > 
> > > > diff --git a/mm/page_ext.c b/mm/page_ext.c
> > > > index 5f5769c7db3b..7ca33dcd9ffa 100644
> > > > --- a/mm/page_ext.c
> > > > +++ b/mm/page_ext.c
> > > > @@ -65,6 +65,9 @@ static struct page_ext_operations *page_ext_ops[] = {
> > > >  #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
> > > >  	&page_idle_ops,
> > > >  #endif
> > > > +#ifdef CONFIG_KASAN
> > > > +	&page_stack_ops,
> > > > +#endif
> > > >  };
> > > >  
> > > >  static unsigned long total_usage;
> > > > 
> > > 
> > > Are you sure this patch compiles?
> > > 
> > This is patchsets, it need another patch2.
> > We have verified it by running KASAN UT on Qemu.
> 
> Any patchset must be bisectable: do not break anything in the middle of
> patchset.
> 

Thanks your reminder.
I should explain complete message at commit log.
Our patchsets is below:
https://lkml.org/lkml/2019/9/9/104
https://lkml.org/lkml/2019/9/9/123


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1568108638.24886.7.camel%40mtksdccf07.
