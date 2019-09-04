Return-Path: <kasan-dev+bncBAABBIMSX7VQKGQEQANODKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 40D49A8594
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 16:24:34 +0200 (CEST)
Received: by mail-yw1-xc3e.google.com with SMTP id e12sf16113973ywe.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 07:24:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567607073; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmo1EnhUvPM+p9kYA9Wjxlmb3Znt8Q1qLDnWe9xh9f8tgHwZ+EEBNjTF/jQG22g9ux
         tJ+KVWZybDrNEnjA/dE/pRHt+YO/QMRwlDZvlKnx5SEQqJ7KTbi8+dtKEsKh54+vnZhi
         a7vVSqOg+k4BggJi3IRfTU+dQEzx/Uq67uviBv9EPsqdT4nrNZGXu8THAmo4E5BT95T3
         BaSUxsxuxT30p7P1BTjAyezyOOIKtt91MYI3oRNcV90lEKIwm74uAemhukM8zGZsYGjm
         T2B4FPadW+2i4/qcHE4mCzjfucrHryg4R/cHYWm2/VhGRPMl/zj3ax57W6+Fo7MRygKi
         6Cmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=cA9Rm9m1Y+zd5xYwUJtqmQArXST4B03uz1uQhKuiMt4=;
        b=cXjymId6K7Cj3J8Mhu0OSahxk5z31t3i0Rgz+ifdKS1IwxGRP9a5fNvrCyQgUoaoFq
         6yo13hpwUzOU/Dz6n45XrcBJ06SE5xU65ryQeuN+e2Thd+ZlnlFr1YHS2eLWj5SjeAb0
         Za62+1cH8kGqvDqOGbWbuf/pAr/6v1/xrrR358tkyZz8rb0JZWwESziuhQtZxm+jR8PC
         ROPLFQiQEZk4qK0xuVkZm7mnz+DHYhTvJUmIEC1wgBUfJpP/A51FntvNP1hUVP2qHS94
         1Y1FzgoN1yGMUuu1k9otI0SchpzhKLejr5UIjTogAdch4qbAlj7GQDuksdLyjfPk2vDX
         3MCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cA9Rm9m1Y+zd5xYwUJtqmQArXST4B03uz1uQhKuiMt4=;
        b=Xl1pYs1xa9me8kv90EKZPgod4E6/HZwlC258R9ORbzqtgO4yvEJpKnfHF0cdm77Rqu
         aIwyHJC34ZPNGS/kUFt6j491EMmBeujToPFiOzO1eCW+gBhu/c8zN/8rudykDhnWQbPk
         pG35pcqDvLBTKnfdyuj2KiiMDRsUDZUd9oPWm8vT8c8BZlg3vBORMViByghdp6D5ip57
         G8JzIXJxjGdHsqA/emp4wz6e/NabEzLGKW82yZBKPeiKx5xLF/QchB8yXE7HVwDP5IDF
         YknlH8petuWgWI0bhjR0Ep2dBCKZ5y6qFPOt44cQ9xjKGbJroMEq7x6zjNjuvWXPd6vV
         4MuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cA9Rm9m1Y+zd5xYwUJtqmQArXST4B03uz1uQhKuiMt4=;
        b=M4tVqtrCjosgilAZ+uJ8VImod9/ll6MYT7iyISzhZgJhISE4gTDRSeAu8bzsz9BtrE
         yDRPR1aXrUvYNgqzaRI4mjxqBt5NEjxWzyRa1vNthknFhY1gPcfheZne8CbjEJevmxJ2
         iKnd0HEN0DKCiY9nsvyfnEAAQLX/0VShxMnZSmpvq1vrE0HnRxS5pmCJxmO/JyhsewMT
         IegtdsJBjXrtHKzCyAWE0prsWwjSXovSvegX4iFMglWSZD5zqmaIj6z55HmDL30OWv/1
         LCZ7ukWzjiV3ol3fpAUha2hN0bEaOftopLeHhsI84bX4e3j2rlKNHNJn37NB8TvUtWKo
         VvsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV6FMeOQCRMwjWnY9VYugahgpfwdqblBAzxpj06CfZWI++jJFPi
	b0iFtAfAU7o4gMqKP8mol9I=
X-Google-Smtp-Source: APXvYqyzbBGweCQOp6rfQIf4NdqIAkf9+j0HoxTzYQMKxXAbvgm/yj/U56Y7fPs18VOV8HT4XinG5w==
X-Received: by 2002:a25:86ca:: with SMTP id y10mr28012066ybm.39.1567607073223;
        Wed, 04 Sep 2019 07:24:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:34c5:: with SMTP id b188ls1904150ywa.2.gmail; Wed, 04
 Sep 2019 07:24:33 -0700 (PDT)
X-Received: by 2002:a81:47d5:: with SMTP id u204mr29937702ywa.145.1567607073004;
        Wed, 04 Sep 2019 07:24:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567607073; cv=none;
        d=google.com; s=arc-20160816;
        b=WU3aikobccefvxpbzWOFzWnRDUQSfj0b36UbSzPDOIiDG/na3lSyUDF0awdKmmIppo
         ZwjsUOqu30HYthTr2xlARl/gSXp3wGSY0OmzMCBrJEaayqTdEe+LM0FRDFeVQMQ8Q9mk
         8z6izU4jV/Zj2W0f201nUrra2Io/tj+VDVjHfE1j7YBdlBDb0y9BBuAZhjLLWrHUsCPQ
         twREd5g2RxhF+WYRDAz8+Rj/pJO/IzmOzKpXpB0vDXgNALTcIKW/ESnwjUgGkymThvQE
         xPOsRy2qxg9Yk+tXqyuYeNfOEU9mEaYU9LcBkQOG3kH/jStUQSUWozVl/QSz2l+tpJ6f
         OLZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=3YK9g5CDB3lN/lNJ8sZoWbSZo72m0pwq+e0rl38A3Xo=;
        b=l7m8mSD6nL+qjUUGIFaeT8JvrVKGiSxa4qxa1JefUU/X4Av1llfcJSYGPEN+lRv3V8
         gm5E92BX5zPnqwOQHFoPEzBvjU0mjixDIBGxdU+BfEBTdvjPw6nOUB+q4oqrekmpZJy6
         sp8YnqVVMELur/GF6oQlr+riN8DQpQ4tKw0HSDBQrPqHWRPz7hF1llpoOdqi1aKNLQRP
         wPSkebxYXJ6mWHIZgYTsZNZx7HpccRxQRLnwcVouwhQuVt1YO1EG/rR1KoMIXyV7Rxjo
         j8BIifbdHWx0wCGabDPyqAHlOK2l9GMEyBSg6Lu3wSnX0mAFloshOf3H16mhQZOdC7Mn
         ziuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id j5si1310534yba.2.2019.09.04.07.24.31
        for <kasan-dev@googlegroups.com>;
        Wed, 04 Sep 2019 07:24:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: fe267de637764d1c8c1e2ed01f75eca6-20190904
X-UUID: fe267de637764d1c8c1e2ed01f75eca6-20190904
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1751036984; Wed, 04 Sep 2019 22:24:26 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 4 Sep 2019 22:24:23 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 4 Sep 2019 22:24:22 +0800
Message-ID: <1567607063.32522.24.camel@mtksdccf07>
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Wed, 4 Sep 2019 22:24:23 +0800
In-Reply-To: <7998e8f1-e5e2-da84-ea1f-33e696015dce@suse.cz>
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
	 <401064ae-279d-bef3-a8d5-0fe155d0886d@suse.cz>
	 <1567605965.32522.14.camel@mtksdccf07>
	 <7998e8f1-e5e2-da84-ea1f-33e696015dce@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Wed, 2019-09-04 at 16:13 +0200, Vlastimil Babka wrote:
> On 9/4/19 4:06 PM, Walter Wu wrote:
> > On Wed, 2019-09-04 at 14:49 +0200, Vlastimil Babka wrote:
> >> On 9/4/19 8:51 AM, Walter Wu wrote:
> >> > This patch is KASAN report adds the alloc/free stacks for page allocator
> >> > in order to help programmer to see memory corruption caused by page.
> >> > 
> >> > By default, KASAN doesn't record alloc/free stack for page allocator.
> >> > It is difficult to fix up page use-after-free issue.
> >> > 
> >> > This feature depends on page owner to record the last stack of pages.
> >> > It is very helpful for solving the page use-after-free or out-of-bound.
> >> > 
> >> > KASAN report will show the last stack of page, it may be:
> >> > a) If page is in-use state, then it prints alloc stack.
> >> >    It is useful to fix up page out-of-bound issue.
> >> 
> >> I expect this will conflict both in syntax and semantics with my series [1] that
> >> adds the freeing stack to page_owner when used together with debug_pagealloc,
> >> and it's now in mmotm. Glad others see the need as well :) Perhaps you could
> >> review the series, see if it fulfils your usecase (AFAICS the series should be a
> >> superset, by storing both stacks at once), and perhaps either make KASAN enable
> >> debug_pagealloc, or turn KASAN into an alternative enabler of the functionality
> >> there?
> >> 
> >> Thanks, Vlastimil
> >> 
> >> [1] https://lore.kernel.org/linux-mm/20190820131828.22684-1-vbabka@suse.cz/t/#u
> >> 
> > Thanks your information.
> > We focus on the smartphone, so it doesn't enable
> > CONFIG_TRANSPARENT_HUGEPAGE, Is it invalid for our usecase?
> 
> The THP fix is not required for the rest of the series, it was even merged to
> mainline separately.
> 
> > And It looks like something is different, because we only need last
> > stack of page, so it can decrease memory overhead.
> 
> That would save you depot_stack_handle_t (which is u32) per page. I guess that's
> nothing compared to KASAN overhead?
> 
If we can use less memory, we can achieve what we want. Why not?

Thanks.
Walter


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1567607063.32522.24.camel%40mtksdccf07.
