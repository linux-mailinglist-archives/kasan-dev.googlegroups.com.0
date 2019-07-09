Return-Path: <kasan-dev+bncBAABBTUDSDUQKGQEQICHSCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 10C2962E51
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jul 2019 04:54:08 +0200 (CEST)
Received: by mail-yw1-xc3c.google.com with SMTP id b63sf12319995ywc.12
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 19:54:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562640846; cv=pass;
        d=google.com; s=arc-20160816;
        b=tTiMP0TqXihRLcbrs3qUJte5Oa8qoF0HgcYd6hF2EjAe1DBEuBxsDanJhLivSmcNB+
         yaArukn7yv4rWNwQYXuWodMcCLhFuQejuwMb8utV5rQowa6/qon3pR50CENS3yvV4yht
         C75Ypun18/uCaU/8sYSBB+3Dys67khRE+8u2j6eO41SehH1hgjOvWsLI83ZAxUI37ig3
         pR5yWeUFaAyipIl9nVE960nOVLgIAQE+l9iKRqRKaJZ59ll8rDycldo2MtEy1RM6PVik
         gAXaFwR0T9QsgK6PRSWys8V9LBLyqwNkquCXL6sZaoo5eLl5YLMFj4ntwvJE1wwDRJr/
         UdmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=0nWOzU4s/qEKrH2ziW8psrPhH25OxUSXOf4JoHVOmws=;
        b=1LmxGZC98DHya2JVePzxr971fdibmS9AnEaehSyoAHC7b9pcT8D9q3Bv5Be7+0ojod
         pmt8w4B8jZ4bIkmuAjuHGwrlSvOCXYETBO3yg/Bynm67LN5rx6tfTBysnh0rPJ2f1RCJ
         KSYhbkZF1yNxUtA2Ekthw79oBoR5rlMyin5IMjSMaDtJCrxbxPHyp7sF7RyjidcI8ylk
         XOsc864beGQO41xpl8BRRf4s4KPakPtsN+UpuprxClORk0FnbkRKMK4MjJWuwExd4vwq
         GibTUSWUAZrk503DuiAk/wUHpnL4x56hRAE3fr7KJRPalbpGTZ7OWQ45Dawr7GFXuEHx
         oxWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nWOzU4s/qEKrH2ziW8psrPhH25OxUSXOf4JoHVOmws=;
        b=OfSY9pck+jWSTHbu1wOsy+Gio76kpzsURp1Bq8bf7LzGScTRCRub1qB66mKNfhEJvL
         TsrFmcKkM435qmIG92fjXRwCAkn4gs0l5Mxu/mJLgcIpJjltF+QoS9y+IMWtBLUfqrBR
         WxrkbKejNfX3jHGH3BNKuXJIzJE2pb9325/B8GcsoG0T3UTn3A5UTDNRry2zwnBQbTvt
         zQ3GyEJ+c3szsUxvs2zHoMQ2jMA1JDUo6yGZuIeEr6g/8bi0JkKxKxXUmOpQCDQ7jQC3
         Vuq4gXOClnMokFJP7CWvzUQVM1VkVC0ybWos1ndg2VgrQXsK85h25zskVgu5SDLYbBKq
         xh+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nWOzU4s/qEKrH2ziW8psrPhH25OxUSXOf4JoHVOmws=;
        b=fNJhdlYGCsDMY8qzy+lG0Wd9bnZIEVG7LI8ar9s8B37IsqtCX3eRhX03E1AAhlplpL
         dnBXOMTWOhl7eiIUJqA1/2fZQDQuANR2XsPE3846lUzUauZl1tfsLvhvxpjpvriawRgn
         yJubE49FiFi6pMQ8a56jtGmus1QS8utFbksnrLnGbc6LsjaNDGNXW3Ll9a1EpbDgIjPF
         7tCmvKOHG09S1AMEXN1JVdi4wCL4i53WWkOXHPphQVo/E7x4ZUifvKn7db3ZqwRdkBvs
         1CuI0pb1li641hof7Vg/akuSksZI4eF2F8MXycPVNGQvODoyqbBj1ctgS1URrNN4nYRm
         1OdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXzyV1i1TAKuq3KLiVHpDGYY2mk0Mpgg3EW+0dRC/ue7ML7plA3
	cdCiMGaR1AHqb9lxgfiphJ0=
X-Google-Smtp-Source: APXvYqwVFuChnFgkYstWAOzeuWEm+Kfky6Ie9SWxHmc6p723QXgZaDi5eviNCy0XeJe9m6mm/80bSg==
X-Received: by 2002:a25:e08:: with SMTP id 8mr13237528ybo.177.1562640846558;
        Mon, 08 Jul 2019 19:54:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:700a:: with SMTP id l10ls1402593ybc.3.gmail; Mon, 08 Jul
 2019 19:54:06 -0700 (PDT)
X-Received: by 2002:a25:bd0f:: with SMTP id f15mr10786325ybk.151.1562640846230;
        Mon, 08 Jul 2019 19:54:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562640846; cv=none;
        d=google.com; s=arc-20160816;
        b=i7tGl1WMqE8YtzGLw9dEUcoQQcy6maCfiUqdBK3o+k6tmPlfmGDkww+L3NYbZ/DheQ
         jGtIHTAckg1WfBC7M4UdS5078tU1YdykXYgXK9u6RNOva19YGjjUTHrY3WYigM6CA2fR
         iGQjhpyNOU5OZSN3ZfR/J8dbJ+rUPsgU4SSwszgYEG16CQ0i9f/8KWO+ub17F5n2PMFl
         G2nLOLRsrLFZaZlP4ZQYvDTyDvq6HO2E50fEuPVBvppix7nc/hFbMLHauREB6EqTwtKf
         XQtq2KTLiiKT87bj7+FyzioG96TUSgIxoVxxynFBpNKA90hfCA14KKKlXJHyl3YYpfpj
         gzaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=1YXVxdVlbjP61OVZVlRbACV4q7st4JmnvP5JYUmOe1Q=;
        b=ZFQwoDtp/mvJQTJ5HRh+oSx+4660i715uHw3oyM2iCeBi0VolCGMOPYAZuNAczvZYq
         Uf2c70/5njcoViq73yBXRFQmHs/Y/USrm8VJXvhK8rLXY3p1tmsiipiWp6HvZAb0RM9A
         eHIuPWCfpKKPMf34PxOb2NntR3sqc9E0N85f4znW6wTBuw2vP4/ULPutqDBKRU18MTy1
         HZ9U+pZ5F0494emyYaC7rYvE+/uH5RIK+U33awEkECgil5YdgTU+0kzG7csTjJpzYi8l
         ySJ2JlvoHNbM5ruxIqVb3QUAT7RdLDQwUBwFJEXuHA6m6fMD+ttUit1K/N2DaTACWCqY
         UJgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id d16si1154516ywg.5.2019.07.08.19.54.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 19:54:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: e54a938dbb3841b2821206c79fe148af-20190709
X-UUID: e54a938dbb3841b2821206c79fe148af-20190709
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 1677781939; Tue, 09 Jul 2019 10:53:54 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 9 Jul 2019 10:53:52 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 9 Jul 2019 10:53:52 +0800
Message-ID: <1562640832.9077.32.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
	<dvyukov@google.com>
CC: Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, "Matthias Brugger"
	<matthias.bgg@gmail.com>, Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd
 Bergmann <arnd@arndb.de>, Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov
	<andreyknvl@google.com>, "Jason A . Donenfeld" <Jason@zx2c4.com>, Miles Chen
	<miles.chen@mediatek.com>, kasan-dev <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Tue, 9 Jul 2019 10:53:52 +0800
In-Reply-To: <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
	 <1560447999.15814.15.camel@mtksdccf07>
	 <1560479520.15814.34.camel@mtksdccf07>
	 <1560744017.15814.49.camel@mtksdccf07>
	 <CACT4Y+Y3uS59rXf92ByQuFK_G4v0H8NNnCY1tCbr4V+PaZF3ag@mail.gmail.com>
	 <1560774735.15814.54.camel@mtksdccf07>
	 <1561974995.18866.1.camel@mtksdccf07>
	 <CACT4Y+aMXTBE0uVkeZz+MuPx3X1nESSBncgkScWvAkciAxP1RA@mail.gmail.com>
	 <ebc99ee1-716b-0b18-66ab-4e93de02ce50@virtuozzo.com>
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

On Mon, 2019-07-08 at 19:33 +0300, Andrey Ryabinin wrote:
> 
> On 7/5/19 4:34 PM, Dmitry Vyukov wrote:
> > On Mon, Jul 1, 2019 at 11:56 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >>>>>>>>> This patch adds memory corruption identification at bug report for
> >>>>>>>>> software tag-based mode, the report show whether it is "use-after-free"
> >>>>>>>>> or "out-of-bound" error instead of "invalid-access" error.This will make
> >>>>>>>>> it easier for programmers to see the memory corruption problem.
> >>>>>>>>>
> >>>>>>>>> Now we extend the quarantine to support both generic and tag-based kasan.
> >>>>>>>>> For tag-based kasan, the quarantine stores only freed object information
> >>>>>>>>> to check if an object is freed recently. When tag-based kasan reports an
> >>>>>>>>> error, we can check if the tagged addr is in the quarantine and make a
> >>>>>>>>> good guess if the object is more like "use-after-free" or "out-of-bound".
> >>>>>>>>>
> >>>>>>>>
> >>>>>>>>
> >>>>>>>> We already have all the information and don't need the quarantine to make such guess.
> >>>>>>>> Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> >>>>>>>> otherwise it's use-after-free.
> >>>>>>>>
> >>>>>>>> In pseudo-code it's something like this:
> >>>>>>>>
> >>>>>>>> u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> >>>>>>>>
> >>>>>>>> if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> >>>>>>>>   // out-of-bounds
> >>>>>>>> else
> >>>>>>>>   // use-after-free
> >>>>>>>
> >>>>>>> Thanks your explanation.
> >>>>>>> I see, we can use it to decide corruption type.
> >>>>>>> But some use-after-free issues, it may not have accurate free-backtrace.
> >>>>>>> Unfortunately in that situation, free-backtrace is the most important.
> >>>>>>> please see below example
> >>>>>>>
> >>>>>>> In generic KASAN, it gets accurate free-backrace(ptr1).
> >>>>>>> In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
> >>>>>>> programmer misjudge, so they may not believe tag-based KASAN.
> >>>>>>> So We provide this patch, we hope tag-based KASAN bug report is the same
> >>>>>>> accurate with generic KASAN.
> >>>>>>>
> >>>>>>> ---
> >>>>>>>     ptr1 = kmalloc(size, GFP_KERNEL);
> >>>>>>>     ptr1_free(ptr1);
> >>>>>>>
> >>>>>>>     ptr2 = kmalloc(size, GFP_KERNEL);
> >>>>>>>     ptr2_free(ptr2);
> >>>>>>>
> >>>>>>>     ptr1[size] = 'x';  //corruption here
> >>>>>>>
> >>>>>>>
> >>>>>>> static noinline void ptr1_free(char* ptr)
> >>>>>>> {
> >>>>>>>     kfree(ptr);
> >>>>>>> }
> >>>>>>> static noinline void ptr2_free(char* ptr)
> >>>>>>> {
> >>>>>>>     kfree(ptr);
> >>>>>>> }
> >>>>>>> ---
> >>>>>>>
> >>>>>> We think of another question about deciding by that shadow of the first
> >>>>>> byte.
> >>>>>> In tag-based KASAN, it is immediately released after calling kfree(), so
> >>>>>> the slub is easy to be used by another pointer, then it will change
> >>>>>> shadow memory to the tag of new pointer, it will not be the
> >>>>>> KASAN_TAG_INVALID, so there are many false negative cases, especially in
> >>>>>> small size allocation.
> >>>>>>
> >>>>>> Our patch is to solve those problems. so please consider it, thanks.
> >>>>>>
> >>>>> Hi, Andrey and Dmitry,
> >>>>>
> >>>>> I am sorry to bother you.
> >>>>> Would you tell me what you think about this patch?
> >>>>> We want to use tag-based KASAN, so we hope its bug report is clear and
> >>>>> correct as generic KASAN.
> >>>>>
> >>>>> Thanks your review.
> >>>>> Walter
> >>>>
> >>>> Hi Walter,
> >>>>
> >>>> I will probably be busy till the next week. Sorry for delays.
> >>>
> >>> It's ok. Thanks your kindly help.
> >>> I hope I can contribute to tag-based KASAN. It is a very important tool
> >>> for us.
> >>
> >> Hi, Dmitry,
> >>
> >> Would you have free time to discuss this patch together?
> >> Thanks.
> > 
> > Sorry for delays. I am overwhelm by some urgent work. I afraid to
> > promise any dates because the next week I am on a conference, then
> > again a backlog and an intern starting...
> > 
> > Andrey, do you still have concerns re this patch? This change allows
> > to print the free stack.
> 
> I 'm not sure that quarantine is a best way to do that. Quarantine is made to delay freeing, but we don't that here.
> If we want to remember more free stacks wouldn't be easier simply to remember more stacks in object itself?
> Same for previously used tags for better use-after-free identification.
> 

Hi Andrey,

We ever tried to use object itself to determine use-after-free
identification, but tag-based KASAN immediately released the pointer
after call kfree(), the original object will be used by another
pointer, if we use object itself to determine use-after-free issue, then
it has many false negative cases. so we create a lite quarantine(ring
buffers) to record recent free stacks in order to avoid those false
negative situations.

We hope to have one solution to cover all cases and be accurate. Our
patch is configurable feature option, it can provide some programmers to
easy see the tag-based KASAN report.


> > We also have a quarantine for hwasan in user-space. Though it works a
> > bit differently then the normal asan quarantine. We keep a per-thread
> > fixed-size ring-buffer of recent allocations:
> > https://github.com/llvm-mirror/compiler-rt/blob/master/lib/hwasan/hwasan_report.cpp#L274-L284
> > and scan these ring buffers during reports.
> > 

Thanks your information, it looks like the same idea with our patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1562640832.9077.32.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
