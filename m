Return-Path: <kasan-dev+bncBC6LHPWNU4DBBG6GST6QKGQEAXPDFWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5F1A2A93F6
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 11:19:08 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id z11sf217464oth.19
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 02:19:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604657947; cv=pass;
        d=google.com; s=arc-20160816;
        b=odK5y0kEaN4ymPTl9UFSX5CQl46BSEBfbc9dmRG+fFlebeXk42ezDe0UQM8/zBTYOJ
         fgTxyXd3SdxBiSoYjxIYP9Zz22HtW6XmuJdGegCSFEIXyIa5Nu5b80ZGeFDRj1aOcv2A
         EUafk8cfgSPhYNWJ4a4ftKQTaU105LVMp3tnTvOi6WF2ntXqCAY7oFz8Gpc0DLB61aIG
         AoSKsaLGFDFvPd867sSY4YvJ9aPe1AOYMX8cb/jJy5bN0i4MHJnFpyPy4l+s98iDvsuv
         5bvBD6EsR+nsRYvnUN0iDqai+1IsAMwymphrHd+tXGTkA5+a8fMh9OqcjBPzsGoFQxi1
         Kdkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=SEwn68gobdKUxQ3/U/UWtVKPKCoTq9aKGs/hajPTiyg=;
        b=0Ch3wVZpaByjvCaOkFzpkhpbFBy/LatY8/UvX5hJt8U4MzD6FrYIu7R8gxGElnNQ3u
         GEIxAzUSuCWdVEvKtQSoAxlwBCE1iaR0iQQ5mD0gjA7hsXhBtMS5UWLintCIw8OfOH8v
         DEs2TxIiVaiKUsBdqEyc2KptndkygAzgCSVUVBM7nVcA6ZHZ3Mi0LOJIH8qVEVQFzge/
         UTmSNRCWdwk1C4OtCh0HPA5zKKR3dPxT6Xv4k6M9ZnoL3wLpbi2XDIHn2qs7B4LwA+7A
         ZN1RMx5XsJJondyvZ6QpsIP+zdt28ecMaoGr6ulPtZmL63OvOvf6dzIkLST8t34MMHaQ
         3daQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eTkda+8e;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::144 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SEwn68gobdKUxQ3/U/UWtVKPKCoTq9aKGs/hajPTiyg=;
        b=O3rxWbbHPfgX8Q2nnRDPy/K973HTlsXpUuP8wgg2XTakxMp7VSxbqDgJn81kXwEZfG
         jzOEflbcGWZSQgDEKG59vncGtympT/IiGfbo6m9vj+OGKtD/4tE3MMhe43YM3QXepniX
         Z34oQByzy6i7MYdRkKD4UnGKe9QOqVQNAYBS755L6yaxOW/GwErgHeM5OONI/uvlYGBg
         ZfbyRrXR81LXB00w4OObQrTIBR7xsJdIx/xjRgYmsrdDxgW8wrD7LJX90Wj4fTQAY2DK
         +PkvSPufE1giCowg1PZxuvfFl56cnWRRN3R+bCTV+2H4J+4FrOd/5EhCHHLDdu4hGbwC
         2WKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SEwn68gobdKUxQ3/U/UWtVKPKCoTq9aKGs/hajPTiyg=;
        b=fGcdcOrnG6/lbo5N3koeyvViUlWQWhXhAXgJSTcxSBT839B2F2Ox9//8edO9DPvV3v
         jkQypujm+05t2MIY0iBfx0g11vV/xhMhPMbvpyEMhfHhrXviLeyM6NgSWwGL0jaxyiVn
         1oPu1Inu/7O/wF1Wkm/pKEjvopFnc2UdQm+g/T6AKGZXWF/rJ6Yke+M9lSauh6YUsnNB
         A/vTwhJdiG3BNOk2/SSDbUtBpPvXP6EGGY+QYFMFgf5engcLDynNUBSTREf3x1gtD3HB
         0kytbPpjjoti4UGRKU7XbekK6DO6/Gln0pl8uybxLFFQMugUIKreasNO5LpirOLn17XA
         8r9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SEwn68gobdKUxQ3/U/UWtVKPKCoTq9aKGs/hajPTiyg=;
        b=CivwDlwa5ZzzKHV3fOi5WEBFH/PlT9S/JxryfR/r/Mookjx7beU/zPiwKlxzT6fWaI
         8MErYNMZTTEHU2gnQbrk4QGCTkcPdH3iT41/j5dKhSVtiKebwyiokwQod/8MHq8wXyge
         v90KVAQHrq2iOV4lTuYJPbRgJjk5Z1lLxPYmVx+O+hCj+dA9Rtsdy4NdFXPDALiO/VGN
         M4RzKyJkz7ssVHdTw6NxKMGPfTkhL9LXfnHavDrltGIjyHeRDq43a5ulSnRSQSTEyEux
         gzZ/sV1PjOmgnlPiUq9N0G5Zme35k4pAQrbk6nWCIrtTisoMgS3nnI6mLVeaY43lEdI/
         Z2og==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eHe0FBNUSkZmhHEJMwU89P2gdTSg7Q+hbk5SEGppUZs7k3eyB
	HBMi11AD92rEF24wQJ5oTPI=
X-Google-Smtp-Source: ABdhPJyZfZgnTYuGmzMc/3bDUc+xSAFlHUzOn3YZNtaBbiQR4KoE4QcKr0RBYkO9yBZYl8Gyxr3bUQ==
X-Received: by 2002:aca:1c16:: with SMTP id c22mr681583oic.121.1604657947333;
        Fri, 06 Nov 2020 02:19:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls240363oie.2.gmail; Fri, 06 Nov
 2020 02:19:07 -0800 (PST)
X-Received: by 2002:aca:e187:: with SMTP id y129mr681268oig.61.1604657946999;
        Fri, 06 Nov 2020 02:19:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604657946; cv=none;
        d=google.com; s=arc-20160816;
        b=J8TOtl10oTDwybRR6RY1nfcH2i+opQyUupyFnome2AP8SftCL0l4SneqgOab9IVGwd
         ooxSSq+G9/tIfCIphhNRAnh7C8I+ZJ05wTCn5kBAeKlUHFCJbIy1KH8fxEz6QrzSbxVn
         47jFRn+dT7SDL9oxh/8o7D8CYd5twvmL3vGBzajkyBDMhnN1VCZeh/OOZ0BkZDe2ZsfH
         Y10HnI+Ff/0YLXkzkZhDB4kjX36UaA19uxp8nX9n+SLLydH++TdyY8qmi1Yzf5nA7+0w
         O67GNECf+IdacqQj5XLy5Ap6l6QO+Uo+Pzs4AHyi9t/LxIr5Uvjxqy0VDif0q8M+a7O6
         OpbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sdK5L9LlPpSjmRzKF8fKPQux7TO4MN23Bk2tcXAjg8U=;
        b=LFEBczGZv+nd0ce57fW5jUNm9SgEvDiH71JcJ0ojCSZsoTlsCzUJ5axOhPVUECysho
         IrQj/EKoTqU0S1gUmrOkmNjfF+QBROAZx0687ZmMsoiV5cIeh2nAud2khZOSQBvrOSBH
         /q8eB//A1QJ2HiY2t4If8xTO+Q76BAIaYtTqKMbQvBT/+LDlzjY25mq2o4fV7j7cXsh+
         95zi5aJS5lSMeEwVcMaM4Zvgy1FfNH0yXqD90xCVetO4WszEuf1NwJkKEor4oPppCuSS
         2ykQ5Vk8MaNfxZrp/NXRpj2aLKa0cOHCOtgj15mFu37A9L5IeSaZldo8ASQ5zbanNbxW
         K7Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=eTkda+8e;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::144 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x144.google.com (mail-il1-x144.google.com. [2607:f8b0:4864:20::144])
        by gmr-mx.google.com with ESMTPS id i23si63739otk.5.2020.11.06.02.19.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 02:19:06 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::144 as permitted sender) client-ip=2607:f8b0:4864:20::144;
Received: by mail-il1-x144.google.com with SMTP id k1so608059ilc.10
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 02:19:06 -0800 (PST)
X-Received: by 2002:a05:6e02:2cc:: with SMTP id v12mr853240ilr.115.1604657946689;
        Fri, 06 Nov 2020 02:19:06 -0800 (PST)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id m10sm752952ilg.77.2020.11.06.02.19.05
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Nov 2020 02:19:06 -0800 (PST)
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailauth.nyi.internal (Postfix) with ESMTP id 002C627C005A;
	Fri,  6 Nov 2020 05:19:00 -0500 (EST)
Received: from mailfrontend2 ([10.202.2.163])
  by compute5.internal (MEProxy); Fri, 06 Nov 2020 05:19:01 -0500
X-ME-Sender: <xms:FCOlX5y8HjuaoyAkq7jwIDTU1Sl_wV8SH2oO1vsYNFXpxLzwy4MYow>
    <xme:FCOlX5SSUDneF7LCh2UOnRwxLQSL5RiYNkjzYwYiivcHaNuYrKjPiCmznGAUuz1PH
    mVgr1KttBK_cUfv0Q>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedujedruddtledgudehucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhepvdelieegudfggeevjefhjeevueevieetjeeikedvgfejfeduheefhffggedv
    geejnecukfhppedufedurddutdejrddugeejrdduvdeinecuvehluhhsthgvrhfuihiivg
    eptdenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhh
    phgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunh
    drfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgv
X-ME-Proxy: <xmx:FCOlXzW5zzpl33uxIFt6V_BfqKtAnVQP1Y1Uwa8p5BWOrO4kUfIYaA>
    <xmx:FCOlX7jllqIUs289gjOnJ0K0a3YpZutrl6BgFqBdNpk0lcbsyNg8dw>
    <xmx:FCOlX7Djhl6IXzlhIkktPtv6yVVIZfUNGsdr_M3uxqAHAAmq1bUG_w>
    <xmx:FCOlX_1Y45FrP0a2wr7Lsr7TwGfc_ExHvlLs8trJHwxVlpUJP8bvMVpq9hQ>
Received: from localhost (unknown [131.107.147.126])
	by mail.messagingengine.com (Postfix) with ESMTPA id D88B33060060;
	Fri,  6 Nov 2020 05:18:59 -0500 (EST)
Date: Fri, 6 Nov 2020 18:18:56 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com,
	Ingo Molnar <mingo@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>
Subject: Re: [PATCH kcsan 3/3] kcsan: Fix encoding masks and regain address
 bit
Message-ID: <20201106101856.GC3025@boqun-archlinux>
References: <20201105220302.GA15733@paulmck-ThinkPad-P72>
 <20201105220324.15808-3-paulmck@kernel.org>
 <20201106012335.GA3025@boqun-archlinux>
 <CANpmjNNj1cc2LUrLdbYy1QkVv80HUPztPXmLfscYB=pU_nffaA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNj1cc2LUrLdbYy1QkVv80HUPztPXmLfscYB=pU_nffaA@mail.gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=eTkda+8e;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::144
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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

On Fri, Nov 06, 2020 at 10:03:21AM +0100, Marco Elver wrote:
> On Fri, 6 Nov 2020 at 02:23, Boqun Feng <boqun.feng@gmail.com> wrote:
> > Hi Marco,
> >
> > On Thu, Nov 05, 2020 at 02:03:24PM -0800, paulmck@kernel.org wrote:
> > > From: Marco Elver <elver@google.com>
> > >
> > > The watchpoint encoding masks for size and address were off-by-one bit
> > > each, with the size mask using 1 unnecessary bit and the address mask
> > > missing 1 bit. However, due to the way the size is shifted into the
> > > encoded watchpoint, we were effectively wasting and never using the
> > > extra bit.
> > >
> > > For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
> > > bit, 14 bits for the size bits, and then 49 bits left for the address.
> > > Prior to this fix we would end up with this usage:
> > >
> > >       [ write<1> | size<14> | wasted<1> | address<48> ]
> > >
> > > Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
> > > size and address respectively. The added static_assert()s verify that
> > > the masks are as expected. With the fixed version, we get the expected
> > > usage:
> > >
> > >       [ write<1> | size<14> |             address<49> ]
> > >
> > > Functionally no change is expected, since that extra address bit is
> > > insignificant for enabled architectures.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > ---
> > >  kernel/kcsan/encoding.h | 14 ++++++--------
> > >  1 file changed, 6 insertions(+), 8 deletions(-)
> > >
> > > diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> > > index 4f73db6..b50bda9 100644
> > > --- a/kernel/kcsan/encoding.h
> > > +++ b/kernel/kcsan/encoding.h
> > > @@ -37,14 +37,12 @@
> > >   */
> > >  #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
> > >
> > > -/*
> > > - * Masks to set/retrieve the encoded data.
> > > - */
> > > -#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
> > > -#define WATCHPOINT_SIZE_MASK                                                   \
> > > -     GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
> > > -#define WATCHPOINT_ADDR_MASK                                                   \
> > > -     GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
> > > +/* Bitmasks for the encoded watchpoint access information. */
> > > +#define WATCHPOINT_WRITE_MASK        BIT(BITS_PER_LONG-1)
> > > +#define WATCHPOINT_SIZE_MASK GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
> > > +#define WATCHPOINT_ADDR_MASK GENMASK(BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS, 0)
> > > +static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
> >
> > Nit:
> >
> > Since you use the static_assert(), why not define WATCHPOINT_ADDR_MASK
> > as:
> >
> > #define WATCHPOINT_ADDR_MASK (BIT(WATCHPOINT_SIZE_BITS) - 1)
> 
> This is incorrect, as the static_assert()s would have indicated. It
> should probably be (BIT(WATCHPOINT_ADDR_BITS) - 1)?
> 
> As an aside, I explicitly did *not* want to use additional arithmetic
> to generate the masks but purely rely on BIT(), and GENMASK(), as it
> would be inconsistent otherwise. The static_assert()s then sanity
> check everything without BIT+GENMASK (because I've grown slightly
> paranoid about off-by-1s here). So I'd rather not start bikeshedding
> about which way around things should go.
> 
> In general, GENMASK() is safer, because subtracting 1 to get the mask
> doesn't always work, specifically e.g. (BIT(BITS_PER_LONG) - 1) does
> not work.
> 
> > Besides, WATCHPOINT_SIZE_MASK can also be defined as:
> 
> No, sorry it cannot.
> 
> > #define WATCHPOINT_SIZE_MASK GENMASK(BITS_PER_LONG - 2, WATCHPOINT_SIZE_BITS)
> 
>    GENMASK(BITS_PER_LONG - 2, WATCHPOINT_SIZE_BITS)
> 
> is not equivalent to the current
> 
>   GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
> 
> Did you mean GENMASK(BITS_PER_LONG-2, WATCHPOINT_ADDR_BITS)? I can

You're right! Guess I should check first about what vim completes for me
;-) And I agree with you on the preference to GENMASK()

> send a v2 for this one.

Let me add an ack for that one, thanks!

Regards,
Boqun

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106101856.GC3025%40boqun-archlinux.
