Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX5XU36AKGQED26XN6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DC81290607
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 15:10:57 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id k7sf2399064ybm.13
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 06:10:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602853856; cv=pass;
        d=google.com; s=arc-20160816;
        b=0w0XUfmI53pL3HV0Q5HcIHEf7cKV66w+42yQ2VAgCUgCAObP4f3kxQ5dTPN0CO6qLS
         Fr5KQKXeIPpVhfDJ7+859t1aO2yLeSuT22ZBUX44iGTYV/UyNyi/hjiVSCtwxTn+kuVJ
         zPbAk2l9uO7AuPimX9fb7swpt7Y+VcKEq+FrcufN8a5oHjg3zEbqPg1chlUHs87sy+ei
         g2RdPIkKWv/OXa5aaRdDHw4XU1NIhIYkPMAUeBHXiz6N7/KHdYalW072QTvQ27AKEPzj
         h5BoVKDtZUkZrWeLxDwmK7dFxcZvbdHlJpihKDik8KkUiHMborPilTavGPAn5lYpBABh
         OZNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4siNvCEQ6PfvM9ibFKBd5WAVR6IKgELBOteImyFfePU=;
        b=q+IMAqXVhabzvyvKStDnA5+b+0vrkjHA6Iwb4KMQexqWXexsHC1MSMWKIFs507VsX+
         hsa90qtAucOWBOJnvEm75dgWyASdC86LSLC/tTUUNpG/CedYA6HRiGElR81Mr7HgZWJa
         1TBYYRccAxSgcDniuqBkt7+a2PPZFsBo3zpHdaJi7YIVrbxNVRzIogOdPsOdeIwczwnr
         PZXKMAFMk16/PF4isTGZ83cF14q3mDrzB11MjAPXNqVRl7EczOaiGl1qc/yl2CG7BYGZ
         1qtoO+GUAmOxAg42wCv5NGH/uPCVU5GwetaqRi8SPKYfUcNFIQa9VhPHN60FfhpV97QQ
         w6ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uEOyU0Jw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4siNvCEQ6PfvM9ibFKBd5WAVR6IKgELBOteImyFfePU=;
        b=gQKmlRzbzHEJsjuiZ80vZtp1BnMPQOVp6KlRXNU+n22++UFPbLUWmRqLaaBOdOY23o
         ykd9TdpgQ4zOU8aZPXyZSnCC9V+WGQRhLDmRXXNyKM/5pvLUA06AFAAeh6PEV2vwkkMg
         9cSIw0rMXJq3e8reTuI0zDyPTWiPSD4AhU1H5AyjbFn57XifGvZakMsEDZ6akqVtfVz6
         pkBv/jtwbiU++qSyoRi5Pyiiev9jVm3uw7lTNgQJiZ+xV3onmyjGMVzKKEs2UZrq2GzO
         Bd+cu2NetK47U8Ukb25UMFhIY8htqe4hs2hDX3SAd42eF7tMMypX2l92dnoW+Q1bbmR+
         1t3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4siNvCEQ6PfvM9ibFKBd5WAVR6IKgELBOteImyFfePU=;
        b=QM6wOubwidl6vQnf+lOQ+RStAnvQK4o3swhAE6B6GDErMBocpzjh5JpVJe8LhkOrVm
         gGOYA/wE87Sjg5r76m4yDaEHX05dOVJ/pHmLpkeeK0SLqERJdx+B83I+5Wt13gAs7P3g
         zkzC8p0h+nSYNvem7+Tz1FHJIPqUjPbk3mtFehDVykZsGEhuTRCuuOMmbGu8toFjB7ol
         WtSRNuLYbpKrXEpmOcw0VUOYvlO7qDa1ebIFrY4bqVAFyTX5hegOlP+Me8eHoX8ARWr5
         G8GTSMVAGDRpvNEd8vc0RdPNLz0LHduGQ03RKOQpZRKnIbYbDWgKZCfYz63+fmf4fTEf
         lMRA==
X-Gm-Message-State: AOAM533q0bZ8dWli82DQDWFe9uxflLkg3q/UpeQpSmREmiT+n/9Hur6S
	F5PDDPIHkQ/Hq1zlz221ZqA=
X-Google-Smtp-Source: ABdhPJxIT2sKgMiTw835NZSXKHunq07fzSEy2jGyskhyRDDMV29MRw2wlFkjZvOOGmerNq1eCvr3/Q==
X-Received: by 2002:a05:6902:510:: with SMTP id x16mr5077871ybs.271.1602853855794;
        Fri, 16 Oct 2020 06:10:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c04:: with SMTP id s4ls1355950ybs.0.gmail; Fri, 16 Oct
 2020 06:10:55 -0700 (PDT)
X-Received: by 2002:a05:6902:1024:: with SMTP id x4mr4650615ybt.429.1602853855297;
        Fri, 16 Oct 2020 06:10:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602853855; cv=none;
        d=google.com; s=arc-20160816;
        b=LLkesiFTx4zVBBvezfoKv9jNzJRbbR/N7EP1Dt+XQ0ZStAeWxDwSzmkNyPXJfI0W73
         lkrlUfFbG+qV+Vgb2K6+3l101M9iOv/FY5R64/pHDdY0JRadw0UicuSLdv3qEFSOS37W
         FTaCViYIN8suus0cQgotuENAWU1HHcTBctCGx0YSTjrHNCdxkbDhUMofrLEwKGyZ8VHu
         9ap35ow2jnVQR6UKI9kbvCT5BQgr7IzbQ226hIc3c5fmTh61SmMC8UbbE8hhPQL5QaeP
         MLA/7+b2OQSVkpMqqp7+4AE4e0hvIG3uREchF0y5rjy/phfwF/3ECVewr23VTMojPA+f
         ifYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Zj+cS5AehZpH9Xc1DCK1Rq5tdmQbPSdPgRnV6iCKcI=;
        b=HaCcSkMURGCCeuvDvrgOEmlIb/JoY5rsyfxKExsw875jtIFX8kkt8XSpF56j8Pm348
         iewkrOoT1JADAxOg2TOD3uAHS/gP8ajgg44gOJ37a9zGtthSO5SaJ+X7Vwf4ZN02vAYm
         G/wT1qmqocYq69Mt3XI6iSOun/kFewn5k5aih3LWgaRbL+ExS5w2v+zeQkq4U+a3zQJH
         fL+3sg5vq0lj01rr9ndBkwX8nPLp3FAe/PWR1Wz3OqEby0zRyqF6wUdUM6Pvevisxu8+
         vsACNVrVeTO79zDGPCcfp0XMgcrFbVSGk6vTrBng1cOgMiiXoUpHWZ2i10QhwL6iYOUu
         nnXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uEOyU0Jw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id i4si179028ybp.4.2020.10.16.06.10.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 06:10:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id a1so1493746pjd.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 06:10:55 -0700 (PDT)
X-Received: by 2002:a17:90b:807:: with SMTP id bk7mr3787953pjb.166.1602853854621;
 Fri, 16 Oct 2020 06:10:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <c44b27703fb2fa11029ecd92522a66988295dfb6.1602708025.git.andreyknvl@google.com>
 <CANpmjNMkZc6X+Z=Bw-hOXO3n9fzq4F3mOnHgieyifkoZM=_Mdw@mail.gmail.com>
In-Reply-To: <CANpmjNMkZc6X+Z=Bw-hOXO3n9fzq4F3mOnHgieyifkoZM=_Mdw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 15:10:43 +0200
Message-ID: <CAAeHK+yQ+hYZSAhyGDYeVYLC-WEL35Qe=xMRtDG52G9Fu6xgXQ@mail.gmail.com>
Subject: Re: [PATCH RFC 8/8] kasan: add and integrate kasan_mode boot param
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uEOyU0Jw;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
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

On Thu, Oct 15, 2020 at 3:56 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 14 Oct 2020 at 22:45, Andrey Konovalov <andreyknvl@google.com> wrote:
> >

[...]

> > @@ -180,6 +182,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
> >  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> >                                               const void *object)
> >  {
> > +       WARN_ON(!static_branch_unlikely(&kasan_debug));
>
> The WARN_ON condition itself should be unlikely, so that would imply
> that the static branch here should be likely since you're negating it.

Here I was thinking that we should optimize for the production use
case, which shouldn't have kasan_debug enabled, hence the unlikely.
But technically this function shouldn't be called in production
anyway, so likely will do fine too.

> And AFAIK, this function should only be called if kasan_debug is true.

Yes, this WARN_ON is to make sure this doesn't happen.

[...]

> > +/* Whether to use syncronous or asynchronous tag checking. */
> > +static bool kasan_sync __ro_after_init;
>
> s/syncronous/synchronous/

Ack.

>
> > +static int __init early_kasan_mode(char *arg)
> > +{
> > +       if (!arg)
> > +               return -EINVAL;
> > +
> > +       if (strcmp(arg, "on") == 0)
> > +               kasan_mode = KASAN_MODE_ON;
> > +       else if (strcmp(arg, "debug") == 0)
>
> s/strcmp(..) == 0/!strcmp(..)/  ?

Sounds good.

[...]

> > @@ -60,6 +111,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
> >  {
> >         struct kasan_alloc_meta *alloc_meta;
> >
> > +       WARN_ON(!static_branch_unlikely(&kasan_debug));
>
> What actually happens if any of these are called with !kasan_debug and
> the warning triggers? Is it still valid to execute the below, or
> should it bail out? Or possibly even disable KASAN entirely?

It shouldn't happen, but if it happens maybe it indeed makes sense to
disable KASAN here is a failsafe. It might be tricky to disable MTE
though, but I'll see what we can do here.

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByQ%2BhYZSAhyGDYeVYLC-WEL35Qe%3DxMRtDG52G9Fu6xgXQ%40mail.gmail.com.
