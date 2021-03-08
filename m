Return-Path: <kasan-dev+bncBDX4HWEMTEBRBN7WTCBAMGQEUIJIJXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C52E331175
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 15:56:56 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id s194sf2182238vkh.8
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 06:56:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615215415; cv=pass;
        d=google.com; s=arc-20160816;
        b=pV4NgtsUd78g8/sRys3DYELDAbgwLBReAi3kw9QnixQsfFk+YvHcKC5Nrl/VJEItQR
         QUjF89zsZbii2Z/477XXvCMt/f3CDjW6Smfn/fGDlmCXiC1T+sgIQJ5BhLrimLgw0UfT
         JgOxZXPu3C2uoEJ0iaRMyPXmfBiDFJMm6qKs8g9b6uhtG14nN8BwUCHiPf7nf2LiaeTI
         YLYkCQfjIYOW6ByxqJlMY0M7vj6i+vRMtEWtGgFgKtXAjvy6cCu2rdAaiKB++6Drv8WA
         B800GWi8KoHsSsiagVyBv/YJrveF0KdRENIRz6PInYchOAkcUFyjQDP9vv9WWjD/i5ny
         XYZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ItRsoL1mMKx7dNHtOEmifU6UkC4rTN2aotMXe4FR8Bw=;
        b=gD1qrL0bUE4uqG4ACIXxMAmxtoT63OH4fF2Kps5R3G6NL+QQUwpcTVa59eQVRAwunk
         qjWZDUQ+8uHBkTPyc4Xf7iuNr5TRQPxQmWaSSiXYJPPnvnV2UXBL7XI9CWHlCI72tb8O
         DhuYwbMkG3bcAULQVYY6XWAZ7lwwhdhSKI5OMdzAZhY8ajd1YGcMsWELWhwi742l5BYV
         bOrauSyRrv7Kc23cq+UieS2iNa6Zr+35MH84Yjen5YfoOLSmySUqvqipeedNG9TAdgnc
         N+ZdRoe68Z+9WZYEr0gJ35BpYA8S8Ww3mNwrX97kZPrRJsd0YnjCqa7VTXenvNx6xmph
         hOWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GIXfP9Rm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ItRsoL1mMKx7dNHtOEmifU6UkC4rTN2aotMXe4FR8Bw=;
        b=G5ZSYHJnHzR3EYtLdb18LLZ/agogHdHcdllqCYwmXF7ihM2OEmnJ0k89NdHJW0hMQQ
         dNPMPBd9BhGuDckZYyfkFYY4WnmnxseUoG9owV+cv6XLEt9s8owYDV7BzQA8ueccZiEn
         XYxC7J/4TlcoR92faOd9kfAV66dFoI7jxo0WeBPYobebEC4C/HLvhKkda3+C9GmDHyVS
         KMD/+AS2E4K4GTr7lZUgCB5HFAM7ekedftBpCNwJRZqERaIzr06CfVeYb1ZoPHdDdGcz
         4PTc9D7ySCnYftMjVYqamgP4O/utx7hFit6GHhFVL740MyNzc8q8kBzhyJJnWFEQmNuF
         XWvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ItRsoL1mMKx7dNHtOEmifU6UkC4rTN2aotMXe4FR8Bw=;
        b=c40B7niy31EL+jV1wX/m2In4iKlGVBixcg7v8zjourG36DAShV0d527LkZ5UCxGz57
         l0ze8xodpCyJehKD+FflUf6aB2Z7usYs7WI4V+ikBNOV3qhbbHw5egcCb7yLs745z7oi
         rUQwXtY8t626MKHVSXJGlywSRG3FrApdd4mOxckDhAgme3LdxY68uQL51S8razOxD8aB
         dfG7oSkDzI9Y+qfwX0zoJOAh8DhdFTmG4eb1Rxufs26NrdqF7F17bYAeSheYPsSNRdG3
         hfa+A6rocOO8ajcn/e3GPNaKb7xwgOm2Tg9cZQUwQPPh/+rWvom7/sKEits6Hkltzewa
         SOfA==
X-Gm-Message-State: AOAM5303+mSCkV3Exbf17yaagYjqLJk3DpBC0CDoyr/pCLi89SLoUIe4
	aqP8LYlCqWIvzN5IosxCEas=
X-Google-Smtp-Source: ABdhPJzsZMChdkNBN6RiNLhnJ0GwoJyRa3mjo4kDFE0nYcnh+2q00+ljuY/kJWYhLyVGJJceY10aFA==
X-Received: by 2002:a67:882:: with SMTP id 124mr12503222vsi.33.1615215415337;
        Mon, 08 Mar 2021 06:56:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c89b:: with SMTP id n27ls896137vkl.1.gmail; Mon, 08 Mar
 2021 06:56:54 -0800 (PST)
X-Received: by 2002:a1f:9d43:: with SMTP id g64mr13546402vke.16.1615215414815;
        Mon, 08 Mar 2021 06:56:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615215414; cv=none;
        d=google.com; s=arc-20160816;
        b=J7VS48yz4vy+Y/fWp0kf6gPXSI6CTiGa/Ok9whlNuuaPGZ9Sk1yLwmvGm9eJygzzPp
         TyIhEQFnQCDHmXJx2XRQt/LBGSvU7jzSJqnu9eU2GC5B9hk6Wuj8mXWneK8P0eSH9EWG
         BS6QRPN5HfnrQJ3bMiDBYnWTj4YPdSJM/4MXC2l6uuulc86XWWjVbqLIRjR5M0qD0u8z
         Uku8XT7+FreRbxN2WMEFKVG+zXkCv5C/nigOfk2S6kLtKjA7d4dLch+Lv/iSmBstch5T
         J2Fe/zPqRTA/5WLujZrk+ebJvxCOnPQJiNi9lEagiDPL5aTpzd4FZvk6GTw3enAtDHJw
         t00w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GCYcXvsikTXrcZukrMxQd7rhmQO713u1DW4C7CyWQ8c=;
        b=p29F3GcPkWw90ixke9vplujk3dl3+Ue0SJHLOQ0saFgIVuCGCm47deAtpBU2X9BlF9
         HRSUXSxirHSKf94oKuCRFSUtl6eR2I4YUwpfpvqnTUQvpaw9VZY+bhqzS5vHP5iYPdyf
         dwb+zCd3wCxj8e0Y94uaryakccgpFqTmmj66wi8mA8P0flB9SdY2i3YLDhTMV2f86WM9
         swkx0c5MKpkHR36EwScyhMR1m9Te1ZPexaaiw6nzAK9tefHecJoYBbClyKKXSfia32ok
         +iotHP5Vu5syOoiXj0DeYT+PsUEnSEYgFqG36MuJVWvKqpeTLMSYQRLqhbcVaH1PbHpt
         HacQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GIXfP9Rm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id u21si789258vkn.2.2021.03.08.06.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 06:56:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id lr10-20020a17090b4b8ab02900dd61b95c5eso860637pjb.4
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 06:56:54 -0800 (PST)
X-Received: by 2002:a17:902:7898:b029:e4:182f:e31d with SMTP id
 q24-20020a1709027898b02900e4182fe31dmr20762682pll.13.1615215414302; Mon, 08
 Mar 2021 06:56:54 -0800 (PST)
MIME-Version: 1.0
References: <20210305171108.GD23855@arm.com> <CAAeHK+yuxANLmtO_hyd0Kg4DpHh2TLmyMQEXP58V8mLoj0vtvg@mail.gmail.com>
 <20210305175124.GG23855@arm.com> <20210305175243.GH23855@arm.com>
 <CAAeHK+ykdwBXETF5WkrWnbzzS6RAJdmqZ3DrFdM_7FoXZR3Wqg@mail.gmail.com> <20210306120121.GA2932@arm.com>
In-Reply-To: <20210306120121.GA2932@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Mar 2021 15:56:43 +0100
Message-ID: <CAAeHK+z5Q7QtV3W3ecDW9daf-USW5Yth=v-TUVhF96rkqtYT3A@mail.gmail.com>
Subject: Re: arm64 KASAN_HW_TAGS panic on non-MTE hardware on 5.12-rc1
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GIXfP9Rm;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102a
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

On Sat, Mar 6, 2021 at 1:01 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Fri, Mar 05, 2021 at 07:36:22PM +0100, Andrey Konovalov wrote:
> > On Fri, Mar 5, 2021 at 6:52 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > > > This is weird. kasan_unpoison_task_stack() is only defined when
> > > > > CONFIG_KASAN_STACK is enabled, which shouldn't be enablable for
> > > > > HW_TAGS.
> > > >
> > > > CONFIG_KASAN=y
> > > > # CONFIG_KASAN_GENERIC is not set
> > > > CONFIG_KASAN_HW_TAGS=y
> > > > CONFIG_KASAN_STACK=1
> > >
> > > From Kconfig:
> > >
> > > config KASAN_STACK
> > >         int
> > >         default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> > >         default 0
> > >
> > > and I use gcc.
> >
> > Ah, that explains it.
> >
> > Could you try applying this patch and see if it fixes the issue?
> >
> > https://patchwork.kernel.org/project/linux-mm/patch/20210226012531.29231-1-walter-zh.wu@mediatek.com/
>
> Walter's patches already in -next fix this issue.

Great!

I'll still send a patch as we need the fix in older kernels too.

Thanks for the report!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz5Q7QtV3W3ecDW9daf-USW5Yth%3Dv-TUVhF96rkqtYT3A%40mail.gmail.com.
