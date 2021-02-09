Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXULROAQMGQEICSOKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 55EAA315503
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 18:26:55 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id y62sf6182184oiy.15
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 09:26:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612891614; cv=pass;
        d=google.com; s=arc-20160816;
        b=nxoV55/UhOW5KcyQt1T0FfASkABo9E5EU/wmTH2SmZN3aEVlzjohadTOotf+6hJzpB
         3heLk1a7587I1+COcTNCOFkmwtUH58qwL1LEmsGYah3639d8by1f8OV09eJ8AW04lsQm
         kwi6yFpfl75wO6BtncsKN1kgB1RPyvfQRYWM84fhgekKoluemvMIx3IV+0mVai0CsHnP
         pgS+4gCF9bX+82rIYQ7H+dHWwBo/QHiDo3UG9m7zotp7Qx7pKFkx2tMiOydBRYiIl345
         gmL0eBMQenZA9UziRZTSkEttkn4mpDprCEmPVtAXzOD+kL58ftedWZlT7yUAqbRAK4/J
         imvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CSjyrvuoPfFX1BsOvXFd6+FGVTAntfbiXequOBFxLFc=;
        b=sVtsGcynZFYr06jrdSiWuPpcYGVYy5pJhEsUXxwv8wyZdmTQavO5u7WfrCrZd+vHHQ
         GgQaEwQPr5oT5kwRme5p7sjfYYiaEf3zgGbM4nIA8TFoA/+hIytJwaMFZJSo0cO9nbO3
         pnPRWCkEbwctbafoqgbLQcm/Sct2I4L9+Lmbl8p/N3NXcG3Tcc/1oxQds4hqynBiJI15
         RAnZb0zQr2ase3zFXA90vV+1BkYm5QvMPZT60VBlvc/IAXuOVYyqXZWGzYbeKjsBCI6x
         6wvmzu+ahLgS48MnWWcraouv/FEww1FN7Ae7SlXvuU+L9k/7l2VNmhOrl5QzmVNRLMz5
         dcZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YoIMbsWI;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CSjyrvuoPfFX1BsOvXFd6+FGVTAntfbiXequOBFxLFc=;
        b=egnWbdKJdm21PcLW/tuuBXF3zIhbqEC0Mr0Jy3tORShxT3OQKRmXbsW8K7RAn2WiOb
         aOyvuoTO+dw/46VECYNp2n1iadPKTFtN+Z7XaLMtckmJgXLwDjSd4UBjLQi3Tl5hcOUj
         jJL8ycWynTKOgAGEERaus2uHuUmRN8DX2Luse2d9yqKXLl5mo7T4ztILtu+2WEZMTCxR
         jqm71cHKl0z8lwKnGCqvxF7EoYu9XEN2gDwLipaRf4ppI7/xg7IlkYQIAnFSpVCKq434
         FmvHS3WZ5O59nWMu24XBajf3T6d/4FNzWpouhqFc8rR2y/Wu16pd3FuugXRLTWV4wCiD
         6TVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CSjyrvuoPfFX1BsOvXFd6+FGVTAntfbiXequOBFxLFc=;
        b=GDPJQ2QXTdFKikwb1w7EqY3sGKZwaPLnOdzF4hLfs9a0h0t7PdOKNBEipJhDMiNnh3
         DmaSVH9lTSCgJ8Z1at+xTlEoI8tDDmqaqfLg2yrqqToZcurlFHdlqKEcY6XY3T+SAWnX
         drOSCnYOY4c2/VuX0ylllIQiz5c+eqdtzkxpdKS+6MP2urJ9RLAT9pMn4RHdYfPg+qii
         0W9NVR5UF33kKf+9PyA8a+nPaTextsQkqzw2r21XLsi95B92DOyseiK/lJGhcD9LR/9A
         967HDVofOwrsRkpZJcAKS0V2dDMAYz6SMCgZKfSvMCKAk8w31klDq9fjmlQ6euJLb1qV
         /tHA==
X-Gm-Message-State: AOAM5302OLCYXlN/t7/jTbeG1GcfIBy0/i4iPqWowIbttVzq9qL95Kuy
	a28qcUv0GQegude4zlM128Y=
X-Google-Smtp-Source: ABdhPJyl3dG3dFVdn209PCTlGVBxPEVJ8498jgPSiooTPMf3bo2p8vkCppYSS0tY/Ty177UnL9mvRw==
X-Received: by 2002:a9d:2aa6:: with SMTP id e35mr10973460otb.283.1612891614380;
        Tue, 09 Feb 2021 09:26:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:19f8:: with SMTP id t24ls1887374ott.11.gmail; Tue,
 09 Feb 2021 09:26:54 -0800 (PST)
X-Received: by 2002:a05:6830:131a:: with SMTP id p26mr16006147otq.134.1612891613996;
        Tue, 09 Feb 2021 09:26:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612891613; cv=none;
        d=google.com; s=arc-20160816;
        b=wUaGyx3xnz6pQaO/IwEOpJhLqHGFrBNwuXaXlGE+MBj/4DNnGJYM6wrNisJV2UYXyt
         OXIbsHtksJHNZVzJBk+pnmI4sbLExjUJ2jCkeH4h0nOJUCZwK7/dfMRw3J975b9Ur/a/
         h78LdtHR9mxe0oMyjsEs14a7LFSCxANEj/yPMjj0id7sDonHvodXkuDIh7jquW/XZIzu
         SAo+aExIkNkY7oRwEBiIeFfKzo23UGuowInuseAMkUIMTtWYB49Vy+q4i4cMXLPf5UYQ
         8yGK+yR6tEbvmygED5NlEyDHeLS2OmuJu0iRbMEHlxXLt8GoGadB2377V1S145ECl+nq
         vR7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ukuRLDcQbuu9Wej1M0AS5B/9jDoZ1QokOXA2WrrNxEY=;
        b=UtbZfyqsc1yUcU68+kaBJFMFbYQpr3Go8SlryE8+cvPGTw+U4iStw2KZIjgYveR7JZ
         ia8FqpdzzCkPZ+pSJOzMo/aMrHBoQeacg/UstxCHhff0MgBYrTJWbS0SgvA0BzXEiWLV
         kQMLr8VZ/epII3cTWVi0NGFZFIKKDE6zruZqlOc+5JKpQ5/dc1nfU6nBm01GTnIey6Be
         vcZFDSYEmGae8mLdDhw1jRmxyEb47tlG2FUmh6JwFoeEfHZWuG6IZyI5PR2g6I94w8Q9
         mNvxb9+mY8NBrbDEdxdCngqKXzc4fLuRSk3Aw8YKCSJZCn16KemVGnSn36M+MOAZJ8fJ
         EqSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YoIMbsWI;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id e184si1944456oif.0.2021.02.09.09.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 09:26:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id q20so12320779pfu.8
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 09:26:53 -0800 (PST)
X-Received: by 2002:a62:8cd7:0:b029:1d9:447c:e21a with SMTP id
 m206-20020a628cd70000b02901d9447ce21amr19146610pfd.2.1612891613122; Tue, 09
 Feb 2021 09:26:53 -0800 (PST)
MIME-Version: 1.0
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-8-vincenzo.frascino@arm.com> <20210209120241.GF1435@arm.com>
 <0e373526-0fa8-c5c0-fb41-5c17aa47f07c@arm.com> <CAAeHK+yj9PR2Tw_xrpKKh=8GyNwgOaEu1pK8L6XL4zz0NtVs3A@mail.gmail.com>
 <20210209170654.GH1435@arm.com>
In-Reply-To: <20210209170654.GH1435@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Feb 2021 18:26:41 +0100
Message-ID: <CAAeHK+wz1LWQmDgem8ts30gXc=SkwZ-HM507=a+iiNpOYM-ssw@mail.gmail.com>
Subject: Re: [PATCH v12 7/7] kasan: don't run tests in async mode
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YoIMbsWI;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42e
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

On Tue, Feb 9, 2021 at 6:07 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Feb 09, 2021 at 04:02:25PM +0100, Andrey Konovalov wrote:
> > On Tue, Feb 9, 2021 at 1:16 PM Vincenzo Frascino
> > <vincenzo.frascino@arm.com> wrote:
> > > On 2/9/21 12:02 PM, Catalin Marinas wrote:
> > > > On Mon, Feb 08, 2021 at 04:56:17PM +0000, Vincenzo Frascino wrote:
> > > >> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > >> index 7285dcf9fcc1..f82d9630cae1 100644
> > > >> --- a/lib/test_kasan.c
> > > >> +++ b/lib/test_kasan.c
> > > >> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
> > > >>              kunit_err(test, "can't run KASAN tests with KASAN disabled");
> > > >>              return -1;
> > > >>      }
> > > >> +    if (kasan_flag_async) {
> > > >> +            kunit_err(test, "can't run KASAN tests in async mode");
> > > >> +            return -1;
> > > >> +    }
> > > >>
> > > >>      multishot = kasan_save_enable_multi_shot();
> > > >>      hw_set_tagging_report_once(false);
> > > >
> > > > I think we can still run the kasan tests in async mode if we check the
> > > > TFSR_EL1 at the end of each test by calling mte_check_tfsr_exit().
> > > >
> > >
> > > IIUC this was the plan for the future. But I let Andrey comment for more details.
> >
> > If it's possible to implement, then it would be good to have. Doesn't
> > have to be a part of this series though.
>
> I think it can be part of this series but after the 5.12 merging window
> (we are a few days away from final 5.11 and I don't think we should
> rush the MTE kernel async support in).
>
> It would be nice to have the kasan tests running with async by the time
> we merge the patches (at a quick look, I think it's possible but, of
> course, we may hit some blockers when implementing it).

OK, sounds good.

If it's possible to put an explicit check for tag faults at the end of
each test, then adding async support shouldn't be hard.

Note, that some of the tests trigger bugs that are detected via
explicit checks within KASAN. For example, KASAN checks that a pointer
that's being freed points to a start of a slab object, or that the
object is accessible when it gets freed, etc. I don't see this being a
problem, so just FYI.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwz1LWQmDgem8ts30gXc%3DSkwZ-HM507%3Da%2BiiNpOYM-ssw%40mail.gmail.com.
