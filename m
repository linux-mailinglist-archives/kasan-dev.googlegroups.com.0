Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDOIRKAQMGQEXD7XUVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E2DE315249
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 16:02:39 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id q93sf2027450pjq.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 07:02:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612882957; cv=pass;
        d=google.com; s=arc-20160816;
        b=miNOBEFRiBYTeiUwKwXO//D5Xs4oQWQW5w7MQGUAdulq6vTMVGlEXJjGGvBk5fd1Wy
         RgifUg7O2wJpdLlFJ0JFITW1D08kpR4XCfiSpXXN10WdrAWrjRpG2hJhxwCGz0AJUJhQ
         zprsL699o0LMIoQV2DtQQzBunW1O3Q9mrhtcJC/vARWC66Hg0RbZRXeQ+q3+Yoyr4FMv
         +qFzW3H9TLz0ECSMOjxZKpWohJu/38Th/OmkNOCM5ImkiB+ZJvFy1JIQdpbOwx77z4sJ
         s7Qp9mdsMRUQfnBC2txSblB7p8kZUrqn19K5SAFaS2lWC1J9t+4S0vAHsrJYcG5HZChk
         sOqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vSkiIRLSLs1msmlIo4GRTiInn7M64Gmtr8S7c+IR6Qo=;
        b=xv5CSP76bWWR54o/Rp3CsN9Mk4KReP/qCW+n29VHB4MI7Hl2KAnnLsOTBhmGLxyNkh
         2uOIZyCIYgjcaKv3OXKny1mZGr6WBlSuUCPhQmk2HO1th36UkowzIynkHj0cT1qI1jpl
         KuNdXr+c8y3xQhCIuPNZ1Jv4R50HV3HUwxszwph9N7zdABFIcHbzg1L31C1gAq390jbu
         Fl3VAP8fCPpknATlpCzthnlMHwbXPeJjzga4kvqYNWcMgdj4ZNXjJjNCS4WIaH8RK6Ih
         eTHPYSoXmQPX/+ZaEDAURuKAYJ7uJgtpdT03mlgUKZ7ye1eeSWQ/s+0p8g3R61f467XJ
         XxEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BkzUN4Mr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vSkiIRLSLs1msmlIo4GRTiInn7M64Gmtr8S7c+IR6Qo=;
        b=BDCI4QTlHwmRdVHRoCxAkt05WjaD67OCkP8xGjz0F50tkIiOam6DKk91CMJDukWsRX
         LcSH2VT+0/+DNKwpHSW3HU0LC3TJQOoXKr4U2A3G+2kvx5HvC/ibop5em8FgbUWhOGfJ
         gIs2kvtm9eBRK0zenNHZkV4MC1wGsG9Eg/DoBLqzz5NcEbsZYB2AaRnQJ48X2/Hmjs7f
         eko5dlCDC/wIKR0ET6Mo8Vz7hjKQk1Ciclgx+7sF1DhKTjujSlih7zsXDpZx6eEYg27r
         ZS+nu6IIEPv6bwzsQUiDSEa7Gt8W9AdMwIAzkxXTWVMR7sTeCtTBHe2ZvRPiE1QTIM3s
         w8ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vSkiIRLSLs1msmlIo4GRTiInn7M64Gmtr8S7c+IR6Qo=;
        b=jB02Mq/bMCxzDB9pC6R+ClavNv1fiM7AhTNBmJr+f0Eji7okQAJAhyxQH8c60GcOOc
         QywaBhL1OKtFdlBppVqkyWsoGifJA3ljlNR4EaFvnLFcEjUIPlaUSA2fyUQdA+HRBeYe
         D4qWPfy07hXpF7SJjtcrc/I+B6eqke5D53qPo2kcgL9hVpNSivN8dWMS9Ls4aJgDdvJB
         u3kwlURrVDBjitYV3kW/I6GvtBo6BhCsN4ysn1vuTgqJTcIrOmwiFj8MbdJSCFdhrFyE
         kRErG31CdDw4l5yWtQiz8YqMS5faPIFPh3dbZzjG4/XMexLI5V5yTwQoWUS6Vkf5oQyT
         Lfqg==
X-Gm-Message-State: AOAM532lnNMyovEYQe9XFRGsraSKH+45JEogfpK4H0JLW1aMtv++BXWz
	JAwusudGh3BvIv+Z9nUlu60=
X-Google-Smtp-Source: ABdhPJyLqMKIx30dcbv+7JBhLFuPq/hn0XrzUhleK+ooVzZ6OUpAnfoKhdCi912hXnxzlU5JYudt1g==
X-Received: by 2002:aa7:8598:0:b029:1dd:9cb4:37ee with SMTP id w24-20020aa785980000b02901dd9cb437eemr9995007pfn.54.1612882957760;
        Tue, 09 Feb 2021 07:02:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a609:: with SMTP id u9ls9732821plq.7.gmail; Tue, 09
 Feb 2021 07:02:37 -0800 (PST)
X-Received: by 2002:a17:902:d647:b029:e0:8ee:d8ac with SMTP id y7-20020a170902d647b02900e008eed8acmr21563501plh.4.1612882957099;
        Tue, 09 Feb 2021 07:02:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612882957; cv=none;
        d=google.com; s=arc-20160816;
        b=WSUDDBYiaBr2YmIpV6o1xvbIYjE29zfrIoRKvSqdlrlAW7lPLXibRLfjZA3CXCOV6M
         ma4Tke/bFqu6zUl5swK92OgPWTpYcbflpHFtAn2SC+nn85NdMWzSYSfHxgxX1NnJhKSU
         EQoukt68VTzeb1c1QFE60ZiIcy0PqwVzJTtLk2aHNDxm79sbEyZr+pndfzWHkU/vxbYF
         iuYEfRgFCwFjdLtJ0p2pfVw8LEFmMnLnbstQwxcqBlMwyZQ3Q//EK58yBHWK3dQtHjrI
         R3ffCBZ5LuHBywQz+DpDHj2x5M4QbXuhp1nkG6mtOOlqF7gB5xC4TOZP9akXM06ikxC6
         fm+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mjT+lhycmX18IGJ07x7zbycUtzukCo5yZRMUX1bB2L4=;
        b=moDs6VHzSNSR/WpbPHijf3lHSkIalNoHdRm2P+bbXVCd/iEzEoqzlvpSUN21C9Qus/
         DMRRQ/vKNE0qDDel0AX2Tp/kFr3VLHpV1F4G2oOSUSSBGijzewRUqoYumoSXwcsBz8ne
         TpTwrbrJazplLEfEy6x4TvWeMDokgBw6eWGPvhGEucNzbsLb6Tk/emf6cTN+fbnzjMbi
         QXdDOr6zYqtoXJt62udeaM1ySDLdoPkRwnVPPVzuQYgS15gtafFjAf52koEtyyw1OzBK
         CWMbuOEvCVCKE1Kvd6N+Hzo5gmq33/RAbdw7ivNkI7KeFNlBRcQENvCkH0bq64rVQwN7
         +8Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BkzUN4Mr;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id k21si62269pfa.5.2021.02.09.07.02.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 07:02:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id w18so12064112pfu.9
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 07:02:37 -0800 (PST)
X-Received: by 2002:a62:8cd7:0:b029:1d9:447c:e21a with SMTP id
 m206-20020a628cd70000b02901d9447ce21amr18569418pfd.2.1612882956610; Tue, 09
 Feb 2021 07:02:36 -0800 (PST)
MIME-Version: 1.0
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-8-vincenzo.frascino@arm.com> <20210209120241.GF1435@arm.com>
 <0e373526-0fa8-c5c0-fb41-5c17aa47f07c@arm.com>
In-Reply-To: <0e373526-0fa8-c5c0-fb41-5c17aa47f07c@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Feb 2021 16:02:25 +0100
Message-ID: <CAAeHK+yj9PR2Tw_xrpKKh=8GyNwgOaEu1pK8L6XL4zz0NtVs3A@mail.gmail.com>
Subject: Re: [PATCH v12 7/7] kasan: don't run tests in async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BkzUN4Mr;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42b
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

On Tue, Feb 9, 2021 at 1:16 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
>
>
> On 2/9/21 12:02 PM, Catalin Marinas wrote:
> > On Mon, Feb 08, 2021 at 04:56:17PM +0000, Vincenzo Frascino wrote:
> >> From: Andrey Konovalov <andreyknvl@google.com>
> >>
> >> Asynchronous KASAN mode doesn't guarantee that a tag fault will be
> >> detected immediately and causes tests to fail. Forbid running them
> >> in asynchronous mode.
> >>
> >> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > That's missing your SoB.
> >
>
> Yes, I will add it in the next iteration.
>
> >> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> >> index 7285dcf9fcc1..f82d9630cae1 100644
> >> --- a/lib/test_kasan.c
> >> +++ b/lib/test_kasan.c
> >> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
> >>              kunit_err(test, "can't run KASAN tests with KASAN disabled");
> >>              return -1;
> >>      }
> >> +    if (kasan_flag_async) {
> >> +            kunit_err(test, "can't run KASAN tests in async mode");
> >> +            return -1;
> >> +    }
> >>
> >>      multishot = kasan_save_enable_multi_shot();
> >>      hw_set_tagging_report_once(false);
> >
> > I think we can still run the kasan tests in async mode if we check the
> > TFSR_EL1 at the end of each test by calling mte_check_tfsr_exit().
> >
>
> IIUC this was the plan for the future. But I let Andrey comment for more details.

If it's possible to implement, then it would be good to have. Doesn't
have to be a part of this series though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Byj9PR2Tw_xrpKKh%3D8GyNwgOaEu1pK8L6XL4zz0NtVs3A%40mail.gmail.com.
