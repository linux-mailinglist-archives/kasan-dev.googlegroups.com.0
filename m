Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMOST35AKGQE3NCUPZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D02B254514
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:38:11 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id y12sf4322408qva.8
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:38:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598531890; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZ1/jd+qZwIhM0PLoKpO04zsZq7wfmSbUb0ib1uWCsDJMRhuTpQK4HtpGtsaSbKT9D
         qE3GguG3xgRChjCFI9DRhucpEFPQ5RQzGoyW7eDqayrWMIuPSC6H1WfKGwPKaAkNQYYf
         mGMez03s65Iw8UjF647RqO1WdI/0/rPgo+/Reanx1lnrzKumI3hgtkQPdX3HWaItpyi8
         fFliKTVYLA6+X5f9lQIgU7H/zI4pfRORPx9A1c6pdHVoR9/Q2lU9LW+yq1T7dNbjphjU
         iUwb4ev3GU93gjZHju41XtwunWXDqm9aA8npotlf4RNCfbByRaX7l4dik3BlvzNlkDq2
         lXLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Bs2Yi/Loh8ltiSjHhyBww4sdT4XkjqwbPiu2flhZIrc=;
        b=iuxrUEH/BITl3ti3m5Wg3iDbp+by8J8Lm540zjjMpUSbRCsRCeQBjaH4LX/tfFzJ48
         J3jKQJQzGqNTfFA/jRNWQbZtoKSoQx4He16aZxdGSE2yc6b6ckPvvCg4d+w8RYGGSsPg
         KGO9zUorkvkHxRIvuW2NE/K2sESPZQhY2rEft8QmfLc3cJ36OwRHiK1WK25EaxBaFyld
         mC/OCfI8QR82sN32eJK8t1PkON5e5FhKPuh9ZIy5Fg1iSe1WrnRE7g/bIZ36oYc2yw6G
         HkN6cSb466yl4Cq+2dVVEQJVodxFME1PFUVut9oL4siNhSwRma4oT5J2T1+c5mlfZgXk
         LODg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=crL7nHRg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bs2Yi/Loh8ltiSjHhyBww4sdT4XkjqwbPiu2flhZIrc=;
        b=TcYjogcqQ5itFd11bldqy0W6jMyLbgJLmVMiQgSkiJOo9u74A4pth9WlhufK94SKYG
         KwIoepcp/XpVCSIlm/P5JA5uynSHJ025+AS2XRQJbAqKuN5yF6d4evjMNfxntTAH/L3C
         dPcLejQijguNefyKZy8C7SKeEsocQ0G/atensY1Kp6/BtW2s/s5Ixn2woiRsNkSf9s5S
         vdAoblmH0kJFZ7fgaF30BYFRb+W3tCURI0O/5mV9Q0TEu25Pq9gmGsR1DuJf8Or1phJx
         Cm9WyxXfYszrpZL/lkh2sSVPZvNhNgiYB0GJu+THamSW/OYoVJ2LecRQMdz0/k58bmqC
         a4Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bs2Yi/Loh8ltiSjHhyBww4sdT4XkjqwbPiu2flhZIrc=;
        b=UnlcW/ctL3o8jqcCkLW0ANFqL6u/B0APJJVTbBsWehbpQOvi+UY0ydAHuYjdAJSDK7
         +ONvALVkPOdiiCI9Hzm2Cduy+jlCYlZ0xm4UM1DItPWSyctVb/WVDYA/z2Kxwuw2pV4o
         euoalOftEssA//IjIVOewX6DY4j80luDHktXbEaawYMt/zpA/uRkIQlr9wyjbor8vLla
         5cMCz4hZYnb1DDfa5ZmzOmLDpvrv1G9UQAEZh8UZeY9AOWFfp4yDwH+QD1xuUNqcXE2o
         nMjNnGHnf+MvaZHcmUs1ztxcaqcK3jxGjkgFS4KI6J6HCJ/+ZR2mvHAx+gzg6hAAc2RE
         LvtA==
X-Gm-Message-State: AOAM5317aBiBrIFbx9tPlwbn2BGXHQmP50F+5ltnXbQx0PuDcUKTsL7J
	WxifVZN1lJ6sPgW9IVSe5Lc=
X-Google-Smtp-Source: ABdhPJzqK0bFF0iHDSgbGvFXhLAdalhW4iUGkUx5Qq5F/J6gdI5KM/K0rBSg17SlEtVtmww47joY4g==
X-Received: by 2002:a37:a74b:: with SMTP id q72mr15104573qke.357.1598531889995;
        Thu, 27 Aug 2020 05:38:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:b087:: with SMTP id z129ls930965qke.0.gmail; Thu, 27 Aug
 2020 05:38:09 -0700 (PDT)
X-Received: by 2002:a05:620a:22e9:: with SMTP id p9mr19240208qki.105.1598531889039;
        Thu, 27 Aug 2020 05:38:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598531889; cv=none;
        d=google.com; s=arc-20160816;
        b=ibyLK/7ypJ6NENWp8q5GTesOr70MgC2+cRVqWm/cWC51BAOHDvVE70ufyBVudu8CwN
         sPM90NuD393WZ3bWhyGA7LtrpMq8V1Hb64YQhdVbIHKHSYnU/DakT7MIr59X1qMBqaPg
         xLAAqxREsqcXoph9JNiTM/SqpYCfb5nsRJ7jrSmKZjoAgb+myUdj49jBb2zp5rgIsscX
         /5CZPj2Vqsdrj4NsK8VamngkPuR9YicJJzaqjb4y2GWxENafh3MBVDoeHQuVkLKRLga+
         cTJb9zf0jZ4LrH3atcPNToVANPfVJctwvHQH64EWDgwFekJuVUqnvbPMfsMYmXtZ1cR/
         ol6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5sih6/oMnkYkkS4cZqAk1lLuHR7D9bxWXGtKLgy7ous=;
        b=OzN3mka9i4LvyIZ8liExe5atqIFvt3AKnXUbm+hVSXZ3JdBxFjNoP/0Qvbbx43txNN
         y4lhRm070lI/Vj6JYh4DVq/ZVbSa2JHhQ/oRK3MDlu1V3JuxJxQQFE9p0BJtQ8bOm6M0
         r7kJHIJQ0JGv/ACXk2PfIi12WVGcpvBGryj7CNbn1M3VUJvwq7NuPlh2DOq36vPsk6IT
         XMRgsw3D29B0SSCUPAllu9kxhGnp/Umd2Jfz9m884KMr8BSzMNXGo/M2DEwRIPSUvcAg
         Y1aW6Ciu7Ng/3kPVeQSnVJFNfzyzGGGFDAYncTSAONceV1zfaakjZ+Fk5PXWCXm0o1Ld
         65bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=crL7nHRg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id a189si105266qke.3.2020.08.27.05.38.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:38:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id g29so2243902pgl.2
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:38:08 -0700 (PDT)
X-Received: by 2002:a62:2bcc:: with SMTP id r195mr7684877pfr.123.1598531888012;
 Thu, 27 Aug 2020 05:38:08 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <4e86d422f930831666137e06a71dff4a7a16a5cd.1597425745.git.andreyknvl@google.com>
 <20200827104517.GH29264@gaia>
In-Reply-To: <20200827104517.GH29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:37:57 +0200
Message-ID: <CAAeHK+zY_MaquqrpYFVcH5XtsWT6WtREqUa897V-UpBpqoiGCQ@mail.gmail.com>
Subject: Re: [PATCH 31/35] kasan, arm64: implement HW_TAGS runtime
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=crL7nHRg;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Thu, Aug 27, 2020 at 12:45 PM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27:13PM +0200, Andrey Konovalov wrote:
> > diff --git a/mm/kasan/mte.c b/mm/kasan/mte.c
> > new file mode 100644
> > index 000000000000..43b7d74161e5
> > --- /dev/null
> > +++ b/mm/kasan/mte.c
>
> Since this is an arm64-specific kasan backend, I wonder whether it makes
> more sense to keep it under arch/arm64 (mte-kasan.c).

I'm not sure if we do. I'd rather keep everything together, spreading
the implementation around the kernel is inconvenient. We already have
software tag-based KASAN implementation (which is also arm64-specific)
in the common code. We could, perhaps, rename mte.c into something
more generic, with other potential future hardware modes in mind.

> > diff --git a/mm/kasan/report_mte.c b/mm/kasan/report_mte.c
> > new file mode 100644
> > index 000000000000..dbbf3aaa8798
> > --- /dev/null
> > +++ b/mm/kasan/report_mte.c
>
> Same for this one.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzY_MaquqrpYFVcH5XtsWT6WtREqUa897V-UpBpqoiGCQ%40mail.gmail.com.
