Return-Path: <kasan-dev+bncBDT63BOBRQFBB4FQXD6AKGQE3ZVDHAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15630293183
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 00:51:30 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id w16sf1345824ioa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 15:51:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603147888; cv=pass;
        d=google.com; s=arc-20160816;
        b=EbhE9FSoxRnHmqEW+Du0stoNSpkPJao4CGj5kqcz7dAxaKFgjjkezCPjtPv9bKP2PQ
         ayo0hienIr8jZoEgi/MzBiEMPo9/qr5lJSrLfghIvGDsdqBcg1gPaUJKiJSAoDhCHodN
         4jlKK58kAlQ3GJBwpijZh06lrnktSYEf9deZdsv2FoN+3u8ax1yFRNdbymlKrsm0Qly9
         6C3LhPZhQTW2bdg4qbehJ9SB58sUqh+W9B/Rl1X5AQHDWmSnK/0Kzfto3cR/HhUc340t
         YlRF9UuLDINoH1Crt65CiwB5961GAFyRpQjPL1/bO1YqpprXTvFvDt32MkwoKEgBH6G9
         oOQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sd+ohCVpVXxQI+DoU8JPuoM1e7ey3sZEjPS0Dn/tmo8=;
        b=T8NkSNZOJLywFaJ2FKpgPHKmMlveysNV2HZgQBqGZiw8n1nId7l40zXIFtioBaijmm
         a9/rw9XBIx+C9bYfE5f+Ttx4orPW/0BWCI0BsLan3aBq6eNcmdMTH2jqMNYeO+7td2Ht
         w4m5O4bYh3GmRsBxVjyb0Z4z7Kt63qE8i0fWIIJiikE1XsRlOjcAx+ofp6xHVvHVhN92
         QDJi23Ia3aFMOFkp4qqD3U5rLEcqW6XH7XvLXxiPf5zau0veOzummI+n6DInAZd9+/JD
         1QCdwk2BmZnFgpAXMaqmCnGXr+M3i6sEutrwkr5EnA+2iE7sOD/8hZlRgrhsY2pWJ1kj
         mO/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OC0a2zIS;
       spf=pass (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=kcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sd+ohCVpVXxQI+DoU8JPuoM1e7ey3sZEjPS0Dn/tmo8=;
        b=T/uh15aqo0xZNy7FtlLjBt6csqNGkSBvzp1m0551yKa9uICJRFOrH7dp/bppr2bqD6
         AOoLHOwfm9mDZ/086I12zIOeOjRmsEdcT/qe1gTZn953k9yTuk8Z8CwvKMXfHU30rs4n
         13bXyDGKqIw9SraHyGVhetqI7UlALMBWCi+9owDnhrRXQXl83ZJq4+f7TkusmVGW0jxU
         gyq1RUMvNXdL6k7NdVU7e0c5Rn5adXxwEmw+ikldGbG+j/3zwE+fF/ndxv9FSaQuMX2C
         LoXnAlQivHo67pMb6MAgnDeQY68BT+lWKrGV1irusD1GaCA1XGq/cYaBSDvliQ1IifdB
         HnLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sd+ohCVpVXxQI+DoU8JPuoM1e7ey3sZEjPS0Dn/tmo8=;
        b=IjN9RWHiNsf6WsqehJxAJEMeyve7ooz6sfv+3MHxYj/olHxRyTu/Kh9yLPlkK3C0aD
         sDW5IVDXWnjm9k7QIu0CxdhLvX5i5cSXVmwW6JIXmhbKso9A1HFMHemteYnSDl4SrYEi
         P0aSnRn400wnyWYTOOUZ/z0bypgQpRi8VWB54QLRUWuB/jIL25ST1W4/TRv//IqvETJl
         Zuv180HOWKwzbDw4NcdZZEZDgkdQ6OMxkmyF85gS9d5Gyx69SpxcauxVn0RSxDLJmBXW
         zZI+wddHUh/PkA0TZXxsbLlox8er50nDFk+HRZ7HGuos0LAGXPRIByfnxX7HK1H/oj2r
         mRww==
X-Gm-Message-State: AOAM5301AgRnCAPGWJXCsSbaLNrkzJO1FmfYfdfa8HnfAyBwpNmz0dXd
	5osTzR6Eqx9vCqanwnwgtWY=
X-Google-Smtp-Source: ABdhPJwNZywR44LTX4lBaWdCH1ZfI4NHj7AVsSnAUNxBnyR7yfJYQiiDyQD7Ij4pzdSPyuWy+JUXyw==
X-Received: by 2002:a02:9667:: with SMTP id c94mr7367jai.91.1603147888655;
        Mon, 19 Oct 2020 15:51:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:a157:: with SMTP id v84ls14057ili.9.gmail; Mon, 19 Oct
 2020 15:51:28 -0700 (PDT)
X-Received: by 2002:a05:6e02:14d1:: with SMTP id o17mr1947549ilk.119.1603147888294;
        Mon, 19 Oct 2020 15:51:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603147888; cv=none;
        d=google.com; s=arc-20160816;
        b=PBWxRdWWRmYVF7eNRXSoBRYn3l4RyVLUuKymhWKMyFvqKpJgBWD+e7UHZD78Mf44B+
         2StEthiTwl7Pe7wP2lFMZTXBfth2Yjfv7MUp93jZTfIjnEPWxJ1fBSIUy9vUn23RSGLo
         KM+czMyaHsK3fgsae0YrvaXk8oAO0AUO9Cct5iUt6LZJtlh089whyZefy77pZW7aqzsL
         dIkEb+WGJ78vgOkQYy0FlRA4Mvc0EXfx0sQRvINrC9noFVImAXs0svoIvfc5ixzPgzeP
         0bN4UIuNQ1dDvbmZzykG9asXJKjQBxIXAKqhEDx1rGI5EHBaMaqQa2M4nFy7qCuNqacM
         ohxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/5knxhq7CVjdPlgBy3BxP03HOY/V3PzThvC7xXq5gGQ=;
        b=G1dujkrzsVcw0Kuni0EsaIdet1LWBh+HwjXJulTMrpt7ijELQAYG3usnO2J1pJVuuD
         DeW/LCzYjhPCAgjgv2m+8v5oH1zNBzeurLX8F1CDt8vKr3inKpKgjtDW80NVlcA0gP1r
         EBraoqcQA5I6GtTKCW+wW6KNfQKRWVn2b6rmHL3PdDHujx+aZ4mwOhe+JYarYZjUsVmO
         WN/kgi/ugTwy38zSpvyDCm3tzNc3iVGpyCSi45rCs1+DqzdJOrCvuT6Y8WcNliQgWj9p
         0ailD1NPvvteU9UuT+IPgXir6JQkIVM6LXrpebDr66aoUUoRcyuICBZkhDUT3RjYTLAk
         q4AQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OC0a2zIS;
       spf=pass (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=kcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe44.google.com (mail-vs1-xe44.google.com. [2607:f8b0:4864:20::e44])
        by gmr-mx.google.com with ESMTPS id o19si3077ilt.2.2020.10.19.15.51.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 15:51:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) client-ip=2607:f8b0:4864:20::e44;
Received: by mail-vs1-xe44.google.com with SMTP id r24so870854vsp.8
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 15:51:28 -0700 (PDT)
X-Received: by 2002:a67:ff01:: with SMTP id v1mr26767vsp.10.1603147887388;
 Mon, 19 Oct 2020 15:51:27 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
 <CAAeHK+zOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF+LBg@mail.gmail.com>
 <CANpmjNPvx4oozqSf9ZXN8FhZia03Y0Ar0twrogkfoxTekHx39A@mail.gmail.com> <CAAeHK+yuUJFbQBCPyp7S+hVMzBM0m=tgrWLMCskELF6SXHXimw@mail.gmail.com>
In-Reply-To: <CAAeHK+yuUJFbQBCPyp7S+hVMzBM0m=tgrWLMCskELF6SXHXimw@mail.gmail.com>
From: "'Kostya Serebryany' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Oct 2020 15:51:15 -0700
Message-ID: <CAN=P9pjxptTQyvZQg7Z9XA50kFfRBc=E3iaK-KR14Fqay7Xo-Q@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Serban Constantinescu <serbanc@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OC0a2zIS;       spf=pass
 (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::e44 as
 permitted sender) smtp.mailfrom=kcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Kostya Serebryany <kcc@google.com>
Reply-To: Kostya Serebryany <kcc@google.com>
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

Hi,
I would like to hear opinions from others in CC on these choices:
* Production use of In-kernel MTE should be based on stripped-down
KASAN, or implemented independently?
* Should we aim at a single boot-time flag (with several values) or
for several independent flags (OFF/SYNC/ASYNC, Stack traces on/off)

Andrey, please give us some idea of the CPU and RAM overheads other
than those coming from MTE
* stack trace collection and storage
* adding redzones to every allocation - not strictly needed for MTE,
but convenient to store the stack trace IDs.

Andrey: with production MTE we should not be using quarantine, which
means storing the stack trace IDs
in the deallocated memory doesn't provide good report quality.
We may need to consider another approach, e.g. the one used in HWASAN
(separate ring buffer, per thread or per core)

--kcc


On Fri, Oct 16, 2020 at 8:52 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Fri, Oct 16, 2020 at 3:31 PM Marco Elver <elver@google.com> wrote:
> >
> > On Fri, 16 Oct 2020 at 15:17, 'Andrey Konovalov' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > [...]
> > > > > The intention with this kind of a high level switch is to hide the
> > > > > implementation details. Arguably, we could add multiple switches that allow
> > > > > to separately control each KASAN or MTE feature, but I'm not sure there's
> > > > > much value in that.
> > > > >
> > > > > Does this make sense? Any preference regarding the name of the parameter
> > > > > and its values?
> > > >
> > > > KASAN itself used to be a debugging tool only. So introducing an "on"
> > > > mode which no longer follows this convention may be confusing.
> > >
> > > Yeah, perhaps "on" is not the best name here.
> > >
> > > > Instead, maybe the following might be less confusing:
> > > >
> > > > "full" - current "debug", normal KASAN, all debugging help available.
> > > > "opt" - current "on", optimized mode for production.
> > >
> > > How about "prod" here?
> >
> > SGTM.
> >
> > [...]
> > >
> > > > > Should we somehow control whether to panic the kernel on a tag fault?
> > > > > Another boot time parameter perhaps?
> > > >
> > > > It already respects panic_on_warn, correct?
> > >
> > > Yes, but Android is unlikely to enable panic_on_warn as they have
> > > warnings happening all over. AFAIR Pixel 3/4 kernels actually have a
> > > custom patch that enables kernel panic for KASAN crashes specifically
> > > (even though they don't obviously use KASAN in production), and I
> > > think it's better to provide a similar facility upstream. Maybe call
> > > it panic_on_kasan or something?
> >
> > Best would be if kasan= can take another option, e.g.
> > "kasan=prod,panic". I think you can change the strcmp() to a
> > str_has_prefix() for the checks for full/prod/on/off, and then check
> > if what comes after it is ",panic".
> >
> > Thanks,
> > -- Marco
>
> CC Kostya and Serban.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAN%3DP9pjxptTQyvZQg7Z9XA50kFfRBc%3DE3iaK-KR14Fqay7Xo-Q%40mail.gmail.com.
