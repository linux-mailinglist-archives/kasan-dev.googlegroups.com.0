Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUU7Q6AAMGQERQUB4DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E9D2F8229
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:24:35 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id t9sf4397615vkm.12
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:24:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610731474; cv=pass;
        d=google.com; s=arc-20160816;
        b=bo9751ueBhB3c4Ml4tAr1w04DBAr3nh6JmYlVq1mm96xbrzqla0C0tktL5d2N+on0A
         k8spKc/j8Uk3k/4cGU6r67YhhTj06f/rFbYBwPRKtkuuIMl0kuxzrYkVaEdVsTkGVukl
         yw7FNwmZ/1TO5wMEH2e4zktuO/wMCHxBpK9hkia2+BW7ASMttRyPwHxFEJKxLbxXLW2I
         6KG0VpKy/ET0EQEgiAP2tXX2j7X008dfXP2XVsza1UnOZW0vwgJBOMAaCsNh2HSHvEu6
         6btMrU7B0neYhDLG4psWlMGWpUq6Zh7dhkNEF2VK1PgPzKxjnYJX6IR2hCNeFYUkK/+5
         x8UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=H2bOQXA+tT4An0tlYY+Ckuw9nkb+qAUjyNweBJDDlg4=;
        b=HK6tZxL3Ju0XW0+cK3sdkUeUWs9/y0ZFmOWVLQvBSL7V732EBIXJ1MFxEk9cySRIM8
         YDgK6lFX2COk1IW6NwJC90qgLEUl0BGUhxPOaNKGZFLlTDNiBxS4VZoH/rHPAghy4piT
         mZOHfyvp442zmiImx6o2NVI1z5SDXjqu2/oou12VkFAupdkBBT5S6R1/kOhMoQyCqBbp
         dUldfwkk5IAsjHbpLhXcOky/nnCGBBn8tpAtw5HKZCT7PE/OJGEoJMKGSrle06QwcdTC
         OvVlhc9hAk6jfG9PZTgI2jXcuWNNo9SlPLI/3NgjNucbM30s8UyViUtuBrrTHYArnLP2
         oFhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SLvWXReU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H2bOQXA+tT4An0tlYY+Ckuw9nkb+qAUjyNweBJDDlg4=;
        b=OAYlf4wGt3kjmmZu/c68NM3Q5h//zusixLyV4R4aGNSJTw6P9mLlDtB95mPdRsIrI0
         OvdvdFuVVtPQbMVlXjkaWU4ofX/1E15x19pytyOYxKIz/e6woDEoxinwPiGd58qmZp2F
         FDonnvi9kcESK+HAOT74x0BoXSTQv7c1jKPp/M/SbnhWQzH7hwdt95YmwmBW2auZtiQ4
         UvMWNsRSPadQ6BQbRwzVYX/vbpAZGcxsE/hH9fnQ7GpueYhF3KZdqJeRMSmp0H0UHKT8
         6r3TiH2OajeTKbV9el8UHx953t6nTJcpSsSgahVGLkuWsduPiwuDMoCUG1CTE6ElxxNk
         PASA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H2bOQXA+tT4An0tlYY+Ckuw9nkb+qAUjyNweBJDDlg4=;
        b=n3LknIqGMpJhNdhyVBGqZM08SwXaYd8FdU+GCupLXG9tnmuAvHv2PmCG1T1YWQ/Lrp
         PXwodDjitLSiTIXqtDFpiWUCEggte36ahpMVemQnMPWnok8nIHNC5rlsvqqOnPaHqumU
         9YzO2n0Zqb85V/WufTP2lO+dPCOrY7cKkTi6ossRzWOnDLE/RREDEvc0NhtJKj8LwzDz
         q+ITl1e6kYLO9n9qFf1unrbey6UUp1LvkCY3nNpP4QxN2elX2ajNdWNA1vSJn8mrqJM6
         aqTic0RGB+rXCSkJAhHCj40690aOGHCgwkW3YRGFFmdze/vvyCIhRtXPgDwM8Gt5hwrs
         kMdg==
X-Gm-Message-State: AOAM5311ExImSZ5M7YYTaQbNzQvhWKp/KFZWug0ekKlhOa+Drl/FtSRH
	056f4XN6lS8FJYDZII1U0o4=
X-Google-Smtp-Source: ABdhPJw3hFtze5nPo+XS1OApjVX+EPQ4+ukqyRpcNvh9i9zxzBadT7n0tRNiZu7L1NpfKOY3EXLW6w==
X-Received: by 2002:a67:db0b:: with SMTP id z11mr11022794vsj.21.1610731474737;
        Fri, 15 Jan 2021 09:24:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:25d1:: with SMTP id y17ls750024uan.9.gmail; Fri, 15 Jan
 2021 09:24:34 -0800 (PST)
X-Received: by 2002:ab0:3894:: with SMTP id z20mr10445361uav.82.1610731474310;
        Fri, 15 Jan 2021 09:24:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610731474; cv=none;
        d=google.com; s=arc-20160816;
        b=I08sa6gkl3+41eSFTpvzVqGOs0yGpE89o1As6Ud9j1V1FbbCSBfCOREp5uHiSPGO3G
         Ni3UZimr2TheXt4PXcLTHqUwT3dpdwkXlnUw4Oel5uVLTFi61bEO+AcV2jnPiF4G7vZg
         fh2akKDEuP7a6+IgeNFa4xaeoHlfZbfUgpb1aysLIeHnoHLA0OuVo7+/z2H5SE+fbxkT
         x8heYemsUWigub5/TX26BDWl1C7nEFvqcM7JVTEVomYLaKPLjBaUr/HWRDu1Gw3yndqz
         sWUUjoxTQromw8vZyISujBYr9XHsOgjHRoj1HmuNGo9muFF63IV0yZQqTxgYym25TwrM
         ve9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6/oQc+fGp9Tgi9OIr+D+9WYXKC5p7WbIvQ4IDqg8DjM=;
        b=0kmiEKHF34uzsQCNQ10E0QrdpqDyGVjr31pOSUEYEt9XAJ7xhyBFng9PBabfKYzU1b
         9iyKvkOHy68GW368GhZrRcVFykHjYE/tM2fsle1qfpl6eKiP30cJBnuC4kUijFyOKaiE
         GTrBtjIh8X2ejgVuwY6cx47DbKNspRvPTyUdRMotnhkz92dTnPw7mjtL23/J8XQ4QqJ5
         LJmppJJmlrPzMsltBZPsFdANUaNrrcPic4MZh5hd7qRCeTrN+0MumtJHIv8r/ibCIS5T
         wIM2+b6cHUCXBAEFCbx1j1RwhIgQMx3/AwXKRVhPN7q3hdjEdindALFZEA6bzi2TllRV
         a/9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SLvWXReU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id n3si686746uad.0.2021.01.15.09.24.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:24:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id v1so5437532pjr.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:24:34 -0800 (PST)
X-Received: by 2002:a17:90b:1087:: with SMTP id gj7mr11401064pjb.41.1610731473330;
 Fri, 15 Jan 2021 09:24:33 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <b75320408b90f18e369a464c446b6969c2afb06c.1610652890.git.andreyknvl@google.com>
 <YAGVqisrGwZfRRQU@elver.google.com> <CAG_fn=XnF1GmOsJbHNtH0nn3yXq5bghYDXDkeqawEXTzom8+sg@mail.gmail.com>
In-Reply-To: <CAG_fn=XnF1GmOsJbHNtH0nn3yXq5bghYDXDkeqawEXTzom8+sg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 18:24:22 +0100
Message-ID: <CAAeHK+ykOaVSETLAZD_EzFf9Q=REGTMfwQtEEVMg-NE62EGogg@mail.gmail.com>
Subject: Re: [PATCH v3 14/15] kasan: add a test for kmem_cache_alloc/free_bulk
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SLvWXReU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034
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

On Fri, Jan 15, 2021 at 2:49 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Fri, Jan 15, 2021 at 2:16 PM Marco Elver <elver@google.com> wrote:
> >
> > On Thu, Jan 14, 2021 at 08:36PM +0100, Andrey Konovalov wrote:
> > > Add a test for kmem_cache_alloc/free_bulk to make sure there are no
> > > false-positives when these functions are used.
> > >
> > > Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> (see a nit below)
>
> > > +     cache = kmem_cache_create("test_cache", size, 0, 0, NULL);
> Looks like there's a tab between "test_cache" and size, please double-check.

Indeed, thanks for noticing! Will fix.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BykOaVSETLAZD_EzFf9Q%3DREGTMfwQtEEVMg-NE62EGogg%40mail.gmail.com.
