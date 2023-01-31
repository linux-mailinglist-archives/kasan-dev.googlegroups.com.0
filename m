Return-Path: <kasan-dev+bncBDW2JDUY5AORBN6K4WPAMGQEQUDPF7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 43C4A6835E6
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 20:00:09 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-163c08ab42esf2541528fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:00:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191607; cv=pass;
        d=google.com; s=arc-20160816;
        b=DXviIYDVG7zCOgGdg/Ga2Vg/GEmjESZ99WE0rvqXXjuYoQ9F1NmmVMZVDt32ym55nH
         COFm1p0OhiYKxVnRo0z0p4mYK9DBOiRteKSGiEHRCvJxr149BrFCR3LcgL5cVGjO18nR
         0eVQfZahjNpB7/MF5DL/mWO4g2YabrBoX8I7SVLDaTbXsnDZdtYnFlk7lsIBeYUtCT3F
         Cv+Geo759hBnY02C5lxI93GQCPPU1LSm6r25ntXZiSd5uB2x0V6E4FT2Wp/ZAkBxb+mY
         VEgSAD9JJRU5WGe8MyiOKaIZHlAHUgf4Na0qAJIBqW8n7P7S2dM8GfZl8oc1dwOqgPMk
         mj7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=IkHfTs8IQ2tot3hBeFH35HRaKD1Uva8Plesmpt+IDoY=;
        b=jPVHh9jqnmHn9Pz/mQK0r7dxpOrrVLH5Gmpxa0ui31qfgI7a/SzseiDUn4qP0ux6fe
         30PUBFESPbtN4jL0TX+FxcQavGhfQOyHtX46CPAW/hUdsZHvgdZSsvW04TH/DbkNcpUg
         Cbj1qiqUOqgkRvaKXJQCwt+C+IvnumzliuwMSss6u5RIjBmsfRA2x8lLZv5tB+GUdGdA
         0ND/8WkGjxucV24vd62G/8+T6poyTENPfhxrAnaC+quR4wyFS6veRhRa/aZBIR37F8BD
         c9UFiEaSMpFq8l18hj+GHtSfRTnTXbGJgCHL/2v1qkTAUAjZ+GCnl/NMriugs4R76MPV
         TGlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kzhGg2/m";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IkHfTs8IQ2tot3hBeFH35HRaKD1Uva8Plesmpt+IDoY=;
        b=swVHZT8aMxTOc+GhuyGqBiZL33MmDxRnZEnVTgyrw6PbT4cIa/b/zlkOvYWutWrsPA
         ED9J47yWBK7sAl73W1AtOtmaV+Z6+UAT91BzPFKI4NK0ozLgLxmLCQm1SaLexQR5tXLj
         Cf9WNhvXpbIioTi+2sDB2zqnNoMF9zYgR6w4V3HFFUg2rZi6Zu/G35DGcMcuHNBUciq6
         OmVSa+ltmTM5QLXk4yYJcv2WDqr1LQOxWZK8P7xve3IJxRGTymeFp1A/jItrGExKBLwc
         KFMjZ0PH5I5xC7o6jgaH62vYLX3xMrOK4ogcPXmBbL9LnKYODVb85qAnbTpE6rC8HSqM
         OI8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=IkHfTs8IQ2tot3hBeFH35HRaKD1Uva8Plesmpt+IDoY=;
        b=IdMveADNezmQXCw8ny7QnVs+ET3zoPeEd/HpyVqW3epXgBCl26RfEhlv//HeRTaiYY
         E+VOjD7R80fkZtnqM2eh4Bn+BJL/u50oehw2laNZtd57t4TudylIYWS9Oa/ETpbOFeK+
         OMQMhHOsEfuHI/dQiPALZjE0qJ1/jvOk6pl7RKMiwwWp1w7p7E1bRD8Lo7VZm2e9hIpN
         wVOeEwoNcY07dNl0AsyFt5GzqkzC3FJIxZDTKlnvty9IkAbUvnyN4atZ1Y02zaecWYef
         j0Usl3xngJ/N/Dseh0F5fvzCxt4SvrwgIk0ffaKnFK7Mv1tl/bEISTx0lIbx50L2j++7
         M2ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IkHfTs8IQ2tot3hBeFH35HRaKD1Uva8Plesmpt+IDoY=;
        b=P5WO/lDrMLkhKxcXtnV+rZ/yEnJAPokIKNa/rJBQspE77mfrM+5JCUW0Yjum6Mrm2p
         hu78o0cx5h8VuWU6mNcZIx41vh50y8fzbWDVimyQHxVhWOVWEGAFoSY1FzudqW3zWotw
         l5rCfFc0QCIwlF9uOCuraU17NQJd6LeZL9KLFthPVzhSLNUNuDVBwFuK+i11C/uM7oiA
         9+9IT8O9a3gL1kN1fnOZXhi/wvvAEvDMcAdDk4w/9YJ7ZbMfA1+4DGeJyQ7O+sKO7dO8
         1J1Eub46TcA2PBHCOUn8AByQTk0enS6ntpLGVfxet8fJ7pc96YdQNbKl/Ct5HHREby5b
         6fPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV154xi4yOmYJsTm2pGx+gVifat7jEASLo96WouZKk/rhfGjOca
	CHxZYNUL/iL7bWK+/IdN8AY=
X-Google-Smtp-Source: AK7set9tuIDdvUsuiCXa0eOZrcX2FmnamvOsInC+8X0G7Stdu4NnDg9k/yUEj2qrH/mpIjmAkXz1Sg==
X-Received: by 2002:a54:4014:0:b0:378:721e:ab8a with SMTP id x20-20020a544014000000b00378721eab8amr362159oie.127.1675191607646;
        Tue, 31 Jan 2023 11:00:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b96:b0:163:2c39:4a44 with SMTP id
 lg22-20020a0568700b9600b001632c394a44ls7064483oab.8.-pod-prod-gmail; Tue, 31
 Jan 2023 11:00:07 -0800 (PST)
X-Received: by 2002:a05:6870:b28f:b0:163:4e1c:f55d with SMTP id c15-20020a056870b28f00b001634e1cf55dmr11890204oao.50.1675191607251;
        Tue, 31 Jan 2023 11:00:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191607; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJ9EWZ46399pFNeO82GdA7OZOh2r6XUdJOC6jb6q5We5VmqAAq1rxrRwOViHhruOc7
         am63KuMvYLGjkI016JusEK42oD3dGnqt/2ISZqIKciTfurzGf9qZx88JACKrnzla3DaG
         PORuDnY9JfqeFAW8zdRfKyfNa2H0Z6wqCF5IFSxmpWQWPCmxCVNdd95+rP7p1cvduw6r
         OMaX2EOSVe3uY2GRqpzIqL5HcnJzlppV4l20TbOsrjJAeGbL2uLpYYStxqCZBgyRSAMz
         3CYHytv8pbgoWFdoErNZOQlUF5lKUYZr3wMU6tDYutY+r5QHTMHiu5+PEEQnSrAg+54A
         w9nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w3/WE1wMhkpHW4nP7y1SsKn66zt1nWRGpIbsLu/1uw8=;
        b=tUr9t50a/QE71J3/EG1NsGE7QmOA4R1WFtWruSCdMGgXebt19teyumVXCqg4tYsLoJ
         /nkPgu8q2qd9j7Vbg7k89kgfjI31rwRsZeIm3VTzyKddaPdC0B+DNWgVx03etkPJt/2Z
         kxREucXHvpTS5cpauIGLDJbofeAVuBqL3fo0siTBOVLVNzGoKH+7MCwJIZgVjfCFDCJb
         WaDG5sCVzT0aH2OD5ZoseAJX+xo3UWMnFcvdf899nRAjsnvx9q/svAcSu8in+kz08Nlp
         fCM4e+Fv+fH2Hy30E+bU4nrPWGMyDN++E8uEJbluvD/GBc4tk0RARvG+h0IOy5yLBAt8
         RnEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kzhGg2/m";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id hg10-20020a056870790a00b0014f9cc82408si1494456oab.5.2023.01.31.11.00.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 11:00:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id g9so10931176pfo.5
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 11:00:07 -0800 (PST)
X-Received: by 2002:a63:f657:0:b0:477:a33f:4858 with SMTP id
 u23-20020a63f657000000b00477a33f4858mr6531588pgj.76.1675191606922; Tue, 31
 Jan 2023 11:00:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
 <CAG_fn=VO0iO4+EuwDR0bKP-4om9_Afir3fY6CExKGRNad+uPLA@mail.gmail.com>
In-Reply-To: <CAG_fn=VO0iO4+EuwDR0bKP-4om9_Afir3fY6CExKGRNad+uPLA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 19:59:55 +0100
Message-ID: <CA+fCnZfjbHaS9So6gO_3ZkgLazJXYAtw-PNV5C0xhAjzVE3p-Q@mail.gmail.com>
Subject: Re: [PATCH 01/18] lib/stackdepot: fix setting next_slab_inited in init_stack_slab
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="kzhGg2/m";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, Jan 31, 2023 at 10:30 AM Alexander Potapenko <glider@google.com> wrote:
>
> Wait, I think there's a problem here.
>
> > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > index 79e894cf8406..0eed9bbcf23e 100644
> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -105,12 +105,13 @@ static bool init_stack_slab(void **prealloc)
> >                 if (depot_index + 1 < STACK_ALLOC_MAX_SLABS) {
> If we get to this branch, but the condition is false, this means that:
>  - next_slab_inited == 0
>  - depot_index == STACK_ALLOC_MAX_SLABS+1
>  - stack_slabs[depot_index] != NULL.
>
> So stack_slabs[] is at full capacity, but upon leaving
> init_stack_slab() we'll always keep next_slab_inited==0.
>
> Now every time __stack_depot_save() is called for a known stack trace,
> it will preallocate 1<<STACK_ALLOC_ORDER pages (because
> next_slab_inited==0), then find the stack trace id in the hash, then
> pass the preallocated pages to init_stack_slab(), which will not
> change the value of next_slab_inited.
> Then the preallocated pages will be freed, and next time
> __stack_depot_save() is called they'll be allocated again.

Ah, right, missed that.

What do you think about renaming next_slab_inited to
next_slab_required and inverting the used values (0/1 -> 1/0)? This
would make this part of code less confusing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfjbHaS9So6gO_3ZkgLazJXYAtw-PNV5C0xhAjzVE3p-Q%40mail.gmail.com.
