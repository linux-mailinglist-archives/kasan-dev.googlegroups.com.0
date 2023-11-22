Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSGM7GVAMGQEIP47DRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 88F5A7F51C4
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 21:36:26 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-5c1af03481bsf172232a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 12:36:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700685385; cv=pass;
        d=google.com; s=arc-20160816;
        b=MNalxA7anifK/dfV3U/170LpsisNGV4OHrakid+kXlsbS6zWQSVKyUbYhmRTiHbGA9
         vWr5YhDZRG6NsfQCMQaOPdWNnW4K2kXWzgkKi4y5C2J3ysCMiFNlLh1hZoSKoJP6h9vz
         yJX+XFQxl4GvafduNkFdRN88XnZBg9zG5lmIz3Q49vvCewDFxUaWEOybrxOcdKURiurS
         +OBqe+w5bAVCjK3rvRzaR8GsNXkDIyxH+u4cHw4UFtKRwQBOqGlWpJkNRuV/kwzh7tlq
         6fEvv+aw0gj59Y9LHyIpxZrFplgw7s970xi+aq1Ii02EjVxE8sQk/TtPqLnEvu8kCPLu
         RLTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8zs4jFiD1xDgNUBULs3lUt/UM/j4+P0vxN2hYvrOxyk=;
        fh=LubqLcB7navSDf0Nt52CtUnJ6CDCRU0TM1wxMFuJtiQ=;
        b=GsfRFArxGj3ODZsgnV0H8FuxTNwAlNjGHGUfIq5p8l3pBOAcDyJWcQfuy9If/DDXDH
         dPZYjl357ZafAgQrAYtRoDoO5UnUC8cW+eLbq/d5VQ0nlBF4Tkqt5v8ZY5+ccty1uktv
         1PF1POVKjZQPqNzT52jgIC08EKcHAhmpJeeVjWvOLTlPYwuPk+4V0VLWoiYN+IaA4SUS
         y9ZbyhX1V4Owk/JqJlCpFIDzZ8hNTlnsYSZsiiICVRkx0K8yW1+0SoM+VWJGOOpnmWpX
         Y2Dj1Q+78KnNxlN08YRy/kM0ylSgy6KWD2CPdHHDOOfv9sdLtBac6UzFj4avD+zQRb6E
         OOtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="MdC0Nty/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700685385; x=1701290185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8zs4jFiD1xDgNUBULs3lUt/UM/j4+P0vxN2hYvrOxyk=;
        b=IxCdE0CXZD2mUr9exLb4hij3XWBXP21JiBmVeopzrbIizXPwvKJBHJOW/Y1Er4BPZh
         tCBAyLHxsjt3iC1OFQF0HFXEz/CIgnzCUxT2qS3LSbaYuTQ5H6g1lfbUj9cB3/ot2tN6
         cvRlyaVmM0meHPAn7EhdWWRlhoXBwVNMX4pxa1RH5RMMfQVHbJlLCd4mWM+ryu8zbPt+
         yjYHr/CzB6hEeZNDz9G2VC8ixFonX1jTSAszOFH4dPv369Nzjl3zjpHeaMs4M6cd9ukB
         NTYmL4RqzdnS37FKkuahdozb1UEuNeKpWWCBWzqDbI+TMuPCHKx/0ME9aXtr21P8MzsB
         xHSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700685385; x=1701290185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8zs4jFiD1xDgNUBULs3lUt/UM/j4+P0vxN2hYvrOxyk=;
        b=sY29FIRUTiLOQR5OGtVUoRnAGccdS8rg1KitPDNwBxQvnhhJm/5aW5903pggfgcp5/
         aWsm0wJfnsKjeuTbxNQEBZei6laryMIkwQgRsq+PujKFQ0w1scga37G00RnBbbtiFYVG
         zc1aHerdzAV/OyqF1e33s0CcH1REboq7UCqX8PAQiLMURjzls2VOyVwNwKGC2glJiHyv
         hGJvmcPr0Xi/cKqLodU1SzwboAggHjh7QvuhKzm5ASC7mrbD4Ydzmg8DRiam490kmrOs
         LmieJ600hUEQPQuUla9wN02KSi/qAzj/YgeNWf7ZEJAvROnKhWe9apH5d2e7LHHSygBJ
         OPpg==
X-Gm-Message-State: AOJu0YxpzOGWQURUDZyAV2tIL+BXHdyunAducfr75mqRFDUBP/t6MPoV
	ep+5V6ghk+5741XqG1FCIck=
X-Google-Smtp-Source: AGHT+IG7Nk1g2FTGpNsBCpZxEl9K+PpPidLB7UrgdZhP8yqYfvZOugQt+q794tabfNwEkab/Ukp0ww==
X-Received: by 2002:a17:902:ee95:b0:1cf:6d67:c3aa with SMTP id a21-20020a170902ee9500b001cf6d67c3aamr3689787pld.40.1700685384742;
        Wed, 22 Nov 2023 12:36:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab8c:b0:1c4:4da1:5c41 with SMTP id
 f12-20020a170902ab8c00b001c44da15c41ls104792plr.1.-pod-prod-09-us; Wed, 22
 Nov 2023 12:36:23 -0800 (PST)
X-Received: by 2002:a17:902:ecc9:b0:1cc:32df:40e7 with SMTP id a9-20020a170902ecc900b001cc32df40e7mr3753501plh.66.1700685383283;
        Wed, 22 Nov 2023 12:36:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700685383; cv=none;
        d=google.com; s=arc-20160816;
        b=ZUiNHMRM8esZjlzGjc3BLCYtfbqOT9i2VhFVa0Ae2tM18OLZhhhDyimbTGNTPUgRxO
         gtCcfMSFREZHGenDxsU7ETodfPo1LSE8Q5vivk4OMZYw1c4DgXxEqCGfMsPjZuzES5ZS
         uHEkfuaenE1t65/rqsj9wPfpIQME+MwVe4n6+AHXlCOKiWPXapz4KO4k6ZrqpyHZ/CXF
         YubHNRPMdvCCI1NuD8WixMu8kKm+QHHv0bRJxqVnz2CIHNECikFS7bfYHnV3ktck/xQi
         ZqcKm0RG6O+LgLCCxpG6Au/f85N3k9vHojbx30l+cLsHEAxaqBI9QbGm1wroo37TlDxA
         Rz/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vkfEHr78Ys9Zl8oeeDr7y3wj216XnJVscyV3Cx1FHDQ=;
        fh=LubqLcB7navSDf0Nt52CtUnJ6CDCRU0TM1wxMFuJtiQ=;
        b=yzWn09QT8So70242UdstVftUfqMXJ8YdkycD6pKx2DKeq6K/sOFfYweDZWtxyKgbqS
         jTBAjxDSLlODb+5FKqLTcykNlFxNW8ZJ3PxMtI7wuucoyJ/mwN0hhuuvJYVVkctx/cXD
         +2dp3wCIM1R/k08qqzS5HXHScN5dbiZyd+l0V+awSOUpMs4E/ULu0Ql0Szg9isQdfjnI
         z0X2uRIf8zjLlyyV/Y4Rca5o+z4IZYLy5xLetlyByTBe2R7UIwDKJpu/DzjBxgz/qyd7
         lFwOg6Zx2ccYCY/Z8WAKIGnuNwrRKwtaMtpZEPF6iOHrDl9ddXhbIbOfrLfzzwnL6xLE
         irlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="MdC0Nty/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92e.google.com (mail-ua1-x92e.google.com. [2607:f8b0:4864:20::92e])
        by gmr-mx.google.com with ESMTPS id f9-20020a170902ce8900b001cc22d403fasi8870plg.8.2023.11.22.12.36.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 12:36:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92e as permitted sender) client-ip=2607:f8b0:4864:20::92e;
Received: by mail-ua1-x92e.google.com with SMTP id a1e0cc1a2514c-7ba170ac211so57376241.2
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 12:36:23 -0800 (PST)
X-Received: by 2002:a1f:4c04:0:b0:4ac:c52d:70f9 with SMTP id
 z4-20020a1f4c04000000b004acc52d70f9mr3579163vka.10.1700685382734; Wed, 22 Nov
 2023 12:36:22 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752A2F21C050D701945B62799BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752A2F21C050D701945B62799BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Nov 2023 21:35:44 +0100
Message-ID: <CANpmjNPvDhyEcc0DdxrL8hVd0rZ-J4k95R5M5AwoeSotg-HCVg@mail.gmail.com>
Subject: Re: [PATCH] kfence: Replace local_clock() with ktime_get_boot_fast_ns()
To: Juntong Deng <juntong.deng@outlook.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="MdC0Nty/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 22 Nov 2023 at 21:01, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> The time obtained by local_clock() is the local CPU time, which may
> drift between CPUs and is not suitable for comparison across CPUs.
>
> It is possible for allocation and free to occur on different CPUs,
> and using local_clock() to record timestamps may cause confusion.

The same problem exists with printk logging.

> ktime_get_boot_fast_ns() is based on clock sources and can be used
> reliably and accurately for comparison across CPUs.

You may be right here, however, the choice of local_clock() was
deliberate: it's the same timestamp source that printk uses.

Also, on systems where there is drift, the arch selects
CONFIG_HAVE_UNSTABLE_SCHED_CLOCK (like on x86) and the drift is
generally bounded.

> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> ---
>  mm/kfence/core.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 3872528d0963..041c03394193 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -295,7 +295,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>         track->num_stack_entries = num_stack_entries;
>         track->pid = task_pid_nr(current);
>         track->cpu = raw_smp_processor_id();
> -       track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
> +       track->ts_nsec = ktime_get_boot_fast_ns();

You have ignored the comment placed here - now it's no longer the same
source as printk timestamps. I think not being able to correlate
information from KFENCE reports with timestamps in lines from printk
is worse.

For now, I have to Nack: Unless you can prove that
ktime_get_boot_fast_ns() can still be correlated with timestamps from
printk timestamps, I think this change only trades one problem for
another.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPvDhyEcc0DdxrL8hVd0rZ-J4k95R5M5AwoeSotg-HCVg%40mail.gmail.com.
