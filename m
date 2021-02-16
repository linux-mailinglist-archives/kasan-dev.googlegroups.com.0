Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTO7V6AQMGQEYF3NQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8938E31CDCA
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 17:16:14 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id 194sf8311219ybl.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 08:16:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613492173; cv=pass;
        d=google.com; s=arc-20160816;
        b=HVIWsAOIRNrnSGqEMiPX7/ESqotFP1r+bWj5Cmxf/N3diDgSrlqT6wFqmC5uV8OPZe
         tcsGPhQxomgjLj9YS+J4dzgW3+ilNLZ1PycTBGL8AHFTu/Du4eqS1IbHcJCB4zNN1+YI
         4QoceGG0kOpmEczb1Z7NBl0Z5CvJkVKzkuO64hEih4g6BROi8No5F2gN/e1vu1mmeoDs
         cgcRPZx7qnQCJeOjuJNtrIfM89RigjLHaeoE4iYqV39ehTbIfk4FZ/g/2/JGnsnijGkl
         OCI/vKe3PcXoKs6Ly+0LRAoO5TeBF7DirN6ivJFsT5ZaRaN1A4LFpCwjvCt1uz2vU3Og
         4FhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YkZvchDUrF7/Pw3Rv5RQBl69Px8FSwScFoHpKoImFyI=;
        b=kid+W/rqr91CTmBAk9pLEBxtMG0iVhkQMYLXlg3sqp+KKPq08DRiQ3T68BhUIsxaVo
         yM5kJDvjR8Wsa+mFOTO4qkQxkTdfatSH9bkhQf1c/JhbALJTBzfy+l0TybqbLtxE2ItX
         N7yEP8oMdfY8qGCJ/14fAewVXNXUcVHHVWrZiPuLPskNeS/0k8E0r9mp11S/kRDFwHgR
         +wbSQ6L7+c352Qca1+Q+Nxald2doMHsOiO7NOtfSoNGhfct+COKkv1tdqcxh2FRg6cw7
         hGIRjHafEoGUP42tDBcoy8yaMLXKmg/VD5lInhUSHMbdaaOl+7sZ8IqT2jb3vAB6K81d
         HJZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DLNDB1jX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YkZvchDUrF7/Pw3Rv5RQBl69Px8FSwScFoHpKoImFyI=;
        b=O+M/OOpNonT9OcPc0AQKN8H2X9b/2RaFKafOPrH+cIfB8divv77ip+Xpp0RxY5glDC
         r/fXLCDCDOgxiyaDcPcIsy3Blxq/OUAixEM/Wdcc9t10av6sKbumQ4lBm0+k6xvIRAPZ
         N5eqQWCTcIX++ali27mU8CHCAFhBamv0H+iR5FEVZrX2rDSUs3zErG5rbA1nq8XB50wz
         bLJYwYgESLa+NgG3Drbft2q+xY48Uakn/+alkiKF0JB9AMEO+jh4k1DBGf3LHgo4lv9U
         BI/wMEPRDngzBHRp86PGmjunh7NkCcl6104LjtYv2Ub2opwtzpaWWGAuWPsNNujRZoYS
         wPnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YkZvchDUrF7/Pw3Rv5RQBl69Px8FSwScFoHpKoImFyI=;
        b=fUd95d56PFBeWT8dYA4n9nW1wocSr7QAP4H65w3eg15K+FHbqevuQVglG5b4JMkxpI
         OIe9GSDOv381ejnv1+TD/ARPMl36Ds726V1My/kFbkA1f8Owtx7F5aoTXDiNreV8myjq
         FchCsLFFvaOh9xelyumr2Hq8szYVP7MRqjcpZIvURkpWMSDXjhK28DEuO7INRE3fxeiW
         HHYn7gg4WxKrbu02eW4x8RSG9/0rmFSE8IOAdxhZHcDl0jSYfMXAPePDz8nRGjirHvNA
         9Z4L+aN3/Htd8KllyKSQaSfK2kXsINYaZ9W502eHSiIeXURZfTYeJubxiPm3sIquFPRo
         ZmNQ==
X-Gm-Message-State: AOAM532ChD4bTbSkbSm2Kpfv8aQxwdgPSSoWxZ24Rs89D/F2TlHa4d5U
	5duyFUR4gSD4UzqITIw8gcI=
X-Google-Smtp-Source: ABdhPJzFdt4RLAbI+zUuyYBaFMIOseDpMzJDNOmMPDm6QnEYRZpBRSylE4Ry7xUs30FiVT9T4zlVDg==
X-Received: by 2002:a25:374a:: with SMTP id e71mr29256637yba.1.1613492173161;
        Tue, 16 Feb 2021 08:16:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bc4c:: with SMTP id d12ls9394727ybk.0.gmail; Tue, 16 Feb
 2021 08:16:12 -0800 (PST)
X-Received: by 2002:a25:50d8:: with SMTP id e207mr27360377ybb.56.1613492172801;
        Tue, 16 Feb 2021 08:16:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613492172; cv=none;
        d=google.com; s=arc-20160816;
        b=r1HJwx66FHLvMt51anXAf1wadmYsM97Z1zjhuM2ZLZ/vWJmFd+YwD01yZi6tcbOmN4
         QSgcuuh59BK9I/LjMzQlmgpRAVx+QKUehRnycPKOg+4Zzpn79MA4KO1nOcrBTVhKqnnU
         N7DCsdfaMSXwicSbIhDxvi95bR7JwWK/pC5hSVtrXdVNPPb8ffq7Qo7B8sHPW2NRRuEo
         vS/2JzgfsOkLcR15aUHApRkt+GruV6NA5l12xYNEvmQbo9iFXJ3HgnuhWgw2+iZ2IIAM
         +9QaH5j8ULIVcTOjVtSrRd0o9Jpbu8T1KFOQ3AlaLwFf+FLglvZacXpimU4dQHCqYU+g
         /USg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AZezvwgrcIwSh/WVrbJ6p/iPLpH0oWCn2iL31GgwM38=;
        b=Yucx/8p80y3Oet+UqUJ8SKzTeQWkJzSR95fgrvPrJ16ZaMBqCf709QVR8e5BgCB6Q4
         JNHaAAVeZa5Tc/OntzTCytxqTUVi5m2JOT5qUrhA3PafHj4Rtkfxi86JO6sEygO7OTHC
         h1XlZ0j+502LNab2x6W535znqXnKQ61T1ek2s0j0pctpi1sMGNxC1IdyALXtF6KG/imm
         vVTl3uYfZWAX4ZDyBLO+vu4XAn9Z5VsIFYxN9in3Yy6N9PG060tk/QtsksLMIe6daUge
         /0hCCIUu/9DT0RWhqrvxFRbfQe794rs9AxfbqJXykcyp/qVwBfSGWGgiBUB/VV9Mavzg
         ZSyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DLNDB1jX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id i194si1399942yba.2.2021.02.16.08.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Feb 2021 08:16:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id f8so4150906plg.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Feb 2021 08:16:12 -0800 (PST)
X-Received: by 2002:a17:90a:de8d:: with SMTP id n13mr4784697pjv.136.1613492171671;
 Tue, 16 Feb 2021 08:16:11 -0800 (PST)
MIME-Version: 1.0
References: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
 <CAAeHK+z1k3Y3qQWwYWa5ZuZdYtR+sqF9CSauoeLfGqR=qcdyDw@mail.gmail.com> <3ab303b3-1488-4c47-91db-248138ab5541n@googlegroups.com>
In-Reply-To: <3ab303b3-1488-4c47-91db-248138ab5541n@googlegroups.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Feb 2021 17:16:01 +0100
Message-ID: <CAAeHK+z2FS0tZxPs73oJBX80mRkLWKyguT72bv2XZ9Db57NCrg@mail.gmail.com>
Subject: Re: __asan_register_globals with out-of-tree modules
To: Shahbaz Ali <shbaz.ali@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DLNDB1jX;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::636
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

On Tue, Feb 16, 2021 at 5:02 PM Shahbaz Ali <shbaz.ali@gmail.com> wrote:
>
> Thanks Andre,
>
> Unfortunately, due to the nature of the system, I do not have an easy option to update it other than apply the 4.9 LTS patches (which I have done already).
>
> Do you think it'd be possible for me to backport KASAN from the current version?

You can try backporting KASAN patches that mention changing global
variables handling, maybe that would help.

Backporting all KASAN patches is possible, but that's a lot of work. I
backported KASAN to the 4.9 Android common kernel two years ago, the
patches are here:

https://github.com/xairy/kernel-sanitizers/tree/android-4.9-kasan

But there have been a number of changes since then.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz2FS0tZxPs73oJBX80mRkLWKyguT72bv2XZ9Db57NCrg%40mail.gmail.com.
