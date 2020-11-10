Return-Path: <kasan-dev+bncBCMIZB7QWENRB2WHVL6QKGQEXZI6QRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F6EC2AD8CF
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 15:30:04 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id u14sf6764463plq.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 06:30:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605018602; cv=pass;
        d=google.com; s=arc-20160816;
        b=gJahKkutHP8+1ECxMdrs8qV+yDuBEWb6QCz7ET+SPw9RcCM8JhfdxVG6415EdUrJak
         pKwHwM2JsIPnPf6aryfKPuUFN0aYAO+3R7wI9JOin07OOb5AqSZEd5uI1NbliXjrnsTa
         Tzrcyo5b9SHxMbSvaUzrPrex70IUO/94g6rZ1+xmCNjtAWwa+1H7+802CQ3FV/36rcok
         I0GTyDsYDo3mVZkMKmNk/LiypcRz+MdrdxLPCC0KtA1IUiht/F3ScyLRiiek5lhKvOX/
         Dm8xx5KkyotwIHY6HaBITcpc1Nh54z9fetmSMvRAjLB7pdYXX7L4m1FY+kNDdDZ3wcJx
         tBuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ANCoaa3dUoJQcUsxYZNQVJZH4Ar/R68XLRtzl3roD7o=;
        b=QJl5ZXq0wZcSfc6yYhgJSGlD6Xa/lnpvQOdvm/ia6fa8G/gb/Py6zCrPWl0QgF7R3r
         ucUmFzh4LOKZ2FIqsmCzXJ5PBk551qW6xBXo6c8Gy/HUCMjx2/Y/IXnkgfqB3KntgwSJ
         xH1OFV1m3hd+kvYccIn7dPrcuMtsX6NXbWNllhwGNo/lP/expv0Ta/mFRevQbMMjGqIF
         I9OIi9T485mqxHWGF+KkQ7nA1O6gbNTropTp0Z4s9cWSbeu14sSqpTyUldg9Y/brPbc7
         pk4lMGPtTOnl9ldS9KfmJq5EMVrw9v85t3tsMic+4Vpn0y9AXEVavBuQz2p53i/eYeHd
         TrQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UJRbT2oG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ANCoaa3dUoJQcUsxYZNQVJZH4Ar/R68XLRtzl3roD7o=;
        b=fni3loigHwsEc8BQXmE6Lw3f7quoS2kLVrRfT/JcmHPkFYnxjcBe6E2LFdbQR0c8cU
         MRFiLuJFpGjXgy7B0OiNgJsKjUEbEcwNzTkX/uzOxQua2wOXmKTIdm6QF1gD5x7n1uBe
         RgR573ZwjlMCi/GLIBzuNoAevkaVVCW6JmyyBu1scECzk+FRHjyxQtVqkOC1TU87ctM1
         iA1CGt3V1Efv0/hsiFA1Ev2Md9PZNFCpemxr9FtjQU+nXnL5a1vPucF9jCUKWsr7pnc8
         1RuoSOorgv1VK76t39IzF+FqpRc8jCVXAgY97fM1wF3QrIpdS8kLeP6Ifqt49xtOxUtS
         kNLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ANCoaa3dUoJQcUsxYZNQVJZH4Ar/R68XLRtzl3roD7o=;
        b=NzMUeG8HxF4RtuxamAxDI2i8IC+nbXYImUwiH0Hy2fjDkygNaZ4qckMFghhEfG+xSa
         mask9tJpX5250nOZWfXS4/Jcxq/Vz/zqy/5Xv+J+cm6uKYvy5CJloEL0qIqst9TjCUMR
         tzXJU7M0uWaE0gTBeIuQAwoPe2h8x/lbYbajZYCF2SjE+ctjayiXYDsJBwPTjYl+pVZq
         fWZDoPj1hQPPHr4IYIuc4R78D84owUkT5v78Nzm53Q5baZudN6s/Iuw8lzYTlouSDTPp
         y8NmWCrPCyEeI1Mpg8GbseTaqojETfvXYNjif9Jv5/dJ88L5SEYS8t3uxVV9+2dgIAKT
         9u6g==
X-Gm-Message-State: AOAM530AN6W7q+9J/x+qlCaBfyyDRY5E2k+jhWd3E32Ki7dJHRGDYcp2
	rSg7pWMy4k9mgkgE7esGCVA=
X-Google-Smtp-Source: ABdhPJyxLUp1JyJf72GwXJ8NCeTDaxzbQNPg1r/3mnTMRIvpE2LhsaZrEt1OWmKoJnkoznWOtRhhFA==
X-Received: by 2002:a17:90a:cf18:: with SMTP id h24mr5697139pju.72.1605018602720;
        Tue, 10 Nov 2020 06:30:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c253:: with SMTP id d19ls2074729pjx.2.canary-gmail;
 Tue, 10 Nov 2020 06:30:02 -0800 (PST)
X-Received: by 2002:a17:90a:e615:: with SMTP id j21mr5536183pjy.74.1605018602228;
        Tue, 10 Nov 2020 06:30:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605018602; cv=none;
        d=google.com; s=arc-20160816;
        b=TmSwCC4kQxOIoGCc8MZLILoUQM80tcfGMjBsDjr5YQ5NOfEdol2uwBUKU3uuUOWyqP
         PywK1YptOL9oaiThoDNPeLhTKg5wc3VmYH38NyD6Gi8x+h5BMa0WA4OoqQ50por9KsyI
         5kCeQSkXMtdq/zm+m1cCp4IN9JEO1ezvHz5OIQqdEaCYkJOY+Xs+hw6HZL3GBETYnoU0
         Gno0dU2tey5Hg/+kJbQR03YCbN/eJbRDP7FPneigSna878G6lj4R3raInfGqWC81l5NJ
         yh6vkoWhJUix3ngvm4xxPa31UiYuoUGfvsWgGytir2fzika569TGzv1GcXgN/d3Z3Fna
         bsyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=B6gXmD/CR29yyroSAzsSWc2TFpJ0GY4uFEljuFgfOKs=;
        b=YDFf7EHU6uhChjkAP+JaqIpDD9tsLPmjHUF7v/ah8LQ2hXBseweyDokRR3NK3Iianv
         eqG9ektX3zzDd3vgxC1FalPfyPTjOAYJ5DCHZQpSl189L8MTEtnwkl+btYPXiWYhDh0p
         NRUAdRHXC/PAiQFlw1hd3LdcsWdSsQwDGpnQv770NNDh4kbX7AYKzP6mBQ4ItJpOW+MY
         4gXha1qe5q3YGGxEldgZDUbeOO1UyXIvMSiOifwcCvthSm4H0Cge3Zk0chpYFwSsW9cv
         mt9xGoKC/zqBSyneZS2cOTD7HPB0eHBVedGtJ2WQyxkbhWWMwtHE4Z7dUsM957plkaWm
         JNqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UJRbT2oG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id k24si268482pjq.2.2020.11.10.06.30.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 06:30:02 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id y11so5499107qvu.10
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 06:30:02 -0800 (PST)
X-Received: by 2002:a05:6214:12ed:: with SMTP id w13mr14999852qvv.23.1605018601573;
 Tue, 10 Nov 2020 06:30:01 -0800 (PST)
MIME-Version: 1.0
References: <34d79b2a-1342-4d5e-8ebc-8c4fd5945f2cn@googlegroups.com>
In-Reply-To: <34d79b2a-1342-4d5e-8ebc-8c4fd5945f2cn@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Nov 2020 15:29:50 +0100
Message-ID: <CACT4Y+a=MGJSkzWOvCSyK1p5JaHkU7RWABOJj=SMrD+DJacieg@mail.gmail.com>
Subject: Re: Continuous KMSAN reports during booting hinders PoC testing
To: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UJRbT2oG;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2d
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Nov 10, 2020 at 11:59 AM mudongl...@gmail.com
<mudongliangabcd@gmail.com> wrote:
>
> Hi all,
>
> when I tried to reproduce the crash(https://syzkaller.appspot.com/bug?id=
=3D3fc6579f907ab3449adb030e8dc65fafdb8e09e4), I found an annoying thing dur=
ing booting of KMSAN-instrumented kernel image - KMSAN keeps reporting seve=
ral uninit-value issues. The issues are in the following:
>
> BUG: KMSAN: uninit-value in unwind_next_frame+0x519/0xf50
> BUG: KMSAN: uninit-value in update_stack_state+0xac7/0xae0
> BUG: KMSAN: uninit-value in __kernel_text_address+0x1b0/0x330
> BUG: KMSAN: uninit-value in arch_stack_walk+0x374/0x3e0
> ...
>
> Even after 20 minutes running, the messages are still printing and QEMU i=
s not ready. I wonder if these messages are false positives or not. And how=
 could I successfully enter the VM and test the provided PoC?
>
> Best regards,
> Dongliang Mu

+kasan-dev
does not seem to be related to syzkaller (to bcc)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Ba%3DMGJSkzWOvCSyK1p5JaHkU7RWABOJj%3DSMrD%2BDJacieg%40mai=
l.gmail.com.
