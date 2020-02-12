Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTEXR7ZAKGQEJUUMPIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 1989D15A56F
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 10:56:29 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id y125sf1659587wmg.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 01:56:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581501389; cv=pass;
        d=google.com; s=arc-20160816;
        b=YbIZQXFrJTfMS3Pd9OqACNB7DjNHPXGioV36kp8POE4y1X661t9LrVxn+GTVvtEkcC
         cAyeqAv7j8pYxnaJhs5fRujVCcR/6gDby8+6ua1PLvVb446c1azjmsRsb6cV4RrM0KIx
         RsCxDiP0WQXo7x3+m1Vm2Yt8xNQ4f2KbAfu11qHtp23oh6TIuKY1moeXTZ+BgKqc5fab
         SOFOIwmFJZ9fzSOMe23O1ZES/j/fP2HT2Ay4fJWo1R/mUBQXJbv3JJfiRRn2zHilZEcl
         TiuHEz6gImUJesiFfMCD+2DldLR/Dd1c3r5SzOD5YlLmce+peMraAIV6v+8jgvBZwkMQ
         zeqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hr1vac8FtpJRTJQ6jxoIRUNMnJjg1xpQ8OqtFNE7eK4=;
        b=q6sQk1ZRo4nyck6AYznn3WuZgWcWc7+JIsyLE8TouDmaMgBaIosgGa3idp5OkANoO5
         8nzLGpwaPTPyraEBNmijFJWubQIhd1BYvnC82MiXPAb9pVBiFD52YCz3vvA+V7y2o0w/
         0NqQMQAQUiVkdpy2or7xxLS29VU0VDQfUvHl85eZJ3b1v0+Kt/VVpDyhhrycujaT9Sss
         8Jnnb+14kDZzjSadyvMeV+nX9fKvwZ9NhboTTSmHeJolFtCBRFj4P1CMKGZr+vB5CWm8
         FH+/0l4w2qC4glPauzEeP3pJYEyQfRvi0hKnOKwuSkH7A81Mi8cm0wB7OeWPh/rnJ/qz
         yuvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vSzKAPAl;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hr1vac8FtpJRTJQ6jxoIRUNMnJjg1xpQ8OqtFNE7eK4=;
        b=MVUARPqL2+8b4uiQvz9547Q92pQLuzInktzAm4II5ABF9wNr5tCEeaTVQAOHBLzwZD
         Q1tRORB5AqKkH6OpZJYTWp5FP1+hE9sC3jqMq30i5GRDty/s3+rBVYSIcbvwOotcUMvO
         xAl+PFVdVUIjGDiRRV1SQ8U7MNJjEIw1sfdIvdVNNpUfS4/nI3KksCMGg+i83fvr5iqj
         0ukzQq9YfHYJX8/CiH8ZzNyArmve4cZKLg4IBoAjY/d4sezvIbeQUGQqyBDngzqsI0KY
         D0vp1ub47NX8QiFAKDc8jXk/JAwB83Y2fVFT8ovxMz+7/59r0Pf3C4+Dl0+TYX7xXg0A
         P26Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hr1vac8FtpJRTJQ6jxoIRUNMnJjg1xpQ8OqtFNE7eK4=;
        b=d5JlF8StVhbTybsvY9ZHUqs/ZS03pvn/3Fk9yO9mTt0pfcACSyz1ZqMioCt4di8CeX
         EoGo4ow7nPL81gYkpfyOehXphUT4LdrmnfPykx3bImDdC4lzFxYvRe+PnESTFemp88e6
         a7JOVjkakDjdSfgh3ni9qf6KqEHtUeUcmjPgK5zGA7n9E9vVNgo83k3n0GqNouX0tIiQ
         vA9M1IxgpIA2tAeww9JazJTjLn+wMvQCo+NvNk082wllFpa6esSMT6te/9UWRks4DH0x
         qScWwbEDoJH3sF/6Baw6SQvvVM6FP7AtNYmcOkhvmduCKgIgdi/J222f+BXJrmugVKp+
         UuEw==
X-Gm-Message-State: APjAAAWsdLOBsjJglit2X3Pmh/8+e1ula3uwQdb9ITIViHfSS37TInQ5
	GH5RmgA0+osEU/Q+A1yKDEo=
X-Google-Smtp-Source: APXvYqzJqUrmSEUrvncXTMI2gZtHxQxCe8V5KxcaZvrZhVgQp/fMHC7ptpapwfRewDwew0XPk2xBQA==
X-Received: by 2002:a7b:c450:: with SMTP id l16mr11255702wmi.166.1581501388859;
        Wed, 12 Feb 2020 01:56:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4141:: with SMTP id c1ls10232353wrq.8.gmail; Wed, 12 Feb
 2020 01:56:28 -0800 (PST)
X-Received: by 2002:a5d:5403:: with SMTP id g3mr15118250wrv.302.1581501388347;
        Wed, 12 Feb 2020 01:56:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581501388; cv=none;
        d=google.com; s=arc-20160816;
        b=lgpSnY45Hbt75/lEsMuiMn1Pbp95y2Z7Mf3GPsOnCijShgUr9m3I4S7r0JSINcDa9O
         B360fXHJDpKjXd7Sv2oinnVs0iuM72I0IbWsTxCaaT8WBWQuJzBQL2ZwaIHpUU0CtAfL
         qAA2sahrHilA7Qi5/w+Oe7Kf/FyXe1cI1kn+UeHwze9c4x2k5knOpMdjKDhnYnlMTea4
         tvAMRGjkiTmIJLetB6BX9ZWNuga8LZYPIoznCr9HjBBFohBulcfgyvNeS7DE6UN7l4wb
         1QD5ilpoS+RU9g4ZxQ60d6/PvwMSLMFEeCEP/AwJKc2mcrVYtuBc71XawLDHhookdVi0
         KpKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TQ1zZ0ymxed3qDUIKzHztDCn/dmuH3K9mD8Ys8Cv5Zg=;
        b=usaJQN28sRv1tUHWvnMnRJi61cfiILCtZ66xRtHVSzANm8W+mjl2CmfWBtIrRoADS5
         8td9IAZnY8y3w3g5oWTmiWoF5g2CxI9gQTC0s5G4Up9QHuFA7+QjRXwJ6po+1FYx+Aqd
         Y8MVUMR4b99+mYqGvmH2PoGgSVNHBJDtv65hYkPFpgGgp5W8VgTUqsoASbUUpfh23wga
         TQG12DT4J0k93FKZaevD9g4S3sel436ZgNz4vXwRMLXx2vSQfa1Mie1WBf0B50uAJz8j
         yDKXgZU66Os1TNEoU2HhTQNyAsEicFdPOm1g5fYLw2uCeIuw/vFnAjTCXu17L5qyI/Ul
         yXIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vSzKAPAl;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id e21si276671wme.1.2020.02.12.01.56.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 01:56:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id s144so4284630wme.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 01:56:28 -0800 (PST)
X-Received: by 2002:a1c:9e13:: with SMTP id h19mr12083830wme.21.1581501387602;
 Wed, 12 Feb 2020 01:56:27 -0800 (PST)
MIME-Version: 1.0
References: <1581501228-5393-1-git-send-email-wang.yi59@zte.com.cn>
In-Reply-To: <1581501228-5393-1-git-send-email-wang.yi59@zte.com.cn>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2020 10:56:16 +0100
Message-ID: <CAG_fn=UGmEMyjASasZTK3cXAZzJ4tb9wCGsW1FoA+kPNJiW1Gw@mail.gmail.com>
Subject: Re: [PATCH] lib: Use kzalloc() instead of kmalloc() with flag GFP_ZERO.
To: Yi Wang <wang.yi59@zte.com.cn>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	xue.zhihong@zte.com.cn, wang.liang82@zte.com.cn, 
	Huang Zijiang <huang.zijiang@zte.com.cn>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vSzKAPAl;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Feb 12, 2020 at 10:54 AM Yi Wang <wang.yi59@zte.com.cn> wrote:
>
> From: Huang Zijiang <huang.zijiang@zte.com.cn>
>
> Use kzalloc instead of manually setting kmalloc
> with flag GFP_ZERO since kzalloc sets allocated memory
> to zero.
>
> Change in v2:
>     add indation
>
> Signed-off-by: Huang Zijiang <huang.zijiang@zte.com.cn>
> Signed-off-by: Yi Wang <wang.yi59@zte.com.cn>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
>  lib/test_kasan.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 328d33b..79be158 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -599,7 +599,7 @@ static noinline void __init kasan_memchr(void)
>         size_t size =3D 24;
>
>         pr_info("out-of-bounds in memchr\n");
> -       ptr =3D kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> +       ptr =3D kzalloc(size, GFP_KERNEL);
>         if (!ptr)
>                 return;
>
> @@ -614,7 +614,7 @@ static noinline void __init kasan_memcmp(void)
>         int arr[9];
>
>         pr_info("out-of-bounds in memcmp\n");
> -       ptr =3D kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> +       ptr =3D kzalloc(size, GFP_KERNEL);
>         if (!ptr)
>                 return;
>
> @@ -629,7 +629,7 @@ static noinline void __init kasan_strings(void)
>         size_t size =3D 24;
>
>         pr_info("use-after-free in strchr\n");
> -       ptr =3D kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> +       ptr =3D kzalloc(size, GFP_KERNEL);
>         if (!ptr)
>                 return;
>
> --
> 1.9.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/1581501228-5393-1-git-send-email-wang.yi59%40zte.com.cn.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUGmEMyjASasZTK3cXAZzJ4tb9wCGsW1FoA%2BkPNJiW1Gw%40mail.gm=
ail.com.
