Return-Path: <kasan-dev+bncBCC5HZGYUYIRBG6ZV6AQMGQEMBKPRHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 238F031CD6F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 17:02:37 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id n9sf4326138oom.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 08:02:37 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pw6r4hMFBQRjv/4qBmxMMOlAHBUxEfm3dRjtNyAi/jo=;
        b=gtDsGA6t8ygCvBX+7USxXYdRkpwpyhNKIiQwNP5kxWaWB2RjvQS1gKrK5BFJAcmQJI
         GS12MocsnnjK6oIsjSMK2NGsMGY7Cacrgz+osNZxwCeL2H6D0S6AYqC/p8fRcqmw8hYR
         xmNLJnF6if0X1/oWXxvh63pcqUdKwP5xJwVqoffF6Kf0M1z6wcegSzssRDnWwbVBon/F
         kXR8mksHZ0tCbnmL4Jr+7kJTFvB4I0VxQKTJiaCcwL7n7kmdeIfzPuiUv0EeSVNawXaN
         EkmHAUKFuqZwkR+mOmrIntr0jAcckofWBdpLtnJfX6XWBkD8ifssLQyBR2DuHr2Ud+ef
         p08Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pw6r4hMFBQRjv/4qBmxMMOlAHBUxEfm3dRjtNyAi/jo=;
        b=FqHwANJSnpNCF1mCewiSzBAlFGnOobmiZHjfyTCdtB/OJKwa7O+CSAtX/Zufc6erXm
         MzfIxtvWzQfFVTNlw80kqBYc1GvZfWz7/LuiXq1GsKXgxezfIEgijACWrwp4euwnQ26Y
         h5tThMLbeEaeOd4a3mtRDEbiA0a4PZ7pBAr+6RAvkEGIyblLH18ipakRNppfaPLWGDSE
         Zkp6bAjLP9yfKo1Lhzep4cZ7eEait3dMhGudKSpeQo/jMXmLdUhABmANkuQP/9jWMS6H
         FgEhlyWHpvS+Ebojvq+MvCMvZTREKu0wWjfmmelQQJ30ztv2LO0nF0vx2GmpQGwtfMbJ
         PZxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Pw6r4hMFBQRjv/4qBmxMMOlAHBUxEfm3dRjtNyAi/jo=;
        b=nagNP5yNyMfyhT8Beu6nRiB/wpVLzB/wHJdJq/yxDhdX5yqADImfhJ9FYoY+kBf+ON
         MgmqS1XMcR4SESl5bCC8glspwUK8gGi74Dy+9K+EHLlXwaeXZxxCIdU48rxDNGMPEWdO
         aSjD0PMhdx/h9BjivDRaXLB8I6dFkAoyGfEojif1p5R/c+9kkaqS1/avsHBrNcG8LQ7c
         qSpYY54OUAk94Dopl7B/kl9pmi0SwXOaJek3IEd7jZfmsMn8TvwuBeaBggLGif9tSXPu
         M0rXabJ7feZiqt3dPEbCBOZg8ec/GYvQvaxC17Es8lHpHhOF20OgrBF2fjMCzoe+F+5L
         yhUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530L2aD8emqmz5MYUCWubie6bK8uJdNMGQoih0hu9hTBNuWCG3bN
	j7F4C2HUjNdIA6xAWMrM3ys=
X-Google-Smtp-Source: ABdhPJxiFm7CKpDu5Qd02YTaz7Xj10CoqV99IfeobvkTEMZipAUaFiI0Mh6JU2YJteKA33/PZJiygQ==
X-Received: by 2002:a9d:a46:: with SMTP id 64mr10304025otg.320.1613491356079;
        Tue, 16 Feb 2021 08:02:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1912:: with SMTP id l18ls4848170oii.1.gmail; Tue, 16 Feb
 2021 08:02:35 -0800 (PST)
X-Received: by 2002:aca:52c3:: with SMTP id g186mr3011476oib.136.1613491355602;
        Tue, 16 Feb 2021 08:02:35 -0800 (PST)
Date: Tue, 16 Feb 2021 08:02:35 -0800 (PST)
From: Shahbaz Ali <shbaz.ali@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <3ab303b3-1488-4c47-91db-248138ab5541n@googlegroups.com>
In-Reply-To: <CAAeHK+z1k3Y3qQWwYWa5ZuZdYtR+sqF9CSauoeLfGqR=qcdyDw@mail.gmail.com>
References: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
 <CAAeHK+z1k3Y3qQWwYWa5ZuZdYtR+sqF9CSauoeLfGqR=qcdyDw@mail.gmail.com>
Subject: Re: __asan_register_globals with out-of-tree modules
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3040_831241574.1613491355117"
X-Original-Sender: shbaz.ali@gmail.com
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

------=_Part_3040_831241574.1613491355117
Content-Type: multipart/alternative; 
	boundary="----=_Part_3041_930532039.1613491355117"

------=_Part_3041_930532039.1613491355117
Content-Type: text/plain; charset="UTF-8"

Thanks Andre,

Unfortunately, due to the nature of the system, I do not have an easy 
option to update it other than apply the 4.9 LTS patches (which I have done 
already).

Do you think it'd be possible for me to backport KASAN from the current 
version?

Shahbaz
On Tuesday, February 16, 2021 at 2:38:10 PM UTC andre...@google.com wrote:

> On Tue, Feb 16, 2021 at 1:40 PM Shahbaz Ali <shba...@gmail.com> wrote:
> >
> > Hi,
> >
> > I am having issues getting kasan working with out-of-tree modules.
> > Always seem to fail during the asan_register_globals step.
> >
> > I have seen and tried suggestions mentioning ABI versions; e.g.
> > https://groups.google.com/g/kasan-dev/c/NkcefkYk3hs/m/74avihf1AwAJ
> >
> > As per suggestions I have tried ABI versions 3/4/5 with no success:
> >
> > Version 5 (default) produces below stacktrace when loading first out of 
> tree module.
> > Version 4 crashes near start of kernel loading with similar trace.
> > Version 3 produces lots of kernel errors.
> >
> > I am on arm aarch64; gcc 6.2
> > Kernel is at patch 4.9.252
>
> Hi Shabhaz,
>
> 4.9 is 4+ years old, there's been hundreds of KASAN changes since
> then. Please try a newer kernel. Preferably, mainline. If it works,
> you can bisect to find a commit that fixes this issue.
>
> Thanks!
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3ab303b3-1488-4c47-91db-248138ab5541n%40googlegroups.com.

------=_Part_3041_930532039.1613491355117
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Thanks Andre,<div><br></div><div>Unfortunately, due to the nature of the sy=
stem, I do not have an easy option to update it other than apply the 4.9 LT=
S patches (which I have done already).</div><div><br></div><div>Do you thin=
k it'd be possible for me to backport KASAN from the current version?</div>=
<div><br></div><div>Shahbaz</div><div class=3D"gmail_quote"><div dir=3D"aut=
o" class=3D"gmail_attr">On Tuesday, February 16, 2021 at 2:38:10 PM UTC and=
re...@google.com wrote:<br/></div><blockquote class=3D"gmail_quote" style=
=3D"margin: 0 0 0 0.8ex; border-left: 1px solid rgb(204, 204, 204); padding=
-left: 1ex;">On Tue, Feb 16, 2021 at 1:40 PM Shahbaz Ali &lt;<a href data-e=
mail-masked rel=3D"nofollow">shba...@gmail.com</a>&gt; wrote:
<br>&gt;
<br>&gt; Hi,
<br>&gt;
<br>&gt; I am having issues getting kasan working with out-of-tree modules.
<br>&gt; Always seem to fail during the asan_register_globals step.
<br>&gt;
<br>&gt; I have seen and tried suggestions mentioning ABI versions; e.g.
<br>&gt; <a href=3D"https://groups.google.com/g/kasan-dev/c/NkcefkYk3hs/m/7=
4avihf1AwAJ" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"htt=
ps://www.google.com/url?hl=3Den&amp;q=3Dhttps://groups.google.com/g/kasan-d=
ev/c/NkcefkYk3hs/m/74avihf1AwAJ&amp;source=3Dgmail&amp;ust=3D16135762463580=
00&amp;usg=3DAFQjCNGhOrYs7y92SraDoBB2U3aeSufB-w">https://groups.google.com/=
g/kasan-dev/c/NkcefkYk3hs/m/74avihf1AwAJ</a>
<br>&gt;
<br>&gt; As per suggestions I have tried ABI versions 3/4/5 with no success=
:
<br>&gt;
<br>&gt; Version 5 (default) produces below stacktrace when loading first o=
ut of tree module.
<br>&gt; Version 4 crashes near start of kernel loading with similar trace.
<br>&gt; Version 3 produces lots of kernel errors.
<br>&gt;
<br>&gt; I am on arm aarch64; gcc 6.2
<br>&gt; Kernel is at patch 4.9.252
<br>
<br>Hi Shabhaz,
<br>
<br>4.9 is 4+ years old, there&#39;s been hundreds of KASAN changes since
<br>then. Please try a newer kernel. Preferably, mainline. If it works,
<br>you can bisect to find a commit that fixes this issue.
<br>
<br>Thanks!
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/3ab303b3-1488-4c47-91db-248138ab5541n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/3ab303b3-1488-4c47-91db-248138ab5541n%40googlegroups.com</a>.<b=
r />

------=_Part_3041_930532039.1613491355117--

------=_Part_3040_831241574.1613491355117--
