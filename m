Return-Path: <kasan-dev+bncBCKMP2VK2UCRB6V44GSAMGQEMJEO5YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4650E73D1B8
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Jun 2023 17:34:20 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-345a459b55bsf3722515ab.1
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jun 2023 08:34:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687707258; cv=pass;
        d=google.com; s=arc-20160816;
        b=FjhU4dJzXm4CGtSSMrvHJxJRKhZs+ve4zDgE8Oaj9MrI3Ij8QI+MJRtGabhJZdhhNm
         wIJH1E//2IXX1U5fVdBg+jj0lKop7yhfEXSPdlHg+Gn9od4LRCXywGZ6ztF8fnFMbZkA
         qneZNb/ykNValocUZXq/XuSIYbu+PSIWnY0Mt18jnQeMhZDAYW4+/FNQya1vb2l47aQF
         kH8GXNIYBLLv+FSsMCB+15MQYMT/gcZ6IoMUrDytPEEk9K+asDhr0/IMO87ANL56vobh
         TGXccnOC62kXJj05wK4siFTUHpjWkR+xCZmc5wwfvL0MGMsuecuOeFdiW5xtbbOFE9Mt
         LuZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=2421YxOw+uedhKa48hDiclAW2R6W7jC//U//UPkpnbc=;
        b=eqQ2f1zSk9fVRdy88UhbP9WnyDgx15j25ugPOqW6TrLBTq3LxPI4H8W4wTxLfs2qQa
         lwQkIKFNuAfh+txW+STgz7OD8m1gSKqKt+IBWXfE5DO2k+H1T1n3tjHEA43cSp9txd22
         Gco4NwteBLmfKCFggdDJBmJVKwozrUrydDueRVs5/r9w9ZfMYwnoLmNtFLq5QznqcRZe
         ufO77N5Tv6u/ZfOSEwWslj+XVJgrTAbyyMUJpMpl1SRpm6jrFxkXLDVCrBDOZYyYjdsH
         1e/NRMryvz8od2jaGsJzmzQfGZtgQ+voksMVC12s/+VF9OFblFFbgdJxtDx6etD6XZxX
         OIHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.171 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687707258; x=1690299258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2421YxOw+uedhKa48hDiclAW2R6W7jC//U//UPkpnbc=;
        b=JgDiZw2cPcHfD2X5nUAUuh0FHZ5M8RffQrE818biiNAzDlvVFP7JnObNXfEmeV+Pc/
         x0lZP6gctCSpsRhyJpHcsE2v0oUwmduRaa56ArBfafWy2zQKnmeE/A6PQHgw4o7wsaeB
         zEFSY30zQ/ZeFbJl/8/ZeKh/pvgwwr+NluKmI/bOEvBdIOXHaYrGiY47czIItlxqdFgX
         0ZdaeQlqLYK9BEmPNOluLZKTs9oQRbZGEyb5Rl9TGtt9GkdQmQtEWYh3QA/ajJc242ME
         t3t/XdAmpBAZiUijiftnoZ0NC+SHVUVYZBCZjOtx1Ox/vVxoySJDOvhvHV1CtwzxTGyE
         FRPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687707258; x=1690299258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2421YxOw+uedhKa48hDiclAW2R6W7jC//U//UPkpnbc=;
        b=TBb52aUP9HWcL+9JHOPtO/LDHEf8SLd9qSDTGkovrRp/27F+5E1L3o3jbfHT1D4cTm
         q1WNR+hurka+GAOp9KLRV0aQVTp7LTkRieeKtsP0qQw0828MeXY4awrE8DzldkvClzfx
         9PFoPXnyE1SORb77cAS1Ef2gzRg84khbblIwhMrKF7utqIDHQvgCuWgLY2vugLNK+HpF
         aNn6ANV4NBtTVecILLEH+xfVZFGIYa+M5QUkPhzIJezczzhTX2XLcdxehuJJu/ENc9ck
         0K3jimyiz/lUXJbOWcxrQUIoTYXZFKgqSkScRWfcSmk2gXsoGJEoyGSEGuKBN9IwuOio
         6b0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxM0LdSj9xNF7tABwAu/BdE4bAKcXELY8mZu6pSdBsrWMG+jM3I
	HH+VdvcCgVT+Q7mo2dCC6LE=
X-Google-Smtp-Source: ACHHUZ7WE9ZeqX0VbnBMEuWY6GkrdUfjP1vmZiUAQH6zvwaghpzpqGZ6os6pcq268vaitfenE/UWjg==
X-Received: by 2002:a92:a30e:0:b0:330:f7b3:ead with SMTP id a14-20020a92a30e000000b00330f7b30eadmr27847175ili.12.1687707258636;
        Sun, 25 Jun 2023 08:34:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d0f:b0:343:c13c:2da0 with SMTP id
 i15-20020a056e021d0f00b00343c13c2da0ls1038416ila.2.-pod-prod-02-us; Sun, 25
 Jun 2023 08:34:17 -0700 (PDT)
X-Received: by 2002:a6b:6b0e:0:b0:774:94e1:3aee with SMTP id g14-20020a6b6b0e000000b0077494e13aeemr25233979ioc.6.1687707257882;
        Sun, 25 Jun 2023 08:34:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687707257; cv=none;
        d=google.com; s=arc-20160816;
        b=GW1lPVaQpfzf3UC3h5XpQzVxca2JwuNhB3YVWISwWSJjGBtjQiZ+cSHiZyU3aaiH8+
         88oqJDeog3w1a7+y8rElRy22faA5ceS/oO68VSO4FCtOFu1htpcWoAdslSb0a0R8U4+N
         Vls7SAb1/8gcrOlrrjnUTiKSXJWb/f/PFH7o50wlcLI4/gy6tQen12t/s6FH7EFdUCw/
         BelYZD5yvriFQKho/HYIsaArx9gxW+1Whhmy2Oyu4ve9rBhGe4auTwHCK1XGKiwsY6o0
         WVGMZM45kZxz8LBv0rBGGBBGBX/kcpgymHV2oDQOZFDfMFqnJP/WtGkxgVNLhU1m/RMx
         Bzhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=Em86VtDkd1foZmdIW9TVdQbVnG2xtBG9ePF3h2l9uqI=;
        fh=bqiR1x7DY1Uv9a7gmO60r6aS/fVW0kpMZ72QlShL934=;
        b=cnM160lLIQV79Mkt8Z0lrTVzIuOpwakGzntBdTXzv1eJrM2GYSRy6Qa2ocnMmVSk7R
         /0EABj5IFc8diu1Sqxa5VI+WZ3+PaeIYR8Bec7GIiKDVwyJU+0vTNs782K5+qUuSzn2l
         JVu6DBjVSXOVceZFoHnQOL+6Us1k29jiVCCud5/E70mCJuFzdjDj42Xeda9q48D3UYDR
         HhrraTTSxV0i/fbj8gpKxrXqgkiJFJr6exkFCqoq0wvjcbGMh3nKYZq5GPrt5SpcAeoo
         9/WNYA/SyA5q7o1Owwr7qUjUqwyYzqB67Q41zoFKi+Z75P+0xO4A9yfVCcecGFj/6e28
         9HzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.171 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-yw1-f171.google.com (mail-yw1-f171.google.com. [209.85.128.171])
        by gmr-mx.google.com with ESMTPS id by15-20020a0566023a0f00b00780d9c3e8d4si270152iob.2.2023.06.25.08.34.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 25 Jun 2023 08:34:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.171 as permitted sender) client-ip=209.85.128.171;
Received: by mail-yw1-f171.google.com with SMTP id 00721157ae682-570284c7e61so26056547b3.1;
        Sun, 25 Jun 2023 08:34:17 -0700 (PDT)
X-Received: by 2002:a81:c201:0:b0:569:e7cb:cd4e with SMTP id z1-20020a81c201000000b00569e7cbcd4emr27671131ywc.48.1687707257078;
        Sun, 25 Jun 2023 08:34:17 -0700 (PDT)
Received: from mail-yw1-f173.google.com (mail-yw1-f173.google.com. [209.85.128.173])
        by smtp.gmail.com with ESMTPSA id y7-20020a0def07000000b0057072e7fa77sm863017ywe.95.2023.06.25.08.34.14
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 25 Jun 2023 08:34:15 -0700 (PDT)
Received: by mail-yw1-f173.google.com with SMTP id 00721157ae682-5701e8f2b79so25993037b3.0;
        Sun, 25 Jun 2023 08:34:14 -0700 (PDT)
X-Received: by 2002:a81:7c41:0:b0:576:777f:28bc with SMTP id
 x62-20020a817c41000000b00576777f28bcmr7920762ywc.21.1687707254518; Sun, 25
 Jun 2023 08:34:14 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
 <6c7a89ba-1253-41e0-82d0-74a67a2e414e@kili.mountain> <DC7CFF65-F4A2-4481-AA5C-0FA986BE48B7@oracle.com>
 <1059342c-f45a-4065-b088-f7a61833096e@kili.mountain> <CAMuHMdW3NO9tafYsCJGStA7YeWye8gwKm2HYb72f1PRXGfXNWg@mail.gmail.com>
 <206F3FDB-59BE-4386-82D2-6FF3CD16D053@oracle.com>
In-Reply-To: <206F3FDB-59BE-4386-82D2-6FF3CD16D053@oracle.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Sun, 25 Jun 2023 17:34:02 +0200
X-Gmail-Original-Message-ID: <CAMuHMdWX_fNxiPSBbWVSwSM+go_=1dccCK9jaYkR+2U14FR8pg@mail.gmail.com>
Message-ID: <CAMuHMdWX_fNxiPSBbWVSwSM+go_=1dccCK9jaYkR+2U14FR8pg@mail.gmail.com>
Subject: Re: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744 __alloc_pages+0x2e8/0x3a0
To: Chuck Lever III <chuck.lever@oracle.com>
Cc: Dan Carpenter <dan.carpenter@linaro.org>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
	open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>, 
	"lkft-triage@lists.linaro.org" <lkft-triage@lists.linaro.org>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mel Gorman <mgorman@techsingularity.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.171
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Chuck,

On Sun, Jun 25, 2023 at 5:17=E2=80=AFPM Chuck Lever III <chuck.lever@oracle=
.com> wrote:
> > On Jun 25, 2023, at 4:46 AM, Geert Uytterhoeven <geert@linux-m68k.org> =
wrote:
> > On Sat, May 13, 2023 at 10:54=E2=80=AFAM Dan Carpenter <dan.carpenter@l=
inaro.org> wrote:
> >> On Fri, May 12, 2023 at 01:56:30PM +0000, Chuck Lever III wrote:
> >>>> On May 12, 2023, at 6:32 AM, Dan Carpenter <dan.carpenter@linaro.org=
> wrote:
> >>>> I'm pretty sure Chuck Lever did this intentionally, but he's not on =
the
> >>>> CC list.  Let's add him.
> >>>>
> >>>> regards,
> >>>> dan carpenter
> >>>>
> >>>> On Fri, May 12, 2023 at 06:15:04PM +0530, Naresh Kamboju wrote:
> >>>>> Following kernel warning has been noticed on qemu-arm64 while runni=
ng kunit
> >>>>> tests while booting Linux 6.4.0-rc1-next-20230512 and It was starte=
d from
> >>>>> 6.3.0-rc7-next-20230420.
> >>>>>
> >>>>> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> >>>>>
> >>>>> This is always reproducible on qemu-arm64, qemu-arm, qemu-x86 and q=
emu-i386.
> >>>>> Is this expected warning as a part of kunit tests ?
> >>>
> >>> Dan's correct, this Kunit test is supposed to check the
> >>> behavior of the API when a too-large privsize is specified.
> >>>
> >>> I'm not sure how to make this work without the superfluous
> >>> warning. Would adding GFP_NOWARN to the allocation help?
> >>
> >> That would silence the splat, yes.
> >
> > But introduce a build failure, as GFP_NOWARN does not exist.
>
> This is the fix that went in:
>
> commit b21c7ba6d9a5532add3827a3b49f49cbc0cb9779
> Author:     Chuck Lever <chuck.lever@oracle.com>
> AuthorDate: Fri May 19 13:12:50 2023 -0400
> Commit:     Jakub Kicinski <kuba@kernel.org>
> CommitDate: Mon May 22 19:24:52 2023 -0700
>
>     net/handshake: Squelch allocation warning during Kunit test
>
>     The "handshake_req_alloc excessive privsize" kunit test is intended
>     to check what happens when the maximum privsize is exceeded. The
>     WARN_ON_ONCE_GFP at mm/page_alloc.c:4744 can be disabled safely for
>     this test.
>
>     Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>     Fixes: 88232ec1ec5e ("net/handshake: Add Kunit tests for the handshak=
e consumer API")
>     Signed-off-by: Chuck Lever <chuck.lever@oracle.com>
>     Link: https://lore.kernel.org/r/168451636052.47152.960044332657045794=
7.stgit@oracle-102.nfsv4bat.org
>     Signed-off-by: Jakub Kicinski <kuba@kernel.org>
>
> diff --git a/net/handshake/handshake-test.c b/net/handshake/handshake-tes=
t.c
> index e6adc5dec11a..6193e46ee6d9 100644
> --- a/net/handshake/handshake-test.c
> +++ b/net/handshake/handshake-test.c
> @@ -102,7 +102,7 @@ struct handshake_req_alloc_test_param handshake_req_a=
lloc_params[] =3D {
>         {
>                 .desc                   =3D "handshake_req_alloc excessiv=
e privsize",
>                 .proto                  =3D &handshake_req_alloc_proto_6,
> -               .gfp                    =3D GFP_KERNEL,
> +               .gfp                    =3D GFP_KERNEL | __GFP_NOWARN,
>                 .expect_success         =3D false,
>         },
>         {
>
> Is there a platform where __GPF_NOWARN is not defined?

"git grep" says all of them, as you misspelled it in your question ;-)

"__GFP_NOWARN"  is defined in include/linux/gfp_types.h,
so it should be available everywhere.

Note the use of "__GFP_NOWARN" instead of "GFP_NOWARN".
Once in a while, people do submit patches using "GFP_NOWARN"...

Gr{oetje,eeting}s,

                        Geert

--=20
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k=
.org

In personal conversations with technical people, I call myself a hacker. Bu=
t
when I'm talking to journalists I just say "programmer" or something like t=
hat.
                                -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMuHMdWX_fNxiPSBbWVSwSM%2Bgo_%3D1dccCK9jaYkR%2B2U14FR8pg%40mail.=
gmail.com.
