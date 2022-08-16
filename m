Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHGW52LQMGQEMTU55MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id E41BD595E67
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 16:35:09 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-32a115757b6sf109751827b3.13
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 07:35:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660660508; cv=pass;
        d=google.com; s=arc-20160816;
        b=g9tX9xuUpI9OO22nXuI5OcwaF65QlXRDcKeKiL1SXNhkBFjGrTNMFqV5NPISNX3FVl
         r+rM4eEwMan5cVTsxRdk/63hjS1qf2Za1fotqjzRqDFubdGwQv0FOIq5pKRzhYjTNf+T
         yd1WO1grlulQHn5DcdujxsJcAMqhI3oTgalIiaFyO0GWlAEC2EwqQvo2VZebuXTt73qu
         n0nMVhpLFHoKnP6Ago5F9sWq2Y0rfD+2LiJu+qQqEZC+Nsc4JsyXYlXs6XhX2APVBR+n
         0As+0dIjKmhnV2rFHYIx1Ujy/Al31l0qqeX2JhWA6FCRkvVvR59xawUxIrFwgG3n74EJ
         9OLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U2KEqJ/DXH8FYuHljxWNvdnf2Dr2qz8tEzDBqA2naN8=;
        b=YghJvklXSomBlDM1uvbPlBXwYYBNdvpsUJ/YMigP9uJNO27UkqO8xLy96BXJkEiMON
         VYwZcE6E6I6ntpbK84t6+kyd7t2SFkBgx0K/cmallZ9jqULNGMWqyT55zWArV09xAX9j
         4Gdzrkt/pmx6NLG9EWNw4K7ViEwRokFMHISZ8FTIK13JEemo4zmKeQTZXm6Ifr0CUT/y
         YzftNz/hR9Khhgf/K3dIWfyzxADWqEl63NmAX7KyATlE5PPTogJBp2ZbnSqUTHIkvuG7
         CkNdzrSh0mxySYgf9OT01kRM0Fv5LJi0kaLh0aFR+AmUSQzGOBKm/hysjdy8fVuBP6cp
         nE7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Nck2pUEE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc;
        bh=U2KEqJ/DXH8FYuHljxWNvdnf2Dr2qz8tEzDBqA2naN8=;
        b=Jwmoke3GXu9Iv/db2KJizEd2J4sZg3sd/yt6KU8BRhmi0QPvE3OlrmxVxcrDlaFIrr
         YXo5Tht3wTTXi7sxKJHqmWPS7AfVSVTyOwrLlhRLdry19d4z2yyhwucVbNazEXKA4nq6
         K2parO+VQ/XZj6z0QyL5tcxtq7u1I2GXZHfWHG5LXfhz7DEH64tgNLLJwfgTdw2BA6/m
         HLq4RoCQIop+uxXI+NfzOpC0gwlpiXr6swcFdQKJ/S1yhNh3EGfWTcDEOpw2VpZq75x9
         eMi3AYi6VM8TI8CRpLv8u0pq65hy57Rp2y/TMU7h2H4XSlqvdwoHhevLKEezPi6r2MYO
         DwYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc;
        bh=U2KEqJ/DXH8FYuHljxWNvdnf2Dr2qz8tEzDBqA2naN8=;
        b=FpKshIFd36ern5OZo/SJ+BNVKaXIvQyS1eeU6ufo0eUFqjxSf1TTylBLrvnnYYVcXH
         P5/qyTRIHnrbnituP8J8HILd5EGZx9pSXbKLFl1RPSGVAkxL+6DfbBZHHh03Rhd1IUk7
         NYjEnovKPJDB0KNGK8INsT9BftmS3zsmgchG0YFPsqs7uFrl4t9OeK23V6L+HbGwy6MF
         FUIbcBysogl5bG9rY76A1+1vVOZEtILkDFO56tj5p7ixoy8h2G5ykkVLtcn2doOwWXsq
         ALwb9gODtlBwVLb9K/fraccOrrguUG+UbyjhqIF3QgzrSEozXtvngY2CDc0Mck7S1bFd
         daBg==
X-Gm-Message-State: ACgBeo0QKJFqsw+22nrAuoM1LuYggYf2QcEMA9Gl/xLQUMKGbtm48/3l
	VZ2byQ4XxLy9xs7Y5Zgb/28=
X-Google-Smtp-Source: AA6agR5iwkbPv+3C/kK4IaiwbX20HJRMWBJ8QHIswO5RtccUKX/ueaDVXRu9e30BIRXz8rHRYtQoKA==
X-Received: by 2002:a25:d40b:0:b0:68d:487f:6a48 with SMTP id m11-20020a25d40b000000b0068d487f6a48mr3292663ybf.126.1660660508654;
        Tue, 16 Aug 2022 07:35:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e2d1:0:b0:328:7d8c:fddb with SMTP id l200-20020a0de2d1000000b003287d8cfddbls6393735ywe.0.-pod-prod-gmail;
 Tue, 16 Aug 2022 07:35:08 -0700 (PDT)
X-Received: by 2002:a0d:e745:0:b0:320:ae6a:ac06 with SMTP id q66-20020a0de745000000b00320ae6aac06mr16475610ywe.185.1660660508029;
        Tue, 16 Aug 2022 07:35:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660660508; cv=none;
        d=google.com; s=arc-20160816;
        b=0/TUeXSpERTvR0hbwZM7g/BNTgw+7AESI9+m73YKY5koHyNozy0QXENcBMpcGSITKR
         Y24zklMDoTnhCwuhA94d+duN5xy3J/AMLEs/w3frI+xHjLUjwdKo2foRAepl1rdKn59q
         7GzRZE4q0phn6Lg7xHZKET46PPIDnRPEZEOS/llW1glAq8R402Cq4E84cCJ7Fv0nE3dm
         f0wBYlUMdxs+ViuM3B39Dv8YA1Tfk1jww73yTGFtap3zqXEb7t6SJqmT0y4Npkn3JW5r
         abTjF8o+Pvxd6cVQ5m1eqDPPC97ws4JM9qmHYArlIdo/rb9TGKVPPhPGwSAS1e5DevqG
         mhZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=sKkqKLJFnzGDyFb/Z3lfz2STDnoaJEZPlY1BVY1Y4VI=;
        b=0GZN7WOWSf/LjKC9hEK6MrYyOaTByQQuiM2MYe9TnjfnAFUVYl2nZJarGzmyiz1Cop
         ejuxlN3R13Bb/mvonaSN7LJue1BkXhT+JykVjv73EvnYwDaBjTo9tlvJbhF1YyZ5jfbm
         T80ILkZSxYmHFdFIfI7p1PbWhYfu4hnZcgVzA2O1ClxyNjEA9S8QeEqvUHRZkpipDV7E
         SfiO87imRfeji9cNmeo/a4XgyovNbBe9NQUC/jLiN0y2CUJgIRx+EoQHsPCueeXFRMH5
         CVL50FqPsGXfzRJ2PktZPLHkYh2RBlMDQt/EWIL0UrQRwKIS9KmASmg7QlRDx4q/3A0p
         IXUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Nck2pUEE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id q14-20020a81990e000000b0031f111d36bbsi1284322ywg.1.2022.08.16.07.35.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 07:35:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-3246910dac3so155928807b3.12
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 07:35:08 -0700 (PDT)
X-Received: by 2002:a81:500a:0:b0:333:9bcd:8a41 with SMTP id
 e10-20020a81500a000000b003339bcd8a41mr2399644ywb.4.1660660507542; Tue, 16 Aug
 2022 07:35:07 -0700 (PDT)
MIME-Version: 1.0
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck> <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
In-Reply-To: <20220816142628.GA11512@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Aug 2022 16:34:31 +0200
Message-ID: <CANpmjNMd=ODXkx37wqYNFhivf_oH-FSo+O4RDKn3wV14kCe69g@mail.gmail.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object search
 tree (overlaps existing) [RPi CM4]
To: Will Deacon <will@kernel.org>
Cc: =?UTF-8?B?WWVlIExlZSAo5p2O5bu66Kq8KQ==?= <Yee.Lee@mediatek.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, Max Schulze <max.schulze@online.de>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"catalin.marinas@arm.com" <catalin.marinas@arm.com>, "naush@raspberrypi.com" <naush@raspberrypi.com>, 
	"glider@google.com" <glider@google.com>, "dvyukov@google.com" <dvyukov@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Nck2pUEE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Tue, 16 Aug 2022 at 16:26, Will Deacon <will@kernel.org> wrote:
>
> On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=BB=BA=E8=
=AA=BC) wrote:
> > The kfence patch(07313a2b29ed) is based on the prior changes in
> > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up earlier i=
n
> > v5.19.
> >
> > @akpm
> > Andrew, sorry that the short fix tag caused confusing. Can we pull out =
the
> > patch(07313a2b29e) in v5.19.x?
> >
> > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/07313a2=
b29ed1079eaa7722624544b97b3ead84b
> > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commit/0c24=
e061196c21d53328d60f4ad0e5a2b3183343
>
> Hmm, so if I'm understanding correctly then:
>
>  - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c24e06119=
6c2)
>    but the patches apply cleanly on their own.
>
>  - The kmemleak change landed in the v6.0 merge window, but the kfence fi=
x
>    landed in 5.19 (and has a fixes tag)
>
> So it sounds like we can either:
>
>  1. Revert 07313a2b29ed in the stable trees which contain it and then fix
>     the original issue some other way.
>
> or,
>
>  2. Backport 0c24e061196c2 everywhere that has 07313a2b29ed. Judging sole=
ly
>     by the size of the patch, this doesn't look like a great idea.
>
> Is that right?

Right, looks like the kfence fix didn't need to be in 5.19. In any
case, this patch I just sent:

https://lore.kernel.org/all/20220816142529.1919543-1-elver@google.com/

fixes the issue for 5.19 as well, because memblock has always used
kmemleak's kmemleak_*_phys() API and technically we should free it
through phys as well.

As far as I can tell, that's also the right thing to do in 6.0-rc1
with 0c24e061196c2, because we have the slab post-alloc hooks that
want to register kfence objects via kmemleak. Unless of course somehow
both "ignore" and "free" works, but "ignore" just sounds wrong in this
case. Any thoughts?

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMd%3DODXkx37wqYNFhivf_oH-FSo%2BO4RDKn3wV14kCe69g%40mail.gm=
ail.com.
