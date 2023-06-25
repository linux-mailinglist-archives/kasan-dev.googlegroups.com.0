Return-Path: <kasan-dev+bncBCKMP2VK2UCRB3P536SAMGQELKBEKFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A5E673CF75
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Jun 2023 10:46:39 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-635325b87c9sf8786506d6.1
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jun 2023 01:46:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687682798; cv=pass;
        d=google.com; s=arc-20160816;
        b=EcvBtYkVkatLRwepJU5RCLHyXp4Yojh2CNMFDWUl5pA4dha1jaWdtjWICjeaHl9QGE
         nNJzgFMCFwJruYruhOdYiNMHrptCNF3eW10wviLJsdOMTGUI2K6CJsC1K5NCituu6s+I
         N4HbcZzKSOa2uhZ4uOIOc3HhBxascVrJsBtST5Up1nI+IT0I1ACdc/rChDAds+PlPQTq
         u3AlJUqZk7wPoaEKVv79nceXBP4Y7Zt2993ilduLT8dw9lvGY70M0E273VlsoeDl6ZMF
         rUmZlrui7R+U1H3dBrXs/FiU/2gPB+c/jb80uN8g63WxAzEoWPM5utX7rDrr4VlqqYQt
         UVxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=fLljve6Ilxzr6MkQOiwLmzc7Ed5KRCDJHu8lJlQsyFU=;
        b=IwRQY2Lz8cqZMKNmFkiYXa4sZ9HLh/LPsmky3HBh+TQ5VT2tJz4gnc81XDgyMcqh6c
         NRtXnd80C2ecaYrSco19Pdwg/UkOz17rMQOFxtYZBDhbfk+YUREhT3c0NRoHqEKLSQJG
         QLisvCc7f+UHMuXsnsyjjZ00eYZ/2H44wwF1U3yHqQop5AlJy410poA7UjNvPzWTVlOS
         HBQJ+t8WIKG7pSXCI6Cy3uvjcPLqjxZQI+Br03Um2mdkJKBdBe8F80t6o+cQ+xC3Pa40
         wFRVnjQfGQKFXL2rhfPXEZp3UKlc5ymQZ8YvANi8o75Yt6UcBnGd2thXa4NntSBpmMae
         ysNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.182 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687682798; x=1690274798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fLljve6Ilxzr6MkQOiwLmzc7Ed5KRCDJHu8lJlQsyFU=;
        b=HW28Pnt0xOZNtjLhgTelhwwQDcjRG/ClcWJrV91wfFKIEgqJrHJ54gJuzWKM8g86Jo
         kIKaoorONQhHTrgsv1eKAjot2t2OWY6yeV/Hlo41AT2g5bxT0nfqBVBwlWDSfCWERGtv
         6HZfZYRt8gkt1Y+VM4gWKVldBTwHgRVHBuCyq+liDLw+CZFCrhFOgAPdwheGJQ82M2Oa
         PSJ3u4xx0a/dCckodH+wiPlTrr6Veq8NzZT7ZjlEELH4r+Ucc0TYZyZjqoxwWDc+rcAZ
         /1sbWy5ObLxxckIJFQFVg4RafI/AN6ain6yXxlzvyNeI67o4ESmTFf2NG2sUoaD4T8VH
         MQFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687682798; x=1690274798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fLljve6Ilxzr6MkQOiwLmzc7Ed5KRCDJHu8lJlQsyFU=;
        b=Y4fC3ZUBzmJ7Adofrv6R0FSi9zdVKuxIHsMaULTbLprU7NQUDxqSouIr4d4mQsydy4
         obY2zBhA2Nf9jSq6fI8zuEl7WYNfMFMfuQ9S8x/GXo6d276gE4mflXZkkEwggPbCQxjd
         A6rTJcW8qmTnxLl0jmBze4bDIXHFYdTfAggwZvzjzQJNcWUfUy04Wo/WrOJiMV+XUr8f
         vZR8idjTYgp8LSCmYF3B9YH3kTpti2sxN7nAvY8t81t/Liy4V1UjC5oK/hze8NU3ePu2
         BKkHsdPqSb3adeGlBC3HuvbMvIv0AvAtkkcRBPj9nZdkpqoPBBjXF+lpiW6snyL4+hdj
         QYxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwwEeyAdLFPNObvwA1K/0rNJUjhCImNTOSYRng1hXUZb0KKVmo1
	A+VPd5nHvKlXrgB6xoN/3Q0=
X-Google-Smtp-Source: ACHHUZ7VD695Nh/umFpvHtmNLo1MgZUOwzBEtYupRo0epKzzokzw9dKCieQemsNW9+1VGQMTpRM8xA==
X-Received: by 2002:a05:6214:29ce:b0:635:dbab:a58c with SMTP id gh14-20020a05621429ce00b00635dbaba58cmr416808qvb.42.1687682797696;
        Sun, 25 Jun 2023 01:46:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1872:b0:632:e74:7075 with SMTP id
 eh18-20020a056214187200b006320e747075ls2527467qvb.0.-pod-prod-06-us; Sun, 25
 Jun 2023 01:46:37 -0700 (PDT)
X-Received: by 2002:a05:6214:628:b0:62d:fddb:1856 with SMTP id a8-20020a056214062800b0062dfddb1856mr27862984qvx.43.1687682796938;
        Sun, 25 Jun 2023 01:46:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687682796; cv=none;
        d=google.com; s=arc-20160816;
        b=AAezA8j5ZAFa31rLLhZLRm9Cc/YtiQCKLwHTc6a97N0r7k7aoeeTc0EZT3LfwnjttA
         sFNMQUqFmVCums5ECq1z1xLcy486bKZ6M7Gb4ex6kGNGKFZT13iyQlStEWcjzzF0g7BD
         m01fZ2g0k/k0dhlU9WBTkFgYFrZY0hklVb5fwZvXAgHvOb5XWxYtw2auO2i2+LeYaIOG
         7j+Nnbi9wr7/1ifVIVzm9t3pmeR5BWBHkP0VzPFgGMNhDh0A43pMbbgkMhgRze+UYWV7
         zgyDlvf2lPi8FRuWPx29XGGvP1JAA2I/cr55v9V1E01GPIktkQyTH0xlsGJuXE+EW0qK
         Mn8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version;
        bh=SHlgsInQ4EQ73iyaQZEOHgbhLEPbwxie4IAHuCK4X/s=;
        fh=InY6yH2b+J25hRH+cfgn7n1klNqcQTb/XFvZVzHumDQ=;
        b=J9sLmM5BBYPvBd1q2s6PDB9/LDm9MkQwDvE5ymyxuAsigmhWs4DRgx5uFILVeQU/vi
         Nuz9ILfYyoxvRAAS1xiZd4gkdOCUuzlVRSOuvuVHzmoCgpuekz+mjk4r7+CgFA3G7X7l
         ieacjgrVJRpFd8GG0UXJFgPnACZYUuDw8XMvduiK+anJz6QrMEIoKkzP2vT9coHeMNz5
         lgmjXkOVrj9pehiF5lRh3+aQ5Z23IRxYG6OAl4HUQ6FIGWcGPCrulqokS40qoPnBsBVD
         YZ3/j+QvGGiHBcXR+z3G9zlDmm+F6Trao/bHyyWhwz2+RJQiijOpR+Yr31mWoj7pmwW3
         y43A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.182 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-yw1-f182.google.com (mail-yw1-f182.google.com. [209.85.128.182])
        by gmr-mx.google.com with ESMTPS id n4-20020ad444a4000000b0062dec72a6b6si251205qvt.1.2023.06.25.01.46.36
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 25 Jun 2023 01:46:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.182 as permitted sender) client-ip=209.85.128.182;
Received: by mail-yw1-f182.google.com with SMTP id 00721157ae682-5701eaf0d04so21553757b3.2;
        Sun, 25 Jun 2023 01:46:36 -0700 (PDT)
X-Received: by 2002:a81:92d2:0:b0:570:6a58:d864 with SMTP id j201-20020a8192d2000000b005706a58d864mr19292168ywg.51.1687682796349;
        Sun, 25 Jun 2023 01:46:36 -0700 (PDT)
Received: from mail-yb1-f177.google.com (mail-yb1-f177.google.com. [209.85.219.177])
        by smtp.gmail.com with ESMTPSA id u4-20020a81a504000000b0054c0f3fd3ddsm726346ywg.30.2023.06.25.01.46.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 25 Jun 2023 01:46:34 -0700 (PDT)
Received: by mail-yb1-f177.google.com with SMTP id 3f1490d57ef6-bff0beb2d82so2199886276.2;
        Sun, 25 Jun 2023 01:46:34 -0700 (PDT)
X-Received: by 2002:a25:d791:0:b0:bc4:78ac:9216 with SMTP id
 o139-20020a25d791000000b00bc478ac9216mr22897394ybg.61.1687682794370; Sun, 25
 Jun 2023 01:46:34 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
 <6c7a89ba-1253-41e0-82d0-74a67a2e414e@kili.mountain> <DC7CFF65-F4A2-4481-AA5C-0FA986BE48B7@oracle.com>
 <1059342c-f45a-4065-b088-f7a61833096e@kili.mountain>
In-Reply-To: <1059342c-f45a-4065-b088-f7a61833096e@kili.mountain>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Sun, 25 Jun 2023 10:46:23 +0200
X-Gmail-Original-Message-ID: <CAMuHMdW3NO9tafYsCJGStA7YeWye8gwKm2HYb72f1PRXGfXNWg@mail.gmail.com>
Message-ID: <CAMuHMdW3NO9tafYsCJGStA7YeWye8gwKm2HYb72f1PRXGfXNWg@mail.gmail.com>
Subject: Re: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744 __alloc_pages+0x2e8/0x3a0
To: Dan Carpenter <dan.carpenter@linaro.org>
Cc: Chuck Lever III <chuck.lever@oracle.com>, Naresh Kamboju <naresh.kamboju@linaro.org>, 
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
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.128.182
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

On Sat, May 13, 2023 at 10:54=E2=80=AFAM Dan Carpenter <dan.carpenter@linar=
o.org> wrote:
> On Fri, May 12, 2023 at 01:56:30PM +0000, Chuck Lever III wrote:
> > > On May 12, 2023, at 6:32 AM, Dan Carpenter <dan.carpenter@linaro.org>=
 wrote:
> > > I'm pretty sure Chuck Lever did this intentionally, but he's not on t=
he
> > > CC list.  Let's add him.
> > >
> > > regards,
> > > dan carpenter
> > >
> > > On Fri, May 12, 2023 at 06:15:04PM +0530, Naresh Kamboju wrote:
> > >> Following kernel warning has been noticed on qemu-arm64 while runnin=
g kunit
> > >> tests while booting Linux 6.4.0-rc1-next-20230512 and It was started=
 from
> > >> 6.3.0-rc7-next-20230420.
> > >>
> > >> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> > >>
> > >> This is always reproducible on qemu-arm64, qemu-arm, qemu-x86 and qe=
mu-i386.
> > >> Is this expected warning as a part of kunit tests ?
> >
> > Dan's correct, this Kunit test is supposed to check the
> > behavior of the API when a too-large privsize is specified.
> >
> > I'm not sure how to make this work without the superfluous
> > warning. Would adding GFP_NOWARN to the allocation help?
>
> That would silence the splat, yes.

But introduce a build failure, as GFP_NOWARN does not exist.

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
kasan-dev/CAMuHMdW3NO9tafYsCJGStA7YeWye8gwKm2HYb72f1PRXGfXNWg%40mail.gmail.=
com.
