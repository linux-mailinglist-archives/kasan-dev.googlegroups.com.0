Return-Path: <kasan-dev+bncBDEKVJM7XAHRBZXSS7YQKGQEXGR2QYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E07931431EA
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 20:03:02 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id d8sf196465wrq.12
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 11:03:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579546982; cv=pass;
        d=google.com; s=arc-20160816;
        b=RYkD6tyoWA1XFbPaZ6h3WnXKef8TOZ7b8p7BxlEy0t6KjKeswPXUyPzarqO972UPqo
         xNq4W+3BagJQCRQSxGGBc+NDCQvH2UPDxvcqp3HMWWL4nWM7noKsCeHUuo1njmO1NQB2
         5GG5D4LfEw41Ck5Yb8ViZsSeO1HiNVVQJJI+QB5PH4H56tkw1S7qFuN5incpzPhabA8k
         4UcIwt8HXyqqrNk98hAmMY/Te3sGqwCH3ePFTPYoUCva1lbbpQ2zeFhQtchXU9CaxSiD
         PIpCr2OcHH6Ywe/qRNkxHBhlgJJoAycAOOb3mkXnBvqgUMAa0uP20J5eDpXCu5d+k5tJ
         y4uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=rmwIDeP/SQRIPZvwVCR5JHljmt5aQLcySzUDdxWFFa0=;
        b=wZAYB9FdLs92rgBYzzhZmoaUKthztycWek9DaAYorXxQiWxO1eeBVwVRbyGwqODERK
         WEDk3QetRlW/S7u5LEc15gCe8j8GzgAmeabetiw7G3mS9tnr6R1dAgmUIkAUcroEZGkd
         Qp/81iXZpjne1/HY3cYw0Mu/iPhqCf1q2fMwz1W4Yovw1U995hsiDwr+eKVWTC6vpXpB
         TDxUH8p7/Xu6uY1d6yNdPYrIdqLmhgInhtEpLOO+b4Yhnbp2mJXWEC70PpiA0VXARRbV
         l8TEvShjPAFoefi/ePMckq1shHhSixbhDQHazhxmio8XkZevhvCE2IqFjlSjg2rM5CoO
         Mnqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rmwIDeP/SQRIPZvwVCR5JHljmt5aQLcySzUDdxWFFa0=;
        b=J7PagK05ZjYOIV1rQ3ylAECjOYo7oe8at99MrPfe5DZS+50NXsStMe2uXGxy1Vj59M
         E0bAmK8EFkFB6l2KyPj0k2REzOFjThMkkC+JsQUSr8/yaiX8p/UXMkoX6B8rNTWfKBME
         H21IIBzYQiWPxq0nXp/ATjsM/FHVxJMth/gxAMOPRVae0oMAhoF6hdvoq1T/ZHJCfWFe
         t03VXTLQLFCsvynEfZqjld9QIVecWAiMECYaXNNm/NyCoq8gwifjiKaDOPAKmwoOVvsX
         sBFWgG1WY1pbvvLGbhGV5O1XrLw6dcMx3lk86yGIK6/M5ssCxMk6ZbzzCFTE/9bkREx7
         nTGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rmwIDeP/SQRIPZvwVCR5JHljmt5aQLcySzUDdxWFFa0=;
        b=Q2M9H+3ND9qnepOdWDzRMQUbvLnsGDGCTFjRK11uoh0OrkeEjKzoFvWudzyJaL3Vq6
         //wR0xZERqAg24vOeDOiBhpBCufsrfsuQWw5hSwXlO7QkLHUiTBwZkSbcXZ8FmZBYZe+
         pQn1o0PvUuVeYXoAEoDT4J6jHwRCuNytkP4/y/7ChzMDdN9bKmGO8AsJ7KwrYr7ky0HZ
         hNOEqWaFuegK1oOfqo+kYJsmfbFYUsFxqlh3cjqUYe6hiBkZTSxVBlz5DaeTuvqiMHu+
         0ev2SPJubuxS7DeGrpoC4GJzQ+Kx0agCVnzV0M6meLMIAv0BJOHlNE368gAqIbEtn32Q
         4JSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW0Hxghh8bfHwLvHJ44mDQIbARWxIaLom9WJZA+S/a/KZoHDsVS
	G6iWxAdA/Yb9OPd/hKnntUs=
X-Google-Smtp-Source: APXvYqwr2BgoBQtCtHQnsRZby6y2xV7GwBtkJAvrcZ2kH3G8JAB46uEaKOIEBI8mSsSVkAOlkRCpNg==
X-Received: by 2002:a05:6000:118d:: with SMTP id g13mr868498wrx.141.1579546982599;
        Mon, 20 Jan 2020 11:03:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6912:: with SMTP id t18ls2859449wru.7.gmail; Mon, 20 Jan
 2020 11:03:02 -0800 (PST)
X-Received: by 2002:a05:6000:12ce:: with SMTP id l14mr969158wrx.342.1579546982059;
        Mon, 20 Jan 2020 11:03:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579546982; cv=none;
        d=google.com; s=arc-20160816;
        b=n8WUCg5ajOVcb92KERUJoclSw6+DaJ0ZK0mSLTC0E9pfZ1MWuUCN5uneX+j+vJ0ekq
         YD01cLxyfrSGaRIm9JJv38G0tFHIaHbjexRaqWTXCRyHI6rN4TBmD+yLRRmcL9JjMDZA
         Byr8DMHVFvgbLkfJLZ5DrywyuP6rB3B/jd7gBIeYOt4FqlqMq64BiG3DzXLJa5NGBhVo
         drGZs9IdTRgzmvQDXVEV+CfW0g7/HOz7ftjVX7gjO4Aq1v6O4hh/24u6uXyZkvClVnjt
         yyk0RDkaQhH0q2ikY0C6G6ZTWKiR34NMwVTNC418X68S7IN6gNRG1G2XLVxY/5W4Aj90
         payw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=zVDX76oU4uN/Wz/AWau+L6wJ8ExpJ/NsK/bCJiqNHG0=;
        b=H2jorlycr/3+Y/718XBCyRQV2XFrESsebOqRi+gsbr6462GSlrnX1cYtOATHxO0W8f
         ciMzWM+74UtOby+jvBTlQvVfDs30wyyuBLxDXdlCAhuCNSyEeu9cKlUPraz9ULmlOuFB
         jhl9jc5vlf+NcKSDrAFM73yGbnM7YTYU4LDimkQShIzRVDFfa6pCsMGSbzI6DX3+xD28
         wET1GFVpWn/+obTEGsKxSNgorjdf1zoHqIsnklpbbSm51TDxLaKwOqQMIU4fL2ymRtaH
         VLTox92te7rhW9jEyQBNspz74l5UQUxZpNioojal0yY8pfk+fyImg1ROwIUyH/X09JSs
         Xmiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.187])
        by gmr-mx.google.com with ESMTPS id m2si37751wmi.3.2020.01.20.11.03.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Jan 2020 11:03:02 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.187;
Received: from mail-qt1-f179.google.com ([209.85.160.179]) by
 mrelayeu.kundenserver.de (mreue011 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1MWAjC-1j9RHj271m-00XgLF for <kasan-dev@googlegroups.com>; Mon, 20 Jan
 2020 20:03:01 +0100
Received: by mail-qt1-f179.google.com with SMTP id d18so603038qtj.10
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 11:03:01 -0800 (PST)
X-Received: by 2002:ac8:768d:: with SMTP id g13mr805093qtr.7.1579546980409;
 Mon, 20 Jan 2020 11:03:00 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
 <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
 <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
 <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
 <CANpmjNO395-atZXu_yEArZqAQ+ib3Ack-miEhA9msJ6_eJsh4g@mail.gmail.com>
 <CANpmjNOH1h=txXnd1aCXTN8THStLTaREcQpzd5QvoXz_3r=8+A@mail.gmail.com>
 <CAK8P3a0p9Y8080T-RR2pp-p2_A0FBae7zB-kSq09sMZ_X7AOhw@mail.gmail.com> <CANpmjNOUTed6FT8X0bUSc1tGBh3jrEJ0DRpQwBfoPF5ah8Wrhw@mail.gmail.com>
In-Reply-To: <CANpmjNOUTed6FT8X0bUSc1tGBh3jrEJ0DRpQwBfoPF5ah8Wrhw@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Mon, 20 Jan 2020 20:02:44 +0100
X-Gmail-Original-Message-ID: <CAK8P3a32sVU4umk2FLnWnMGMQxThvMHAKxVM+G4X-hMgpBsXMA@mail.gmail.com>
Message-ID: <CAK8P3a32sVU4umk2FLnWnMGMQxThvMHAKxVM+G4X-hMgpBsXMA@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:f+vD3V7BbhBWlMuN68dTZCHBe5NrOroU+9wvIB8Uymf4wEuvuQs
 d3lwl2rOjxvCH4z1jW5YlGZkeaS7duKL98HiS4MH23BHwywq3L9GFgKVd2EblKl+sjiv5iP
 6f0xGWARljCXzHQc71yh5/hoTx9ATJM6/tdQsiPmDpIS2OWrihOa9QipXndeiyWmtgSMKwC
 aP8tVJKkCwkFZXCsF2oYg==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:6V5kiZc6A1o=:8bnPbtPV8rtcDZYmg1ZeIN
 J8qdFm4XQsYDKyHW38R+Ln9Q61uNp2breC0dwQdSNLT1kVeINgQJfYvhh0Jq+O+i9IF4MokxB
 DCcuXSRd3HaI9jbqE8Ju+PNCxDUa4EqbarkCNutIVbX9NSXwT1xMgMKveLuv2XphEg+AiyPwd
 tUzjjCVNnu17Mxi/KIVGY8dXaGDE3wW0F+74KOV47/v5N09rx9qmDoxydUxbnRrOAxLATkFZT
 giamYvhCmvwb9cF9eORruRm27A73Sr7cX+g8ykcsq/EnjkoZVPlD4gkdPVZARXw4PrSfuYI1E
 Furji1UJ/baB9I/Yi2OtRUYhYzBpYoQOpMGzj4s3nH28YJ9oDpFFOdbaYzKlbe05fPyfa+9e2
 RlXhoCIjbOcCMlsMZCS+5B4auzFPEsbQzQtr575qZ/7Tzkkl1f0oNA0h/7cGBrMsEcSVMoikt
 sl5wzPJiYc0+swbCOlkuKHLt6hOFCgu1tm1PLgc3X8Q/jW+kNVEFY7bJ0k1gOPoVMkQ43ilk2
 6AgDJbSZHcMZkjYW43p7qlXyhbNR2r201EVhqoE3qUTgJJsIP0fZZiJ3/cmYNxgCkwSySdLog
 IKUTDSHtojgiDLAS3YN5kdOoYel2JDWFRFbxmNLlRx21mhH/1H8vXERmDtps8+R/Mr4E0NSWo
 TfHNknKl89qIJHxg4xzI64y7j8B41SSiJpN+E4AkVQQSsur/kV8q6HNxiGUy5tjQ0/yIT2zfU
 pSgvhTb+KRecKlItgayv00xBSIF0vEKXp99I8CpOmWSO7fJ9FmNiQDTfRXRz17OE9TDs3tqvr
 v/ssSVWkWwxs4k6P5IyVveYV4vUlbgx4onAkL6SPRj3dvqEvEfHDjGS7L7q1sOZDAoZY2Wl6N
 EMWyXl9JgJJcCHAUwEAg==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.187 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Mon, Jan 20, 2020 at 4:11 PM Marco Elver <elver@google.com> wrote:
> On Mon, 20 Jan 2020 at 15:40, Arnd Bergmann <arnd@arndb.de> wrote:
> > On Mon, Jan 20, 2020 at 3:23 PM Marco Elver <elver@google.com> wrote:
> > > On Fri, 17 Jan 2020 at 14:14, Marco Elver <elver@google.com> wrote:
> > > > On Fri, 17 Jan 2020 at 13:25, Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > On Wed, Jan 15, 2020 at 9:50 PM Marco Elver <elver@google.com> wrote:
> >
> > > > > If you can't find any, I would prefer having the simpler interface
> > > > > with just one set of annotations.
> > > >
> > > > That's fair enough. I'll prepare a v2 series that first introduces the
> > > > new header, and then applies it to the locations that seem obvious
> > > > candidates for having both checks.
> > >
> > > I've sent a new patch series which introduces instrumented.h:
> > >    http://lkml.kernel.org/r/20200120141927.114373-1-elver@google.com
> >
> > Looks good to me, feel free to add
> >
> > Acked-by: Arnd Bergmann <arnd@arndb.de>
> >
> > if you are merging this through your own tree or someone else's,
> > or let me know if I should put it into the asm-generic git tree.
>
> Thank you!  It seems there is still some debate around the user-copy
> instrumentation.
>
> The main question we have right now is if we should add pre/post hooks
> for them. Although in the version above I added KCSAN checks after the
> user-copies, it seems maybe we want it before. I personally don't have
> a strong preference, and wanted to err on the side of being more
> conservative.
>
> If I send a v2, and it now turns out we do all the instrumentation
> before the user-copies for KASAN and KCSAN, then we have a bunch of
> empty hooks. However, for KMSAN we need the post-hook, at least for
> copy_from_user. Do you mind a bunch of empty functions to provide
> pre/post hooks for user-copies? Could the post-hooks be generally
> useful for something else?

I'd prefer not to add any empty hooks, let's do that once they
are actually used.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a32sVU4umk2FLnWnMGMQxThvMHAKxVM%2BG4X-hMgpBsXMA%40mail.gmail.com.
