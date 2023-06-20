Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHGBY6SAMGQE3O46N7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D15C57372A7
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 19:23:41 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2b483c8ff1dsf15633351fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 10:23:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687281821; cv=pass;
        d=google.com; s=arc-20160816;
        b=DEfhQIZ9vjgzzGJTYzeZUsOwC/qhyVIkcsNC5hpa/0maNW6p6zQ1+Zm3e1lO0587Hy
         4/3aWoioNoOMktSt1vXM+dBOPBt3d/e0+eLLHBZ1smAILcOHzTZtYv7i3bTJdX6rsXpU
         pqXvFlBoB49NZIY6IVoHW0auN8lZ+EjHkzcCK3gILXq63Oi8CF2KtIGlZeNHxJ1Xxwpp
         4adQ2TwRSseexSUAn/cee/m9KX14bez2lPMOknYyrz2HEVY46EAnIxvo1GLIPqjDcdPn
         ftSxccuOYI9w0JclZ6BMwREI79RB2g8+q5YhOPj++lSj7vVCdYz1TgG7OY9Ak+iW1C/K
         2RLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZVxlkJPVzZ2F9rR4ncnh8j6uDPb710d1DgglwIiGjLU=;
        b=cfjF022+KqCnlCSzNdZJgVv53SqjWg5p9BeA2jtnxyVibwKhuNamjlCxubYycczCU0
         Q4i9FjCy90hw7rek0rUXk9NU24Mz0esPVqQnAMWNgFCY/OD4A/XiFHs9EbGc9pSmAeor
         SwY/LmxquNY6L1s8uovGrREmCPrKzqhPg444dJve07f7lQbunXhGZtpSYxn44EzYf30k
         GDKPqYHCRSTtCFxVYSJX00DvpRLEClAF7huHtcAxJWFxN9+88HQv1TxVM7DeRfjg51os
         SmwvCW8HrIYo9b7Hmgfd3/wmoQJsVPzSEQ/xW+QY1Aq2iE6r6zpy/lfndDpGBK5AcqF1
         8nFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=sjjrqJuC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687281821; x=1689873821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZVxlkJPVzZ2F9rR4ncnh8j6uDPb710d1DgglwIiGjLU=;
        b=YYbVpK4X7ogmQpcUf5psDd7psKH+RiIQ7RhU3+CPxJw7GpKJE9rkhOMFwfxtrC0f1G
         YZ5fCpowYHhBoFpmE+o70xD0n6i8w8aYedgTqzeqao8/Y4fxUQryEANM4i1Edn8+L+6+
         sD4gNWBGMlxR3yUrNN+HrTPEk6Bd7ntkq7uXBA23Llh/9kHG7uKXfHaT9cdMGC0/zVLi
         TJTGJ/TR0NMbUkP+eZ5+XqdeZCmxKyekjJ9Hg6fG70Dm9evnT2eMRtezuhXpNh5HxS0q
         vEzNU5CIxqXtqVs2SR6Y4G9rotC92lPxh5Mxu0gbMiivG1Vi8M6qISFt/UkIJ2fF52DL
         oXTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687281821; x=1689873821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZVxlkJPVzZ2F9rR4ncnh8j6uDPb710d1DgglwIiGjLU=;
        b=WLn/BaSLMSk0zF1yrcyypDKyJ5iuQs/O+Y9wRCasAY696bNo+yRsfaVKE9Rc7DveJn
         c5PvjJPEfO07uHQIfXpL1RHAYK2NOj/QVsg4mER4pfn2iOg28c09Ig3wbjy0RzJ3Aqmr
         6D1tulUh++/g3ndb4qK4juOQ1JKTBX4dhrgjz4ZHORuAnLKgdiFcKqNhyV+W5CRLYobQ
         SXjlR6e/O2aIvtjqA/XVnct20128ZeH+264ON4AjqcruRP3q/xSCQUusMnNJcZquB+Jb
         MXb2498HhCbcn5r+3uPTiewoMLEiF1ygG90YspLeCuEqqczG+s0xPugwaynHYPHeEb9R
         oyHg==
X-Gm-Message-State: AC+VfDwSzvaDvz7VeWX5ZGh+E0GgoXCgcGAQ9/cOBTlp6qPTAq9ALLg8
	czKG4A2x8N+uSLdluInayeU=
X-Google-Smtp-Source: ACHHUZ6rziVo2VVs6Sy43iIQYZkY8vsEGmUab/0fiQPlCZJxO7S0AUMqyrnLuCRzQ9S/GDw4jaaQCw==
X-Received: by 2002:a2e:81c5:0:b0:2b4:8487:5f60 with SMTP id s5-20020a2e81c5000000b002b484875f60mr3300110ljg.35.1687281820660;
        Tue, 20 Jun 2023 10:23:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7218:0:b0:2b4:6dc4:68cf with SMTP id n24-20020a2e7218000000b002b46dc468cfls674322ljc.1.-pod-prod-04-eu;
 Tue, 20 Jun 2023 10:23:39 -0700 (PDT)
X-Received: by 2002:a2e:b616:0:b0:2b1:e5d7:633a with SMTP id r22-20020a2eb616000000b002b1e5d7633amr8878836ljn.1.1687281818973;
        Tue, 20 Jun 2023 10:23:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687281818; cv=none;
        d=google.com; s=arc-20160816;
        b=awCcsEVAmp6mAZ+dWkuWZ0d5XbXgsSWdkqmmBaYIxT/jmBkNnjD91m/boOTPUTme1y
         6HMqMym00ZIb60jhocCIjo9sw2akO66I9X9o6kHFs8R/lmTzn4iJa9AgoYEy5/ivBxVf
         /BTEVbTbIp47v/QWUs5cOIfLhzA9IZpGg4deKcANZOUEar+4I7uaLBK4o54sJhRcJ45Q
         y7f81FvXp7us2rLRfM42pEJSf6Uo7WQ8COI1K9JmCDXv5VvaTu9/GJraziA6ofTzHYN4
         bbqxUcVn4Gi7wMoSgkdmA0JkMhs/hRhTOKxGJNjpDGvk6FpLVByNx4STyB48HdhX76lY
         Mfqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=s9mWYfGROnySR6uue4WG7vLMYCpdaHNd7ovm5oIrCjM=;
        b=Hs4PdC2k7TBSi4tYlvO1vXB4kcHFVp6Eeg5vNVGPXnpzfEtZw96/omo0gzLfDkHmyy
         9oD1oZ1ZUrOS8kYQUsS7iBmoAg8qQpeJEkugLJZl38JMr17GxQu/IuyH5kFjnNep4WVW
         BK1Avc0XRTdTh6S9qd7JPgh6y+s4Im4lyekkVQN4EwFpU02OPC8D6o4y3RdU+by7a9kR
         yw9P1AoIcfNjzinONVIzPnob8u5ZUgDwaTWPeGjyiNUqNDVW0kQNdVV4uZj00r4cglRM
         dFRVTugzgpXe9QWUkFP3PQq8iQYuMnZiAGGz1B1E77x8oIqpfkoYqwVEEJ3+Fogalf4T
         vekg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=sjjrqJuC;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id w20-20020aa7d294000000b0050bd0abf2b4si132285edq.3.2023.06.20.10.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 10:23:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3112f2b9625so3320215f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 10:23:38 -0700 (PDT)
X-Received: by 2002:adf:f004:0:b0:311:1df7:3e05 with SMTP id j4-20020adff004000000b003111df73e05mr9335340wro.22.1687281818234;
        Tue, 20 Jun 2023 10:23:38 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:8530:a6a3:373f:683c])
        by smtp.gmail.com with ESMTPSA id g18-20020a7bc4d2000000b003f8d0308604sm14028860wmk.9.2023.06.20.10.23.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jun 2023 10:23:37 -0700 (PDT)
Date: Tue, 20 Jun 2023 19:23:31 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Taras Madan <tarasmadan@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
Message-ID: <ZJHgkxdnlSXfXLkn@elver.google.com>
References: <20230614095158.1133673-1-elver@google.com>
 <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
 <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
 <ZJGSqdDQPs0sRQTb@elver.google.com>
 <CA+fCnZdZ0=kKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg@mail.gmail.com>
 <ZJG8WiamZvEJJKUc@elver.google.com>
 <CA+fCnZdStZDyTGJfiW1uZVhhb-DraZmHnam0cdrB83-nnoottA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdStZDyTGJfiW1uZVhhb-DraZmHnam0cdrB83-nnoottA@mail.gmail.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=sjjrqJuC;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as
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

On Tue, Jun 20, 2023 at 06:27PM +0200, Andrey Konovalov wrote:
> On Tue, Jun 20, 2023 at 4:49=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > On Tue, Jun 20, 2023 at 03:56PM +0200, Andrey Konovalov wrote:
> > ...
> > > Could you move this to the section that describes the kasan.fault
> > > flag? This seems more consistent.
> >
> > Like this?
> >
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tool=
s/kasan.rst
> > index 7f37a46af574..f4acf9c2e90f 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -110,7 +110,9 @@ parameter can be used to control panic and reportin=
g behaviour:
> >  - ``kasan.fault=3Dreport``, ``=3Dpanic``, or ``=3Dpanic_on_write`` con=
trols whether
> >    to only print a KASAN report, panic the kernel, or panic the kernel =
on
> >    invalid writes only (default: ``report``). The panic happens even if
> > -  ``kasan_multi_shot`` is enabled.
> > +  ``kasan_multi_shot`` is enabled. Note that when using asynchronous m=
ode of
> > +  Hardware Tag-Based KASAN, ``kasan.fault=3Dpanic_on_write`` always pa=
nics on
> > +  asynchronously checked accesses (including reads).
> >
> >  Software and Hardware Tag-Based KASAN modes (see the section about var=
ious
> >  modes below) support altering stack trace collection behavior:
>=20
> Yes, this looks great! Thanks!

The patch here is already in mm-stable (which I recall doesn't do
rebases?), so I sent

 https://lkml.kernel.org/r/ZJHfL6vavKUZ3Yd8@elver.google.com

to be used as a fixup or just added to mm-stable by Andrew at one point
or another as well.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZJHgkxdnlSXfXLkn%40elver.google.com.
