Return-Path: <kasan-dev+bncBD63B2HX4EPBBZGM2L7QKGQE76R5V2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id B779A2EB1BC
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 18:48:21 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id e14sf55089iow.23
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 09:48:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609868900; cv=pass;
        d=google.com; s=arc-20160816;
        b=UWy1A19lpYmXaQzf8ad0iRpO8yvVZp2JNAP9IsUUeqpDvb5gsPEmIhcglCRKLUCYPH
         1LweKaFbmrpRtWjtqF7MS9UtsYwUrW1MyI3BmrHsOXaKGLy859T3pt7EpPxX53Z+I5Xw
         GsBHKhpDVzXGgeuSk9Q0gZuDUtb5j+KPK5LpEfE04qulzj3LYf0LjA6Ir/2BH1F50rtl
         CHzq14VvSsd8YJuL1H/e+tZO1r1XYVYnIoJrmXkrIkBaoLuE5EXg6Fuve/XxmaU5u9Rn
         bmG8DORLj55owbUsX7qzOY6sMZtHXeBWsphqPMYHVesG93Kgs3I3YVe8adHuwTn6YJF7
         n+ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=6qRvph6MXIA2/XIUZcZgb0eqnyzrWBYx555emMCB/LE=;
        b=Wnri60d/1zN8DJbFDC58Ot8goyRAHweP20Tg9iNnJvCaOvtir0PtMArGcZ6hLQrIlc
         SitaSlNa9PDeEWrmjHeIvmWx4iPIAjiPMpX8WAkvPEIkjTzhjDxHtZdE6HSHLf+ZwSGh
         BI2S4zcm2voeIfhe2fZ0bJhFcdtSPU5+K+TX/JDoIzINJylYYCoj+XXobN7R8BL4/yZr
         G6IafbupkM3WoPUWBWSWSdUDONSr/FXZFISJ2zAqvkBxQ0r88WpjAnoM0t69YVgVkVzx
         HMfeFJ3lBD7FcMLOWsZAzwElkk8yWHoj1DlOO4xBhNQPlvZfCCup3dsza80FFGKDbq3Y
         GSSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=JZkOToB1;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6qRvph6MXIA2/XIUZcZgb0eqnyzrWBYx555emMCB/LE=;
        b=YJqtB61IonXSWykYkVw1mfuImkwJedEA5WcuzLyzlhLnHs6EP6jaahzPH8Kx3KjC42
         OxINvHj1jMkWyvkK2QunrlGrQf9wmh+trilYN7K0muvvM38a7RcvNmYjSzDxxfWKNcLX
         u9DzaBFTBHPuIkJZomGl1m7d6Opz0GEbbsmBVUsXehvm95LMZYMR8+vTNgvT9kTlS++z
         x65iZ0afKHL2Q6sgN+am2XXcjeCGZKCt+062gWF/+tx2WB+s7X8unj904DJLqzbN1yWh
         TsFPYzCcbrwNhDCtgtpj4rjpQB5vzIbF+meWv30V03rF5PyeWSwkVloXIA1cs3jT81+n
         3G8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6qRvph6MXIA2/XIUZcZgb0eqnyzrWBYx555emMCB/LE=;
        b=T//zSO2LrVXH/mXgxSZTIJwduW6bYPfIBe518SHEGobGSzY0f224hI8VaiLPb663Qd
         wf9QZgrukK9kbZPx9OvkXIK5jqMBAJ18upn1ocB40mj+vaByn0CrCqXTaRsLviZhYIjq
         WXy/F19l6+qPCShvWgVAZ55ivdViTNYPpa+BPFYp0OibvMmi98Wdt5Gd6XUOncfVGA/H
         j5WexpyczL0eTiYsiQmziW24162Y8x7UBXO2UdrJ0nCGuX6NZNgW2lXUeReGGqQos+1d
         GrxRwjjU7rz1FW9/sf4FJyqf7w/eWr0FLsFrupcq47F/Xvuolrdq3TDC9TmOSKDxNN7i
         60Zg==
X-Gm-Message-State: AOAM532W/ey6SyS9/bsflzRC3wg6oc+3NOEZu4xkSLkaz4ZQZBN37QD1
	XN2nA1QSZU2NZvWjuJ1TfwI=
X-Google-Smtp-Source: ABdhPJwPf+tUKdtuUsM4sUE4f1UdXpd8AcyTHUkB15Yut3h1Q2DYty/mOkmN2mkEzXxGi0tADe0Lcg==
X-Received: by 2002:a92:cb44:: with SMTP id f4mr686539ilq.131.1609868900758;
        Tue, 05 Jan 2021 09:48:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9ed0:: with SMTP id a16ls24360ioe.5.gmail; Tue, 05 Jan
 2021 09:48:20 -0800 (PST)
X-Received: by 2002:a6b:8e41:: with SMTP id q62mr191254iod.5.1609868900392;
        Tue, 05 Jan 2021 09:48:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609868900; cv=none;
        d=google.com; s=arc-20160816;
        b=jt8lQQDcPHyK2HomGmU3s1Sh80Jf3SbtMP/c1rKCceYrWiG371MqR3gzno4ZeB4mle
         5+InTQ+6/e8AvDxLTUNDhSANZr5tsxUfwWATTKCpJ2ZK5L58KR+fNJQxvyic0cWoz73n
         HYDa5kHlr6w7zalFX4oqRdWzaFFbAAVoXopZ400AUkqbmf8AAQTHKGryNegyPKR11IJp
         O7sc1A19kjFNUH0sx6l/00hDFH+02CAg6BiDK8HdMmTJqUOGxpKHjqP88d4Qb0DjDO0r
         Yu7AT7AfOZgymZKrqs+6l0TbgO5U3TtL2T9+yNJRqZieoyEyfgpq2Q/JfU5UIg3a7pnQ
         JMTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ZixcJ7RylJhdo6zUEtkxbZFOpLxowdMQY57ZW65Vd9Y=;
        b=KMRyAy+2B182ypyjVDCcTOd4Phqzw6WDE/pyBVxA83cbFzTIcQodK8p7LGfjUtDfHv
         +EwjYYs/elAw+6/BNnWm1Ikn9DonoOrH5EDZiB7viv9ianspA+BjsdvDLLU4GKnJJGRX
         +BFDEk7IQR0ReiwJEi6RaDDwcqp7zBh80osxUNkqisFkO+QKrVCGln1hOKXpnfr5+b45
         qeDoo6G5KdmfxnviQEQ3rC/Rg1+WenZTiE28mxAXA798WIhEKlC38/I1/GvpO/rAPU77
         92sZVScU0pldFH4XtMnq0DAcHYkQq/RtkdRGgizgiXk/R3NrVid/J1zqP9Pd8QDVYNZI
         ekYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=JZkOToB1;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id j4si2182ilr.2.2021.01.05.09.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 09:48:20 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id b5so74596pjl.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 09:48:20 -0800 (PST)
X-Received: by 2002:a17:90a:cb8d:: with SMTP id a13mr330816pju.155.1609868899822;
        Tue, 05 Jan 2021 09:48:19 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id 145sm419463pge.88.2021.01.05.09.48.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Jan 2021 09:48:18 -0800 (PST)
Date: Tue, 5 Jan 2021 09:48:10 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20210105174810.GD287109@cork>
References: <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
 <20201209201038.GC2526461@cork>
 <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
 <20201209204233.GD2526461@cork>
 <CANpmjNMXOYkG25Gt6n54Ov+pxVjGMXRUWAMkDD4JWtLCNq4jPA@mail.gmail.com>
 <20201229174720.GB3961007@cork>
 <CACT4Y+aAuJexS9o0Vct--v5WX-a123OfcuKmYKgAEUWxSbzd5w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CACT4Y+aAuJexS9o0Vct--v5WX-a123OfcuKmYKgAEUWxSbzd5w@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=JZkOToB1;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Tue, Jan 05, 2021 at 01:57:58PM +0100, Dmitry Vyukov wrote:
>=20
> This is awesome!
> Are these bugs public? Or do you mind sharing at least some details on
> these bugs? E.g. type of bug, affects production, would be easy/hard
> to find/debug otherwise.

Not public, we have out-of-tree drivers from vendors.  One was a
use-after-free (write) and would have been exceedingly hard to find
otherwise.  The second was sscanf reading one byte beyond the end of
buffer.  I think the buffer was smaller than the kmalloc bin size, so it
couldn't even result in a page fault.

I suppose coverity would have found the use-after-free.  We just gave up
on it because it took too much effort to work with the vendor and deal
with their copy-protection scheme.

In case any vendors are reading:
Don't try to sell us gamification.  Sell us something that finds bugs
and is easy to use and we will pay money.  And to most developers, easy
to use means something we can invoke on the command line that generates
plain-text output.
Also, everyone is incredibly busy.  The time we spend dealing with
vendors is time we don't spend fixing bugs.  So if you cost us more time
than your tool saves us, you lose a customer.

J=C3=B6rn

--
"Security vulnerabilities are here to stay."
-- Scott Culp, Manager of the Microsoft Security Response Center, 2001

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210105174810.GD287109%40cork.
