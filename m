Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYPWSDWQKGQEMA3P2FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id C8B5ED5E4C
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 11:09:54 +0200 (CEST)
Received: by mail-yw1-xc37.google.com with SMTP id s39sf13205222ywa.19
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 02:09:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571044193; cv=pass;
        d=google.com; s=arc-20160816;
        b=UrOn5xGJPYG+1v0NpafxA1D8Gnj71AbIdTcC32gm3MkUHSDMVgpHyw8Y1lVeom1pFE
         sh9hEJ8DSoWUdqeh/oV+Q/nIdkuhMGyzZQF8jYcKbnkuiaTtyf7IwmESafGR/7aiFho5
         t6ZB5vn4pWMutfKkc0LphgepKDIp5K9+ioyeYtrv2lETDuHqVks54Iid8whATCwAwtZn
         yDfnIvQ3/YmE124Y8ewEm0o6ojPxtkds72p8c+V7bClzkA+Wywqvy5/maAsIY1844Ckm
         MSIhn5gOytoxB/m0QEnD/VazPBoh6AQVsYSNKsKPxblx/o7razED7zgCtE4UN44l/FkL
         n93g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y6Lh6u0sMy5M/hpfbJmliHEr1hc4vsRvtWSaZk3wWWU=;
        b=SEMbvhNwFt5kX5Dgef1NA3VIk5oJmI0j0eAncbZs1vlb7uPaLzEXLa3AQA5g4jdWCb
         q6etzn0tIscGbVRJSu3xamhk6+24L6SUijkImGl4HCJq5wCIAY3XnwEfnJPqJjv7+r5/
         uzpB+tpm+CfUunvwHG58q+FRat7STtXVgDnGsfUTK9uAiOBrRGyWx/n59U12Xp4Jw9GB
         WRjELKSFAnF0pYObOE2KWlenFXQhbZdN3xWGCTdUT59PRBOA/IyAJhu0RJ17DoG3Xa0j
         HrLAnFXIJJK7kP3WqArDxNb9wBN0EDnLLSdyCfEn3Budda9177HjU0IUM7mFywaFN/u2
         Utdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=utOwdNUa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Y6Lh6u0sMy5M/hpfbJmliHEr1hc4vsRvtWSaZk3wWWU=;
        b=hJUJNNVd1iX32rejF1Oh4G+SZ3B3EksOd8xMmlwAJRCcCBIU5Qg0LHrNRC8Pq/nW5V
         /4ahNGtlSg3S9AuShFuHvspIOF7ahYLaGKwy1khZFuNbUIweLakA7s3xQwe40Fjv7pnf
         cJDcrkCdl5VBFoLvhDC1Smsg4ZngbDgWS83qjInyqne008jZ3XYXAzdOLpeZCOzHmHfd
         /o5htsv8kZ+zq7tzLRpxSpnP9BpAqQKde+azh3WnrUN1XiWqL9plvI2YIlO9sKKN9S6G
         U0lVdxX9La37vCQdBAE8fVj2+gxelQDRFZPL7/OpxvkQSP/GZhMDw2W1ySSMdGxLOrWX
         lEnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y6Lh6u0sMy5M/hpfbJmliHEr1hc4vsRvtWSaZk3wWWU=;
        b=d4/t4KHtQhJKAK0OKzebtNVZPIvd/l68pA2mR/NzzU0jwpDmZaAiHPtLgdUi60VjFp
         k/O2wFkdr/G0YmZ05frYvJ/KdgVsExxvbfB7jgX9ZD8uqim58vQX2j+FYvQYxWxDy/p5
         vWcQ/1hKevjMiRuK6tg7BhU63qA6jAMJIC89TAIazH/ueMRCvbfohD6MQTmTOPsxMPUL
         9cy+5pWoEIR3UHQRxWd02QIwyZ8odbJoPGTqq0wz7kGp+YnpqTVkabDyXiZzNQYmliA4
         DMTgSY6n4ioNTztxpzf6vGxs+knUn9jkhB480UcLefljbWFiPv6QO2v/L6u4DVqVNNjI
         94+w==
X-Gm-Message-State: APjAAAVOVh2UFxjY8NOLBpk5SlQhYKlGZ2MTvpbeDWqmqqh1sM46/b3Y
	ziJqrQL9pIm8HDkTVECP0ew=
X-Google-Smtp-Source: APXvYqzwMT5vDCpH5erYWDDWJ5OBmXjFO/S56d++fmTtAqlHzSJwbJJjUsayo9bxowmEIpRvNGV9Kg==
X-Received: by 2002:a81:53d7:: with SMTP id h206mr12113614ywb.38.1571044193466;
        Mon, 14 Oct 2019 02:09:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:77c4:: with SMTP id s187ls2344552ywc.7.gmail; Mon, 14
 Oct 2019 02:09:53 -0700 (PDT)
X-Received: by 2002:a81:b343:: with SMTP id r64mr12043644ywh.96.1571044193163;
        Mon, 14 Oct 2019 02:09:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571044193; cv=none;
        d=google.com; s=arc-20160816;
        b=fccIP+N750tVDxpdmBCeoyfE64ocOskDKiQm8prXTVSqjAiuHHVvP2NOftyy7Woxld
         dCoqZHyVPMtZ7FCZmpZ+a6Dkk458NQh6X47zzI7u6wxHfy8feEZT0tJlMpaql+MJbucN
         G5Mf1onWD9uI2xU47DKvaFdVnyyVnm0cPFs7Ef0H5aaBTA+DxC1JP+Dk6bd+FCW4pP7h
         nW3LIkdJL0TRDiRdZqQHctgaF0rgDMnFebvSMRVkHS2JUTHero1Jn03p3Qs8f/7QtsRB
         G/RKgKdFqom2Akt3VLTfsasj2IcaARXJXLAcv7dRf9yeUGKQTLtMANJSOC5jEvgAh/Fn
         G92Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mmj2BkgM8N7EfRm0KQme7Wm8/QTctqo/rgR46m8jYww=;
        b=dNqwuhOXaTEJAaKd63BxsbduyBtvO80jfO0YfE0NkabNFAH5hE9mDYPieqFypdNSLn
         qQLol/QxMuESaaEtsAwL4TgJHL3h7zf8xDI0PZOa3BxFEKyXLISUzJvW8aLvxej22KHc
         Yh20fbkCXYFQM1c81eu8hy+ah0RHsFvF0srxHt8msHwbiguVCD41bYJ6EBbC4xV8d4fd
         xaav7x7AWe3rLy2rEOfhSkuO8r6rVMelYlCcOpkyAwuYRwxUzYXZHhAlv8wSjiqqF896
         WAA/f74vf/R4KWaqyPy7f6xBxDr24jp0WcnqnV+Dp8qBPm4sFsxpV+TLPxjQ0WTBQgNb
         uSrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=utOwdNUa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id p140si1712947ywg.4.2019.10.14.02.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 02:09:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id 89so13156997oth.13
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 02:09:53 -0700 (PDT)
X-Received: by 2002:a9d:7590:: with SMTP id s16mr23066520otk.2.1571044192234;
 Mon, 14 Oct 2019 02:09:52 -0700 (PDT)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org> <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
In-Reply-To: <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2019 11:09:40 +0200
Message-ID: <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: Dmitry Vyukov <dvyukov@google.com>
Cc: sgrover@codeaurora.org, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Will Deacon <willdeacon@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Alan Stern <stern@rowland.harvard.edu>, Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=utOwdNUa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Mon, 14 Oct 2019 at 10:40, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
> >
> > Hi Dmitry,
> >
> > I am from Qualcomm Linux Security Team, just going through KCSAN and fo=
und that there was a thread for arm64 support (https://lkml.org/lkml/2019/9=
/20/804).
> >
> > Can you please tell me if KCSAN is supported on ARM64 now? Can I just r=
ebase the KCSAN branch on top of our let=E2=80=99s say android mainline ker=
nel, enable the config and run syzkaller on that for finding race condition=
s?
> >
> > It would be very helpful if you reply, we want to setup this for findin=
g issues on our proprietary modules that are not part of kernel mainline.
> >
> > Regards,
> >
> > Sachin Grover
>
> +more people re KCSAN on ARM64

KCSAN does not yet have ARM64 support. Once it's upstream, I would
expect that Mark's patches (from repo linked in LKML thread) will just
cleanly apply to enable ARM64 support.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong%40mail.gmail.=
com.
