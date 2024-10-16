Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLMCX64AMGQEPKYTWNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BE189A0B89
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 15:35:44 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-204e310e050sf83304895ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 06:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729085743; cv=pass;
        d=google.com; s=arc-20240605;
        b=euitRLaJ/IlAmhFYYGop+55WZRPM1zxAjJ9nFi1WQEnXH6cxVNaWc+ytxkw66Y4r5T
         yHJr9w5V5V+RDz/guuwd2ThtgbRcgHWPpkmCrwqdLBirINddXx7MKLwBTXR2yn8e99In
         Q5oH66Fst/Fj5jCmLAO5h83Hp1+J0ZHjOCVBmxcVoYrGEtIupvQpygHAmpjJCLPjnWxn
         1KQfe/MKvbkzQbSzJGgMGsqHheyLtjnstpafkV4u8yTfDhNLCHwm/oAo9qx/diPoMLM7
         YWtS9x9za1GVbH7vG7tWdW6DHJtOwbf3KPhOJrOgYD5DsvT+BD/OnxsxjzuYCqO/mJb4
         e5yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/+xWil4rPTwK8sNgT2qImsmzT016/zGHSHB2tTRG1oA=;
        fh=sf5rZn5NfdIkCp68VZQJCpOnbJLcxZncZps7RYalTrs=;
        b=EgmVhA2tgIi6IzrZyj1JSVoYt4l8/aXlbkaKEeb9PMvSX3YKtV/ocH0snWDWp4ZPF+
         vcixPXdsSj6sBlQ2nEFSEtxmIC/6Ig6DPuJ66luy7ESbbIeG0ZcAPy/4K5FRhhvFH5+T
         YQ5txyRsQGChQLWonu1uWyXI/wmbcZouPpvs0CtgwaJyZ/mPHI+KNm4xUAoEW1DlxVI/
         UYVSafbJTaERbILIHyafOTaBZARY1aPf7VPr8D/gxSgu65vgEo4nahBN+MAzf2gzHbvO
         +Or0FW9kbUMTEcn2KrfM9zK6UduS8xin74waL+r+lPEG0/0VB1IMfGAZnOJAwe/O0ypp
         2yLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YpGmsXHB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729085743; x=1729690543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/+xWil4rPTwK8sNgT2qImsmzT016/zGHSHB2tTRG1oA=;
        b=Tl36tDPGA1VMKntmslRNjENaiFaNnNt9GxmdFHk4xNRnspBsxFYxImh7UjuOQ9xspu
         itotn6gOJ9PU5Hf1e5M6LYgcQObeV7fIBIWqTBD+f4tDCPil19R5IhsDIBp9TxHESnSA
         1A+R1Z0JzEfi6FdpVJemqCx6zDq8XcdM38BQIekq3xFFPb3QexwySh8HeXDCH9ChBegv
         72rOoJUV8gqPZ/LH4qdK02U+7lJGkLC9crcw3wRWTjPfX8yQ9U/KUhS+rsUJBwych2Ge
         R/q7TH2ahbn4Og5gCe7F7K6+kXOrbqD6rxgNmlqW0Bcj++3fNfK/j/ryyZyos5WeT7c0
         HgUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729085743; x=1729690543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/+xWil4rPTwK8sNgT2qImsmzT016/zGHSHB2tTRG1oA=;
        b=P+ZVFbu7dY55n1ehXSLnNnLkSGevRX8e0fiMwyRXKQL5aMpjxNxZpThEDKLiq+AGPz
         zyRxLL3hHJXiLWaE1ymU78nv67F/H8136vmkv9ZGn7Penuw8vxHVbznsQHj9gDFdBTpG
         GA6m6DXp9H/6hnGlOMGedylGj1WCSb+XAYkwuFgFxJmM0mQfPa2/67K1/PE00ZBxYGWT
         sTShsR32F8QccbIUVyxRXRiqNz3QL1IZNcd2JOh9hji+aN1Dc+b1tvvj259t7T6GQ5Yk
         WN9p77igU/pJo6oq/2JNIGpyTGyGaSExP94UnXEfqGXuNQ6LatQNJTdBZFwsy1G2slnF
         EQrw==
X-Forwarded-Encrypted: i=2; AJvYcCXJ8Vgjfu+j8LzJatNOOmSh/fW98cIqwsWTmJeaVitlOiorzYZYOK+GxBFFlRlBVDMFBRrSnw==@lfdr.de
X-Gm-Message-State: AOJu0YyaCDIWif+FV6p2bNg/7dg1z/0YcbVlHym7LAurZ2dW/PshN1Ya
	fho+Wx9Ilak3k3FxdCaOLnMsVnx5MrnRQVFfO2jYRb0HarDX+u+O
X-Google-Smtp-Source: AGHT+IFsD6Eo2eilQj+47ZTxE+56Ag9N8GCbinoiSHArb9eafUJiYVt9VAFmYihfZg0MpimjiVCfCw==
X-Received: by 2002:a17:903:18b:b0:20c:ceb4:aa7f with SMTP id d9443c01a7336-20d27e5a05fmr61941525ad.11.1729085742080;
        Wed, 16 Oct 2024 06:35:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:440b:b0:1f2:eff5:fd69 with SMTP id
 d9443c01a7336-20c8069d4f2ls1836635ad.0.-pod-prod-08-us; Wed, 16 Oct 2024
 06:35:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUouNjqx1C4fLjtyCnL8jh0vxr74vcbkk+6pOVWcwgKlXo85yAKsqHliKeavqOR14BlWh4ZI1KY2YI=@googlegroups.com
X-Received: by 2002:a17:902:d4cc:b0:20b:9062:7b08 with SMTP id d9443c01a7336-20d27f27632mr54546985ad.45.1729085740829;
        Wed, 16 Oct 2024 06:35:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729085740; cv=none;
        d=google.com; s=arc-20240605;
        b=edGOi7KlCWyf+Iun9qTHTmk5FYim6SInIoHrdaDb6NlB10y0Y+BML4yTUOt+vPkZLw
         dhNuZylx5XeYrAAF5XUbV4JRaOqUriL8mv/kJZLmRkEVQMUmnBoxBay8mA08agtdbFkU
         I1NM58OStnBGRgepGENDEHHHFQA5DeW+3LPAbvD0Q7HXxQOwEhGXpunQPjCc9KXFFBzr
         WZfanQN2g/3P8KA9yiZAA2gmovj77u7ZUrL+VnPOZHRPLxB3CetMds1t/U+9xLFJQu3w
         x9k7TFazWZtNo1w0WYlZK0yoa5fmmuI7uxy2Cf0lg/cmzHyXExk6oDwmrsdV8yEVrEUm
         tMVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RGFMMPXEklcwVgl1501lsYrVn6gGilFzAu+XllYmFno=;
        fh=uvMteHMCiap/pr/g9nN33xBU/nQ+s0iinVg8KmftHgg=;
        b=b80gYS6CT/112Vq14vmv5I3ad+Ndixi8A+bWB6dyMwhw3Ak//+/zGXhF6U4M+QuYZO
         7Picu6zOsPWf4bCoYEL+xgr3n4z79Am4yI9qrbB6XN57XSLoaHJyJkLYXO5DrdX4xEij
         wk70K/Tg4T62MU22P1yXO9a9d8GvuEtrame+v4sk+JE0vAdMMuCFcYRAAzNRGZwbE1a+
         6eOfSrmow/aX0cP0xanU9E9tIEqnXCUbkjyYL/R/scT+X3CmChCwkOQ92ioL5S8h1Sov
         ecCeEft32PSNkgc16/90/X53vKVJRyyyR+r73A+gnjKGybIX/a3pBdE6wtXEnJ3XekH+
         sX4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=YpGmsXHB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20d18021c40si1525165ad.2.2024.10.16.06.35.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 06:35:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id 5614622812f47-3e3e6d83138so3841885b6e.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 06:35:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWY+hfb8HG1UbVPOdNFIL9okaM3XN1wjFj4ImsqRZWVsyEQh0s0s09EXNGTQQqxS03j3LTIhwO7nuM=@googlegroups.com
X-Received: by 2002:a05:6808:1905:b0:3e0:6864:52d5 with SMTP id
 5614622812f47-3e5f02584d7mr3874075b6e.27.1729085739815; Wed, 16 Oct 2024
 06:35:39 -0700 (PDT)
MIME-Version: 1.0
References: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
 <CAD-N9QWdqPaZSh=Xi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ@mail.gmail.com>
 <CANpmjNOg=+Y-E0ozJbOoxOzOcayYnZkC0JGtuz4AOQQNmjSUuQ@mail.gmail.com> <c19c79ea-a535-48da-8f13-ae0ff135bbbe@stanley.mountain>
In-Reply-To: <c19c79ea-a535-48da-8f13-ae0ff135bbbe@stanley.mountain>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2024 15:34:58 +0200
Message-ID: <CAG_fn=UZwpvANRFqgXX+RA3ZO_KLAcQFs0kjeim0Y75GoAgJ8g@mail.gmail.com>
Subject: Re: [PATCH] docs/dev-tools: fix a typo
To: Dan Carpenter <dan.carpenter@linaro.org>
Cc: Marco Elver <elver@google.com>, Dongliang Mu <mudongliangabcd@gmail.com>, 
	Haoyang Liu <tttturtleruss@hust.edu.cn>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, hust-os-kernel-patches@googlegroups.com, 
	kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=YpGmsXHB;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 16, 2024 at 3:30=E2=80=AFPM Dan Carpenter <dan.carpenter@linaro=
.org> wrote:
>
> On Tue, Oct 15, 2024 at 04:32:27PM +0200, 'Marco Elver' via HUST OS Kerne=
l Contribution wrote:
> > On Tue, 15 Oct 2024 at 16:11, Dongliang Mu <mudongliangabcd@gmail.com> =
wrote:
> > >
> > > On Tue, Oct 15, 2024 at 10:09=E2=80=AFPM Haoyang Liu <tttturtleruss@h=
ust.edu.cn> wrote:
> > > >
> > > > fix a typo in dev-tools/kmsan.rst
> > > >
> > > > Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> > > > ---
> > > >  Documentation/dev-tools/kmsan.rst | 2 +-
> > > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > > >
> > > > diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-=
tools/kmsan.rst
> > > > index 6a48d96c5c85..0dc668b183f6 100644
> > > > --- a/Documentation/dev-tools/kmsan.rst
> > > > +++ b/Documentation/dev-tools/kmsan.rst
> > > > @@ -133,7 +133,7 @@ KMSAN shadow memory
> > > >  -------------------
> > > >
> > > >  KMSAN associates a metadata byte (also called shadow byte) with ev=
ery byte of
> > > > -kernel memory. A bit in the shadow byte is set iff the correspondi=
ng bit of the
> > > > +kernel memory. A bit in the shadow byte is set if the correspondin=
g bit of the
> > >
> > > This is not a typo. iff is if and only if
> >
> > +1
> >
> > https://en.wikipedia.org/wiki/If_and_only_if
> >
>
> Does "iff" really add anything over regular "if"?  I would have thought t=
he
> "only if" could be assumed in this case.  Or if it's really necessary the=
n we
> could spell it out.

I think you are actually right, "if" should be just as fine in this case.

> regards,
> dan carpenter
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUZwpvANRFqgXX%2BRA3ZO_KLAcQFs0kjeim0Y75GoAgJ8g%40mail.gm=
ail.com.
