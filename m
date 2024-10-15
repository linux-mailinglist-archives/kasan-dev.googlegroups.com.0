Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI72XG4AMGQETM7LUTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BAD399EF9F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 16:33:09 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6cbf039dccfsf86717976d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 07:33:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729002788; cv=pass;
        d=google.com; s=arc-20240605;
        b=jH4mtP2nHoxlVk+0v7JV0WdCl9qtEu7+8DqvNZXTyL4kQFZo/5NunZYFXLFziMvg2Z
         EgSFMf0iDVdhmn70bWj0fpwrPn+ykExMPT1oyjGolLJ55bHaYkuw+/wHXBb3ghe9dILF
         rn8dxL7YNOfgH9nYmWFlbDFsrPqw43nr5J5gwuieQ0W8gjwYk79QgCPk2uNM0ZDNxM1d
         8Mv9BG8+7HzXiL6bqFEvSEXBD3HITqddI0xBSXzjFWYGHaOJsnaL9UG1Mz2w4sxDtZTB
         yt3DjrQrNGq8v1+AW3U7rYraoj2Ua/zGRyHFGWhwT2ZW6u8+LA+h0O9WwHDbbetyolPz
         Gyuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=odcHtQ1RqBN/FnKXVezHArYuvz7pcGaB8xyDYxWTusc=;
        fh=Vb5D7vevdjQa9AQpWiiovmRVu1r2sdJBymxEJhnI/dI=;
        b=QWQuE18BcMqvIeuzwofarm/QJyJ3OAxi/QVDL6k7m+xFQGbja3hh/uxBM8dk/hhrDP
         S2lywh0KNjtb/z3MOqYFoRdCgzvxQ5bkl0ef1QY941MhknS+SZNiv9841l/llej/JcNf
         xepxHAWCNPyN5uCYP4Pe00b40S4rvCjJDMKgXokeYGwJAUU2LdzHson+oQb5C1yw8iH2
         Qtsptv58sxttvkQNtRIXbhLuaZmkuLYpSOW7Arha9tbN7t20J5wnbn3qcotJW5eT1x7c
         dVjh1hWDFVB9H8nn2Jj7TOtjDd9kUlVZpvnjPoAQ4PWIR7MVt6R7s6PpGGn8HehBOLzb
         RkDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sSc2Hyiv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729002788; x=1729607588; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=odcHtQ1RqBN/FnKXVezHArYuvz7pcGaB8xyDYxWTusc=;
        b=CD23gJ31/9s+29eNGesCxXWt0Ma5P6/RAp4M6TBoRr3TnlAWg6li3/qpMfbP7DnVuu
         Q08W2ghGONqyKyI+rCYHdDuP8WlAWNi69a65X0UZ+7pt6X9KBQr/E2ij9Tg5CI6O/TMX
         KdPs05d9FCKqr/Kfnn2NZyggjxbd/zWmNTTBquIxfrKP4OnClXhHsjor4b+dCjeFc3Bf
         NW9tIINMTzWGar2nLo86qKHsCdIqpeKBouNgeFHZ3+w29ytXHHr1fJ0sD9m3S16KBjfA
         SpZcZJYxiJMNsEOV4KIyxKps+KikqEGjeU9+w8IxfT93vg1skgDCOONkJ+xD8dmKSeG7
         xe+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729002788; x=1729607588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=odcHtQ1RqBN/FnKXVezHArYuvz7pcGaB8xyDYxWTusc=;
        b=rTARlpdcDbhetaOaI/qWZiFN6BzJRS7U+LAp7svibNhzD8K6dgZs6newxIBqCoOce1
         J6itqZMCq7mIqp+94G96oVNkngaBT7gDYwv+62ZQancCctHJQ6WQG8tRUP9ZEvpNtYJI
         GItJEbBsWSEDR82TcMF+QPQxEevm39CEBWyR0+yqDndW8dXtCUN4d3WF//YrrHcO/QJu
         2kaeVD7ED/vFkp1yEkCdOHtUASag3sEZHNjj1gBpU9UdiCnMnT6kBN/Cv+x4YOTXrVeW
         tvz0ntZ3qz6X9aFBCAfiPrDaIVuTRZp9SEJblEx7HDsX9lfruQDdmam4oIbZa7qvGVVH
         t0Rg==
X-Forwarded-Encrypted: i=2; AJvYcCVm6cpxAtQW2qzi97badn2HSW33Lo+9j6vsE4C8Ox0bvKNHT1wRfhc7EHp2iaaPHrbh/mbX1A==@lfdr.de
X-Gm-Message-State: AOJu0Yycg1uOOOD/sKW7m9+xNHnN8IGsOOYd06kOnxHUzS4D4rQESEC7
	bN3WLgIHAlLnsP/rNBlIhTm8xN53UHI649AUg8RVD28QOfwUeAGG
X-Google-Smtp-Source: AGHT+IESg5M5KDfsfafEK4Fm5E4xBDNhuRUsah/gvRJD6el8L5apMSuSV2I50sMmBY00hsyI/zlKMQ==
X-Received: by 2002:a05:6214:3b84:b0:6cb:c54c:b782 with SMTP id 6a1803df08f44-6cc2b91a5d2mr6770356d6.32.1729002788058;
        Tue, 15 Oct 2024 07:33:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:21c4:b0:6cb:7ce9:f52c with SMTP id
 6a1803df08f44-6cbe5492462ls7770486d6.0.-pod-prod-07-us; Tue, 15 Oct 2024
 07:33:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUyox6a12nxLv8WSiJUWA7QgdDUwHjtez8KY7oJkM0j4FCKDGlYvdH2Gi1WwZSjO0bHrRpyuprn3Us=@googlegroups.com
X-Received: by 2002:a05:620a:2453:b0:7a9:c0f3:3ccb with SMTP id af79cd13be357-7b141849703mr77578385a.40.1729002786383;
        Tue, 15 Oct 2024 07:33:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729002786; cv=none;
        d=google.com; s=arc-20240605;
        b=Ov7rXBasJi5BBhThsU1IOqiU0Qgys1m8YAY9WjLxtREu0FVUfnEUJMT83hFmgHjR8z
         snbfhD6UgoO6EE3qMspTgqVsh7xbYJS7ZCOeFgOSH1Cd6PAk6ZZsn9M9XGWiuAkYgWy2
         7Zvj/a+GKqQlLx1cMsPt/MD5u5sik9pfEMxPl9jstxkGeNPsxgbyVCCmYSc3eSE+pZen
         JhETAoz4oHMmYP8kmnBCXXF62aCoUhHD7CWvNENVN1VnkCClaiRjzM82NwpLO4hhEulb
         gBklpVYMfA3a9Xvk5Kgjnh4uSAwPK1uwsvO3NzWrIhUuy655C9NfbmToy3YEB7sw2s8F
         0evA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qYbi5gZJ4OrZjgdOZozfnDl/MQxnlNPVWNQhf6fR4f0=;
        fh=5bNBxezQpueZ4qOyqhtZ7Iqoj83meHNnSHL5xZOYcmU=;
        b=eokBJd980wLSrJBwjtSQTE8Gdx2HBZfX/dfsrMWtNLEcfeKQS6qj8S+mzpGjidSgd7
         WpPiTVoJwMw9FpmNsMEfbfP76iEAuEwYMSFIvsZvDpj2P92adYI34Le/Lza+1ppx7je8
         iI5uVcSsqUhHAfiEQ/QdzACIDOSnHfHPZTLsYSTjT4VIWwFWlJVyIBvSarvxLRxy7pmg
         622Pq5tmJVNKVptBIGBOiXiJmqTQt/ce+HPhrASkh+l7AjuH4BDMjEloTd454gXlAVA7
         DE+CUDuSfavLuavgSGtbqIfBTTAncBsdKmy2p17UV+MWocyfz4BvwxF4fEFgyAnmIitE
         bmCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sSc2Hyiv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b13d8b27a8si3069985a.1.2024.10.15.07.33.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Oct 2024 07:33:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 3f1490d57ef6-e290e857d56so4532394276.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 07:33:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUQqczGSfCRvNzdLhSATX1HnZGbN+ICtRFVcEyvei5/hz/B2VODRyrbqXfvS+h7E/dFC/fSi28pmfk=@googlegroups.com
X-Received: by 2002:a05:6902:114d:b0:e29:3923:9934 with SMTP id
 3f1490d57ef6-e297830bb05mr532299276.26.1729002785701; Tue, 15 Oct 2024
 07:33:05 -0700 (PDT)
MIME-Version: 1.0
References: <20241015140159.8082-1-tttturtleruss@hust.edu.cn> <CAD-N9QWdqPaZSh=Xi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ@mail.gmail.com>
In-Reply-To: <CAD-N9QWdqPaZSh=Xi_CWcKyNmxCS0WOteAtRvwHLZf16fab3eQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Oct 2024 16:32:27 +0200
Message-ID: <CANpmjNOg=+Y-E0ozJbOoxOzOcayYnZkC0JGtuz4AOQQNmjSUuQ@mail.gmail.com>
Subject: Re: [PATCH] docs/dev-tools: fix a typo
To: Dongliang Mu <mudongliangabcd@gmail.com>
Cc: Haoyang Liu <tttturtleruss@hust.edu.cn>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	hust-os-kernel-patches@googlegroups.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sSc2Hyiv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 15 Oct 2024 at 16:11, Dongliang Mu <mudongliangabcd@gmail.com> wrot=
e:
>
> On Tue, Oct 15, 2024 at 10:09=E2=80=AFPM Haoyang Liu <tttturtleruss@hust.=
edu.cn> wrote:
> >
> > fix a typo in dev-tools/kmsan.rst
> >
> > Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> > ---
> >  Documentation/dev-tools/kmsan.rst | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tool=
s/kmsan.rst
> > index 6a48d96c5c85..0dc668b183f6 100644
> > --- a/Documentation/dev-tools/kmsan.rst
> > +++ b/Documentation/dev-tools/kmsan.rst
> > @@ -133,7 +133,7 @@ KMSAN shadow memory
> >  -------------------
> >
> >  KMSAN associates a metadata byte (also called shadow byte) with every =
byte of
> > -kernel memory. A bit in the shadow byte is set iff the corresponding b=
it of the
> > +kernel memory. A bit in the shadow byte is set if the corresponding bi=
t of the
>
> This is not a typo. iff is if and only if

+1

https://en.wikipedia.org/wiki/If_and_only_if

Nack.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOg%3D%2BY-E0ozJbOoxOzOcayYnZkC0JGtuz4AOQQNmjSUuQ%40mail.gm=
ail.com.
