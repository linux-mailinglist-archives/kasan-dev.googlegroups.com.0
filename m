Return-Path: <kasan-dev+bncBCCMH5WKTMGRB6N3XPAQMGQE6BJUVRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B762AAC06D8
	for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 10:19:07 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3dc8689c611sf13910075ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 01:19:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747901946; cv=pass;
        d=google.com; s=arc-20240605;
        b=LyvCEbwLjASDjMY7J+ClJjS420u82pPS8U12yx1LrfGnUVgGMpdDYthWU9qAWXUyQq
         QPvYIocRJptBbSPuuzTcdlM0/XuV+rOqD+u1QBTQ+CKNLCDAw+7UupmjP0o7HyCdngfb
         sKGlYeYYrrauCROOV/VNbkqzg5IEkcFsB1WECNCEzHSlt2LP3JG9qrROcmUf8gazq/WZ
         P/TidE+zTkWsW+wQMKTn9mq1/4ykHFER2h8YIFrGkQCt06+dlnUSQ46GFPE2dvPNrVoQ
         8F2Reaw6GGvUhQ/OsH1BpwwDPNvsre8e+seffhaB2w5Xn+0TPj42L6RdD7wa9K2iLlvg
         Zf+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1doyCScSBkaTloopkFE3YtyWfPcJaXRlGovHgMDBePM=;
        fh=SPg7E2l7Msk4CpzyM3injyP4pTXX/qdFymGIMx5EK8s=;
        b=TJLLPaK0QY1gKyrBLcP/J0uja31ZlkEK+SNU+v1cao6mAC/3Z0ShYwhXah6NkVSwCS
         HeEeqwSQzmxtZIyWHdKVzfPjRFJzjyTUUGC5xgT2+iqe13FHGod6cIcmZ0mRE6TOCufV
         4beSkS3Yb4RVi4LSaAVbedNhhXYrqLWqjU6GPJdxnerDTkLKf6iBnjmN45Gm9gPrNnGC
         5Vua2cbWaJPymNMXwqyApJfexJncSWzcSTrEwOGu31dhtQCwz2JwhNUeZytHH/x7kQ6N
         h+uZnFcE9kbicl7EUZD1nhdxvTTHNiseAsysdSuklK2+Wqs6l6Sd/7VtDLEj16EWzlf+
         2g9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4cPL6kGA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747901946; x=1748506746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1doyCScSBkaTloopkFE3YtyWfPcJaXRlGovHgMDBePM=;
        b=A/3CFRvRFuEZUfo6D0ST6Gz0i8X2AJXXHCuIaeYk2QLuGLhXg/CAOnLr3S4mtKu4e/
         JmxMBBtVI6Gq36A4yC1GPPWJPA6cQCNwh4aI0G/FRBqXBw25rOMbAWJNYEW+n7Zaq1PO
         WphJjORyGFqJaVun1U2XfQRRxInMc+uRnlfmJ40FHQ4QHTnWu0a2j7DkImC8IDu1QKES
         N5nwNCDOdWKRv+FKAKJOy+oU8+oaa1StOZY7fOutQTR+9pkoDBLbJVr5HJJq738AYkRT
         46d218ycsLvjQPaW5spbwORT260Ru2is5K7+6LT2gP4amugWEbBSzzVQWt605yoQ7+sE
         4Lfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747901946; x=1748506746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1doyCScSBkaTloopkFE3YtyWfPcJaXRlGovHgMDBePM=;
        b=etbZwwdavWaU4JuqaCG1BFtjhsFaU0NqDBrV2yDiEWqTiTXuhLDIRuCoOWqMRd+OaY
         9Pa1JYO336XcJUo2/TRYyJ1DhnaWCxaCtps9cw6XhqkYsfSbLL1lnzI95I96yT9BRA/N
         Sl8yE9ZNTEVzxnPIubXIvd0uof6cgRuFw87dc+QtMlpioE1sri9mvkt6iWeda6TGQJ5h
         FH4w+pl+AQhqnAhzlwUkbVrOljhXEtI3Llc5cvkeuDCEuwtXeokOo8yzPd+qbSZVIppM
         8nODo1fasGONAwTtYtd9Wocg8e+txgabJKN5k07bA+VLNBZsy4sh/tRu0T3sEkBu3USv
         2Q1w==
X-Forwarded-Encrypted: i=2; AJvYcCXcYah+DQIgD/VJJGlu7vlQzIs0Mcvz4i8HgWtujYqgqgzIU6BajlWj8AcXqQlELQ0gDIbIjg==@lfdr.de
X-Gm-Message-State: AOJu0YyMyGCRnnmzQuCAKnZJ8Harv7hwDiDU+35pCjKrfI7SikQ3Y7fy
	eMbEJ+xFRdVZY6jRRZ3wk2UAx3s9x7eY4GgmqXMBvV0Pq1HOL1AAOJqQ
X-Google-Smtp-Source: AGHT+IHBfRDpIg9YS0uIugXefntZrHb4v3YRQs1rrfyhEuSCKvWLDQLswlEV1xjXtjH9tyS9Mzp+gg==
X-Received: by 2002:a05:6e02:2193:b0:3dc:7a56:18f6 with SMTP id e9e14a558f8ab-3dc7a561c1emr113346095ab.22.1747901946129;
        Thu, 22 May 2025 01:19:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGzUi/azNrwqFBa25Led5P4DseaSEe02nsnu8KrCCi8pQ==
Received: by 2002:a92:c5c5:0:b0:3db:8425:8106 with SMTP id e9e14a558f8ab-3db84258317ls33634335ab.0.-pod-prod-09-us;
 Thu, 22 May 2025 01:19:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFE9LTtWfO4oPr6JYWJzcTUIl0WCgiqeeR3axmh31uW3XyJvKKUMj++r4dz05kg9EHwhGlxKeR01A=@googlegroups.com
X-Received: by 2002:a05:6602:371b:b0:85b:3f1a:30aa with SMTP id ca18e2360f4ac-86a23229aabmr3047642239f.9.1747901945075;
        Thu, 22 May 2025 01:19:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747901945; cv=none;
        d=google.com; s=arc-20240605;
        b=BKgdaEviEisCrJ6wVoVa2tBmm+eTNPUWWmWteJLCC+FP20G4B3bx/ALHRtQF/DEpsT
         GIpZZk+JDuE4kTgK7tOqyJkCe3HQ6JcZNQUzF2Vepj1cL1YnVpNlcTK/wFcUpWls74yc
         7rALqr/diMTXJO7o+Pyt6DhmjGUeMotvPrs+GkGPHJ+He29+Qsswo1l/fn5g3jL9+ZpZ
         mABWtYq2MZD+ZWB5r8Rq/EVX/S8148gyXPBWEox5gM6y24EVA3FH7UWzeuWHBoHUmCeI
         Mk/C0n8puw3Clvu7cBpKJkdfDOFfdpnAVrPJ93btN7BtV1BPBUET/iugp0i011TfMs7S
         +4dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oJTN6hV71jQUNgSy1LNPLAIveMnFUYRGpDK+06PX/VA=;
        fh=sBQ/dglpj0C3T3Mkm3+tZk4ogh2tDMk0yGoNqgULMwE=;
        b=lOVhUgZ1ozzr1EZM8iHEuBTEWe7kb8akILsF/RM0qyCinrix7yQ0UStGpSrILB++o9
         WBUM5VVGURVi20n2Zcpts/BodJdyb5q1h4jPW13MJmjcilu+3TcLrGEkQSVmCTdqh3zX
         C5114PJVXJHHceJYEg6OnTNR1xXD5PZOdcZM+VYUnxq3QbmVbIUtBwB3fJDS1wz2X0mx
         OXZWqLyX3JGLiAjfEN+f/aXZkGkBmDcQg3ncG9lutBq6PP0xzpRsnpYkoXQBfkRIDnio
         OikPE6IWaM7OYf2ega7ndS61SsQ5KljPCVlNRTZBXD0H03GIbd3umHbTY0WDS9NUksqI
         Ohnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4cPL6kGA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-86a236f3c72si62033239f.4.2025.05.22.01.19.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 May 2025 01:19:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-6f8b9c72045so80931076d6.1
        for <kasan-dev@googlegroups.com>; Thu, 22 May 2025 01:19:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW92ltuS/T+/2uaq4wVsWURLhA6mVdvzcV3ktPSPZ3TBUmKsgwihg+Hh9Ghphk7GWfaBoPmah/rzGM=@googlegroups.com
X-Gm-Gg: ASbGncuTHLrC4SVzK6Q4WmMeCtAbNw00LumWe07AklgeD9r27k567WPIc4HFzAgSWWb
	3iW/64Y7uNBxgxxsmtJTTOi2inzoGH06bpzzpY3/+46WXsrlB/AtVodpb1dIXMPre/Z/M8deLFP
	vdLZdpxa7ZP4aDeMPAOalUIDS4uAfkl6kSJ3a3WdzVuKKCvfKOjsKDapGGdlK7wlhCI2Fii/gP+
	A==
X-Received: by 2002:ad4:5f8e:0:b0:6f0:e2d4:5936 with SMTP id
 6a1803df08f44-6f8b0881a22mr402532476d6.22.1747901944252; Thu, 22 May 2025
 01:19:04 -0700 (PDT)
MIME-Version: 1.0
References: <20250507133043.61905-1-lukas.bulwahn@redhat.com>
 <20250508164425.GD834338@ax162> <CACT4Y+a=FLk--rrN0TQiKcQ+NjND_vnSRnwrrg1XzAYaUmKxhw@mail.gmail.com>
 <CAG_fn=XTLcqa8jBTQONNDEWFMJaMTKYO+rxjoWMHESWaYVYbgA@mail.gmail.com> <61db74cd-2d6c-4880-8e80-12baa338a727@app.fastmail.com>
In-Reply-To: <61db74cd-2d6c-4880-8e80-12baa338a727@app.fastmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 May 2025 10:18:27 +0200
X-Gm-Features: AX0GCFuwLEa7GMNWl3kzXafes8eikGOYdLyOEbupah07l52RPChxZx4Uvrgxo3o
Message-ID: <CAG_fn=XZ4CrMfPEr8hgsFfkuftRAKp3xLjAUqSjwmn5Q98c27A@mail.gmail.com>
Subject: Re: [PATCH] Makefile.kcov: apply needed compiler option
 unconditionally in CFLAGS_KCOV
To: Arnd Bergmann <arnd@arndb.de>
Cc: Linux Memory Management List <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <nathan@kernel.org>, Lukas Bulwahn <lbulwahn@redhat.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Andrey Konovalov <andreyknvl@gmail.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Lukas Bulwahn <lukas.bulwahn@redhat.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4cPL6kGA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
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

On Wed, May 21, 2025 at 4:11=E2=80=AFPM Arnd Bergmann <arnd@arndb.de> wrote=
:
>
> On Wed, May 21, 2025, at 12:02, Alexander Potapenko wrote:
> > On Tue, May 20, 2025 at 4:57=E2=80=AFPM 'Dmitry Vyukov' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> >>
> >> On Thu, 8 May 2025 at 18:44, Nathan Chancellor <nathan@kernel.org> wro=
te:
> >> >
> >> > On Wed, May 07, 2025 at 03:30:43PM +0200, Lukas Bulwahn wrote:
> >> > > From: Lukas Bulwahn <lukas.bulwahn@redhat.com>
> >> > >
> >> > > Commit 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin") remo=
ves the
> >> > > config CC_HAS_SANCOV_TRACE_PC, as all supported compilers include =
the
> >> > > compiler option '-fsanitize-coverage=3Dtrace-pc' by now.
> >> > >
> >> > > The commit however misses the important use of this config option =
in
> >> > > Makefile.kcov to add '-fsanitize-coverage=3Dtrace-pc' to CFLAGS_KC=
OV.
> >> > > Include the compiler option '-fsanitize-coverage=3Dtrace-pc' uncon=
ditionally
> >> > > to CFLAGS_KCOV, as all compilers provide that option now.
> >> > >
> >> > > Fixes: 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin")
> >> > > Signed-off-by: Lukas Bulwahn <lukas.bulwahn@redhat.com>
> >> >
> >> > Good catch.
> >> >
> >> > Reviewed-by: Nathan Chancellor <nathan@kernel.org>
> >>
> >> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> >>
> >> Thanks for fixing this!
> >
> > @akpm, could you please take this patch at your convenience?
>
> I have applied it on the asm-generic tree now, as this contains
> the original broken commit. Sorry for missing it earlier.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXZ4CrMfPEr8hgsFfkuftRAKp3xLjAUqSjwmn5Q98c27A%40mail.gmail.com.
