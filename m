Return-Path: <kasan-dev+bncBCMIZB7QWENRB7GW3DZAKGQEOFHA77Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FD0E16F990
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 09:25:34 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id h2sf300997pgr.12
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2020 00:25:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582705533; cv=pass;
        d=google.com; s=arc-20160816;
        b=rV41FIiNjFk5aT6l6cZBVIYP/cv6O/j7vlXYsYDNitMOY6MSk+0G87jE5vace6zlAb
         M36chzOTo76I//Ymf89MxhUn23FL+KNl1tu/32CuJvSVb1eVd5lJ/vjCuwGOKtevNbSA
         GDzd9Y8gBXcmcbDmecZVxkQJKU7+nSMXg2mSdSiKcoKZAvfCzS5K9MGYg1oe5ORCV7pK
         TuDT+nNBDXRWgSFCu9Q4hkbKCV5d41dATsN0EI9R3LMcE/qBY4NzDXcG86RGDiKLLCat
         QKEkW/QBNbjR3Du2wySs2UyZq5V9TcsfySQHuvhvQUXXbOWXVw7frfHr+pDPczFx2XW6
         EicA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QGRpvx91H/TSR9z2kjEqlvsAEg7+/0jXSNHkcG4/v+s=;
        b=S3/A+ZQiVnLbxJgEEHg4RZVpK7mZaWL6bwjok2DP8pnHp2HcFTByllql3WQ22dxahr
         H7MDtHhQY/A1lJH3JSSZPEyYsq1pbS0wqjhMGYlv5lswUKa1wdLfRsf4tn+vC8Tz1YdU
         +2vmNfjqsga3Z6EBePmuNs9rkjDIw+T3xnFdm5VLP8qxAh5alFan4rolK122S+DHQAjt
         jofDNh/5Ii8bZWIAb8ZgIPXUmVZro0qLqSwysNjLT6DNATRTrPNp4z0Y/nuyjI1ddNXF
         tupUrts2ablDqReEl30akZf9VALVdjJ4X9l2Bx2keEjMzyKb1eDNOe5D+WFSQnWKOm09
         AFqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=odZxHrCu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QGRpvx91H/TSR9z2kjEqlvsAEg7+/0jXSNHkcG4/v+s=;
        b=TwK1xQ1EUoLEiDt0KIlRpvZ7LjIiILALgpynjOwJNwdM+k1G2Tdj7EBUOF60BdYNes
         IzIWe2CuSfLQ9qTJY8rYPwgz7+JvL114JVdxlp3tFcV3ZEJOPLsDpzspGbrRyvPiXfvT
         lDIEM76LPebGOZpUvDD2ME06hD47jX2Dz5JxYiPyiOJvENCHauVGSCjYHjdHcfRnhJJx
         RcXjAz8ndY8ggXIy5pg8inwMjxLcgl0lUyYdRw8vWBJvunH/nJw0ERD3RiWLh9U2QrXX
         Nkkp1YDNTzQ+9+4kpTWWN298gxYSBx2mzRG5uHnrECEMGMwZiEGn1B4UFne9oUiOzS0m
         lr9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QGRpvx91H/TSR9z2kjEqlvsAEg7+/0jXSNHkcG4/v+s=;
        b=pnxLG1wH0DyQIu59wzbse5LzOWkpmhjiLwHFlOUXq0onk+4LeoKQUoc610geGUQe9u
         bDMk5rMfisCCNf6GgtYLFuepymO7RbQRwRxVkhTdYeHMkMXxy69QBY3YsAN4O7bmigKP
         yh5a/2eBplAiREdQ3saVTjvonzt9U0rFjqiP9e/gVHhiv3s/MeJ7hVcQ5OFJ3+8+RsDA
         bx5vfEJTthNuZABNEHZC/6G4swR1fBTRW/8KUpR3iDX5OmQYehMs+u7w6ovFOI9ryFas
         od5XaOMbFBtt1mxbUdb4J5/jl7OTakCDKixPH/EbZaown1ZpsALGbUZFGcNk7S3Sj0qs
         pilw==
X-Gm-Message-State: APjAAAWS+Lw30hRJdxhcgF/qTeKtj6ZWnDSDnTK7cni+GCpGXSeKuBr9
	yBERsmmF+qzBGgXkEPFwrUk=
X-Google-Smtp-Source: APXvYqxz/GQtVAiWPRwG83pF+4a6Fsw6MTIKo9Ggx3IWkykKuv9fD5cmm1apm167E9AucQ0lIRgFSg==
X-Received: by 2002:a17:902:8f94:: with SMTP id z20mr3004911plo.62.1582705532744;
        Wed, 26 Feb 2020 00:25:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:f248:: with SMTP id y8ls401624pfl.6.gmail; Wed, 26 Feb
 2020 00:25:32 -0800 (PST)
X-Received: by 2002:a62:5bc3:: with SMTP id p186mr3296233pfb.162.1582705532298;
        Wed, 26 Feb 2020 00:25:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582705532; cv=none;
        d=google.com; s=arc-20160816;
        b=FJorO5JpqeSNFMYNlkKoRUr4kROOd2TVRn+tgzJkNoEPGKEsu1nngv7A6RGF4Ix0W+
         IvlDA640yK5ItqKtT4/x2d/1sFhwfvQtBAqAX5v+HwSelACY+Q6V5iZwutCg/2xytuzy
         4+1IXCpFPwomcW0vzHi3eGhPNychaaQZouuuoT8b5hD8Ja3g1ZaqTd2dv7mO6nO/61w0
         PlNdDAQ1Ah1DZDa/19Vdd7GI7EDv5RwUWMqXTMy0r2/qMRzewiSfXuNfGHVAXyPTA5p/
         mWUf8FUGWeWFk3Z54xszVdDOPFZPCrErZipQQKCLPNCnwDTkJ5jurbHbvRZztD9rqR6h
         8mcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cjh2KSmW7Oxpq1/ClFi7GqmxslhaVoZOJbBuz8+Ksew=;
        b=dKeMJVkyXFVa8Zgr1RpMhUkuC7Vtgpa89ErawAzim7+WtkoV4NHQiOPfBh2DXLKAow
         3Rl6CeYySDIRuHaZj2SdsTcvs6iaFHEZRzcJqPufUpU39qhv/E38W7C4F0vk52kYah0l
         bkSUhjW/ktBDLzBlIaYk9N39fRvkdcj2uCp/46ngPO4hYkmjGCWioKnXL9X7oyaOkXTJ
         zj+Qu0HQu1p8elHeosdR4MI0qYtgA1TavQM9dhZD2B3kTvYmyLv7Vu8DbfyHs9XHN/+R
         t6urY8+h71QRGMeIecsZS7hyiAnH1bm7RchwZs59Ey44cUi9X+8HBSrjv1QcV3TlGDq6
         rtbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=odZxHrCu;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id h2si536205pju.2.2020.02.26.00.25.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2020 00:25:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id z19so1861535qkj.5
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2020 00:25:32 -0800 (PST)
X-Received: by 2002:ae9:e003:: with SMTP id m3mr4358251qkk.250.1582705531053;
 Wed, 26 Feb 2020 00:25:31 -0800 (PST)
MIME-Version: 1.0
References: <573fe6d3-7fc2-4a29-9ffb-f6099b7d594c@googlegroups.com>
In-Reply-To: <573fe6d3-7fc2-4a29-9ffb-f6099b7d594c@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Feb 2020 09:25:19 +0100
Message-ID: <CACT4Y+YiCthS8z=h4zmypyiVq7+Ungu5zTLHFzYTXK82uWA5Xg@mail.gmail.com>
Subject: Re: Build and fuzz out-of-tree build Linux driver with KCOV
To: bruceshenzk@gmail.com
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=odZxHrCu;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Feb 25, 2020 at 5:29 PM <bruceshenzk@gmail.com> wrote:
>
> Hi,
>
> I am exploring szykaller by fuzzing some custom drivers. I am experience =
some issues with out-of-tree build driver.
>
> In short, I cannot get KCOV instrumented into the dynamic driver module. =
This is not a problem with Syzkaller but with driver build.
>
> CONFIG_KCOV is enabled in .config file, and `-fsanitize-coverage=3Dtrace-=
pc` got into CFLAGS. I dumped gcc command with `make V=3D1 -C $KERNEL M=3D$=
(pwd) modules`.
>
> However, the final .ko dynamic driver module is not instrumented. The pro=
blem is that `-fsanitize-coverage=3Dtrace-pc` works as LDFLAGS, where instr=
umentation is done at link time. Nevertheless, module link invokes LD direc=
tly, so that GCC has no chance do the instrumentation at link time.
>
>
> Here is some extra information.
>
> Linux version 5.6.0-rc1+
> Revision: 0bf999f9c5e74c7ecf9dafb527146601e5c848b9
> gcc version 7.4.0

Hi Zekun,

Frankly I don't know, we don't use out-of-tree modules.
Does the same happen with KASAN instrumentation? If yes, it's a
broader problem, +kasan-dev for how to use KASAN with out-of-tree
modules. If not, then there is something in KASAN that makes it work,
which should borrow for KCOV.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYiCthS8z%3Dh4zmypyiVq7%2BUngu5zTLHFzYTXK82uWA5Xg%40mail.=
gmail.com.
