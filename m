Return-Path: <kasan-dev+bncBDRZHGH43YJRB7VJ3LBQMGQE4T2HMIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 13CD0B06563
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 19:51:12 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-3132c8437ffsf9459692a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 10:51:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752601855; cv=pass;
        d=google.com; s=arc-20240605;
        b=cso2IQk/XW2HUVU9WxbN8eCZFYl25RGcUU4QSlFv7FoqoWBVd9UQbIAKynLcz8oDuh
         F9MpdoXdEcFt6N04HKt86QVfbbJG/RFlOVu8H5UCWrMa7EsvL9Yq3sBgeWTY0bZlj1OG
         Q00Y9SC5uoNb2WWB074c5XQkuflnMhSfRYaXsqJotiE+AJhRdYRAj77WazB3+ujxWNcZ
         AhKa7UygMORImij2gatfP941gfcez5Yq9LBJyjs19zIbDdpgWGhN3lr2ByVbRZOtI4nd
         zc4qzu6GemmyUeehdbiHlFbQ1LrwYrUYpDIsThHurBbSTib9CkDQ6NQadbmO7/OW24Is
         DSAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8lfB0ZUUsU5CBVX3ay5UHlCO50r+hHlFFt1/CYQJ+rk=;
        fh=5II2qwmio358u9AeE3lheNo6xdbEUK1RhEYhpIqZjDU=;
        b=QrtKC+KY56w73G6rnHIlOIOX1fXkkavnHJ9GlJo1hG1G4UxjiYI3/o2zUQq5Aws1Ac
         xoX37hKkoMyFmiBspoYpY8JPKoxjATS0IdiPJJkqDGq4U0LFOPpoYU9NkeyVroXSTn5f
         x3Yql/Tbfg+tvjq0KMV+k7UcBPBGALxISWpntmCYaQuoRU89yhwzkxdtpHyptHvmxM/Q
         oZDWP1zet9Sp5THweKXo2JOQd+3jYJX+6IwNCATxZIiC8P+zhLYp87SeI9uaJNMLgVqO
         S9OAOCO8WovxLpWshlX6gtbBQzfqzKGtzeilpYY5dV7yQdKxo1R+4gHqoPihgcByfrb1
         LanA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DJ0St0AU;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752601855; x=1753206655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8lfB0ZUUsU5CBVX3ay5UHlCO50r+hHlFFt1/CYQJ+rk=;
        b=a9IIei7RRXvkojIRXcCX+ezW9Jyje3ssioziy47mbe5ceJtto9j9T79Qq/8Rt4u+CV
         H92/qajPyIXd0XJbyzGoRv90QC8ziNOb4D/wG1ho48Ueudf3pRhF6Gj5alqDak2EZJZs
         J1X8GsaE+9qvvCehxTZgOg3+Qb+JWqMMa8UWLO6d59yny7CDWryEdigIhDhpm4kWbrly
         +X8sLmLpDTHYeeEZ2VquRW93v4z35q3Ga2J3I+8MzI5+ax6REcDOzrXQC6ooCy1+7z0V
         x2Wnqr1ChFphDkosvQQ67tmN/J7NwOUGLQiNsMHoBTxCh54nG741YCmmmtU8JlP2uk1D
         c+rg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752601855; x=1753206655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8lfB0ZUUsU5CBVX3ay5UHlCO50r+hHlFFt1/CYQJ+rk=;
        b=kyec7+CYshXHNLyhDbKgw/lqHKCXvNhCvaHYROw/LwbICiERMX5gn05fUMAh0L/hHV
         Yo7x1zcarH+5nwwyzSHiAEJt4v9L6iibmb2arBMS1Qt9qf09KRooeIjJcye1G2PNamcQ
         N8NE8+4YNNKSIqAwtCDR5jv3qUuuElQuTGWunHKfMJUqq1B68ZqWWeCzurKB+SvvziWf
         7M0r2P9z7NrWql9Tuxr1K7RPJwgeBz2ECS4uaY4TG9UxQeQEeffQdm+iClUx2kT5fgs0
         /drvP1JTJ0xE8uzFwv4H1M20smFs4zyMGkfIPaDyIrC+hzIBTsunEakxLAr8HVEHqSS/
         +2lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752601855; x=1753206655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8lfB0ZUUsU5CBVX3ay5UHlCO50r+hHlFFt1/CYQJ+rk=;
        b=TWnzX6vOBCakQw0F7eatZP6MQ9iRv55Wt7GKxWDeULnFNU9oeYHBZQIjwg6SbLCxj6
         gZQVGQDOqw/N++DZ0x0oIjyVVe0xD8zu/irGvYqMhj6rxELrqFvYc60XZDliAUmB8vU7
         8V/WA25/U6yZRDE6FLS2n0hGjHUm3lE9e8ef9WL1XqL36EITmvxIkjJLjOe+neSssCBg
         WXaHQGndC9n8e7ZyEx6LAtIfK2Siww2RfVTrETemxq1BC9az/0tR9D2KR7T8qF2ZDpC0
         e/qvJm+wYsRzLm1epyLgo0E4cx6Ba4FPQL07nPYDUnGDgFvUDfek32CUgO/9I+NPxCcp
         4qZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVwGL6uK5wmCKSUNYurgllKAbpsxIvG2CIyzfea/am0OFei/NZSCForcfQf27nC8k19wfTVg==@lfdr.de
X-Gm-Message-State: AOJu0Yzu77rH6ehR9PMbwK79x1mNWHJmcjQS5boq5BvuK+IOUYKUjitR
	Y9jMa5nL3d+bameyVpE3T1XalY5/xxZtMuL97w4W13DpqpzlbDHW9ekW
X-Google-Smtp-Source: AGHT+IFgA5eOBfp/XKQWvIpR1b+syeiwMB3ueu/bvPvQRdvCXXBzwldM9PBny53QiHg/ZLXKf1bunA==
X-Received: by 2002:a17:90a:da8d:b0:311:d28a:73ef with SMTP id 98e67ed59e1d1-31c9e700806mr148530a91.10.1752601854493;
        Tue, 15 Jul 2025 10:50:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7+No5wIiMqpzx7+ZdDSObttQSYhH/tDyqldbtkWKX2w==
Received: by 2002:a17:90b:4a4d:b0:314:21ab:c5d3 with SMTP id
 98e67ed59e1d1-31c3c7adb7bls6278958a91.1.-pod-prod-06-us; Tue, 15 Jul 2025
 10:50:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYnAE1EhxwNomDJPFKZyzo4VHUDD9beaFMO4hcJXN4HW0xW+HapRZRiy104g+5Noj+CBUZIIub8Rc=@googlegroups.com
X-Received: by 2002:a17:90b:3d86:b0:311:a4d6:30f8 with SMTP id 98e67ed59e1d1-31c9e701e0fmr99087a91.13.1752601850901;
        Tue, 15 Jul 2025 10:50:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752601850; cv=none;
        d=google.com; s=arc-20240605;
        b=UD5xEI0p4g1ujQBrwVuCe7j4cH6Et87tDL8k0pdw/QJpaAQHlQytMz0TqD1ExvHG4c
         NXtfqRtMkAa/dzWb4C2oj7oPh6bXT9e8XC3kZ9q7xS0XbvI830NBcjL7B/cGXzOgQzEV
         HyW6h7uHwRMgtKOOCosBSdKTfudsWD1vyBzSuTJZFyn16Y9EDtOtGjIXhvsnSOm0zVSQ
         XxczauRnwYG1Ukfa4ux4iZnPoWT3VmLAx8GCqdSiF7HwBP8SGrC+xQv2Mg47RiHvSXxb
         FsY0KZrD6F+VTgpUSshy0dYmvBONDCqQliTSiPcTsfpwXqsHjYeoZQNoyrJu69GHWuUj
         x7DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/tvLXhbUj3btoVOLnjJSvLA3iyBL9Ok27em6LBsQ+Xo=;
        fh=FWceelyi4/vZtzqxmZhVa3i1dY8uD4xWqyVZxmt19Q8=;
        b=OHprYW3snHF9PiObzGRkknprZF+5qc4jVSvWyhcoAiCHQh4mo/Vii5Cu9jrwmbnQJL
         6AQXS/C6LJjrtcaVLucFOvV9/T57+ev8XY8ul2ZbCTbYovr2M/WTU2dE2vnT/p4mx4bZ
         6cfF9cNR7//kIo1JQempVbVfF4UoOeZK7Cr1269+OJgTR8hedzgEbUGr6BNKOHg/wm5T
         bu6PeqdtuStJo/JysX+IdfoWw+J0RyT20sjIhGOhsyyEWABbI706XRKCM/BWhlCMCElx
         QGdOTG9I2yaerEdHEyjBsyTmLA3oGneFxDbnx98fjW4Nc20RIl163ouI8PWamdZMW7Im
         jmlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DJ0St0AU;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c924766b1si98633a91.1.2025.07.15.10.50.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jul 2025 10:50:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-3138e64fc73so1387041a91.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Jul 2025 10:50:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV2jTMu//FEWuOf+DXQQuTOub3SScHxj9Pb8BBcGe+Ykt+1pFQI3648Fyix8Wf+kUhXy+RPN7biP88=@googlegroups.com
X-Gm-Gg: ASbGncsWH4EAnTVJG4dV0GHrUPsmaT9+0Cv90RbYBxZKvhywm5WxD8suUpDYkkGPq65
	hmhTiS44/8gLRIJTFH8z11TticL7bD+3goObEVHGDh0Fyv9NKWR2tsZ61vRjDC++Nv8iSZjXcbv
	IJuMObbxFvpBC3OyqshYJZDaYwptNYYXoWh5jmUCFXICGZvzsH1G6wU/e4vBsUNUlFcG81ha71N
	0JIPhmM
X-Received: by 2002:a17:90b:518d:b0:312:ec:411a with SMTP id
 98e67ed59e1d1-31c9e76ae7amr42706a91.3.1752601850205; Tue, 15 Jul 2025
 10:50:50 -0700 (PDT)
MIME-Version: 1.0
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com> <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
In-Reply-To: <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Tue, 15 Jul 2025 19:50:36 +0200
X-Gm-Features: Ac12FXyoQ4fNoRKEvC6GhXGS-MiKTOay0FzcQVu316wRZ_qnU2L3B1IndxZsU0Q
Message-ID: <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
Subject: Re: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
To: =?UTF-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>
Cc: Miguel Ojeda <ojeda@kernel.org>, =?UTF-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?= <Ping.Zhou1@unisoc.com>, 
	=?UTF-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?= <Ziwei.Dai@unisoc.com>, 
	=?UTF-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?= <lina.yang@unisoc.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"rust-for-linux@vger.kernel.org" <rust-for-linux@vger.kernel.org>, 
	=?UTF-8?B?546L5Y+MIChTaHVhbmcgV2FuZyk=?= <shuang.wang@unisoc.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, =?UTF-8?B?QXJ2ZSBIasO4bm5ldsOlZw==?= <arve@android.com>, 
	Todd Kjos <tkjos@android.com>, Martijn Coenen <maco@android.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Christian Brauner <christian@brauner.io>, 
	Carlos Llamas <cmllamas@google.com>, Suren Baghdasaryan <surenb@google.com>, 
	Jamie Cunliffe <Jamie.Cunliffe@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DJ0St0AU;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Tue, Jul 15, 2025 at 11:41=E2=80=AFAM =E5=88=98=E6=B5=B7=E7=87=95 (Haiya=
n Liu) <haiyan.liu@unisoc.com> wrote:
>
> The commit changes the fragment and diff is:

An Android engineer should know how to handle that, but if you are
reporting upstream, it is best to try to reproduce the issue with the
upstream kernels (e.g. arm64 is not in 6.6.y) and provide the full
kernel config used.

> Only two rust-related global variables in fmr.rs and layout.rs have this =
issue. Their asan.module_ctor complied binaries are wrong.

I am not sure what you mean by `fmr.rs`. As for `layout.rs`, that is
in the `kernel` crate in 6.12.y -- isn't there a single
`asan.module_ctor` per TU? Which object file are you referring to? I
get the pair for my `rust/kernel.o`.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72%3Dv6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg%40mail.gmail.com.
