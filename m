Return-Path: <kasan-dev+bncBCA2BG6MWAHBBE6ZSCIAMGQEWYFZJFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id AEB634AFEF2
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Feb 2022 22:05:24 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id s19-20020acaa913000000b002d3691e7135sf865446oie.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Feb 2022 13:05:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644440723; cv=pass;
        d=google.com; s=arc-20160816;
        b=082hrdU2+IofbNq1kgaRqJaLXKlBTjDHmpLvvspI4M5az8SuzTieLTB27hN/C/mFEv
         Co8DIPv7NXEaRSQoA6TU0vZE58DKytfQ3IAageFcYTEpn0Yjph4i+tE8IQlcIclCrB6E
         eG77vV1VJKODQ9cLzxeSMociMvMFZZmLnWFjRhqVz/MQVr3GFKAxkpGYz0mPulqxsd0R
         4QGZ3v3risxhdFAOsAT5/ASfZk3U7psD4GiTKp6nGa4C//2nQxKKlaOZno6UZpZLJapc
         gPkfiwgUUInNbsruJWNZukC3WkjIe644R132jujAMM8131IbnnyKzNaTdK0LjQ4hEo+3
         eCrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8rjajvoaqlHErukXGBX55RvENqCJlA//UnbuENMY/mE=;
        b=o2zggcdGZW5+hXDo3detzWs40enxYIWoAMPN6jacN3nDCm/8H12KpautDz1dlHF971
         fMvDJ8m6f2HB3cYClhcPwR1qzQUjuMnEXP5WqIXBph/AqZKwEYSj2h+JgRpcAP4YoNbk
         7NRlYuXXtl5/9tzlFF/0UnjrpOwnQbGE4Hi313vT2AMih4bSQ+K8dmYc/m/Ehoryx9Sn
         bkBFt3uZ1Uu0HN6MF1ze0apr4AGnLEMjYlyC5mydKK5/FkCo5mEqcfd8Xe7g34GfpM3z
         vHQ4DbxZBF76OpT/bjCzf+giXNvTL2fXoW217nBeWkMtGfmA7zdzTHE54s1d6DqYX5bR
         EJJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sxNtbNCZ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8rjajvoaqlHErukXGBX55RvENqCJlA//UnbuENMY/mE=;
        b=Hn9jJl4ZMrYoQBjs5IfllKPqgD8SLc4fSsNYkLFRHbgMYK0BPi6cr3PiB1onyXY/29
         wQ2rLD+00KmzFjoXIZJ3/cT2+G6ouLturXjwU45pWZ27Z9RGy+xe8qYFVpJ1U2yomey7
         TFLvnCKO4WZ17xNlJPTkvz4BQmQIJ0VhB19RR9oT3II/7wu14j4OnWtdd5TiFPkEXI+D
         CCZbS6O/3QfqWNABlPkZ1i5YogwuDXe/dNt1I7YMUYZohHoRkIdN5+zMCyp9QKFZUYS2
         u9roj9KoBrcIdqeXms5TBsE3JS8ZbsisI81cGrVafDGDXJvEWkwrb2X79WAjPUPp5OhR
         ZvWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8rjajvoaqlHErukXGBX55RvENqCJlA//UnbuENMY/mE=;
        b=XE97QPpg22JEzJzRQszEM1xpZHCGVeYr6sJ6WEh2Ev/HooXlqKxc3AYPi/1ZTM6YYK
         3Eck5oC3N0LML12KtVROgux0naPfFHquJIpG3ajp6aX2b2SAMJv728AloqenuHZr02Rh
         UvI8B9n4DCQeo5Jo4WYwYvlyBW0t9+LVIWnuEyFbq0VVq4/xxPGuJsYG7X24L5vL4ILf
         KtgSOg1on1IIAtTFOWrkw4THhAjm6sd7oEmyVIgRRettSIIkJq5rnEU4Ar4Vz6y1asi7
         i8bGU2DUGVd5RXi/26hmXKQ/tuPcqrhSxQBNuNwc4+/nxiLknlNd8zgDHEQwqt7PhDFy
         6BPw==
X-Gm-Message-State: AOAM532QKAZOgJriZAIBKqdOawIDDVRfVTPQqKistEOg4Oo+3VGJlGF6
	iqQczaXq8v+uokK6hIffMQE=
X-Google-Smtp-Source: ABdhPJw8SVFA94BnmVI7xVc3TbNGp7tc2+38jv2c3g9EUwuQumYhK5dn94tjarCjECSTIR4rKV7z6Q==
X-Received: by 2002:a05:6870:12cc:: with SMTP id 12mr1407329oam.215.1644440723246;
        Wed, 09 Feb 2022 13:05:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:211a:: with SMTP id r26ls913808oiw.1.gmail; Wed, 09
 Feb 2022 13:05:23 -0800 (PST)
X-Received: by 2002:aca:1005:: with SMTP id 5mr1847145oiq.19.1644440722950;
        Wed, 09 Feb 2022 13:05:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644440722; cv=none;
        d=google.com; s=arc-20160816;
        b=EucyEQakDb010aVlHzp3IgVcsmWDMJQjdFMBLMHtDpddjP2ptgjRIIkfY15UbxvRO0
         UkWB8G21YQUDB/pxaVEbhs4q1OjMYxFgvrz79lmNbNQpCRWNO1LJAICSzaOsKPfLtAwz
         B7+TnEvJzKl5Udcv6u8kpricx7PekVEPb4zd6pZL8L3qW0FGpB1P9PQTrvTv5vs0YDC4
         8n9y4ekw9ZEYcnXU6ygRPL79lnXV7Kw1bmUZZM1LUIxTniYJkORxXD51bnlOgDAjMh8x
         fnzvfM9DWjC7SAbRZlcW5Fc1z4APrC3+5WHJ968qOhbZxQkpRnJQzkmjT01ZDkdTgsK9
         jByg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V84L2PoKJ1SmhfGQgH8rqYWxNln8hG0mJ8WVBKOnt3Q=;
        b=VH3lZhJBnsyWSv65yCONPiL7LYD/+n9qfHVk+gzfs6e3/OygtlDapypCV5W4xUhkPS
         Q5Nqz+w6zNhqN5Vufv/WAreqVAEZ+W2XgOTm9i8zVYBegt+hzu1uDXQWZa1gAfy97iUo
         W47cbxYXs7vc8lO7JxbEX2Xhro7GCxLsru67xQiDEMOKge7ZqXP68G4ZEvApUzLEyT1B
         mLbIP1eHl/p977ZmBESakOmdLaJbzp78IBTFODrQD+nqQ3A2yqpT4p4lOOlBVLlD2hQ0
         ORGErvlxpmd6D2mbYFNuCtWEIm96lyVdTDv0etiukEwoNgte5mEQFinaspTOPRVmHBBi
         1ilw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sxNtbNCZ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id x31si1064573otr.0.2022.02.09.13.05.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Feb 2022 13:05:22 -0800 (PST)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id i30so6523474pfk.8
        for <kasan-dev@googlegroups.com>; Wed, 09 Feb 2022 13:05:22 -0800 (PST)
X-Received: by 2002:a63:2a95:: with SMTP id q143mr3411045pgq.407.1644440721971;
 Wed, 09 Feb 2022 13:05:21 -0800 (PST)
MIME-Version: 1.0
References: <20220208114541.2046909-1-ribalda@chromium.org> <20220208114541.2046909-2-ribalda@chromium.org>
In-Reply-To: <20220208114541.2046909-2-ribalda@chromium.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Feb 2022 16:05:10 -0500
Message-ID: <CAFd5g46AupffbhjXce_T_NrYZvBxHDE0-cTph22bMDCJ-wyj6Q@mail.gmail.com>
Subject: Re: [PATCH v4 2/6] kunit: use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, 
	Mika Westerberg <mika.westerberg@linux.intel.com>, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sxNtbNCZ;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Tue, Feb 8, 2022 at 6:45 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the NULL checks with the more specific and idiomatic NULL macros.
>
> Reviewed-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g46AupffbhjXce_T_NrYZvBxHDE0-cTph22bMDCJ-wyj6Q%40mail.gmail.com.
