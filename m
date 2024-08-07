Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAPAZS2QMGQEJEDBRHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id A463C94A2BE
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 10:27:47 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-44feda40d1esf774721cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 01:27:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723019266; cv=pass;
        d=google.com; s=arc-20240605;
        b=LvInwrq0ec3IxexBbHkqQoeuXQjlRseWvjApHZlmuur6jh4DdQ5liILsbAvTYx/c3R
         8ePhFFi8mgPxBP5e1MqrWXLELBH8y4WaQJ5R8TjiU6hDHehhDuEkozahZRQcHh8t/4Vb
         ZBlWd3M3zLZWczOd0jm6RbatoS7riz2Oa5HtJTs4Kkw50hkIGb7hPYXfQDlbRDH2rFUx
         CNSUvrdjMJCw3iNAwSFGuuYdPwndk4GnJycYg5Q73f0SSgSLv10cEk6OfC32Ww82J/Sq
         Iztc3+AKxgvwigdkntbAjnUM2s/OZ0OeGCpTWpQ10wRL83jxpPjcJDyjCmzKowtJe5vJ
         o3uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2jcGM7ReSe+b7VVZdJKyhPVojv4TLR49iZ+m1qcYthc=;
        fh=ZcLcliab+Tg47YzfQsnW3JottPjliToRGaeTBuCtk44=;
        b=ApVzit756f6lEW1p+9097NeIglsbyfBuuvM+T9r8KJYMXmN2hiRqEoWNU1ok6mWwrn
         nTErgB1K3aRfFl7ZuYBY15pEHfIUiuYy5cT+t67pd+5kuBWFlZfaAaUWDhzgQd45c5B1
         gQPLPVJdwmH7IcC59UsPXlA9Vuzc+qwR3xFkimT6eSDtOJ8YccNo+9k4puMfONfHeuMh
         7F12XK/nEPK8TJ16cS03bvuM/nV4VM7CicdDwx5oFDd2HJaSqxE2bDtO1ysoXJsvptQW
         pnHIJU2t10wuz7t7SJkAY9YWt40TO4b7B15iu3XHUYJZ4RU47/HxVwW/mt/YRO0JSLW6
         3wcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LGBc7Djb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723019266; x=1723624066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2jcGM7ReSe+b7VVZdJKyhPVojv4TLR49iZ+m1qcYthc=;
        b=NpF2HJVSHgO2EQtU4kiPk7cEPNX5skoKyJb66qH+xhuhZUinMK+/hVEigiGVY7uJPH
         y4oboNZCHchBP1FLmEUWoi1UyBtrsssgY2FnriVwNNrmGDYOFL3pX/037+IKeECeip9m
         YulMs4QuIaMW8XagqMhn+VtSVZYSdfj4c0QOvKWR1Z39Yggl3qm6C5v8qEIXGtgtzKcv
         aFLvdsoDAKnWOZYnRNbZX82xb4u4p5/F34OidSHYY7rcrmqPrYzrOUVez92iEkhNp3Ci
         Sy4bBeNbgT/PikCzNFAI+5XYKYV3jJjH9rmfJOLPOU4JLZ/NwHvEBJhYR1mzojltMnGF
         5i7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723019266; x=1723624066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2jcGM7ReSe+b7VVZdJKyhPVojv4TLR49iZ+m1qcYthc=;
        b=qnjf59DwZPm+0pIc7wHtiLSnZguwX7cXlau510ZcUwd5AvBUPFyxDwVwrg5tlGBs3U
         KXWkHuW7Jc70KlAFGp3sCSRHqMpu4gFSTiui4v1DhovyPA0NYjBen0GEVZkxsW0wYjTR
         BJVTZTtk5It+MEWQPj19w59Nd+IONU8JntahxWAH2lLBlSpIMedvqKYJ/8Xbq4bLp3ti
         4ErhfT6PwWCm0hFYAqFdo5uAmg6j3kcITO2cFCFhilrVp0c0nWsuB5RBvU6TU1FgAZRg
         o8Hi13CCxYonzra2/jd6Xfr7NQPbhURhjiabUT3p97z4uDQJQLzbnnk4gJU7eX50dA8k
         M+5w==
X-Forwarded-Encrypted: i=2; AJvYcCVCe5SF01aYicMdWUGgaCedkLRUNKPuLXv3081TjSP6BsdwuZTwtUwFuSifNU23Wmv3JO66DX/Iw5XznIOTS+83wZsd9VchDw==
X-Gm-Message-State: AOJu0Yy70RUAEgGe1g9z/smDOIM7mh0xXpSJ+Rn9ONuNVKxeCcPtlLFb
	r6Gsov4IuOxRdipOZY+RA01BHVMDvWfWRlJE2aRsq1SWSTA4btKx
X-Google-Smtp-Source: AGHT+IE8zbnj1cLX4VfOnR4ah9/W2U1qiYZIBXVVo97R1ZGw7VU7x9v4P92hNdQOOsh0aWv1DaNo9w==
X-Received: by 2002:ac8:5a8e:0:b0:447:d7ff:961d with SMTP id d75a77b69052e-451c7810753mr1978521cf.9.1723019266156;
        Wed, 07 Aug 2024 01:27:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:102d:b0:e0b:43f4:b53b with SMTP id
 3f1490d57ef6-e0bf49ec5e9ls2402276.0.-pod-prod-00-us; Wed, 07 Aug 2024
 01:27:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+9OunwXELAabmXCOD8Hu8s7vMPIXZqanNZKMOw48Vmnt0KfDsbRx0Ci9cBYrs5qZQ1Ma7ujXKciWgT/JZPM+bOd3xfVSxOq80Sg==
X-Received: by 2002:a05:6902:18d4:b0:e0b:f8e2:3e89 with SMTP id 3f1490d57ef6-e0e877bc4famr1539276276.15.1723019265188;
        Wed, 07 Aug 2024 01:27:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723019265; cv=none;
        d=google.com; s=arc-20160816;
        b=Ugyr7NqDhRbiqGuywVVbRHiRmNz4cQQm/PYFSHSXyPu2oYHNjPr/dKgKYp6eLS7C5u
         LGRPTEH0V1t3otTTr5l8zEmHVBIS1qVwgUi4cHyNMFgoSFE4kVeoKyfOMoR2sxNBaMj5
         JP6ewoFgUa7U2LPhrxgRRABYhanCKDJtCJk1aC2IBm5uCx6hRRHD/n2uRYMSXCsZws8D
         fgkXlIwLwiAmkMgHgcYOMj2UYVY+qM+RBR4fRhD3sGVua/Pdi0GAVaaYdnD1pETzhiYU
         yK6C7feWTzIgL61+jeRgaCRy+ApltoGzRV2Tld9Td83fDmMQ++alauLsL9Z/QySv2+dP
         0bNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EcjlAwWs3hexCvUovNEYGd6p98RErfbaioX/6j6nW3U=;
        fh=XzfhWtqFWc+ff8oPxdtLfMz7zcKwmGfp1l6YjSyQtWU=;
        b=dszz9nOzZdWjRmtbIrgHJZGudisonejt4OP7ICG12U6mFkOSFkv/dSbFzoZ6dwwM3X
         /LCLWn1teb+QamxVOZj9zOS7jCrLqZgHS00mli6sqkhsjSxMFXkvT66noenuWNTp/f/Z
         YIpO5vbnVUOMQOIZZKyNmTqQd/pB8SUj/YFITqDdAyuHvhbiT9rbMG3zGHp/JTU/eila
         J6Hl2I8pu4SL2wEP01cm8r4datHyoX6487HMrv/BMRfEZ6Pf1VfDUwKZpGRrVGPVV3Ka
         rExvnNku875SA4ULqfH9dulGG95N8Iz2DK3ZmEQYLCdMowivOH7AX9GXb1XLLL+dy3LV
         CpXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LGBc7Djb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e0be55bb03fsi492945276.4.2024.08.07.01.27.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 01:27:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6b7a36f26f3so5653046d6.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 01:27:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVNR9vwl3J1b8NJtNAY2yvBGlf0IGZ2zGCZDZH3aCCf3QHVpiqMSKVLDsv7ChiL+3ppX4KZaJoxR5S23PkIw+bIP9ggDYY/6B+4lw==
X-Received: by 2002:ad4:41c2:0:b0:6b5:e0d3:31b3 with SMTP id
 6a1803df08f44-6bbbbdc7376mr27127586d6.9.1723019264543; Wed, 07 Aug 2024
 01:27:44 -0700 (PDT)
MIME-Version: 1.0
References: <20240805124203.2692278-1-elver@google.com>
In-Reply-To: <20240805124203.2692278-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Aug 2024 10:27:03 +0200
Message-ID: <CAG_fn=UBWge=QGeB+XQRtuFkzqWbrA8_FJsrwhihhwkrzt8DoQ@mail.gmail.com>
Subject: Re: [PATCH] kfence: introduce burst mode
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=LGBc7Djb;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
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

On Mon, Aug 5, 2024 at 2:43=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> Introduce burst mode, which can be configured with kfence.burst=3D$count,
> where the burst count denotes the additional successive slab allocations
> to be allocated through KFENCE for each sample interval.
>
> The idea is that this can give developers an additional knob to make
> KFENCE more aggressive when debugging specific issues of systems where
> either rebooting or recompiling the kernel with KASAN is not possible.
>
> Experiment: To assess the effectiveness of the new option, we randomly
> picked a recent out-of-bounds [1] and use-after-free bug [2], each with
> a reproducer provided by syzbot, that initially detected these bugs with
> KASAN. We then tried to reproduce the bugs with KFENCE below.
>
> [1] Fixed by: 7c55b78818cf ("jfs: xattr: fix buffer overflow for invalid =
xattr")
>     https://syzkaller.appspot.com/bug?id=3D9d1b59d4718239da6f6069d3891863=
c25f9f24a2
> [2] Fixed by: f8ad00f3fb2a ("l2tp: fix possible UAF when cleaning up tunn=
els")
>     https://syzkaller.appspot.com/bug?id=3D4f34adc84f4a3b080187c390eeef60=
611fd450e1
>
> The following KFENCE configs were compared. A pool size of 1023 objects
> was used for all configurations.
>
>         Baseline
>                 kfence.sample_interval=3D100
>                 kfence.skip_covered_thresh=3D75
>                 kfence.burst=3D0
>
>         Aggressive
>                 kfence.sample_interval=3D1
>                 kfence.skip_covered_thresh=3D10
>                 kfence.burst=3D0
>
>         AggressiveBurst
>                 kfence.sample_interval=3D1
>                 kfence.skip_covered_thresh=3D10
>                 kfence.burst=3D1000
>
> Each reproducer was run 10 times (after a fresh reboot), with the
> following detection counts for each KFENCE config:
>
>                     | Detection Count out of 10 |
>                     |    OOB [1]  |    UAF [2]  |
>   ------------------+-------------+-------------+
>   Default           |     0/10    |     0/10    |
>   Aggressive        |     0/10    |     0/10    |
>   AggressiveBurst   |     8/10    |     8/10    |
>
> With the Default and even the Aggressive configs the results are
> unsurprising, given KFENCE has not been designed for deterministic bug
> detection of small test cases.
>
> However, when enabling burst mode with relatively large burst count,
> KFENCE can start to detect heap memory-safety bugs even in simpler test
> cases with high probability (in the above cases with ~80% probability).
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUBWge%3DQGeB%2BXQRtuFkzqWbrA8_FJsrwhihhwkrzt8DoQ%40mail.=
gmail.com.
