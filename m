Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBYE2RHCAMGQEIRWPS5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 207B3B10E5B
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 17:12:34 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5551093dd58sf601939e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 08:12:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753369953; cv=pass;
        d=google.com; s=arc-20240605;
        b=VZCAFIkxt1MnkCyBVCgJxP+bjnovGwzkvZkNniOBnCADcXFRKJ3AuWg1BsSzWiHQFB
         8jIZCZdfX7qqqMU+IcbrxszxXKuJHpXD+X9SlVIvYwxK4hWUCDDKzSKBVMShhuYbLHiW
         jezyQx5kYtg8uNJLjm4n/9pmYSu4Pn1Pa06oyKos6AqpcxZvxfNHn2QLi13p4HjEFepF
         2RmpTy2v2fI/T+GpcpDpOz8pkbWF5UWlx7rwv5rH42DoGeF2nXhn2x5BgHdIu2d/i+vj
         tWVboouD6AX0vPWSHKaEqyEdqps6pLMENC3ktr9iv2uDiJp+lE2QgN8v83D6SKC3U19F
         u6ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Jka74Q3D9gGakHSVM3h+9OSBu6t5qRTVBAfnRJiwTiI=;
        fh=NmGzamsWKKkvvB9ZoNbDECDBcFlJV7LlzjfD05RXEMU=;
        b=QMYPOYswE6RUVgZc2eRM4ESJiwONpzrvzB6tfb2NM5bSUI86v6FJyruFua83F2WE5M
         QhFFEMeRMqdO9/OISM2JErdSECP3qUHjojHmGAx7Xw2zwJwkloPEQDFcc+TMAKS2qjed
         PNelN+/R52v/fQxhDTBU1IkMgdb91m4IH8cUnxCcboSoF3L5gp0+QLHqdM15QyvZWRkP
         C8oGo00NntP35CMg0ad4L0WDzwlRt1JsdC6KLT2+2ad31vVe5Vz+QnR7lUmqpv4xgcJ8
         fMPhDeJFEWoIHe5fb3DfLtI7Jmdxb5GuYj8yAVbhDshoTboM6MavLrWp3Pb7DjaMAWyz
         l+ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TxrKrFIA;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753369953; x=1753974753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Jka74Q3D9gGakHSVM3h+9OSBu6t5qRTVBAfnRJiwTiI=;
        b=rVbg+IZCrJTenf/G1VubfWi0Zk4Y39vROs0SqiddsvAYHy9+aGt0buiKrese9tV7p6
         ntfZjM6LWcgdnvW8VRtH31D7jJP1W3vjgE7TmJp4ZIEf36ORml3rPxOoNNkbj1q8HmSd
         cJqialElorxlVavD7gASov86BgFUWGQZWec1fO28rw1G+a+uQ/4graDidc2lXwBsFQbk
         0pp8zlv1M4K/CSjR/RzVgvlOcUjKyzmFEu+dxu6MbtUxohGSZv0ITq4vJeb/xzZPc1dP
         gZnoNVRnLNjWqduMG8pDBA1RR2vDtwlu7p6doTuLT/7imrP1QLVXouG5l+lJT8vjxiEi
         WunQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753369953; x=1753974753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Jka74Q3D9gGakHSVM3h+9OSBu6t5qRTVBAfnRJiwTiI=;
        b=iu8QWKnI6/XHeK/kFVB0tbpocuJ3p67fIL+OUeS7s/ReV+5qsm2HyvfHuj2Vn+XGjb
         C9YsQSlsKuG96o5aLN6KoOjllUzAv1gRXA5niht/OtFDlJDClrh3U5ZPJLqyE3yB5L/t
         iRVhw60uu4QsyOnWQ2Tg2h/89ZddLI7aHBBMYQcrT7XI8tYXdasrpu8oOKdtmPB1rZDl
         qxghE1M6osm+TN7Z3mAQGf5lxIJ+9wlJTMqCZYjodxoESVBQ3aNZNOzMvcbY2nwNY9RD
         6R+KepU+/KtysC3IoySiTqAEhUuNkQJHiNj5tVID3qbzu8Nu9LsAvqqru2APDa/vjJzd
         SqGw==
X-Forwarded-Encrypted: i=2; AJvYcCVnjyJz43naxEjyreVKDAqtlrN86jautXBXkTHje1QJ4wCIrwl1XZNgMAB3IMMbRUN+1jyZTQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw+w1jlu0RUnH4a0gjL4oqVbWrqt3c7qw+8oqyPDXhauKHbNqIj
	v1eD1p7lVgi38hW77PnUvAhh/AbFKfD80k0fuvSe9h6Ja+5Dqq6gMd4B
X-Google-Smtp-Source: AGHT+IHSwDYy4gJVBInBUu47rIADFReJw5pGZ9ICRRzHlYScUn/Bvq2Ea9m5RIRjo71GISNCvcuUOQ==
X-Received: by 2002:ac2:4e0b:0:b0:553:2a16:2513 with SMTP id 2adb3069b0e04-55a513d9bcfmr2306171e87.47.1753369952660;
        Thu, 24 Jul 2025 08:12:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcGGXDJk76miestteAs/9GyJ7Rj0tFCEN3i7FMelBuW9w==
Received: by 2002:a05:6512:438b:b0:558:fd76:c60c with SMTP id
 2adb3069b0e04-55b51e48c4els350409e87.0.-pod-prod-03-eu; Thu, 24 Jul 2025
 08:12:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQUMd/jHDuT30NTjTYFJri4NTlEuI0bsBlgzZD03hlMAxtELCt8D3zGkZz5Fj/woo6Gq15b4k/wWk=@googlegroups.com
X-Received: by 2002:a2e:a591:0:b0:32f:219d:760d with SMTP id 38308e7fff4ca-330dfd9961emr22085111fa.20.1753369949506;
        Thu, 24 Jul 2025 08:12:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753369949; cv=none;
        d=google.com; s=arc-20240605;
        b=bZ92d91jPuiS33HG6n0aJdbRlIqfE5xoq+8WxGK/N7dvhV1QfKbCbVuecmmxy4E2xV
         vKZ4ZVcpfTmuMYhZKAJxC0Op2B8xnBxW8lKEVwJjT4PXHsJ6Qfr+4MvclfS4ZevoIYe/
         E16wk/Y34e+sx9iyOZdMHVKMCquKK1y/LS3eNbzTf4lUqXMs+GgZTL85DIN/EP2ex/bl
         BLX8EYyRwcgruOuOSr7CwzgOUEBiPS/bygXcVZHj5laca+lquDkX0bkULPHhOu/ZYfNa
         1jT7p6f57TI2CHgXQ4P8TBu2rBKXEIcQfOr4heKTzOm0chgCuUzP6URoECyiwTaC7r2Z
         5o1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kqXvn/StDWrS77Y+1IlIaBQTJAyFT2n+pM6JuFAK6gU=;
        fh=HrYbyxmvc7TbMpLUXx/lzde7yrxrjWZR7tNNujxwPsI=;
        b=IZt0PZd6pGpKtDqsOOGi8PBSo3tgQijgMEroAxyDush428G5X4Ur+jkZrDGO3lvjh5
         N6S3P3KD0y7ThPuyxKyuWsq1tWyi6YFpRfLGp+gCMqSm0VCX7pkVqrgKbQnVvUJpNYf6
         tmxCOlTbeOwkCAlY0jaXxB74wwKoUsCxw6Ss5rVnad3QXuOcnMkZcj+92X4TesTmRumO
         oePZDs3EcGM11d1z7VUH5wAnJlPRg0/hv9UhDbs1x7z32xfGirHD0/n+yNo9SXp5lZnD
         HRVm5Dmr5asrFIg7Y1b+UD0AensWPV3jgOlIXNBQmlfDC9HNfbBOZ/8fH5efUFs7N6LT
         alyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TxrKrFIA;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331e0951bfbsi603661fa.6.2025.07.24.08.12.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Jul 2025 08:12:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-5f438523d6fso10931a12.1
        for <kasan-dev@googlegroups.com>; Thu, 24 Jul 2025 08:12:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXyOFjsX/JtGmvZBNpJW60SxmVqWuoPlWrPmxnGqT3rNNlRv615KnY3RKIIzzRGIzwUe8rt30qs9fw=@googlegroups.com
X-Gm-Gg: ASbGncsaTlcriIgmeI19ihn77NYHYnxiETretqSkLlw2CNwGwvljab2MLV3ZIN4KQq7
	Hj+M1rRkLab4B0+zIBI1ehfuYJ5y1uZlDFlEoMfTtwnXMxiyUATm538tDm5We6VsUtPIz9EQtM2
	4NqMrfsmpgsw6Uv1JPn6qFhV9ZlxWOULAsW9ujxDKRYKEnOupJFZTGX3R0yHpAB71cUC4dAHB7W
	e48b4rjDfSCNH6PQK11WoWLidJo5o1aNA==
X-Received: by 2002:a50:d7ca:0:b0:612:ef17:7853 with SMTP id
 4fb4d7f45d1cf-614cce4afe5mr78429a12.7.1753369948492; Thu, 24 Jul 2025
 08:12:28 -0700 (PDT)
MIME-Version: 1.0
References: <20250723-kasan-tsbrcu-noquarantine-v1-1-846c8645976c@google.com> <45cd4505-39a0-404d-9840-a0a75fcc707f@suse.cz>
In-Reply-To: <45cd4505-39a0-404d-9840-a0a75fcc707f@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 24 Jul 2025 17:11:51 +0200
X-Gm-Features: Ac12FXyEpQmBUWM62BqVW--MRdpwMGBL7kBF9xwxQYUchJD8HK0S4n7Iw79CZgM
Message-ID: <CAG48ez0KjPqqDdzejsjhaHSuJG_0Q8zhyi-7rYq9gSZJergVVw@mail.gmail.com>
Subject: Re: [PATCH] kasan: skip quarantine if object is still accessible
 under RCU
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TxrKrFIA;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::536 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Jul 24, 2025 at 12:14=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> w=
rote:
> On 7/23/25 16:59, Jann Horn wrote:
> > Currently, enabling KASAN masks bugs where a lockless lookup path gets =
a
> > pointer to a SLAB_TYPESAFE_BY_RCU object that might concurrently be
> > recycled and is insufficiently careful about handling recycled objects:
> > KASAN puts freed objects in SLAB_TYPESAFE_BY_RCU slabs onto its quarant=
ine
> > queues, even when it can't actually detect UAF in these objects, and th=
e
> > quarantine prevents fast recycling.
> >
> > When I introduced CONFIG_SLUB_RCU_DEBUG, my intention was that enabling
> > CONFIG_SLUB_RCU_DEBUG should cause KASAN to mark such objects as freed
> > after an RCU grace period and put them on the quarantine, while disabli=
ng
> > CONFIG_SLUB_RCU_DEBUG should allow such objects to be reused immediatel=
y;
> > but that hasn't actually been working.
>
> Was the "allow reuse immediately" not working also before you introduced
> CONFIG_SLUB_RCU_DEBUG, or is it a side-effect of that? IOW should we add =
a
> Fixes: here?

This was already an issue before. I think it got broken by refactoring
in commit b556a462eb8df6b6836c318d23f43409c40a7c7e ("kasan: save free
stack traces for slab mempools"), but I don't think it was necessarily
an intentionally supported feature.

> > I discovered such a UAF bug involving SLAB_TYPESAFE_BY_RCU yesterday; I
> > could only trigger this bug in a KASAN build by disabling
> > CONFIG_SLUB_RCU_DEBUG and applying this patch.
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez0KjPqqDdzejsjhaHSuJG_0Q8zhyi-7rYq9gSZJergVVw%40mail.gmail.com.
