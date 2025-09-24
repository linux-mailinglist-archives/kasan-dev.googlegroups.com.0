Return-Path: <kasan-dev+bncBDAOJ6534YNBBIF32HDAMGQEJFAESSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 092CFB9C3C5
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 23:07:46 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-46e31191379sf1358155e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:07:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758748065; cv=pass;
        d=google.com; s=arc-20240605;
        b=K7H/9n0qzguvULkFtfWLCcHY2C4B9afRPc3p5/4q9jLkyamM6knRowsf1IsBqvGVZx
         8gNiownouyeUNtRUeLyrzp7Q7+gtsxQxWdf4ld6n632LuUTGcFDZPX2HfVdsCm/tv/e+
         VuLgqjifbqaAcdE5l4tTPmVwH9+KnveMoFmu/xRpUbOa5vlCbJHcju0hBCI9kMgpN8GV
         mKuS0F+VhWKUUiuVLdGTRE+k+MsLeCKIAsfq4LX2LhBDUgaw+hv4JmAIHo14yAXQZDaf
         HNp1h8letuoOJGBR8I9qP2QC6NfFoRAzrgWep1BR+ikHikL4ApoI9RclPXNSTdoT8bDK
         zk5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=GRXLD3Mi24Sqy4Wu0hMxzbYSQ5i4kmsWSXCrgBEr8Dg=;
        fh=Hnw5DKwiwA86RTxrcgmDUdh/R+4fIrlV4QuquvSpvgY=;
        b=WZar9IZMGeCs3mZ5RKpnaUGzVrQwAiD16i8BSJyGlYzdSag9UO6fv/S1YNCzAn70jP
         jA7Vwi01ELMWLkdA2fLx0G8or6nAZFxsewHog9pEIk3KqzIHlNJXIPGG2Ttx2YriaQu5
         u54BbV4+tW60fzB/L0Jgb9hNdhhDw4Yi7hpZF4bge5sW4u6kOmo0BHg3RvUgXE6BTr0/
         PztlguZ5j6xCblYK0S86piHT0DVScun4ba+wfaAMgdPilPpPrH+C8EIZRuFKhZSfMd/2
         Ll2TULL3e/WQiMzSw/MfkLgYBbRssn/dT2spOzW+Y8vuZkZLqMBfT1ZDuu42g3uq9fbU
         LPig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mpeYOKIU;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758748065; x=1759352865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GRXLD3Mi24Sqy4Wu0hMxzbYSQ5i4kmsWSXCrgBEr8Dg=;
        b=emRQWiQenxysQbLjGGP2FstMcAIrEYj+OTHXfieovYU+AMS7WcGcMMut28+slOrpGt
         EcNhDgTXKXHR/tmQVG9KHEPluH2qo9UrehRlh3yJIBHn5LApDLZ/fPCeVDmFpCHSUJgA
         U00FfEIfZPC36ByKKvGmwFqwh92NbQrkez98R8FiNM5/nw5jJEHCFlEZX1f0zWPjwwxM
         hxnnBs8un59FXMyrB5ECSNY80DKv3MUsPazCSkrhV1BxYaKdchv//t5Ep3hm/Vd4hjLP
         RaHumliBt2THFrsgA8/McEkHhI7enV9lvWziH4bPldm/vFFuuzpCcXeNZpytm+FrFCEz
         5RIA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758748065; x=1759352865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GRXLD3Mi24Sqy4Wu0hMxzbYSQ5i4kmsWSXCrgBEr8Dg=;
        b=lwXmgDa0FTEMvT95sYZAI9jTlW2Hr1mHTMLVmHWs4P11M9E6V6Fyg4Ris0c8i2YIzX
         qioz9O6wY/z2IvtBGIDsLyNtzU5UJd6GDScD3PQpLHUHumEqQONqOMwhhW9aIX4ELI/7
         /uB6/aw8PXzbLUxRe3PsECASSeZYHena6xmGnDQy8ddx94Y2AOe18lVwKmm5Y0Pc9Bdg
         c+WbbstnocDh0+mYRcLirfz+Ci832PQxDnISMYWX0x5RX0ESi5sK7MwtsUAQ5HYyHpXm
         y8JEZPE+KVDlPrtxF7wkSYpsdH2oalzkcTUZ/BOu9RKWegFzHEtyBW9cQQ6WM/kdESxW
         WwlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758748065; x=1759352865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GRXLD3Mi24Sqy4Wu0hMxzbYSQ5i4kmsWSXCrgBEr8Dg=;
        b=Bt49ovwKlJNQJVuB2ivbp2guq57FjzpzbcImN+9VGkA8+kO2PtlKvZR2yxT/Oj6xF0
         PaiDEmX421oZP/Hx1fs5ka09ZbBmHCLVa6pmIYCZYiTvQ7SFZzlJRV5fkgzd7rrX7FsJ
         x8P21FivLgEp5q1CjM4ocNaANPxsUhgFbBm9wT46pNTEYhYFP0zMJJ5FWRmgkTrpR95u
         LvkZVhBG3710po6CRVFHh4ajHtjLs9dOnfBpror5PoRKmVoCrC1Q3Eb1dctQkHOsSjjf
         q1dh17QEvnOLZvdxTbvQASi3H4ZB6vrCb4NmUQSfilq8pNjiHSTMUZz5TUqDPZsiqm5F
         q2Iw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUi2JYCLvO0SGJ663BS6OSjLYjmuq8UDJnviPnII2KvdZnZi/K+ADDaW1QMXTqcZWXfQmmEnA==@lfdr.de
X-Gm-Message-State: AOJu0YzeJWTVQnViA93sQ1Ve/P0vZof9DRTft9+PSITHK8C5iFYhY4Io
	ljat9uxUxqKZpcwaC0IbjTlE5tclX72Dgptibr+RopbfFrDtHyGjckMN
X-Google-Smtp-Source: AGHT+IHjifJYvz/11HB42Vk6y8Qg6PTXK6lbEbUUtDKyc3/tz5sq9ou9tx3YZ2mPgpYfRZ27GTrPxQ==
X-Received: by 2002:a05:600c:8b16:b0:45d:f7f9:9ac7 with SMTP id 5b1f17b1804b1-46e3299b8cbmr10469955e9.6.1758748065084;
        Wed, 24 Sep 2025 14:07:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7p/c3+F5uihoxYyQdAAVj/NvgdiAD22kubu85OAiW5GQ=="
Received: by 2002:a05:600c:6383:b0:46e:1aaa:6922 with SMTP id
 5b1f17b1804b1-46e33824ddals995775e9.0.-pod-prod-05-eu; Wed, 24 Sep 2025
 14:07:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5w9liEmUgD3SgCQ/Es+flIwgMI3XpPqEXZI0TbvOmUetfo9IvVyTU53cGHiR1Yl3kEvmy+7kNp/I=@googlegroups.com
X-Received: by 2002:a05:6000:288d:b0:3d1:61f0:d26c with SMTP id ffacd0b85a97d-40e4abd7c93mr1106426f8f.54.1758748062197;
        Wed, 24 Sep 2025 14:07:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758748062; cv=none;
        d=google.com; s=arc-20240605;
        b=bASJuTrXPlNyAGNaVQWI4Q9kG00N/I+6yZD8JIeqjbJUoLHdxHwv2u5iTxEcAUqC3Z
         c2bdQEHyIQ+CelnzGp2sXkEl8d0ICmtHG+vWQfAIMA2d4dtk+0FHQdMash8poBnnBKDv
         vKO0yUElDHM7obg/tx56u6c5/GoplF1FQ5QT5YQk4CpMyuFpygtt8hNgtJfrVUnMsjUU
         Oifcrrhx4IsVidpWS89c8cVhUyG5qT13Vq8Oi6j43yUWzrENRicJ+w1hVAdzWNEtEKyH
         aYktJ4eajpd1/aeMQlZ83FM5/RNpTwVFbsQdb7hUhO2Fm60YcU9gqeJBZclsdAx0XCiS
         /ZLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gE7xr797IjE97kDTlx6kiGCJ5AYi5oF7DWAxEs64oWE=;
        fh=Dz1qspeAsFvmF2slo/9AFUtinBr86VjCHsnFfdUE7So=;
        b=eN8bZaNg8Ld5pe6LNyi/2/HH1BJYFztCAvSm84f5X7iuGgtzAaahn/uXTqO8npsq/u
         DHtIPG/18cRlJ6uEWOhSgDuGZArV4ZE0gQLd7V1r/8xF/5rUucLkaXLBhHg54I0Pcr6Z
         FFYZXo6pXO7lyWSMAYyB3qw1SZ5J2+Gz8PXyFiWfUJDU9LLk/isoWtvmbtGouF0yju5n
         +KwpGwXqo3zTrFAtPYMQonu0N0jvMVAgzXPu5xUtxcTARMiscrdwceYKhpb8nIOP1mW7
         9HLqSCrfR7IxCZ4fnu/MtarjAUs5rDmQ4lCEgt4UnQGDxMbOqJqz/DrX3q6lnrqYV5qt
         5UcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mpeYOKIU;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e33bce606si38275e9.1.2025.09.24.14.07.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 14:07:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id 38308e7fff4ca-36a6a3974fdso2697121fa.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 14:07:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJQ2P2qU0imv7O/aMwFj6i8cSecibBgZTbZM1fY9MXC5QbGC5WigvEi2QkkREtelgE9BNKhsSuG2U=@googlegroups.com
X-Gm-Gg: ASbGnctDvSozsxkUpIIcPcMmCJx2wShUlnciSEHjMn/jN7sbc0uKI6bUAcs4uJuQC8g
	zCVqiJoTt2XmPHcVs8BT7Cfe1zbXku+G1m9mHPZnAIeLJIfHzyPeiE30CVOPFuDx6sgxNczqeU2
	St46pvQBIbnPRW9lm4Vp6ggEPcYceynF7hnCiDGFlnB/oz7ClVf4UZjAxzsbNssDC+txZbHYAB/
	l5Lj9U=
X-Received: by 2002:a2e:9a12:0:b0:333:e590:1bc9 with SMTP id
 38308e7fff4ca-36f7f2481d7mr2143301fa.24.1758748061412; Wed, 24 Sep 2025
 14:07:41 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv> <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com> <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
 <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv> <CA+fCnZcWEuBerMeS4RCXQtged06MJhY=55KsYeJEOJn3K0psXQ@mail.gmail.com>
 <aNNY1AzfGua3Kk3S@MiWiFi-R3L-srv>
In-Reply-To: <aNNY1AzfGua3Kk3S@MiWiFi-R3L-srv>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Thu, 25 Sep 2025 00:07:24 +0300
X-Gm-Features: AS18NWAbw-7uGsKJ0oGYd7zu1yq2_988Moths_iRDqX3j-B6KBGWgGPm02szRx4
Message-ID: <CACzwLxh10=H5LE0p86xKqfvObqq+6ZN5Cs0hJ9i1MKJHWnNx2w@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, glider@google.com, 
	dvyukov@google.com, elver@google.com, linux-mm@kvack.org, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mpeYOKIU;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22a
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Sep 24, 2025 at 5:35=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> On 09/23/25 at 07:49pm, Andrey Konovalov wrote:
> > Since the Sabyrzhan's patches are already in mm-stable (and I assume
> > will be merged during the next merge window), just rebase your changes
> > on top.
>
> That's fine, I will rebase.
>
> >
> > But also note that Sabyrzhan is planning to move out the
> > kasan_enabled() checks into include/linux/kasan.h (which is a clean-up
> > I would have also asked you to do with the kasan=3Doff patches), so
> > maybe you should sync up with him wrt these changes.
>
> Hi Sabyrzhan,
>
> What's your thought? You want to do the cleanup after my rebasing on
> your merged patches or you prefer to do it ahead of time? Please let me
> know so that I can adjust my posting accordingly. Thanks.
>

Hello,

I can make all necessary changes only next week. Currently, traveling.
I will send the fix-up patch Andrey has described somewhere next week.
Please let me know if it's ok.

> Thanks
> Baoquan
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxh10%3DH5LE0p86xKqfvObqq%2B6ZN5Cs0hJ9i1MKJHWnNx2w%40mail.gmail.com.
