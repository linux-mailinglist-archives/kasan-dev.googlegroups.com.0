Return-Path: <kasan-dev+bncBDAOJ6534YNBBU4Q4HCAMGQESGOXOZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A04FB1F8C4
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 09:20:53 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-459db6e35c3sf25439695e9.2
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 00:20:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754810453; cv=pass;
        d=google.com; s=arc-20240605;
        b=MWOwjrbGwJg617ZVuPkVTpDfoAd4DsKPyln0JIia76OcAW4ttNWnOCWn1h1T51XQEW
         Jf2r9zzQ9Zhwwild/KMaUmnnIxSascr0XiXKsnvkmq2G86morgJvM7KthyCLUiOv3a6W
         Si3JW65+pVLNk7BL67CqQwPLs4LRvTDeDTIRElnvlwE29LzvXOjHDGa380kLtd6JTX90
         Joj6utFOWY9w3j6x/QeLcMUW1y0di1DRyjZMpvytCfZ8risBrd1+cQ48JuM7axaxDCcG
         m5gcD1Dsv8E66qSomCcSjfDwA3OPzKX3tgMpSOoWChJTunehac0YHfjUP9baT+ZEQb6K
         XoCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dRI+c++jqX4Lt3o4c4zgpjONHnWrfkWLGN7jAwEWv1c=;
        fh=BR+8AlKeeBh905i2hXfFRlqlSM28hpsp4fr78kXJmys=;
        b=U8acBMtTVfO5gmGEyyGhHN4dQ9JXFWbvolQwIdWLAUbL5QRVJFOTQgirezIQVUDo2c
         GBB94r7sLITI6sUihDo2IYOmcCmwQFFnvRWfebmI7RO1HpbMPo2vkavPA86C7Bp0J9pe
         vrYnI6RtsiF996EmzhGB7QrDMHzg4Q4v9JoHC+LCUK6zTD5mk7J+9m2oRBbjUy9cQcU2
         B/NGqxUJTnOJB/peMjpZSu+PLBiDGrn6Sijj5YkjI3wKuPJvX1GEGGR99MPQFErQrH9w
         d6UMr0wmAObkF+g48vX0DWU5YanRr8Pi8YcxYC7jXV72s2CxpPnG3ZWWSlYhxETXDpmc
         yS3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gjQa7a03;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754810453; x=1755415253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dRI+c++jqX4Lt3o4c4zgpjONHnWrfkWLGN7jAwEWv1c=;
        b=u+bECNHYGBOQQqeC1XO9R9RsFWudmuaLljZ252JaiuVapQP6PuLVsUQ3ZPQhJFFdp2
         Hx6LOBFgHZI3Adbmspg8TPOcuzB7p5AkxcuDSd0+BfyBkbGtvQntUn5qbFM6ExMN7utf
         lpCmDOWrt6S8PDW2oByGyTcHFPIfXwwSRLMyLkbEnCdUF6rQ6dAKANvxBOMNOG+JVDvO
         LemM02/tRdbFx1dNVBb0Ihye4GFAgmeIsG2XClOouYh73nMzw/FKUOA7qM9kIAJzX/GP
         cOFUFRx+yLGGaM3ERfFpV85zCyf/he9SXM5kZ2qt2a2RgGvXOG1PHA9UMeNj2Zpf4VVl
         qwQg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754810453; x=1755415253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dRI+c++jqX4Lt3o4c4zgpjONHnWrfkWLGN7jAwEWv1c=;
        b=hNSIu4GTodOZ7ywcBJ49hnRKRwTuwAB7cVvtk14rtLZfgaTdrXnF9GbKtpqUB7EnzZ
         Uf6I3UFi5PUQjXu111s8kGWAl+2T1ClKcIsYrO7QYVb+uGkAPeZbqhDsyUDqlxJUChrg
         dVBufB6XpbFtz1vSN+GbQuajsP5NTsmSATRz+1ub8RZpk25N7hNgq8gukDgL3W7hhrfi
         uP7wpBjdrAhM/SU9vayGn+CtFv4z4oqF3yTu/GjSFbspIxi+tNNNW4RrvSLdDFYTSS4v
         krQxrJsjT3aE7VAI56dVfU1mQpuEoQ8psWJdh/VT7qBk4wLzJY8yoBNujNrgeweCdhiC
         s02Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754810453; x=1755415253;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dRI+c++jqX4Lt3o4c4zgpjONHnWrfkWLGN7jAwEWv1c=;
        b=UdoMly3yn19BD+LHC/6jc/9uA8wgKWF7SkXUrfT8Cmoj8WZuoJNIXdORkajcuI1CoW
         ZyNDMqZhP392hsiAhEQUAbKU7SusfT8ADaoZFe63gW4Uw+sNNc2HP73STNADi9kKbtYi
         /uKxVsjk2qKDXNTiweev22jcx7lqpPUeqQWWQLXGTa+LuZ71WxcUuI8UY2v5SSMPH8+x
         bhPmy4NAp2LYIuwYdN88M3pS2t81CwPHxzhHnkOgUc3aK+X3WBrCzvDofFRD5Jis82Pm
         uD37N3l/Ym+t4WiA6WfdQgd48d3fNQxKup2PGLVY2tOMQfI3Au/f0M0UQDVfTWyhsYRl
         t8Zw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSABIIsAUxPnIdu1ntaDKtzEsI3Yg5tZ0Cr3oiLNeYv8M7HBYb7RB3cJiYciNvXDFN2nZzCQ==@lfdr.de
X-Gm-Message-State: AOJu0YyHCC1/BjYVD2/FF3AxUGKonMiY544MmYSBKCvyGhIL9ryjVt41
	aoedUHtZtovxV0LoZ0onTQM5DZbwG/w+NBvFS2aErMrCFyJE0MQx8EzC
X-Google-Smtp-Source: AGHT+IHTD32rB3BBktTcYcRQXa0Fk8+ThpdjE2uMWgsFijTU2OGq4V17/oXZmy62239XUkZ3GJi8YA==
X-Received: by 2002:a05:600c:4e94:b0:456:1752:2b43 with SMTP id 5b1f17b1804b1-459f4f0f0d2mr56725455e9.21.1754810452490;
        Sun, 10 Aug 2025 00:20:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeSGJN9XM8pqjlZW0aO2hu5KaxtikOCq7CjRNMB7mdBaQ==
Received: by 2002:a05:600c:8b04:b0:43c:ed2c:bcf2 with SMTP id
 5b1f17b1804b1-459f03fb315ls17789935e9.1.-pod-prod-05-eu; Sun, 10 Aug 2025
 00:20:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXdzHGaHpbtexG9mmIRwrE7rrd1kogfwqTGCN4a6o03ZqUi6frxJ3aNAlT9NynlXtkQf6GlB4DPWSM=@googlegroups.com
X-Received: by 2002:a05:600c:3111:b0:459:e20e:be2f with SMTP id 5b1f17b1804b1-459f4eb6543mr85440335e9.14.1754810449608;
        Sun, 10 Aug 2025 00:20:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754810449; cv=none;
        d=google.com; s=arc-20240605;
        b=TfO4AEB5LuAGym0+86om6EgFRLZ01l8FaR8UBnr40vjACZYvljaT4O1IfWv8QWoRw2
         w2oRsaLOzr0GdeRowW0wkGaYDqip9Xth0q/D3d5PhhIVvbhWb/VjOmD4F3ERJJPZ7eBo
         gVNacbgo6GvsYXRmvbQ3vYNV+FEEC7X80GDUA8i9KGGi8IANDXiVggOJ1DD8/rqG9QbI
         Rah+78i96gdshFw8mBjRqHsjyHAlFW2mzZn63r9AWQjQ5h3dCfK9kxk0BDB7WqxyO+uS
         +fJqEQtiInqwLwl7rrD9YYsWOh2jzF17fn1vcA7hbJiBRcKV4PEF8GTf3O8p4yYjJ8Nv
         jfCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EpwULXc7N4PVrAxnhzJUCLFsDhMEPa8K20pRMtf9QU4=;
        fh=9Ihx4Pax3ALVcOvu00RjKChcPPaYUHFIEutZSU7tWEk=;
        b=TQbqKBZRoFiWXrL9SN9rjzduKyCxFpfygj+1y7LLLs9fWeyM3qJdMizUF2l/9HPhfh
         bLwj0aqgmCDLwVzxpNToGx+bkzm8dlFGeBsJ/ep1oD53MCpXMxF1cbLy6JMwG9/dRKWM
         NjdS47m55lp2/UbAbYsblvZAf+SDsOtFSPMYNfuoZ+EtJDBUpDozgOUTs+zc3J7xLZsY
         IbbhX1dhN0wekYNwMhq9qUvWMInR7NNDuOdK8e2NehJ0W/iXvhgH59c7laABViz6r849
         MaQVYAc6YmMUbmgniQnbTyEBN/usYNBDvZK8YQHrPI3E0lBwQRo4c/xg23TuDBksZOTT
         M70A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gjQa7a03;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c48d27dsi516178f8f.8.2025.08.10.00.20.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Aug 2025 00:20:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-3322bb2ac6eso26310371fa.0
        for <kasan-dev@googlegroups.com>; Sun, 10 Aug 2025 00:20:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVlUb0mJFHtf4fmlTH2Tg0w66ElGoygqU59Yb+Lwmz+fTZsphC/+d0NFzPTUn90uzhDzEv4466yVS8=@googlegroups.com
X-Gm-Gg: ASbGncuoC/9jcMpACHCZlNEasDLhPZzXXGkPx8Qv+k4OmSEkOu4W/Ml1fOLP/zKryXM
	HVlM+Iqbv6s7P44QZIagoNODMv/bbibAX1e7pb03IjhT43ODtMLVmq6qIe1ZVUVuWMzGCI9LF+e
	gyeTVFIC2EWyI6OUoDDSyBMBfpX1mA1bHdzTST5hQUXmj+cZEulxBWown4TbJ48D0iKS6CNubdJ
	M05rkC11ouy3lqs3Pz/6BUyKgfsH+rw2Olgfy0=
X-Received: by 2002:a2e:96cc:0:b0:32f:425b:3278 with SMTP id
 38308e7fff4ca-333a22ede04mr18232851fa.25.1754810448509; Sun, 10 Aug 2025
 00:20:48 -0700 (PDT)
MIME-Version: 1.0
References: <20250807194012.631367-1-snovitoll@gmail.com> <20250807194012.631367-2-snovitoll@gmail.com>
 <22872a3f-85dc-4740-b605-ba80b5a3b1bc@csgroup.eu> <CACzwLxjnofD0EsxrtgbG3svXHL+TpYcio4B67SCY9Mi3C-jdsQ@mail.gmail.com>
 <af677847-e625-43d7-8750-b2ce4ba9626c@csgroup.eu>
In-Reply-To: <af677847-e625-43d7-8750-b2ce4ba9626c@csgroup.eu>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Sun, 10 Aug 2025 12:20:31 +0500
X-Gm-Features: Ac12FXxZS7GKPiKLVRILyIcM2smc0R0yETsf0Ytt07yeIUtr59o1Bn8VVZobpbU
Message-ID: <CACzwLxjr+Z+xUj-936rcWDSqEwfUP7bRB1xcqZQKGE7ux-gEXQ@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: ryabinin.a.a@gmail.com, bhe@redhat.com, hca@linux.ibm.com, 
	andreyknvl@gmail.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, davidgow@google.co, glider@google.com, 
	dvyukov@google.com, alex@ghiti.fr, agordeev@linux.ibm.com, 
	vincenzo.frascino@arm.com, elver@google.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gjQa7a03;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233
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

On Fri, Aug 8, 2025 at 10:03=E2=80=AFPM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 08/08/2025 =C3=A0 17:33, Sabyrzhan Tasbolatov a =C3=A9crit :
> > On Fri, Aug 8, 2025 at 10:03=E2=80=AFAM Christophe Leroy
> > <christophe.leroy@csgroup.eu> wrote:
> >>
> >>
> >>
> >> Le 07/08/2025 =C3=A0 21:40, Sabyrzhan Tasbolatov a =C3=A9crit :
> >>> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures [1] that =
need
> >>> to defer KASAN initialization until shadow memory is properly set up,
> >>> and unify the static key infrastructure across all KASAN modes.
> >>
> >> That probably desserves more details, maybe copy in informations from
> >> the top of cover letter.
> >>
> >> I think there should also be some exeplanations about
> >> kasan_arch_is_ready() becoming kasan_enabled(), and also why
> >> kasan_arch_is_ready() completely disappear from mm/kasan/common.c
> >> without being replaced by kasan_enabled().
> >>
> >>>
> >>> [1] PowerPC, UML, LoongArch selects ARCH_DEFER_KASAN.
> >>>
> >>> Closes: https://eur01.safelinks.protection.outlook.com/?url=3Dhttps%3=
A%2F%2Fbugzilla.kernel.org%2Fshow_bug.cgi%3Fid%3D217049&data=3D05%7C02%7Cch=
ristophe.leroy%40csgroup.eu%7Cfe4f5a759ad6452b047408ddd691024a%7C8b87af7d86=
474dc78df45f69a2011bb5%7C0%7C0%7C638902640503259176%7CUnknown%7CTWFpbGZsb3d=
8eyJFbXB0eU1hcGkiOnRydWUsIlYiOiIwLjAuMDAwMCIsIlAiOiJXaW4zMiIsIkFOIjoiTWFpbC=
IsIldUIjoyfQ%3D%3D%7C0%7C%7C%7C&sdata=3DUM4uvQihJdeWwcC6DIiJXbn4wGsrijjRcHc=
55uCMErI%3D&reserved=3D0
> >>> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> >>> ---
> >>> Changes in v5:
> >>> - Unified patches where arch (powerpc, UML, loongarch) selects
> >>>     ARCH_DEFER_KASAN in the first patch not to break
> >>>     bisectability
> >>> - Removed kasan_arch_is_ready completely as there is no user
> >>> - Removed __wrappers in v4, left only those where it's necessary
> >>>     due to different implementations
> >>>
> >>> Changes in v4:
> >>> - Fixed HW_TAGS static key functionality (was broken in v3)
> >>> - Merged configuration and implementation for atomicity
> >>> ---
> >>>    arch/loongarch/Kconfig                 |  1 +
> >>>    arch/loongarch/include/asm/kasan.h     |  7 ------
> >>>    arch/loongarch/mm/kasan_init.c         |  8 +++----
> >>>    arch/powerpc/Kconfig                   |  1 +
> >>>    arch/powerpc/include/asm/kasan.h       | 12 ----------
> >>>    arch/powerpc/mm/kasan/init_32.c        |  2 +-
> >>>    arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
> >>>    arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
> >>>    arch/um/Kconfig                        |  1 +
> >>>    arch/um/include/asm/kasan.h            |  5 ++--
> >>>    arch/um/kernel/mem.c                   | 10 ++++++--
> >>>    include/linux/kasan-enabled.h          | 32 ++++++++++++++++++----=
----
> >>>    include/linux/kasan.h                  |  6 +++++
> >>>    lib/Kconfig.kasan                      |  8 +++++++
> >>>    mm/kasan/common.c                      | 17 ++++++++++----
> >>>    mm/kasan/generic.c                     | 19 +++++++++++----
> >>>    mm/kasan/hw_tags.c                     |  9 +-------
> >>>    mm/kasan/kasan.h                       |  8 ++++++-
> >>>    mm/kasan/shadow.c                      | 12 +++++-----
> >>>    mm/kasan/sw_tags.c                     |  1 +
> >>>    mm/kasan/tags.c                        |  2 +-
> >>>    21 files changed, 100 insertions(+), 69 deletions(-)
> >>>
> >>> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> >>> index f0abc38c40a..cd64b2bc12d 100644
> >>> --- a/arch/loongarch/Kconfig
> >>> +++ b/arch/loongarch/Kconfig
> >>> @@ -9,6 +9,7 @@ config LOONGARCH
> >>>        select ACPI_PPTT if ACPI
> >>>        select ACPI_SYSTEM_POWER_STATES_SUPPORT if ACPI
> >>>        select ARCH_BINFMT_ELF_STATE
> >>> +     select ARCH_DEFER_KASAN if KASAN
> >>
> >> Instead of adding 'if KASAN' in all users, you could do in two steps:
> >>
> >> Add a symbol ARCH_NEEDS_DEFER_KASAN.
> >>
> >> +config ARCH_NEEDS_DEFER_KASAN
> >> +       bool
> >>
> >> And then:
> >>
> >> +config ARCH_DEFER_KASAN
> >> +       def_bool
> >> +       depends on KASAN
> >> +       depends on ARCH_DEFER_KASAN
> >> +       help
> >> +         Architectures should select this if they need to defer KASAN
> >> +         initialization until shadow memory is properly set up. This
> >> +         enables runtime control via static keys. Otherwise, KASAN us=
es
> >> +         compile-time constants for better performance.
> >>
> >
> > Actually, I don't see the benefits from this option. Sorry, have just
> > revisited this again.
> > With the new symbol, arch (PowerPC, UML, LoongArch) still needs select
> > 2 options:
> >
> > select ARCH_NEEDS_DEFER_KASAN
> > select ARCH_DEFER_KASAN
>
> Sorry, my mistake, ARCH_DEFER_KASAN has to be 'def_bool y'. Missing the
> 'y'. That way it is automatically set to 'y' as long as KASAN and
> ARCH_NEEDS_DEFER_KASAN are selected. Should be:
>
> config ARCH_DEFER_KASAN
>         def_bool y
>         depends on KASAN
>         depends on ARCH_NEEDS_DEFER_KASAN
>
>
> >
> > and the oneline with `if` condition is cleaner.
> > select ARCH_DEFER_KASAN if KASAN

Hello,

Have just had a chance to test this.

lib/Kconfig.kasan:
        config ARCH_NEEDS_DEFER_KASAN
                bool

        config ARCH_DEFER_KASAN
                def_bool y
                depends on KASAN
                depends on ARCH_NEEDS_DEFER_KASAN

It works for UML defconfig where arch/um/Kconfig is:

config UML
        bool
        default y
        select ARCH_NEEDS_DEFER_KASAN
        select ARCH_DEFER_KASAN if STATIC_LINK

But it prints warnings for PowerPC, LoongArch:

config LOONGARCH
        bool
        ...
        select ARCH_NEEDS_DEFER_KASAN
        select ARCH_DEFER_KASAN

$ make defconfig ARCH=3Dloongarch
*** Default configuration is based on 'loongson3_defconfig'

WARNING: unmet direct dependencies detected for ARCH_DEFER_KASAN
  Depends on [n]: KASAN [=3Dn] && ARCH_NEEDS_DEFER_KASAN [=3Dy]
  Selected by [y]:
  - LOONGARCH [=3Dy]


config PPC
        bool
        default y
        select ARCH_DEFER_KASAN if PPC_RADIX_MMU
        select ARCH_NEEDS_DEFER_KASAN

$ make ppc64_defconfig

WARNING: unmet direct dependencies detected for ARCH_DEFER_KASAN
  Depends on [n]: KASAN [=3Dn] && ARCH_NEEDS_DEFER_KASAN [=3Dy]
  Selected by [y]:
  - PPC [=3Dy] && PPC_RADIX_MMU [=3Dy]


> >
>
> I don't think so because it requires all architectures to add 'if KASAN'
> which is not convenient.
>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxjr%2BZ%2BxUj-936rcWDSqEwfUP7bRB1xcqZQKGE7ux-gEXQ%40mail.gmail.com.
