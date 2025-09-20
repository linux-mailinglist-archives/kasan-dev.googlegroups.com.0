Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSNSXLDAMGQE5JHVUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 61E8EB8C7A9
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 14:08:43 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-6235a68374fsf2064181eaf.0
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Sep 2025 05:08:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758370122; cv=pass;
        d=google.com; s=arc-20240605;
        b=L66526LFEwLHNZx4pgIuUGRJCt9MBivdRWLizQ9lUh+cIf/j0H0de3cTX3qlzCokL4
         qlcDzEPSU0KhhOdw8feTXYMTGtKMyMlg81ahxU5wLjDHujCUXHxSLqMLPQRsNOFTpPdr
         1HSsPovcNCfHxkVXbHDm97F5PUCmw23YLnOFiSQytq6Nn80v3r1qeLLJKH1cEm3YuBLb
         C2OazlIgcXVKX4PwbCJjea1cjbJGNUEo1mfW0EzPRM8VprIw3dQcX7adYpwzm0xpfqQc
         c3ECoRyCg/YhxIzIv/xKcDtCtNoQOYcAb8I8CfccJnLeTSdCOKNJx7oRLaqt+iaWP4yI
         5BQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EWzSBzzdLgSkqzWyKNYkjcZFNIfuo5HrguOkm7UuOow=;
        fh=Es0N+dHk2Ioupmw+Jks+Fb2T8PEoKwWnxSrnRZOebK0=;
        b=ZdRwYRUpJcO2+jizURFZakyB+lHIytKPsKi6jbQTFQuXH7JtcSihZerQWjOsPDXH2c
         e4vHpd1vaDU0S99KPkNUFKlOd6rSUwd0a3uhnzmj4voqi5dbbWmg+dFee6sD6ROiWHe7
         22ptAObAeV0YVM440TaCnf7mBMAjuRGJ8KBeEXiNwB4I0N2hydtXpcI/OGHNoCeChwQ+
         6/5ptofL5JvHDJANDKITyBymhTd89HX1wSN7zShc42Y7aXBncNG2RWs4vyWa/lWlmrfm
         UKmDBhy+5bYWonF3mu18zH0foteO6qCcIMNVKOZOIi0Mmc5IsSDg2mWdqUb7WtvRUwte
         E/ZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eyjjtT0H;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758370122; x=1758974922; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EWzSBzzdLgSkqzWyKNYkjcZFNIfuo5HrguOkm7UuOow=;
        b=jQr6qqVw5BAx+ks8xV0pF0I3NcNZEn34zLoxGec1gKgD2JWNUTkNTq5eRySjY3V0ey
         VQ9qbREX8gxTf/yvqVSXl1QnosqZBzrFAZTkf6s6D8dJ3rhiLb/PsJZ3RDrx473b1DI4
         Zv5u5/wySfX6WUeen0iT5x7iMfUWspuxDD0DE1D3RBmpO8OI2+3XcnIEeo3F9dASqf8A
         u9AJl38qvDaFe25H95Gvk9UjhVTyZ/LNGHetC3HidXbWkePZ7VJNGGAkeH8TPkfMurDC
         VkL507NMeOvDwVffRh1Br91N9HTWMZZJUb1ViTlTBOxXHaJXZ1fVfmxcvPW31T16h+O1
         31JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758370122; x=1758974922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EWzSBzzdLgSkqzWyKNYkjcZFNIfuo5HrguOkm7UuOow=;
        b=E4A6N/4HnqtIF9jyxh/FsZ4gebzlSsmuQK1R7ohI30A3ozThCQz77fAdYdHehRuw7b
         P6NlxIRmbxT0Dh3/8EW7h6yaJrgEzGMK9DdebL41GKMJmsQGQ2VUIqnCWvFzFtxtBEAh
         hRwL3dQo5XRSoKadNhutm5+/V2bnbxZKwxUCRh6aVzdtwtmsi4WJQ81tyRKHrYLhr1gS
         X5VaewLtYq4OD9Y6/Ks5wEeqoInGm1quKQa8k5gRldGUJCEi8mir9Mp1nJAlWPn+qDwa
         UnHkwWIp5H41dg+9Zl39cww/h9vJOMboHchsTb9Y5uzhrLWwjoNf5B58DIz1PUOSN3jb
         SNUg==
X-Forwarded-Encrypted: i=2; AJvYcCV2USxzyf92bW74iY4CaiJF5mvjtOEvHRIeBVlTS+/Gwmdoq9gHSWKBUz5R2CyBk764e9MBrA==@lfdr.de
X-Gm-Message-State: AOJu0Yz1LWlJwX5TXsI94U+959XE29jskvuQaehR/H1IpkYQHkEZ9daE
	3+TtCfyx2K9148VuCOyoMzjBxpbTaem5/WlUha2Bnk3+uaL3i9wGj+m2
X-Google-Smtp-Source: AGHT+IFBYDknplbac7JGYsaj+m3mgAWce/qQGITHKExbUW5ZMsHkVAYphZueCbCxo5y33e6FL9mJqA==
X-Received: by 2002:a05:6820:2228:b0:623:483e:52d5 with SMTP id 006d021491bc7-6272b1befb9mr3215839eaf.7.1758370121792;
        Sat, 20 Sep 2025 05:08:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7L03gZayJ4l51yivuHAvWcbFhzgq8R8xkToHtMEVGYXg==
Received: by 2002:a05:6820:450a:b0:61d:ad9a:b7c1 with SMTP id
 006d021491bc7-625df4db16fls1695372eaf.1.-pod-prod-05-us; Sat, 20 Sep 2025
 05:08:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIvAso3ga4K17VY5P6Cs4/cgyVo777TVaceTNhMVLoTHU+e76n84sKtBBaMiAZir6nVYMSCYMDmOc=@googlegroups.com
X-Received: by 2002:a05:6808:30aa:b0:43b:bcb:70de with SMTP id 5614622812f47-43d6c2c2b7amr2964503b6e.46.1758370120747;
        Sat, 20 Sep 2025 05:08:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758370120; cv=none;
        d=google.com; s=arc-20240605;
        b=YplDOn3eUG1J1EZCdp+vmjJ0ryALAA4nSlnoDg5iS2B6DBJ2LzStrrI5BPTQnCSp+Q
         DEakp2b926SiGU3lZFnsize3VVU4P82qgfJNNwGDL+h01ZdVCwZu+OzmRk6C0XZNfg70
         st8rHF9b92H1ARHATF2uzwX2Vgs9ByBa4b4jBgiAmguH2NWWRShVHm3Lpz2ciXVfXge+
         0JgRcFao6Ea1Al3WXOq1lVnV9MVi2Q0zau5TlwAyFxBzdRMAFObRQcvBOcsOy/Yrl6AI
         OEr04yIeiWiJameXcaRYtThL19AQp55AkjUXjmx6gDhPeudnOOhs82Gr78MxGkaRt4sU
         bA5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rg0aAAaEFwb8WUGfzZYLj8KGkf4Q3J2CuRbPLZDHdFI=;
        fh=CDvVPQ6fkXLvomNHMZNjb7+lOff7m+PA6BSqbPWmc9k=;
        b=I8cgX70acqsj40dkuko3vb8sxfKVWLgB9cYYpEla8hifCYzhsmIbmoGiCpUNTngkez
         dM184pbp7GXdQc+ytSku1zUnoNGEiV1zbb2s7vdSDKyec0M7gPnQsAJG7aW/E6qTo9qd
         fxckt/zjB6NF/6gFaZsBZPDwMXq+JBAraVpeKcisrIkmXtJQ8cQ7RXt1p22JQ64QCiKT
         WUjMtgza0TPM8T8IaZYuiUAdXqWI1yuimT/v2zGZxxKo2hkQjoTe94NFPR5B4Jrj+8x4
         VAk3W3Iw8LoynSK/aLriJfJ25Ym1IQcNSTOdKJdz5EoHk9QwDZa3HT7QNEV+ZVZFfoRB
         tooQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eyjjtT0H;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43d5c8a3a6dsi315537b6e.3.2025.09.20.05.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 20 Sep 2025 05:08:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-796fe71deecso22341046d6.1
        for <kasan-dev@googlegroups.com>; Sat, 20 Sep 2025 05:08:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUsD/hyhrSiU11C6qiKUCgrTVMa9pMtSmygqLf/xR1sZ6s3Nl7puYloNlgIa2BR/skBiSrQapGaZ6k=@googlegroups.com
X-Gm-Gg: ASbGncu7OBdCLgId0tJ6H0ACTZdvvDLdZL7WPLi2OR7yGz3XTXgoUEBzXVf0TG3Qs+H
	aJXCFVOdULrtx3jogHd5Jz8sNVEk9W0jznb4EgaQrd2ZyYsjAVkAJhiWFrpTDCdQaeTFuv6BOXU
	Ekmzi5+v2Lki3Kwmmu7Lvw4MW0qMAkM9LBKIuEYR5N4ohPbj1XoQDAPoEh0EK7KnnhKboKtjft7
	9/PzPx45BoXqS0ATtKdaS9y1mDltVjqmvAVkw==
X-Received: by 2002:a05:6214:5712:b0:7b0:d5a0:c60d with SMTP id
 6a1803df08f44-7b0d5a0c6c5mr11507116d6.10.1758370120098; Sat, 20 Sep 2025
 05:08:40 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
 <20250919145750.3448393-9-ethan.w.s.graham@gmail.com> <CAHp75VdyZudJkskL0E9DEzYXgFeUwCBEwXEVUMuKSx0R9NUxmQ@mail.gmail.com>
In-Reply-To: <CAHp75VdyZudJkskL0E9DEzYXgFeUwCBEwXEVUMuKSx0R9NUxmQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 20 Sep 2025 14:08:01 +0200
X-Gm-Features: AS18NWBVqpbu6_S8igqrpC6d_4rlaGzIrca9Y3paJY9H7AfaiH53k8LL1oZq4JA
Message-ID: <CAG_fn=XTcPrsgxg+MpFqnj9t2OoYa=SF1ts8odHFaMqD+YpZ_w@mail.gmail.com>
Subject: Re: [PATCH v2 08/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	andreyknvl@gmail.com, andy@kernel.org, brauner@kernel.org, 
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com, 
	dhowells@redhat.com, dvyukov@google.com, elver@google.com, 
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz, 
	jannh@google.com, johannes@sipsolutions.net, kasan-dev@googlegroups.com, 
	kees@kernel.org, kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de, 
	rmoar@google.com, shuah@kernel.org, sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eyjjtT0H;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
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

On Sat, Sep 20, 2025 at 12:54=E2=80=AFPM Andy Shevchenko
<andy.shevchenko@gmail.com> wrote:
>
> On Fri, Sep 19, 2025 at 5:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gm=
ail.com> wrote:
> >
> > From: Ethan Graham <ethangraham@google.com>
> >
> > Add a KFuzzTest fuzzer for the parse_xy() function, located in a new
> > file under /drivers/auxdisplay/tests.
> >
> > To validate the correctness and effectiveness of this KFuzzTest target,
> > a bug was injected into parse_xy() like so:
> >
> > drivers/auxdisplay/charlcd.c:179
> > - s =3D p;
> > + s =3D p + 1;
> >
> > Although a simple off-by-one bug, it requires a specific input sequence
> > in order to trigger it, thus demonstrating the power of pairing
> > KFuzzTest with a coverage-guided fuzzer like syzkaller.
>
> ...
>
> > --- a/drivers/auxdisplay/charlcd.c
> > +++ b/drivers/auxdisplay/charlcd.c
> > @@ -682,3 +682,11 @@ EXPORT_SYMBOL_GPL(charlcd_unregister);
> >
> >  MODULE_DESCRIPTION("Character LCD core support");
> >  MODULE_LICENSE("GPL");
> > +
> > +/*
> > + * When CONFIG_KFUZZTEST is enabled, we include this _kfuzz.c file to =
ensure
> > + * that KFuzzTest targets are built.
> > + */
> > +#ifdef CONFIG_KFUZZTEST
> > +#include "tests/charlcd_kfuzz.c"
> > +#endif /* CONFIG_KFUZZTEST */
>
> No, NAK. We don't want to see these in each and every module. Please,
> make sure that nothing, except maybe Kconfig, is modified in this
> folder (yet, you may add a _separate_ test module, as you already have
> done in this patch).

This is one of the cases in which we can't go without changing the
original code, because parse_xy() is a static function.
Including the test into the source is not the only option, we could as
well make the function visible unconditionally, or introduce a macro
similar to VISIBLE_IF_KUNIT.
Do you prefer any of those?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXTcPrsgxg%2BMpFqnj9t2OoYa%3DSF1ts8odHFaMqD%2BYpZ_w%40mail.gmail.com=
.
