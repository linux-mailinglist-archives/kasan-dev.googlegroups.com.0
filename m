Return-Path: <kasan-dev+bncBCT4VV5O2QKBBIOUY3EQMGQEF7SQ2JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id AE536CA445E
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:34:58 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-37cf98ec368sf7721861fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:34:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862498; cv=pass;
        d=google.com; s=arc-20240605;
        b=eBvPXeIluv0QXluuj/rB7LOKVBvA4MNMy6XkYAHs3/CWNf4Jk6A8kLzRQUnBYjP/O+
         wS8mgl8ebBEEyHstquApKBO3Y3eqHjxtXhJqOUjjJLNWvFEKiWoCUQhX6TbW+hS4oUvU
         DsWV4EpblO9CKjvNVUqGNyOC/Ru8fpa9lVgA+1mnAOeq7yJDjoSFaZm+um1te55TFoxZ
         wYAOwlBMHeKKY+dJPlxfMaB+5IT9N5hT0DsMNmoBmdywuBHAVKBVLtIZ9XEEf5It4b7W
         BHQBhRHJOqeQcSjTi0/X0xjhP6zuw/tkqCiCo3V4duxUwWt/X2T9Wm/HJPh2YqyjoAZ+
         xBTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Da1edGc6Dwa5kS1uvfVWKs7r+yIkDpR5xy4mj/kCxmg=;
        fh=bEmt5ZswKV/YKVK0uKZDD3ECuZVieCHc12/vMYeJZ1E=;
        b=EMVLDSygkYer23sJ1b5XOuVdHTki6fTdaOKcr/jqMLvBaoisz/oEabqwchOCZW8vyb
         081X/LcHVsri8953ehL/y816meYpk/WeMzwV/INmPi1iRw+Nz9e2qW9kC9kbNO8db6Md
         XXsj6lfNm9H+N0u1ZQ+wkGpFoEWy94tb5pdcP89D3l1HEb+Ic1Uw3wdf+rKPHA6FYsYg
         FEaQvvSG8pDMgVI+8nhcER4C8tI0Lv747A8mbZW1g8F+vVreXwNcmXfJSOsSUFha87oF
         VFKw3Smur6gFKijd7IouTsgr9ljy3GAM2ivOS64RcHqi9xSb9Cg9dGqwEG8EEn9OIJhb
         phRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hXqSsfi+;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862498; x=1765467298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Da1edGc6Dwa5kS1uvfVWKs7r+yIkDpR5xy4mj/kCxmg=;
        b=qazsqqWYOZEBFaRBOiQf+5nBe80xy5yQoCKyxr7jCZxLFxEmKY0NJZbe4ty53fn6JJ
         zzls/ICx9FRjBXJVG0nGROeczIm/Mr/KQ9BTxG/ghUw5fkHmBYtqbV6ZXCj02dtQfk1u
         m7AcjjgqE5OWfj8WwQxYjma47g2ObOoNyPzjC7L1a5BZne49Y03E+hKb1EWdfEohTzzj
         E0m3sngdLBi5m0siC19emV4alihstn5dGWSdTMTvIXZ8eCH5ilmsxGaEAR+nSsyz3yPu
         4rJAKzS6vyxme2JUIMmGGeUF1h6UtJwX5szQp1WdQcUQQZsRm0dEQ9lsL10iUKvaW4ng
         YNOA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764862498; x=1765467298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Da1edGc6Dwa5kS1uvfVWKs7r+yIkDpR5xy4mj/kCxmg=;
        b=g9AeTQmwWB89YpUain6NOR3uP6SKiKMN18iWvAcKzZ31RBZAmTm9BjZ7tQEVmdAHpO
         YtBrEcuIzZB+JHFhWac8BBI18g1wv5Pi4F+RPBf9HqbvZ8cUE6WCYq5ER4HqEop+NE7V
         1sFI6qVi62W7vWLB3VkpYN4+uY23hbljJY3F0cTaXryXpKBdoZkPkwOK4Yq5jFFC84yx
         gbdtH+hnYELy9FU1DhWYGgDpBCnD1aA+kvVizo7VMAziYfs2V8pyFtfJpmjPYOTyy7Nm
         QHrdYVpTGEk4lH3SUScwmbpnDNxzh30C8QiT5x33CodSI07370NKynZHrjNsRHI14/zX
         jUYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862498; x=1765467298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Da1edGc6Dwa5kS1uvfVWKs7r+yIkDpR5xy4mj/kCxmg=;
        b=CYt3TjEG7hzpuG0P3DXiT1swd4TEe8jALk5JZunmmiXTCYhnmlHPteaSQx573q01Q1
         F3wKJSc28hobMs14QKpHwvwseCuH2fwiVLXZdStzjNIbL7moqAAcEylLlQRUuV2QUnVg
         26B4pV27lfZiM4ErqCD96txNDP7rzd1j8dmDZxCTtPSLNblQiN7inajUxgKuPAHmC2J6
         3qgAnD798Anb0O+95Z/JWb8ktmlXogj05Aoura5pBLA4g33HCjrpGTqzdJ2kIuL2IcUv
         2vLlFsDnpWoW0iPP0RcuzE2ey3NIH+VGPKN+Jo4ZbvsDmHQKdGTPOZutA72YF+xgi/kf
         jgsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXSknR0xU5DB2sxma1+j6gNEsYIfa+p8iEEesga83oLTDnA5c0zH0+ZMlzK9wI0iSa++5DtSw==@lfdr.de
X-Gm-Message-State: AOJu0Yzu/XYoARjXzZ+B0mCx550wBWPCyz9KLxLhDgdg7sEhzmX+YYtU
	qcrbvLuHiGFj2wCVIU/mCsfZG5LUnCCliYa2CT5EkLWOXwfF1tTrxBgu
X-Google-Smtp-Source: AGHT+IF4cEyTkF3TF5YmK3ALjSMBERZzoUnKz+prDTUDwfopyXR93M9AOZkqfDuNO27/atcJgcUJtA==
X-Received: by 2002:a05:651c:2101:b0:37b:b4b0:a4be with SMTP id 38308e7fff4ca-37e6ddfb5f9mr10816771fa.24.1764862497822;
        Thu, 04 Dec 2025 07:34:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bZBGpkBM1U83vganReEozu+ADXqtuYWSMTjUdpJUzgwQ=="
Received: by 2002:a05:651c:435c:20b0:377:735b:7cbf with SMTP id
 38308e7fff4ca-37e6e93b169ls1419191fa.0.-pod-prod-08-eu; Thu, 04 Dec 2025
 07:34:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXZ44+nq0VJxafARYlhXKV/e3q1hiMbGBu1WKDn/xZEOXBM0Ao1T3oxDfkudr/jjKWsPRoJm9c1Rts=@googlegroups.com
X-Received: by 2002:a2e:be22:0:b0:37a:2c75:7d83 with SMTP id 38308e7fff4ca-37e6dcef18fmr10979621fa.13.1764862494412;
        Thu, 04 Dec 2025 07:34:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862494; cv=none;
        d=google.com; s=arc-20240605;
        b=gNFZxcvXbTTp98/nCufnNeHGJhY0mDtzMZ7tmPtz6y0LJ/AZDpw1+rj+JSnDTCvv8S
         CLQLYitgiXc7faoMLfObiGecRpZIB1MGZp+VizKb+8XdW7aQt2/4i3+vCKessUgQNNWg
         /Wt/YrpV0o+LCNnDsJGMB1nwbEgOoLF1fnwO1JBWKt3O1WqijIFe691/o/0MDc8YSLsM
         eyvSZH5qIsO11N3yDCFvQOcvgVTG26xF4F1ajegW0whedm58aKp2+w2SiJUPnbheBV42
         JSjuFTI+0QVE3EgUNWUe4CZXpwIDzXJLpXemL3gZJi5C8pu0/WqXA1wHQzB1PnEv37P8
         XzqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G52wAaQsJpBzbRSlGJ+JRlnvopv8+9HkybJuziiObfU=;
        fh=yzkGrx8nFGjFtDNXR1UWJBme7Y1ZbOQ6erYIGUoMBds=;
        b=ZfpeZlxrHap6Y10V2F+Ms5xtpZfPUfUmqF+aT2MfWC2AEnIE4BWnwTidwMxggOqke4
         ZKQNcTWYzId+x+N/3N7BqCbWG8EtxZJ/xTbAMj7kuskkKkr3zJ8l2qN/iGvwbk+4PMKO
         0rF/hH/5Xlf8C5Nd0uzeUkYNBIN4zOD+g/L2x1KcCgntZlULKVobHhy850MdVf3AemCQ
         Mzyu9bT2ttabwhoeWmzYCxvUq43kvNpx958HMdkUE/kYC3LQJakLGqQJLOryG2SwHK+i
         PctKfqk5oE+JxVckP+cXNYRiFq1MKz/nTtTOywy4RXlL1G45YNV8La0xzPSugf3ZbC7K
         LE7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hXqSsfi+;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e6fe6b7efsi363701fa.4.2025.12.04.07.34.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:34:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id a640c23a62f3a-b79f8f7ea43so96920466b.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:34:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUd4WG/WTjKr/Uc3MpP4766eO6BtBdATbCS/UGvUP9so2vnCWWJOfN8JMXLBvjtRoJJm7BA1Tg7nJc=@googlegroups.com
X-Gm-Gg: ASbGncvoYytautOPeEMPQnnxWU/VYPRaTMmOGvhhkPjXpAP8IqWSBCFlTq3XKH6FNJA
	oBIXr5wqCPkV0g51WlLJdudpAUayG5ES1m783IOv0DY4Ypa8mN54Qo5dDNNKDYO2Fo0GKpQdEn0
	VGqwlRp/lhwYZSjdb74z6qv8N97aXQD0bvLNWJwupatYEQ/I+EUcqiJlJE9FeRlphkBh20R002l
	8ho/etYQ71LrBCHK/C++FalhWUHuH5Zn5a2oAyAaiHLyXFq/luZvofd95kmur9VAKAIAa2jyACv
	1g2nDUGVTN9sCLZTI4mJg2vS89S6FiE0qnyiCHLGeD6Js9GaS6b3l9NAkzo4X47EGePnCBY=
X-Received: by 2002:a17:907:3d11:b0:b73:5db4:4ffc with SMTP id
 a640c23a62f3a-b79ec6eafe4mr430825866b.54.1764862493337; Thu, 04 Dec 2025
 07:34:53 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com> <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
 <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com>
In-Reply-To: <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Thu, 4 Dec 2025 17:34:17 +0200
X-Gm-Features: AWmQ_blNq2tKsiaeXqmusYzQlrYj54gbJfHS_HnTcSjJWKKhY3CPArHyaMfz3CM
Message-ID: <CAHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Marco Elver <elver@google.com>
Cc: Ethan Graham <ethan.w.s.graham@gmail.com>, glider@google.com, andreyknvl@gmail.com, 
	andy@kernel.org, brauner@kernel.org, brendan.higgins@linux.dev, 
	davem@davemloft.net, davidgow@google.com, dhowells@redhat.com, 
	dvyukov@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, shuah@kernel.org, sj@kernel.org, 
	tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hXqSsfi+;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
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

On Thu, Dec 4, 2025 at 5:33=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
> On Thu, 4 Dec 2025 at 16:26, Andy Shevchenko <andy.shevchenko@gmail.com> =
wrote:

[..]

> > > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > > Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> >
> > I believe one of two SoBs is enough.
>
> Per my interpretation of
> https://docs.kernel.org/process/submitting-patches.html#developer-s-certi=
ficate-of-origin-1-1
> it's required where the affiliation/identity of the author has
> changed; it's as if another developer picked up the series and
> continues improving it.

Since the original address does not exist, the Originally-by: or free
text in the commit message / cover letter should be enough.

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA%40mail.gmail.com.
