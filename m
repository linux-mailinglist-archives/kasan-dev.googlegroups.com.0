Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5OUY3EQMGQEGFP5GII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id B2C6CCA448B
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:36:23 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-8b2e235d4d2sf360567585a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:36:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862582; cv=pass;
        d=google.com; s=arc-20240605;
        b=gdCm1QvMjZHQCCkZo9V0YdwO5IZOUCRl5DAVKIix4ehYsYEyiCBS3RVdMR8Q+kiM4w
         neBo4lEMQ5fujd9bh/zsS/Dyw4syWQ/Xc7aGpo/If380CNBwxR5/STewxZYt/paaECre
         w2RGu0ay5YF0HbD+bF2Hz0+qWXykbaxWlWJ5LpY5ZgezSZkKhaUjGV7tvmhmka9UiDhf
         uDu81PLj8HSNVJfOyTEHzouS+Up7Au07wSHnnE2Yy9LDLWaGkDdaXBLBfrzp8JuGS77z
         PoiwMYCUf/7ZcCeSRxo90hu6DlBR7DFTzE/+h8oIeeIYMnt8ZkK1IoLDZ/faCr5OvSsC
         gx7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mRbGqE5zZFTLRL17eeomCP9zR6zZPnFARTotO7oY/Zo=;
        fh=H40QLWKSlm7ktXId0o9SrEx1fMUB4sUclKcSk/SKXFE=;
        b=VScRFiskDrTodrlBTCftyk6J6CbJ9D7gsZoK/UirOvF7kdme3n1/60yeWr0eL2rlTV
         dFzWEZ+v3X1zTxff8/glb2eBfnAeoGRWC/oKuyJRz0yQ9cz/K7EOezluGSK8P/zQW9DE
         SDhzeLjWMI5QjTn3EMgmc54wFQFuZp/lc/j4XTspAP/cljHbqcpUgpH95rgakV+5unMw
         bS3ArejSj5RC1GIVlWZzVufkn9ej3vv9eEzL8whUEaMcDeasqfr85tcf4TL5SBZEfC3T
         35q0o3+3xD/RUAm6PRujNsCwJ/sVXpUWqlVIfLI4hUNRMxLti8ZKCIBGlLHuCpLebHQs
         PJXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2RX3kZId;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862582; x=1765467382; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mRbGqE5zZFTLRL17eeomCP9zR6zZPnFARTotO7oY/Zo=;
        b=DlqXPYBCsWbHG8i3r2HwGgTTS6KPQk13fhfyiqCcV3dD1fTlyUG0zACRvcPKJ4ej5o
         09xFXIzwq9iyTSweGP+v4jEC+sDLUWxZSoz7/XhFf+j7tm2qJ1PtIGGMIK9+URlJBfK0
         TK1DQXCbZp/9z7UErCdrmshCZYCJcA9XK5op+tmcXMKJclrrrBfz0WErowiLHDgvAH4v
         4DRF5x1FKZw1NzY/9s9jmg+Iowndm5k6fTV9FFt7Kr4B3puTsUDt+1sLPE1iQkQm/Uh4
         x5JwwRy/8G49Mrc7h+KcrV2jZZucAi+CHDxd+CV4LFjWIrxXQabpha3PwaDSToEBvTGM
         j8+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862582; x=1765467382;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mRbGqE5zZFTLRL17eeomCP9zR6zZPnFARTotO7oY/Zo=;
        b=Mvd3ujxVsCNZObB/W0+cx3v9QGQGRmZ3GdJEXHtEdbrQKxkMLxWXIS4jbv25NSX6Nd
         Wb1BuYYXcV3Qfru3becaO086NN6l8htBGPxowwtuFdyAq0PgIcFYr+Q0n6daW7hq87Ut
         0+0YfUCO+B5ly7AZshSH63n0sQXYFHfVvEZF/jCzY7W15VVCSn2hBcPyoL/r3+L3Q2/Y
         tVlZgQGaggmaxLsWdf6SPlRbOjiisAYu+0g/oFx1u50Drs8SOj5r97TipVrMtfPCIrkD
         J8AKmxMuwLvbBLJpQQHGKpJ3ZB3cMODvc0scP1zJ53hrC2CkyWb8ACp2cWsx4S9Pp9gv
         f7uw==
X-Forwarded-Encrypted: i=2; AJvYcCVtrlmeicDGxuMjNgw8hEvj7AI6lP3WEntvKGG+/sVgOFJd9ddfY7xZbDKY2eVWfHhX6cjAPQ==@lfdr.de
X-Gm-Message-State: AOJu0YxEa2CdP78DHQphFcfJZv1xlavAZ6dzYuWvucMyQCdO7MqfdRRC
	oIam148jvReCAkngvksNzEOZumnCjBnzsm8IUdz+Tsyu64QUW/Cp1hf5
X-Google-Smtp-Source: AGHT+IFaIBvDCHKWL0qe0KBIriU+aArp3uYNT1k2UYKX0wtVBRcGmcTQMrtgdudq5Cca0rcqaQi/wQ==
X-Received: by 2002:a05:620a:4489:b0:8b2:e2ca:36b with SMTP id af79cd13be357-8b5e47cf46cmr944469485a.3.1764862581970;
        Thu, 04 Dec 2025 07:36:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aseI2dgdWjjwLDztl1tZEij27/buCmEUV9ru8I79/xPQ=="
Received: by 2002:a05:6214:848:b0:882:4764:faad with SMTP id
 6a1803df08f44-88825c82163ls14487006d6.0.-pod-prod-06-us; Thu, 04 Dec 2025
 07:36:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXYDmoVD/BnnkMZ6jKUav7P5WnA7b3RFpfUnmAc5e5LBFAgr8TH2uL8Uy8WX2vxJscNaNLLTXhmhaA=@googlegroups.com
X-Received: by 2002:a05:6122:d93:b0:557:2551:7e9f with SMTP id 71dfb90a1353d-55e5c0201d8mr2062757e0c.14.1764862580822;
        Thu, 04 Dec 2025 07:36:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862580; cv=none;
        d=google.com; s=arc-20240605;
        b=OVmgKfxWWX60LtsB0WkKHWGK6VZ872K6wor6p8+fKZOeRe5XOefvo6w1Vl6BwATirH
         fSuqpJruMm/1tGgb9ssSxtVOMZEVeRG7sxs63js0iHxgR8BharqV6+37AIzuk6wg3EL8
         oc3zYauzvVc2/Fq5Qf4OZMxCB0mo98RQahWSV6JFFayMYyUjjMkSdJgO5TsDWYKNzknJ
         1IrEyrIiPtuJubWi4oRUVxPtZJxHiy+ya1/m+TRUvqrXdWmboC5WTnPmiz1ym42253aX
         EM12sld8iNEpMmyaU+a3U5sRdRN8bwZtMymn5rHwQ7ReHgbbUZeKnwAYZJs0p3UsCG1l
         Z4VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LWBFD2aC28ujRjWCANBBdmEOHCG4fNF+CSlRr6FISyA=;
        fh=/gRk6zKoeWrYKFD06iss+oVNzyDTGlnvJ/mbVmXX+C0=;
        b=aplK07M3/zfCe/5Z+MvThHZPHckia+5aliMMyh2OvI+6YX3LFh7q0ZOrtOtcCpef1X
         uAolXFN7zJaZEr3MfTeDg6sYv6+6s4LP1xn0b2jAkxLvpfaZ4JTOdm847wb/P1T4biL+
         I0ZF9djY2kShbuZD2cIzRBLaz56vK+8tcgPXQRbwlkLf5GL8GkT9qXN92cBR25XRuIDF
         AoFtrnyCJAKJ5VRlyvxa1rLx6Nq8ml2yy4v/Pc4knMOilkGBBJ6cmEQY4k8gHyz72rz/
         v2o2I5oXPxRHO+wkN2clWXJvQC9Nc3fAWyVri+Xhjh6kC0wjTXcqsWogMCEa77v+J2gP
         f6oA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2RX3kZId;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55e6c473e99si96845e0c.0.2025.12.04.07.36.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 07:36:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-7b8e49d8b35so1223572b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 07:36:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXQMGDBOhi0wH6MPGE6hkkr/mujjZFMbjr6MCEGkWpKuGGtRqYNHIyc67RftdzZI3Y5DAOp4lQOwpY=@googlegroups.com
X-Gm-Gg: ASbGncs66RSbsZM9zvxuZ6H3rOtyYIuPotr2tvq224TLmgvwCY5wkU5M7gOXav9FyVa
	l10fAZaX5wRR4MlMRaFQo7YHc8uwtcxx4kEogvS8yJAA7VG+wGJhyOhUYOufsha1sovAcKgbONv
	FNOWTd+tZZ7n8SP5QPwWs2OYg2i11EgE42D+Hi8HKitbvd5O3TDG0xDVHz1BFEpwYj8lZghSA88
	r/QqnSFQeD6BvJUmiHVfQXIdPEantGIYb1NknCMFZeI4k3SvjIfKKIx1PJ7OVU8LIdsApsZj0Cv
	F7Tryn2z9g85vLdshRLjFfC8GA==
X-Received: by 2002:a05:7022:2584:b0:119:fac9:ce12 with SMTP id
 a92af1059eb24-11df0bf6409mr5437809c88.13.1764862579414; Thu, 04 Dec 2025
 07:36:19 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com> <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
 <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com> <CAHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA@mail.gmail.com>
In-Reply-To: <CAHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Dec 2025 16:35:41 +0100
X-Gm-Features: AWmQ_blR-jXZjBSUNwkZ-Kj8R77y7Gb2w-LzAguJomE44k13qlmxusnxd-LQq3I
Message-ID: <CANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP+6ew@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Andy Shevchenko <andy.shevchenko@gmail.com>
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2RX3kZId;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 4 Dec 2025 at 16:34, Andy Shevchenko <andy.shevchenko@gmail.com> wr=
ote:
>
> On Thu, Dec 4, 2025 at 5:33=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> > On Thu, 4 Dec 2025 at 16:26, Andy Shevchenko <andy.shevchenko@gmail.com=
> wrote:
>
> [..]
>
> > > > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > > > Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> > >
> > > I believe one of two SoBs is enough.
> >
> > Per my interpretation of
> > https://docs.kernel.org/process/submitting-patches.html#developer-s-cer=
tificate-of-origin-1-1
> > it's required where the affiliation/identity of the author has
> > changed; it's as if another developer picked up the series and
> > continues improving it.
>
> Since the original address does not exist, the Originally-by: or free
> text in the commit message / cover letter should be enough.

The original copyright still applies, and the SOB captures that.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP%2B6ew%40mail.gmail.com.
