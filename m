Return-Path: <kasan-dev+bncBDP53XW3ZQCBB5P6Y7EQMGQEOS6C52A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FA69CA581A
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 22:39:03 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4ed6e701d26sf29914671cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 13:39:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764884342; cv=pass;
        d=google.com; s=arc-20240605;
        b=iyOugFlZf5CbWR+ZNYvNek5Aj1rDWr1zKZObI21ZNG1z9R3iJIgutdRhLLn6JntIRU
         cojRibDtPyCeaZYMb55HhhQfBz2Fo8aa0pvdq3IktabF1xItPUdTiWlS8g7Szcg2KAXX
         nB08ZtLXh1MvlGKCpUbnE6fqq5krW/eY/ZvpKbU6suYYcnIPKuWzoxC+B4T2SRWj26eG
         EJDAeT03C3rJeOAaj1NGk2AFRRjNBjTcHqP9YM6yFe2htZZAbiQKTyUjv0Aqtfw+pfdc
         MKitZ2jPO2+xDB9UtwKBSjmblfRO0hn5S2bArn84D+4FyUeAYIsnFMYortLUfQtrOKWA
         PoRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=c2AJOwiYTOZKD99l4E6VE9bCu182C9SLyGd2FB7xfhk=;
        fh=RQKynDX3H7BY2IeS88JpehQ9Iirw2XBRGDjNVKc4V40=;
        b=Q1CS1IqyPa4rBkpO4MyUQD1/pefwZF48b0hgI9c8IdnxMNFs5gQzA4q+unfqWCzw9i
         SKJwmngPg/sA+U6TuID3qdP8cKGwq6LgvdjTTv47grHzuBmsRXpjmeXTomxlI9t6qclx
         f6GhL4PILu+KzIP9WeMQ6FKp6SZyGDb+B1kK00RGA/lvjF4fTgj55/Uit75xlwnUCZsM
         gw+5HtY8S/QdUZ+n2hs2xIshRuwHMXH9q9WrLdX1yQf09PoIHCkyEthBM1iEICaCaOIb
         nMuLare7kcQ36w9YZCxQkoT7jukuxBFL3mw+Ub+nQGaLMZayeALOCfpzUElF2c6bo6fp
         ynSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LBlbixH5;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764884342; x=1765489142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=c2AJOwiYTOZKD99l4E6VE9bCu182C9SLyGd2FB7xfhk=;
        b=Uj8Q9I0ZGJGizo3IRM4sc6KWqO7teLVtMr+lerGv7GeZLoxAmWY1YcGCCXPiKII6L5
         9Q1v2xRaLs1bwuAhMVK5rd0Av0XASg5732MI6knMLgKLQkhaaElWPK5UQtvK98aiN0in
         MDScftD6azRI4g4IAcrvov/ME+vkZ2EUsfxKQW6cQ6vtJcEDsyVTdNyjD/7JQqXMLOBn
         7/tuqEUgkS5ng5t8sV4cyY2jAuMVxk04ZNrzLGTzVW38uHlCSNf0SROFOggxB2ujGM/I
         FhKgBGf5/eUDkV9tJFkp+VcIItSjnQSiiGIJxH18Zx4PRvtNgmPGmhJiTLNf+NkIUaa2
         y06Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764884342; x=1765489142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c2AJOwiYTOZKD99l4E6VE9bCu182C9SLyGd2FB7xfhk=;
        b=CAfDamf52G9mZMJuoxbFXmwEDAoGunSwunVpEMYrTFJNauaxWVIU2cmS3hN4AJmzZc
         yEgr8f3RZeT3FhA89mR6ekz82m5AZOxRb3XD8tBPbnvBxy141xoCCIy4039q7DPp7LPX
         48Dn0oex4qPVgtxGpu3rT2iZ4EtSBXmxwOE0veUxa0U/ORnjt7Ui4WKTt6omIK+fu8L1
         0n5rM0XCV6Q+l288wAUpgR7rwLA28x5XmjYi3wAe5t86rQRWZtO18QqD8bsA76cZ4f1E
         rEKpd8MOpjuov6lmtXi71xFFs5vOdvqAhMyGBsgMYoGAXeeFjgkwmdA+Is18iSuGR6Wa
         fRSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764884342; x=1765489142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c2AJOwiYTOZKD99l4E6VE9bCu182C9SLyGd2FB7xfhk=;
        b=tUoC/Q6W5EE8XOHgll8zzqILaLPH78Ym/UUIfMjo6S+rtS9m5oUcst6q/d8TDpn1Be
         HLLo1TSkeQh4vx5G+Qgmd8MVJAYA5+Wit1zr9KJ0MqjB2CroGs3q5E9BvIINrRsDR07u
         LTIBTLMlE/8FojpjCGGdlHpq1/ckgo75JakAUuLbVpMcBjHx/Wm9mnBfrABaMTxX0t+w
         i0Bk+2hrFSQAKT1Wf8vFOXC5pBNQBiAvGOa9cVOqGVyx7AByvPhIRQDjXkPvxJ3EFteT
         zTDnpS26yUltONWTIFqbuN40nRlHI1YtKHay1GU60e9jW3BI7oJkQH0NILETupLEmee9
         xU8g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVVkSu9C5X8KPd71N8/ujwf+hNV7h/DsloEACm+LPGNjtW76pgyh+rP5cw+fDzTm14SVS3Bww==@lfdr.de
X-Gm-Message-State: AOJu0YzShUst06fJsXRlWukZA1PFLv+7Rvot52tHZarFPbjalI7ZXXxH
	fFxTBK3kDmlSLHdgfBV5vVdvk/xe4RStRni2SP+LCq2Z/kyNSmNPNbRy
X-Google-Smtp-Source: AGHT+IF4D/Ig++i2sICy/l2TM9xA3xQJ4B4/f0MvfMJees4JGcPa+bRcDfc8zF4R3rZxAiRjii6Cfw==
X-Received: by 2002:ac8:5906:0:b0:4ee:191e:ade2 with SMTP id d75a77b69052e-4f017656800mr112343891cf.67.1764884341786;
        Thu, 04 Dec 2025 13:39:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YFfI/XjFp6nY89itepZmi2E09V2K5oDKD+GReE3ThYOg=="
Received: by 2002:a05:622a:301:b0:4ed:7e5c:f41a with SMTP id
 d75a77b69052e-4f024c53db5ls28157531cf.2.-pod-prod-03-us; Thu, 04 Dec 2025
 13:39:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVtwUM/7mZ1lqde24/mZl/Ex05R3vj3how1c0PPRqSpJTB9zWxV7jPS36/5wWdHUHSz86/wfqy9uss=@googlegroups.com
X-Received: by 2002:a05:622a:283:b0:4eb:7574:65f6 with SMTP id d75a77b69052e-4f0175064cemr108793031cf.7.1764884340646;
        Thu, 04 Dec 2025 13:39:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764884340; cv=none;
        d=google.com; s=arc-20240605;
        b=Ymx36TjaGgDGWTSI18f2vj/v0qN2s3VWGBD07+hdeAA4T9F3UKSBioznvhidZOyEGu
         zdaPqGzV17X97y1JliZlDEzXKzDpm1DOACPCarWMVYl07blLn2JbSyBQn2uXGssNRzfA
         +8sDFgM7QDbxTihSRON4p14oFcMoeW281IUH1Bcr6ckNziL4QZKSeg2xS1yqNX21ZC+f
         8R/0zvEa6m2/268LDdBkBa+ZhWJfXq8Iaq1UJIyfXWYwi8ImLc2TZNbQU9T4MYVkWZSb
         8H37d5iwx4yqsMPU+Aih6Fu5tey/u8hJELRh/dBveey3kqy8Fok4yY8XgueuJAd/7Ulm
         FNzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7a4apymdvLMzvSssxC4jYelA1RIA+3s9lZemZv4hiVM=;
        fh=zTln2FzOTP7hp+eFSLDSnbd8Xqkv0SD7EckBiEBlS9E=;
        b=ce1ihg8KKte25JXf9bHr78eoe/D6wwV04+E5Rx6eHlGWhBTQUh1h8ST+3Ov5n90Cjm
         yRjQQR4klBrHKQl0lNweUr/mKSxEI/MEW9CZXSnnRfdtAjfLPbNnU1fH6ri+vt5TdTsB
         goQBy7njpZHVa0uyRungyUvZqE0n4t8l5EsTLudY044iAzIhIxNzsPcDDIEdVr4aVjPm
         HLV6oKgkkPC/4k/m9YAHRO1JtLKW9nQmySLob59dgBPxfYO6ZaNjHiYeiU0FYNcSORH3
         iGPCyMsv4guzqArlRuked2vV69GjVAiOikcUGbbHbETco65+UQT7PR3kDvbXVHIxIZeZ
         UgIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LBlbixH5;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4f027652cb5si1235811cf.2.2025.12.04.13.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 13:39:00 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-7e2762ad850so1308870b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 13:39:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXfB30XogjZkMrvugj1LBvSZ18efKy8yZX+SMs81jItPAamrxGWIAPpFVfTEdDJujG25c3W9LEmbI8=@googlegroups.com
X-Gm-Gg: ASbGncvmrowpjgs4c/EfFUDu2f/q0XyQG3iZ6tUOmEQyEIQcDpo5VM3R26mG/wrYq74
	OK6wEtbM3C3ydhjspK0X/8tNB+5x7IVM9sWrqZypYXi42oyicBHmt2y9pttAxsDdMTa10n4ce+l
	a3p9txe6ijgIbs5o5XUBYvU7ui1ms6EiB9Dsjwhu1zOx6teVO2dtDnsYuexH34LnPmIF8/TqRGH
	tqhTNQO4/zAPAZfwz3/4+JZ3EzU5Ee3q3/VOK/67pBwV0Ts6WcI5dxXmLHAjU0jp04DVS4btSpd
	juWP0aE=
X-Received: by 2002:a05:7022:410:b0:11b:82b8:40ae with SMTP id
 a92af1059eb24-11df0c48844mr6019656c88.18.1764884339502; Thu, 04 Dec 2025
 13:38:59 -0800 (PST)
MIME-Version: 1.0
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
 <20251204141250.21114-10-ethan.w.s.graham@gmail.com> <CAHp75VfSkDvWVqi+W2iLJZhfe9+ZqSvTEN7Lh-JQbyKjPO6p_A@mail.gmail.com>
 <CANpmjNMQDs8egBfCMH_Nx7gdfxP+N40Lf6eD=-25afeTcbRS+Q@mail.gmail.com>
 <CAHp75VfsD5Yj1_JcXS5gxnN3XpLjuA7nKTZMmMHB_q-qD2E8SA@mail.gmail.com>
 <CANpmjNOKBw9qN4zwLzCsOkZUBegzU0eRTBmbt1z3WFvXOP+6ew@mail.gmail.com> <CAHp75Vd9VOH2zHFmoU5rrQCRqJSBG2UDCfKgvOR6hwavDVqHeQ@mail.gmail.com>
In-Reply-To: <CAHp75Vd9VOH2zHFmoU5rrQCRqJSBG2UDCfKgvOR6hwavDVqHeQ@mail.gmail.com>
From: Ethan Graham <ethan.w.s.graham@gmail.com>
Date: Thu, 4 Dec 2025 22:38:47 +0100
X-Gm-Features: AWmQ_bkrTLjU1bji3dq_q0_9aUL2KpYGKaTrBSm-1EAw-k6T0Q2iOVkzFyxbFXs
Message-ID: <CANgxf6woLz0VBnmFqrhwQiLwrQkb5oLb+1tHoOU5+aN=a21k8Q@mail.gmail.com>
Subject: Re: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Marco Elver <elver@google.com>, glider@google.com, andreyknvl@gmail.com, 
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
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LBlbixH5;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

On Thu, Dec 4, 2025 at 6:10=E2=80=AFPM Andy Shevchenko
<andy.shevchenko@gmail.com> wrote:
>
> On Thu, Dec 4, 2025 at 5:36=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> > On Thu, 4 Dec 2025 at 16:34, Andy Shevchenko <andy.shevchenko@gmail.com=
> wrote:
> > > On Thu, Dec 4, 2025 at 5:33=E2=80=AFPM Marco Elver <elver@google.com>=
 wrote:
> > > > On Thu, 4 Dec 2025 at 16:26, Andy Shevchenko <andy.shevchenko@gmail=
.com> wrote:
>
> [..]
>
> > > > > > Signed-off-by: Ethan Graham <ethangraham@google.com>
> > > > > > Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
> > > > >
> > > > > I believe one of two SoBs is enough.
> > > >
> > > > Per my interpretation of
> > > > https://docs.kernel.org/process/submitting-patches.html#developer-s=
-certificate-of-origin-1-1
> > > > it's required where the affiliation/identity of the author has
> > > > changed; it's as if another developer picked up the series and
> > > > continues improving it.
> > >
> > > Since the original address does not exist, the Originally-by: or free
> > > text in the commit message / cover letter should be enough.
> >
> > The original copyright still applies, and the SOB captures that.
>
> The problem is that you put a non-existing person there. Make sure
> emails are not bouncing and I will not object (however, I just saw
> Greg's reply).

Understood. I'll stick to the single SoB in the next version as Greg
suggested.

This address is permanent, so there won't be any bouncing issues.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANgxf6woLz0VBnmFqrhwQiLwrQkb5oLb%2B1tHoOU5%2BaN%3Da21k8Q%40mail.gmail.com.
