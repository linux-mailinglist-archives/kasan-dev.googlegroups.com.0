Return-Path: <kasan-dev+bncBDEKVJM7XAHRB6WBRO7QMGQEWQDSCWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 27F06A70782
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 17:59:41 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2ff798e8c90sf9193295a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 09:59:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742921979; cv=pass;
        d=google.com; s=arc-20240605;
        b=VskmQ2C2QbShK7K7fmTdsh54HKzYp6/ZNAVO7MJKi3KzLYeHxeA+cDIpqK+CHD9Hbp
         imWf94mwAsXTcS2eQYb9Ih6ggamPwvFxxsnM1VT4tJ60aVCLq5+CNGGwK+ZKIL/SPs85
         A40XnASWQ9ltp2pS9YgLOv50KPDFvd081Sv7DjmtB+IpCUsNV0PybcGTdGQmxWH8Qw2Y
         pLm1fikvpYeWj6Z7BaXP9T4eWN+INWl42D40bGMuZ9i/NtKMGD4e2DNGA2QcrWk0YOyN
         VKvFIivIuJ4LJFz2MTC33CbOGkACnP1OvQlrx5w2jMrn9XFpJbMslusxPWCIsiydP7SV
         6UsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:sender:dkim-signature;
        bh=OVkUzff3BU53q22W14IwcS0sO6hQ3IXwTBKwz51ZrRE=;
        fh=QeknSX+0yx79R/1pVN66qbpLLQ6KDaQVvF9znvysD/I=;
        b=NSroQd6oC0ypZbqy0T0+UGdh0KgOLn57pz1MVwmYRi6wvMEbX9XRaFY7BZQSVNmf0m
         Sv3i0pGZ14LQKt2T7npwDPBWiGCEZuh0MrxLmKwRpghfGW7LLBufKQOwQaERnhKmEYCx
         VOT97RJ12vAKMlqDeCH3fXo1n5VWIsmTLOaZtQ7oYWq02MB55NhE9EckbyMJTT2pZISm
         IXwOCx7E+KciHOQ6nF1PMkYtHHkkn2sFh8VMSttufryMi1q4cf6IOduHx4GB82GFExRu
         XBjQ+bQQpodmexUhtJ5GoEs3IM0FjM15iG30c27EtcgN42tq2shZa3kc/+aQuZawFJbo
         vE+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=cas0BCBQ;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=gvfwj1bg;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.145 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742921979; x=1743526779; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:subject:references
         :in-reply-to:message-id:cc:to:from:date:mime-version:feedback-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OVkUzff3BU53q22W14IwcS0sO6hQ3IXwTBKwz51ZrRE=;
        b=IRlngrvXJlcqVe+vm8lMRFYR+uCYOvMAtEUw3MVSS/28kCBl81PNkyv7aOwwKEihAm
         evCH8V0OLD7A7P6eKQSRuPEQaughUX7WzeQRcsFCFWDgSHxoPg6beeAvUq46cGd/OtO6
         NlJQCEru0WGAB3LBVkQ3AoewtdFf/17QaC4SdnzJkjqbjWfrM7E+zyI1Don/9639CCzq
         Z1oqxtpbAs4JDM5z3FGYHpnqx54iv3951Ir2c4jfjAaD9qEc3nAp/+TwYqEOrXh/+FIv
         o6CkIWGLPgiinIi67T5r1lsJntHpNBB3DqmEwWZN6NBm6er9vO9Ykytkj1xRhAYgDEMW
         fNQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742921979; x=1743526779;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OVkUzff3BU53q22W14IwcS0sO6hQ3IXwTBKwz51ZrRE=;
        b=NTifTBDSygAVNb6Ti0njTKINYgThBVyaZH2TrWOh7KMliQ43iDevl5URLlzFRUtzdg
         Yl2ymCxS5VwOxPNwcZKfFQJVXlM94j0O6gFGkpvH4TAwH7jWD8SrVUUxze3+22eGzdHL
         uQgzx2u2QHoysdaa3F6eqG+SzzlSwLOyiQU16WTLtrSBmbjnkpTqjgztBTKkmjcawstK
         WU3Vd4FzAXm5z/i61okuBh0kBx/gQ0iTc+TRmP25P1G66gwOEMxjQmfPR8XfVsuNaC8o
         ii7luYxLhG+oB2ygbCeEVYARsQ1smxgia/fHEuids297tN4Ry9HjAzmjZsTMAHyfi9uK
         xbGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUxy8ShsrpC4ER+iecaTaDV0VUu7GE0QpkXgutFtJHOT8yRrgPvEtIGmKUQIMybWkllAsctw==@lfdr.de
X-Gm-Message-State: AOJu0YzfVG4sCm9TRVWLN2EGffnW42dS7xZwkyHWTpKRlWAyHP1F+jLa
	lTsHXoyJTQZg2T1CtwS5MGeRsLow6WS/8WtFUak71iUvbyJCi/wp
X-Google-Smtp-Source: AGHT+IG0kz3XMtiCLR8ZPQrouCiFxX/UyowovRPU/o0OUwKbbT9YGD9BPox/nPZIFOXyf083Y/WlKg==
X-Received: by 2002:a17:90b:4a03:b0:2f9:d9fe:e72e with SMTP id 98e67ed59e1d1-3030feba6cdmr31876114a91.16.1742921978759;
        Tue, 25 Mar 2025 09:59:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI0ELqgpJotIRHD89/JP3yoawCHlG8YYDPHe1y6b46uVw==
Received: by 2002:a17:90a:d489:b0:2ff:4b14:3df0 with SMTP id
 98e67ed59e1d1-301d4589220ls3167689a91.0.-pod-prod-04-us; Tue, 25 Mar 2025
 09:59:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXHLdRVoX3I73f0Q6lW+T9Z/Sgp7qEpDpmL1QVl3LldVSBC6TC/XdQMUYuJOXAbmufwMeic1/GD8mM=@googlegroups.com
X-Received: by 2002:a17:90b:2dd2:b0:2f6:d266:f45e with SMTP id 98e67ed59e1d1-3030fe8d517mr31392814a91.2.1742921977341;
        Tue, 25 Mar 2025 09:59:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742921977; cv=none;
        d=google.com; s=arc-20240605;
        b=bQ7o4Je4x0Bffz3oq1cpnAeI518tvkVR5T6Fek0yBunj/8TfGxCtnPUwALYHQnUlHY
         OGqRCDUSOGFnEy7u34eJOzgsi8ITSEufevEfR8Hmh5TFvmeAZuSZXpr218ijlX6j/h9Z
         VCmp8M8QojZk7j427isJpDpXePkBddRI2U+fYsmdP/uY6O89IgQSjghBzvPKqUKt0BVd
         RltFxQl1tzObo3Jc6HERQnYP2H2iDcUlVnQ9Z+1PXfaVvh3GYpvpqiMCN0QZIDxigCmS
         1cBfzJRca20m5/RbicnNUtUmr4F/SF6OMJijamyh+kdxTu42j/X0QMgi6Iz65Fu6+wx5
         mf6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=1kZo2dIkUctXPOLQlyuKriYib5RXb/4Fue46r1qeads=;
        fh=ZWDw56At8xlpJwR9ZajrH3Dr5fIUYBKWH78y4io6eBU=;
        b=LF9Wxc0hWdtl7NyoP7ykvFpwg4Kr5U1PwoQTkbB478J7CjLGAGzYuVGQp89Kwyp6FP
         i34V+VMN4OHI3JUldak7IPNpyv6tYNQ8FA+wcLI0xsHtt8pvAcZOqcCgQN15Biiq47yj
         2Cy+GgrDx7vjoGUsUcwbKL4WZZaxMfP1HNNnNOtflKmE8ICiE8Rl2gv4cT+vIwjTHZ/G
         8qiZcWIAxXv1CPgg05KeYUehgEd+/u8+OKnaTXlxNxcZ3C+v+ZPq02LIijyJ9G7ogDCD
         rDE9i9/1PsJeCLYNzpoPE1qMR+rgM0NxtIGIhDwtPekE7qUDSF9fRIkgp5VPSa3LbVHU
         bNwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=cas0BCBQ;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=gvfwj1bg;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.145 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fout-b2-smtp.messagingengine.com (fout-b2-smtp.messagingengine.com. [202.12.124.145])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-301bf4773d4si554180a91.1.2025.03.25.09.59.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Mar 2025 09:59:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 202.12.124.145 as permitted sender) client-ip=202.12.124.145;
Received: from phl-compute-07.internal (phl-compute-07.phl.internal [10.202.2.47])
	by mailfout.stl.internal (Postfix) with ESMTP id 40FF111401BA;
	Tue, 25 Mar 2025 12:59:36 -0400 (EDT)
Received: from phl-imap-11 ([10.202.2.101])
  by phl-compute-07.internal (MEProxy); Tue, 25 Mar 2025 12:59:36 -0400
X-ME-Sender: <xms:9-DiZxg08AyG8NQJG_o8Xk3DBrrx3Pw16TSkR8-tc1XrxE30DhysZA>
    <xme:9-DiZ2DaKW-U94kxMtFazEIvd6UgUYctMBmcXRiaHOmJxIv-8_CaLVtXJ-wp5kQrA
    xC3cuEJw5bgdEEZktc>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefvddrtddtgdduieefudelucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggv
    pdfurfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpih
    gvnhhtshculddquddttddmnecujfgurhepofggfffhvfevkfgjfhfutgfgsehtqhertder
    tdejnecuhfhrohhmpedftehrnhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnug
    gsrdguvgeqnecuggftrfgrthhtvghrnhepvdfhvdekueduveffffetgfdvveefvdelhedv
    vdegjedvfeehtdeggeevheefleejnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrg
    hmpehmrghilhhfrhhomheprghrnhgusegrrhhnuggsrdguvgdpnhgspghrtghpthhtohep
    iedpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtohepughvhihukhhovhesghhoohhglh
    gvrdgtohhmpdhrtghpthhtohepvghlvhgvrhesghhoohhglhgvrdgtohhmpdhrtghpthht
    ohepjhgrnhhnhhesghhoohhglhgvrdgtohhmpdhrtghpthhtohepkhgrshgrnhdquggvvh
    esghhoohhglhgvghhrohhuphhsrdgtohhmpdhrtghpthhtoheplhhinhhugidqrghrtghh
    sehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoheplhhinhhugidqkhgvrhhnvg
    hlsehvghgvrhdrkhgvrhhnvghlrdhorhhg
X-ME-Proxy: <xmx:9-DiZxGT5HYiuXiurSrrYEElDS_5tE8daS5nTZe49bbPi4HvVLsePQ>
    <xmx:9-DiZ2RQA5Lw5HAPc-QXlWJC5cLJfg920U1ceCsi5scu-fqOlefSRQ>
    <xmx:9-DiZ-zWFjamXMMJ6ZN1uRs0CufpBX1dXFiiibdgfHzQl7Oiu7PjXw>
    <xmx:9-DiZ84mSNf77RxbnO4xkODeSzNv2MOseFCKbeGE3YwKfWoZCFT71g>
    <xmx:-ODiZ1oUaxOfKSLrcy47mz1kvH3WB-AvHtxfzNnliw2F8e4BWFi7cM5o>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id C90822220072; Tue, 25 Mar 2025 12:59:35 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: T022a60d36d02d9f7
Date: Tue, 25 Mar 2025 17:59:14 +0100
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Jann Horn" <jannh@google.com>, "Marco Elver" <elver@google.com>
Cc: "Dmitry Vyukov" <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Linux-Arch <linux-arch@vger.kernel.org>, linux-kernel@vger.kernel.org
Message-Id: <fbd8d426-e45f-4f2e-b201-20b8396b20f9@app.fastmail.com>
In-Reply-To: <CAG48ez2eECk+iU759BhPLrDJrGcBPT2dkAZg_O_c1fdD+HsifQ@mail.gmail.com>
References: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
 <26df580c-b2cc-4bb0-b15b-4e9b74897ff0@app.fastmail.com>
 <CANpmjNMGr8-r_uPRMhwBGX42hbV+pavL7n1+zyBK167ZT7=nmA@mail.gmail.com>
 <CAG48ez2eECk+iU759BhPLrDJrGcBPT2dkAZg_O_c1fdD+HsifQ@mail.gmail.com>
Subject: Re: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm1 header.b=cas0BCBQ;       dkim=pass
 header.i=@messagingengine.com header.s=fm2 header.b=gvfwj1bg;       spf=pass
 (google.com: domain of arnd@arndb.de designates 202.12.124.145 as permitted
 sender) smtp.mailfrom=arnd@arndb.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=arndb.de
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

On Tue, Mar 25, 2025, at 17:36, Jann Horn wrote:
> On Tue, Mar 25, 2025 at 5:31=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
>> On Tue, 25 Mar 2025 at 17:06, Arnd Bergmann <arnd@arndb.de> wrote:
>> > On Tue, Mar 25, 2025, at 17:01, Jann Horn wrote:
>> > > Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infras=
tructure")
>> > > Signed-off-by: Jann Horn <jannh@google.com>
> [...]
>> I have nothing pending yet. Unless you're very certain there'll be
>> more KCSAN patches,
>
> No, I don't know yet whether I'll have more KCSAN patches for 6.15.
>
>> I'd suggest that Arnd can take it. I'm fine with
>> KCSAN-related patches that aren't strongly dependent on each other
>> outside kernel/kcsan to go through whichever tree is closest.
>
> Sounds good to me.

Applied, should be able send the PR tomorrow with the rest of
my asm-generic changes.

     Arnd

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
bd8d426-e45f-4f2e-b201-20b8396b20f9%40app.fastmail.com.
