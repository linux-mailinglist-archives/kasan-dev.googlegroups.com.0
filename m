Return-Path: <kasan-dev+bncBDEKVJM7XAHRBBNBW22AMGQEF25RECY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id B629292C3EF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jul 2024 21:33:27 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-70b2793d2ffsf3121391b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jul 2024 12:33:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1720553606; cv=pass;
        d=google.com; s=arc-20160816;
        b=I/XBISaXdvbzE4gB6kVGLI66k9/cuKoFrGHG7O8+LzKeKBIHNwAUjm6RXzXbn8ZWpq
         i5Bew12ViIhRr02Zke/GpldeUP16a6/B+99Z/pDQiyCG9V6kmANHAjfwZ2F7smQPUog2
         E4EYmE2sUEY1mYx9RExl0KiuVLNwC9TW5MMjf6NEsbtikadd8rL3Co284QypVHoHz2Pm
         59OoLvFwhdwaK1exKdZDudsP4JPRkbImJfz89D541p7oOszluYGVGeEDDefnuE31RFA1
         saVVWHD0XRkSB1NPuurEBzb1JHNDKR79M08FWME+bnOBYqa4BBTAU+VvUQYwbFi6MXMO
         RAsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=XqA5JugL11WV/tIYc4kB/8tfi9Qc2j+9TsYiwBC4FIM=;
        fh=RzXr9tbGfYdVmtEycUcMO6O1RYykMzxaTH933c2eRh4=;
        b=zAHDkg6xWFh7DXWJr6YKGqKf157EAJ6fzWwa5CEzUUe7ZLMhzse1WzU9PaJn/VUt6K
         ZGQYrVA4dHPm0Lx6OvjsUxF525Bhh1CSzEoUIiuGpeZ+jAsZd1lb6BfXNEgrf1yzdHiT
         Ee3N6BUNX5lqHmJNwjKlj7EpD1/EjpXbKJOXKeUsMg6BzHf2ZeloOkRnjNKHcH3fRcI2
         MN40iit0ulOg3vtDJe2fxw+O2KB+PfstrYWG0aTqjW1guM9XMA5Y1IQT7FQg/RhBo3SR
         mtJGAD6uNyNrLNvebkzp7PEPnq59hnmYCIKedKgsV0rERs8tC8UXjWszugK/FT6cku1E
         2IkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=nch44eC1;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=BPwP3bQn;
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.159 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1720553606; x=1721158406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XqA5JugL11WV/tIYc4kB/8tfi9Qc2j+9TsYiwBC4FIM=;
        b=lIN8BaK9Tm13GntA8m7wnbBFIdx03WxwNWSEiyP1apvvt4VmICTBP58SB4Yhf+rCyz
         xbKG6cDzwtL1aYWH0a2G81nFU/knFMtQJXwmGx3zJ8aCPIBUJGEPXgvJoDRvzBybb7WQ
         jEaEkSX98HoFQ9mYWLF1w5dCQQ2XmGrcXyFUc/zIw3bB1Z0AOZK6rECQPnSfw4K4v5Y9
         6TfyJD3ExtbiMD8YE+yAw3yGH7DbhGbvBxAZe6c0Cx4ckUBNxNku2x7GjpC5rZOq9wJU
         3kAFrfeNhCmDjcCCK/BrUW+/powaDFT19PWmR+a9zcRNVCurOH2vX5i7VY/SwAtl+QLW
         ZbOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1720553606; x=1721158406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XqA5JugL11WV/tIYc4kB/8tfi9Qc2j+9TsYiwBC4FIM=;
        b=AXajZrIfzxnDZAJXo78ceTBVZf0qoWm5/AEIHNhGOAI9pevnJb0V+G65ETKVYkmOyQ
         9sxzsgdld1t7nSiB7yqEs060PgR6ZDMQhx67Dr8s2mvaptdKOmwlYKxf3OBb2ni9xs1p
         EpwDyHizrEGqJDklXV/S4jGs9iwLqH0S4cc2Rk0SVUv1tl64nDYMHl62G7bwJ/FUyChA
         S73lTr48nP2k8JsKFqwXYCAMUvmrx1Zvtvx7L49+WGz634RjtSKdzH74RFp5r0S4GqPi
         AlFvJDb9WwSlQIIZP1e3TOpfqCdC75lsqAauSWsYaIs3hdO2zKusbCxVu64z3NbY+Qgr
         zkTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXC7uVvpkSnbP3mbejqZs3K01Fp0yV0uAIefAGV5FIzkSAGPuUHc0l8nVvJoHzMFV2U1JkPJWFj/X0J9/EjvdU7iRWqjQccow==
X-Gm-Message-State: AOJu0YyZYFFonGdyvJ/iyIy5j5jzrAaQp18KWgdLPdlAfUb9kzVKAdh9
	UUA1ETuB4kKHo2H7/mLx9i3zKAHgYVZh5oH8yOpWiOVGG6j4DOJ5
X-Google-Smtp-Source: AGHT+IEbH3oHe3rMrJtYEVS8FGYat2M2A3JdG9ZS09Fv75gP7n+M3FXwRIyyvUx0DImlG9reZhBviA==
X-Received: by 2002:a05:6a00:845:b0:705:a7a6:6d11 with SMTP id d2e1a72fcca58-70b435ed145mr4008044b3a.24.1720553605719;
        Tue, 09 Jul 2024 12:33:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d8a:b0:705:b591:29f0 with SMTP id
 d2e1a72fcca58-70afefb1cdals3043281b3a.1.-pod-prod-06-us; Tue, 09 Jul 2024
 12:33:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUruNyZy5GA49kythO5WKcFc7uuMDGp7WhyAuHxQPDXqR9f2oczATaRQs0v05LG6uPVCcsS772rrmaEENAR6fLwAMoh8yct/xwsNw==
X-Received: by 2002:a05:6a21:7884:b0:1c0:f23b:d35a with SMTP id adf61e73a8af0-1c2980f9412mr3856677637.5.1720553604574;
        Tue, 09 Jul 2024 12:33:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1720553604; cv=none;
        d=google.com; s=arc-20160816;
        b=rqsEMNJQ+sSBr59P49NjH8CoWL2b5KEvO9VPK4Axa0vg42q0TK7Zho7IRwlAWr7hxx
         rOfXDJDJig1ZZYR3iPQZiFDYUcvTlwKJgMl3JShr8wszmXDdNE1C0SSUHADo9EgQRxyP
         9L3FiEeupN9rPr0UuBIdG2QuRuxyR4Tm7g98BkBkDzMuhjRllo/sDKNvWEdaU3RYHCii
         +xL0deZt69bXlso/6dCSKi+JtkcRekDedqkZrIf25/3SPUAGnOxYPRmwn62fHhEzuuTM
         K6huN2LbLWZu1i0JtHUYqLeyiEhSntnVYFhZ3SQVmGbgr1rH4VPLUMBGMEHEW/dLAwxc
         BVLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=AE0fFzRZO99KbEKs+v9clAHq1pXfvPK0Ierrsu1abhs=;
        fh=5jlKxLVBIxtu567gyNSTp/QL6lJdLU+pOvFv7YezgJ8=;
        b=wkljdQ+MPBwmJZUCOUIUG70K5WlUVlQJyrIE4qc1R+4n0tJ+G/7BSmMZfVYllLzAHU
         CMyJaUj9C1MZ8iKwn2Z3T46hx8Lqvk7cyxJrxQUiItm6oC97OUG9Mnh0tFWeGAelclpD
         F8eD9i9ltcID+nb5Ut84q5VkkYuxqBAr4iF3UbmnXR8lndm1TGH6/xNnae/QX3xTk07m
         pjfUmiioV5ogzW6EetIxgKiLS6GqXB2s7zu7lewITYuOG3Oiq6zJahrgFkoGp6cqt4GZ
         Fe5hkTIAcGqE+Nopz9yK1xrjGpCLJ5zl7UV6gFoH5Rhk4kvRkt86SMpz4cLvWpzfpeJA
         ZhEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=nch44eC1;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=BPwP3bQn;
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.159 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fhigh8-smtp.messagingengine.com (fhigh8-smtp.messagingengine.com. [103.168.172.159])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fbb6ac0135si897035ad.10.2024.07.09.12.33.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jul 2024 12:33:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 103.168.172.159 as permitted sender) client-ip=103.168.172.159;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailfhigh.nyi.internal (Postfix) with ESMTP id BA6ED1140138;
	Tue,  9 Jul 2024 15:33:23 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute5.internal (MEProxy); Tue, 09 Jul 2024 15:33:23 -0400
X-ME-Sender: <xms:gpCNZoCXVKxZYgd-tL_p2k9_uAle5NRuWFn4b8oB91ZexvboAwvAow>
    <xme:gpCNZqidF1K-9jUuTpzLvnQflD26Kb9sEmupPhPbyGA9GSp03Apa1q1viLXpquDUZ
    AokqUCeyiJz8LMOVVg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrvdelgddufeelucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedftehr
    nhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrth
    htvghrnhepffehueegteeihfegtefhjefgtdeugfegjeelheejueethfefgeeghfektdek
    teffnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomheprg
    hrnhgusegrrhhnuggsrdguvg
X-ME-Proxy: <xmx:gpCNZrlo8ynwoKGV2tVyoVZMt7SWJuifyw3wICL6bMUVIvZwXZo-jA>
    <xmx:gpCNZuw4KcrMuigBpuH5fvIFjqsotTvmBsQtqM4r_KdKiRkHuKaHIQ>
    <xmx:gpCNZtQIhXrJAMWS_snE1w-VQFd1vK5gHYOcGo9BFyaUAxzSgEFSjQ>
    <xmx:gpCNZpbW6SzaKP6FffvTqJOfe6Ku42gxdzjTMmwUfEj0O7Ox92ndQQ>
    <xmx:g5CNZq9s7g6T8sbAgzbFYlPgW05GWwkwxKheEFU6xYuovRAa8A8CY_up>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 2F097B6008D; Tue,  9 Jul 2024 15:33:22 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.11.0-alpha0-568-g843fbadbe-fm-20240701.003-g843fbadb
MIME-Version: 1.0
Message-Id: <5bfebbd4-d12e-4735-acab-549a7cf9604a@app.fastmail.com>
In-Reply-To: <0e0150ca-fdfa-40cb-ad7f-6ac695b702e4@quicinc.com>
References: <87y16bbvgb.fsf@kernel.org>
 <917565ee-732a-4df0-a717-a71fbb34fd79@quicinc.com>
 <837cd2e4-d231-411a-8af4-64b950c4066a@quicinc.com>
 <c9b23ee3-6790-404d-80a3-4ca196327546@app.fastmail.com>
 <0e0150ca-fdfa-40cb-ad7f-6ac695b702e4@quicinc.com>
Date: Tue, 09 Jul 2024 21:33:01 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Jeff Johnson" <quic_jjohnson@quicinc.com>,
 "Kalle Valo" <kvalo@kernel.org>
Cc: linux-kernel@vger.kernel.org, ath12k@lists.infradead.org,
 kasan-dev@googlegroups.com, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>
Subject: Re: crosstool: x86 kernel compiled with GCC 14.1 fails to boot
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm1 header.b=nch44eC1;       dkim=pass
 header.i=@messagingengine.com header.s=fm2 header.b=BPwP3bQn;       spf=pass
 (google.com: domain of arnd@arndb.de designates 103.168.172.159 as permitted
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

On Tue, Jul 9, 2024, at 17:29, Jeff Johnson wrote:
> On 7/8/2024 10:44 PM, Arnd Bergmann wrote:
>> On Tue, Jul 9, 2024, at 05:55, Jeff Johnson wrote:
>
> I picked my favorite to begin with, enabling KASAN (which in turn enabled a
> few others). The resulting kernel did not boot for me (just saw a black screen
> after the GRUB menu). Diff between working and non-working config is below.

Ok, good to know. I've added the KASAN developers to Cc now, maybe
they have already seen reports of x86 kernels failing with gcc-14?

> I then downloaded and built the config you supplied. With that I have the same
> behavior as my original config, the display is frozen with:
> Loading initial ramdisk ...

Interesting, so the same config that works for me fails on your
machine. I can see three possible reasons for this:

- qemu vs hardware -- Can you try running this kernel in
  qemu-system-x86_64 to see if that still boots

- kernel version -- it's possible that this is a known bug
  that was already fixed in the 6.10-rc7 kernel source I
  tried, or that your source tree has a new bug that I don't.
  Which version did you try?

- cross-compile vs native compile -- It's possible that my
  cross-built native x86_64 compiler has a bug that is not
  in natively built gcc binaries, or in the cross compiler
  I have on ARM. I've mostly ruled this one out by building
  the same kernel using the x86 compilers through qemu-user.

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5bfebbd4-d12e-4735-acab-549a7cf9604a%40app.fastmail.com.
