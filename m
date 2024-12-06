Return-Path: <kasan-dev+bncBDEKVJM7XAHRB7HEZK5AMGQEHMFRXVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 75CC29E689D
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Dec 2024 09:14:54 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-725164ccd4dsf1563131b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Dec 2024 00:14:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733472893; cv=pass;
        d=google.com; s=arc-20240605;
        b=LEam2+7BK0oIei2ADERt3odiCsj20BrHdf/LGBTwYfRkpk3gGKJ9GJx2zXpvuCkQ2A
         UNg3sAI2T7gr2sSQpZTUQIqmd/zaYzulo0kXesu29DiFPUn8SOp0uuPs/C6yqhWKHPfw
         x1hnovHwost737YsFSUM4G1rZsP7hvHIeULrx6DelF+Vb1dIJFZR0xNPwa0QqnD7ZedR
         hnd+Z8t5kHHFXhg3wCM7AtOG4vO7mOGUAVmrri21oB3bQhNfqawia80A+JJa5mfn0iSE
         Wj2LnkTCcDB2r29cMrv0g4ASjlvaiLDgaAaacAgg2DrRi2ol3f8ZQ5i8PeT3R8v00V9k
         y6lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:references:in-reply-to
         :message-id:cc:to:from:date:mime-version:feedback-id:sender
         :dkim-signature;
        bh=cuSFzCCmIrNhkDNu1NsgXo9obqiSo2yXywhzx6dUFSI=;
        fh=Qpb7iBB6RoTJB8wEIgvQl5xDMZk3EvRQwSCxS3YdpUg=;
        b=ZfQzJhY/Bfm9Cd3ppOTewr6d+Vwcgm8sOgozu768M9AwJYc0Htcw/7IZufrKthABpd
         72CB1PNweTmFCWZg2OVSDO5KYFe6Kvc6gcXOVhAbLokuRWndzM2HLaoIOKqcWpkh8lld
         0solcu9f6emQbwK7+S4aNqCFUtRkcAIlktLAm+19DNBeT3aHkOsn3Qx/3jPOSGK0UqPb
         tL9AerqwFyLLWCEgDOZRz+KejJ9hEkgiwfL5V/jvESdu4A9KLkqDZh0lrwWKgePhr6tf
         yRN0U6IcMAcIlAo0Eo765lQoZhQiWqMNdd3/7n1VFfKZFcLCkTl5gK14gJS0WSH/gOs4
         Lo/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=pXckWW2s;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=sHeGb7qE;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733472892; x=1734077692; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:references:in-reply-to:message-id:cc:to
         :from:date:mime-version:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cuSFzCCmIrNhkDNu1NsgXo9obqiSo2yXywhzx6dUFSI=;
        b=YqSeM288Cacm8pDaQ3FzTo8jTPYZxRAvBBofPQR5x90/XKAwWB1tjQ5dGDSmmZf3LW
         RF5D0+dkchhTO7ETqHyYfz9pb9MqQEjE7nBGsMS3+k5EDCCO2a5cJRJ12NcOcyOmShPF
         sR57lQKPVWHd1Z0GVGwIyS1IiWpTrGr1WtLomP7NHyS1m30J7kZwUrROeq+7NhqDd8vQ
         Fec1etaoTSUADSyCr6A5m51Jw9zvgHgPp5mg6dlU3VOnJPllo797O2fn4VqR3TKuTP6F
         6ucHC0upR49/mGR+WFjrILcGVrG6uGkdpJBOz0mjWYAH6KvXyuvQpZrBu87vxIntXuaz
         Qp3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733472893; x=1734077693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cuSFzCCmIrNhkDNu1NsgXo9obqiSo2yXywhzx6dUFSI=;
        b=DS9iBJ2RMD1TeTUNAkpwNZGHfPDNDU1v34uTkfRXqhhxsfCG11VOyAN2r/qNfKMEqi
         MsIvJySRX1dYiHnwEkJZK8TVf15G5tbIiU9fQHKt0hR+VH60gi/EeCruNOaD3C54AGl6
         UZvCvN93Vp8STvtNxhwHfX0wmcMjOaoURJUqN2w5jlwXrv/MHQC2g6fSAhbi5rrtWulm
         /Sxlex6qoOxsXfIGwW/d22/a2C627aaGtEHFqSDCAJDcXQCqO5EDokrvywjcr8nwFEYF
         6W8fVNXHEZCn+mFZdTE3fh1ODXFAK1umzHvy35zsJNU8obTv2vUDjzZTo4Hpu93tNUUB
         /upA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvD+2owssawEy2TodxyEm0U8+Y96slQpHxtP6itKymxeAhYN5JsgAp/MCXgJ25YmnLghlLLw==@lfdr.de
X-Gm-Message-State: AOJu0YzVPt9KJlBewSc/rv8Hl8YvRtoY+25QxH8iJSdouSW+xohcUgnO
	t0FHLLlmhfSP9Eu8ZnnfmM73GCFD7jUsKBBrlk69jqBWBMXnmkym
X-Google-Smtp-Source: AGHT+IGkZyWbqtCLVOrB/DZqcuc7XrwkFKNdkMR41c5IzipcXpXJiuUveAaE2jt3683xUi2xuWu1oQ==
X-Received: by 2002:a05:6a00:4613:b0:725:8c02:8dbc with SMTP id d2e1a72fcca58-725b81b5cf5mr4141341b3a.22.1733472892468;
        Fri, 06 Dec 2024 00:14:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4f0e:b0:725:3fb9:271b with SMTP id
 d2e1a72fcca58-7259d7a1c22ls1786293b3a.2.-pod-prod-01-us; Fri, 06 Dec 2024
 00:14:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXwvaUS49pygxn1plqh1KvftSJcJLSc6cM85o2qc8xoWyH7M27V500VVZgcX0homM4fqiacA3YlFHs=@googlegroups.com
X-Received: by 2002:a05:6a00:218e:b0:725:9cb4:da8 with SMTP id d2e1a72fcca58-725b80e4a49mr4205861b3a.2.1733472891132;
        Fri, 06 Dec 2024 00:14:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733472891; cv=none;
        d=google.com; s=arc-20240605;
        b=ZLYLL8f1g4Du0ch4AXlF/nZj3Gp32wkRp5BXhCkVGRq7qIZiqy5JtKaFHa/kA1ABz+
         6bt1j4vQJEiyCtGw/nbmvO9yaFJuq3UqyqKQnyqwtYXjTRUH6eLZyKkb7HaclVnk760w
         Ort2uotd4GZdsBnB+o4aNbjT86YuMztHg5c6PhJ4plvkoLGvOiNjghGypG74aODuUB4T
         IcPi+htumJ+6+PbMTdVCwGyzLW9yvv2di2jsOjeJ8wQKOn1d/Xr4cJEbCEfbRVkeofkZ
         StLX7vHiC6XitiPth7Q4Lww/hXZjoaso0DrPivNmm4skrW3C00usenvG6PnF+JhqE2ke
         8MQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=+CiivsHw0GsDv+l7OLvRGatcFJi5S1S1fcW7OKv42mQ=;
        fh=DNhQX6JmRjnRE8p9hBKYgYKh1OpmRN8hpc9QQHjqG6g=;
        b=SeMeiPvQ0GrdCxrFTBiW6FDfbUwEqvsNtnsq3JlZRrSgIx+CAyL3/YkyM2I8Q0Q1jP
         UW3F9an8B1j+xsST1hgLZpC5gOjEEYeZbtJmyvqMElo7b2sLvBGoF3oMrfRZhjsf4PKY
         Z66Vl2XMmR0eXn8cZLuDFI3YIXSxNiQyQdZsNBEhFd/XX79FCiQEAzjvnTh02CNQq1O5
         6oWBs6Z0GiLy12G84QKXJBuNmGaK2bwkhOniCtno9OJlRmlK2uhmhD2A+IQZ7gRsSPg0
         tp/pg5lVHuc9dhpCdljwQ5Z6myl0JW6YJdYMlOIAxAEOlptPWlgwnXjdlBFWLfGJMjF7
         aLrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=pXckWW2s;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=sHeGb7qE;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fhigh-b6-smtp.messagingengine.com (fhigh-b6-smtp.messagingengine.com. [202.12.124.157])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-725a2da4c23si138591b3a.5.2024.12.06.00.14.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Dec 2024 00:14:51 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted sender) client-ip=202.12.124.157;
Received: from phl-compute-10.internal (phl-compute-10.phl.internal [10.202.2.50])
	by mailfhigh.stl.internal (Postfix) with ESMTP id 8B62125401A4;
	Fri,  6 Dec 2024 03:14:49 -0500 (EST)
Received: from phl-imap-11 ([10.202.2.101])
  by phl-compute-10.internal (MEProxy); Fri, 06 Dec 2024 03:14:49 -0500
X-ME-Sender: <xms:eLJSZ8oEBU9sosKyjwR7pKq3xbj7uonUkEZezol8JTAejBhi3JYvxA>
    <xme:eLJSZyqingUbGotVfmXEmfiTf0cIt2SkcloadGaZLNtPdixxbrlQz3qGiEuHE47el
    tZqIcS7Fc19RAwybKY>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefuddrieekgdduudehucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggvpdfu
    rfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnh
    htshculddquddttddmnecujfgurhepofggfffhvfevkfgjfhfutgfgsehtjeertdertddt
    necuhfhrohhmpedftehrnhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrd
    guvgeqnecuggftrfgrthhtvghrnhephfdthfdvtdefhedukeetgefggffhjeeggeetfefg
    gfevudegudevledvkefhvdeinecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpe
    hmrghilhhfrhhomheprghrnhgusegrrhhnuggsrdguvgdpnhgspghrtghpthhtohepudeh
    pdhmohguvgepshhmthhpohhuthdprhgtphhtthhopehrohgsihhnrdhmuhhrphhhhiesrg
    hrmhdrtghomhdprhgtphhtthhopehvihhntggvnhiiohdrfhhrrghstghinhhosegrrhhm
    rdgtohhmpdhrtghpthhtohepkhgvvghstghoohhksegthhhrohhmihhumhdrohhrghdprh
    gtphhtthhopegrnhgurhgvhihknhhvlhesghhmrghilhdrtghomhdprhgtphhtthhopehr
    higrsghinhhinhdrrgdrrgesghhmrghilhdrtghomhdprhgtphhtthhopeguvhihuhhkoh
    hvsehgohhoghhlvgdrtghomhdprhgtphhtthhopegvlhhvvghrsehgohhoghhlvgdrtgho
    mhdprhgtphhtthhopehglhhiuggvrhesghhoohhglhgvrdgtohhmpdhrtghpthhtohepkh
    grshgrnhdquggvvhesghhoohhglhgvghhrohhuphhsrdgtohhm
X-ME-Proxy: <xmx:eLJSZxMgVcxqz0Gs_wLqlipfmPu89jkBAV5-3b9JsHLX5Z7oX9D3-A>
    <xmx:eLJSZz4md8s0pf6otWcUcQ3Zjjbvm1JqurlGVtsbXCpinoCsQ39Ofw>
    <xmx:eLJSZ77Agu_PYpt_x9IpyvpJJ2urUw7oP-amPVz50j94u1lNRlWHfA>
    <xmx:eLJSZzhh5WctICoMy7-ZNMxQwOGMpmgZIrJmWIDaLwzhe3IG1BoeWw>
    <xmx:ebJSZ6R-G1r3_buE5ycNdcbYxfZcFyDuAOEJFck1nIxbxD4kvV9nr-st>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 12DBB2220072; Fri,  6 Dec 2024 03:14:47 -0500 (EST)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
Date: Fri, 06 Dec 2024 09:14:27 +0100
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Ahmad Fatoum" <a.fatoum@pengutronix.de>, kasan-dev@googlegroups.com,
 iommu@lists.linux.dev
Cc: "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Christoph Hellwig" <hch@lst.de>,
 "Marek Szyprowski" <m.szyprowski@samsung.com>,
 "Robin Murphy" <robin.murphy@arm.com>,
 "Paul E. McKenney" <paulmck@kernel.org>, "Marco Elver" <elver@google.com>,
 "Kees Cook" <keescook@chromium.org>,
 "Pengutronix Kernel Team" <kernel@pengutronix.de>
Message-Id: <360e2ec9-556e-4507-a539-f86f7619fe29@app.fastmail.com>
In-Reply-To: <72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de>
References: <72ad8ca7-5280-457e-9769-b8a645966105@pengutronix.de>
Subject: Re: Using KASAN to catch streaming DMA API violations
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b=pXckWW2s;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=sHeGb7qE;       spf=pass
 (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted
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

On Thu, Dec 5, 2024, at 15:54, Ahmad Fatoum wrote:

> That way accessing a device mapped buffer before sync'ing it to the CPU is
> detected like KASAN would detect a use-after-free.  When the ownership is moved
> back to the CPU, the memory is unpoisoned and such an access would be allowed
> again.

Right. I would go even further and say that transferring ownership
to the device poisons an area that is aligned to ARCH_DMA_MINALIGN,
making it possibly bigger on both ends of the area. Transferring
ownership back to the CPU only unpoisons the exact area that was
specified, leaving the unaligned bytes around it as uninitialized.

That may need to be controlled by an additional Kconfig option on
top of poisoning the data initially.

ARCH_DMA_MINALIGN is between 4 and 128 bytes depending on the
architecture.

> The aforementioned barebox functionality goes a step further and also used
> the shadow memory information to detect repeated syncs without an ownership
> change. While this is not a bug, my impression is that this is unnecessary
> overhead and a diagnostic could help correct a developer's misunderstanding
> of the API.

Agreed, there is clearly something wrong if a driver does it, but
I can see them still work correctly without any risk of data corruption,
so it's a different class of bug.

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/360e2ec9-556e-4507-a539-f86f7619fe29%40app.fastmail.com.
