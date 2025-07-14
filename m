Return-Path: <kasan-dev+bncBCMJDXP7R4IBBYWF2XBQMGQEFSFJU4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E2CD4B04838
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 22:04:51 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-61383e65723sf3632505eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 13:04:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752523490; cv=pass;
        d=google.com; s=arc-20240605;
        b=fPgYKubSL0eX6KHsWfJCcs6zRFkwRnH2Os5+OMsZ2h/m508TcPp7DF3njQGfvvh9tj
         pqkqQdWF4lpWCyeZpCBGj3sxw9eJWOhYIXjT0J0akoTKkFRIw0pMY0TuOWM55m9hXiji
         Q6MnkBJ5PzYDvuXpiUBZCFP0f08+04edN9ymOAyMRYjUgPiaJhZixv90U8kbB67A0/3t
         FWzyw8WOzpuYZSFEFCPe3iEM1ZgpfFCRcE8ITrv535LyMf3Tbl3WI9daziRygVVl1eg1
         YMYersx9aZTiq9LCiPzwPAzoYgTtUOKq72oUa8weVPcDFEnriHG9jkJCFOqj2k5WsvOi
         HAMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=SusmOgDHBeQTb4KkbdQLcdtfo5fcjDfuCL3x6nfW64E=;
        fh=b/uclatuqFeT6wsIkY6q3P2p1VIgowI3AQIsidEXPBI=;
        b=Oi9V8mGi1xhyfNv3nkF2TVW1AApb1UYsyg1WEMH7tEcwhv0fzlZG6F/xkhV1Mlkc3B
         mLZ5f3jBKRtZGmyurRPG5agfPBmW33wiKfifH0JcbTTecdh+IHLoh/RH7sFSIHvQbs8U
         qO4vdsM8McPkWs9CrRIOHUgZX8+FVTH6jnNHJyIyb3AoprOrp18zzSv13tE5VpXx9W5d
         1xLaL6gSASLO05HomXhbxm85+yHs3+4e6X1OWnTLAtPPXiyvNcF/40pqK5ickX4asstT
         CCJmIGXKobpRAiJ5a2tJoF9COkFtYsHCu2YHG2dasmMf8ZVJ54u1PrirBQ6BQn17cGoC
         K37Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a4U4Xl96;
       spf=pass (google.com: domain of ojeda@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=ojeda@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752523490; x=1753128290; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SusmOgDHBeQTb4KkbdQLcdtfo5fcjDfuCL3x6nfW64E=;
        b=KgQD3xd1fFQnuyzJxPnpFnGi4/zXqGHlPYQzMMftYqhMEOv5HgWodec60Nj0ZhMI0+
         lXzv/EXXNzRk8nfhux9/dx0AahvIukSvHrheBraaDoPNC+hLrwjQYsEyWlj0Zf2SyKfj
         dEofz6t9lf8zfbfy1ua4tqlCLDSTufO1Ov31iUpnUkAz2rM6UXzpJUNwqfbkY8U6k+OS
         g5/Wgd2+AmavQkMmH+upNFgaoQlWXR7n/jgFG8dZsHlS66E7dZQNBfXOesPgN+zdHPEu
         g5LV9a57A+AhgKV9o2aw4r4w+KAQNl+OmOvu8JLSqQXgBCsaK6/OAIkiEGy9uZNPo8iz
         +BDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752523490; x=1753128290;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SusmOgDHBeQTb4KkbdQLcdtfo5fcjDfuCL3x6nfW64E=;
        b=EKep0uzkkK5c+EPYciBbqEZl3uxTQx3CDKkXAuGjI7wKcS2QePNpP+sHFODdXUDXnr
         9tLDucfqC6vnZo7AluX1N3Mt389aDDtcNaXeUu7nrptnAxrlXAjQCzNdlJCG1eBmPdLC
         wcIAQz8+Aznk4hE6JJnBlfQexY0SNR/alhgQ7l+aYveIWhjAIp1x1MN28XpqCzllJwWu
         e6MtqsQCSMbpOwYQSyeBPe2cAIMD+ykLG1snMDs8sKKE8nyga944MMHV8N0l6Dc53w9d
         rsDbxSPthHyHE9KFpq1RUjuQQ6dzVs/8FNV4MiIoDofC7wKXm0A/tWST1P/tmv99bovU
         zOuA==
X-Forwarded-Encrypted: i=2; AJvYcCX274WFHMHZH0mtaG6Gsm2tBdrXJ51QFxvxWB11mMqm4M5EVYKcTYyOQm4WvXLhWY/SAGmrCw==@lfdr.de
X-Gm-Message-State: AOJu0YziYG2EtGRUB14PaUhYpbqQGu3yNlzdANwasbxzdC2xBG2P6DVJ
	IkZh0RyQhtmuwtbO2GgtHpdBAP4jqoscAO+GqvlRaHRsJbzcqz2JPNJa
X-Google-Smtp-Source: AGHT+IG0TlFJM2PjWPoGvxEHNSWuyF28a70dHaP218+nscRWusGu/8AhigTR/paY5A6G/hNYMsGb6A==
X-Received: by 2002:a05:6820:4b15:b0:613:e361:a954 with SMTP id 006d021491bc7-613e5d36ccbmr9644130eaf.0.1752523490519;
        Mon, 14 Jul 2025 13:04:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeNxTjUNrgYbNyu0UMuSUUp4R+Rsw+K564JMGMcnSl5Aw==
Received: by 2002:a05:6820:4df7:b0:611:7896:558b with SMTP id
 006d021491bc7-613d7ab8387ls2365654eaf.0.-pod-prod-08-us; Mon, 14 Jul 2025
 13:04:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXz5z5Q90qM4SqDr6ghBHMHfVz3mVY1sxloO5xqMEhfsILRAV0ShCBIfuFZUG8rOGA7ru/4D80pkPs=@googlegroups.com
X-Received: by 2002:a05:6808:3998:b0:40c:fcbd:61a4 with SMTP id 5614622812f47-41537277e36mr9637862b6e.2.1752523489754;
        Mon, 14 Jul 2025 13:04:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752523489; cv=none;
        d=google.com; s=arc-20240605;
        b=SXjdj15F9PrLW8UQ/K+147PugQkqik2c6GWYQPufDesP/gmjxtEDxHx8Cm7MmuhETf
         s0J8cZQjoGgPQ15ipl2+iWYslrkNpK2+qFdHpONUYh3wVhgHz8nQta8v0VUGqNQL/Hoi
         ni5icQssK4ffqVqSVI03UvZONh91v5WRuSG8eUZJElZdVzBt4s4Qabmu6AIQ23c/6RsS
         AsIcbXYnkDqNAxKmIpyLtoLy2WtleqPbgasBUJItkaxHbEIFehOpmNWrgnIYgCrVL78C
         irLOaVoLVMxGIjFaYXgnPeR5oDvwkk+cFOi90N5Bg7fk+6jk+SaPtujMJu4qYL28P3za
         vo8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eo5MLvSZkHW64U5g6JRb+TrPrqv+7F35qBXJoN4jrZ8=;
        fh=SvS0PhFTtdcgIibruP5v8g9uT7bQpm5NKuN7TA4GeHc=;
        b=ivWm7Olix4O9OP3drhHI7LRsivNlFFWLYwlaHARmZxILsrINqYd4mHygLDSU04dAsA
         DPz/e/vmDUNmBwTv77kL0mqxg+/aE47jb3twDl0qjJU9oVtwtYG9AQ3rnSQENR7VfwBs
         a6Yg3fwmcSegflVxc3wUwn/AOph0tvtcCyCsrgs4FIipBhc3vEDlDplktCHQy5GhBQoE
         4LaS+e1Cdc97Yb6SCUMUUDS/CC9O3LU3aQG/gM7A+moBkbo5Naz8FfwDfVmf+FQ5nUNZ
         CJpbUK+iZYo0Asp7JA2I3k8MWIpqTcXR5mDBo64MoE0M8JVrA7ZJaKnX6IR8qVvGHmuC
         m92g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a4U4Xl96;
       spf=pass (google.com: domain of ojeda@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=ojeda@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-414191e6140si466293b6e.2.2025.07.14.13.04.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jul 2025 13:04:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of ojeda@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id CC89844069;
	Mon, 14 Jul 2025 20:04:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BEE85C4CEED;
	Mon, 14 Jul 2025 20:04:43 +0000 (UTC)
From: "'Miguel Ojeda' via kasan-dev" <kasan-dev@googlegroups.com>
To: haiyan.liu@unisoc.com
Cc: Ping.Zhou1@unisoc.com,
	Ziwei.Dai@unisoc.com,
	lina.yang@unisoc.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	rust-for-linux@vger.kernel.org,
	shuang.wang@unisoc.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	=?UTF-8?q?Arve=20Hj=C3=B8nnev=C3=A5g?= <arve@android.com>,
	Todd Kjos <tkjos@android.com>,
	Martijn Coenen <maco@android.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Christian Brauner <christian@brauner.io>,
	Carlos Llamas <cmllamas@google.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Jamie Cunliffe <Jamie.Cunliffe@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: Meet compiled kernel binaray abnormal issue while enabling generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
Date: Mon, 14 Jul 2025 22:04:30 +0200
Message-ID: <20250714200431.1917584-1-ojeda@kernel.org>
In-Reply-To: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ojeda@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=a4U4Xl96;       spf=pass
 (google.com: domain of ojeda@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=ojeda@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Miguel Ojeda <ojeda@kernel.org>
Reply-To: Miguel Ojeda <ojeda@kernel.org>
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

On Mon, 14 Jul 2025 03:12:33 +0000 "=E5=88=98=E6=B5=B7=E7=87=95 (Haiyan Liu=
)" <haiyan.liu@unisoc.com> wrote:
>
> After I delete the rust build flags, the asan.module_ctor binary is right=
 and kasan feature works fine.Could you help check why KBUILD_RUSTFLAGS imp=
acts kernel complication with kasan feature enabled and how can this issue =
fixed?

I assume Rust is enabled in that kernel, right? Or do you mean that somehow=
 removing those lines from the `Makefile` makes the issue go away even if R=
ust is not enabled?

Could you please share your kernel commit and the full configuration? From =
a quick build arm64 KASAN in v6.12.38, I see the `paciasp`/`autiasp` pair i=
n one of the Rust object files:

    0000000000000000 <asan.module_ctor>:
           0: d503233f     	paciasp
           4: f81f0ffe     	str	x30, [sp, #-0x10]!
           8: 90000000     	adrp	x0, 0x0 <asan.module_ctor>
           c: 91000000     	add	x0, x0, #0x0
          10: 52800601     	mov	w1, #0x30               // =3D48
          14: 94000000     	bl	0x14 <asan.module_ctor+0x14>
          18: f84107fe     	ldr	x30, [sp], #0x10
          1c: d50323bf     	autiasp
          20: d65f03c0     	ret

But I am definitely not an expert at all in this, so Cc'ing KASAN and Andro=
id maintainers: https://lore.kernel.org/rust-for-linux/4c459085b9ae42bdbf99=
b6014952b965@BJMBX01.spreadtrum.com/

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250714200431.1917584-1-ojeda%40kernel.org.
