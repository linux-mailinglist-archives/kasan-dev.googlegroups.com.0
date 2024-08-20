Return-Path: <kasan-dev+bncBCG7JFGA6YOBB6NPSO3AMGQEW2OWFKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E2A21958D9F
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 19:52:58 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2702b61bdffsf3938292fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2024 10:52:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724176377; cv=pass;
        d=google.com; s=arc-20160816;
        b=QwNC9zeJ2O0FggjMb4sKsuEn3xsWXBun+z6PO60O5OHqXd1T1ah0CyASjNh2G4Md1s
         b7DyzLKkb/A2fbIko3zmD4NIlSkaljFFAwKan3q4zXsm281/3VjfgrPzOf6p+OI9+olI
         tX5LKfKidbagm2YI7JHKnUkszSlqP/s4SCtsrJBlmN9EnkQH9z1D8J8OFRxAMmLWkofx
         DqeII8BSCeFoA8eDzSDzB4wcf2rI6tdSVoGMbhu3j6UeXyFRzMmfTs8hWjXmNQi8z+xW
         kWPLdmsdA+TlmtOGpif/+Et0Mp2k1jyvuRrt1layAszX5BBd0Rjx3LRlcoTGE2k3Rv7z
         TK7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :feedback-id:sender:dkim-signature;
        bh=NxInAmEUWSwPLFGDSMBr9G5rJ8BusN8qtEBBbA7aE0Y=;
        fh=kzajvFdMe/95XaXnG8HmgoZl3hlpZoMZqDQa6UhKUCY=;
        b=1FtEelpny3Wu0LGnlRLr36wDMtIDeamH1Y7ZuuumSwDnXl+XxJy8F2YofhkSEbhx1m
         3563oOxDp+BG3xyvL5P0auEfljv7WGr19oTsGWDJQjZZxPTJZYtLWe5BwWu1ZpTZDMwJ
         /SNLummyN4Sh/gpeyvdpMccGzaxlR7N2sLHdwVJ5kyrfjtk1VfFZ0J4striDHiF/otFV
         6dE/lh7e0m9xU+i5Os/1ARGfnKjDi3RUwFnk/jTX25mmawUSlBK0oz/qSGl4HWhRKWMx
         6lY91aulZ61WDCgDuEM7YN4Se05+i4iyxXZiTuGXwzz3YxzdRMwGXga9lSgj2rsxhDZZ
         I14g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ryhl.io header.s=fm1 header.b="Do/drMqW";
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=aOrQjEVx;
       spf=pass (google.com: domain of alice@ryhl.io designates 103.168.172.153 as permitted sender) smtp.mailfrom=alice@ryhl.io;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ryhl.io
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724176377; x=1724781177; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:feedback-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NxInAmEUWSwPLFGDSMBr9G5rJ8BusN8qtEBBbA7aE0Y=;
        b=Q86s4ZtBSkNTURvyd12OZejNypl/+y2NwZG07WxTGJcb7HZSsAE+IZ59M1Xeepp7SL
         wn0UTiNMjby0QhBcehoeEvGpZVOI6wd0j6wV7XPwkII/9OaJJjw3kB2WFBbx3rYcYUhM
         QwpH+ZRizoC2Z6LARu8yxFUeeFDp0jVk0/hUGl7FlwaM+2DZdmHJLpPyq2ECRK73da3Y
         q36iSbZfIIxdtBEmsMs+wiVDKtOv3qpuMrPZgTquzRtC1z2/zxKjj2um2FOFpraqjVok
         /QCqcmqNojzMyTEUV9+T6xL4umKDqrknyYDV6Z7cu4dp3cmY1NE5m9xWiqnFLZFGPrMQ
         6kSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724176377; x=1724781177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:feedback-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NxInAmEUWSwPLFGDSMBr9G5rJ8BusN8qtEBBbA7aE0Y=;
        b=PjMr6qF96kddpkRl68mE3ftjRqdY6VK0ZHSJViO48K5UdnOmYKtgQmB/lSnuSdeJaX
         HE+5FmXtWOmm/S0qpIEQqoz1p4ALqJf+G/Jj3AEE3G/vpi8wCD0IXRKwCGXnNuWLFmyi
         Tj5FnIjOHwIsH62UEBoUdKq56xrEUVoW7DmBr5rFhJnG5JdpyIsJqutA1PHCXfsROIeH
         DGgNLu3Zuz853raXYzaw92CGudeJrA0Fl1WWzOBnoqqTlEH1nvEGNfTR4lDpMCY51Y6k
         fobvZLjAUSsQ48bXnK/z7YCsrEOtHKe6Nth1FuHejJNF03iLLv8NWSii8p5cSRLsVN5f
         6zOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVUrdA31zEa+F6qV4lziVAE+hoNi5wlYzYEfblDXwTNA/riq8F62W3NWSMZOel1wKz49GzIDQ==@lfdr.de
X-Gm-Message-State: AOJu0YzpTyDejre51TPy0YfjBfrY588woDk5QxBrF/qceKDt8ljPnqeQ
	alAnN15nkGjFkpijFqzg9F5hoVVcfKSFx2CXGdD9UX4BojzLx7J9
X-Google-Smtp-Source: AGHT+IGCxfoZVgguKQ0/mNHYqVWipBgcGfTiduYkCoI74+5Bd5q6c27IKlrnCFdJlCpYA6N8TOoLaw==
X-Received: by 2002:a05:6871:592:b0:261:21e9:1f0f with SMTP id 586e51a60fabf-2701c52035bmr14129696fac.36.1724176377232;
        Tue, 20 Aug 2024 10:52:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f787:b0:25e:749:fb39 with SMTP id
 586e51a60fabf-26fff3b95a4ls5942409fac.1.-pod-prod-06-us; Tue, 20 Aug 2024
 10:52:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0CzK72RYCLbrAUb2QWe5AGMGp6C63iq2Bi7jCjU0n68GaMgC7JMyasCWJUX1czIvIBzjEcPN8/x0=@googlegroups.com
X-Received: by 2002:a05:6870:658e:b0:25d:ff4c:bc64 with SMTP id 586e51a60fabf-2701c33ee32mr15705061fac.6.1724176376352;
        Tue, 20 Aug 2024 10:52:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724176376; cv=none;
        d=google.com; s=arc-20160816;
        b=VnTIapPj1prg37N8LLTU4Wel5EykFdh+Php3fOQFIwG7myfo+37+JaT8fn6rRCLpMM
         zIeVlo8FCi8hK+ZnOdJnrp3qO2rkHCG1OM0mGQQdTa7/QBcyVtvLU/u9Z5Tf2Zkmb6eq
         WeRKk/7ykKWVTOSwut1Sx43PYnmmhIY1K1waRVPWHJE/mI/Pjj8zq0J2dfIiQixxtQve
         Xc+R2qzBT+8ZgdxSqxlO8EUaGaZxYkdYqNDHm5OYpd2q2Sz+Eya6g+LMl7edsEdt/Qk0
         gUJS2oNI8nuLHND04KFe/IciTTMgOk2wcLoo1HhG2O/iACwQxK1iFIndupdLFVTx8SDh
         q/Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :feedback-id:dkim-signature:dkim-signature;
        bh=FmUZfUav3BKMSvLL7a8dJXOXth5me8Z3O4LEP0Z5+eA=;
        fh=qejZ1ax0qxGuWkfS7b1dYQQHNNW9ZGA17pgCnXTx3p8=;
        b=UHE89w6FQ3nH6BrrSc3eZPpl6QTMdE8MbCjhDJwMUaF7wZn4zVALTvmjOLN5abURGr
         jQCxBEWru80XIRHTY7a3trY8V6ahb9oLj4+EDLAEW3Y44kUzbkptizLkkqsLizU8TiJP
         d0NmR0h8PIDMzUqCIwtCPIO/NDQciM8aki1xOXzcKRBTe1EUr8kxpxlu8psj2xH5ELCs
         TWZZnOwyoRPdk7wOJUR3I8wI7eNuqctwS0bylgM3ojL2RouOkBdpntjB55A3EseBTSr/
         kfQP1NaphJ2+KwVheobu+Xr2U31gYHFbf7whWTTKvcv+y70BJln0aiEseImDggyAjdSZ
         fdpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ryhl.io header.s=fm1 header.b="Do/drMqW";
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=aOrQjEVx;
       spf=pass (google.com: domain of alice@ryhl.io designates 103.168.172.153 as permitted sender) smtp.mailfrom=alice@ryhl.io;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ryhl.io
Received: from fhigh2-smtp.messagingengine.com (fhigh2-smtp.messagingengine.com. [103.168.172.153])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2700442b08csi529508fac.1.2024.08.20.10.52.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Aug 2024 10:52:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of alice@ryhl.io designates 103.168.172.153 as permitted sender) client-ip=103.168.172.153;
Received: from phl-compute-05.internal (phl-compute-05.nyi.internal [10.202.2.45])
	by mailfhigh.nyi.internal (Postfix) with ESMTP id 7E900114C014;
	Tue, 20 Aug 2024 13:52:55 -0400 (EDT)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-05.internal (MEProxy); Tue, 20 Aug 2024 13:52:55 -0400
X-ME-Sender: <xms:9tfEZhzAgdAA-bW8OMZtHZKOT6uYZ97YP2IoG5apHHAlOmPwpH6soQ>
    <xme:9tfEZhQQngPNEE1UZkr_bvU6uMaC19-bftzJs4k4jxWO2XZAvGs2sWGHW7N4iHL2c
    IDWDnlSK3ITx18lag>
X-ME-Received: <xmr:9tfEZrUoj67aa7dHtZ0tJAyQuqSAqvZ93Xw5zHPndRE4o1a3_IiC2Dk-W1o48P1PL-m-asXqqhG8Cqur2XntRGFg_MdVAfTV9zXE>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrudduiedgudduhecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpggftfghnshhusghstghrihgsvgdp
    uffrtefokffrpgfnqfghnecuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivg
    hnthhsucdlqddutddtmdenucfjughrpefkffggfgfuvfevfhfhjggtgfesthejredttddv
    jeenucfhrhhomheptehlihgtvgcutfihhhhluceorghlihgtvgesrhihhhhlrdhioheqne
    cuggftrfgrthhtvghrnhepfefguefgtdeghfeuieduffejhfevueehueehkedvteefgfeh
    hedtffdutdfgudejnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilh
    hfrhhomheprghlihgtvgesrhihhhhlrdhiohdpnhgspghrtghpthhtohepvdefpdhmohgu
    vgepshhmthhpohhuthdprhgtphhtthhopehmmhgruhhrvghrsehgohhoghhlvgdrtghomh
    dprhgtphhtthhopeguvhihuhhkohhvsehgohhoghhlvgdrtghomhdprhgtphhtthhopeho
    jhgvuggrsehkvghrnhgvlhdrohhrghdprhgtphhtthhopegrnhgurhgvhihknhhvlhesgh
    hmrghilhdrtghomhdprhgtphhtthhopegrlhgvgidrghgrhihnohhrsehgmhgrihhlrdgt
    ohhmpdhrtghpthhtohepfigvughsohhnrghfsehgmhgrihhlrdgtohhmpdhrtghpthhtoh
    epnhgrthhhrghnsehkvghrnhgvlhdrohhrghdprhgtphhtthhopegrlhhitggvrhihhhhl
    sehgohhoghhlvgdrtghomhdprhgtphhtthhopehsrghmihhtohhlvhgrnhgvnhesghhooh
    hglhgvrdgtohhm
X-ME-Proxy: <xmx:99fEZjhfRrMqzgkpGd9hhUi7E9B-_0S8w5Zx2DFug1oFHIlFul4rJg>
    <xmx:99fEZjCfZiKxTy6ZTfFJxK-Om95jjUtrg4SIauFtB4BIVQutbLQ4Hw>
    <xmx:99fEZsKD3bnRmfxVFCGM2QoXZ72QrntbQzcZk2rJWnhEpTd9YP2cWA>
    <xmx:99fEZiD3Jk0jhuFSUCEfrxHqawpqzlOPqsF9hBkDnuXzsWPUVziJMQ>
    <xmx:99fEZgyaMNvkyoMedsJClIsMceGU0erYbuZdmiGZvxuDXDUaxjuzLxKz>
Feedback-ID: i56684263:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Tue,
 20 Aug 2024 13:52:50 -0400 (EDT)
Message-ID: <d1e5e8e4-3d54-45d9-aae5-183a5642e0dc@ryhl.io>
Date: Tue, 20 Aug 2024 19:55:41 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 0/4] Rust KASAN Support
To: Matthew Maurer <mmaurer@google.com>, dvyukov@google.com,
 ojeda@kernel.org, andreyknvl@gmail.com, Alex Gaynor <alex.gaynor@gmail.com>,
 Wedson Almeida Filho <wedsonaf@gmail.com>,
 Nathan Chancellor <nathan@kernel.org>
Cc: aliceryhl@google.com, samitolvanen@google.com,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com,
 ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>,
 Gary Guo <gary@garyguo.net>, =?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?=
 <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>,
 Andreas Hindborg <a.hindborg@samsung.com>,
 Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling
 <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 rust-for-linux@vger.kernel.org, llvm@lists.linux.dev
References: <20240819213534.4080408-1-mmaurer@google.com>
Content-Language: en-US, da
From: Alice Ryhl <alice@ryhl.io>
In-Reply-To: <20240819213534.4080408-1-mmaurer@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: alice@ryhl.io
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ryhl.io header.s=fm1 header.b="Do/drMqW";       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=aOrQjEVx;       spf=pass
 (google.com: domain of alice@ryhl.io designates 103.168.172.153 as permitted
 sender) smtp.mailfrom=alice@ryhl.io;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=ryhl.io
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

On 8/19/24 11:35 PM, Matthew Maurer wrote:
> The notable piece of feedback I have not followed is in the renaming of
> kasan_test.c to kasan_test_c.c - this was done in order to allow the
> module to be named kasan_test but consist of two .o files. The other
> options I see are renaming the test suite or creating a separate Rust
> test suite, but both of those seemed more invasive than the rename. Let
> me know if you have another approach you'd prefer there.

If you're sending another version anyway, then it would make sense to 
mention why the file is renamed in the commit message of that patch.

Alice

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d1e5e8e4-3d54-45d9-aae5-183a5642e0dc%40ryhl.io.
