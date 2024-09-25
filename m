Return-Path: <kasan-dev+bncBDRZHGH43YJRBEWIZ63QMGQEMNFZWFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DFDB4985717
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 12:21:07 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6cb25c3c532sf5201716d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 03:21:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727259666; cv=pass;
        d=google.com; s=arc-20240605;
        b=a+vHD5B8BgJqAvOCssLyEbifRnoF0B/svnlNZTKq+NOaUh5OjvdQUqhB1Evd9Na7Mm
         V8k51bNzOsTBzkujZLQYn7cjOntubn/o/MIn9YkcrYRRtkZn+R2m0k5zA2lfpDcJlZ62
         HcChfX/2WpSkdbaNFOpuCe+WId3WRAbtgTJ6+zKXlF50oc2lryKbp9Cx39WCHuYbd6JW
         C0fJViiPwn85K6WT0RpKMJ9MKvB9tajEvy7D1XdeIKTm16ihRmM5jJnfI6YSdlVgtGpc
         veQaJPnd4hTBt2t+cYhv65CV0Px4awzDej0m3l/sGIJYybLHuFZpY3PjCdVQ6oaC/ZsI
         gKyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/4PnJVXR1rwfBF/kAjX/4qBkYeyC8P5WiAs4MPe4ujQ=;
        fh=+3ce95lPBLS+0pFQIiKFVbuR/psadctLEtlEerlDMbY=;
        b=bhyR3eDZSvY1VY30J5HqHMGiFH66qt0TFAPUwXToeMKZLeudvbLD2YZre//BctlKEh
         eHpGLnT91pOC9G7XLJoOQn2CGblcX3fPi+VC+zEz3+1zI0A4A8wnspS0qIcv/wGZR58R
         q7fVCx8jD7u1La8w4ctw3Cq8h3s2WtcAhcu3lc+PZJQKWcASZUu9+SCMxPhklrljaq24
         AoEsDa81TFpAhpyALJRieQ0rWCVKUJ5HYLgjQQS96wxCIw/St/6dj2ORhq0arBtuxhX8
         NtamMnrsYxX0W8yJoBeq+JSsDyxPVrMbwpCo0AcOqtv67E0j9ckXN9E9kuBqB3tt62Fq
         BLlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QIAdwo03;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727259666; x=1727864466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/4PnJVXR1rwfBF/kAjX/4qBkYeyC8P5WiAs4MPe4ujQ=;
        b=l7AbdsYSLhL9D+AL/GPTdPq4GmhBNu1V9TLCGc8ZoLMb2zbLgibh2CmyCWOYgY8RGn
         EJkH5vkDPf4y7wMFU6V2w31fIDH2gkTOLI/vbUKN5+2N3r1WdTN9XJBxf2+Tbx0/jh7j
         KB9NUdNmqiW7N6e6CpV5WQrzTudeVU9vulsSG66zJtuG2UlsMalq8MIv4b2ld3hdcijl
         60k6zdkZgSWzbqYaf6d6Ews8fv64+7uK9e2utsKNi6rCDSFuYONBJamTDndcGDkm3Yo2
         sE6PyNd/VgXHvvgxsLoZPYqnZ94WEdQ7d2dYi59NGTxrOf2GuEgKqCCDFe19IMcKBdue
         TjBQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727259666; x=1727864466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/4PnJVXR1rwfBF/kAjX/4qBkYeyC8P5WiAs4MPe4ujQ=;
        b=XQBs4lJUUesXKCJxoytmBq9hFfkGo22SsFI0wK7/FkRqIZpnsGzOkn6yMy/aoEmpJh
         YHFTY7T/vR9jt5HjwsKwqGUDrbiaHnWfVUm5Gk8XdG1RH37m/7du4q15g/LMaRkjM2K+
         l6qyA2y5OgMBwyzLrF0LM57+i1F2DypvABYVwlReHVrB0Syp9+dOuxAOs/qxVAxJmJAJ
         fg+e8E8XgpXjKSpiidqRd+PU+3YBFztnSYzsItnJmUDX98HHUm8hP0xo8lrBJF/bkFuV
         MBt8eqmjyYmfmx7xCbdLkzd6RX7kWxv2GKdKc/IjRjP8g57nPTd4pkD+HKIg+yHEUb0c
         xMEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727259666; x=1727864466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/4PnJVXR1rwfBF/kAjX/4qBkYeyC8P5WiAs4MPe4ujQ=;
        b=nYYJAI7bQ2EwPEM9cX/zQIvqrCzNHdpPQ3GLMTtk9ON6K8tj/POzv+b0brLjss8e5z
         IGdk0iTyeSXbL5AKzHqkeGsfYAI6eRBLiQGh6FLn4I37/7eaJyCUo9xkX8QxDNbSdGJi
         fja1z3IjPVzxE1ho5tSwptogt6pPAaSO9taSa/Jkjrbplise9U3msDIHOv6kro2+BUdN
         +eNJ685vTZL2VT4URyctP8o+VykVnfUPMtR6/jtYwrwDZoVXsuu8xbDk4J6T/grJok6o
         f9vwUhZy/sNejNY313NV6Ve/bX1HmNN+PRbs5pRQ22M9pIsZlEEcKd6vd3xnseyD9KHr
         jygw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRxhZn3OIn7AXfblV1lGDn1slQObvUUOwXTEw+bGoLy79aHVbbqdexf93Duli5BvvfECp92Q==@lfdr.de
X-Gm-Message-State: AOJu0YxQ9o7Z4+lF0s2RUDnOY5zdKdGGU6Z0VGbvu2hhoWxRhRsRFlC6
	n3ou0wKDITl6OgDepAjXV+y3VBwfCsJrGk/1m6vVieV/BL9SzNg6
X-Google-Smtp-Source: AGHT+IF/ru3yzDsly3GTxsT6lLmdeHfq0/pOgfDFcJJ+xtbT7JXo8Jmxnou9oURVdyC5BhV2f3fxqA==
X-Received: by 2002:a05:6214:3d87:b0:6c3:6d8c:b293 with SMTP id 6a1803df08f44-6cb1dd15d65mr43566116d6.7.1727259666367;
        Wed, 25 Sep 2024 03:21:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2348:b0:6c5:15ae:4b18 with SMTP id
 6a1803df08f44-6c6823b3e99ls89136576d6.0.-pod-prod-02-us; Wed, 25 Sep 2024
 03:21:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWAXXnJe9BVxhO3EXXLBGfzJTyiwjwPJlfBrKkTFBY4ptH/AKnjPFRWaB0vVRf3IZnJPouAh07ZKNk=@googlegroups.com
X-Received: by 2002:a05:6214:4497:b0:6c7:5e3c:ed4 with SMTP id 6a1803df08f44-6cb1ddb5302mr30431236d6.32.1727259665248;
        Wed, 25 Sep 2024 03:21:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727259665; cv=none;
        d=google.com; s=arc-20240605;
        b=QVX9oYNYaS6fjCMzU7VRyJAtDS2Yw4S6nx1GW7x277qIrI+JqLWrmmlnBuAkavNlwn
         jtU+IU2/cEhEyT/CIJRWnefbS5b6eaF5+M4fM/jL475aGcLoWrO5K1GZsQcRH8b0KaYn
         2AUmvDoUES+wzh5tyFC/FHf6VR7WG7ms1rxs8zAIW8pkAZqPelBpgBYjgUdKwa5sKlXa
         /Br32OyrJELNgRQ/PYYXhE+7AioNbTdX7yrkyNKlTUolWqVa1kQJh2TkYZaiHZPN+atp
         ZIw20ElUBVPtdB4Wqco6KpZLVnnvLeVfiBfEbmrooEEWZqgBQX0JGbU/5S5lQjwgzwUJ
         eQfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TCDnE5O1Qj4Sx4FFyUqVkcdfYPO8wvEkGDEg/b8x6RM=;
        fh=GiXels2OhPpNbM5+57A7OeWF/oYkZWHDv5ZMdCRJxms=;
        b=g3a7l1XPdoAg1VRRirzpnwkOI6XVN/8tRLBWWfcFkrMm7AqBALyCU8F8pTkOnpPXrF
         yomp/u7cAEGe9W3gx4l3V9mpB1xuUw9/cOTRb5omXir7cfD5/JVPLXDiN5UjCDiYz2PV
         sEr6L1HZy1/2D8VzQO7oDGgqY4+hhK7F6ofGFL+O0tLSonYnFk1XWrO/+qZjVPyjEhBi
         klp1KHgNVOG6vUF0oE2E641gdmbHqa4FDdleJIpdwap5nYU07spyn9/OJwdISRZZb6Yr
         ARECFyoY/wK6z5nWH+U1gCm5rekjBGJ/4/qaExcpU9kWkWMq85s6viDjfW2DsApihdpT
         fRdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QIAdwo03;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cb0f3f9948si1495446d6.0.2024.09.25.03.21.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 03:21:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-718ebb01fd2so1216927b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2024 03:21:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVkG28/T5pfc5ZjGUBN1oU/prZODbHYVdK/Fw2C6xdv/g1+lpSNg8yHEvuAcG9v1YfoG5efinV2Pdc=@googlegroups.com
X-Received: by 2002:a05:6a00:1149:b0:70d:140c:7369 with SMTP id
 d2e1a72fcca58-71b0ac5a8c4mr1439818b3a.3.1727259664158; Wed, 25 Sep 2024
 03:21:04 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com> <CANiq72mv5E0PvZRW5eAEvqvqj74PH01hcRhLWTouB4z32jTeSA@mail.gmail.com>
 <CANiq72myZL4_poCMuNFevtpYYc0V0embjSuKb7y=C+m3vVA_8g@mail.gmail.com>
 <CAH5fLgheG47LdgJGX6grHXL6h08tsSM1DACRkkzQk_1U8VAOxQ@mail.gmail.com> <CAH5fLgj7E03DKBcptgmZ8SLgco=Qs4puO=O6=v9=-3SSuqJyUQ@mail.gmail.com>
In-Reply-To: <CAH5fLgj7E03DKBcptgmZ8SLgco=Qs4puO=O6=v9=-3SSuqJyUQ@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 25 Sep 2024 12:20:50 +0200
Message-ID: <CANiq72mFKE4tLp1bgr+c0-Hi+dmReFT4m5RcV6MigjyiAiuwmg@mail.gmail.com>
Subject: Re: [PATCH v4 0/4] Rust KASAN Support
To: Alice Ryhl <aliceryhl@google.com>
Cc: Matthew Maurer <mmaurer@google.com>, andreyknvl@gmail.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, dvyukov@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QIAdwo03;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Wed, Sep 25, 2024 at 12:00=E2=80=AFPM Alice Ryhl <aliceryhl@google.com> =
wrote:
>
> I posted a fix:
> https://github.com/rust-lang/rust/pull/130824

Reviewed, tagged and added to the lists -- thanks!

> We'll need a check on RUSTC_VERSION in Kconfig for this. If the PR
> gets merged within the next 22 days, this will land in 1.83.0. Would
> you like me to send a fix with that version number now or wait for it
> to get merged before I send that fix?

Perhaps it could also go into 1.82.0 since it is a fix? (there are
still a couple weeks for that)

In any case, I think we can put 1.83 in the fix already and modify
later if needed. Even then, I am not sure if the requirement is a big
deal, i.e. I guess we could keep the warning and avoid adding the
restriction. But since this is for KASAN-enabled, I guess it is fine
adding the restriction and being safe & proper.

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72mFKE4tLp1bgr%2Bc0-Hi%2BdmReFT4m5RcV6MigjyiAiuwmg%40mail.gm=
ail.com.
