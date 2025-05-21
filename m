Return-Path: <kasan-dev+bncBDEKVJM7XAHRBJV6W7AQMGQE3DHSWCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6E79ABF75B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 May 2025 16:11:52 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-7caef20a527sf927398085a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 May 2025 07:11:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747836711; cv=pass;
        d=google.com; s=arc-20240605;
        b=VhUHZ09gtx+11Jjida5C69CtA/dl6BuQHPi0412M7gCL1kt8+/oOIykhRPxJ4CFgvn
         3zUwr8+x52r+psavzEqklUVI38Lm5yIqpiPECigj51Fps+4Kj5lnvlwM4fys/eVUVTay
         gsYchB+Z9FJH4lJGUAAqkdL7xt2NliHxURht7ZKIVUYh4N9dnE/hzZXiHvoMuxGG2IBt
         c/RJbmMu4/Rp6wRZwwii+50x21Ni4yEnQqUrgzmQ/WNIvneDw0mZY2yWACLdNLtRTJ+k
         ksU17FPlXLYpPz4ovbnf7faEFLCIuBG4RqvLHEkCP2j1Dx5KN34dh+dYxCGZ0PFYarAI
         Ajcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:sender:dkim-signature;
        bh=+OxLe2X54XrqnxOe2zNI1b6CZWkLzxusKGMRLjQSTuo=;
        fh=tMFjssjFxjYXspe6YWYvP3lCspqdEGKX/wcK/lzmQxI=;
        b=Sy7ZY0j/yHakPlbqcvUPBxs3DXpowVjaxiAk9b541JGTnng7NluAZwsaH5E1qNuoeT
         k9ZeN7ATuS/yU8zsqAAO4aiE22lQ6tKGkfjW3GSQX+mY4L/6RwBalmZvsNZIMGTzxz2t
         iptFnoQ7TBKWJAk+YqOVqC/q13/+OO0H9nrgeR/htLajpRMULa9gG9I1UBtvpjnGbUNu
         8k/8PTaSEbGa3krUNTlrCmREQVGft4Nkphd8mAvU25JKHxnBHhmuG6/V8ptE9DFAoROw
         AJ8UB7o9GBiIKcO1TkL6ZADlCxnWB4x9WOkE4boxzub1eWx0s6MdotkSeT4mWXvNLX6D
         jjxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=UvgZO2tu;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=PHH2Z+0c;
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.152 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747836711; x=1748441511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:subject:references
         :in-reply-to:message-id:cc:to:from:date:mime-version:feedback-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+OxLe2X54XrqnxOe2zNI1b6CZWkLzxusKGMRLjQSTuo=;
        b=r3uYvSgKZxPX6DYQTGdHZ2T+Fzr1liJqPxG8sw+vZpCgc9vq2C+HOWt7LgYwAjFivG
         o7JukT2IzMclxUDyzK445qvPDjFPcRbTr/HcS5iGDTec2jkKhA+YZ022NZZG+XXY4zlS
         RNFGqVXr0UpYoYE01AKHqo4vsPfG6IJGdqsua0ivNz8ksUPvTb1tEFFg2UkMoQ3Bai17
         dm5W0CyEIsdi1ZjvyxSNeMp6sj7fJGO1dwYjgNAQF+2L4pCoykjWVvSgJUKvv5qdGohR
         /sWrOu9A5O1Dwey7e+JCcUnbVuIjDkO0hQvHOD6ZixXztusyaMGm8WHbcHA5Y+R7i/44
         ohyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747836711; x=1748441511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+OxLe2X54XrqnxOe2zNI1b6CZWkLzxusKGMRLjQSTuo=;
        b=NPmSJd65GIVjQN/7SV5TsemNdCmKCTsdCjOqTiWGCrVsg/f3OOiYUQh+QUSaNpgYh9
         ZqHH+QsKCz9B3Qo77kTASN1mu72PgVg5zTLW2jDa+k/h1hTLNyS67cAbMlCkF8igJ7YJ
         P5fau0DjP5Vx9RyAeCH3/CWRdtuEteKSEKDU2tB3TO02vIP7Og+AbL04TsRs42nw3TnQ
         YaZH5H/os6iy6F44eYtuqMLEuFeVbqCiXlDWjDNxdpvSWtXJV7H5EajZbazXEE2biDNf
         8aVg9VVVndk6zXKlIeExRDpocDtvnEpxN10UdBOfmOmGKAHIEdNEYQEwQGWAQNXVBK0U
         1F9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOYlyI8088Z4onAyCR3zBgW8Tdmcm1VX5TbVNPhZthoixa4xBYYGKh9O3q8SG01YOjZdIfCA==@lfdr.de
X-Gm-Message-State: AOJu0Yy/etpMfbReNGaoAK1CBIFhxQE1Go24Ys44v+4jSjVw5hy9uaV0
	NYzIkEbT0/rCFu4DkMhau5pga0ZEKi+VPmr4tpoq033pUcTAIFJQoDsA
X-Google-Smtp-Source: AGHT+IGV87v7yJ9bF7IaMdkFtCzloKAiZlCEuNa34PQz/im4cwEMRtZMe78pOv0kLdMb0aT6EQXprw==
X-Received: by 2002:a05:622a:6087:b0:477:4df:9a58 with SMTP id d75a77b69052e-494b079b997mr356318001cf.18.1747836710627;
        Wed, 21 May 2025 07:11:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEbch52V+I7qK5vYaGE6nKhhP5MRHmmhs7OfnhcCWGDYQ==
Received: by 2002:ac8:4e0a:0:b0:49a:d2c9:9f20 with SMTP id d75a77b69052e-49ad2c9a003ls24945751cf.2.-pod-prod-06-us;
 Wed, 21 May 2025 07:11:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWiFU2NyNZM3gpzU7w+fsqgtkcakXhiDkfZ7RouJKnj7ciQD4XZfG6FHQP10ATi6ySDE7hoSgZ/V88=@googlegroups.com
X-Received: by 2002:a17:902:c411:b0:227:e6fe:2908 with SMTP id d9443c01a7336-231de3bb4a4mr301675565ad.48.1747836698623;
        Wed, 21 May 2025 07:11:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747836698; cv=none;
        d=google.com; s=arc-20240605;
        b=hFALOFUNbnj1mgQWTHez0PghhEtq9TAzqabGlPKm+1YRcdzQqfoTpmnyzc3mDvieM3
         DfNmQNl2AcIl7qOgKoeEtJrTvDUZKQw7L+EVYKnkcCQ6k4ni9/1s5wo6bNpVzQ5/vhg8
         iPIUrtcvQ/n8dSPYOX2gRrzGvy7lwjAj3yFzgsq5BAF/SUBimLCJ/nwnyenUh3DSDI+O
         irceyyB7ZuMv68qDHhvWzra6zDpldb81j8AaVBfSTzO9l/KO6JjWf+l/GjCxatjQa+St
         PjFNOJ0pKeeSmWeChMKZvZ/D7UlCg3clqBicFut/MuDc8j8HmKjBdUrKh7iEZOdvK42x
         aYqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=HWI5tsYR82od73rLR1d73ZRHNmjGxzPzzskX0QA3T0s=;
        fh=ZaRCUHR/6y02niCEznoELAorVmkxpfrGi+k4Nrif+S4=;
        b=jIsLdMYwdaZ+BCMgbhwSf1Qumzi5czzgqWiv1z4Vnl647dW/JImMyLK7H6uvw9N/20
         YIsP4K3v1YCEXrzL3bMQbyCpqgl95uUQfd2TXiHc4vCHxpNgEeUfNRdOtoXBeOJ2SlMB
         63lhRXHZMFGfjIL9Zizy2GX6KwTtaRLQn8p/M0YqRRBfD3pWXdMWsAXlmyPS2N0bpIEk
         5BAKmd0JHXPvNk3ceMMbCKLH2msU2AYW/mCBWsOii0D3QtIhDslbusqBxDuFip30f/fw
         Wu3mDVDzt4InHvnhNAaXoNVaRrvhwDPvHAsCR20AIrA8XL9+blQqDsKJv/+vNBLRbAI+
         bXYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=UvgZO2tu;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=PHH2Z+0c;
       spf=pass (google.com: domain of arnd@arndb.de designates 103.168.172.152 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fhigh-a1-smtp.messagingengine.com (fhigh-a1-smtp.messagingengine.com. [103.168.172.152])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-231d4e3f320si5416945ad.8.2025.05.21.07.11.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 May 2025 07:11:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 103.168.172.152 as permitted sender) client-ip=103.168.172.152;
Received: from phl-compute-05.internal (phl-compute-05.phl.internal [10.202.2.45])
	by mailfhigh.phl.internal (Postfix) with ESMTP id D28781140115;
	Wed, 21 May 2025 10:11:37 -0400 (EDT)
Received: from phl-imap-12 ([10.202.2.86])
  by phl-compute-05.internal (MEProxy); Wed, 21 May 2025 10:11:37 -0400
X-ME-Sender: <xms:Gd8taNJRtpAdQ1fn-VeX5nac47719thOgFLRag1XBeSrdxlOyv0erg>
    <xme:Gd8taJKesTwfbHvYI8A1xdnyFnZ9agrTWGaukmHKpGYOew9OozAxVXfqWXw9dwwhd
    yGvEscWXCy0BtXYisQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeffedrtddtgdefvdelucdltddurdegfedvrddttd
    dmucetufdoteggodetrfdotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgf
    nhhsuhgsshgtrhhisggvpdfurfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttd
    enucesvcftvggtihhpihgvnhhtshculddquddttddmnecujfgurhepofggfffhvfevkfgj
    fhfutgfgsehtqhertdertdejnecuhfhrohhmpedftehrnhguuceuvghrghhmrghnnhdfuc
    eorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrthhtvghrnhepvdfhvdekueduveff
    ffetgfdvveefvdelhedvvdegjedvfeehtdeggeevheefleejnecuvehluhhsthgvrhfuih
    iivgeptdenucfrrghrrghmpehmrghilhhfrhhomheprghrnhgusegrrhhnuggsrdguvgdp
    nhgspghrtghpthhtohepudegpdhmohguvgepshhmthhpohhuthdprhgtphhtthhopegrnh
    gurhgvhihknhhvlhesghhmrghilhdrtghomhdprhgtphhtthhopeguvhihuhhkohhvsehg
    ohhoghhlvgdrtghomhdprhgtphhtthhopehglhhiuggvrhesghhoohhglhgvrdgtohhmpd
    hrtghpthhtohepkhgrshgrnhdquggvvhesghhoohhglhgvghhrohhuphhsrdgtohhmpdhr
    tghpthhtohepmhgrshgrhhhirhhohieskhgvrhhnvghlrdhorhhgpdhrtghpthhtohepnh
    grthhhrghnsehkvghrnhgvlhdrohhrghdprhgtphhtthhopehlihhnuhigqdhmmheskhhv
    rggtkhdrohhrghdprhgtphhtthhopegrkhhpmheslhhinhhugidqfhhouhhnuggrthhioh
    hnrdhorhhgpdhrtghpthhtohepnhhitgholhgrshdrshgthhhivghrsehlihhnuhigrdgu
    vghv
X-ME-Proxy: <xmx:Gd8taFsIEC4GZHg5Hu8aA7VK2AQdHWupCHisjiHUC3T0zlNw_s2Ngw>
    <xmx:Gd8taOa8HOf2g3NcRGP0_xBQfcS9_TSIBx7K163Y20Yr9_0EAxZp6w>
    <xmx:Gd8taEbWPg1yILveN5vwcjTQY_Ex6Ob0CL8hRXtBlz3DivwI3SnrEA>
    <xmx:Gd8taCC8stVoZjthgL3MSSmcYhqAY8sFJ-iTkMYG3TfDeLI_3diEsg>
    <xmx:Gd8taK__j3JZ5GSiiKeqVDaDJGlTkAZ-3rraLt143UlbS8opPORdVkoQ>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 32C301060060; Wed, 21 May 2025 10:11:37 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: T2ad347d80e1d0ee9
Date: Wed, 21 May 2025 16:10:47 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Alexander Potapenko" <glider@google.com>,
 "Linux Memory Management List" <linux-mm@kvack.org>,
 "Andrew Morton" <akpm@linux-foundation.org>
Cc: "Nathan Chancellor" <nathan@kernel.org>,
 "Lukas Bulwahn" <lbulwahn@redhat.com>,
 "Masahiro Yamada" <masahiroy@kernel.org>,
 "Nicolas Schier" <nicolas.schier@linux.dev>,
 "Andrey Konovalov" <andreyknvl@gmail.com>, linux-kbuild@vger.kernel.org,
 kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
 linux-kernel@vger.kernel.org, "Lukas Bulwahn" <lukas.bulwahn@redhat.com>,
 "Dmitry Vyukov" <dvyukov@google.com>
Message-Id: <61db74cd-2d6c-4880-8e80-12baa338a727@app.fastmail.com>
In-Reply-To: <CAG_fn=XTLcqa8jBTQONNDEWFMJaMTKYO+rxjoWMHESWaYVYbgA@mail.gmail.com>
References: <20250507133043.61905-1-lukas.bulwahn@redhat.com>
 <20250508164425.GD834338@ax162>
 <CACT4Y+a=FLk--rrN0TQiKcQ+NjND_vnSRnwrrg1XzAYaUmKxhw@mail.gmail.com>
 <CAG_fn=XTLcqa8jBTQONNDEWFMJaMTKYO+rxjoWMHESWaYVYbgA@mail.gmail.com>
Subject: Re: [PATCH] Makefile.kcov: apply needed compiler option unconditionally in
 CFLAGS_KCOV
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b=UvgZO2tu;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=PHH2Z+0c;       spf=pass
 (google.com: domain of arnd@arndb.de designates 103.168.172.152 as permitted
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

On Wed, May 21, 2025, at 12:02, Alexander Potapenko wrote:
> On Tue, May 20, 2025 at 4:57=E2=80=AFPM 'Dmitry Vyukov' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>
>> On Thu, 8 May 2025 at 18:44, Nathan Chancellor <nathan@kernel.org> wrote=
:
>> >
>> > On Wed, May 07, 2025 at 03:30:43PM +0200, Lukas Bulwahn wrote:
>> > > From: Lukas Bulwahn <lukas.bulwahn@redhat.com>
>> > >
>> > > Commit 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin") remove=
s the
>> > > config CC_HAS_SANCOV_TRACE_PC, as all supported compilers include th=
e
>> > > compiler option '-fsanitize-coverage=3Dtrace-pc' by now.
>> > >
>> > > The commit however misses the important use of this config option in
>> > > Makefile.kcov to add '-fsanitize-coverage=3Dtrace-pc' to CFLAGS_KCOV=
.
>> > > Include the compiler option '-fsanitize-coverage=3Dtrace-pc' uncondi=
tionally
>> > > to CFLAGS_KCOV, as all compilers provide that option now.
>> > >
>> > > Fixes: 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin")
>> > > Signed-off-by: Lukas Bulwahn <lukas.bulwahn@redhat.com>
>> >
>> > Good catch.
>> >
>> > Reviewed-by: Nathan Chancellor <nathan@kernel.org>
>>
>> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>>
>> Thanks for fixing this!
>
> @akpm, could you please take this patch at your convenience?

I have applied it on the asm-generic tree now, as this contains
the original broken commit. Sorry for missing it earlier.

      Arnd

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
1db74cd-2d6c-4880-8e80-12baa338a727%40app.fastmail.com.
