Return-Path: <kasan-dev+bncBDEKVJM7XAHRBF6X4ORQMGQEJOOCHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D12171F298
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jun 2023 21:03:53 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-3f70b806046sf343055e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jun 2023 12:03:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685646232; cv=pass;
        d=google.com; s=arc-20160816;
        b=eihGow2Az75t8g7lpAmbzx1YKfDxBVp0scCHXs5SWuTlKl72OV01iVn0IdrSqmYS3h
         rXB+k2aI14cXlgz9dazEee8rN4K2zoYTu4ruZUHhgKPP35zlC36os4rk/olSJBTsyywJ
         HoHFzra3NqBSpXdYILGQa4DpqWZ5eeCfIqoPbDIVjlkk71zWlYqWWpwBYpUi+rsXzL7x
         kNCoJGkZ5l05LEulKtNSPVu6152bzoa8GB0U7Nl35Nx03mvDks21lGuaMjKG4ObXb2of
         d7FVMvXw3yPbvVRZbQvTFbM27YO9ENV9Rkd3tFHZtYmSjqBrp1oYKPZ7aRELEp3YmbWD
         Y9Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=i64mdVLgX0KV3WADdtC6K21D4mbqgQoxjqKSfBIQoLs=;
        b=V4fsC5ntLgYrTq4VN0D+xx5aEMUZRcHf0QjHiyv/7eZrSFpM1nGCb5DY0XXjA/l8cQ
         LT0y7OffBL+dmY6dRzG5cZZqsO2JflwvkhPq58Zas/Xegg28/ooH6P2tCN/ThUfc3K1F
         17hC6nkypkqdbzypgpWc7UUVmIPRK/Nt6/j9yby42WTuTp/lSsslg4RVa9BBRS5kBovK
         GDdyosmdSRdjzWfInJI6tw2AK5as1s/K/9XcH/xztMipW97XGVKYJqmqu65MSEuvy974
         tq8R1PVKSNM4ewPzDGGfEr6zne+8mdvgM1OioO+00eiAOyEI4uq2n3i5v1rvw1Ylqmjl
         Ue2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b="C/QaeHLc";
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=CE0FJDq5;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685646232; x=1688238232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i64mdVLgX0KV3WADdtC6K21D4mbqgQoxjqKSfBIQoLs=;
        b=jtt02WyFaYtb8Gke68gWYVe9oh3AKwWzRFF/D/4+4inFLfF6fdILmZrltRb43ImbdT
         4mMOvUa1Oyq90ynEehxkoTQpc33K5LP30vTxr1FaXGCLH0I0PNwC59udM6jZLzQ92hQZ
         sCDEqH0AVL+Z1kwED3Q0E/BIAbht54H1b5sZdw+pvRxZmhSWNPD2uqbN+wPKmM8ZAkGw
         W/FvIJXPunDVLq2gLSCHi41iXAPZDJEG6lbSxhb2LULfloE8BJaFbp0jUqtcXGTYgxiD
         43yTep/MqVHAxOOn7zUQGZka/+rqm8hlUVA+gdcStD4dGRLQ8jzA1yWa69DQ6gPQ4EH4
         y32g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685646232; x=1688238232;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i64mdVLgX0KV3WADdtC6K21D4mbqgQoxjqKSfBIQoLs=;
        b=JhoWOgvi2ugaSWRrKYSL/LJ1X0sOlZPsdT57sUZ3+UH1m0RYISDYy9Bf3cpnC/lGtn
         MdX47DMHFJkWU6HD9sTGtd7GmeBGrCbKEQ4DNYZvM9YAtze/TNdZRS4/KFT4os3cRDHC
         aMMn7dvt7/oLyvRbecG0KtKm/wVNoK4UD1nIpT+BwQwONyTGvaW4QjbpIq+5mUNeGWA1
         CZbJyG3STEMjgwCNIB295Jxs0TB00s4/15c21Uo87PiZUFzeeH3pr4I5hXSWLXPE6gar
         nYE/PG3X12BXSwZV5Q6h+O0ZUuD8bwzNUwONXtHVFHIqGjJjoCCKYSF1LTtbBdrotY8n
         apqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzqDbNS9GhfH6P7otoB7Sz1DuJkxhbMVDK6Wb6LD3C4qdkPOtjK
	FiwtJrrjtEQmf/+Um4efO/A=
X-Google-Smtp-Source: ACHHUZ49fopaov9NeUTzjctLAhiqtM9a/OJOy574WsbvqYdp1ShyW2iM63cUP9w9m3u/OtucLOVcwA==
X-Received: by 2002:a05:600c:314b:b0:3f6:f4b:d4a6 with SMTP id h11-20020a05600c314b00b003f60f4bd4a6mr27979wmo.7.1685646232205;
        Thu, 01 Jun 2023 12:03:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:38e:b0:30c:2d4b:ad61 with SMTP id
 u14-20020a056000038e00b0030c2d4bad61ls93581wrf.0.-pod-prod-03-eu; Thu, 01 Jun
 2023 12:03:50 -0700 (PDT)
X-Received: by 2002:a5d:5188:0:b0:2d1:3eb9:c3c2 with SMTP id k8-20020a5d5188000000b002d13eb9c3c2mr2376236wrv.54.1685646230563;
        Thu, 01 Jun 2023 12:03:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685646230; cv=none;
        d=google.com; s=arc-20160816;
        b=gUD0bALVxfxUbNbT19ABdHQYQw3+yKsYE+rjVNV9CDGv7EHdLfJWIrz/HvRSla0jP1
         I4C+JHsvUMsqf//aLlpAy5UI/Og4Y30xaD352MRTAxE1bih/S7ceK3vtvFTyMwBmpZCC
         5ZP8r6fRec7k/92aQrffyOdzEqGso7Cujtc/TcU5OkCkSql0HCUhdKGUBcR1vemqS3l6
         b4JSg3/2Fv4xa69ZyG+8J2nO/LWs/VG4sdppeRAmwd1AJMZ07Vx38z/xXp4bnbl9PnCq
         /wLXDT16krdw6nh68qaRVZIdyCaNXd2F6jzgnKpHHH4WNZwVGdc6aJmNimB1tISUZDld
         7MNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=DuN/fEwKhCSFTr6+YhFwlXQbFJgJ5LGQ3Wa6HZ4sPZ0=;
        b=WVMisCpFPtAdeUfLz8kgUXYzwQVw+IpCYkzBpR5JEviqtKZjpq/c4mcWzC3NnRfWrK
         fGk7+7MtobchkHFLIs+Y1vvmK+09/zGX/h/U05wmzcsXURL/oDImq6+XmTTbMQ0f4UIL
         +wK+mlCLopV6fOZJ2jl8dHUQxcwtc5U33RBGVPmJPr+lEumdpsXLFHzW/L65OUReY6Z0
         kw4Og6yRj9cR7Cc7aexU3ObKs1ltCMkvFry0dwHp8W6sItOX/aEIv8AurtafSWNtQUG7
         KqYIOiQPslHnGW8bqMQCDbJFXaGSmFRZSbRwsLVqkgXEuF/yeUrj0GofumC/qKLHetDc
         ibGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b="C/QaeHLc";
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=CE0FJDq5;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from wout5-smtp.messagingengine.com (wout5-smtp.messagingengine.com. [64.147.123.21])
        by gmr-mx.google.com with ESMTPS id az16-20020a05600c601000b003f42786c7b4si199249wmb.0.2023.06.01.12.03.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Jun 2023 12:03:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted sender) client-ip=64.147.123.21;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.west.internal (Postfix) with ESMTP id AC642320091A;
	Thu,  1 Jun 2023 15:03:46 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Thu, 01 Jun 2023 15:03:48 -0400
X-ME-Sender: <xms:kOt4ZA_xHqfSd9_RYqeU0tHY-I1qRDgVYk7nkh_VuFNAAPpWvX7Phg>
    <xme:kOt4ZIs5inhK977IoAHvpOzRI5YQ2VRsMI28w1ZIZwpsy-4LSV5eFZEV51MXNDaY2
    j0WGqpa8cAH4l9JxWQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrfeeluddgudefvdcutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmd
    enucfjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdet
    rhhnugcuuegvrhhgmhgrnhhnfdcuoegrrhhnugesrghrnhgusgdruggvqeenucggtffrrg
    htthgvrhhnpeffheeugeetiefhgeethfejgfdtuefggeejleehjeeutefhfeeggefhkedt
    keetffenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpe
    grrhhnugesrghrnhgusgdruggv
X-ME-Proxy: <xmx:kOt4ZGC6ERAFa-qx2gxgJOc7DAlGEWcmZqsX_cIG0jQsYmt0S7C6Qg>
    <xmx:kOt4ZAcHYho97oJtWheRANisLoDF2mjLF2bYpfDULl3ACdM99-K-jw>
    <xmx:kOt4ZFMMxRbpFHYrHlhSI_2OYDfO__X7HEz-epFmBDG_X0BSzkQ2JA>
    <xmx:kut4ZM--RC614ju2WZYpsnNbcb4noPLl_tcLOEN7DmPanaWTuZEL6g>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 8F4D8B60083; Thu,  1 Jun 2023 15:03:44 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-447-ge2460e13b3-fm-20230525.001-ge2460e13
Mime-Version: 1.0
Message-Id: <bfcb63da-eaec-44f6-bcf3-7a15ed745b6b@app.fastmail.com>
In-Reply-To: <202306011127.B801968@keescook>
References: <20230601151832.3632525-1-arnd@kernel.org>
 <202306010909.89C4BED@keescook>
 <f6fcae8a-9b50-48e4-84e9-c37613226c63@app.fastmail.com>
 <202306011127.B801968@keescook>
Date: Thu, 01 Jun 2023 21:03:24 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Kees Cook" <keescook@chromium.org>
Cc: "Arnd Bergmann" <arnd@kernel.org>, kasan-dev@googlegroups.com,
 "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Marco Elver" <elver@google.com>, linux-media@vger.kernel.org,
 linux-crypto@vger.kernel.org, "Herbert Xu" <herbert@gondor.apana.org.au>,
 "Ard Biesheuvel" <ardb@kernel.org>,
 "Mauro Carvalho Chehab" <mchehab@kernel.org>,
 "Dan Carpenter" <dan.carpenter@linaro.org>,
 "Matthias Brugger" <matthias.bgg@gmail.com>,
 "AngeloGioacchino Del Regno" <angelogioacchino.delregno@collabora.com>,
 "Nathan Chancellor" <nathan@kernel.org>,
 "Nick Desaulniers" <ndesaulniers@google.com>, "Tom Rix" <trix@redhat.com>,
 "Josh Poimboeuf" <jpoimboe@kernel.org>, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org,
 llvm@lists.linux.dev
Subject: Re: [PATCH] [RFC] ubsan: disallow bounds checking with gcov on broken gcc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b="C/QaeHLc";       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=CE0FJDq5;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted
 sender) smtp.mailfrom=arnd@arndb.de
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

On Thu, Jun 1, 2023, at 20:28, Kees Cook wrote:
> On Thu, Jun 01, 2023 at 07:50:38PM +0200, Arnd Bergmann wrote:
>> On Thu, Jun 1, 2023, at 18:14, Kees Cook wrote:
>> >
>> > i.e. fall back through these:
>> > 	-fsanitize=array-bounds (Clang)
>> > 	-fsanitize=bounds-strict (!GCOV || bug fixed in GCC)
>> > 	-fsanitize=bounds
>> 
>> From what I can tell, -fsanitize=bounds has the same problem
>> as -fsanitize=bounds-strict, so that would not help.
>
> Ah, did something change with GCOV? This (bounds vs bounds-strict) is
> the only recent change to CONFIG_UBSAN_BOUNDS...

I missed this problem in my usual randconfig builds because I was
building with GCOV disabled due to disk size limitations until
Dan Carpenter pointed out the specific issue.

I suspect it's been there for a longer time.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bfcb63da-eaec-44f6-bcf3-7a15ed745b6b%40app.fastmail.com.
