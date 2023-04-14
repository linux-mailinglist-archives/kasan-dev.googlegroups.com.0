Return-Path: <kasan-dev+bncBDEKVJM7XAHRBWOC42QQMGQEHVOBIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 241516E2A49
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 20:54:18 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id bh18-20020a05600c3d1200b003f05a99b571sf12070293wmb.8
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 11:54:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681498457; cv=pass;
        d=google.com; s=arc-20160816;
        b=j/e3JWdI5jsGVw1D3w9zpZU8rHSKMxxEIzTKHS74c8HGvOIwmPX5eAhjCWu8vnbR5f
         tp3dXfdbVgcXoeAVXN8LKRvOvIUzSL/iHx0wWb+g14VdNhAk79OmR5EBKhia+i9/Ewt9
         aMAp0goGeUaJpW5vFaDSlH89sg2kcqfbgkSprpuQcu8u2j+sXbieJzlHFXXCOejNHA7J
         sCMrxXIjgqJufC85JIzlBNECJxNTzOKa2cq9shRlnszt39f7YyWi/brbVmKWFPKIwZG0
         lqxk2HRHuFXycYNJU12dBzeEjxRlHqt0rhuE6SP7f4ajWvnaoA9dEaNXPM4/je/fA1K/
         cDgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=Yia5PiBp/RAdyMCGd9NKzbsjyoduT0gqaNiw8WXCSUs=;
        b=h6IE7TlsepXzEuN64HIGMkj047fEWysQImsdyM9DvY+Kn3FPU6yo6pi5pBLjyhhy8e
         4m9L9zOJf9+LOoev0zWYbX8kK9MMS+zNdrmz8JA6SjWcAp0FTJI9R7df5/7S8yw2fPnP
         DjAiGE4bRZbpsPnPEKQfO7Bsj8JL9qI1ensFmrW2tSuVsfY+S/Ag11t8u/S3HEmxV0i1
         DIkAqK7Xk7s4Dw0i44oWjINeggxuqqy1Tdmm4s+r3MJn5nwsqP4mch/ArUBhE56pbnQs
         jl10v8ClH5SuK3Jf33g717vSD/3AVgbEhRxVMPKbte9NgRvznuudqhTL11emnzkf1Rfh
         2xkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=GoP8TIfV;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=D97nFEMz;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681498457; x=1684090457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yia5PiBp/RAdyMCGd9NKzbsjyoduT0gqaNiw8WXCSUs=;
        b=KkODyMqlKitUH9h6FEJI4O82EJOz2sffqbp/YfXtGBIcVYszlrzHpAA82QzgGefDzZ
         evT+fVZnTCazvRbGrx4cWNx5c10yt2JnVExVg6dPW43yDv8oungMg9jpuhpE6QMW2IEv
         M3y4qfPaJbzUlhVLXyeDTXUo3y8QV0sPgZpbDbTbLstXzyMk0coWijTn4Z5Fz7o13hKV
         sGjxq8sn8gq7eqU9NZN/QyMN2u3EmZ28WOO4b2a1KfAn7oSS2MhIfExYOf9Kveh+ziXa
         GnnHG9PdCErygA2rpak0F16PQipf7xg29Bgwaewj1m02QaevE7/kxLc7GEea+3rYaBJw
         mzEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681498457; x=1684090457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yia5PiBp/RAdyMCGd9NKzbsjyoduT0gqaNiw8WXCSUs=;
        b=hUMq0hwKWmJy2BMkj6dqiqpUt7FLbxFyLRLFHbhCv4I/CK40jm9Vu4ztsxJl3daIJL
         nyvpzv94Mg3hxtOcdhYfJE7bLJCEgLxs2QWvDiXO1wkIxFCYpHdRZVUxBd6iwnpibKPE
         VpbagmNE10NZX/4lfXvyoHG2yfIUFWk2tpNEKNahdR3+I1IBa6HGO4S5AndX5fUvE2Nr
         Q9oBXRJcJom9QD+84yco3Tt2xi4OLflPosX5ou3d1QKS5PRX6AIToU/hj5O4jjSj8UWU
         lH/wqUi2w6NYKfAnIBrhRIwNnh6eQ0SRpK8XRXgC+cvo8ArKQsW/wKGAdoLd+A2wl6im
         q+Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9czHgjK3/S4yWiQPunqQ0Vva6NiiKkngncHHPshA2wN9iYoofIX
	hUJ6kRIKsQbC4X9UVamGUDY=
X-Google-Smtp-Source: AKy350Zxa/gKKVvlzLz0G7FZ6xvqbEnB27mFwJjmvyaE0FkjeDeH8j0DuzUILv8h2nxu0wAQHFcppw==
X-Received: by 2002:adf:fec7:0:b0:2e2:1f55:7ce9 with SMTP id q7-20020adffec7000000b002e21f557ce9mr1363087wrs.1.1681498457494;
        Fri, 14 Apr 2023 11:54:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c08:b0:3ef:2ea3:191b with SMTP id
 j8-20020a05600c1c0800b003ef2ea3191bls3040969wms.0.-pod-canary-gmail; Fri, 14
 Apr 2023 11:54:16 -0700 (PDT)
X-Received: by 2002:a05:600c:b4d:b0:3f1:662a:93c4 with SMTP id k13-20020a05600c0b4d00b003f1662a93c4mr61826wmr.36.1681498456158;
        Fri, 14 Apr 2023 11:54:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681498456; cv=none;
        d=google.com; s=arc-20160816;
        b=X1jPiqqYy830Fhtyx+oNHNdHaDm5cxj05z/j4NvqJaTBsrGgWT63Y3BtEzSi6JsKkP
         UIPspt6DPdicRheAgWH+QPEcnlRBGR+k91DgBqHpVABp9Mh4NgVhbwI0/PL5wCCErI3s
         Xu3X082mwV/8Zyq8ET7qpluFAanfDOfCSL2qHu+HZuX0XF5haa9NfQw3uJUs0YRI63t1
         qWNAOUz9q1G8FTS3iFFLGU/zO7fS1YRrqi3W95zf6vE78v3bqb+ojNDEmvn3pxkfV7uN
         +bM6OHjQ7WYIFWRI3Hy77Z1PJ4iBKkxX9ZSOMu6UDQLrlIgBD8cDg4y9Uy4yTEbcIatx
         yM4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=f+eksfp3DfnIrZxYIuunG6lmnjTIyE/skvW2EyyiYuk=;
        b=OmzSEUP5ccLJIBmPU2RepKbGcHaj/kzPHOAvgz14iirx2pJ89hJ257SDRy5F5a+moN
         aPlTV7L0qwPyJgPGphp/DAlE2iV9q4kBAje7HtlDKJsRXRQEYMexpoWk7w6+ZiU4aW59
         kt3Im+rEXDtUDEHOlRs9EVc0/TVFKapnRzN5YrjFLJFD7ws34eMSIWqUzX71aJ4G48po
         BOvX3fiAYpyb9zDlgfrqfFOyCaEpKUTc+zrc5ap9sY63KzWqV5z027KUMHiasNYlOjMd
         INBl+iTRGvNUPTY/5gUQxUNlq+FOx0UdfBTIEAEw3OBlGAkcCIl6l+RJ1md+pfLEA+lP
         Xr5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=GoP8TIfV;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=D97nFEMz;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from wout3-smtp.messagingengine.com (wout3-smtp.messagingengine.com. [64.147.123.19])
        by gmr-mx.google.com with ESMTPS id az24-20020a05600c601800b003ef74ef04bdsi287960wmb.0.2023.04.14.11.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Apr 2023 11:54:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted sender) client-ip=64.147.123.19;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.west.internal (Postfix) with ESMTP id C84B8320024A;
	Fri, 14 Apr 2023 14:54:11 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Fri, 14 Apr 2023 14:54:13 -0400
X-ME-Sender: <xms:UqE5ZM__ZM91pQUfchkfPFVBlwBP1q_lOJcVa0UcAhN9JZMyMMZpzw>
    <xme:UqE5ZEsBn6hw5AePBTVzDhY3vZATfmz9OFUeI8AOlMUozilo0W95gaaBU1d2PCEFI
    PO-lk1PH1kItduvGWA>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrvdeltddgudefudcutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmd
    enucfjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdet
    rhhnugcuuegvrhhgmhgrnhhnfdcuoegrrhhnugesrghrnhgusgdruggvqeenucggtffrrg
    htthgvrhhnpeffheeugeetiefhgeethfejgfdtuefggeejleehjeeutefhfeeggefhkedt
    keetffenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpe
    grrhhnugesrghrnhgusgdruggv
X-ME-Proxy: <xmx:UqE5ZCBHYdlqxoP2L9VqXZxjYMr5fIiUa8GckvwDxOU6kGOodErs8g>
    <xmx:UqE5ZMd0tYqgyVklMk7XfHZTyK0gdE4t2WvX8fgjgNbdCadAV2bR5Q>
    <xmx:UqE5ZBNH5YvyjNTeh-BYsHW-iB9fEFjIpQnLuxZ4XesS4dcmZNqdXQ>
    <xmx:U6E5ZOfu9quh-s0aPVkxQW75nFfADwQ7etQbil9I0sBAixItgrqMTQ>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 77353B60086; Fri, 14 Apr 2023 14:54:10 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-334-g8c072af647-fm-20230330.001-g8c072af6
Mime-Version: 1.0
Message-Id: <24ebf857-b70d-4d94-8870-e41b91649dd1@app.fastmail.com>
In-Reply-To: <20230414162605.GA2161385@dev-arch.thelio-3990X>
References: <20230414082943.1341757-1-arnd@kernel.org>
 <20230414162605.GA2161385@dev-arch.thelio-3990X>
Date: Fri, 14 Apr 2023 20:53:49 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Nathan Chancellor" <nathan@kernel.org>, "Arnd Bergmann" <arnd@kernel.org>
Cc: "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Masahiro Yamada" <masahiroy@kernel.org>,
 "Nick Desaulniers" <ndesaulniers@google.com>,
 "Marco Elver" <elver@google.com>, "Nicolas Schier" <nicolas@fjasle.eu>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>, "Tom Rix" <trix@redhat.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Michael Ellerman" <mpe@ellerman.id.au>,
 "Peter Zijlstra" <peterz@infradead.org>, linux-kbuild@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev
Subject: Re: [PATCH] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1 for clang-14
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm2 header.b=GoP8TIfV;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=D97nFEMz;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.19 as permitted
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

On Fri, Apr 14, 2023, at 18:26, Nathan Chancellor wrote:
> On Fri, Apr 14, 2023 at 10:29:27AM +0200, Arnd Bergmann wrote:
>> From: Arnd Bergmann <arnd@arndb.de>
>> 
>> Unknown -mllvm options don't cause an error to be returned by clang, so
>> the cc-option helper adds the unknown hwasan-kernel-mem-intrinsic-prefix=1
>> flag to CFLAGS with compilers that are new enough for hwasan but too
>
> Hmmm, how did a change like commit 0e1aa5b62160 ("kcsan: Restrict
> supported compilers") work if cc-option does not work with unknown
> '-mllvm' flags (or did it)? That definitely seems like a problem, as I
> see a few different places where '-mllvm' options are used with
> cc-option. I guess I will leave that up to the sanitizer folks to
> comment on that further, one small comment below.

That one adds both "-fsanitize=thread" and "-mllvm
-tsan-distinguish-volatile=1". If the first one is missing in the
compiler, neither will be set. If only the second one fails, I assume
you'd get the same result I see with hwasan-kernel-mem-intrinsic-prefix=1.

>>  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
>> +ifeq ($(call clang-min-version, 150000),y)
>>  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>> +endif
>> +ifeq ($(call gcc-min-version, 130000),y)
>> +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>> +endif
>
> I do not think you need to duplicate this block, I think
>
>   ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
>   CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>   endif
>
> would work, as only one of those conditions can be true at a time.

Are you sure that clang-min-version evaluates to an empty string
rather than "n" or something else? I haven't found a documentation
that says anything about it other than it returning "y" if the condition
is true.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/24ebf857-b70d-4d94-8870-e41b91649dd1%40app.fastmail.com.
