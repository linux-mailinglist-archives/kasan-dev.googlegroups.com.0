Return-Path: <kasan-dev+bncBAABBAVBR6KAMGQEXWDIYGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BDA352A85A
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 18:42:51 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id bv12-20020a0560001f0c00b0020e359b3852sf790358wrb.14
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 09:42:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652805763; cv=pass;
        d=google.com; s=arc-20160816;
        b=XuRrhTavse8NNYN/IRyvVXoqhZGrW5lVQx8bYShsdWrB+ZBa+MFm/ycpGn2yAL+nDY
         HEJdiOXRORF3vN1hbJoWfNlxEn4fhMPCL4MXV2PTYJSAkU3YgfmcnCG8fqGc+YXQ+kZc
         8q1Kh1d3eOUZVJnjN9C7vnFDe2boWuJ1pvA1yyVvtvpqbu+OF2mzRHgU9iCT5zhYljAb
         y6PzEt5AfOD8JhivLH270N+1aA6r8alB+DJq9eXIHbm2zB46kqzvi4yMw0BW9Vo8er+w
         ZgonTKHImczafjsyWbfK3bKdc23PTjCjhaFu6LNxeqXJzrFqz+K+TWE2mDM8mLPuoGrC
         CKZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6CLrNBFRB81t20xxiRbEAlv/stTO2rRfMYAxePuYbJw=;
        b=GWZkrSQhH1Yk9xs+XSR+KumN28MLlvxMwaARW7wdKHib7sYe4HriwyfePSkKz0m05e
         s3QYCrLmcCh9106MAVtfXWusxoi8+OlruBU3Yhsj51imhMsKRGWKiLG302titJN61Rb3
         XvykyPFgh/8B7779DcP/Zg8g708x+gVUD1L9d4EA8DjLcyzy2AzduWiQwcU1M/nx2jqg
         bLHS8shpzDDmxZE3IlvwMA3aKSVTwZF9wtssss0TSlthMk28y3WgwBwFzIj8KoW6p8+S
         13H81dN3Cb8jOn1zY9he3SX/lREPKJMJw2vw8FFPMGO//81QJwbUatJEbM5q8m8bgHfn
         +w5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hQeQSS+V;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6CLrNBFRB81t20xxiRbEAlv/stTO2rRfMYAxePuYbJw=;
        b=ONjfNWWxm5PNRWc6nk25EMNiyk08zelcZ8l5IdgJVxuiXl12VMWSiUK9QxjUx3ctmS
         RNPPnuKDjBMVhMeIsRyKDg0u0/U+JXnVL6k6sLgRFDiQYJpjizCBv4VfdIVqMKDQI3xb
         6MltLBT3Atk5h1a2wDgBr+2llh5z3/iRzSIY/l1bgDF5stnBnowvsvSg7UckspC0nox5
         DZtMuy56M7tGgZCNKRjbTvhN0DEsox7C603LKd+038nZMzMpjhoeuKwD2uVFchX0HOqz
         aobhng+A2eNEMvwp5Lgn+xsfNeiL4V6Ty5PgbMRofGjZk9BOSDkCfKjBneoDAWyw2i3O
         odPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6CLrNBFRB81t20xxiRbEAlv/stTO2rRfMYAxePuYbJw=;
        b=e4OVvtkfVtciHHCnuUyrDNB4+Q0IQSU32B2v41Vo7oNg4lDlzBBIttMOJqc8uCArbk
         CaDiPvnThYItb2VDQ/Lc887rmV7Tc9qn+HyiRwO/zrrJIk19xaTL3v/b9lD4ZcIZE9OP
         kuqrJU9dTQdsPToqmYz1cnF0ba73A3e3mp010RXBs8UvN+9X+OZOHrSIX4vlf5TmbM7b
         8/JtdsSXwQnpohTiEkMOxwrh/+zaGBXWZLNIKnt9x7Q6+pDkAyc42BirA00alAH55EoS
         4T2LTLzNNoCFwYviYhdHO1GSVmDy7JkM0VfmTChZn3bvd4cAPE7ApDjoZVDf1WhgsAJE
         RrKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TlNBonlizfNtCW1L//cDeO1mVD6kK/pV8FGGeZJORKg08+qXA
	LtJKKnlR/hi8nJ4OErosT6c=
X-Google-Smtp-Source: ABdhPJxXeqY6K1F32Gj9GExADzXd+su79CUpLAJrmeOmLj57DqCmoKnYoQgn6nAfVhQ9hXUN6AkfTg==
X-Received: by 2002:a05:600c:1c97:b0:394:7a2e:a83c with SMTP id k23-20020a05600c1c9700b003947a2ea83cmr33048559wms.175.1652805762664;
        Tue, 17 May 2022 09:42:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20c:7b09:42a4 with SMTP id l4-20020a5d6d84000000b0020c7b0942a4ls3748469wrs.2.gmail;
 Tue, 17 May 2022 09:42:42 -0700 (PDT)
X-Received: by 2002:adf:cf0e:0:b0:20d:db6:aa0d with SMTP id o14-20020adfcf0e000000b0020d0db6aa0dmr7150801wrj.573.1652805761895;
        Tue, 17 May 2022 09:42:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652805761; cv=none;
        d=google.com; s=arc-20160816;
        b=d6NpYQ4gG7kRx0u53BOw1xSQtUJ5vEmhZCbQqWVOTGKDU9zdDPFvQRaru14gfxJiNs
         o2tECsvY/biR3nGl1z4A3p9XxEzCub54ohxifPVpmlskomY1ive5fIQv11CK8fbjLUmF
         GexrD5yH8pu4s6iZOCZCWQVbitOqnMtc1z4hJLbNRstHN7DCQw4avBBxwPLeLTv+5+qb
         inHn497HQXctgTRX0WMweQB+ADyjkxL1kk4dt+BZYWH1V8LFcNoZ/Mh4/jCbd5U82fF1
         +6ePD9Hq32eNC/kFSNy1x29LUkjqGPhdOVIPNnXoposoU6BEgYA56P3PlEVEoFKCORh+
         XLEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yscMU/RU+AXLwmB6v1rGAUVcwDvl6A89GKD2cL8coQ4=;
        b=VaWMij4jszLfU4FKQ04G99vhxtC0bZRhZDPN+q8kc9WXK9RQnGTMW0bkC2eW520gPR
         PHoJ7uzTNLLNZNAt9cozMimaUNqdLWioFLvr8HGFtwMw3dPuRfhSvRN+NTIXFznApbHy
         FRf1T4e1UMczkaBXFVmQu0lCisNHdFFlfIW8fN0vTmbCkxbDP1FqObIsk0ugNZ3qI3O8
         RsSfIoRGhg6z5tT0tvBCBcT10HClTDsrjpnHsc9u4c19/rs4FM4ncg5wwUZX1D++9FIm
         +OAQUFpHLYSe6ZcIOd0GeLOa9gzD/fWMEUiOZr/kOVKOcKzSlg5N5B6bQfOwaLNNhB87
         Q0pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hQeQSS+V;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id p33-20020a05600c1da100b0039469a105f3si154042wms.2.2022.05.17.09.42.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 May 2022 09:42:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 77DF0B81AFA;
	Tue, 17 May 2022 16:42:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 73A2DC385B8;
	Tue, 17 May 2022 16:42:36 +0000 (UTC)
Date: Wed, 18 May 2022 00:33:52 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Anup Patel <apatel@ventanamicro.com>
Cc: Anup Patel <anup@brainfault.org>, Atish Patra <atishp@atishpatra.org>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	linux-riscv <linux-riscv@lists.infradead.org>,
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
Message-ID: <YoPOcHvhWEqeEwzo@xhacker>
References: <20220508160749.984-1-jszhang@kernel.org>
 <20220508160749.984-3-jszhang@kernel.org>
 <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
 <YnkoKxaPbrTnZPQv@xhacker>
 <CAOnJCU+XR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA@mail.gmail.com>
 <YoCollqhS93NJZjL@xhacker>
 <CAAhSdy3_av5H-V_d5ynwgfeZYsCnCSd5pFSEKCzDSDBbD+pGLA@mail.gmail.com>
 <YoKIv2ATRdQfYbBf@xhacker>
 <CAK9=C2VJ-+bu20+QOfKrq6cEBE93Yi21U=zU9AKOSQi1GGHWiA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAK9=C2VJ-+bu20+QOfKrq6cEBE93Yi21U=zU9AKOSQi1GGHWiA@mail.gmail.com>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hQeQSS+V;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, May 17, 2022 at 09:31:50AM +0530, Anup Patel wrote:
> On Mon, May 16, 2022 at 11:02 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> >
...
> > Currently, RISCV_ISA_EXT_MAX equals to 64 while the base ID is 26.
> > In those 26 base IDs, only F/D and V need static key, it means
> > we waste at least 24 static keys.
> 
> If you want to save space of unused static keys then there are other
> ways.
> 
> For example, you can create a small static key array which has
> many-to-one relation with the ISA extension numbers. For ISA extension

"any problem in computer science can be solved with another layer of
indirection" ;)
I see your points, thanks very much! But I think the array should
be a static inline function to make use of compiler optimization to
avoid the array references for performance. And the static key check
maybe used in modules, I want to export less vars.
I'm cooking the patches, will send out for review soon.

> which are always ON or always OFF, we can use fixed FALSE and
> TRUE keys. Something like below.
> 
> enum riscv_isa_ext_key {
>     RISCV_ISA_EXT_KEY_FALSE = 0,
>     RISCV_ISA_EXT_KEY_TRUE,
>     RISCV_ISA_EXT_KEY_FLOAD, /* For 'F' and 'D' */
>     RISCV_ISA_EXT_KEY_VECTOR, /* For all vector extensions */
>     RISCV_ISA_EXT_KEY_SVINVAL,
>     RISCV_ISA_EXT_KEY_SSCOFPMT,
>     RISCV_ISA_EXT_KEY_MAX,
> };
> 
> extern unsigned char __riscv_isa_ext_id2key[RISCV_ISA_EXT_ID_MAX];
> extern struct static_key_false __riscv_isa_ext_keys[RISCV_ISA_EXT_KEY_MAX];
> 
> static __always_inline bool __riscv_isa_extension_keycheck(unsigned int ext)
> {
>     if (RISCV_ISA_EXT_ID_MAX <= ext)
>         return false;
>     return static_branch_unlikely(&__riscv_isa_ext_keys[__riscv_isa_ext_id2key[ext]]);
> }
> #define riscv_isa_extension_keycheck(ext)    \
>     __riscv_isa_extension_keycheck(RISCV_ISA_EXT_##ext)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoPOcHvhWEqeEwzo%40xhacker.
