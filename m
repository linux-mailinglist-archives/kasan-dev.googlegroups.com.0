Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYXOQKQAMGQERVXFHZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F1696A8494
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 15:49:07 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id d6-20020a92d786000000b00316f1737173sf10224571iln.16
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 06:49:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677768546; cv=pass;
        d=google.com; s=arc-20160816;
        b=a5lW1k2/HyKmZTaij1KumPtnNBP4/wy07YNuEWGZlASVnMbRGEutOoIE3EMbGUOW9/
         ngNAgegJSLw+McZ1g1Jwxe7bI2Bg/kwm6Z775mPWy8gv8KsnKZqPuEZfM1IeRWONAUpV
         O4PxcsrO5RRHnTM7YYpTxfdjhTk85R2zHwNc0oGe35q8IAX3Bms/QPn/a5dDoTOGE1au
         ZyppOI2AWttRr1lN1NaTGZFBCbRmycVq1LohAaBYas8wW0thRCFlC18CabQa84WsOdIG
         +r9PNNUH43XnXwCWnvWAXfU4nZ/IXAheZ2oLw+MnObYFm3CfUDDiI6/VaSTsTSl4xfq/
         naRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dPutv6IEUk4Ij49Sqk/xkCDI8rUgvcwk/szDK4cC3ic=;
        b=abLUftvvEnFn9oFpMvC/PXtHwh7VB0vksgcWvzmLIsTggB5mpVhqkiZBI1R5wXJA03
         auHJLDUr02ZMb4G5wI8qDD8emukgy2KplIGGozuXWD0l8nLG9/fjA/fVsWt5Fe6Jem0n
         mhWUG83KA21J4QoKPVBICYQBt90FlDrb58gbcwjxTG8z3QnaBJh6cBgqpMOf8Sh03+Sn
         xjPmyLeuPQdtYHPJqeRSiELSAXVPHga3JYNNs9wekDeps8Z1B591paV0TOi8VgiNKHpP
         bTU2+3E0PCu77fk/fE4xqShDsZRRB8uiR77UVDCpgMh5Tf+nckFXngz96lXekK8D31F3
         4LBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=of2jhdzO;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dPutv6IEUk4Ij49Sqk/xkCDI8rUgvcwk/szDK4cC3ic=;
        b=S2KsHKDl0kDe+VM0TtQnDnv6cMnYGJKaix7+k3WSKVMeD7awrG4JE49EOVNiI8k+VK
         gRVCeURJ1SO3CLh7yJOpEoVKIRZPz3PI2IGaPi36qMXX8R5mwNiGL50REuMs6EEQhbsq
         9L2Eq6anUndwHu6qRyQy4A8dxt006ZPR3RVrFNhk+6TH5NV8PwJuU1m7wZwsVqHghIxS
         J/mLAcc1Lqn4YuTqce1N5x9s07Cs1iA8XFmi7OPNuqODH9mh4hi7zgK1JS/yVFyK9Be4
         abELeQZM9zls54t3GE9NAvM7UlUWdZb6WzCXPM9zRaisJ2zlTpQ+olN/RZ/7HlemTcQF
         7x6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dPutv6IEUk4Ij49Sqk/xkCDI8rUgvcwk/szDK4cC3ic=;
        b=kEuRg2o1SKchDiTtk8Gf5IMCGd5bFUOyd/5tADJY62FSpZwuJlT/6FIpZrLO9oTKQ2
         CKHpmNFRELEOCNzbeJ7GriX3PxizkA3zNLVaaOEo49FLji87AFrLPpS6/vBiE5P2WC4R
         TPB67LVdIOLyuiam14lLoG9qLTYKB9urrPeHRlwr6GnJSD5jFCuEpT4u+IBqzzvxrj91
         Xc5B8BIlAyPjzJ6hcg48WnPRhIp8NUOXV2JLhDkvKByBqOym/DjNKiJNiH6rr7zSmNZ2
         ziXsehY5+k84eSPo9C8BIyuOkCsoylZcVOurm9LsZouWLMtv3Vf8hgOhKoI7c3EwzksJ
         prbQ==
X-Gm-Message-State: AO0yUKXdehyhZfTmm6D/v1XqQEVAvim9Dp7g4TujroxsdSsu/FaS87Tg
	OX0XRA1FLANTBNdiTolC/Ss=
X-Google-Smtp-Source: AK7set8U1aXOadf9B6ordY2S+RTIaPWEYgGCbgwf/mM7X5M00dE/kjwRJdJI9+67e30lRYaroiB/cg==
X-Received: by 2002:a02:2282:0:b0:3b5:733b:daba with SMTP id o124-20020a022282000000b003b5733bdabamr4734112jao.3.1677768546410;
        Thu, 02 Mar 2023 06:49:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:ba45:0:b0:74c:83ab:5b4c with SMTP id k66-20020a6bba45000000b0074c83ab5b4cls4522717iof.4.-pod-prod-gmail;
 Thu, 02 Mar 2023 06:49:05 -0800 (PST)
X-Received: by 2002:a6b:7d0b:0:b0:74c:ecb4:6e83 with SMTP id c11-20020a6b7d0b000000b0074cecb46e83mr7895151ioq.11.1677768545739;
        Thu, 02 Mar 2023 06:49:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677768545; cv=none;
        d=google.com; s=arc-20160816;
        b=sDUUBHuLNuaysKuurZgU/+9808qnXV4Cxik3RMOYQ6g7J+w5WtbBtKpveEy85GdO/M
         Y7vQHKC8s5PDaoGfIbN8TtISVAk+ummuXRByEfMqsnSj5mM0Ny7waX2r4jeR8n9u6shN
         F9ANWES+tAyOZXJxLTlyNnMX+NFrub6uEdRa9EUTfkW5y85YgXAXdXT7AI8PqLvP/wi1
         Gers2IM47eP+1zBpPmMl/9GjFQ9S6KXyuoO7raN2ALLCyQn+DM+OXDBhd47mVhgrQs3b
         6zzKeJU2nPv1QB1yS8j4kBOFLG4mBgl+FWe/iLTD92wroaeKACoLsY2E9RPb6Vg/Ew+y
         8OAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2l3NQJUTH3/qN89xY5bS6AJLfJmHgspkf61yJ8LdA9c=;
        b=vcTVWSWajlCJE6ITWbLRfEx5UIX0VNBCQSXeNIaIFPrqrvRqz6dxYthgw3SzxaGLAd
         n+yFb82MDHdzMZARuPbiwjcSn6fSI8PZjOvnWzmFVLAWlWfZUf+5dV/nbVTb9IWykAiF
         UatwS8eBsw1D4mHPGN6JwgNjUe+IHhcV2Va1eua3Sym7lIZjjCS5N+zJcMkT8CSIXjFM
         bTPoqhm8MupEVZfDRN5KvzleXnQw7tym4IEaHyJdFmTCXoikBvpWkklZ7BVoikoTDl1G
         i6ssR9WCBIohbU6q8P7CZdyk9AzPUeOVago4j0TjzU70i4HeKx8/fuAifA7pQOGKAmrG
         k4RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=of2jhdzO;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id w3-20020a056e021a6300b00316f4a326adsi638199ilv.4.2023.03.02.06.49.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 06:49:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id v10so6822985iox.8
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 06:49:05 -0800 (PST)
X-Received: by 2002:a02:940a:0:b0:3ea:f622:3c7 with SMTP id
 a10-20020a02940a000000b003eaf62203c7mr4693665jai.5.1677768545351; Thu, 02 Mar
 2023 06:49:05 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <20230301143933.2374658-2-glider@google.com>
 <CANpmjNOG=T8R=BXO8PUX3FJQnKQfPjNyLGJ0wG5G_4_mHwJ-gA@mail.gmail.com>
In-Reply-To: <CANpmjNOG=T8R=BXO8PUX3FJQnKQfPjNyLGJ0wG5G_4_mHwJ-gA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 15:48:29 +0100
Message-ID: <CAG_fn=X_E7r7JnBKWTygwiTa7HWJ1=AhtJOoH7is_mz0fhgfXA@mail.gmail.com>
Subject: Re: [PATCH 2/4] kmsan: another take at fixing memcpy tests
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=of2jhdzO;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> > +#define DO_NOT_OPTIMIZE(var) asm("" ::: "memory")
>
> That's just a normal "barrier()" - use that instead?

Ok, will do (I still think I'd better hide it behind a macro so that
we can change the implementation of DO_NOT_OPTIMIZE in the future if
the compiler starts outsmarting us again.

> > +/*
> > + * Test case: ensure that memcpy() correctly copies initialized values.
> > + */
> > +static void test_init_memcpy(struct kunit *test)
> > +{
> > +       EXPECTATION_NO_REPORT(expect);
> > +       volatile int src;
> > +       volatile int dst = 0;
> > +
> > +       // Ensure DO_NOT_OPTIMIZE() does not cause extra checks.
>
> ^^ this comment seems redundant now, given DO_NOT_OPTIMIZE() has a
> comment (it's also using //-style comment).

Moved it to the test description:

/*
 * Test case: ensure that memcpy() correctly copies initialized values.
 * Also serves as a regression test to ensure DO_NOT_OPTIMIZE() does not cause
 * extra checks.
 */

I think it's still relevant here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DX_E7r7JnBKWTygwiTa7HWJ1%3DAhtJOoH7is_mz0fhgfXA%40mail.gmail.com.
