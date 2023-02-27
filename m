Return-Path: <kasan-dev+bncBCT4XGV33UIBBUOX6SPQMGQELZ4HJOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8118F6A4DD4
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 23:16:50 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-536cad819c7sf168170017b3.6
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 14:16:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677536209; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lc1L/Nf/oehQV26uNmjNtfyXs2vpOJ9+N5dmYPIA7Fm7/01mS4jcs/yCAKiih2Jg+w
         syexMYSqJ4oUDKTAx1TEccLg4RNSKumi77PA7xnVcZ4l3h8vveqdl+V4tUqNvYxyvLIE
         /H+uTKPRNSosBaZ5nwgHdouU2hRFqMplHZ7j1AULy2ot8ApgHp8rf/wz7H94X6+FDDF1
         1Ikbef+fvNf2CWs9C0vVV71K4I9Mp5KdzlPQYedIKqydGdlDUXZyyAiBlmZIi+TYGn+F
         phsKmRA2YtsWe2b9forcB1tyWAL3/JokIEdZ9noEkljBmHgGZYo8KXrODYjb2SM8TCmW
         r7GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=dof0eOdmxnM8cTMZViTErfYSPv5/RlRGr6Zu5e9UeEs=;
        b=bBZym/6Wi6griqVBuUUnzYQA/oUzdTTqN/zeetQdwROgT1UldhF0cD0SvxvL8Wkv/v
         RHAwuGxa6x26iYJAudhBitHz4mybKcVTkx4qkgO10wx9fs+gobJLFcWulGC04Ba+lrK9
         JKwNSQ+eChFQIX9sd0ClXtP/DN5pk+QYDetPNDFRd5HCO5WkXcU6DKMEC1sZ2swXyoxn
         taZTQ8COaxnCb4av3DGd3cko2jnY0J5ED3LL6544s8vD1C5zsW7wQBF0hCaClj5fB5CH
         L4Fgl8+f58LMhXevK1HL9eXEB9zn6LQai0DCgMWhLzrHzuWHBkCfK/VbKylToYFdagcE
         V4Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=npNn47k9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dof0eOdmxnM8cTMZViTErfYSPv5/RlRGr6Zu5e9UeEs=;
        b=e7G5CkqxjcT+k8HDq1v++Wc/ID0B2gBOTjckAZBhditK9bODZ7FL/YPmsz0ar9Euir
         IwNOdOZ11OT0ZUBITrwOEg4C29gn+chn4gR8maM/pazb/BHodGD9XZUp+YwbA2MLww4E
         Tg8LEXQ8KTs76QLONtzxn+Q5U532k3E6NX0JcvCj/2bJ1jwSDrHx8Ln+cmW/m9rZTnXm
         YxMFjgLB9QZ14/nxp8IRygCcO/5qidsvSfez68EcwN9WjALtNKm+gg7QiEaZZGL+Eu8d
         q5Pv9U6u1D9GUmONrp+WxxmqmfOej0F0Eo2vVmJqc/4jXXEBrW4wu78fekK//FDKrQMP
         HDaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dof0eOdmxnM8cTMZViTErfYSPv5/RlRGr6Zu5e9UeEs=;
        b=Dpx51SRxTdF61WTNjCCW/nZzY70htn+1KFroj4YU4oYUgAoMGMl8RdZeudFqLNT5Bx
         /p6VkWlBJSBTsMWRj8b+kWgbFNse9d44S7xt97QYl9fGkTUkwkDMPB6yPneUkBylL+R3
         rK7a7pUML80rbU1AMap7wCwPD1/jVTjg2Rkz9suGGgOkfPJr5I5Mlw1JTRMuHu4o8l56
         DZJUidKWuofGRYrWx4hrN+QM+fqk4n52mytPhlzzU66oR+Ruq6o3hxT+eIMZdSeeF40y
         J5Lju/e1DwDqCVFwccmnQIzADdLuzXH5eTjKeeoOx/k0dmR+869BNh/o9vvBsf4b1UhA
         usJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWozbYdImDeaD4lm6gX2KYk0zItTJYDQmt29FzsKHQtKqwZYzpM
	G1rMvfFIPRqEWx5EdvqNTM8=
X-Google-Smtp-Source: AK7set/OLd3Kyip26hqqnpXXz40oq8S9Pcb0qA+/K4GBjryMYlX43y9SmWQShgJaK4moywYFgs3jug==
X-Received: by 2002:a81:ad67:0:b0:525:2005:7dc2 with SMTP id l39-20020a81ad67000000b0052520057dc2mr210663ywk.1.1677536209240;
        Mon, 27 Feb 2023 14:16:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:d8f:b0:538:65bd:da4e with SMTP id
 da15-20020a05690c0d8f00b0053865bdda4els7074296ywb.0.-pod-prod-gmail; Mon, 27
 Feb 2023 14:16:48 -0800 (PST)
X-Received: by 2002:a05:690c:29d:b0:52e:e90b:5e2 with SMTP id bf29-20020a05690c029d00b0052ee90b05e2mr9910864ywb.1.1677536208590;
        Mon, 27 Feb 2023 14:16:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677536208; cv=none;
        d=google.com; s=arc-20160816;
        b=cE3tZDysazJmApCI0wJh9baOyGcgV5nYhTBkE+hSDoPYKqk5jIkRWhuV79N5WMu/56
         c2KIdV+EVhKpj0cz0VhvjPpB4mQCitGHsDkfLn2dYcet+pa6MEgZS73CftQPfQyfQFg/
         aYRWOFcbHtxaiFaE6KG+3WDPheg/dpi+yIpfaSZoZ1bpltR0yU8KcceoQHiHL2AN/K9u
         gpWHqbRqsg6tiP14Kg4j1he5m45Syms7uHmLgUi90zQdDa2JXs5wo67c9HJJrdhrecIX
         tScISqaFoDTgyA6z9wpEBHHBkDMXeGPb9Y9+FQafaifsxAQU7e0f+NTDaZKZO++pMLtF
         o2kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=K7EXgnX1JwxKA36K5U4FUv9GXeR6A34QIp6oZXH1kGA=;
        b=LCksIcVQcdf0QbNS6ApfCvSzfg3O6ZQCZrPq14A+O+Y9enltSHY8v5WQy31Qzm4sqz
         QAPtwqwXJSMU9Xgk/g7iiXpYVLn5wOAepZ7K28JTpfO6tkfqFpSVydvd/iQPXBeYyv4y
         PtWLpsmT1xVzXlv7N4FQ0kxX3XUj3kn0AWHPRGCNeESzWEcKRBearbIOqgtArnNQD1H5
         Efg20p6uQBHhoz6UFDeYMMyEpqyso5gM+FmkjI0ZhsLdD+/DX9XePME9mJHNPY/ae8m8
         idfNFMBwLHKPoQee0hVxor5XKq/h66Nrj3r3obuJULgjV2ojz7A+KXT5WBAWYVEh7e2E
         +0pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=npNn47k9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bp16-20020a05690c069000b00533bad9d28csi774905ywb.4.2023.02.27.14.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Feb 2023 14:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1B00F60A48;
	Mon, 27 Feb 2023 22:16:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ED0EEC433EF;
	Mon, 27 Feb 2023 22:16:46 +0000 (UTC)
Date: Mon, 27 Feb 2023 14:16:46 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>, Liam Howlett
 <liam.howlett@oracle.com>, kasan-dev@googlegroups.com,
 linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, Daniel Axtens <dja@axtens.net>, kernel test robot
 <lkp@intel.com>
Subject: Re: [PATCH mm] kasan, powerpc: Don't rename memintrinsics if
 compiler adds prefixes
Message-Id: <20230227141646.084c9a49fcae018852ca60f5@linux-foundation.org>
In-Reply-To: <20230227094726.3833247-1-elver@google.com>
References: <20230227094726.3833247-1-elver@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=npNn47k9;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 27 Feb 2023 10:47:27 +0100 Marco Elver <elver@google.com> wrote:

> With appropriate compiler support [1], KASAN builds use __asan prefixed
> meminstrinsics, and KASAN no longer overrides memcpy/memset/memmove.
> 
> If compiler support is detected (CC_HAS_KASAN_MEMINTRINSIC_PREFIX),
> define memintrinsics normally (do not prefix '__').
> 
> On powerpc, KASAN is the only user of __mem functions, which are used to
> define instrumented memintrinsics. Alias the normal versions for KASAN
> to use in its implementation.
> 
> Link: https://lore.kernel.org/all/20230224085942.1791837-1-elver@google.com/ [1]
> Link: https://lore.kernel.org/oe-kbuild-all/202302271348.U5lvmo0S-lkp@intel.com/
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Marco Elver <elver@google.com>

Seems this is a fix against "kasan: treat meminstrinsic as builtins in
uninstrumented files", so I'll plan to fold this patch into that patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230227141646.084c9a49fcae018852ca60f5%40linux-foundation.org.
