Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBGGSWWQQMGQERHJQ5AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DC866D7C87
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Apr 2023 14:27:06 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id r25-20020a056602235900b0074d472df653sf21483946iot.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Apr 2023 05:27:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680697625; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2jKl8SBiayyx3xn9znFmLDcCGkeWi8D+rOGXl7pwflVHn5zPADFhUFdMTQuteEiPY
         i+ci4LVWoyo0aaMN7APx2Di8vDSWOdOYH+n/auZrcY8IJuazqemiGJYQ5xs3Kc8m0ExT
         vU8gWkNNp6SW5bG9MkJzwaW/1BzcTjATJ3hYHTHtYrLw1VnhkFeGXMMBksVsuPJMgGli
         l1H04+79KrTVkwSwijPsV/FwnsDAn0GTenCs/9p2sfqf1a7MM2aSDM+Z3IODDQTccvm5
         JxmM+xmwiREI0ZDZlk0/tCqqAP2MwEq1BaneoPaknGRxHOW6W7uCxBMADhqQfXyga8vb
         q3VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=3g10rIr+lp2/PW41t/2/TkJTfAVCpY60rNZ1ZQ+J800=;
        b=068Kpt2Zhn9MUWINEFEiTffXiw0sbpl6UoWr5ve0K7IGpgaKRcqCE0WLkBY1bZ5KG8
         euzA75cfajYYdgPDUO5XKEjhJu/HmkUSQlNSWwhCpkhIN978SejRpPYh6Rf2I8jfrsN6
         MVDF14rKaZ+K9Sy7XQpmhLF+GxxslmTLm3l/jMGwNIIpfmu4AB5KgkAZYoXuWdNo8aHV
         fobJuvBM2IwDKCVYx8ilMVsc6Vk/c1mhB5PFHz+S9P6iXypJBZA7AuX5pH+2PfdgU8Nm
         plq5f4KUbzHp8D0Q/cid1vUH7TowCthl3eNoFP8xYb0kexjzfmxDWn8gxFDQ4Cqje+AJ
         qcAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fM4nuxkN;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680697625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3g10rIr+lp2/PW41t/2/TkJTfAVCpY60rNZ1ZQ+J800=;
        b=NPdv7wdB2fVss9AxUMEQtyu3iqtFaF/f/4i1T8y30uNrDv7nztKgjtHh2rc7baqgh/
         PqDcBHsgeqt5tdxJChmAhbD635xvg1BVHZ7V9STCcmgdY1Nc02xmW17qAE74Gqrn+c1b
         +WHkVns8F7gHNbM92+XLV8oLv7UGqm6Fwc3sD30iwxzsS0yMHntiLwbKRGgvsgt51yZe
         DcztjR79Gc4FfEn8U5iGK55H5MI0iccr/6PAxvWlKfxZkF0AdWz854rSCCkQ+g220+Ik
         usDGHOaf/bWJe7jdSSs93tkg8u8FV51QJbLhxS5QA/kmhKz27lVaxHVuKFPiy8rmeDhQ
         lIRw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680697625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=3g10rIr+lp2/PW41t/2/TkJTfAVCpY60rNZ1ZQ+J800=;
        b=Bfz3PTWa6zuxbEjMzcFkp7gs4yOmO/+ACazmQXR6sFoks3tqQDD3590MJPb5pAaE/g
         fj3GIcj2QCQkkcUtHSgGhQe9IUk0M8JoQ/XvAAqHolt9oXtx9z1lTgTkkBwzKKYz2zB0
         VtUcSuFsnnWXMLhBYFxLvQNspL2zbBS4VK5R603TI3pzmz8w08Y2kPW3nKxHCEpFj/uH
         fAjTaYZAwMYBlgn5ltMyIew51Mc9IwNBrzQZDpk/KTzd5FDMf8S+y0JdlFMBEbJexoDj
         VFIkNDFkTjvpK+qrcKbEG00RWEQLjxcMeFV6jBjD9iJgBse7FrMaE8SjlOx6rangEmPJ
         FceQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680697625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3g10rIr+lp2/PW41t/2/TkJTfAVCpY60rNZ1ZQ+J800=;
        b=fmEZh4iKcTRDY0St/jgHwBngN6+8Stmv/zKXhArsMENnK9gNTW3hvAyznOgn+6uvrR
         r563X8jrITDSX5Pb56ow4gjVhdZ24QnhOIYzM/TyuMfUdpqZjF8sfg0LapFdImCczrVm
         SqHRkv3++JpSJOZBvoUT2gEASeMVptgVwrAZ5AQcZrRjUU53s0jaHPxbSusa73r15ovR
         Ffr22dRsL7x3ayOAuTMQfhmQVa3wBS6Vz175h79C8ijpWQKNbr8hYjX6J11EmeITGSRN
         yxAIxZ68C59HfHOjnlAYqI8eQR20scpzSFcDtJsu7DzpGmMvTdnc6w+MZIZSeQ3+MYi1
         G+mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9d9d6v3eu6blF+0GigmsZsoKbfh15z6nf0UyOyxJPB4VI+ZG5Bp
	LcGpLPWV2urHWqcKb5CYdAs=
X-Google-Smtp-Source: AKy350Z1DKJR8Vc1rQaw+E5u06J1kKE+e7bqQr+v3q0G4QNYiro6kTbrCcj4P24ZFuVyS2Mxzv2jWQ==
X-Received: by 2002:a92:bd08:0:b0:326:34d7:5d68 with SMTP id c8-20020a92bd08000000b0032634d75d68mr3466537ile.4.1680697624764;
        Wed, 05 Apr 2023 05:27:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b70a:0:b0:317:9a9f:53a5 with SMTP id k10-20020a92b70a000000b003179a9f53a5ls5569204ili.8.-pod-prod-gmail;
 Wed, 05 Apr 2023 05:27:04 -0700 (PDT)
X-Received: by 2002:a92:dc49:0:b0:318:d56e:9efa with SMTP id x9-20020a92dc49000000b00318d56e9efamr4712921ilq.24.1680697624046;
        Wed, 05 Apr 2023 05:27:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680697624; cv=none;
        d=google.com; s=arc-20160816;
        b=0eweI+6rfIcW7Pi/pR4ERa5YRfjcK/SraXvVWOgHEEF/I+5jTbMyLw59jz7NjqIc59
         8Zr6GzieD5ZLSC//SA4XIHvDheioQWV7U0W6E9jrBuk5vbJt/txwrpG8evlRxaV1EIh5
         CTeuddDBmYePpCk7hkJd5t//CMY3308JhqnjQf+q1Jbk+h6LeS9vDJgV0WkIOx/nTJnb
         c3WYcTtq1NgHTHgozN+h0fsYTuX2tg8FfnpTmB7kk2I8X5aSwfXFvFRrsttSkFgar85t
         3rXJZHzyg/kPF3U+g5mCc6cKeJG1ydzwg67CLRJB1E5nai7fcsec3M1BRdZZV/Zd/MPF
         yAnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=nSvnKg+6McgJprhw+if0EMirzUlxLZrKLELfH8kmkS0=;
        b=upahilxokZ9cL/GucSWd2liiYM00B5Q0ZoclYgB6C58SIzI9CMcq3bfwTZ3bIDgNRY
         aRTi4TcNs6vnAYfc9UbKyprg/L7y+JheH5ZV8u5UB0p4b0epjqIGYrSr2ZJcfy8RbbxX
         3HK8h3sMisHGLE7e/554eL3HMIoxwaha3gxrwa8Qi9Nm3LdficV5JSyK0RYqc5sK/XlD
         tBDZBcSQR4LphSTs+O9Y/+xJbLBm5kmBqzHtKnsVX4XDoiW+/gEV1+/III1XdEyWy6e8
         crdGKUkOa62Jikiwgua9CxIcbNBBWixtaPTnhFp6IINDpx5cHBgAH6LzijzSh9j/t2j3
         Wezw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fM4nuxkN;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id g6-20020a056e021e0600b0032648a7d410si812373ila.5.2023.04.05.05.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Apr 2023 05:27:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id o11so34276269ple.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Apr 2023 05:27:03 -0700 (PDT)
X-Received: by 2002:a17:90b:1c91:b0:23b:4388:7d8a with SMTP id oo17-20020a17090b1c9100b0023b43887d8amr6718995pjb.21.1680697623102;
        Wed, 05 Apr 2023 05:27:03 -0700 (PDT)
Received: from [192.168.0.6] ([211.108.101.96])
        by smtp.gmail.com with ESMTPSA id q23-20020a170902789700b0019ac7319ed1sm10055186pll.126.2023.04.05.05.26.46
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Apr 2023 05:27:02 -0700 (PDT)
Message-ID: <b7a7c5d7-d3c8-503f-7447-602ec2a18fb0@gmail.com>
Date: Wed, 5 Apr 2023 21:26:47 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.9.1
Subject: Re: [PATCH RFC] Randomized slab caches for kmalloc()
To: "GONG, Ruiqi" <gongruiqi1@huawei.com>, Dennis Zhou <dennis@kernel.org>,
 Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>
Cc: Roman Gushchin <roman.gushchin@linux.dev>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 Kees Cook <keescook@chromium.org>, linux-hardening@vger.kernel.org,
 Paul Moore <paul@paul-moore.com>, linux-security-module@vger.kernel.org,
 James Morris <jmorris@namei.org>, Wang Weiyang <wangweiyang2@huawei.com>,
 Xiu Jianfeng <xiujianfeng@huawei.com>
References: <20230315095459.186113-1-gongruiqi1@huawei.com>
Content-Language: en-US
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
In-Reply-To: <20230315095459.186113-1-gongruiqi1@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=fM4nuxkN;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::631
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On 3/15/2023 6:54 PM, GONG, Ruiqi wrote:
> When exploiting memory vulnerabilities, "heap spraying" is a common
> technique targeting those related to dynamic memory allocation (i.e. the
> "heap"), and it plays an important role in a successful exploitation.
> Basically, it is to overwrite the memory area of vulnerable object by
> triggering allocation in other subsystems or modules and therefore
> getting a reference to the targeted memory location. It's usable on
> various types of vulnerablity including use after free (UAF), heap out-
> of-bound write and etc.
>
> There are (at least) two reasons why the heap can be sprayed: 1) generic
> slab caches are shared among different subsystems and modules, and
> 2) dedicated slab caches could be merged with the generic ones.
> Currently these two factors cannot be prevented at a low cost: the first
> one is a widely used memory allocation mechanism, and shutting down slab
> merging completely via `slub_nomerge` would be overkill.
>
> To efficiently prevent heap spraying, we propose the following approach:
> to create multiple copies of generic slab caches that will never be
> merged, and random one of them will be used at allocation. The random
> selection is based on the location of code that calls `kmalloc()`, which
> means it is static at runtime (rather than dynamically determined at
> each time of allocation, which could be bypassed by repeatedly spraying
> in brute force). In this way, the vulnerable object and memory allocated
> in other subsystems and modules will (most probably) be on different
> slab caches, which prevents the object from being sprayed.
>
> Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
> ---

I'm not yet sure if this feature is appropriate for mainline kernel.

I have few questions:

1) What is cost of this configuration, in terms of memory overhead, or=20
execution time?


2) The actual cache depends on caller which is static at build time, not=20
runtime.

 =C2=A0=C2=A0=C2=A0 What about using (caller ^ (some subsystem-wide random =
sequence)),

 =C2=A0=C2=A0=C2=A0 which is static at runtime?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b7a7c5d7-d3c8-503f-7447-602ec2a18fb0%40gmail.com.
