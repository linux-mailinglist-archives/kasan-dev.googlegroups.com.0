Return-Path: <kasan-dev+bncBDW2JDUY5AORBXUMSKQQMGQE4VCEFAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 750696CF25D
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 20:41:36 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id r17-20020a05683002f100b006a131178723sf4224716ote.10
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 11:41:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680115295; cv=pass;
        d=google.com; s=arc-20160816;
        b=0aKtKyxhSVyCfVTRDCxj3Vbskd0g9xM62frS5+mBnofdnz7t2F9lwvEbJqTFFUElu+
         G/6GmrGt7ionWpOPvGpmzsbQfeJHRuHTZnkl2+sLmLO3H1ll69t6U5TgnTpOkEJefNhJ
         4O6Lnu/jlL22DVfyWdLYrTKbB4n6yIphLCc+/mtZhIWPNEHbUo/rV+saG5IuP4K9zsJO
         6QqxBX/mJj0zc9apNHU251BFuOkcxZsownBsyqgO6peihXrYliB2Btk9U6LbuSO0XRP8
         h8CZbu+9wv5p9NYcQQV4W9nyPo1U0efu0VqmHp0jk6l+Pk/Sd1idIksvgoM8pA2RaR46
         6zxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=NT/+hKreNV6mN0NURWzaKcGMQyTU6lb0SJ7JT9RhIzg=;
        b=jUnTR82R8lwi3Cp4OxMvC3e8rRuStMSjoI2u97r+TxzE3tUhXXRCacoXNNC2JCGsG4
         1rAzy7bevg7UVgZdEQQafzmX/iYvsmwSpUX4g9MRv+5ZROvMD6kMn7buvvzjFXVIS7Iw
         TRwvBzdCyitj6HfaV08aWaYwWU8VYPHIc/T+Td0pMQxGt4wHme9TV7SjV7scUw6YJxhx
         alMfwFV9sqZecO17TunUx9tKIaXBW5CSZUrUA4eOJ+zBpePW8RmNBokI4R52ImWgdRqx
         TRRzi17tnELbrFr3PshDUotEs4evxz67JDyvmPCMW+Idv9Ic0Kv5zHpvzMW5vqezmSev
         GumA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ABvWcdvF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680115295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NT/+hKreNV6mN0NURWzaKcGMQyTU6lb0SJ7JT9RhIzg=;
        b=Prcqwa4hgcxId6RYwUeh49PBjtdOp3IgbKkc0lGRuPZH9uMdTTjtPkpTTcyRl2Ig9e
         IZAivKZl3XPn/CUVRJd58NrcO5aqsvSFp7catVgr3gtDYo5nvgJh4lp7ebcZCSjhu5Qo
         DPqAfGQx+2TYTN5cPwidAhRwdHU3zVkyamFxveI8Xnlqtna7Fuu4F+pGjGJAaoNb7+VL
         dA4lUpALc9LFjPWA12QW7Llsotxy1nEwbHEipqAI4At5dTZNOgfTwiIjAQNXZ9GIh52P
         76TVdL5v+a+FBvVl5cMlyCiFVFXKIvBBD1kZqEznC0mwpFVfHCO/BnmngvGoTiI9zS8A
         lnRw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680115295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NT/+hKreNV6mN0NURWzaKcGMQyTU6lb0SJ7JT9RhIzg=;
        b=n80uIRR40FkEJ63oCTgY383sovjyNIBlh8C59P7tJ53yJj8oVmLiGvGPQh8e4AkMzg
         afQbKdm+W4hCF1DqyHi1FMs5AQKbBG5NUHSsDDftkVVTI8b3NRFZpZg7xLJQ4tuWCe/V
         a64e+Q5ZxbmfA2tZsj2KupgqE1p3JrWMWP6Ensco7RN96VkPZ0btECnx+fn6oTU1IuFZ
         OJg7PoXkNqx41qz0ASLR8ovEq+RsFWpUPNObEfNJBPfZW0hDU7NeJvUMNdof45b22/3f
         w9pLzeYhgqVruTaEaLThuYyzCasiTgZ6fliPSizgKNhIVhn/vqEuczGb3aaTbJneGgFF
         D9TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680115295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=NT/+hKreNV6mN0NURWzaKcGMQyTU6lb0SJ7JT9RhIzg=;
        b=o+ytZ5+lYb5/fhkbyeTx+6TJDJ/WlIY3U3l79218uXClPiCuZRkMUDZn2RXapkou1s
         deSE/bhMktkB3ILH6pOwtMU4fSxWCX+VIienLXj83CM63bfltBZlhfGpouoT//54tJB8
         cJ6o/WJPbz8y4bu9O0A7b08lWOzmXDWf6aCEmYZYXE3kXEUKB5mcpfQmHVxvQQ9mVhW+
         Fwsj5tcU/GtMKzTudoyQsKtdIoKLfCAwjJH1Pnm4O++aeMTbS5QVk/URIj8ySLp4r1Ye
         loE/IvQ63ibMBMcPwmia2EBE0BEeSUjqNqesqGol3VNKxASzl//16OELfCYaFNwtRpeO
         80/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXHN78MYwZTMabxqNmN+4+z4wjYX6Vl7o7ZrNLI8v4ZzDjj9nvM
	1vJesDFqVJ10+UUDwiB+u+Q=
X-Google-Smtp-Source: AKy350btUV68THQs0ZNk8Q6qK6/NGJLPV8vUWjVzVIsczOBcH/RTmqcXBAB/bxJM4Txa9aBYXfDZAg==
X-Received: by 2002:a05:6871:23c9:b0:177:ac40:8f6d with SMTP id xy9-20020a05687123c900b00177ac408f6dmr5133362oab.8.1680115294898;
        Wed, 29 Mar 2023 11:41:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:11a:b0:37f:a766:5f32 with SMTP id
 b26-20020a056808011a00b0037fa7665f32ls3724107oie.5.-pod-prod-gmail; Wed, 29
 Mar 2023 11:41:34 -0700 (PDT)
X-Received: by 2002:a05:6808:86:b0:386:e510:db0 with SMTP id s6-20020a056808008600b00386e5100db0mr8954661oic.44.1680115294463;
        Wed, 29 Mar 2023 11:41:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680115294; cv=none;
        d=google.com; s=arc-20160816;
        b=P/CKMJXoDsy0BHk3/Wayx7K8wZEPtOBplbpatnwerlua6o6qHK2bMlZMRgIeC59QV1
         exWlYo3H36U85joilgXNSVSbFKUQh0Vph42b/ZMkaHbU0sz+6yz2inmqIXfjrAlvABq3
         766s5P4ovh9Ci/G1A9ScL0UJy5f94V1FLy6tr3vvzMHOtONwQVfs+qKCM1keNc1rimyX
         KOLResQhrCueLP55RzRTqJ+FqKxFB0Rcg49gfV5eGAX6eYnIraAGKQXl8Iw/orkThmqo
         ENLui6eU/MlqoACWdwWjPUonpM8RslbcwgJeC88o3Vkhzmmyo3R/wxVG16FdxawLujNb
         oMDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dxmuN5bOpF+xyVb1w+Z2846HXpRYFN7xoRDxUCB2yvc=;
        b=oSe9+xXpCvwcwJyvU19D7py5GjI1ugQMIIVNQ8QSPkWcfq/QnAtUwPtOzb0pSs+xbk
         cjd5B6pESRKGOuU4ag+RbNrptetgcV+zltM2YGjG9RLPCgE91iNMlKwczvQA41ZQyTPB
         boceilezXntj17GRDNK6UnMKrPnfwrJ3owvHL0oK1emA3v0utqqgB9bSiv1jm3q91n3+
         tSuMD3nz2dDhs34KWuH3PdR4MEIxtCRRQqXibF0FA6mpW6RMdSQenLGQRooazcCy5yjp
         7uaZ0LGWE11INwUCndqOPl08OALs3k3/eOrI8DmX8QYK6nyreUmU2YyxqSTyM6U3T3su
         IbuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ABvWcdvF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id eh5-20020a056808274500b003869e414f18si2488462oib.4.2023.03.29.11.41.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Mar 2023 11:41:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id le6so15792801plb.12
        for <kasan-dev@googlegroups.com>; Wed, 29 Mar 2023 11:41:34 -0700 (PDT)
X-Received: by 2002:a17:903:41c6:b0:1a0:7630:8eed with SMTP id
 u6-20020a17090341c600b001a076308eedmr7544643ple.11.1680115293931; Wed, 29 Mar
 2023 11:41:33 -0700 (PDT)
MIME-Version: 1.0
References: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
 <74d26337b2360733956114069e96ff11c296a944.1680114854.git.andreyknvl@google.com>
In-Reply-To: <74d26337b2360733956114069e96ff11c296a944.1680114854.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 29 Mar 2023 20:41:23 +0200
Message-ID: <CA+fCnZcNynt_fzhikr4SnQfTqmOWMepg-yhnVQfzE7pn3GAS6g@mail.gmail.com>
Subject: Re: [PATCH v2 3/5] arm64: mte: Rename TCO routines
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Weizhao Ouyang <ouyangweizhao@zeku.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ABvWcdvF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Wed, Mar 29, 2023 at 8:37=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> The TCO related routines are used in uaccess methods and
> load_unaligned_zeropad() but are unrelated to both even if the naming
> suggest otherwise.
>
> Improve the readability of the code moving the away from uaccess.h and
> pre-pending them with "mte".
>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Chages v1->v2:
> - Drop __ from mte_disable/enable_tco names, as those functions are to
>   be exported to KASAN code.

Hi Catalin and Vincenzo,

Could you please take a look at this patch and other arm64 parts in
this series and give your ack if they look good?

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcNynt_fzhikr4SnQfTqmOWMepg-yhnVQfzE7pn3GAS6g%40mail.gmai=
l.com.
