Return-Path: <kasan-dev+bncBAABBUWHT2QQMGQEFPSPDOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E8DDA6D2DEB
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Apr 2023 05:24:03 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id o3-20020a9d7183000000b00697e5dc461bsf5087719otj.7
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Mar 2023 20:24:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680319442; cv=pass;
        d=google.com; s=arc-20160816;
        b=tQv7Zw2G5KSfFuf4kRyo0vMiBd/mXG/eWX5kmuy+3EsYlCexnA+H13nWl2AatIZjLP
         DlLBqGed9qUHeYACPFFlt2tLyHslyKb0xh/RpNxAWn9pgoxF0FA+vbEOVh1S9i9qBIVi
         fzXaaT493nysXqRY4aOjoT8eKYZvuT1fKiWnBISqRMsXW5h5vUqq0HUdzKzki8fgfPzE
         zno370Mdn0InYwrMHpAHEdgO0BBt6NDGAGAYdg5T619mzBgLad/03E1lzhRpSmd+71LD
         /8KnELZJmMlig5a7MD+btZPeCh+WVXFCO7gl5cSqPzpWxoSxE0+e3nTq0Zovi86yMl7S
         rbKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=MBFM3NHX8dLbGYIgP7qMA1lgIld+AaMqGvmoUjZAteo=;
        b=dxLZ6NuS8XtcJ8HWcaOHEoke6W2IqLoNlg/EyRRdxnefnTErJ7IKn6PcRvHdoDEx4U
         vaA8jQUjRd6Xhe2JM8iYg8FIn7tEVk+KZiGhm+TkFO7G1Ue/CZKGuCAkDS9zElWC5DqX
         IylPYEqCYbZH/9nnacFX3oGQxEKS/4SLeOuwpyjfKnh9e+K3fQ6bJnUc3S8EHub+SFsZ
         eTcKm8aIOwNVf0c2MRSh/n4bnxbO9pP3aQoTDEvszjWGXsiruJSfwbdE25HgI9v2GOaM
         kncD5qL/p6tm0RMSIdqSSgBI6xu5xOPuX30KGK2diWpu/qP+eyt3rjHiRFhTn7PVnwvO
         acvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680319442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MBFM3NHX8dLbGYIgP7qMA1lgIld+AaMqGvmoUjZAteo=;
        b=OPReHs4ZLL8rXVPAJUpJd+KCPVBj/gN/bJxN/rC1ZnnelxE2yLJaq9UdN6StyFFW6t
         hEjjAoncNANsHWX99ssO8IP65sIFwlEZx9Yi2CodcQgTzLTNfj7nehtELStApNqE615r
         U97Vfbv8dxU0Pj5aohGGiVObjnm/z98RpFKzDi54sX9QdZqooOi3OQ89UJWACGdRWedd
         QkH54zka+6zSJwez+cFrpnKCKnH6Ro1+CXROFalu3QHIHJLclmvaoc6cH0rdmyg8h3TE
         RAmjJcwk3I5zoh44JecllQTxeqdJsTXkzD2jcr/HFf4iqqaZhaQRmX8riSXsSnN44joa
         RJ3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680319442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MBFM3NHX8dLbGYIgP7qMA1lgIld+AaMqGvmoUjZAteo=;
        b=IshnHbVWQDDqSnWtFErJHdKRUTBTOfUDsCshR6K9MBl8pR0i8dJfDIuqr91gK1oS5d
         HKbAUaAoQdAirAkU4ScO+kwXl1AmdP928nZ+g0l/TpusrZVrdrX7SElnMK2A84AAObL4
         Y/qNJ7SUHkaRRKWFmVb7paemn41T1mzirrZ2I2iC3HDEUORI9rhzbSjI3oDcGrHZ7XS9
         0vxxHapQbitTuMelVodN167OalttW/M4RojBIjTr0VOm1z+DSic1poFzYbzdx7L4shZN
         qmLCbGMITMSf/cg/Ew9kwJUpGA5jN+jWHNFssTmaq5lqK/sSM+4LKWOGOJ9CGjq2PwQJ
         w5dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9f81R808wpc/5/cxcT9Zq4BcSsluNR0+yOA5ilFJ6iCDITUsISJ
	3W4g+0g98+4zw0OSUza3m8s=
X-Google-Smtp-Source: AKy350byjda2jAv86cuVxTWiA3f/yJ6f7hnPaGoUTk+caHjn1V9GabEr7/tNCK1iuFy3RmGpAv8+EA==
X-Received: by 2002:a05:6870:3324:b0:180:2a9f:1ac1 with SMTP id x36-20020a056870332400b001802a9f1ac1mr2726637oae.2.1680319442259;
        Fri, 31 Mar 2023 20:24:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1828:b0:384:d300:3fb8 with SMTP id
 bh40-20020a056808182800b00384d3003fb8ls1725121oib.9.-pod-prod-gmail; Fri, 31
 Mar 2023 20:24:01 -0700 (PDT)
X-Received: by 2002:aca:1b0a:0:b0:389:9592:b4d0 with SMTP id b10-20020aca1b0a000000b003899592b4d0mr1634415oib.53.1680319441880;
        Fri, 31 Mar 2023 20:24:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680319441; cv=none;
        d=google.com; s=arc-20160816;
        b=zdpUuinwyuKFupsd8gn1rguf6vHUMXhd19g5p8s0Kl+Xax/aI8wXJzdbBn1RKumVwu
         DKLv3PACiod3tFzZdX3A1MhXMmGg0CmlPNPYe1SmUNoQX1YLNG8LY+49Ol8XEL1fQFUr
         5+GJodfZ9/T+NLZVff5XYRp26w76eMvxhFOV36pVmEaeJli03PuCCCrX99MJiVRZlrZg
         2kTzzoHv95Us3+WFxTUqu7jAQ7ep7fkjGJeP2uWMpquWtHty9n3VaeSqdgkDPKQJdYFR
         KoQbSsOd5b/YVse06lr8T8grRq4lIcmCAP2MNSGnLUVLEEI9QZCAVknllg3SuDw2n7cX
         sV/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Mvog04limpniNR5GCN+WElbsWp5SySjX0E8c0mW1ou8=;
        b=l60d/2uHqSR5EbnjtD0JSwXn8A7yhXb36kYNRD+rP2UN8Id3yjeCjmwm+eOprQNYvy
         3G8g1GTQ28g0pHXrBmsWN97bdjq5WGASTQrixzNIzKYyOvjuNhkMZluaiuwg8IrPA8+8
         xepQjmYKf6kYBvXpjaSM+b3RskJf3PpZI2QL9aZTqS8obREd+1c1i0OZErzcmUMU1k0/
         Ipi7BNLzPTd+cq0CIn8fsUR+Sk6bZ1zD8+hn68p8mzMnULRtI1RbWQXCN+fxvEbpnEOB
         mA/gm/bPZn5bJekoB800rHe7QSFQGdlm+s3MwnZ7fsEAUzuLJ7uuPWddM5j4CqqUVMyM
         xPnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=zhangqing@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id s204-20020acadbd5000000b0038a7c1bb0dfsi167831oig.4.2023.03.31.20.24.00
        for <kasan-dev@googlegroups.com>;
        Fri, 31 Mar 2023 20:24:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8BxONmwoydk7yQVAA--.32512S3;
	Sat, 01 Apr 2023 11:23:28 +0800 (CST)
Received: from [10.130.0.102] (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8Axnr6uoydka4sSAA--.45160S3;
	Sat, 01 Apr 2023 11:23:28 +0800 (CST)
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 loongarch@lists.linux.dev, linux-kernel@vger.kernel.org,
 linux-hardening@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>
References: <20230328111714.2056-1-zhangqing@loongson.cn>
 <CA+fCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA@mail.gmail.com>
 <dccfbff3-7bad-de33-4d96-248bdff44a8b@loongson.cn>
 <CA+fCnZddt50+10SZ+hZRKBudsmMF0W9XpsDG6=58p1ot62LjXQ@mail.gmail.com>
 <2360000f-7292-9da8-d6b5-94b125c5f2b0@loongson.cn>
 <CA+fCnZfoTszdoy7o_EfPXOc4QYo_Jgw9Qf0ua2JoNp0PXdrTPA@mail.gmail.com>
From: Qing Zhang <zhangqing@loongson.cn>
Message-ID: <34a1a391-6ad9-8722-b206-1e830711b096@loongson.cn>
Date: Sat, 1 Apr 2023 11:23:26 +0800
User-Agent: Mozilla/5.0 (X11; Linux mips64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZfoTszdoy7o_EfPXOc4QYo_Jgw9Qf0ua2JoNp0PXdrTPA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: AQAAf8Axnr6uoydka4sSAA--.45160S3
X-CM-SenderInfo: x2kd0wptlqwqxorr0wxvrqhubq/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3Ic02F40EFcxC0VAKzVAqx4xG6I80ebIjqfuFe4nvWSU5nxnvy29K
	BjDU0xBIdaVrnRJUUUBSb4IE77IF4wAFF20E14v26r1j6r4UM7CY07I20VC2zVCF04k26c
	xKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1Y6r17M28lY4IEw2IIxxk0rwA2F7IY1VAKz4vE
	j48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_JFI_Gr1l84ACjcxK6xIIjxv20xvEc7CjxV
	AFwI0_Jr0_Gr1l84ACjcxK6I8E87Iv67AKxVWxJVW8Jr1l84ACjcxK6I8E87Iv6xkF7I0E
	14v26r4j6r4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI
	0UMc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUAVWUtwAv7VC2z280
	aVAFwI0_Jr0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JMxk0xIA0c2IEe2
	xFo4CEbIxvr21l42xK82IYc2Ij64vIr41l4c8EcI0En4kS14v26r1Y6r17MxC20s026xCa
	FVCjc4AY6r1j6r4UMxCIbckI1I0E14v26r1Y6r17MI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2
	IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y0x0EwIxGrwCI
	42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVWUJVW8JwCI42
	IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280
	aVCY1x0267AKxVWUJVW8JbIYCTnIWIevJa73UjIFyTuYvjxU2nYFDUUUU
X-Original-Sender: zhangqing@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhangqing@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=zhangqing@loongson.cn
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

On 2023/3/31 =E4=B8=8B=E5=8D=8811:58, Andrey Konovalov wrote:
> On Thu, Mar 30, 2023 at 6:32=E2=80=AFAM Qing Zhang <zhangqing@loongson.cn=
> wrote:
>>
>>> I get that, but you already added a special case for
>>> __HAVE_ARCH_SHADOW_MAP to addr_has_metadata, so you can just call it?
>>>
>> ok, all the changes are going to be in v2.
>=20
> Could you also please put changes to the common KASAN code into a
> separate patch/patches? This will simplify any potential backporting
> of common KASAN code changes in the future.
>=20
ok, no problem.

Thanks,
-Qing
> Thanks!
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/34a1a391-6ad9-8722-b206-1e830711b096%40loongson.cn.
