Return-Path: <kasan-dev+bncBDW2JDUY5AORBEHF5XCAMGQELZKTETA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D5EC1B22E62
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 18:57:54 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-55b995be1e8sf2509625e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 09:57:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755017874; cv=pass;
        d=google.com; s=arc-20240605;
        b=WF3Mwftyt+vVg+F4xVLxnrhHFbMPQKsjxE3Zq21D/3JFgyuYaQZOKCJkzjU2g5dfig
         EfBART0Br+xF0+EC6dVr/xHTW20TlqaHP4tqId8YunMeo87BcqYrv+EnjPq+7JRIfe0s
         nQRdzRABI/TbTrSzrPY1niUEHfXaahA/A9adN/nvwui65FCjoboRb+Ix1yC137SVxxqI
         RX1kUTysGL7c5pHakvJFOYXptnONFmyHI3fyKyTgNchDkmGoXW+d0ViPbtYSDCTeYNKa
         VvjGhDhMRLmxB/Ip292KXfry8YEl5QJyZvChB85nbmB9MvHI3JAxL4c4SBhIu/MXBfMC
         xuDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=JrrY5tzzirpNURl7Lxd68sSrPthoSb/7YSS0mGt7kvk=;
        fh=nXyt1EXG/i/4IHhSrkcDiZWNinn2+DfenBX6NlbuOWs=;
        b=SiPHGi82tvb0mFvp2up8OwAHJGLGAQgUrLdgR1oscNNHqIIZqWAbTuaelBEcoxsdY1
         1eP5ErV4AjRdBp46B1bUMmMJaL++kN+2oTN3P5xoJ73jvYZcqx7VQHhvq3m7eSI5rRpy
         Wiaic2dCMgGZ9RPOzIcihxMSqTJBPzp3fP9gX6ZXrCrpoRA3hO8fJsaZp0Ud50DRX6DS
         uCmwjV8d0QtGqzaA1GLd5EovpQSI92ga1AJFObMkLeNs+0UdWjngy0oiTJxIFOq74AsP
         lwZgTBmh0SVfntRZ0lnceoxNwrKn/LgaeRyRWpPETWGeoNMA+UIvW7dH63UZ6OyHmAUK
         vrcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SU6GlYgZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755017874; x=1755622674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JrrY5tzzirpNURl7Lxd68sSrPthoSb/7YSS0mGt7kvk=;
        b=TWj4bqCCFwdbAHvTmmbswrEr2pjWjCCpNzEOa1Px44d1Gp8haInXFjz2agruvPduRK
         7a2eNoctHxMn6zXeA4JqPJn/W3U/Qi1nbHnjvYiy3iW3Eh4p3RTCTyMbcRaRlsDq2izJ
         cgIRpEhu6N5cQXzggwwMZQ+tDqbBIiYjZ1wRuRJQ23dATxxJ8dr9EtyJWtwhNNlKHs/W
         wrwtjsI0ZFb8HXZu2jjJA3DPGY8BNhYpnbCjm20WXKJiHmb2Bvr9fv+OgfXlAj1lFGOw
         /0CIxQ/m0italn5IEBuwyxgUTNK9vMY3meKKpMfnoEwyHpYhjzITpDdcbuKUumc10yYG
         W7PA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755017874; x=1755622674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JrrY5tzzirpNURl7Lxd68sSrPthoSb/7YSS0mGt7kvk=;
        b=YcudVRFeX+qrSX2y6tjYqbbSh8JjdB1BLt/jySu6vSVT7kxFeVLw10v7Mc9FygoQBX
         3ZQBI4eyETl63lk9LKblsH2zP5zTc/TQ+hiKPubuH4YPqbjryLV2/RKlhI85OrqatogX
         0WO/xZP2sBQ+9/fmOS0HjHjayqeVpyknz3u6r/kZqDnkRgTiThQdatM+nAyAVpjrLJGq
         LQULSgMfkvDh/86/c00VDBoVJnvoMkRlvoeqghsiA6EzIikGNUwwvVGbhNCZSlq6TaOm
         ZEuxcYX6hB4rV/iZHIjBvkPJjgViQACv1u1MZhTCU7i6C+PlwZgCi8RkSgQ8EQAbEDAn
         EvZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755017874; x=1755622674;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JrrY5tzzirpNURl7Lxd68sSrPthoSb/7YSS0mGt7kvk=;
        b=V4nXoE+sXVGr+26kZquapxnbKDvgnhzk5F36ul5d4pTqOudGL2pJv7oSUsYYUmHrlq
         0m+H9zNlOv+852KJBr6TbeXqB/6Yo8TYbspTC2VsD5Qhidgdsbp+2b/eeloXfKez+Tyj
         r4hcPEkrn6FW6zBe5/q3ZNuZsc1WYPVGofbZ6fOYA7DH1V5KeHlXA0LpRW95X/eckYxD
         q3n8HMpJ8LB6S+7lLI1Tm6fSf+kwUO048U4AdIqX9dl/0UtbNISrdISKFtbZeJ7glAZI
         L0HQG5goXdranWJjic+3vdSvFUsZUCykSvNMf3T0Fo4SaVgpYne/GhJNDIMMJ+nVxRcp
         KIVQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbrLG1Z8WocieyGYR/Xp5L7WDx58SL5QH3F/NJ6+UZ5211TvhlkSgVUjZxWhcEW++TgzwGDg==@lfdr.de
X-Gm-Message-State: AOJu0Ywm9IPVroooqGNkkJNETFRpoUDcrIKCAuOHNC8L7XxZxN4wTTfO
	/isAPZ/Ml7mVwgRbDuy3RTazedYJmUjVZLCiefY7Cuvl9IcKkik2oIO2
X-Google-Smtp-Source: AGHT+IEDw0lEMznGX2sdLqcOPOpMVdQ4CpMHENg1IX+/hgKfz0sgv6DGwhONWqfeeSQRz5t3wVIyOA==
X-Received: by 2002:a05:6512:3991:b0:55b:827d:e377 with SMTP id 2adb3069b0e04-55ce0345563mr7749e87.22.1755017873472;
        Tue, 12 Aug 2025 09:57:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/sw/KoXcwnZtYnnZtVAeZpChnxLVJv1jPFZKXlc5MuA==
Received: by 2002:ac2:5b01:0:b0:550:eb65:d6c6 with SMTP id 2adb3069b0e04-55cb627f15cls1437715e87.2.-pod-prod-05-eu;
 Tue, 12 Aug 2025 09:57:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVY5qaKAby8dpwxnm2Fhu+g7zg4uKBtp5ckjY54rhizDzWOOUKTojCHyTX1/I23wc2ECjHbYbGks5o=@googlegroups.com
X-Received: by 2002:a05:6512:4023:b0:55c:db8a:53fc with SMTP id 2adb3069b0e04-55cdff94b5cmr31210e87.50.1755017870249;
        Tue, 12 Aug 2025 09:57:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755017870; cv=none;
        d=google.com; s=arc-20240605;
        b=YHGKnkFaZxLcFfp7PirUaltMx0V3kyYoMpZvnTmg2hoE6PpGz1VU3PiM8lEfrohEj/
         pjwGYiLnwL2/r1Cow/2QOsfP/YunQW3vhbja9btGfBktSmtfjwOwVlXmD6BPoGnrgOqI
         h3ivzmJgmbIc2j8o6Demagro6sPk4puytOUlFnbx59Qrj+hs18ffneEjhdYRJTvFigx2
         mZYFmnkd3kPqzO3YV43orqBqiBrknseKbNDw0yXprp6g48itETKIO0Rg0A61PfJGQk9B
         VCTQxKkcLs2zcageYSHS28d9VTm4MD+DOQWIYHv3H9Q402loVxpMjzK6hiG4MfgLvj0u
         cuZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=THi5EeRjYjU12pg786HqRQnWCXSwecn27iJQLPTdTuM=;
        fh=M+Or7s6de9UIb0mqHB23q609genm5kwghjr/x9zgRaQ=;
        b=Ba+jHIYF8bFJJRs2q4yXn3RPeS7m+ucJcwQpalFmJf3JFGpKbsu4cd7/79RerFcles
         xRy3kzz6sbuDHyvCx5YrVRi5/ZWZPnfQLHSK2+MhYZxiGriVS2kWKulve08l+hrXu7SV
         RPwGp7+svRrrAWovtFngVKeiKpHNEJvYeV7KowZ2hXxuYqyCDJxNhb6LBix8EU41DDt9
         dODWWjkOvaN8RsZM+Df2zdasy/TRM2A9Rhx7a88/KWapcQY3VFDP6py5OdGXw6Wb1rXa
         4nrZGvwCcV7Fv69k9/QUeBZJ2Dr4ixqEwB7uWU9YI1+EFNaW93Q7ut2F8P+bYSmQSdj8
         ydSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SU6GlYgZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b88970321si672934e87.8.2025.08.12.09.57.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 09:57:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-45a11f20e03so7555055e9.2
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 09:57:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZ7wU/8SwNOg3YR72wLjSS6+4IxRzy7jdgq8hWpytExAs2ogKSHjxSSDHT+R1qLtoqrmbjVIa3xKQ=@googlegroups.com
X-Gm-Gg: ASbGncvtKB+59y/jcrZRa2phEUuriz+s3+RiFZKS7vo4yObjfVOhvFJ+jZYkbY2r1m5
	zxn9mkl/TT220ssSnOGNctHVLqeQiMIz1QatlHIE1LbtwwzYVD7fQ8mOrxZfx3cVns01i+H5ufJ
	n69/nQFcf05XN+3gZpjdect/NpBC9Iclvxo7hr8LP2R0HlXTg9SuyyLP1VbgQjEPeu0/eV0XXWt
	O986WQZGA==
X-Received: by 2002:a05:600c:548b:b0:456:1c4a:82ca with SMTP id
 5b1f17b1804b1-45a15b8ff7cmr4280275e9.32.1755017869451; Tue, 12 Aug 2025
 09:57:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250812124941.69508-1-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Aug 2025 18:57:37 +0200
X-Gm-Features: Ac12FXxO7VtFtbvMzrNpRmaaDrUzWKgNXXMRGHfAEt4lFzHjRoU7D-oGMR2kngk
Message-ID: <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	elver@google.com, snovitoll@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SU6GlYgZ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 12, 2025 at 2:49=E2=80=AFPM Baoquan He <bhe@redhat.com> wrote:
>
> Currently only hw_tags mode of kasan can be enabled or disabled with
> kernel parameter kasan=3Don|off for built kernel. For kasan generic and
> sw_tags mode, there's no way to disable them once kernel is built.
> This is not convenient sometime, e.g in system kdump is configured.
> When the 1st kernel has KASAN enabled and crash triggered to switch to
> kdump kernel, the generic or sw_tags mode will cost much extra memory
> for kasan shadow while in fact it's meaningless to have kasan in kdump
> kernel.
>
> So this patchset moves the kasan=3Don|off out of hw_tags scope and into
> common code to make it visible in generic and sw_tags mode too. Then we
> can add kasan=3Doff in kdump kernel to reduce the unneeded meomry cost fo=
r
> kasan.

Hi Baoquan,

Could you clarify what are you trying to achieve by disabling
Generic/SW_TAGS KASAN via command-line? Do you want not to see any
KASAN reports produced? Or gain back the performance?

Because for the no reports goal, it would be much easier to add a
command-line parameter to silent the reports.

And the performance goal can only be partially achieved, as you cannot
remove the compiler instrumentation without rebuilding the kernel.
(What are the boot times for KASAN_GENERIC=3Dn vs KASAN_GENERIC=3Dy +
kasan=3Doff vs KASAN_GENERIC=3Dy btw?)

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2%2BNA%40mail.gmail.com.
