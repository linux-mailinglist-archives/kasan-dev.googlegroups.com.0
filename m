Return-Path: <kasan-dev+bncBDW2JDUY5AORBNGO5TCQMGQELYPJCVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id E8963B461CB
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 20:08:53 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3e04ea95c6csf1387898f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 11:08:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757095733; cv=pass;
        d=google.com; s=arc-20240605;
        b=hhqIkm6pZEMOkLN6bKvuVBieLHvCcvJq8+rANtSlH8n25J1uxjVOr4mjSfe3BDrmI3
         kQtKISsRQj0CQlRx9E3sQctpVjANPjN9I6erPKbDoB5XDJCUOYsH3ku3rHqCBUGCJgLX
         mlNeRQ/5IeoipMDyiswsCFSV6xmYFE65ZYrsIgQSzl/1hoHX6OBUPKBBRgmSIJiU4dgc
         Gpm3EeMqxkIEq6TMKkz0fSsgpo4kkvvLgArzL1/nYQQ5f6KcMn7w755EC1YCXlZuapfU
         wFsqj8z9Fhg12OWzZmlR7EP6iw8SNfhRBY/FMmlZ7BfwGzf8PYdJpqoDcbt9QlE/AvAH
         NfWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=lLHngebhqdAzh4hXrcOgPNS736OSLFkrLbMsfNIvUFU=;
        fh=CIwA04F1SJ7es+3oyvRHhb/U76VX09HbptOzp6XGJ9Y=;
        b=g4Zpu2wohh7ZQJwS9jzrv3b4/izRo8h4QrTybFQGHJryFPTOS2znV0TMLxaucLS0Fv
         51QApUQ1C1APtuCOgbhQwbM5lQnAjWJTevGWX82P0qpWtLo9lop8g0BzyYfcaYsEm/aT
         wAc+4Zo8WzcUHlibRpshGqouE7QpvX+paZFnxQE/3JU1/ltHrGV2GSBz1J/h/18FWAYp
         GeRaUtQZl0rqPPve9rX0RCdp0rEtKLcqzrmPtmt/fqCYosRv4OWkp4s42fDALTSMUWFz
         U0f9lUhpLvSHi2pg7hX7vXGphv4leodHoyLtmMnuq7IWJY5CxK8iPzStRl/kSKf+Fv7t
         wmSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CsR1tWeP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757095733; x=1757700533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lLHngebhqdAzh4hXrcOgPNS736OSLFkrLbMsfNIvUFU=;
        b=Wv+fJLNfy0LPQJFP5lRP795kuibkuU09zVh8/2u0eD7+tZA1/jYSYoiF9+Ny/1htOm
         uLjhr2RgDFHd+VCTSLZ1S49HrW6QtYO3U7x0eVMNa7MTxEdvTISC7ZRosOsiGHRuFvWM
         CsC9UfRIcIJ60RAzkQLZA1bVLp29Ry5fbfNqDvUf3BHeZvy02InwLl2a9cyse74M5Jmm
         C+/eIMzZL1NGWBDhIWSdTfAxvzkY5f1L1sIsBEoLWa0XX4/Scw6kEzuuKyFSzH3eHVFD
         JPutPgfLCPKIUfdGmKUVf/Ta+YiWzyhem2ZBTsygLMJ80AWoSZAmbB+xRkQCBc8wMa7g
         n35g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757095733; x=1757700533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lLHngebhqdAzh4hXrcOgPNS736OSLFkrLbMsfNIvUFU=;
        b=YjS8mwJTWKFfbF8ilSiPC4dQ2DYQuSzWFG1wj9ZZzRmF169dxmUCkoWVNWGlu3gskq
         ysFs/iF1MzJT6D5JX0IyFA0VSbSi6kc9cFrm7DvvVd/5MaIMXwjAXM2f3VYiWmLZtkvT
         RHXLneLNmDSxnrEHy7XsGyZxEA97tfpsn8f3UAKdnghGqXqvhyolsRPrbAmsE3zMSUCI
         wRakmPM+sBnpuYQXIh9gdYizmEz6wUmHhEjE2okMTjP4hc49kcA6fT5qJ+EG8JkFczK0
         aZcqhqWJ1Fv212WCyDX4ebdcba7b1rtmxRzyOrhkEwFu3wbsfZ04tnaf+a9vRA8LKeA+
         hmCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757095733; x=1757700533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lLHngebhqdAzh4hXrcOgPNS736OSLFkrLbMsfNIvUFU=;
        b=P8Va58jBcVemeJI4FTxKUAKTBcgYgzny8jwKfVSKuYLzkuv+IUqElWBZFcvTCu/ME8
         0G6JWEg82wF3Lz6N9ZYTjjWqhMD7CGD2dZwFhlyp+SPYXZi8upTVo28hdOeZ2lmn/oc4
         /9slOgq/HYbHsO+yL+mnrQ9M91CDq/yQGQh0A4kJFpm2rkdnEsljiCQ/Yu7cFyh4kHJc
         QZbCT8cf5ZwJazsRAdcriALbz8pJspc+LdECGTaDCsEeK0RlRX9TYslJG4lj/5N2Oi+O
         VJ5YLI6XEyHW41yFqTaH1X96RtyJSjTixb2n/eNiRcyUV2bHAn/Kqu+28Nqi4fwbniPX
         c9Tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvD2l+HXE4zI6lA8KI3ZUiwILYFG82b+BBmINPX3QZcibZAOgsxmuh4Qf+2fawE9WCtTwCPg==@lfdr.de
X-Gm-Message-State: AOJu0YyIiq2lbjeEt9KmPubvbg14IT8tfp5sIN/IUl2zKMeLT2fMGSbv
	00W1Fq2gG6RVOkzX59+bBQ92ttfAuf60Ht7SORP/sKsYH/lpx+TbEn2J
X-Google-Smtp-Source: AGHT+IEw7/0cy+9Xv5yn2DuR6gWvrC//LP1pgry+4b6a6oKnJc3RWaTgOnGo5mndSG1fRvPXa9z0Ww==
X-Received: by 2002:a05:6000:24c3:b0:3ca:8031:4b38 with SMTP id ffacd0b85a97d-3d1d99cbafcmr18608686f8f.0.1757095733109;
        Fri, 05 Sep 2025 11:08:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPm3htsGuLo3BsozzL7wKDBdlm46QMXlzVcZ2VZ4agLw==
Received: by 2002:a05:600c:4f0b:b0:45b:bd1e:2b11 with SMTP id
 5b1f17b1804b1-45dd8053a58ls5041105e9.0.-pod-prod-03-eu; Fri, 05 Sep 2025
 11:08:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXOEi9v8si0R7PVmHFFfweg6IrYyg2aCd+ZNqaTw95P5HTQTbEfohJp2Jde/nmajIeF3U1P7MesFao=@googlegroups.com
X-Received: by 2002:a05:600c:19ce:b0:45d:84ca:8a7 with SMTP id 5b1f17b1804b1-45da74cf485mr72747155e9.14.1757095730052;
        Fri, 05 Sep 2025 11:08:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757095730; cv=none;
        d=google.com; s=arc-20240605;
        b=W57+WAQuZ+nJ0+PvNqiHV3ya9Im73viIK7JrWK2dlkL1i87gbqvb0uYf33yrH82ImB
         uwV3eecpuKVH0DXH6B0gy0JzdusKV0HWntxHjyooJmtQUbgiFziJU15ebqcMcT0oE+pQ
         WxpbuCQiwWlK2cejHqo6vbI+Vvl8L+Fx+0UDEzubCOKmSYLLExz3eL/V89XqJbQzc1wE
         9QAMeyD60wFDPHIbOXctdwku3lEXkjXlECVsFf7mlmkv2X0Rob49ecoBkuDppgfsUU2y
         V56R9OSJj0K1SqbjmLRh2tBbGc3LDIH8QKUz9kAtu3zmuT8SjTdAS3+I21WsxkPbhVDW
         Ncdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iGdnI/KfWDDu00FpGfqLB2W/2CyE6C3w8An1H9pjQWM=;
        fh=b5n0vCq2vKbL59cpalOV01fo9UmLToxi6PqKJV/pTc4=;
        b=BIjy93OS5VYtp17BIyzH82xFq7guV4Jq6tYz2QHpzqvt1om12U7KIIXkIg6SYuiV37
         nstv8zbUqPtW/PSUqjpy8IJGW18nr2tb4J1RC5FgcbDVBi1CFp1TGk+k/0vcOcO0rbih
         PBpGYN6Ob0jpyE/04+hfpEZYdo6Uc6vkjrP2Wp7x57m2VVb0phaLCXB6fa4K2tzEijrF
         8wsN86o5iCBLijA8f1XwCjsHqbL/Yd8C3wByYIFTByFZGbxVmhi/T0Zz5eIGFxbvyPE2
         765UWYMeko2qPllclGM0w8zLel7Mn1RIe5sjnyQDilPj6hKHSuy5y3ckj58xeEBjOtJQ
         7iBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CsR1tWeP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e278ac83dasi92085f8f.4.2025.09.05.11.08.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 11:08:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-3df3be0e098so1324913f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 11:08:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBWAaeNGxdwCy0Qin56eY5Hwi5FwkpVvJ9AoKpuHPij+kcN5kgH8yC5Sz0cd8feOhL9AATEA2Dt44=@googlegroups.com
X-Gm-Gg: ASbGncswtuqFlCEweYKK7eigjjuVMRXSSQuws249gX5xP4P3IVxelM6XmW68ZWpiFJe
	MQmTIFn9yhiCVBJdFCIX23WL2KygE4pzr2cZoVX+3S0PLtdn9Aa8V5DWRo5rb0yJgTuiPfgaSO6
	xZeEhFHINkqywAWcABWizID1f/jzwfNkr3YQQqJB2vX9M+bxAtIK3ZPizojyZKN1+SSJ1nNI0nA
	O2nPNHrukSZ5Zf14Q==
X-Received: by 2002:a05:6000:18a8:b0:3d9:7021:fff0 with SMTP id
 ffacd0b85a97d-3d970220156mr11837479f8f.37.1757095729307; Fri, 05 Sep 2025
 11:08:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv> <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
In-Reply-To: <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Sep 2025 20:08:36 +0200
X-Gm-Features: Ac12FXwl8rdmcy6KM72QT5kbnXVskzKHCQ5SWTQj8L2OmEz2lTLzNNXRX0uI6YQ
Message-ID: <CA+fCnZdWxWD99t9yhmB90VPefi3Gohn8Peo6=cxrvw8Zdz+3qQ@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Baoquan He <bhe@redhat.com>, snovitoll@gmail.com, glider@google.com, 
	dvyukov@google.com, elver@google.com, linux-mm@kvack.org, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CsR1tWeP;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434
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

On Fri, Sep 5, 2025 at 7:12=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail.=
com> wrote:
>
> > But have you tried running kasan=3Doff + CONFIG_KASAN_STACK=3Dy +
> > CONFIG_VMAP_STACK=3Dy (+ CONFIG_KASAN_VMALLOC=3Dy)? I would expect this
> > should causes crashes, as the early shadow is mapped as read-only and
> > the inline stack instrumentation will try writing into it (or do the
> > writes into the early shadow somehow get ignored?..).
> >
>
> It's not read-only, otherwise we would crash very early before full shado=
w
> setup and won't be able to boot at all. So writes still happen, and shado=
w
> checked, but reports are disabled.

Hm, I thought it worked like that, but then what threw me off just now
was seeing that zero_pte_populate()->pte_wrprotect() (on arm64) resets
the PTE_WRITE bit and sets the PTE_RDONLY bit. So I thought the
kasan_early_shadow_page is marked as read-only and then the
instrumentation is disabled for all early code that might write into
the page before the proper shadow is set up. Or am I reading this
bit-setting code wrong?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdWxWD99t9yhmB90VPefi3Gohn8Peo6%3Dcxrvw8Zdz%2B3qQ%40mail.gmail.com.
