Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBWENST3QKGQEJZHHZKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E1F071F845D
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 19:03:22 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id m11sf9604730pfh.22
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Jun 2020 10:03:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592067801; cv=pass;
        d=google.com; s=arc-20160816;
        b=zZSLyVtQJ4C/P3xKv3uyukzjFHXs90F5SFR5/MI/GlTW/JAGMDGTnJKenneTK5j6jU
         mQChY/6vx7qYsQt+C1hs9K9kOJPxiXUUHO03oxns6bPBCTJUX+Yra5e9ppU66DU7bpCf
         /zogBXdWy3ZHI+/1yhlhbRjzImVi2KrnEUDofk9IfKxtgdQQgxXJRODg+yRfIy4nmr8N
         PQEjG65meunrDND1qgLu46XQ4qcUkpsnKtdsCFsgSIrvvpNvd/ZXO9PaEP8OXx1erE0e
         Up039nSTc7cK87jiFnIb4ZJwOdAQpVexVeTMGAVV/w1InmmL1nn1yPPpwUkIm5kbs8kk
         EHKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=JJOyLJkkHwz8GaGUrT0WTipGjBhSOS0UDGowFRHqzWo=;
        b=Lyu2b3mfem2gs8wvB2d3RMIxILJw+V9zHX8rbd8P6ilZJNsmjGGqrXiyhI/ZPoFoLg
         hLd97Jz/IhkZyyfR4dIMo9v8536VzeSrjUmZjTu1TVPYvAJQT0w/mZkPlKC+9r0snjAv
         vtMe1TCZcjdf6+q1ke0RjNAIrWzo5rhurIhjW7mzo12Hyy0HRl2bZuS5gRPrvZJ2mXtI
         5Bwd4HPiRwztxIC/6leXQBJpKVqF+3LldKhaaNFOcjEqPkd8OooF2fDQyJ7DPF3JPbsU
         qmjHWuWBrZ1yAZZlH4rUXEdfCZz4Al3Hg5M0nq+Qu8X2wCCp2XHd2Q9iXpQZam4peCok
         PuKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=jjhW0IgQ;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JJOyLJkkHwz8GaGUrT0WTipGjBhSOS0UDGowFRHqzWo=;
        b=s4gFSVLKdpPEDtJ1m9e8rEgk2NfXY0TjlfQK1SA2+5xSqSvJbuo1OM0Y8c1WPdskGq
         nrYv4GHOiSrlXqi2ifq1dyu1VTspvDli9ALLTrKBT37M799VminzfUrxw2sGnbRWPGzW
         UHsnbQxqVNRNOxEcgROtSI7pQoPIySEZDy+O162XnFKNbTFrq7odzku0Ivc5G9ZuwpKO
         mTV65WnTRuCOhN/H7RoMVzbji90WpXQwJUeyo4FDtZ0trJNt2f0Cn8wHRqH6uvWUJKKx
         T0auqd3mvtq/sNAZYiLKkEsRqVvk1xYRFhHY944bpF8X9FzN3g9wafSFC8FrPvC+UDcT
         ZyMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JJOyLJkkHwz8GaGUrT0WTipGjBhSOS0UDGowFRHqzWo=;
        b=CQkZ19fh0fDKUfNOauLoSWJsXz8U8nvTcUPF1dfqmYASNje6rD4SY2WS9vtVpm3p++
         Y5galWUgLktBJ41XVI6q9AJtEmZ8H8GG7bYvkdtNQFhugiiyO6yKZSr6rEMk0eUO65vb
         1ojNN3ZKzyfuWpxFC9Y3MjObu46KW92D+oIyvoNxDahp/3rbDzuFGiWgrCIfRquiYEsH
         BbT+mlAoP1zQi69OlNM1Iv7KTH3bi/v/dtir+oeORIhmOYqZc2GNQnMfYFIyokVhyqh9
         EdBaZTVlA8eUABjK4KNgICVYiClN22601gSQ45WrLWsBGbX0d40SDOsqFXqkUIKgOzfo
         Z+YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532P5BznvHh0K8D0TsyVFaNaM58CE6lgUBV6d25djQ5hYBFpNjP1
	f4DXKB+k6c/Cek4s19G8UM4=
X-Google-Smtp-Source: ABdhPJzSbCwaBRE30RhfZ9AbL3LkfV8LA2smKjPf1eeMp+RBufy8ZaOuoYV60O6QTQuL+/qkpvPO/w==
X-Received: by 2002:a17:902:7896:: with SMTP id q22mr6157855pll.338.1592067801077;
        Sat, 13 Jun 2020 10:03:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:94b5:: with SMTP id a21ls2679484pfl.5.gmail; Sat, 13 Jun
 2020 10:03:20 -0700 (PDT)
X-Received: by 2002:a63:40a:: with SMTP id 10mr15800644pge.310.1592067800637;
        Sat, 13 Jun 2020 10:03:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592067800; cv=none;
        d=google.com; s=arc-20160816;
        b=IATNdMW2gWs1sgmz8TDPgTxcx6ETp95sQmEi2dZS4gyUQriyCq0WcOi2FrvYqNy4AU
         48Bry1i7HY4gDqV4uOD6Gqkqm4U1ZxGEfPHFrHFUHZBgHdGll3WX7LM4j0XugUDFFGkR
         tHcvvPyeu25JGW9RO6164gK6U2rNxfDMs1NeIWF8bm43jGWQNX50mn4Hvc0jaq+V3sUE
         wYkVKCV/MzPkp9PsZehjYGynCrC5dIB4JE7MeieOApMA7a5ti9SSryC4s7CSnSTRic0g
         9L4ZrPseEuKeX1JvYQhWngKTTdw62OFAHGwJM35uGNkB3o6+BuAUcdACZQQQYt4RG+Kh
         9DCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=TVoF46ZTp3UNeAoEv5PyfO7EYExBt4O+bZ/7yxKofXw=;
        b=YwxCdvWIkjbKYfWB7ZcMfAKnExtVL0BpfawZPMzcRwkN4wbcWeV75jsR6SLrYRYdGM
         gjJjzMGvYnHPVxc1ZHmB5GtVCo98mz8dgxhXqvQxvFWD7jz6OBaJuEfaX+wDEZfyTYhS
         8pJHN0ZK6XbRjIImEw7NkRk8Obm93MoyOIOrM/PqxDCALex/sb+MfOblO5moi8LmFSex
         sXmk0O6vsVjt+a3iZ/IB0hmx+mdxcnnZtB5S6vJuzS8hLv6hkJGmaMTQn952+HaMeRLp
         qK4PWz79qI5YrzbYWL/wVx5T6xSFZqWdaZJPFFKe8shA1PjyKHlVQiHxIkBjAfsNWmOr
         Tipg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=jjhW0IgQ;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id v185si478833pfv.2.2020.06.13.10.03.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Jun 2020 10:03:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id g28so12025310qkl.0
        for <kasan-dev@googlegroups.com>; Sat, 13 Jun 2020 10:03:20 -0700 (PDT)
X-Received: by 2002:a05:620a:21cc:: with SMTP id h12mr8301162qka.194.1592067800115;
        Sat, 13 Jun 2020 10:03:20 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id c191sm6627234qke.114.2020.06.13.10.03.18
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 13 Jun 2020 10:03:19 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: AMD SME + KASAN = doom
Date: Sat, 13 Jun 2020 13:03:18 -0400
Message-Id: <E41B9DFC-F407-4C6A-BCFB-6E3E6B72BA0C@lca.pw>
References: <20200613155449.GB3090@zn.tnic>
Cc: Thomas.Lendacky@amd.com, brijesh.singh@amd.com, tglx@linutronix.de,
 glider@google.com, peterz@infradead.org, dvyukov@google.com,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
In-Reply-To: <20200613155449.GB3090@zn.tnic>
To: Borislav Petkov <bp@suse.de>
X-Mailer: iPhone Mail (17F80)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=jjhW0IgQ;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72f as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Jun 13, 2020, at 11:54 AM, Borislav Petkov <bp@suse.de> wrote:
>=20
> $ head arch/x86/mm/Makefile
> # SPDX-License-Identifier: GPL-2.0
> # Kernel does not boot with instrumentation of tlb.c and mem_encrypt*.c
> KCOV_INSTRUMENT_tlb.o                   :=3D n
> KCOV_INSTRUMENT_mem_encrypt.o           :=3D n
> KCOV_INSTRUMENT_mem_encrypt_identity.o  :=3D n
>=20
> KASAN_SANITIZE_mem_encrypt.o            :=3D n
> KASAN_SANITIZE_mem_encrypt_identity.o   :=3D n
>=20
> so something else needs to be de-KASAN-ed too.

Okay, I=E2=80=99ll try to figure out what else needs to be done.

>=20
> For now flip your Subject: AMD SME - KASAN =3D boot.

Which is a bit of shame because KASAN is proved useful for testing and at t=
he same time SME could flags some issues with drivers like megasas_raid (wh=
ere the driver will do a  firmware dump during the boot which I plan to deb=
ug more a bit later).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/E41B9DFC-F407-4C6A-BCFB-6E3E6B72BA0C%40lca.pw.
