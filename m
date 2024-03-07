Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBUMLUSXQMGQEEDOTSPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 30B24874504
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 01:09:55 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-565146088eesf164491a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 16:09:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709770194; cv=pass;
        d=google.com; s=arc-20160816;
        b=qOZ0cOFvjJoD4a+KAgsuPaypta+hTkfFF9jYfjGeroMIhLxS1zoZiC8dtdUnGY5m0f
         dD0apFciQ3f9Zarjj9YyeeM2nFgpVAB93NzU5z6ugS3je8vva1zW3W7fKXVh5DIr6qaj
         +eTP+62zlX7hs0YDDaxoskWsYVUPctABeQJ2zUvQ3GyobHwBEpXCPY42fxdlygRqtmk0
         5lyq+g0AUnvj9dG2++KsBB5iSRinA8zXnoX+97B0oe/HdxdJvPCcItGjA3/gqtcXQknn
         /mIpbMRxlIQBlgOPtBjqpdb7lS7xcBcaySOe4vFT8nMLGve278ex1gVBe3d8yNo4FWmI
         fuzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HscAqmacOX08ick/zlpwv/OAqPipCDK3EjHW/dac9vc=;
        fh=ESppa15QykEkk6tKaZUl+qYTKHfPSNMpVH0vOW8La80=;
        b=e6EHUf7uQzKgmHt1zJ2oK0uWBWHi8/xb0k7+z5mo3GgpYHnAuX8EuconUTx6AqoO9U
         Gfbcsnye1gBKWDMGt9LsNzP7rioFB92mNgjR+o6VbzWkMtwEp3ZvppviEmYw7yzHUlQc
         oK2tPnXIIkTz6ZhkCzyhEBOt0pW1q1lpZ6Ju1a2F5vhkOaRao8r6w5uMnjc0XLOrRqM+
         2UAUqGyHMwz9kKNq4hzdDzEd/Mwy6WunHisl1O3qSCzj2HAa+OKf86ax+X9A/dTUtwoJ
         Cu9RNx4bkh7JQGlxxPnLwvHeL7B5RFpuHHy6y+xYDpe6tBMbzvbElV++SZlsagjuswG4
         dDNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Wg8HbCDV;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709770194; x=1710374994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HscAqmacOX08ick/zlpwv/OAqPipCDK3EjHW/dac9vc=;
        b=pwZ8ibVV+MykPUzI8mOZB28N54qCfyaaTW2zwVkfeHaolvBVAK1hvGjEPXUI6dyUnd
         ELoGFR5uVXSJaP5IJoPy+wJXVG7Nb60DQsLSknK5F+rFCPsLwM0jXfI7gkgp9KGWRkZL
         Kc+wqkUFz7+w8dCkFBNTDrnF0KRKuxC/9TD7mC4lb3/ZX4D4h01J+r1tz31WMyn2qPYw
         +pwMiTvEJdo//2MM19d/5yo6XIjgK7b86yPMaGGNg0zDAzDDthT1mGgqbiWpSqBCSA4b
         HCcRhADeqWctqZLbp99vYb5tBSaV+Aims2/oCNXhE0T5UaknNsXLayzjBREtje3/x3Bs
         5Lvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709770194; x=1710374994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HscAqmacOX08ick/zlpwv/OAqPipCDK3EjHW/dac9vc=;
        b=B7crPFz2OdZGPBfcbdkZey9ZM2NKIoHAUAVjnSOznzpHN57eb3VI0gOKudjQ/ZEKPH
         ZiBtkY20bGs3FU9QZxU4ZSAnHuMqgBeW5/skKXUHqC64tD4K4+3biAiJ0X1jPruHSJxJ
         oqX2pdy1VqGMo4HLUppXueiUbGoMduX5jm754thGOWK4dsMkyIVuR0G93e6Xp2OBF750
         b9sB4/9bDd4LGxcg80qKHtXDfjuNSlEeQcEB8LujZd9NvF5YswZ4BKJtbgRooTvhhW/a
         RBIInlbP4UcOmulcbgu7SABfy1/nCaAQOAC/eT3fh9Sn68xEAbvZj70+rb6wIx7clknI
         cHkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFuUVSGg7XodIZBU40aRfnGmaN31eooLO27m0ftt5O0q75cJRjPyHYnXhk0uJA+93KaIrNHtupUQDEMiQaqQeHBTuFxD1ZIA==
X-Gm-Message-State: AOJu0Yz7GRPho/+C2Ntm/+QLCipaKvhIbE+s0XbyVz3F5ChW/Gbptipx
	TK0fJCzGfkMmjGsX3k15BG0r1RGFuVO9bPYemhUbe+ZzUx0knpL3
X-Google-Smtp-Source: AGHT+IEsvCSn5Xc6vchKmj2hb+rsaiaJofslB51aDONaFtqs3heWHfFmJdP3fwNnGlu28h8No009Bg==
X-Received: by 2002:a50:c192:0:b0:568:1444:a824 with SMTP id m18-20020a50c192000000b005681444a824mr483300edf.7.1709770193207;
        Wed, 06 Mar 2024 16:09:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:f12:b0:567:bc57:1e4f with SMTP id
 i18-20020a0564020f1200b00567bc571e4fls128969eda.2.-pod-prod-07-eu; Wed, 06
 Mar 2024 16:09:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU5Wt8+a+/iae9H/Er3Xwo0Zex77Es4GiR/nlRDScHQMGo9JMDxNvvVfls0NpIhD/6aKGA/5d+zmMkIlEQLc8yiqNLDMzKr7NP6HA==
X-Received: by 2002:a05:6402:1ca6:b0:567:658:412 with SMTP id cz6-20020a0564021ca600b0056706580412mr9326552edb.13.1709770190883;
        Wed, 06 Mar 2024 16:09:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709770190; cv=none;
        d=google.com; s=arc-20160816;
        b=tqvGyhRczjQ8MDqNWuB2ia7nxjTcw79tIjb5Gg9zTgqh/i5/qjhQKyTvA2/8AOtkdK
         5wHJJ2t5irZ7Cxbjlpl47DwkQpCQWOBrlSWSFPrI7bEn8nkPEv4ntIm0UUuTHIf9RKVE
         x7bioJUTWNhgOwO1/yFx7HYijH3Qpcccp3r35McvxNghgM3k8goG93YECg2niiV+yieF
         Sd19NjBJ3aHqn//3cQs45Pd/4tvaQYVrgs9lzdjvQPVSgj6V05XlwDnhV+kfU1XSKXtJ
         AuN2uwif1MI8rCCaFLjbZJiOKWloj6diKLE3yRkEUqW6wB5Rn4lOPaOytGt4+eHGhZUM
         j3pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u06nZ2DWpJktMWK7UhBFXPvQ5pWNvpHECWD/Jt3Ivqw=;
        fh=8ytN58psjDUHONbWpDpGxB5Xi4kfCdJggR+6HiUa1mM=;
        b=I/bRb4Wus3wd4DQrcCoiMIGz3tcw1CuYAAF78xVgkzxNljNJMnRDLi5FTEcEo2CHcX
         u9rWpjjGz0ot6PgYunyt9Qngpf48MWiogTS5H4NL52+L+rOtLv0Wct4c6Pd7U233vXA2
         ki8BwTV5MYowqwvuKM1AQL5EcqXY3jmi5/Gom1wwQJBDwEXyii/0rHoxRwgC4GSFErnR
         ywKZusuaxPFuV2WA/jZUzbAjvZWJ5NTPeptdS/2UfE9zi1C3QnWJLh62IQMGll52KU/e
         Cw//n4KXzmYYIc770R3u8xiEiTgULVAMN30um+3A/iFPpKE5yljE31KiM943JVEpA7hj
         +UxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Wg8HbCDV;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id b60-20020a509f42000000b0056789c4ff8dsi216661edf.0.2024.03.06.16.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 16:09:50 -0800 (PST)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id a640c23a62f3a-a45ba1f8e89so41242266b.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 16:09:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVzKg0cuDM3wzg9h5Tz5DV4W/SlWAES9KNavc3IoubanQpTLCcfzvbuNF/VRpV1wpDQzRCfBMC78SuPVarGmuFaGr8+ghlSPsqaxg==
X-Received: by 2002:a17:906:e0d5:b0:a44:9fe3:d7d1 with SMTP id gl21-20020a170906e0d500b00a449fe3d7d1mr10676200ejb.43.1709770190241;
        Wed, 06 Mar 2024 16:09:50 -0800 (PST)
Received: from mail-ej1-f52.google.com (mail-ej1-f52.google.com. [209.85.218.52])
        by smtp.gmail.com with ESMTPSA id cm29-20020a170906f59d00b00a3ce60b003asm7830010ejd.176.2024.03.06.16.09.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 16:09:49 -0800 (PST)
Received: by mail-ej1-f52.google.com with SMTP id a640c23a62f3a-a45670f9508so49329366b.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 16:09:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVTX/oJIol9sXOIV2as1FVNbsEYJAmbYexJ8z3bmP0jWbcK97nmHl8cSzN7iEzmyT8X4hVmZl2gVYK1zCnNTH2Ejcj9SmA5Vyi07w==
X-Received: by 2002:a17:906:3392:b0:a44:bf5a:2175 with SMTP id
 v18-20020a170906339200b00a44bf5a2175mr10557302eja.71.1709770189003; Wed, 06
 Mar 2024 16:09:49 -0800 (PST)
MIME-Version: 1.0
References: <3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp>
 <06c11112-db64-40ed-bb96-fa02b590a432@I-love.SAKURA.ne.jp>
 <CAHk-=whGn2hDpHDrgHEzGdicXLZMTgFq8iaH8p+HnZVWj32_VQ@mail.gmail.com> <9692c93d-1482-4750-a8fc-0ff060028675@I-love.SAKURA.ne.jp>
In-Reply-To: <9692c93d-1482-4750-a8fc-0ff060028675@I-love.SAKURA.ne.jp>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Wed, 6 Mar 2024 16:09:32 -0800
X-Gmail-Original-Message-ID: <CAHk-=wgA1N72WfT9knweT=p1jhHGV3N0C2Z+7zvGL+LgG-AwXA@mail.gmail.com>
Message-ID: <CAHk-=wgA1N72WfT9knweT=p1jhHGV3N0C2Z+7zvGL+LgG-AwXA@mail.gmail.com>
Subject: Re: [PATCH v2] x86: disable non-instrumented version of copy_mc when
 KMSAN is enabled
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "H. Peter Anvin" <hpa@zytor.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=Wg8HbCDV;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Wed, 6 Mar 2024 at 14:08, Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> Something like below one?

I'd rather leave the regular fallbacks (to memcpy and copy_to_user())
alone, and I'd just put the

        kmsan_memmove(dst, src, len - ret);

etc in the places that currently just call the MC copy functions.

The copy_mc_to_user() logic is already set up for that, since it has
to do the __uaccess_begin/end().

Changing copy_mc_to_kernel() to look visually the same would only
improve on this horror-show, I feel.

Obviously some kmsan person needs to validate your kmsan_memmove() thing, but

> Can we assume that 0 <= ret <= len is always true?

Yes. It had better be for other reasons.

                  Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwgA1N72WfT9knweT%3Dp1jhHGV3N0C2Z%2B7zvGL%2BLgG-AwXA%40mail.gmail.com.
