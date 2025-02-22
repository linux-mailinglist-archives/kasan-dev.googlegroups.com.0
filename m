Return-Path: <kasan-dev+bncBDW2JDUY5AORBCGQ466QMGQE3P3WWOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BC58A40954
	for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 16:06:50 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5461901d470sf2580547e87.1
        for <lists+kasan-dev@lfdr.de>; Sat, 22 Feb 2025 07:06:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740236809; cv=pass;
        d=google.com; s=arc-20240605;
        b=ddN5J6IQZ7vhVUdw/trsLrrXWMB7HnvWRwA48jiQH88VzzCrmOg8OzdIoyEPm8lcSH
         GA+5xqL5m24pG3ODQ82RiaTvN/VG3E1B1+OEpvZU6uWCbkw1Wz4vvUQ4Ty3fzw51EZUc
         iC3CsywXxOayAoT32eyyam+vmIWT6AUrLu/hrNed33XJvuWoT5AgboVPo7HqO8CKqs0p
         4HttNutetGmFxFeY4KAaMpxUYwYxO+JuLzvJNRT70dX56bPKQX1Kz2eA7ag0giEdV/V8
         NPpC5x7zKrfY5fJl6aEU2iD+Hi3wkRLLEEIDg3JlP7qJG/KRYVhDkvIyiREdwqgycJOU
         PMVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3kNYvDmM3MNKqKgFfi50dtouG/BlOVcSaEDElSeBD5o=;
        fh=s0Qjxvmb6W/RGlAUYQu49+HWAoAJKq595pJU3kEgfmU=;
        b=jFsAk0GZ3v1ns/EwPPBu6i6YYobOmIao7dE2KxYADX6Wg54VNBAYPZQEHicY3R10MB
         SsocR5Wglm+jYCxixE5Vt/ZvOSZj0D1xYF+gQvL/pnRuHc42lOE96Xxj7hihlpeVzDSo
         ahDEOa64LzYMMdeJyyiZgVT32SnRPmc3FDoDDOMslK1Y9tk0J2LUYVkocaA2AbWp7j/s
         lNImILftilT4XbrzQHq6p13H3tpsNUcoY6xU1EXdXAtlx3/0DeRtJMr/P+L/7MWQeQqH
         AuIbJ2ng3A2wRnKE/gWMXyGwCbGPFflU14Y/BpD4IbFGpTbn9dfSsJkj1xdXwIirH1Ce
         2jUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mm+9Mhlx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740236809; x=1740841609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3kNYvDmM3MNKqKgFfi50dtouG/BlOVcSaEDElSeBD5o=;
        b=ejdS+J0+VuuWBzxnR7iuDDk1LkN8hVxcLsHHz8fp4RWE3mk4wZmXUEjRioIpn1YFjS
         32Mm4eYZKUI+EW+npJSXdlxvVkRhChAW83cuTr+8rYfmNM5UgFOde5ddVhVvb81WUoAO
         hddlURuBK9NhdnGtaLLQlqE4ytHEo0pntx04t8xVy2qypbwgH1qyaEUgBO1YI/jrYf4w
         McpPLq/7gZ0SYHgGF8g/FAh6w0KRmOjlEfAMpjCx7CPig7yYE7+N+MiDFCimJilzW+zu
         VkVeOcM0FYQV09Dsvjr83niHuwOgbxzwoNMpH4X9Dkoh2t6osIKkZh33JcPL1M2OopZ8
         ojyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740236809; x=1740841609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3kNYvDmM3MNKqKgFfi50dtouG/BlOVcSaEDElSeBD5o=;
        b=fL98ccwHYgLnuvnfMIcSvVJnYJRORXB7tioA0ZVk8rppLtfJK9BKsL8m6EfByxNmWX
         TCMzA7vs5XlKliXuXo9HYbQr5sSoQMzufzhrjMHCoH1nqSLQ8rIwpbN+SBPq+hPMPSkS
         vLyv9PklE9VLjAFCDh8QnqcuHkBCW3zpW46lwh7XRW10tgW+LPRd60m+VsYPdrTQOpZN
         VJc6Sbp/6sukznjDg4Si0DuWeLroifXL4fJ/EorjAa9nc0ME6pjsjIpPbsNKGtlZSyEi
         iTV16HdP287SxgfwQ9VRF7KsG/8t9ZYws0Bsuc6kqqcApCV9kHGzo2XBMKM/XSsz4uLN
         BbzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740236809; x=1740841609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3kNYvDmM3MNKqKgFfi50dtouG/BlOVcSaEDElSeBD5o=;
        b=nv6mplh8vE9s7B9LzOOJdVuDbi3fPHf+6l0IJEeI65UJGowkgqpiWU72AHqGwwMBG4
         z0OHUfoZyoYH4zrjO8BGvMFuoIz3CMF5q7kwQYMBZGI8BRB3HOpEXVnmKM2wH3JvAitx
         HT4my9aMYJmA0NhWot2k1fMmBog/rljiSMefC1u9VM0elATUtUsxPdUjTXTzBKNi8ai/
         06rlVRCX1BH6T4rplCHT7EVb8z2nYt6owiz6/2j7SmvJBe9vjAg0/6ie1vorLCrd2vgr
         SJMX+h6978GVJdfo9MveI/kB8Qb7lik+oP1hFlRU7W+9U1O+oGsmogSg8DYaQS858EJ5
         NcNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+zdEhm8aNl6K4UiG80RKew/UhL5BqkyfDzw7MMz1uxrvR9OQ26JkJyWjiDei2UJdCKw0gLA==@lfdr.de
X-Gm-Message-State: AOJu0Ywg58Lih/cnwRawiaca4Axp9tkLgKJK88dZt9gWaMXyUaHEYizb
	4y+fyn+SCW7zA/a7iRxcejVHV1+eTY3NsUq8J2VHjeBZXcoLvR+0
X-Google-Smtp-Source: AGHT+IHLpIb704yJhSewKb1dLB6q7JeWC6ykTZw3Tyo5+BjHTA7GxobpjnINmDzaFazUOW4YXY7O1A==
X-Received: by 2002:a05:6512:104e:b0:546:2ea9:6666 with SMTP id 2adb3069b0e04-54838f4e48emr3693167e87.34.1740236808718;
        Sat, 22 Feb 2025 07:06:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGJa6VBuRBcKWNldNUnRkD5MAumOnRGdAp19lvbncqx/w==
Received: by 2002:a19:2d18:0:b0:545:285c:f14f with SMTP id 2adb3069b0e04-546da1bb527ls353464e87.2.-pod-prod-08-eu;
 Sat, 22 Feb 2025 07:06:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWOT7mBHaFpV4eSHaI1AYjC9Ah3FmqG2hwcFJJRPXZTt5bCrmHN3OaBEPz8OGMd0ulVMpM3CFL79pU=@googlegroups.com
X-Received: by 2002:a05:6512:ba6:b0:545:f70:8aa0 with SMTP id 2adb3069b0e04-54838f4ed99mr3607745e87.33.1740236806035;
        Sat, 22 Feb 2025 07:06:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740236806; cv=none;
        d=google.com; s=arc-20240605;
        b=Drs35NqKFqHsB3AuUNZzXGQdiq+N93YHaq6nvgOJFuQUh6r0XY/Y3WjH1VF0SPiLJn
         GY62wWyMO67Rm+vEbIkOQjzV2Un2uB5JyGFug0vwfW3UxfKcybI6CbVbbjq0nJCdSnEM
         wwqFOhMcjUhmYdnIQbIVvcdAziRj+nzMMga8gZ4yocp8GU6uggE2cOgDMypNxnzgydAe
         8BwL0PsTEmqapn0+R+KmBx7bGQKOtBa8BfHLQg61LI/YRVSz5aCKNckARq/blbtMcbnM
         Bp/Ne/9LvZOi6Cd3KULij0K93VlUzPG7SFh9dbmgavXlhkLu1TnxFXaXkosg9ATQBhP/
         bWJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Q6IG2omqZBIGpvuNs0TcKEamdR0fZsdINqF9gR0Bnm8=;
        fh=AhWyauX5jz0LKe4FviBcEMwceGnKUBWo9LyqtOcbItE=;
        b=ORyJQZFR2SFAcL40lUSCZ28D0swASZsuhrYqfifWrbSbsl9LezCJ8zFw4G2G1HLdXL
         VZso/jEioLPwPX0SIowOtNu7FR7rYdWC3y+uYRkCi03Kra7mb6oZ0ovlArtxnHC0CA65
         ypbia+AYs04tR/s6CozG8dSvWKrrpvlFt7oCvCNOWyZ4GEok8nFYg3mezHnLMJ4zt9WD
         QErgqJSwY76kODs33DZ9Xqq0fYQcMfqcdtycOnwcBgfkcegKBqG57vo2OSZeNDUzOO7s
         2jcKagsDhHYwd+MQLM1bZgexJ5f2fy8FPbs9Km2GcOdFrACsu0vfyjPZvKau1v4J/F/O
         DidQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mm+9Mhlx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5452a0db925si233096e87.5.2025.02.22.07.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 22 Feb 2025 07:06:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-439a2780b44so19140475e9.1
        for <kasan-dev@googlegroups.com>; Sat, 22 Feb 2025 07:06:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXP2tlc0GcEbFJbnUSHF+e4uMI+j5QPeoZo1XomCR8RnYOOSuJKeRrgd2JWMh5IeWoDo2UAA4PZ0bg=@googlegroups.com
X-Gm-Gg: ASbGncvROwLlQbJTIE9GwEXD6dbdW6IZVgRVj8UaXY1VJY6+ObZFh9LkE/3K8JSRKBv
	sTXY3jzs+sni42QBiIkRcrEMrchkXdfGrMnyDxPwpscXD+nOuL1l15cM6U305mKa0MVtZW4rE+J
	BBVblfIspKdg==
X-Received: by 2002:a5d:6d85:0:b0:38f:3d74:9af with SMTP id
 ffacd0b85a97d-38f6f0d0806mr6580744f8f.45.1740236805307; Sat, 22 Feb 2025
 07:06:45 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <d266338a0eae1f673802e41d7230c4c92c3532b3.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZezPtE+xaZpsf3B5MwhpfdQV+5b4EgAa9PX0FR1+iawfA@mail.gmail.com> <afc4db6mt3uuimj4lokfeglhqc22u5ckgvunqtiwecjan5vjj2@lvphketnxhhr>
In-Reply-To: <afc4db6mt3uuimj4lokfeglhqc22u5ckgvunqtiwecjan5vjj2@lvphketnxhhr>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 22 Feb 2025 16:06:34 +0100
X-Gm-Features: AWEUYZkJMUGTJnf0tyUt8lWwOa_mEt-qqEj8jwlDkAHHUkPqAhs2iK4gMtYGacQ
Message-ID: <CA+fCnZdhvzUs6NWxCz+PcxBf=tz5xcsHOraKT5+y+vNJb2b-Lg@mail.gmail.com>
Subject: Re: [PATCH v2 14/14] x86: Make software tag-based kasan available
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mm+9Mhlx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e
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

On Fri, Feb 21, 2025 at 3:45=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >What's the purpose of this config option? I think we can just change
> >the value of the KASAN_SHADOW_SCALE_SHIFT define when KASAN_SW_TAGS is
> >enabled.
>
> Well, I was aiming at later adding the "default 5 if KASAN_SW_TAGS_DENSE"=
, and
> this way it would look much cleaner than the:
>
> if KASAN_SW_TAGS
>         if KASAN_SW_TAGS_DENSE
>                 KASAN_SHADOW_SCALE_SHIFT =3D 5
>         else
>                 KASAN_SHADOW_SCALE_SHIFT =3D 4
> else
>         KASAN_SHADOW_SCALE_SHIFT =3D 3

I think this is fine. It's still better than adding a non-configurable
config option.

> But now that I think of it, it should be possible to overwrite the
> KASAN_SHADOW_SCALE_SHIFT from non-arch code if dense mode is enabled.

This should also work. Especially since the dense mode will probably
work for arm64 as well.

But let's keep this series self-contained.

> That's a topic for the next series but I'd imagine all architectures woul=
d
> normally use the 16 memory bytes / shadow byte and if they'd care for the=
 dense
> mode they'd go for 32 memory bytes / shadow byte. Or do you think that's =
a
> faulty assumption?

Probably, but for sure I don't know, not that many architectures that
care about memory tagging yet :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdhvzUs6NWxCz%2BPcxBf%3Dtz5xcsHOraKT5%2By%2BvNJb2b-Lg%40mail.gmail.c=
om.
