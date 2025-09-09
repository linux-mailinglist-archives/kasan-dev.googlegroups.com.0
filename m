Return-Path: <kasan-dev+bncBDW2JDUY5AORBJX3QDDAMGQEMWNR2VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id ADEBFB4FFD6
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 16:46:00 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-336de0ff5d6sf21290301fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 07:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757429160; cv=pass;
        d=google.com; s=arc-20240605;
        b=HBRXAYyg9BvPrAI27FZ8XD/zn2UuCuUlt2gSOf1p/he1RNgKVf/AqQ1lQ8enQzjnPb
         IeWBTBlrAURbKfH3oNNApmr8gPQWaPcXA1LiCEP+d4xMCEl8+QMNdxo7jOUzYUfSnSZc
         T+YqD5tYV4neTiA4sc5RYW+R1LPh1+nnUUIngL+Ha09oInbNy9rTooZO+6hwad+tlvIo
         WjP0jStpziEBa9qR17j6CE4RtKluuqF1mMVD0o3uZlb6I2NmUaKoThUdgeFaJgTOrgMd
         dgrPDageXGnTKoUNudqWh2lVM/WnbqkIop875SAB/AlIpd4dQmx8TR4x8c4rghhxikKe
         0yqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=C3XPU0Pj1vk/5ByZKVex8ODxdjatKlDGECk9kGs94/c=;
        fh=U75hgRp0/jtTkbr3i1u/Lf6f56hsvySwxAUzHSJeVQ0=;
        b=A2I9f9zz86ZOrwPLOqMM5c+NBABYWOwYVnmgrjcKgmgAW66xoZNdT2TxxpmTgD+NzC
         WOfHoeGvk0Ft/yH8iFxGJGtfG/K2TRNTbk0gVxUikYNKBfe1N71OWB36MZvP3c3gUJr8
         H+gF/VI1mXCkxpPFsXCM+mXFZU8giYPh006sSYpn1SJysqer1ws4vXE989gg7y8xKsu0
         96uRepHl7LwKCyxMTuusxNO3R98Ll05N28vFtkYim9kP+U+GrVcre8DsdrESNZt5Cvfc
         iYtVk8f2t61L/9DZvbD7lt2dDSx2KE4XF8VheOxspeKnl9XH7bbax9e1eVc8kpBrrEXH
         eDLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PN0NrAd2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757429160; x=1758033960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C3XPU0Pj1vk/5ByZKVex8ODxdjatKlDGECk9kGs94/c=;
        b=EZ6gPQd364rVe95qMxVLVt+pwTra/HYnGFgBNXQc4dMH1EDEG8rOrZzCMwxQrnlwIg
         sTXExmQp7nuCcNjMIlU4JNnb5PlLsZAgea65elgzLogaPw40/ZVttALgWKdPP53JPVTf
         u/YFCdWM2H3Q98EHPHWw9HUXmRJXnizU6EqRIFLTO7lgkYuQNZ/uo41DxrKBrjR+fi/A
         577/6TsQOgicMiwHWEp85q3z/Ua9yifqxPR64kO3wynPKe1XfQcW+cBSCA+fxgRYi7bi
         RrRC0kLDDcXBPvDkkherZJfN7cwprT6RZ6190ce1smKSeFg4aedKwhA8yWhtXnNkyOUt
         s4kQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757429160; x=1758033960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=C3XPU0Pj1vk/5ByZKVex8ODxdjatKlDGECk9kGs94/c=;
        b=LGZckxryg0nkECXIprCw7zh9wtGxcCAS+a7yMtCwenl05KEbd/n1ZxEdhXZpoGzXKu
         nNt6NBi8U/mtSOvAbtBCaQzyqZaYxo0+700ZOed836nMISUteGLX2sU7AvnnQa98QQms
         VctTMrOy35V+ToQ/V3PGhHuH5UAM1k19DV/+qJXJIX6ov0UkkP2oEMXFteDbd06XNHlG
         OAUQVlcEOSt+Sbeg60ypVj31BltKrrCHqh2Z58JiuVdvCSY/YW3AKQ8BOWzZGiZ/stdS
         +XAvb2mMJ4nyjy5FKEdy0d4wDYfetiE+0zPBHnRU1TpIf/Rtpqxr6FocWPues2jjqH3G
         tGpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757429160; x=1758033960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=C3XPU0Pj1vk/5ByZKVex8ODxdjatKlDGECk9kGs94/c=;
        b=pSJN4N4D05Rneakx2obBUaPUwgOu82oWbfyCnRnS3g8S2s29XOvwGHW6QHx/5V/0gL
         2eKo7XwGRokzp1/a9XPGL35TRgEWbImxksxPsW6tgRYsc3zfjyTT2k6AfGIyucRkEVWn
         IFnjFrfiiWt6j74k0B4GXeJvHzkvVsM1coj3gO5g4ekVqTRyKEseUETc8lbB5SuMy6vA
         uVCjvoGaX00HvO3jpEFy/UvvYHsRRysUVl5rrSMBsXHE/eCl/IHaG8KjtXB3sXLZBpbK
         IxVK3Hbp52rnt8NQ164sKROOs9u1vQGwzmvSaSrtH6EMio+QwzItv3npaC2zt3ExayH/
         Toaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFCrwWjo5ckCTAsQTiayMU+3Cj/Hz7BE/nHSAYOQYWn1e43NmDeIkN8nae/X26sUnn03O8CQ==@lfdr.de
X-Gm-Message-State: AOJu0YxEky9Ax6b8fpE6MoTCZrEZ+gyrNpq+2sMUMlx3bu+uU6c3P5IC
	HHLFQ71lXUKe1KLvAHeUdwxOQ1xCQR9a+DVsia3P0Atag5FZzKlG3ZHE
X-Google-Smtp-Source: AGHT+IF44RzP5EFL+4WmImQY1Eh+RdMz6ldkKI8bRRLBF2daVnJEmfZA6TL4IQcuI0E648J2A3mGuA==
X-Received: by 2002:a05:651c:1117:10b0:336:5d33:c394 with SMTP id 38308e7fff4ca-33b56213846mr33956271fa.33.1757429159410;
        Tue, 09 Sep 2025 07:45:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd3ZIFj7a/tK500z3EdOwBMWSGxOXVg/1h1a6dU31fUVQ==
Received: by 2002:a05:651c:20cf:10b0:338:97c:7be4 with SMTP id
 38308e7fff4ca-338cd477ddbls9023271fa.1.-pod-prod-04-eu; Tue, 09 Sep 2025
 07:45:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZT8pahbmIjJqLpf5iAS4I2YPdRo5xKdlUecu3htjbduzmJ93XAgdqjiJanCnITq7inDSqQI4Tw6k=@googlegroups.com
X-Received: by 2002:a05:651c:1117:10b0:336:5d33:c394 with SMTP id 38308e7fff4ca-33b56213846mr33955271fa.33.1757429156566;
        Tue, 09 Sep 2025 07:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757429156; cv=none;
        d=google.com; s=arc-20240605;
        b=i8f66JxlMz/ZLqiuqYY5wjLPKozk2DRdqQ6rs2CpLv/3FZXCrafEeRkOpdyOVUr3DK
         OHvA4xsQnQwHRwigEQXa9hbHBb74VKtXhCY2YQ5hdX0GvcKdtCj+UqZT2BbBG68K9MMH
         K9dY2S1Flbw3x+g87mb7JJVK2y3t+8N/8zSpASbFLwOx5jXdmMEGzm5WXv+3mY1kFgpl
         1uMslxirtd52W/uri+22kDuXjXVVTb6dJbAddCznJFfUgSKY3E3itGUXxdxHKtb8LUPD
         swryM/xZzPCfmGy8LtUOVcW5djm/s4OQ/SalVZEgR4LwynGhaJR/DukmN0VbAw/BcNnY
         eC2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8T/yu3N8TV6o0nCvXPls2b7J7vwcGfC7bXk5KdT0X2s=;
        fh=BjLUBJOa8tD7oaKXdh/Wd0/Un6BDIUWId6LCOfX79qs=;
        b=KrokgapqmQSiwvShcTdup2hBIS9ApUDfv52HaZ6zOKqZzcZi/QgdoGAVtkJDN4aVRN
         62IUvwklOE4SSCZDdYLtz6NTvsEo+6eg/ijIE4mk43ECjrNXTHfIn3EIFb8PWxho5BSw
         lJ2AQn9EHuTbgBa/FRotllsWz9GfIgMbhNrZo5pp0D/CEcZcoJO+fvDf2VIDTznge+Yn
         S6GICwws2hHCJnaTvkz3gW/vUhjVeUSakx7l1t6ax+B77lXchet8I2QNuodtuomkUrp5
         64VcaviNr8wvoufeoN6iuaqPxOrhxocyeCORjrS4+WuEhPGf9J0zw3Svz1xVfSIy/ekr
         kYPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PN0NrAd2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4faaadbsi3273181fa.5.2025.09.09.07.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 07:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-45de60d39b7so16139755e9.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 07:45:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBCi0Er/1vCBPPBvqjALmhu73X6ZIyPkyPIomPNIk4tBuO6ANDzoJBdmCbyHzIfGxKkw3hEs34hFs=@googlegroups.com
X-Gm-Gg: ASbGncumn6zFDV1We2DjjW3X08KC6xMgQqjXKoHK+ieHwPPGnDMtO9MStIm0WpcnakC
	YvE6DxzpgTWMG66b1XlmQsXOeBxjZgGVWApKUVnSc1kQWKW+V9qcE1xi4mC9ys9YP3vesIN8f7B
	J6oEq6psNPDGTI2dYBUQR8OgmD2E/bhVzvclXwJwD9xRm8GjuOki/OieekEqn8p5Js0jyx6NwRQ
	uJEKgWM
X-Received: by 2002:a05:6000:2c0d:b0:3e7:441e:c9e1 with SMTP id
 ffacd0b85a97d-3e7441ecde8mr6759404f8f.18.1757429155814; Tue, 09 Sep 2025
 07:45:55 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZf1YeWzf38XjkXPjTH3dqSCeZ2_XaK0AGUeG05UuXPAbw@mail.gmail.com>
 <cfz7zprwfird7gf5fl36zdpmv3lmht2ibcfwkeulqocw3kokpl@u6snlpuqcc5k>
 <CA+fCnZe52tKCuGUP0LzbAsxqiukOXyLFT4Zc6_c0K1mFCXJ=dQ@mail.gmail.com> <m7sliogcv2ggy2m7inkzy5p6fkpinic7hqtjoo22ewycancs64@dnfcl2khgfur>
In-Reply-To: <m7sliogcv2ggy2m7inkzy5p6fkpinic7hqtjoo22ewycancs64@dnfcl2khgfur>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 9 Sep 2025 16:45:43 +0200
X-Gm-Features: AS18NWCko3Nu4vYg1YjsVoZlO3pFTQTWFNFMYZcWhGCR7k_x37D691H981KEWl4
Message-ID: <CA+fCnZc3ZY43KeQcWSw4kgcCqJpAvNj6gKd+x0AkjhuE2R8Hdw@mail.gmail.com>
Subject: Re: [PATCH v5 15/19] kasan: x86: Apply multishot to the inline report handler
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PN0NrAd2;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::336
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

On Tue, Sep 9, 2025 at 10:42=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> On 2025-09-08 at 22:19:11 +0200, Andrey Konovalov wrote:
> >On Mon, Sep 8, 2025 at 3:04=E2=80=AFPM Maciej Wieczor-Retman
> ><maciej.wieczor-retman@intel.com> wrote:
> >>
> >> >> +       if (kasan_multi_shot_enabled())
> >> >> +               return true;
> >> >
> >> >It's odd this this is required on x86 but not on arm64, see my commen=
t
> >> >on the patch that adds kasan_inline_handler().
> >> >
> >>
> >> I think this is needed if we want to keep the kasan_inline_recover bel=
ow.
> >> Because without this patch, kasan_report() will report a mismatch, an =
then die()
> >> will be called. So the multishot gets ignored.
> >
> >But die() should be called only when recovery is disabled. And
> >recovery should always be enabled.
>
> Hmm I thought when I was testing inline mode last time, that recovery was=
 always
> disabled. I'll recheck later.
>
> But just looking at llvm code, hwasan-recover has init(false). And the ke=
rnel
> doesn't do anything to this value in Makefile.kasan. Perhaps it just need=
s to be
> corrected in the Makefile.kasan?

Recovery should be disabled as the default when
-fsanitize=3Dkernel-hwaddress is used (unless something was
broken/changed); see this patch:

https://github.com/llvm/llvm-project/commit/1ba9d9c6ca1ffeef7e833261ebca463=
a92adf82f

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZc3ZY43KeQcWSw4kgcCqJpAvNj6gKd%2Bx0AkjhuE2R8Hdw%40mail.gmail.com.
