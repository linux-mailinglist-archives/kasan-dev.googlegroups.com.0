Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHGLZDEAMGQELL532LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 65EFEC486BA
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 18:49:18 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7b0e73b0eadsf7363555b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 09:49:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762796957; cv=pass;
        d=google.com; s=arc-20240605;
        b=NtFaDQ+jlqDWOVo5HopVlG9koPPz7eeSmFI0ntlWewz9k8u7P6g1MvXfv8p5JxOVkO
         p2x7agLYG44OR6ScQn8MpNFCmtIomvDc/VJBFl95q/bTY+5KlmZKEaZj5308ZiAbyOh7
         FYbKbHANobf0R5FT7HLvdga19ReRsqdlq+qpDzsagj8rv3fTmCxq0YDExZdQ0PdK6S0Z
         cU6/+EDPbAHD47GIUr2n9qjQCEQGF6hKqcmp/BF4UvpntuJf3rUUZzsDXhld8mIWulkr
         QvnPdtzkHk7e8dcO40v/w9VLAqVXktSs/jxfFhA0P48tjYJx7Bxb2C4aWhLXJw1CFwth
         /dkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eCE7NpJMTbsPUnTOwDD1ke6kupLDLA6pzBGGe+LFoJA=;
        fh=U4oXVdfc6I5Mh19+bnAg4E84okirG5VP4qKhV7bBNY8=;
        b=gaqUSzEBeI1i9ln07RgJz+0gtBI4kCD5xrssLQmoyw7utm2fNTLFG7rWRyoX/uEKey
         Iam0WCzh8wF+0whJ37A1aXBicf5y2o5qY2HkAYTrndJWtkHwDRkIKFrbw4nid3GlZ0iw
         MYsgY3eZt+Hj2QSReK2beI+k5Wku40jgjB/wyiHg60qg5wSK6EocHpXWRhoLeUMzUZPZ
         xcPaAiD7Ncc78nMAuf24gz4dz2EEuf0RJo9/PX14kBVSTRiZdgnYPuI3QGlRYopOHh1D
         jOtuPPwquaFgO+e4fLQ+hzdxP7TA6vL0ySQIfVP6UMt6KhySsGR/mmDdpYj+KXIFHIY2
         w4LQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wwT8g0Jk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762796957; x=1763401757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eCE7NpJMTbsPUnTOwDD1ke6kupLDLA6pzBGGe+LFoJA=;
        b=ummeEbddEnZ/CqerZIX9MFcgXavHqf+dsMr4RSS1EsjoLXp+UE8v93WYjnPOKlrgd4
         8nxULHBmkDhSZFZSDvkuBWVv9ZYg/TP1BC45xTFQbIbXZML8qudYk7sXwfAyKFmxPgpd
         ZG2LQsud9AYm00qFNq+KLk5YCkiyTsfoItihcxIhk19K6KS8STbN7ATp4OOJS5ERIQy7
         ArhbDAS541Dk3V41Tiq41/rmgr/+0BPSwtRQBe2amczI6gQJJ/jflCaflu/D9ZOW7YI7
         LX+EsHwwb2DdnMiJKElHRGn4n+ClI8Nl499DlPh5n9meij42Mr8LqGITf8KQGp5Oktz0
         HMWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762796957; x=1763401757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eCE7NpJMTbsPUnTOwDD1ke6kupLDLA6pzBGGe+LFoJA=;
        b=sFrPffh87iGATuuYhbOp5/Z3BUcZkuEbHxhrVjz7fcPsjy2ixbDMv4/KRSzj0DLwqI
         BjTcnDWXYVLJhU3U1PptTWGH01GAEp4E7qLKGvqnBk/9vhAMjvTStVLzmOblEwCu/rql
         krQSTGkFufo4a4NZfpWe1VbaOvs2wCV6Pi0R8JCV+w3NChMNsokjMD+g4lrmSF5lrb0Q
         Pzmqh84L1/Jy7Vx2ROu0jTuqJL0sowkG5ZYiCVY8rv7h1U1AvVGgAfKPoUYhCm7LgBZ8
         ejamG3WzrLUbHy2vzUFPOKULaAHA8//y+Dd0HLEiUbVZthpZLjyrsQY+d2WCWU1J8b7u
         ckcw==
X-Forwarded-Encrypted: i=2; AJvYcCVqmpIn0mqrA58dQpfnrdqIP5A9MfPy5vaIW8FbRWwIWzq4eevKb3JgyWTFkGYMDOBkx4/A8w==@lfdr.de
X-Gm-Message-State: AOJu0Yyt5AKKLnKcHsvOEGmtQ2+nI8gOAAuLp13KAuDcnzFWcqCZAzzE
	NN4XBnD6Pcw0wOuVWNfCYV0Autc15bi5ZoM3fgRLI7uGgI/CluYe2Rms
X-Google-Smtp-Source: AGHT+IEsWT1Y7NZI5E3eU5xCc+Chc3+Xo1Pc20/EqG/Mg0PBi9/snD/gG7slWoOlRUeqz0Na9VeJRw==
X-Received: by 2002:a05:6a00:2311:b0:7a2:8853:28f6 with SMTP id d2e1a72fcca58-7b226b9272cmr10504973b3a.22.1762796956627;
        Mon, 10 Nov 2025 09:49:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z3ke/glQ+LB04X86Ed/tuowD/LLArpuLbs75nKJjMPBw=="
Received: by 2002:a05:6a00:6d48:20b0:7b0:8151:5d07 with SMTP id
 d2e1a72fcca58-7b0815164b4ls2922600b3a.1.-pod-prod-08-us; Mon, 10 Nov 2025
 09:49:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU9C/X6EHsEzE5SmPvGd+oCdpuPk1fTns5AhkBn/ngfEeZQEYxgzQXO3pAzFBkTdNfvQF5DwSKhkLE=@googlegroups.com
X-Received: by 2002:a05:6a20:94ca:b0:350:ee00:3c9f with SMTP id adf61e73a8af0-353a24f7cbcmr12486527637.48.1762796955220;
        Mon, 10 Nov 2025 09:49:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762796955; cv=none;
        d=google.com; s=arc-20240605;
        b=F/jQPnj+xtdo5qfAaXSUnyHeyHZjHQXKn0sdc1B9m3TmhdmA4bw6kVbaYtqGOQEbfc
         GDuoAh5/5FXl5WXxZgXxbMJTGebnP4dRquIEHe38ldyCABoe0JfkLgdLwzAlyylXUNGD
         YFOe6njYebeGeUBHgBSQkoA/nZ4bI39a6R8Zly6z11/Q+6ssWMyABf+ufj4fzkGiAs23
         8o8qCSeddNATt4elTV+7gFwBAcXtiV3r3iciPZ1ub0mA58xO2PWetLdw5VFpsk/S2b+W
         +IwRcrhQYnPmvq2+HtfR8Qz6zWIiTW7hkMQ+gVrZaxVYd2OWL/vQ2QgaGjQ2WLvgJQPu
         lwyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BPbi2NPPrBKl69IkN7kcBKOxfNw5kLfKkjmbVe2fGbs=;
        fh=zMEYTaLCs2u3VrsUIWmwhrBMZOlleMuApkziNb6/JxA=;
        b=V1JwhlPW/5jZ9ckqDdjhbzETvZn63yeQqRFVpQLI8DHBsQHs59YJcoTvZt+zoH8x1U
         nThO0w0uNLxlI4jOT5xEg1M3hxJKgKSajA/lP3M2s3dSWJR4XpknEQSpfO+5HuaQV/kN
         IZi60hIH8asava7XdXRQyAXfnQ24TbmlZCHuWxetBjBDbcm/OJuae2gFSqLmsuZfGUAd
         FQs+sqCbtCOrMow2oMwgU2FMLcdw+RRLXbvamfOCaySspo/81tJbfMZZtkX62u1yoGhK
         w0Rn5wAnokxAn4ocR+85xK2O3Kpi1etBGTatJyGpfDY2R8O+Mwu0TDgv7vJHfl80jsJa
         1phQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wwT8g0Jk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b0cba7b5f7si310396b3a.6.2025.11.10.09.49.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 09:49:15 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-882451b353fso11739756d6.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 09:49:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVy+vC5wZ5QbQUFmLEY9IxSEJC0if65JQjYcvZgifeICNJHZQSJINTSgQgp7rYbDe1EizyqBWf6xO0=@googlegroups.com
X-Gm-Gg: ASbGncu9Nv6bC/Clw57gDTb5z7DoGfUHSCOyUUnq6uiJkZ43qurc1DeXvYn4+SDtoeE
	+k3r7PEepFR2wA3fw1oTSTDJdXL9Pv21HSxHd7dHrorKyl1eudGmpMQMqswQgECUMB5cTZHjZnj
	MUKURdK12oBjyLqt4uRCx3csSJ2LvzJjIFDxRLXO/OBe08K9kuSI9kTF0aHRHE6sj3iByiC9qJg
	8M+mAdZ+2uIRmIlPOIdiz5JVwHyD/UHXRCiAqQKS/k2EJNvdem5vIFtq9iCZDpjje2KxvnY4PSO
	tszjpFEuLZ7hbhOdy99ZY4LBGQ==
X-Received: by 2002:a05:6214:1cc2:b0:880:4bde:e0cb with SMTP id
 6a1803df08f44-882385de9demr131074376d6.29.1762796952867; Mon, 10 Nov 2025
 09:49:12 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <0ca5d46e292e5074c119c7c58e6ec9901fb0ed73.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <0ca5d46e292e5074c119c7c58e6ec9901fb0ed73.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Nov 2025 18:48:35 +0100
X-Gm-Features: AWmQ_bkJUSMUoO8onDW_Kv00mrjnva_voIrMRMQdowErjlplIdY_Q4t-6BqV8ig
Message-ID: <CAG_fn=W033hGM7_jnj0irwW0gc6McLw2nbhfZROWfieqKTxVdQ@mail.gmail.com>
Subject: Re: [PATCH v6 14/18] x86: Minimal SLAB alignment
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wwT8g0Jk;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> diff --git a/arch/x86/include/asm/cache.h b/arch/x86/include/asm/cache.h
> index 69404eae9983..3232583b5487 100644
> --- a/arch/x86/include/asm/cache.h
> +++ b/arch/x86/include/asm/cache.h
> @@ -21,4 +21,8 @@
>  #endif
>  #endif
>
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)

I don't think linux/linkage.h (the only header included here) defines
KASAN_SHADOW_SCALE_SHIFT, does it?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW033hGM7_jnj0irwW0gc6McLw2nbhfZROWfieqKTxVdQ%40mail.gmail.com.
