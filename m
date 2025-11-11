Return-Path: <kasan-dev+bncBCCMH5WKTMGRBB4FZTEAMGQEHUXURBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id ED65EC4CABA
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:31:53 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-297e1cf9aedsf92005065ad.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:31:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762853512; cv=pass;
        d=google.com; s=arc-20240605;
        b=HK9U29v03bdtUUU1ZXEZFOEU+x4b8zoqMgj99Fco9jQv2zSH6YDM7X1+cx2CLCbBi4
         NugOkt0dGvyvMSVJKPVDnZaQiB6q1yEcZHSPX9AorYT9Lu28VZ0bSkT6+5ec86++hZvb
         3OOtu74qRfOOAtEYd0y2ZuazPTJLkme7wNh6DHTF1JG5UNWHTakLwHcVpM3fehoGJx6h
         ZwowWEqMr4NJQN6imlLYmsJ3T0kvwV8vY93IQQAfJXnGUjtu+ZIr8aE7NUcIM6nVtfLt
         FTwa18MREtd3e+D1bya2y8sahKBL+kB58vWwLHCqVIVxkh6ON8Bq6wMT9Aa/kaBUZe89
         s0vg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PWA17HZrr2h1wWKf42yT43ua80vPCPCb46csXDFX+TA=;
        fh=Wb9QWIler21t9mLjTjRJRWIkQwx5chLH5MXGeB2e/BY=;
        b=K9zj1Ms71u0kXGX/uFHB6oiAk16Bt7ceaVHDZv/ikH7+rvDvVepa5h7cOSVdkpgNHK
         Wg2bAw3XwQ6WoMZ6LHqxNGnSPPenpap6CZvWSQkWTe7FO63toeARKiLSVr1xpuLlnpwh
         9x6Y9Wy7CZadCo8b7/MyjXC2eYEkhgLa+2BBS6l7iX7gQeO3GERYQMIDHwX+gyzq//9P
         JZM9JHAp8Yvg1awLK7i4DJV9D3RgvpelhTuK54UvtOOpqIXsY6XwPcIUEebl4FK+Kbju
         M+pdzGsGJPCZPwauJDcG5iQUtMrypHQYtb+0oWUDHO/6P4DssjwvYPm4UNRgdhsYnOEz
         2aqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KGpwW8Oa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762853512; x=1763458312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PWA17HZrr2h1wWKf42yT43ua80vPCPCb46csXDFX+TA=;
        b=HqVUbgcekDE28qQGglI+lfpm3B+zuGuK3xzl4W8KI36P4A1QOaek9aQmAVhTc5/F97
         V6mjcNbj91GUZvOIwVNEikFDr2Sw7mLLdX5SREaJ9jTEkxyfmHmsSIg9UoQaeuo5Tsck
         8VdHLmohBNIdFwu59qW7XBtVJDJ4Hvee4JfrgXTFHSPeMCalgRilbo5f6E0PivAyI26a
         6TeGnBrnToQ7/FrgcapNMUTwZaoTVkAwsqrXulVeoCRCJjJfHZD8LFFxP7UsNlHzXXIV
         9olf9vyFdc9m/r/EPBOcdPCwPJW4eDy0ijA0vt3bOcZKsUDvJUKAaon44oaw1RSEX+WE
         Zong==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762853512; x=1763458312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PWA17HZrr2h1wWKf42yT43ua80vPCPCb46csXDFX+TA=;
        b=FZ2MAeaDQqslM7dOJV1y7m2Vc0/swv28JtDnmi/c7IVBtfp0fy7vlYWbvL0QwOiql9
         Y2zFlr4PvaHfukOGpPlDkcWVIGp648fj47NEEOOK1MvOkF7PfB/eyCjHMurCbPi2NErf
         p1zZz/B3lpG4kCEOpnp8I2y3nBkw3UFEk97kpNxnSMfbRi4vmUgiCH+mIuNGpMwCcxc6
         y/wq8ocZvmZE6L2XOO8MKS/uyb4YO+2yDUhVFLJIPe5jjEfHBdT7CF1QqAPcx1hGOmVO
         eLkbq77TUWAx+X0MBh1D/wTu8F3OU51keByyAPgG4Wb4xYLicY/KAtlZEZH1WGTKWBl4
         Uiow==
X-Forwarded-Encrypted: i=2; AJvYcCWOoaxH5Ws1tlDjFufq7iv6HVR26P5T6xiUPb9omNLOfd2T86/AModd+AfA5dyYEgsBvyNlWg==@lfdr.de
X-Gm-Message-State: AOJu0YwUzL23mjblX3W1Xp5JToanSuozoxutxzrgo7xODwSDnkVGqX7n
	1c8Uya6+BEYkBvZxlRDdWTMhH5W+/V5jhGhW9N8q8ItcoaL2hAaiiAVr
X-Google-Smtp-Source: AGHT+IGoBOLDHK1UiXRLda5lFUNm375YAbvwpbwJ/0ld+CrFPvqVJuUjh34JBHoi7M5l/DhZS5qgGg==
X-Received: by 2002:a17:903:1a8d:b0:298:3545:81e2 with SMTP id d9443c01a7336-298354584d6mr63438915ad.22.1762853512354;
        Tue, 11 Nov 2025 01:31:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y1mqn9Txma9uAn+gpqItqUJ2kgqqzPhM4HrUZWt7E+lA=="
Received: by 2002:a17:902:fb47:b0:266:5df2:e141 with SMTP id
 d9443c01a7336-29651e81cc3ls39645455ad.0.-pod-prod-01-us; Tue, 11 Nov 2025
 01:31:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXoku0RCALq2iEkCjYggLPibpw2aoBv62eVN6pvenpr+E0dpjKxCY3V4PCEF8X4iHvaZVJadfToa0c=@googlegroups.com
X-Received: by 2002:a17:903:2f86:b0:295:596f:84ef with SMTP id d9443c01a7336-297e56be204mr134425085ad.31.1762853510997;
        Tue, 11 Nov 2025 01:31:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762853510; cv=none;
        d=google.com; s=arc-20240605;
        b=hi9P2aKw9wsEvpeavrlV1maDUcQQOUTIZvxgANyyE/S8DfLAkcylLSVmuP93WlGfDJ
         gM+bS90/J6u14SfwZKc6Mf10SCs6REbs5pnFZ6fBNaxrooOL5VFjZcSN9jCJFTx05l/F
         BhCFI3dcKR2lFrUQXwc1nYlOlLTSMlqbbNkzSV0ZTgrOHV5pRSZN8R2fZYFNR96bR/Bt
         zcwOANc8mIIsRIO9jnmH3nH4crcYHzq5KGoTFXhqrIn+Ud/A2gS8A7QpXK+erhuoVgJi
         Jo7wP2NVvsElDDLKd2MJmYaT8928t+9irzdqrVlcaEEe0fwvMX0S60S+G++VzlKQcyGB
         trVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mcuXePJv9UMRmDbNyzI2WPi4AQ0WM2JROyTQZuxeHnI=;
        fh=GSVOJtyWBHE29ru9QdeKQj3+sOeZIh7w89N2uRelOOQ=;
        b=aYpqQgG75oikwl1nhdM1hwi2aIKDCHdX+eLhJa2aSVsm6JqMsb7YXJYK5THqxhFIvm
         3+Ipuy9qICCtCgD5T+OeHPhBD77mlsbZdapKzV3SrPASKPPX8zKAqA2x3+w3jJ1+Ouzw
         L0/9f6/S6M+jHgjOr/BtySBqn/vsj1CttXwDDQLWOLEmzH9/C4mZa6MYm2uymJOIVznU
         H9jRf5hAkKAXUMPmu96jGhgZ2jPqEpvzOVY87BjfOWBUzeU8uzc3C7a8jsy6nOSmhBuY
         xtFINqdZ4fR3q2x4LYx9wPvdkLIZFY2+NswFwqyC324wOxLenXSje/VRZASAMY2/fmwU
         pa9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KGpwW8Oa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2965096e394si3096725ad.2.2025.11.11.01.31.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:31:50 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-4ed9c19248bso32560311cf.1
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:31:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUcc+Iqe6xyvrCiuNuhypKgOMwePiVsl2qRq7NQnL9g7GU6yH2f9V5npNOdwU6oe0mTK98ors3ZMWE=@googlegroups.com
X-Gm-Gg: ASbGncs4EzlIwLyHDtvN9PS9XAhTFzZKWHU1f4VdNTB7oQVutDKuKL7yYJwHN8Ynrxq
	UrSDwHbftjdDdvCN/+NM27zD1K3o/820LlWIU1JuNyGLIie2exYBmpmTd3D8nbJ8Y4L+NTW596M
	SVn3Gn7jWWJXev/Ph8viJ5hoH0xkpN8sD3tNF0Rc9teP5POk6Zsuu+1teGvdA1h+zgxpZ8yebDQ
	T+Idszl94LhkIKchyB1QfBniei2qpnFY9urOg/6txHws+COsQnYDXGS7k/H4Ti/U3rLhKaAc8GO
	yYWNalLb+tvbUnfMc5U+WuMotLh+iVxvzEbF
X-Received: by 2002:a05:622a:2c1:b0:4ed:6d2c:dbf2 with SMTP id
 d75a77b69052e-4eda4edae35mr142374501cf.32.1762853509963; Tue, 11 Nov 2025
 01:31:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <5be986faa12ed1176889c3ba25852c42674305f4.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <5be986faa12ed1176889c3ba25852c42674305f4.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:31:13 +0100
X-Gm-Features: AWmQ_bnBejbyt9xhMGcc96j04H3RtNf27KB78uQcmIocgSxJqcCqkGPoQwhXWUQ
Message-ID: <CAG_fn=XFXFAvKS2+bc66FR+gw7rfSybETAOBUR_vneaVdF5F9A@mail.gmail.com>
Subject: Re: [PATCH v6 06/18] x86/kasan: Add arch specific kasan functions
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
 header.i=@google.com header.s=20230601 header.b=KGpwW8Oa;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as
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

> +#ifdef CONFIG_64BIT
> +static inline void *__tag_set(const void *__addr, u8 tag)
> +{
> +       u64 addr = (u64)__addr;
> +
> +       addr &= ~__tag_shifted(KASAN_TAG_MASK);

KASAN_TAG_MASK is only defined in Patch 07, does this patch compile?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXFXFAvKS2%2Bbc66FR%2Bgw7rfSybETAOBUR_vneaVdF5F9A%40mail.gmail.com.
