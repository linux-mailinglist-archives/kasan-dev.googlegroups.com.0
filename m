Return-Path: <kasan-dev+bncBCCMH5WKTMGRBS4KZTEAMGQEFLMVWVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id DE899C4CBC8
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:43:41 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2958a134514sf45847005ad.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:43:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762854220; cv=pass;
        d=google.com; s=arc-20240605;
        b=DNUkNLsOJTuLRF4aE+p0oxhC7NZzFYUFxgDoqB2ZjrTL9IzzZQvbhYbBKYWgS3OLC0
         H8OELBzgZSd4ZlJ1X/zNBlsvEnPhgiC4fSaykPQopdr1HtShnMZ5tzlXfephIPCYocIP
         kNy/xWU8B17Z/gNbUlBmRdVVbdu+df5ECo5HM0JPYXKlSp1NfrP+UsNYfIk6Wi3VL6R3
         N7TIwwwT7hZSro+J9lig2heETwxMW1LhUmGhMkoBs+wULNhJXpoj9c4KCbRg3aBoHaus
         sz+DuJ+j51kA+Vj+duQVOxfqn0s2Qri2HX8xiCJ9JeeuWiOOOvkbEYRqN/hwCQbtQOe+
         o2pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f/KncFBJO0hsSi7HZehhxMjkyQDpSyFoGV2YSghcxV8=;
        fh=pZcqDGMank9+h5y6idx/MyiI/bKq63CaJZLKxj5waQk=;
        b=l0+LynimGnC9HXbsNCTnMb35fT68Hdo0RZ/QFZASXz8Ljnt12RF3+53AasQzk09bpa
         kapyxGwASXHIyIHqYs/PdLXHILcH7Nh7CsgQrhSOms8UzvDXElHBAbIjrnctjVMNXGDH
         8vywrpuxewAxWDjxFL4EByzTEuNvvi8oxWvwxTWxI338uWXw8omlkxR+DOtboCBWGSQ+
         LHrvKb5UZVzYQ5L3XN1hLUkiP7jcZwZHXx88njxK4S2kCk9+OKKUSkHrCCgrn/wZsm8M
         U7ZP/bQQKZ4gAVShrv6SoyZzvb8o+OGkUFtxb5meFhj6Y3+EzupTGCAkn9bVRWmfPh9U
         PjWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VkKy7Lpx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762854220; x=1763459020; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f/KncFBJO0hsSi7HZehhxMjkyQDpSyFoGV2YSghcxV8=;
        b=KqYokCGLo4q+JL/OHgqOgcCKz1eoNa7Pgh8Ksc7qluFml+ypoR3v8Rbg4Wcq0f1rIN
         /OzDIoFau8biAROHudUrbnCrQnvy/e0j+VTP4lAeFuxuuL9JIoBPz75E+xlem0PhnMyv
         XWWZhGSEAYkVkYw9HeGpD8LO1ecB+uyD3VTjC+XCwfP0xnb7g4OP/rje2zFgFCO3Noea
         ZkKRnRw8W86TUs5+pFhi673ecGvMT7dm52XPfcbrmpNljBjzKk4iOhobbr1AGvJHd0x1
         d8i6DEuZZoSQRB4cDkLjSapxMCxf2Ry/ijkVgD2d1MELw0l+aU0eA9NUA8mFgDVtIGU8
         oilw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762854220; x=1763459020;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=f/KncFBJO0hsSi7HZehhxMjkyQDpSyFoGV2YSghcxV8=;
        b=LEhYVBNUYouULw6DhQPWQ+XnomDozjmLHErk6NhvbLdUIRNocU8U28WdtLNhvkBF1h
         Egk/ZL/66Ct3ARcsVQLOH7wbE+sDS7VzZQKS2LKHyd2Az0Nztuc8G5bfXF5KAgaWj2+3
         KT74W7pXzJcznoaTpmRU8qMkE+EvZ0R/8+RbhCMF5AtDjxW9lnG3YhVTNhvrWisFj44N
         ZLlIGA1Y7nW7vopRqunVEYXvaiJ+/BIvqwqNKNDmjH1ACU55JfZfpGwxcD9f88/rNkHI
         GaAl1/mEqUfr9qBEF5g2K+rCNp2U/gWMGKz4/OlMmsW8JXDxklFikCO+x7u3fO4IbPvU
         5FRA==
X-Forwarded-Encrypted: i=2; AJvYcCUfmPvqD7ZGY1UhfYup+FC0Ao31UGJ4yP2okv1QiWhks+xeBSCkNxIQcS4KsR0EyocsScQxoA==@lfdr.de
X-Gm-Message-State: AOJu0YzLLhq0YW2uQTP0H8o9mjp5IgNL3yuUGl34gOfuqjb1JZJZGiSS
	Bl2inUYDLs5htX43a/OWOUGfwx5xAt42s9jkaK9kzMXnJUOZt5iqtKL5
X-Google-Smtp-Source: AGHT+IE3HLEhEYpEBVvB+ZmGJP1kgPo3kuGMOWk+AepPDUcR5PbZ9L5hfq3PyUcC+2CkJnxG+9Z73w==
X-Received: by 2002:a17:903:1a2e:b0:295:9c48:96c0 with SMTP id d9443c01a7336-297e53f905bmr146901775ad.5.1762854220225;
        Tue, 11 Nov 2025 01:43:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z9oxqq1A7gpUmbaZhMLMhtMlRtVnlLFHXnwXVvOs64yA=="
Received: by 2002:a17:902:694b:b0:295:3ebe:5b4b with SMTP id
 d9443c01a7336-2965243bab5ls25177565ad.2.-pod-prod-09-us; Tue, 11 Nov 2025
 01:43:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0rgKTcMsRgap+3omK2dpislJwN3bYUewgAmxgvEwg1jzwvTwKIqKw2MHIDYOw6DkIfeP+8/HE68M=@googlegroups.com
X-Received: by 2002:a17:902:f688:b0:297:f088:56e6 with SMTP id d9443c01a7336-297f0885746mr123352295ad.25.1762854218852;
        Tue, 11 Nov 2025 01:43:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762854218; cv=none;
        d=google.com; s=arc-20240605;
        b=XPxVzzApEcELf0yx3llo94ZDTs3KnTYLVYxraFGQMnZtfELQrXeJC9X80jJv4pN++k
         Azkotj1MT71AS2tdwLWFL6vpRPeTK+LUN68COMsoKhHuCtISwT1m8rtAKVkjjtx758CB
         Ocx2iANhcjAtG4koio/Q/WAiPCvtyLQMO0BHpeabGq1iZvt3SUf5mWcvWBJkW5u5DS15
         GbWqOp5nlcHrEj9wYMDMwE4UReEuF7aJlAd3rbI85+dav4opKTA1lUW6vKJUvXBmWvZK
         r/Kq/Vp/VcEwCDC7WbV3IzEZ2B42yV4cLbUCbmm4dm3PQGIqLHkBHbg5uLTiuHtAqVjH
         9quA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pIXt5RY2avngREVQV/WVzy+4eYrZh/+QLtTn4Iny2dI=;
        fh=kWkZ4ACIvkjtJr1LUYzo6fF4Z94ER+YeB+MCYbBW5sc=;
        b=JOh8nIJ7iarF+bAvmtHUjtUXOI4VUxsTwdcGDolwLuwTQMpPfP5lWdZ2MgU+TL5quM
         zCG+1mtkRps+e/1bD5yBG4nJ+x3pEXAI6j140EYo/PePuIwrEYCkZFRrE0hr0HIvgQc/
         HqMZkCOEzwHS+JcYF6HOWAUp6+xmihlgFWcUjMeiOZAy0TbpgXhir4NZhCYO8mRKAxRN
         JSQnUoQdtR8IHbOTO9We24kmg0lox5gHmLJLJoqTqxQYTryy8RoeDf+IKrCUk3Ke+WiT
         8Yrf9XnsbjiXpC0zye1+OUnFd0J976CjmnsH3CDUJlXe5XMbmg1o8oGBU3IAUqeSnT6b
         gBAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VkKy7Lpx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29808a68834si6201345ad.0.2025.11.11.01.43.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:43:38 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-3436cbb723fso2505102a91.2
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:43:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVguQOPIXtWbxE3+5iePg5cPiwUmsC4Z8/+lrEmQMkPk5cxur+RkgoFh75x2U/95RXtLCBqHmssqHc=@googlegroups.com
X-Gm-Gg: ASbGncsdlZxSAN0tj6VZgbudke0LvqkRfNaWRg34Olyu0z2khJ2uh/ycQD5E3R26MFQ
	2/Y93SffjKsmf4Sm/OttQfH8yM34EuTbPk9TUuY9A5WOVTR+lW0VuL+HuSnz7YHfV18QegShaZk
	ifaaLuIf6UA60CrY3cePNP3r+7/d66dLDTCm+zLshLayqv6QuBwVrZr0QPDmLvsmTVyB4jahXOu
	Q0lkX/xC55Cf9JVuuF0mI4UfML67IOZH6dgOE2j/Mbcqd1Oz0UyXS7pdV6uU5mAqpnmH6w5bwPw
	/LnqrAwYC6VIR6t/Rx2U5v1BeAv94wD95nHu
X-Received: by 2002:a17:90b:6c3:b0:340:5b6a:5bb0 with SMTP id
 98e67ed59e1d1-3436ccfd8dfmr13988152a91.26.1762854218118; Tue, 11 Nov 2025
 01:43:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <d030a07c956c1e7cbf8cd44d6b42120baaa41723.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <d030a07c956c1e7cbf8cd44d6b42120baaa41723.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:42:59 +0100
X-Gm-Features: AWmQ_bkUJ_QlWZiGCG2FxZvthHc4c4y_090hZyMeaaw5jt0Qf6xk9VB1Qerb_Pc
Message-ID: <CAG_fn=VUzLi1C9jss1eHV=pPh4QFmWk-fQUbhNwrGNSUk-yKaw@mail.gmail.com>
Subject: Re: [PATCH v6 08/18] x86/mm: Reset tag for virtual to physical
 address conversions
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VkKy7Lpx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 29, 2025 at 8:07=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> Any place where pointer arithmetic is used to convert a virtual address
> into a physical one can raise errors if the virtual address is tagged.
>
> Reset the pointer's tag by sign extending the tag bits in macros that do
> pointer arithmetic in address conversions. There will be no change in
> compiled code with KASAN disabled since the compiler will optimize the
> __tag_reset() out.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVUzLi1C9jss1eHV%3DpPh4QFmWk-fQUbhNwrGNSUk-yKaw%40mail.gmail.com.
