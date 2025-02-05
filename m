Return-Path: <kasan-dev+bncBAABBCXSR26QMGQEIZYMV2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id EDDDDA299F1
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2025 20:16:27 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6dfa69e6983sf2152646d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 11:16:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738782986; cv=pass;
        d=google.com; s=arc-20240605;
        b=jjA9O9Ajeo4w5FmZo5/RTNpTfiIZhr+nnbOKO/j9vC5ZUP3jTQzB0+wANoJZBiqBbT
         ngOlsa+Q/ZjNMTrnolFl9LgQbnnEg+aRL+VWRgFj9pKLa2iHYqnVGRxyAXyAIaAykEr5
         Rg2v+Zp0SgpgF8SozcO+d8w7VXxEeqsWvtDQSoMn992tuujnWI7zaui4qDgt8//y0FDg
         QFdp+LkyAErCMgiQN+FA5ozqzAtFebFa2OKIojW75xwKJiwAY+WBWwVB6lwzqkc9N6Yx
         9p0RGWtOTRB5VSoYGy7RpHRM1HYsX1wawUPS6Xr+JmEo79A2ii8v4fepUNwhlIgn2ezf
         q+Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=HGK/YutSeQ9wQNQMY2cRnjPDWG0oNvrK9Xgd+UYevN4=;
        fh=ApY+KHqkBVX+8mc9EoCuynhHN8Y2Nfk0hvLo1jaJzm4=;
        b=GDgANs2e2SGz/E6gbf/5nU3btUH0ba70VSa8vJhbCBacyxNPcKvYZImvyfCNCXEeBp
         WaWf45xQUeS5WzQgkmEtBkBpPHmmDZuebRUSQgjUGdgTcQSvvU3wEQQjo4nKPC7bnjSX
         E0+PbqydX+7L5oDHyg6ejq48dlNGLzG27AZSYd5L8o+UiB39Xxc2FWvKlFvDJGjOW/xh
         MeDMC7zshESvyd9/I58AuBrujNLq53HyWgnnbnDM21XgAUBAE3HYNEzZtMGYhw1tW6oi
         GsA/jsfzEEusZWTTz7laj+Uyw6kCIk/cK/D1Cb/VZcc1siDUW0Moa5THc5375mIO2Lyj
         Tfgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b="hAl/xLVS";
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738782986; x=1739387786; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HGK/YutSeQ9wQNQMY2cRnjPDWG0oNvrK9Xgd+UYevN4=;
        b=I/gvRxGY52LQLygSSt6EL1kZ5v1KlmkhVy+q/9nzBs4gC2W1eAMzi/XR6LUyPP3uOt
         EnhdTL1Dx8tjI/4Ibm+fm+1O+eZqjBPzwkE3wg2wtsdv6eRbq6Zs33nJhbHDVbL3bOtD
         C2atjko/Z70FwErCdRFN9CW9fufUpDfBD8J5qSDJjmOxdiqfbNaZpzUuOGg7l2PFBVUO
         MOzYBO1mOk3FMFaDKMHPeF87+5Km+Od56j0nv59ji6ZaXFlO8BS26kIShD4iPL//OzXh
         PC4HKuX5gvdCQN8xLg8Ox8/MV9mNAikmw5PH/uUflLg6ecMV3Mx0cl0Tx+QIKvgq+uMx
         K96A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738782986; x=1739387786;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HGK/YutSeQ9wQNQMY2cRnjPDWG0oNvrK9Xgd+UYevN4=;
        b=sy8Jmy+hib5Gl8Gd0blsyAkAG/Bu6QfGBNYJUEVBwC8uwpsTAIL9rCBv4au4AvRo/B
         G6AfTSqL23txhINrP1tBUrL/RzX4pdRmyM4Prkx2kGTIKuKlmswepgHQNGZiINkKzr3B
         8luSvUevb03dFJicW356AcT7TlyxKQ4ppTpsb0P6RhsSUSQy9cHL3u6R/fTubU+RR8Jo
         T2ig3ePyfItjYkpNmeM1RoDeqXYQiGjzkI9bbECAh6KZqyJ/BBE2SUuckPbd5Sr0uJKI
         xJfSkvnb79rOPkhF+7vGGSmTkujZ37pOkWC+t12a21Kjl1m0PAI65B0xYy6t1duQLAkQ
         Tn/Q==
X-Forwarded-Encrypted: i=2; AJvYcCU94xD5ZPeVdJ0oZjVnrH9ZWWkJ9Za98xVyMRwwcXerl9p+zLV6Kg+faVD4YEjL2ogHUEDEuQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz+IfIGet8vlACvd6luQc1ingG4hWP9S+w+LJNuHB6NCh/Nxtkx
	tnMYzUzxfvusJHW6jzoG3wcWPd47d5l/Z1hz1aaWuXMzlT2I09C6
X-Google-Smtp-Source: AGHT+IGYWMpIEFy9HixCeWcTTipZyCMSB9+HgT7eYu4TnLejyJV/YxmmZgRHclMPmAwIWvIzxIaKIA==
X-Received: by 2002:ad4:5aea:0:b0:6e2:3721:f2c6 with SMTP id 6a1803df08f44-6e42fc1c548mr66176996d6.33.1738782986557;
        Wed, 05 Feb 2025 11:16:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aa52:0:b0:6d8:b1cf:a07d with SMTP id 6a1803df08f44-6e43944d419ls2310006d6.2.-pod-prod-02-us;
 Wed, 05 Feb 2025 11:16:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXXh2XFo6MS9b57Msa9ypLtrIn48ayeRiT5FC6h5TtmnbrX9Wz85x1RENXXw0ULsh6YGQXG0Vq07RY=@googlegroups.com
X-Received: by 2002:ad4:5c87:0:b0:6d8:8a8f:75b0 with SMTP id 6a1803df08f44-6e42fb7d377mr66485906d6.14.1738782985889;
        Wed, 05 Feb 2025 11:16:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738782985; cv=none;
        d=google.com; s=arc-20240605;
        b=T/T2RsIaNRKAPIeo9MpZIftTXG+O7huI1E7gSy3/NWCWyKqdYqSAJiZ0kNaUu7+pww
         9FqVKIyNpVWAwDvk498nRqTjvk5HB0QoAVYKXU90D+V2TEQrE0R51e3ttPT0gdMMLh84
         FA9Ibt1AgC1MGhpdAuwh0EhECKjwCSAmH/fsSwtfs7pGlvpRnekGeDEk9cY2XmkWkSFK
         T0w9513eZOUmE360k7DDc8UrVWrzr0gRbyt/qMx8QDsMOFOnx0nP5gX+nnd/Q20jIYMF
         CXuRY4VjPANPDrie7mQnp135g2AuvBqnOrZkIIzw3ROPamD+t8xZYyPAZQXZnwindSMw
         wG6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=GWuVhWwk1JtiZgefarbYor8+WHPmqHpAXH1e9T4Rkh0=;
        fh=BlQfB3bR9jS2LVVifI+ZlK3II9S7glWXqwp06dz2WNM=;
        b=Og82yZTHpS6cEQnBDQeuzi5G/OyMcdLd51KONoqetOpn3ibZO/sN0aSXhIdUTseOFH
         LhatdwwUdUcgEX+QmUVsRrqEQKJle0ULvJ+q10/Psz7Z/0XDK0svJc6ympqKyOOzAdCc
         Sw24l47Lp2t8AOEt8ANI2TPDIjwQzrwhmGj/bT8yn6sBq1v8ihCRp6WQMuhnPegmHYiV
         wuvjn+6s8Viek60uxZH1WPDs1l6VOs02ejFfaPPzitsXB3ProReMq9Vg/W7J6XpeE9kx
         2wmPHnCxBUiPqunhlUNuHvbYlOOaddwQACoZ8AZd8tK0xPgfbzgqf13gGp/fKS6baorx
         YKVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b="hAl/xLVS";
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
Received: from gentwo.org (gentwo.org. [62.72.0.81])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e2548cf035si6054976d6.5.2025.02.05.11.16.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Feb 2025 11:16:25 -0800 (PST)
Received-SPF: pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) client-ip=62.72.0.81;
Received: by gentwo.org (Postfix, from userid 1003)
	id 6887F401F1; Wed,  5 Feb 2025 10:51:47 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id 6476D401E1;
	Wed,  5 Feb 2025 10:51:47 -0800 (PST)
Date: Wed, 5 Feb 2025 10:51:47 -0800 (PST)
From: "'Christoph Lameter (Ampere)' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jessica Clarke <jrtc27@jrtc27.com>
cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, luto@kernel.org, 
    xin@zytor.com, kirill.shutemov@linux.intel.com, palmer@dabbelt.com, 
    tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com, ardb@kernel.org, 
    dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
    akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, 
    dvyukov@google.com, richard.weiyang@gmail.com, ytcoode@gmail.com, 
    tglx@linutronix.de, hpa@zytor.com, seanjc@google.com, 
    paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com, 
    jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com, 
    jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com, 
    rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com, 
    catalin.marinas@arm.com, junichi.nomura@nec.com, nathan@kernel.org, 
    ryabinin.a.a@gmail.com, dennis@kernel.org, bp@alien8.de, 
    kevinloughlin@google.com, morbo@google.com, dan.j.williams@intel.com, 
    julian.stecklina@cyberus-technology.de, peterz@infradead.org, 
    kees@kernel.org, kasan-dev@googlegroups.com, x86@kernel.org, 
    linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
    linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
    linux-doc@vger.kernel.org
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode
 for x86
In-Reply-To: <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com>
Message-ID: <72837fcd-97a8-c213-0098-c8f308c3415d@gentwo.org>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com> <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org> <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="8323329-1508829946-1738781507=:2407083"
X-Original-Sender: cl@gentwo.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gentwo.org header.s=default header.b="hAl/xLVS";       spf=pass
 (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted
 sender) smtp.mailfrom=cl@gentwo.org;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=gentwo.org
X-Original-From: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Reply-To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
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

  This message is in MIME format.  The first part should be readable text,
  while the remaining parts are likely unreadable without MIME-aware tools.

--8323329-1508829946-1738781507=:2407083
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Tue, 4 Feb 2025, Jessica Clarke wrote:

> It=E2=80=99s not =E2=80=9Cno performance penalty=E2=80=9D, there is a cos=
t to tracking the MTE
> tags for checking. In asynchronous (or asymmetric) mode that=E2=80=99s no=
t too


On Ampere Processor hardware there is no penalty since the logic is build
into the usual read/write paths. This is by design. There may be on other
platforms that cannot do this.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
2837fcd-97a8-c213-0098-c8f308c3415d%40gentwo.org.

--8323329-1508829946-1738781507=:2407083--
