Return-Path: <kasan-dev+bncBDW2JDUY5AORBHFS3W6QMGQEKGJNBBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C485CA3E0CF
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 17:32:30 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-38f62a0ec3fsf758113f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 08:32:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740069149; cv=pass;
        d=google.com; s=arc-20240605;
        b=j/2DJzsbyesRnN0V5CCw905EVtjE75IC4zXQPY6NcX8sEKQD5/SegzIUTayf78787z
         0AnJNZcFyqaV9lSlxsB8QL4aFYmLfd31pakbTHfpv8NW8qJafUVcAD86tER1DfpWutYc
         RundXZ58NZAvb9VUKerJRDvtyhtVm9jKnfoIRA7uDKKxLaujbXUW3NJlOKqpi4ABqg7R
         7U7X/Z6vSNOBisRc7a/GV6Tp/T31gIIeyMz7ifQXVWxOOFEyYKBmsZ2rNgosuL4bnsSo
         kEQMUvhIqxHW6R06obqzy3xyGJsz+87uF0hly1tMjBF+9qklQmqqW0eRpRUUiops5NYL
         IpFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=G6se5EvcVZaqchybVPn+1WqmBxh5pbd+ob0LaNw/oF8=;
        fh=XfQczz4GEW2y2/whx+LJXJbg/BmPbLJFG3PmnD9zPvo=;
        b=gfEuk3e8YkkvQdl6WeJGyPj/ZYSnOABh4So/cS7AeGelBwgvktMgODGBvMRSGw4+eZ
         m6c+7yUW0dnSiMC0y7sN1INhrnMVfxo8xqJLnJFQLrp76hUVpSPdtialqeJUDpgxdN/u
         BX/ostkaMssa016hyOjXHhB2C3L/XxPmaeQexwyUMki72jstA9onpcOvOSIs/wn+5Z31
         PAX8lxJ4VXfCIcwbgg0gL0k+xJmCSEfx5oYp4c5kdgXJZnzxXRR8yHJvVf8qAsDi4QuY
         58snq2BSSH6THoycfGrvui0wMcFCRRYxm6ZZHKLI9eixQ1/XA86VfTCDfjxy7aSJSenZ
         6I4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kzlJlQhT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740069149; x=1740673949; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G6se5EvcVZaqchybVPn+1WqmBxh5pbd+ob0LaNw/oF8=;
        b=bRZ796vbIk2Km1n6FjEL6/ZxrRuLW8JC2zXZQHkIuaXdWwXtH25K+1oboLD7xb0Mek
         7XVOkWRClWwhr9S/Zz35ghNmkDs9tdpgCbw2o8IaoKKDTGCplCaFvjmgZQ4f627Lmitu
         IFc9DDn3gje8gTuRDdfSehn81lnGjLFdNQFBO1wIQdFF8H0Ukzz0BgQ+j+NIEYlL12ac
         54llagcD1MjhQW/+x5Uxp67yN/9fwL4d3zB9MB73WmplBQB/GO/RIY7QueLZ8iR0kzL2
         vIyARYp0j1Gv8/JL/5yYWZBLRxh10KOxd5Rxo9GfSghkIBhbvpz9B6x0mb20S8mtBd8K
         MsuQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740069149; x=1740673949; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G6se5EvcVZaqchybVPn+1WqmBxh5pbd+ob0LaNw/oF8=;
        b=B5COR3fjp/9HySOfMmjjSByGzINdLbCecwRjaAd49kQ21HGNy8QIbKU7SJwuuH8g75
         TrRtgZLneGf9YEEWIhCzHh0LoRbRZcFuMer1dUlOR4LXsHN+N/z/FpBgSLKMarGY7N8m
         sXOloo2gSac7fApEY5ntVAWlwGqMHR5LsxU7DCC8dg4ltmORWyxhWZn9qH/OEP5x93sF
         aq9QJT9IwYmknanQG6fzqubaiUs3WEi+HGfOQCCT0uGf2qnP1JpEciqGAblsuRmcfDBk
         5IQ1orw8vB9EiVSBHMVsjQVzM4016i7Qu+aGdqyXPR49+XJLiyys0egZvWwKMfI5Bn//
         heBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740069149; x=1740673949;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=G6se5EvcVZaqchybVPn+1WqmBxh5pbd+ob0LaNw/oF8=;
        b=jdHppyUNJEzjUoIqZg5A49U9KUMl1oDZrUBYLBLQx7uyvY8ffL3m719RhcCEsmhhZQ
         FblFG9eb2unnGCZnU+E+wwupGZ5RQniU5p4nRLJXkeePc0AnNzcI/JjndpsapgeRuVPG
         FAZ4pka/3q4A4LMdtmCKNS2OJuYHvNKd7sHcG52SzYKklFLh1rRw2fSVdo0kjNOCxCGF
         igSBUrrlQFl4Be/emsGvq+BL6rDw2GlFfRAq90JvuE9pJAoYWuYn7Pv6qoxUrAEZ/+ad
         m3h/llbnBvLdYaJ52LlaOi5nb4U9+EOEC8pjp7NFMp09IcHSJyXk9+URcutnxTKtjmab
         7OJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWW5NnN9we/LrWZa3RY+YsM2KajHv0wLAhSrVnvgPhDFnNcvivmpXddx0pUdcbvwILqSkbK+A==@lfdr.de
X-Gm-Message-State: AOJu0YwVxCIk/BOACfFbXmK0mByVimgyhD3riqWUiVi9XN5lhaRt7EWA
	aQvxzuHa6Lz8x0vLTE6Wm3cS56Jss6eQXA2V5w3edgdlYWfIhzAD
X-Google-Smtp-Source: AGHT+IGGSJIy4hxA2ISMk9nIMu5aTf5GF54sMzESnMtrKRn5mMey31gXqSWtb7PtYqaUdIZg88H8sA==
X-Received: by 2002:a05:6000:1845:b0:385:fd07:8616 with SMTP id ffacd0b85a97d-38f33e80e93mr22665681f8f.0.1740069148591;
        Thu, 20 Feb 2025 08:32:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEAlCsBrU7wsjRSut0qRF5ZFRy7BD+yNcVv8xpR6sPQiw==
Received: by 2002:a5d:648c:0:b0:38f:2065:b9a8 with SMTP id ffacd0b85a97d-38f614739a0ls825706f8f.1.-pod-prod-02-eu;
 Thu, 20 Feb 2025 08:32:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU1K/U9o2aTa+4ohUAo1XBbWBGn0fC1LIt+NtiR1Mw7v7x5xWS2ehy9JjIFfkvS1aFtdyjGz1ohlXs=@googlegroups.com
X-Received: by 2002:a5d:6c66:0:b0:388:c61d:43e0 with SMTP id ffacd0b85a97d-38f34167d68mr25611039f8f.48.1740069145564;
        Thu, 20 Feb 2025 08:32:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740069145; cv=none;
        d=google.com; s=arc-20240605;
        b=Faf6hKHZgENyMCeTa+JTQsIRjZUi7Emj7OroD9dHzr+WH00xOkIwgN6XFmcnqyA53O
         nlrq5oeUQOA8QkJlBYtx/iquKKm/qXqx7y57tu28BkL/Xxec3BTDhNGOi5EmJMHxfmti
         B65ZS/A4nkhhVkOhmvHQscbBpjn57kKtQK/eB6dnOlA344IaaqLi6DKfjb8Iasqpj2Qa
         o9F919PnNw7QgRoowDwNeodJy51mkGk62xBzSYUXjkvbIrT8LYTr7aDYjqErIidiTqD8
         hXitpUbHlHwWlWUuJdmlqMMtYGixeApswzxvmK4u7kiZUuOuloTNiihYR36PQfo+kUb+
         x5OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=djJ6cJLCBX31nVMQXMRyTslZq1heGpJZhHxgGn2SThg=;
        fh=no1yFO6ULpShCPoKRLq/Fy6l73d8PufReXpr0R0+S7o=;
        b=JPyp547Y0ALiFuanOZ09beNBWJRoHPHgIExssRTusD7ueKCeXJqLOtmTshCvJDUOu4
         960uc4zkwtQSOw9FG8qG6uWTN/rrGNuba1c2QIJG8jAUReBxZXs+fyPuxqPNcWbFZ6U6
         iQkSkwTV1FC6ZglHZCY+9XxxHwHdsHE70TsStfl1Uf7YKmOYUYDPr1rQN+WPCh3HaruA
         TO6ELK9FIDMemyhRD3jgrNur/bUPVtV3w79W6cN2dSxfMVPYDbtLVsX7tWcDpfgkgzZ5
         APKVwuQu09LjmXwf5IZ/lw2XEKuvoCucir5C+IJETZM0B8dmgO80a4qZs/K/SMOeEs7v
         Oqqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kzlJlQhT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f25921c98si200043f8f.5.2025.02.20.08.32.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2025 08:32:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-38f325ddbc2so828900f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2025 08:32:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVB8VjLvp0Zn5Jr9Z/oNEahWKtSkQGLFOsOswCB2WB6cYJmovDi2Egtuv5zHBuKV25ZIAkcmZ4PiGI=@googlegroups.com
X-Gm-Gg: ASbGncsmyapck4CX7+onaZvK72TPvJ+Bo5cXzatk3g7gkNxManSzsJOS+3j8e/yD4c1
	zwyfPIoumAzjxF7vtJs4EkzTJa0MzxDc6oHDm5HANp/Jrbr9+5gWyINReBDmv4mFsVsmPnWw+fa
	0=
X-Received: by 2002:a05:6000:10c:b0:38f:2111:f5ac with SMTP id
 ffacd0b85a97d-38f33f51088mr18279347f8f.31.1740069144731; Thu, 20 Feb 2025
 08:32:24 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <d266338a0eae1f673802e41d7230c4c92c3532b3.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZezPtE+xaZpsf3B5MwhpfdQV+5b4EgAa9PX0FR1+iawfA@mail.gmail.com>
In-Reply-To: <CA+fCnZezPtE+xaZpsf3B5MwhpfdQV+5b4EgAa9PX0FR1+iawfA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 17:32:12 +0100
X-Gm-Features: AWEUYZlJk8i1PGeryrJoWL6O3cLwlGsfEZG1iYKTI3r7jC586Nd1JaZw47VvF2U
Message-ID: <CA+fCnZfHAEP08xwUM5TXAihtFzrVG_kJMVXBD1U2Z1BoqkM1gA@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=kzlJlQhT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
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

On Thu, Feb 20, 2025 at 12:31=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
>
> On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
> <maciej.wieczor-retman@intel.com> wrote:
> >
> > Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
> > ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignor=
e
> > (TBI) that allows the software tag-based mode on arm64 platform.
> >
> > Set scale macro based on KASAN mode: in software tag-based mode 32 byte=
s
> > of memory map to one shadow byte and 16 in generic mode.
>
> These should be 16 and 8.
>
> >
> > Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> > ---
> > Changelog v2:
> > - Remove KASAN dense code.
> >
> >  arch/x86/Kconfig                | 6 ++++++
> >  arch/x86/boot/compressed/misc.h | 1 +
> >  arch/x86/include/asm/kasan.h    | 2 +-
> >  arch/x86/kernel/setup.c         | 2 ++
> >  4 files changed, 10 insertions(+), 1 deletion(-)
> >
> > diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> > index f4ef64bf824a..dc48eb5b664f 100644
> > --- a/arch/x86/Kconfig
> > +++ b/arch/x86/Kconfig
> > @@ -195,6 +195,7 @@ config X86
> >         select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >         select HAVE_ARCH_KASAN                  if X86_64
> >         select HAVE_ARCH_KASAN_VMALLOC          if X86_64
> > +       select HAVE_ARCH_KASAN_SW_TAGS          if ADDRESS_MASKING
> >         select HAVE_ARCH_KFENCE
> >         select HAVE_ARCH_KMSAN                  if X86_64
> >         select HAVE_ARCH_KGDB
> > @@ -402,6 +403,11 @@ config KASAN_SHADOW_OFFSET
> >         hex
> >         default 0xdffffc0000000000 if KASAN_GENERIC
> >
> > +config KASAN_SHADOW_SCALE_SHIFT
> > +       int
> > +       default 4 if KASAN_SW_TAGS
> > +       default 3
>
> What's the purpose of this config option? I think we can just change
> the value of the KASAN_SHADOW_SCALE_SHIFT define when KASAN_SW_TAGS is
> enabled.
>
>
> > +
> >  config HAVE_INTEL_TXT
> >         def_bool y
> >         depends on INTEL_IOMMU && ACPI
> > diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed=
/misc.h
> > index dd8d1a85f671..f6a87e9ad200 100644
> > --- a/arch/x86/boot/compressed/misc.h
> > +++ b/arch/x86/boot/compressed/misc.h
> > @@ -13,6 +13,7 @@
> >  #undef CONFIG_PARAVIRT_SPINLOCKS
> >  #undef CONFIG_KASAN
> >  #undef CONFIG_KASAN_GENERIC
> > +#undef CONFIG_KASAN_SW_TAGS
> >
> >  #define __NO_FORTIFY
> >
> > diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.=
h
> > index 4bfd3641af84..cfc31e4a2f70 100644
> > --- a/arch/x86/include/asm/kasan.h
> > +++ b/arch/x86/include/asm/kasan.h
> > @@ -6,7 +6,7 @@
> >  #include <linux/kasan-tags.h>
> >  #include <linux/types.h>
> >
> > -#define KASAN_SHADOW_SCALE_SHIFT 3
> > +#define KASAN_SHADOW_SCALE_SHIFT CONFIG_KASAN_SHADOW_SCALE_SHIFT
> >
> >  /*
> >   * Compiler uses shadow offset assuming that addresses start
> > diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> > index cebee310e200..768990c573ea 100644
> > --- a/arch/x86/kernel/setup.c
> > +++ b/arch/x86/kernel/setup.c
> > @@ -1124,6 +1124,8 @@ void __init setup_arch(char **cmdline_p)
> >
> >         kasan_init();
> >
> > +       kasan_init_sw_tags();
> > +
> >         /*
> >          * Sync back kernel address range.
> >          *
> > --
> > 2.47.1
> >

Also please update the descriptions of all related options in lib/Kconfig.k=
asan.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfHAEP08xwUM5TXAihtFzrVG_kJMVXBD1U2Z1BoqkM1gA%40mail.gmail.com.
