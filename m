Return-Path: <kasan-dev+bncBDW2JDUY5AORBL7Q7C6QMGQEPBST4MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id AB1BCA44F00
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 22:37:53 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5e082a05744sf6122471a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 13:37:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740519473; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y8uCk9nQcw27ZJvx0xtgN/4Vu8zqNlZKZiseIET4uQqdd+DWcw7Rlw7kayJmm3YCDb
         QA6NJDOdVbhi99Vj+v9fR7rehtstnhoGFN6/pzHRJfOouy9AbmNstz3ABm1P7hR1dytx
         oPj30hA+Bd+O27hiHPXt6VwyQ2o28StnZ0kbe15n7hFuHbGRmOK1j5bBDnb1MnnVzp8Q
         sH3xGhJj19ZemBwczNNgcQ6dWq+daC2oGO9ae+ildIxkEmuCGXogJz00LQxDNSTAE2Vl
         IAebht/aANE7RggMZ2PqOxzq03bxv28KM2WQwoAN8u+6Hb6BUIUG5Th0VXohYjCaa9FL
         OlSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CC6vGVTECHQtx3sTsdZy4eKlMfu4tw+OPlpEJ4uwybY=;
        fh=jK4ot8Two97LUIuIBoETja7pdZKpotzQYv2DsPSF/2g=;
        b=EvGbSGp9xxC/y/whX4oHtWNDAZRiINMC+SrvP35o6X0rSO3uA+TcDPBHR6nbzumTvu
         iUBZdyVxvuBodkvDtIo0orGGyqKmllmE5sXbwT6UfDBqZe6WxzIgLFuFO/Ifx/OZOCxb
         rxfBlh30ZDhyQegRAam5ORfF+q7fzybXaWj6gKlfpf07n7DAdGQh1sM7FCCu6W13le/g
         m66y4KQqYHdSW5ztCrVVKBE+7vOoJg9bITZSPPa9w6PKlXJv+YzmkkENSOTtjSlnTSqh
         2wpD4l50HMMjorzWrRJU3zElU3tBANqX3wBw5Cw3gzHAtcQixaeuMbyxGAOEoG3/UBvu
         cpxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dHbKIKGA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740519473; x=1741124273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CC6vGVTECHQtx3sTsdZy4eKlMfu4tw+OPlpEJ4uwybY=;
        b=oAGkpBcT9AHiJIRpO07PDDo/g6byjUzO94Gqkf/4WdfSV/pU3klx4Ex7Y3ZJjgLKGF
         OLqWnFqU6puCXpSU/7B4Y+T03dG2NpS8YjbSss9NCZ4nS6evoUyauRKOHZogCHmgic99
         +9Y0XkFXQS3LrTRVsHiYJ1nlkJnfkPnl5GuQEUd80drH5qQxoa2usUmzNkJtEwQrbC94
         fv6210BkWQXlEIKoh/hiQf+gxeb2aAwMZGa8mdR7xjERK41cuT88wW4f08Rvm2esAIwI
         CTbXXB8uPBcHUnrvOMSmRabP9fJh2s4eO5OcnJROTl/rQhKQmN2e+mgOEy/Vo/frhOBb
         fOyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740519473; x=1741124273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CC6vGVTECHQtx3sTsdZy4eKlMfu4tw+OPlpEJ4uwybY=;
        b=Q+xD9ySLBBFuq/oSZRJxEPy7j+qWgMFSnpFLCpPUZtd6IlItKoLs7UpXJfDz370tI4
         upGwHa+/tNAYX6E4on9Z9R+XY0KmIJPNgrnlOJYRrRwQtgzLwjAv20GzSnIpZWaNywG4
         DhNQbARHTTLhBS5uBw1qGd9726BtT3yVSZ4WbWCKTQBVv7HERRi4Ov4gJE+IW3Hp4LBl
         9SfjLSAY2exUjeABRqwPYVCsJploqDKyrWbZATYaES9xk5kdYt3us0k/xpVOAHZRyduV
         XWYSMg5HtjSOdmOGscpRfDlnH4gsVM2K6M6MsPsJ2lNDaNFa7viSLqu3uSU7iSDCMnRZ
         2nbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740519473; x=1741124273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CC6vGVTECHQtx3sTsdZy4eKlMfu4tw+OPlpEJ4uwybY=;
        b=RLbrWFATcTzcFut+ody41W6O0TsRpuqVjnvK6cnGMVr6tMNnYogEhRjZ6WHnJIR/B3
         G7hYMZYoUpv/5l4mdRf0VmuOAUh/7+PkCzAbdfIrVb8EAc8PyCMYxS/B3HdCvWf1oJKB
         yOIM5UnEoK0HId49oHKzLZ3agfmTzdVLl2pLVmQs0tiosBkr8REEHZUfI3c0bhp/rHvc
         3s09C+1BIhD4AA+zdXCtPxtMnB6S9S1ioSf5jw/AYXcHxlxlJ9HaEMLjndErZ1cjedr5
         Xx4VRDGmy/hI70Zu/11L9hLYxLBjuG2dlcysvY185e4DiZvEBEA0NXY3rM7OFaiDxOoB
         lTJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWo43VqdIJT7D7ST2ARM83Vl0MXuq2DUfCNkcRh6fGoTHEPZ51TIT0mqTyIpMNzW2P46XJVBQ==@lfdr.de
X-Gm-Message-State: AOJu0YxqaHieKAp+WBE7RFp2VyiEohy5xBT3P4QDYOjuhzzYLIkpLM3/
	eYLxKTRQFUPRSUZtBuzRqLWVkFKfQmpWPBsKQV7SrAVqxBAl3Y+B
X-Google-Smtp-Source: AGHT+IHE5yMaEJ1R5CQiTSJLxxspu7vWoxvyMDyfTQ94DTDFS8pomeryENncfzH9wDAEKJKuhjUYbw==
X-Received: by 2002:a05:6402:518f:b0:5e0:51c0:701e with SMTP id 4fb4d7f45d1cf-5e0b7254f98mr18794141a12.32.1740519471565;
        Tue, 25 Feb 2025 13:37:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHs8QwpIiQ56zEksrSr8iVXquayiCLI18DQT1ceIfnmlA==
Received: by 2002:a50:d71a:0:b0:5dc:cf28:2128 with SMTP id 4fb4d7f45d1cf-5e0b63b4260ls525024a12.0.-pod-prod-03-eu;
 Tue, 25 Feb 2025 13:37:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWy9H6vkWy8Up/+xegd6Oz+PNQr0w2EkeqJtLXcr/xtW/hZlYCH/x3UTqyJmq5Q2Lg8GJZWOUvgf/s=@googlegroups.com
X-Received: by 2002:a05:6402:3583:b0:5dc:cf9b:b048 with SMTP id 4fb4d7f45d1cf-5e0b70cb80bmr17268327a12.1.1740519469127;
        Tue, 25 Feb 2025 13:37:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740519469; cv=none;
        d=google.com; s=arc-20240605;
        b=WDXwfocwOgm9QT3TY49ViU8RpCMcklOxUSBc6IPbvnHS3eazHCJAbbLJknXHnpKQTv
         govYT+anAFQAsim7L5ac64xWwIincRO7sX8EqBj5zMg0YBi9oEl7nKVnHlDj0F6liypB
         fy98qZExsaXQF2V9jsRQh1PdF5WJWIvqLzhbhVpoR2dM0FX1T1CYi9/z72uS6qwdUNvz
         G632BlZxWy0N5E+pKCqVimB/RJzspkRgpNIE65wBr2IzpXwXnG7ZBIBOn8yC+yl2qkOh
         YVFxp0yT/CtzN32rDtdaULZ24qpiZVXJ74XscScvul7cuZ53RNHA/VYNxY9u0dz9dzAx
         sgLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9QCyp1JUlv9qVfn+zUKpBjTnHTrPkzYz/kl8dlHJcy0=;
        fh=ak/S155eo2Pk4jHBYZQ/UDFQ6p58hIj+tDxZ+x7IDlM=;
        b=FCcvCEydY76cOYb45qzh98f7qizLqvfxI+gnX0YILFVlrdrtiNGQqO1yfituHnJae0
         pZie6CaXU1owJjXl4Z/JiU9UkF2YAB9t1HOTXd0Xv/8yBsZi7bBrTqvd+vajlv066oln
         UYu65z/zg1j3rZ7ZyJEyEkslY31LeML6y1iPyOdYjmyHc2Z/kliDt4PWBXV+ngNM75lC
         wUzm4wXX9OBSWQegHKAVKJXS/0wASC7FFbZ9hg4gKmoadBzl+D8EuCpqm2nfKJaDP3nc
         6Td8TpsxY+FwV1vVpo4eRNjx2ZZj17pp2VswpfBeM8HjZQSJEq1M4zg0hxzj8I2QnydJ
         AE7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dHbKIKGA;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5e461b6cfa6si124943a12.5.2025.02.25.13.37.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2025 13:37:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-38f3ee8a119so3034065f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2025 13:37:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVAKW1sbHS+yiwRTkeT7szTOxbhN1PcjU3MJU5uyKMTs3jse0YvUoaqMHw81X3SmYqamF1/TMLd3wM=@googlegroups.com
X-Gm-Gg: ASbGncszxQ4/npi0DE4KebIgrkBWfsIePNee/BLPASqIXCsX+XG0Yv1JxPlVEmoTIy/
	nTLhfVaNwmMMRe6Ungj5Soda0RPm8B2ERPppLyoQ7V67SsNKsNXCTNwN+vIYqNfdta9iF4TFU1U
	XiT4YaG+xr
X-Received: by 2002:a5d:588d:0:b0:390:d5f1:de9f with SMTP id
 ffacd0b85a97d-390d5f1e3dcmr106316f8f.18.1740519468347; Tue, 25 Feb 2025
 13:37:48 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com> <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
In-Reply-To: <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 25 Feb 2025 22:37:37 +0100
X-Gm-Features: AWEUYZnhs_dCGf3N8iOL4s8huRdd6HbG8f2NLaDJFhsXr34i64LAvkBz9QgjSAQ
Message-ID: <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
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
 header.i=@gmail.com header.s=20230601 header.b=dHbKIKGA;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
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

On Tue, Feb 25, 2025 at 6:16=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> I mean in my tests, with setting offset in runtime, everything works corr=
ectly
> in inline mode. Even though hwasan-mapping-offset ends up empty and doesn=
't end
> up in CFLAGS_KASAN. I assume this means that the inline mode is pretty mu=
ch the
> same as outline mode with the runtime offset setting?
>
> I also tested if hwasan-mapping-offset does anything if I passed random v=
alues
> to it by hardcoding them in the makefile and still everything seemed to w=
ork
> just fine. Therefore I assumed that this option doesn't have any effect o=
n x86.

Hm that's weird. I wonder if inline instrumentation somehow gets auto-disab=
led.

> Hmm indeed it does. Then I'm not sure why I didn't crash when I started p=
utting
> in random variables. I'll dive into assembly and see what's up in there.

Please do, I'm curious what's going on there.

> But anyway I have an idea how to setup the x86 offset for tag-based mode =
so it
> works for both paging modes. I did some testing and value
>         0xffeffc0000000000
> seems to work fine and has at least some of the benefits I was hoping for=
 when
> doing the runtime_const thing. It works in both paging modes because in 5=
 levels
> it's just a little bit below the 0xffe0000000000000 that I was thinking a=
bout
> first and in 4 levels, because of LAM, it becomes 0xfffffc0000000000 (bec=
ause in
> 4 level paging bits 62:48 are masked from address translation. So it's th=
e same
> as the end of generic mode shadow memory space.
>
> The alignment doesn't fit the shadow memory size so it's not optimal but =
I'm not
> sure it can be if we want to have the inline mode and python scripts work=
ing at
> the same time. At the very least I think the KASAN_SHADOW_END won't colli=
de with
> other things in the tab-based mode in 5 level paging mode, so no extra st=
eps are
> needed (arch/x86/mm/kasan_init_64.c in kasan_init()).

What do you mean by "The alignment doesn't fit the shadow memory size"?

> Do you see any problems with this offset for x86 tag-based mode?

I don't, but I think someone who understands the x86 memory layout
better needs to look at this.

> Btw I think kasan_check_range() can be optimized on x86 if we use
> addr_has_metadata() that doesn't use KASAN_SHADOW_START. Getting rid of i=
t from
> the implementation will remove pgtable_l5_enabled() which is pretty slow =
so
> kasan_check_range() which is called a lot would probably work much faster=
.
> Do you see any way in which addr_has_metadata() will make sense but won't=
 use
> KASAN_SHADOW_START? Every one of my ideas ends up using pgtable_l5_enable=
d()
> because the metadata can have 6 or 15 bits depending on paging level.

What if we turn pgtable_l5_enabled() into using a read-only static key
(DEFINE_STATIC_KEY_FALSE_RO) instead of a bool variable? Or if that is
not acceptable, we could cache its value in a KASAN-specific static
key.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcsg13eoaDJpueZ%3DerWjosgLDeTrjXVaifA305qAFEYDQ%40mail.gmail.com.
