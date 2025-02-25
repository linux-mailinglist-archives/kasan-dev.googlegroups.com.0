Return-Path: <kasan-dev+bncBDW2JDUY5AORBS7Q7C6QMGQEWJQ52CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A17DA44F05
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 22:38:23 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-439a5c4dfb2sf27645645e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 13:38:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740519501; cv=pass;
        d=google.com; s=arc-20240605;
        b=cH8h3HtUzTWa5qjot2SN27MY8BRKTzFRivKOuphse3OIDyWV1GZtgReaWLyeBSyoMT
         ErtxERLz/U8AR0HT0TPtKqePsQOI01CR6U4Fl2+iY9zQ+CLJiAMU0f/UupPGAHqLBNuw
         MiqkNfz9zfzG/YDt8mM0FV7ZRfl5TpegccWF+aYOYVvU6bwQcHwbpwpB5plSLvXiwIm+
         EdM/MVleQMi3ZQUaCLRl1KWqjeUPng1QrSyblnuacKwUt+166bXFuOM6oTBDCB7DxwWH
         TL6I6XdyVOKIu3ycyJr5BXtX6tizlu8CUuuAh6AzZmySoc7Daq2UWj0ToVC/Z5r5+aTW
         KR1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=TdxeEY6l9pPsYNCw6uLeBCH0Ayio5m3KEs51A20G0sc=;
        fh=MU+3oW5OQBUxr2g49RRg7EdAqzE2o164Fa7DeBBwddM=;
        b=UxKdvqpKeDZ2PA+Jka72N1MpckmZOUaW2wRE6gVDikdNZM6Y3JpbSdjy/mG+aip0gv
         KNPe6D7jYNRDyOfZFuRUSZcGmzJDIj0aVGoRB0RASQQrynQDjvpalivcy5rz1GgBFiWe
         uJCX02IwwRRY4ZQROe5N2Mi1gsCh8ytIdDKlT3BH+Z2l8poMDeIvR7NF5W2uXiHQ1rv7
         O7ZNRciYtivUjpRqqzFBQvpxlm4qMuZ5nOo7mDXPCdNVKKPV88gBwFt6gmzz7Enno9eF
         uH2+drdRQdKBf3zAhsXoS/l7oHzDE9Qu7rvNjZ0r91S5Th4cBmWOqxFSwPSPb30tb5qc
         ukUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lm5ndipm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740519501; x=1741124301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TdxeEY6l9pPsYNCw6uLeBCH0Ayio5m3KEs51A20G0sc=;
        b=DU6zsR9kfwQM7zWt+Vv25/+yutjqXXF52u+JBOV8JMxejz/nL8IczKVIhu9IY4L2nI
         zfr8+nF8raOKmk/l9h5qdAwE/XyYxYpE+Jk1FMSxuQrxqTT9YOk0OeZQNTbsIJfhFwv4
         1xvBB9wcPyYH1GwcXFeb2tX6w6WlZp5wOAA9H4xrWyxaUUJKr886CsshqieiXE3jfMdx
         7AKtnoIeuGwwBWbszQj+LmBkdFZkw4FrcbwnqoYVT9pu6nR27wH/tc6IhtgefyzPTRki
         Rc4CiDRse1O7x6hKfbWjkgCXRgQUeuEWYCs03QgXPEXgLmUWN9sB3DD+8n8mmx3Wl6MJ
         ZPBw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740519501; x=1741124301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TdxeEY6l9pPsYNCw6uLeBCH0Ayio5m3KEs51A20G0sc=;
        b=C9wNA2yxCZmWKmIJpGjIs+b4Lnd6OYB3v+KkLA/LVHEgMBX7v8yQBzBw2FMLU+xZh6
         81OV7OXNnpttWizK+HJIJffTRjRy9J5q8sQIFB7qGclqQr399g19nFv2iBH1BStzy7yD
         2xtqhhQD6oMfZ2XfLZpDGkCyDttdN1y3phwhksPjLOmHS/PkA1f/smnUZxolQ/Qydh9Q
         ozzGXwyokyj1vYRg5x+H+TW9Yw/VKbJHIxlK+JPIACC5ikmSVsTbb6l60W7ga1NOOo1J
         u89F/jr+MqbmQOyrH0avYFw+Vw7/FsEoXa3dPqiAkMQU0GvtHiNr+8qeCwQeTen+2AFj
         oeFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740519501; x=1741124301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TdxeEY6l9pPsYNCw6uLeBCH0Ayio5m3KEs51A20G0sc=;
        b=FPVLcegi+B9C9XXFLBk9ME9VSiA2bs5Be0ukokO3l/glgahZcTN19jmIJWny/WyzLu
         8wiJfKmQzzhpR2GdYppjhhF4dnTS5kQWtRhJcojmdzz/9wVafYufCePG2AGddM7AcFG/
         LT5RBMAkfp+Mn6a1YTLH0c9veiZsBOJj878rk6EE1l8Y6QcZoY2k/mPSV32XeWlYTRpe
         T4EWvk9YADxe96YtTNFU0cVKRvW+f1pgwmj3ALeqOc4d6OOgveU38P8j+idr+jWaJ6Rb
         1WPkKxYGwW0UFivtzD7pLWI+z/qQA9FWDLvjCz3fUKr4Lj56hIXgq1x/EVgDI1/Kg+DE
         gf6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWm4A21CMPac3S/zGKKKK9W48AKLqV68gfyO4k3RFRn5yohuwBA53iWhaH3XhQ9c1ddbOWhgg==@lfdr.de
X-Gm-Message-State: AOJu0YxjkzDZQGkEY5yB0Rv2Inu6bqYlDus7rUU0CBbjQieR2dVieACS
	LsfTyDw+anvuTgxuv5MsmWprz9yNaOxWaWLmNhp3Kea8gdB5Jz/y
X-Google-Smtp-Source: AGHT+IET3d2ZOb9dq/SlEaHQ1TloO1pCr+/SOkLIEKBuIurMYFFRjEv7WfzH4TCw4k/0uhwdVCq5Fw==
X-Received: by 2002:a05:600c:4708:b0:439:86fb:7340 with SMTP id 5b1f17b1804b1-43ab903f64cmr10444715e9.30.1740519500131;
        Tue, 25 Feb 2025 13:38:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG9VhUnJrd8yW9OQs48k4foq1VRZOdMtd4iVqkHk/Gsyw==
Received: by 2002:a05:600c:304c:b0:439:ad97:3e41 with SMTP id
 5b1f17b1804b1-43ab93fa5cels854275e9.0.-pod-prod-08-eu; Tue, 25 Feb 2025
 13:38:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXBLKbYQ0cPH/98qOxv+8SMPxSxQd1XeD7FDaIl8liPlIWSz3d2JdQ0Q8xNg6hMFFWtKpzjHaEhPeY=@googlegroups.com
X-Received: by 2002:a05:600c:3b83:b0:439:8346:505f with SMTP id 5b1f17b1804b1-43ab90169f2mr7728335e9.20.1740519498094;
        Tue, 25 Feb 2025 13:38:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740519498; cv=none;
        d=google.com; s=arc-20240605;
        b=axDkYJH8/GDV1Z4bwOhN9AMwkYFAweRbzKqjnbFM7cHCiEwwmTFIe4O8reFVsvghr2
         UTtmcIm0gZXHyzSZsvjkHNMDuBAyqkvFVf7WjyiwpH1w0v8ZdJTS5Y6wc8IsPanMzQvE
         jdsEOXJ7VAGje1c5Rg44bW7Wv9IT5J13BkMuFFiqdJHwFiXVN0Qnb6KvweOXrC02tSb7
         8LGL0Ve2lSuKxNM1rGyTV0VjWbV4YlUlocjmuudMSk3C2K4nf5I6/NwDkWKzkLCDwSVd
         dExKcojZxV+wyA5pLRKxsKkb1KhoqOGaw/LK9H+9gxBOW7zCTi+Ga0+cHaR+mvrTOuTt
         +Vkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fXFKcm0lZuF5OG0aApeKuQOf3+mW6bFB0yCFPCGgwEk=;
        fh=HpJkJRoo7chY/1rnhgLjwGeCQiXy40q+eJ7Ai3cT3HU=;
        b=SLWU6giSb3NPj9nRQr+j6rVcJs3/7GwS0YDTcwNEDe+xUbdCvO6n/MEM0xXdrwstY8
         dBhsv6XF5ma/YijQgYLHXPPmLOGgF6fscEmoKDL1f/ypCIG0feidYBTpqIvJByLwkQi2
         YBgEU5yWoS90cDNHxHoiW3wERMy+g55hte89PFc8ppe9cVi9Tjy1hQxQYTFsNdeX9BNZ
         ByIYsV4g+xZ1tyHyy7a2QCdhsn7m6P8aVXu75qUST9OAkH3bKh1i2jdUoQBgESio63tg
         jSxAK9NNN50EZJhcc7nFNykPDjfrlCgbArmPmmLb4pI4ZtPyTJOT8PxVxNkPF6XK6gq5
         mTfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lm5ndipm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab3742b77si2641875e9.1.2025.02.25.13.38.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2025 13:38:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-439846bc7eeso39017955e9.3
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2025 13:38:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXNdH/viCei6Ko73BOyKSjUVdfIfqYtvkLcdVRI7d3PtEFdXR2JYlRH+EIBVXA8Lcm4k/H6XpU2DMw=@googlegroups.com
X-Gm-Gg: ASbGncsDMX97fr7KciHgqsys0g4bPA0AcfsO4ACTw9T2016p6d3cpYaP4psKEV/xfV8
	Vg8A73pkz3XqlgfKrjrWpYcl0BNN4MLFr9jBDNqh6+fuN+hyYPbbHmgRZGLQuCzxaw1gH9KUBqv
	m7YRSU41D2
X-Received: by 2002:adf:f003:0:b0:388:da10:ff13 with SMTP id
 ffacd0b85a97d-390d4f3c491mr589082f8f.21.1740519497503; Tue, 25 Feb 2025
 13:38:17 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt> <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
In-Reply-To: <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 25 Feb 2025 22:38:06 +0100
X-Gm-Features: AWEUYZlodhwAbgPi0Dk16h7YK7x4HrrqY-JVxMx5ByQmdcv8cbnJsNVhi4etBIM
Message-ID: <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Vitaly Buka <vitalybuka@google.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, mark.rutland@arm.com, 
	broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, rppt@kernel.org, 
	kaleshsingh@google.com, richard.weiyang@gmail.com, luto@kernel.org, 
	glider@google.com, pankaj.gupta@amd.com, pawan.kumar.gupta@linux.intel.com, 
	kuan-ying.lee@canonical.com, tony.luck@intel.com, tj@kernel.org, 
	jgross@suse.com, dvyukov@google.com, baohua@kernel.org, 
	samuel.holland@sifive.com, dennis@kernel.org, akpm@linux-foundation.org, 
	thomas.weissschuh@linutronix.de, surenb@google.com, kbingham@kernel.org, 
	ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, xin@zytor.com, 
	rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, cl@linux.com, 
	jhubbard@nvidia.com, hpa@zytor.com, scott@os.amperecomputing.com, 
	david@redhat.com, jan.kiszka@siemens.com, vincenzo.frascino@arm.com, 
	corbet@lwn.net, maz@kernel.org, mingo@redhat.com, arnd@arndb.de, 
	ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lm5ndipm;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
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

On Tue, Feb 25, 2025 at 9:13=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >>Thanks for letting me know about the tag resets, that should make chang=
ing the
> >>check in kasan_non_canonical_hook() easier.
> >
> >Ah, but the [0xff00000000000000, 0xffffffffffffffff] won't be true for x=
86
> >right? Here the tag reset function only resets bits 60:57. So I presume
> >[0x3e00000000000000, 0xffffffffffffffff] would be the range?
>
> Sorry, brain freeze, I meant [0x1e00000000000000, 0xffffffffffffffff]

+Vitaly, who implemented [1]

Ah, so when the compiler calculates the shadow memory address on x86,
it does | 0x7E (=3D=3D 0x3F << 1) [2] for when CompileKernel =3D=3D true,
because LAM uses bits [62:57], I see.

What value can bit 63 and take for _valid kernel_ pointers (on which
KASAN is intended to operate)? If it is always 1, we could arguably
change the compiler to do | 0xFE for CompileKernel. Which would leave
us with only one region to check: [0xfe00000000000000,
0xffffffffffffffff]. But I don't know whether changing the compiler
makes sense: it technically does as instructed by the LAM spec.
(Vitaly, any thoughts? For context: we are discussing how to check
whether a pointer can be a result of a memory-to-shadow mapping
applied to a potentially invalid pointer in kernel HWASAN.)

With the way the compiler works right now, for the perfectly precise
check, I think we need to check 2 ranges: [0xfe00000000000000,
0xffffffffffffffff] for when bit 63 is set (of a potentially-invalid
pointer to which memory-to-shadow mapping is to be applied) and
[0x7e00000000000000, 0x7fffffffffffffff] for when bit 63 is reset. Bit
56 ranges through [0, 1] in both cases.

However, in these patches, you use only bits [60:57]. The compiler is
not aware of this, so it still sets bits [62:57], and we end up with
the same two ranges. But in the KASAN code, you only set bits [60:57],
and thus we can end up with 8 potential ranges (2 possible values for
each of the top 3 bits), which gets complicated. So checking only one
range that covers all of them seems to be reasonable for simplicity
even though not entirely precise. And yes, [0x1e00000000000000,
0xffffffffffffffff] looks like the what we need.

[1] https://github.com/llvm/llvm-project/commit/cb6099ba43b9262a317083858a2=
9fd31af7efa5c
[2] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tran=
sforms/Instrumentation/HWAddressSanitizer.cpp#L1259

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeEm%2B-RzqEXp1FqYJ5Gsm%2BmUZh5k3nq%3D92ZuTiqwsaWvA%40mail.gmail.com=
.
