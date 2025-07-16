Return-Path: <kasan-dev+bncBDI7FD5TRANRBCHH4DBQMGQEIX5APVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D1F0B080D8
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 01:19:39 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45600d19a2asf2618665e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 16:19:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752707978; cv=pass;
        d=google.com; s=arc-20240605;
        b=H1UuPGAz4HHNhhgUPI2a8O3p8sitl7eiHMSPven3x9XfGTRfka9jsVgj6Aetap/PLs
         BnBMFYQ64SBir1UTuBdTQNhkM7f53NwhZZSKqZl2m0E25s9nAzS6F8u6KAg2sz3meufh
         QZ6M7fiT9p9ImwgH6bDwSNakTF1gM3wFEND4GjPgOn7t5CX8neq/UEADO7Xo8bwW6GLL
         7d/iX4hRDgMww7qvQHi0TKQZT/FblBFckDTSUfv/kiKxM7vTBLMiJq4bLYv13LzioDxD
         S9pmKAmTN3VdJx4EQzuy2VZoDD4S4bVUY75JZ7SvBOYrgJNIv6PZGJ+2UH83HpqeWPBA
         XV4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UClQQeWt0FTkNSQ9UcuTRDBbPTQOHDYYea+Oj2QCVi8=;
        fh=zUY6hypM1m1nkx4Y8IUAqCUEsK0tF0yW2riS79Y69vs=;
        b=E6z7Aey+toIc58geJroXhcnNj1GCRNceBZC2TpJVjk+peE/llylCR8uzWuqC7CFWM5
         XqHKVHCyaGE9BhDndwIFqalrVu+p1+r5pQrn7imY/9pL0TnfgXdjBQjCUQoa4xJnAguc
         +xEROItw8eQxQ6QKEzdv3cjZnRhv73wnY7WJOz1t9WWGW+ERBWkt3sDSWH/yaIJ/EWVe
         67F8POMuhAkJsFKXPxGwFQH4BKv6okJRGxlN9FNlegvULTx0ZOFh6nNw8XeX6TFiwksS
         530f3jA6ZSIgKiZyp9cr0tBLcoUClleqXV6LOaAplvsl4hK6BVbGsKxF34KbGkygKU3D
         wXbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A1TkBzeA;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752707978; x=1753312778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UClQQeWt0FTkNSQ9UcuTRDBbPTQOHDYYea+Oj2QCVi8=;
        b=T+HqLJZbLTx/r5lXN+oJxdzXsX/nAgZB9Jx9QKeQacJMwUi29VqxTTJpfsO+6JkKsV
         7vK7/dBY2WvOTCcdZwHcgn4nzr5NS6Vjmd+cZCFdIkaGz4tJuI/9FJ9YcGRKvKdsCysF
         ljZo221AnTejP+55cIi7/t/oCHpC8O0VjjhIfuCI4jovH0Bp1eEdKXRfSrstY0YQHlOR
         kDetgCZhdjBBdQk9hHqayzWOKwQ754kWdqjQ1TmEHu0vMrguXmcieolDfgb0JbpDPx5v
         STbp5VQzRLspswnlr0Lmi5xp6Slz7w0Mu7DOSSxQ2V2/XcCWaa4+YTHNG5co95sWD4rw
         hWqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752707978; x=1753312778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UClQQeWt0FTkNSQ9UcuTRDBbPTQOHDYYea+Oj2QCVi8=;
        b=AvsgulvW91XjloggPUDEEsIoLtxi+PpgqKLTgE2K17bKiU3dnalUJyxbieec3W2ga5
         NcThpPI5X7Or6/EPEcOLtncXwhtr6cs8SCERdrI/0HIsLZiiLsg/Lw4Wavgx9/xTcDrK
         4wZu11AnrXrA4eXKqFMgwWaxRciipCWq+atp5IWI22FuS/RXDeMuKk5QYxjj4jFtHKmG
         iQ0SfokQkH6wByqOgzSrY8V6tgwZ9PhVieCip2Ni/2+zuinhXPPKgLwL/EXURzU5d5yg
         5Cdv7002jLul16IUkdMqSKCiCWc8xJEKlx21I2Oox9WLZRZKrdlnYe3xHPb5SWApmiw/
         ld0w==
X-Forwarded-Encrypted: i=2; AJvYcCW5wCM7HO8R8iI3S5t3UV6FSam/MNPtIiPPABWDB5pWI+b2k2SXQEk0He52EZ4SSYaIuz9vgw==@lfdr.de
X-Gm-Message-State: AOJu0YwsrMQ4UVf0u/5zkgF8ub8b85YlzFTE54lKLRRZWj/BBK/62KYF
	+dH3P+qHjr5XIIvZcVEhIRIsoG83iciWJD+CLet+hQIRx1a7aiDLYvAV
X-Google-Smtp-Source: AGHT+IHopYCGrvuwI0qbkf5u3QXNztyWD6GfIKD8f9EaEnxPQcQfvMd5kAIg/DdOYSrJojjyLSoEYQ==
X-Received: by 2002:a05:600c:3b97:b0:456:2000:2f3c with SMTP id 5b1f17b1804b1-4562e36c6aemr35338905e9.22.1752707978223;
        Wed, 16 Jul 2025 16:19:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZda9hrEur6dB8rWshGDCp31Gy6LR/xXKU/Lq+1itGzMPQ==
Received: by 2002:a05:600c:6209:b0:456:136f:d41f with SMTP id
 5b1f17b1804b1-4563418bd30ls2160415e9.1.-pod-prod-07-eu; Wed, 16 Jul 2025
 16:19:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLKSWV/PLYB08Bo1+xLyacyYH1wx1HXf1OE1hHqBeViydJqzOv6MLAv6vDYm/yqgRIGKstNLGjP4o=@googlegroups.com
X-Received: by 2002:a05:600c:468b:b0:456:2419:dc05 with SMTP id 5b1f17b1804b1-4562e33db7fmr49439045e9.12.1752707974857;
        Wed, 16 Jul 2025 16:19:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752707974; cv=none;
        d=google.com; s=arc-20240605;
        b=jHl7+phE5KPq5ptxj1j0EVfl92hw1oV1OKBgkeayUw8E3ILFBUi23GnnCWTqQN8dE9
         56wv49kwvj6lgFjx4sM6aK8/hM9mQ0CKtGNqWxUnXUshbOONwjE0Tdy5Pvy+ERE9oSdw
         9Bgr9GdpGSHG8+/tQ0ApCy17FQla4M85qpk08iYOmlfu6JhPfsbdEIemu/ncaUIkvujK
         8CNH+i6DATOON+qRgIDEF4nggnrbVIsaLa1fpnr4qRXTtDqGyL1vnfUn6JzEXQ6kVP8G
         U4tVxraLn2AZX5c/ezGD5mTnXbqgI13MJb0c2SvxrOwhd3D6dK2yWAbXeSlPyvp4ybif
         JZ3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9/NnJDTcQwKH0nX4EoIsUlDscSEoGQ+CI3cGaPK+Ctg=;
        fh=XWhioDEZl1CzXX5q7SdPbNF6Iuz2vUCP3dS/b8U3k8w=;
        b=MgSft8FPbGbsntcD4Yr6u95H8N60hFTQvOlouWPSN3QPVx85OvtX4gb0c2QQNKWF+V
         WPJqAizdayDVKcrU8kxTZpwcaZvYYnOsN7LJ4LcqlODBJnKwscQ1evEvdYQa8e6mV4ao
         7VeXjEU3WvuuZK8yhRsRCtC+NfJ57u683u71vRpFHqrFSEQFgEzGxV0BjwcSx2xuRd8O
         FQLwLntOTBvHz6Nbs83qhBjegS151YhBgLfDkC7zyyZb4BQix9pjiJiwaSwvrY3+O835
         eYiC2lr7THTuqr2n9h1AyWgts6mtHE9Z4Ur2D5k1R1cEz3gy1ysjMUNpuHmoda4VYfEV
         YM7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=A1TkBzeA;
       spf=pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=mmaurer@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4562e829bb2si793845e9.2.2025.07.16.16.19.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jul 2025 16:19:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id 4fb4d7f45d1cf-60b86fc4b47so2411a12.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Jul 2025 16:19:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXVlFiZ6IH37jOk6nQA3gy7wS29/IYWM46GNPevSt0YZdW3/J0xgGCwQVlUl1C/uYXw6vZKeSOPoFw=@googlegroups.com
X-Gm-Gg: ASbGnctyd191zw134kKxcAM7H8o3Rt3HJRUD4UdBIqFhKVac8wgpOVTFMDRabLDUPAW
	zgm2ZHqtpu3+8BsKBqUcWbmLN4yjxfv5ASVQMvEgd3qo/i2GTcuhXktutX0cOBgiiR8Oe1ijGbG
	c94rDJOOQrfr3uBdYTbcAwJoJL6lCCyDuqoTsW7LXVMq2KHt06RvDeaSHqB799pSDDO8k56BUF3
	J5wIYNQOAMm+rmCGdje9RSIoG2QX7xy4xyRnnXVoLwlIxt5
X-Received: by 2002:a50:d75b:0:b0:601:f23b:a377 with SMTP id
 4fb4d7f45d1cf-612a4cf8fc8mr29145a12.6.1752707974101; Wed, 16 Jul 2025
 16:19:34 -0700 (PDT)
MIME-Version: 1.0
References: <4c459085b9ae42bdbf99b6014952b965@BJMBX01.spreadtrum.com>
 <202507150830.56F8U908028199@SHSPAM01.spreadtrum.com> <c34f4f606eb04c38b64e8f3a658cd051@BJMBX01.spreadtrum.com>
 <CANiq72=v6jkOasLiem7RXe-WUSg9PkNqrZneeMOTi1pzwXuHYg@mail.gmail.com>
 <24e87f60203c443abe7549ce5c0e9e75@BJMBX01.spreadtrum.com> <aHftocnJcLg64c29@google.com>
 <CAH5fLgiiZE_mFhB4J+G7-Jdz46+d-5NP15npjn2_H7DgSAynxw@mail.gmail.com>
In-Reply-To: <CAH5fLgiiZE_mFhB4J+G7-Jdz46+d-5NP15npjn2_H7DgSAynxw@mail.gmail.com>
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Jul 2025 16:19:22 -0700
X-Gm-Features: Ac12FXxXgsXM-s4jPwxbK0qidi2uE_QL2umvn-Fdybn9nHdZCi0VGiyXjMukuYQ
Message-ID: <CAGSQo03DH9L7OFZsGXU8gt_4iq2zo6gZbJtw3p2hD6tGp0KTzA@mail.gmail.com>
Subject: Re: Meet compiled kernel binaray abnormal issue while enabling
 generic kasan in kernel 6.12 with some default KBUILD_RUSTFLAGS on
To: Alice Ryhl <aliceryhl@google.com>
Cc: Carlos Llamas <cmllamas@google.com>, =?UTF-8?B?5YiY5rW354eVIChIYWl5YW4gTGl1KQ==?= <haiyan.liu@unisoc.com>, 
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Miguel Ojeda <ojeda@kernel.org>, 
	=?UTF-8?B?5ZGo5bmzIChQaW5nIFpob3UvOTAzMik=?= <Ping.Zhou1@unisoc.com>, 
	=?UTF-8?B?5Luj5a2Q5Li6IChaaXdlaSBEYWkp?= <Ziwei.Dai@unisoc.com>, 
	=?UTF-8?B?5p2o5Li95aicIChMaW5hIFlhbmcp?= <lina.yang@unisoc.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"rust-for-linux@vger.kernel.org" <rust-for-linux@vger.kernel.org>, 
	=?UTF-8?B?546L5Y+MIChTaHVhbmcgV2FuZyk=?= <shuang.wang@unisoc.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, =?UTF-8?B?QXJ2ZSBIasO4bm5ldsOlZw==?= <arve@android.com>, 
	Todd Kjos <tkjos@android.com>, Martijn Coenen <maco@android.com>, 
	Joel Fernandes <joelagnelf@nvidia.com>, Christian Brauner <christian@brauner.io>, 
	Suren Baghdasaryan <surenb@google.com>, Jamie Cunliffe <Jamie.Cunliffe@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=A1TkBzeA;       spf=pass
 (google.com: domain of mmaurer@google.com designates 2a00:1450:4864:20::536
 as permitted sender) smtp.mailfrom=mmaurer@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

The reason removing that code makes your build "work" is because it
entirely disables pointer authentication in Rust code when you remove
it. That is likely not what you want.

> > We have KASAN builds with android16-6.12 and haven't seen this issue.
> > Can you share your entire config file, so we can try to reproduce?

This - please provide the config file or instructions to reproduce the
build. Since this is an upstream avenue, ideally provide instructions
for reproducing against `linux-next`, or failing that (e.g. if it's
not broken there) against v6.12.38. The default android16-6.12 build
will work fine with ASAN. If you can't provide the entire config file
in a public context, or if you only have instructions for building it
with Kleaf + fragments, or can only reproduce with the Android tree,
please reroute this request to our bug intake system (I am pretty sure
unisoc has access) and cc myself, carlos, and Alice.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAGSQo03DH9L7OFZsGXU8gt_4iq2zo6gZbJtw3p2hD6tGp0KTzA%40mail.gmail.com.
