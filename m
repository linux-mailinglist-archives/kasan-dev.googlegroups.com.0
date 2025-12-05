Return-Path: <kasan-dev+bncBDW2JDUY5AORBN7BZDEQMGQEPTPAUVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F78ACA5C9C
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 02:09:13 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-6416581521esf1925615a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:09:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764896952; cv=pass;
        d=google.com; s=arc-20240605;
        b=R+Mmo8YOPttXeQZ5yiLoR8OSdRNe6tHXHWvwUxMu/pbkV92dhylNR6tLOedzjjgFbV
         1Y60fP8enYbMl02mfcg8+zhcnHsalddn+uzmUv7nEREHcz9RNoLiLqZzHznV0Ux9KPo6
         Kjc4Vx/WyZXAWx4EAb3KIbHuANg8OQw7Iayw+ZbXBb+dawwgUmggngZpW1ARvBGcSBeu
         ulr4nBLozf/3p4Lmkt1X8iP79GQJffwLu7QOKpgN/t1epszsRyaQxpGOjuSDb7TtPir6
         Z8TcQSNrUvezMshfLIducyxlxQRYG0+rKQqfRAnvWQp7WaLMzFH4TFInMZJg7A/siVq5
         IEJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=0gVFbsdf5n+TAMao7Yleg2rxFAoKA3sN2Y7s/KQ6wg8=;
        fh=oMvwMsJjYs2oRRTAqddR57H5KVB2bKLKln3+yorgQXE=;
        b=SrXL07zsrqon4v1FfBQ3TObBV9Es0zUZNOSjOquTOPxRKS65tOGITa3T4eu8q3Zpcz
         uMd+BGmOX7h1Vrfl/JTVTVWwkd0XGm/ljlKhzElO8/1yozHYdjVmJOdwsksJdh/JokcJ
         lHHTDg4McFYNl4G/5pjebNvbIwsKLQOC/EXUq/uSDxMVPWwa9pRjTcVO31/Wy4divquO
         PIYHAEIzJCEUYcOMvl/QXOR2zrvK7jmKSlr3MRi0ZSXkxEuXseoWVa5HTvD30yFFcfzs
         2LnnYnzhGChAYNBW1HifAl/snYCpzHsWzfqEtf1X2UGnKboCuTlNvbE+nBQ8n4vGN4VX
         PHSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nDe2lTFO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764896952; x=1765501752; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0gVFbsdf5n+TAMao7Yleg2rxFAoKA3sN2Y7s/KQ6wg8=;
        b=T2xOo/IdfbhF7IpyGNHnj2vWHf6iKTTyFqnAS5F8EekyQ2A1pPJTPIlRMXISvBgYde
         hkxc1hYVP3ViKJTuZXbgsboG1oLNm63YnyMiMj+yIFpihlHLcTVN1ia2ctmzsEQzwOoY
         acTIiIuYLwVTvMQqdDddx+VHDQ0TkoGCT5zXNMO11LpiHuuo39nYOcLnd3u6S0UXIwDc
         Mh46C4RkRfX4FXnnQ6a59NRFd6PcBmdUE7G1q5qJosaZ/R2ArhUf21EG+vY0WtGQAuZa
         hzesqnp85bLQaH66r3KE3JfMzN5P2LaSzfkQHS+4TTX5LTXp7VEHD3HI8supExuNi/l3
         7n5Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764896952; x=1765501752; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0gVFbsdf5n+TAMao7Yleg2rxFAoKA3sN2Y7s/KQ6wg8=;
        b=mmE0sM1bqxhl9DXX3pAs8tqcaqAZlRxxo8Azift8/GBENjYdoPXmxOdMSFf+d/ES97
         02HOzujR13Iq1IaCU+zo52KzkiuRHpORKO6rQAWZa2p6kXz7FAgsv+liq7eeiYB+Dd2f
         NtO43idDZ+oHvfKFyWczOVlIuyAGy31uwespYgCmm04NGrY+8LW8CmOkx/s6adacTlya
         eHaZ2KhGSzq/NBOWp9S2WAVM7xeBhUCLRCGi+7BhKiyXIoi1OcY5mkoz/E/mTp0OYfm6
         IiG5GRzFmS/sURTix47KX9e6PYUXM9wp0YQ8kL0IxvW0v97pO7L92iQYai9GNPUObf+r
         3UXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764896952; x=1765501752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0gVFbsdf5n+TAMao7Yleg2rxFAoKA3sN2Y7s/KQ6wg8=;
        b=jRvX6Oqjqhd0ds+mB9mIeIMathWDEEshEmb7qMeLvl9iyfmH5s5UKQGq2BRldAjXvw
         u0EDNEzpEuH/2WGcSx0CRRTvJqJfkPva+FQU8r3d+fTPJdnrAQAKtJEkCBII2wy88uQK
         lf96SsldJ4K+ChVvEUEwHqUzJBygH3coan90a4YTQ6XaX8KubKWX21zcCSMYf2XthkwP
         vAOkcJ05+PImcZgLDCeSHcFR4fOKf6N+qRCHDghe8ieYFr41WoNOyoLZ+2jV897dk7Dq
         NJs9DmclafvMAkPqw+8XbBjGZKlVG+/ukOqwxLmJS8EtMADs3mBJgNoZ5puhtItxEaDf
         a6gw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6Pe1U1oYsJKOn6rxNU2Q/AXr/dWs90HoM2KflF/Ub5y34pI7g2d6u3OUbIUGeD4lhL3FJSw==@lfdr.de
X-Gm-Message-State: AOJu0YyuYfrBDfgQwAKcUtTMkTHKb0KaW7VYguxOIxSJk0aOE5fiyCW8
	5etLlUYdB7XBAdFx+8WctWGft4WmDpS8+3mOV7S6Pt8icEPQLh4nMnty
X-Google-Smtp-Source: AGHT+IEzlDC93qpKae3N54tPFJ/meBfUpgHjBOmEfC5Uc1EGtPCzaRQWe0vgq+Oqxc+UWubkrApRLw==
X-Received: by 2002:a05:6402:90b:b0:647:5544:77e with SMTP id 4fb4d7f45d1cf-647abde1b6dmr3564207a12.29.1764896952495;
        Thu, 04 Dec 2025 17:09:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a272SkyqP1oSyqBrk2y1YcI4sMifCctMOtgr3BvOZq0A=="
Received: by 2002:a05:6402:f15:b0:640:cdaf:4226 with SMTP id
 4fb4d7f45d1cf-647ad5b16eals1132120a12.1.-pod-prod-09-eu; Thu, 04 Dec 2025
 17:09:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxjg/XBSWe3Kwuq2sMokioimFtMAzhweSDKKxLcDDNJTs49BNvAZsdvuvBWyi10nv3hVsC7FkhOLw=@googlegroups.com
X-Received: by 2002:a17:906:478d:b0:b76:6c85:9b60 with SMTP id a640c23a62f3a-b79ec1e0edamr482683966b.0.1764896949749;
        Thu, 04 Dec 2025 17:09:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764896949; cv=none;
        d=google.com; s=arc-20240605;
        b=ZfHQWogKuYsqZRJNq5cOPLAoSR5krCpBZ3xVIyMVE6OItVxyuwDEWXN+HIn37PCeJh
         bDbocal+aN29vflhKWr1dqoz8zFczQsKOCNdhlcz5OdqSGLB/r/Uh+ZICskyKlVChmBl
         bFSuvbP6+25bF6pOThvGlNRVBklpBGWGyNhoWW/CnCXGHtqOHM0xaFT29CkMJjIKvj6s
         vmPfyZB31CsIR4SjuVa84DfEdDUby4/6SuaIY91ZEeaPVZwoqUaYU1s+3jodWPjitD9I
         q2hfUKhndb3+0Ece87W/pxHExvPSD8RgY8+51qn3GAAQGymVOJ0OKZ8qqSyymwAm+KXY
         aNGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ESNpKydnctKAjT+ZBVg0a3DE2zeWzMFqr1QgEt4u5co=;
        fh=/h73aZ3V3GvtnvZC323iVPl0xXDAl01tKkDaE71ukBU=;
        b=bgOac3fTW21PT9br9P4uuPZ/JsR97ESFFTjIkgLpfc8U4YZR9nVh37KsTe0VNrGu2v
         hj/Wa6rcTqBYHwp0FAWKmSQEOFwTFWXJYj2R4LCKWcH5HxJrY5XH/XV9YEzWEd9e/ZRt
         G5dcbkuuMWGCgMuu21GM4dkBR/dhPmVrSdlREFigAUcH/QoJsGgFF0BBvBjll5pZaID3
         65Vwv35mg3aXIkmf5t6RvQdQI4/t33z7/BH03EeJKdyelsTu5bvOr2/VT8jrlPBGFPxN
         nE4TGwEfGSRYLzcMk0JjKF9R1wowW7coMZJ4JWGeX5V5JcY7fU2yiuDeOPE7imhCekE7
         2mpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nDe2lTFO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b79f4936304si5975166b.2.2025.12.04.17.09.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 17:09:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-42e2e5da5fcso1071602f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 17:09:09 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXgDKY487EnsHcvu/Qcd/PiHGP8qNbc3rAXHbz0jUAdFVWR6xY7GuDqyGPOjH53luouTcu00Ee6Ct8=@googlegroups.com
X-Gm-Gg: ASbGncsTJBqLGDODDSi4j4H8OUGk/jaRtiBQMN8ZWwPE8BVmw/5oFi39vUTRDHVrjk4
	6sIZyJZmUBi97ffI721NToNCsl2FnO8Dw/4Avb6rnZ3zyHvgudFxAgNUP4Mr9/ck5I8NnO/OQzd
	rT6P5kl/xGLmyqKkcWvp4F0K5jJEXJ7StArosJ9Jnctkg2jWNoUJJWGB0hOnL0/RlzY4XrQMoZ1
	hFnMdDS9QphbFFOLpmQDIhGtpZfcJVyBWCB6CEvi5cDg7WdkKwkpE9wOM78n+AMibzbNKJWDCFP
	Tz/vjj+oR6T4hmMn+SBL3VTvbWwzzK6/
X-Received: by 2002:a05:6000:250d:b0:42b:530c:d8b5 with SMTP id
 ffacd0b85a97d-42f79867232mr5216864f8f.58.1764896948983; Thu, 04 Dec 2025
 17:09:08 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764874575.git.m.wieczorretman@pm.me> <38dece0a4074c43e48150d1e242f8242c73bf1a5.1764874575.git.m.wieczorretman@pm.me>
In-Reply-To: <38dece0a4074c43e48150d1e242f8242c73bf1a5.1764874575.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Dec 2025 02:08:57 +0100
X-Gm-Features: AQt7F2rJmIzAQLLWNUCtlHH3vMgTJvmbF98DSGlcKvxxcaL8y5jTuVOv6OgUATo
Message-ID: <CA+fCnZdsdLYqRe3DQPv-ATAsXwKPMExfEyODt134het_9B01Zg@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] mm/kasan: Fix incorrect unpoisoning in vrealloc
 for KASAN
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Danilo Krummrich <dakr@kernel.org>, Kees Cook <kees@kernel.org>, jiayuan.chen@linux.dev, 
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nDe2lTFO;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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

On Thu, Dec 4, 2025 at 8:00=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Jiayuan Chen <jiayuan.chen@linux.dev>
>
> Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes two
> issues:
>
> 1. In vrealloc the KASAN_VMALLOC_VM_ALLOC flag is missing when
>    unpoisoning the extended region. This flag is required to correctly
>    associate the allocation with KASAN's vmalloc tracking.
>
>    Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explicitl=
y
>    sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with it=
.
>    vrealloc must behave consistently =E2=80=94 especially when reusing ex=
isting
>    vmalloc regions =E2=80=94 to ensure KASAN can track allocations correc=
tly.
>
> 2. When vrealloc reuses an existing vmalloc region (without allocating
>    new pages) KASAN generates a new tag, which breaks tag-based memory
>    access tracking.
>
> Introduce KASAN_VMALLOC_KEEP_TAG, a new KASAN flag that allows reusing
> the tag already attached to the pointer, ensuring consistent tag
> behavior during reallocation.
>
> Pass KASAN_VMALLOC_KEEP_TAG and KASAN_VMALLOC_VM_ALLOC to the
> kasan_unpoison_vmalloc inside vrealloc_node_align_noprof().
>
> [1]: https://syzkaller.appspot.com/bug?extid=3D997752115a851cb0cf36
>
> Fixes: a0309faf1cb0 ("mm: vmalloc: support more granular vrealloc() sizin=
g")
> Reported-by: syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/68e243a2.050a0220.1696c6.007d.GAE@goo=
gle.com/T/
> Signed-off-by: Jiayuan Chen <jiayuan.chen@linux.dev>
> Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  include/linux/kasan.h | 1 +
>  mm/kasan/hw_tags.c    | 2 +-
>  mm/kasan/shadow.c     | 4 +++-
>  mm/vmalloc.c          | 4 +++-
>  4 files changed, 8 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d12e1a5f5a9a..6d7972bb390c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -28,6 +28,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>  #define KASAN_VMALLOC_INIT             ((__force kasan_vmalloc_flags_t)0=
x01u)
>  #define KASAN_VMALLOC_VM_ALLOC         ((__force kasan_vmalloc_flags_t)0=
x02u)
>  #define KASAN_VMALLOC_PROT_NORMAL      ((__force kasan_vmalloc_flags_t)0=
x04u)
> +#define KASAN_VMALLOC_KEEP_TAG         ((__force kasan_vmalloc_flags_t)0=
x08u)
>
>  #define KASAN_VMALLOC_PAGE_RANGE 0x1 /* Apply exsiting page range */
>  #define KASAN_VMALLOC_TLB_FLUSH  0x2 /* TLB flush */
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 1c373cc4b3fa..cbef5e450954 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -361,7 +361,7 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>                 return (void *)start;
>         }
>
> -       tag =3D kasan_random_tag();
> +       tag =3D (flags & KASAN_VMALLOC_KEEP_TAG) ? get_tag(start) : kasan=
_random_tag();
>         start =3D set_tag(start, tag);
>
>         /* Unpoison and initialize memory up to size. */
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 5d2a876035d6..5e47ae7fdd59 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -648,7 +648,9 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>             !(flags & KASAN_VMALLOC_PROT_NORMAL))
>                 return (void *)start;
>
> -       start =3D set_tag(start, kasan_random_tag());
> +       if (unlikely(!(flags & KASAN_VMALLOC_KEEP_TAG)))
> +               start =3D set_tag(start, kasan_random_tag());
> +
>         kasan_unpoison(start, size, false);
>         return (void *)start;
>  }
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 798b2ed21e46..22a73a087135 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4176,7 +4176,9 @@ void *vrealloc_node_align_noprof(const void *p, siz=
e_t size, unsigned long align
>          */
>         if (size <=3D alloced_size) {
>                 kasan_unpoison_vmalloc(p + old_size, size - old_size,
> -                                      KASAN_VMALLOC_PROT_NORMAL);
> +                                      KASAN_VMALLOC_PROT_NORMAL |
> +                                      KASAN_VMALLOC_VM_ALLOC |
> +                                      KASAN_VMALLOC_KEEP_TAG);
>                 /*
>                  * No need to zero memory here, as unused memory will hav=
e
>                  * already been zeroed at initial allocation time or duri=
ng
> --
> 2.52.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdsdLYqRe3DQPv-ATAsXwKPMExfEyODt134het_9B01Zg%40mail.gmail.com.
