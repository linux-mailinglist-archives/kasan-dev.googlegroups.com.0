Return-Path: <kasan-dev+bncBDW2JDUY5AORBXVUWKWAMGQEQ6OJARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BC13281F23E
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 22:42:55 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-50c21a1733esf4271497e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Dec 2023 13:42:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703713375; cv=pass;
        d=google.com; s=arc-20160816;
        b=NFGPJ3H2Zjk6VZ8covRVyCRVYMTsk1FXgNbHJgQyh9OZ+GmGUCJ1NDgn/UxD3ar/kI
         TVCTF7dZOLPzY+6jZttT1KuYGb+4YnrTAfMfhvojoRBYinLExlU1GKkAzqRr+jCFTG4o
         1O4iU0p8MfgjoTU+4jRMwuLgfOQNNazhKhwA7aam6YPaov/G8AKFRC/bbNOLLeOTYXyY
         OXS5njXVo/BDl9vA+7SdFpoq+rNs44ePl1UnK+FWwlrRs/GtGdJSIbtR6GJBGzDvpILh
         ejHXaB85TfZ9QAdn2COsZSWsMuUo/N7jSaegrqFBYPfL9klmbR1qqkNxKUSvsRs6pylA
         tUMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=escYZ8Zca8Cdgv/kWStPnBuUbZaiiVi65mHuwl6XbdU=;
        fh=4SOFOWIUjDZKXtxqHHuIsmiwkoIxFXDTWSZTQ6TNHNQ=;
        b=hH5ppFWF6o/p4ZQRvnVUAdk6q5N1J+JnCL1doD9ZdF+OVzmYMPkRV9vsLbyw2exTfj
         PWv21faG8MkGk2Cr/qhlaaeUWsCOIfhHMGlsnxGIumzLj43m6ftjzriSoUKbFmvB9yGP
         6rgFBn8o3E/0xgntk5H8OTXWhMXfZ885ZK3NdU2TOd9rWO29HkwmL4HlonOtcZwVugxj
         t5XebbIgkhJg5cM9Q2HxqZ8e57GgfWBUxI40NSeI6M+fQeVXYEPFr8e8f0dSUYDpVSDz
         khCiAZ/sX+JZYNs0UzeF30IFXS8oU+l1znU6NYScf+VDrnRV5i1e/Smw1FtMazTqiyUN
         vMzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YptnsesS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703713375; x=1704318175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=escYZ8Zca8Cdgv/kWStPnBuUbZaiiVi65mHuwl6XbdU=;
        b=si5QEFPQnnzcHUC7bY0AhusLX3qX4vcNS1FYx7rtibXfHM8uq3YvdQJfK9rw2g96ye
         uDLaY6It6TMHKm+7l2lJ6KfvdnaG3hS492cDQN0hPXOMDLUesYRjZ/4xio+hT6B8I3ml
         gk18ylqD1cluYZmAW9gNKz7p9jYkfUEgxhGxuF/Z7toSxiKZ5Z1StU3y/0UTWCxgVG3K
         sPn5V7MB9gTp7cWPaVLReL9ozUze6MtQNOtIlH65TeXx/cY3hL2depoe8ClrV6eAY/H9
         6i48C0Cl0XQsnc4R5YGsXA0W8HlVZjjWalmXcPXzOlkPNNWCy2XXdQZkBmV+MHYKDfTp
         Yy0w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703713375; x=1704318175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=escYZ8Zca8Cdgv/kWStPnBuUbZaiiVi65mHuwl6XbdU=;
        b=TP2Q7e8Z4qf9yGp1dpJAYvWA6Ul2xYwXFRgWVE6mmkX6wyi7WJgbgMn/dm+bNAZlU9
         z3jzWd+r5dwdfnFBT8D5eqIf/EA9PlNN8eYYq1C7m8blt1ccPMnIVN+13d/9NUFOWuqg
         t1odIoKXQk+dPCaDLlupAIcZ/NOf+KbYrxf1AtHhC4SUeU9OvDiumCt1+Bzg2p9QzPl0
         fE7rbfDqAvqxSl6vpPC+K8XzYMCDBcf3drNb+cFiMVxh3EPB3WciI64Pra+XXfBdwEx5
         9Oe7ChFJqz0ajaA7Swk5UPM14SD33XAkMJ8JSnaZysbC1txitho1mQvRkfbu9DMpihaU
         TteA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703713375; x=1704318175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=escYZ8Zca8Cdgv/kWStPnBuUbZaiiVi65mHuwl6XbdU=;
        b=FT2Ebl2jC/AOqTSQpVLUV/z2NvNdF+iqLZtHbqj5f6XParPENhtR5nljBtAA/GvRo6
         F5gp54I3kLKWDF938z77ktWW4oETIzLTT5NJTm13FVVA6fT4bNC0q4M5fTjkEAJIUyXZ
         ovbuB+Qhbm0UMKfRBXkU4VByYsF8L536psKSHzfOhko+dukBKiD6Pcl6F1i8c+h8ZLRM
         x5U8ENIZciZaiPdSBamYPymJmvogMQgLA9g4WljpNMLpGxO9KIcLRpXGp0LcGNFlu/9p
         z1K0oOOziK/rt/o54c37KD2AF6IZwvied1fIytSl2TY8QpNz6QX7xdl6zSGqB5BH1BtW
         RQpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzOQjovjdt4d+v5N0DUgX5JmkGtzL0RPAprwFxEJB5q6hrWobVZ
	5J1+w6SL8aVpIUKObeQwjak=
X-Google-Smtp-Source: AGHT+IErMWfn0msAZ5uGubqRlq4/p60UlDdYRNahJ96PFDEWG9Z7EMyiX19wm29KoAyiEEbH2a7lhA==
X-Received: by 2002:a05:6512:3b6:b0:50e:70b4:fab3 with SMTP id v22-20020a05651203b600b0050e70b4fab3mr2872352lfp.63.1703713374383;
        Wed, 27 Dec 2023 13:42:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e27:b0:50e:7222:eee2 with SMTP id
 i39-20020a0565123e2700b0050e7222eee2ls358594lfv.0.-pod-prod-04-eu; Wed, 27
 Dec 2023 13:42:52 -0800 (PST)
X-Received: by 2002:a05:6512:3b28:b0:50e:7f8a:5f77 with SMTP id f40-20020a0565123b2800b0050e7f8a5f77mr2005218lfv.127.1703713372413;
        Wed, 27 Dec 2023 13:42:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703713372; cv=none;
        d=google.com; s=arc-20160816;
        b=amXMba5Ph6MwFzh2UNBb/yA8N32iGN4Nkw3JM5nKfYz04ZCNu1RpQVOmavWz38mbjL
         rNhDbUAaGglBjLEV55byQ80LDhYH8gkyxE/Al957wziK1j8HBPcDhNwGA0L2rQcjPJYd
         hMmTNl2CcVHOj3vvJE5xG+X6Gr3U4HTbL17shQABruFDFMkSfPYdWEe1Am0nRLPpOGvb
         5hIHApk2m2J0CGXhtO/6iYbqus15DUiW5tqXdBZS6PpVQYFLddlt/6pxIm2CYi8IZDuY
         B4rMm08OGgY8wzZiOg5H63px6l+L4ugqv0CicuvmuglSGLQDy27+NfZgiFG77pQaBUWh
         EAFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hDLD4+/i2vMq1fQYbzWj7QeJ4PZ6TaAuPhlpaYobBH0=;
        fh=4SOFOWIUjDZKXtxqHHuIsmiwkoIxFXDTWSZTQ6TNHNQ=;
        b=ISPCZjGZC07GEV09XdgEMeHc7Dw3XWzJYTlVgBVRdN8flGznqNHTsL8UJRXFvzE0rG
         ArAzi9D0DobL0Ho+ocE0cKhEKJkUEzImj8ZI4/0goBHC1zavk5EkVlWxnfgVH+q2kUWc
         gSC0TGnFyiEaprpKIZWe8cbuV5ehqZu/8Q6XesLgWvsNwjz8hTXDzXrFe31xLKS7JmSv
         Z+/ybhBMKccXMZOnOeryDRxE/7d9xulYGNmFAFOZ2QCD+96HLQkRilHAxi0yWaVMrp7a
         C7BgdT3UdF0dHwvXffAfq1dgDgx8EGCn38SXyLuiHCj/DKAAf1caIPK/GPFExdWDB2RQ
         EzGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YptnsesS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id t3-20020a195f03000000b0050e6b19b855si610579lfb.11.2023.12.27.13.42.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Dec 2023 13:42:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3368abe1093so4792782f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 27 Dec 2023 13:42:52 -0800 (PST)
X-Received: by 2002:a5d:598c:0:b0:336:e8da:e17f with SMTP id
 n12-20020a5d598c000000b00336e8dae17fmr1859975wri.113.1703713371579; Wed, 27
 Dec 2023 13:42:51 -0800 (PST)
MIME-Version: 1.0
References: <20231226225121.235865-1-andrey.konovalov@linux.dev>
 <202312280213.6j147JJb-lkp@intel.com> <20231227132311.557c302e92bdc9ffb88b42d5@linux-foundation.org>
In-Reply-To: <20231227132311.557c302e92bdc9ffb88b42d5@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 27 Dec 2023 22:42:40 +0100
Message-ID: <CA+fCnZfZMhkqOvsvavJ-YTddY4kniP+sWFZRYy+nd3+8_C9hPA@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: stop leaking stack trace handles
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kernel test robot <lkp@intel.com>, andrey.konovalov@linux.dev, 
	Marco Elver <elver@google.com>, oe-kbuild-all@lists.linux.dev, 
	Linux Memory Management List <linux-mm@kvack.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YptnsesS;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Dec 27, 2023 at 10:23=E2=80=AFPM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> Thanks, I added this fix:
>
> --- a/mm/kasan/generic.c~kasan-stop-leaking-stack-trace-handles-fix
> +++ a/mm/kasan/generic.c
> @@ -503,7 +503,7 @@ void kasan_init_object_meta(struct kmem_
>          */
>  }
>
> -void release_alloc_meta(struct kasan_alloc_meta *meta)
> +static void release_alloc_meta(struct kasan_alloc_meta *meta)
>  {
>         /* Evict the stack traces from stack depot. */
>         stack_depot_put(meta->alloc_track.stack);
> @@ -514,7 +514,7 @@ void release_alloc_meta(struct kasan_all
>         __memset(meta, 0, sizeof(*meta));
>  }
>
> -void release_free_meta(const void *object, struct kasan_free_meta *meta)
> +static void release_free_meta(const void *object, struct kasan_free_meta=
 *meta)
>  {
>         /* Check if free meta is valid. */
>         if (*(u8 *)kasan_mem_to_shadow(object) !=3D KASAN_SLAB_FREE_META)
> _
>

Could you mark them as "static inline" even?

I'll fix this if I end up sending v2.

Thank you, Andrew!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfZMhkqOvsvavJ-YTddY4kniP%2BsWFZRYy%2Bnd3%2B8_C9hPA%40mai=
l.gmail.com.
