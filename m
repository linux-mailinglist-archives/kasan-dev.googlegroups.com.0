Return-Path: <kasan-dev+bncBDW2JDUY5AORBV4QYC3QMGQEHZXX2ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B93D97E179
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 14:06:48 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-374b981dd62sf1516649f8f.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 05:06:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727006808; cv=pass;
        d=google.com; s=arc-20240605;
        b=VSeQ5pHjzpQ8JfcUsbOPBxQWsU95I1m4h7Rc+OWaYag9WlSeep4GZ0YZ73GAZrOXpp
         m8/1s1sncpimqM1GMJkUttmerffQTVL5GdsSPiX+08j8L6aLyQ9zf67uCgKrXsgh4hTp
         QQ3ddMqByNiaiyR+Eg8YNbkJ2Ld/o33Wrs6/jG3uC6qlXTb7JRUR6V/a3Zb9h21hhoMt
         G6E8U6mwYMmlN0nXljjoh69BcnBdfvwxX1cukvet/5B7mINdDi6nFQMCYxNe/5lqNA50
         ux0Ho1Pe0046vTmcUPITh64gV4084rU1HbN8AgpLndLYsUeKs+L++BHtJM6sqiuqejG6
         lYfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dwg0oYactmuAXhLn9IpJzPVOXuQcRpm1qrHW521QINw=;
        fh=qyl6YbgI1jshrijNklLo/T1Qu01MfuYMVayIPCAO7CI=;
        b=C5KVavi5GJBKFttmbV7dgLqR1iKImbfy/QXtaQq54jGA9c3/NUW91+76B9oqQvno/u
         /WrswNKphHBJAYEDQd8ok4BV1RY6nE/KXWsMgTipcMPd06zBV/8Cd8izLdG2l9Cf2bdX
         xW7gewWc5sIR5seiBRnmi38VogMUMyIY9deJwb4USomq0hBADZBL0v6CarsWKbNkXRZC
         oOgTteoTBlXbOk+ZCBcAI4VBMH5YXZVKWKWVrmw0ZZv6O8n0Q2DpG90Sx2IL9oso8aZT
         h3svDZt864NVtZXhtwP+qp3Jg1APZfeHUOWdDR00b4wZufe7VJk7APPC83bRNmlnkwzR
         1FDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XYKaLXGb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727006808; x=1727611608; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dwg0oYactmuAXhLn9IpJzPVOXuQcRpm1qrHW521QINw=;
        b=LpIIBFZeiGrFXx5ujCjIeIGqnKCHaDb3J1ofr3S7kFoS0amLHiKAcFXP7dvCrIIHGC
         S21OhmYCcOA53yVkhRaqL2K9ySIJVH/mDHoyPCaSKAcKcLM9u/+TxkoST8BYUYYvhARh
         BG1KDWFphGVFv2YxrCdUdOxczEoa0jFtLPj+nO4bdrlLSBFsKWOE+WRRUSIYfPiOnY5p
         EUSwERjT6QlLOsTujTxXdKVCxCkLhPWAsboDo3u6O8nh1lkAUZd7Kshr/bvJsuWTMDTR
         Z/9NOQ7h136SzqtHMe58Si08X75U0uR7fWMfXGkbjqNRMWRGkZFlbbWkayXDhnoL2fyl
         NwGg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727006808; x=1727611608; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dwg0oYactmuAXhLn9IpJzPVOXuQcRpm1qrHW521QINw=;
        b=EAp0yj7IaixodCuyjYKsR40Wxw0FVLc8ThlRhoxx6+gtWng+AtS6M22R+8OknuYwk7
         iyllbuHvwTpLoCIfx7xBFNFD8vTWve8tc1DEsFP1Rs/A09eq3u4PjG9NNySkAcAxCDY+
         z3x9aVEHezSOOZo2A8KDA7dIbDlGZcbF2M6yGUN7HpISZaT6PpIoWJlhxn4fsMSjI2L6
         AyL8e0v4YpoRETWimeVYDS7ySYIUm1rvyMiFU5nv5Sh75YOXyf7UEoBBPCCULxytymVw
         ek80e6ddPOjzhlJcapCFKK5LRpLF8vzmqNugTSZyDtdMTUmHpjhGCF2on+K7jZIdK88F
         LOyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727006808; x=1727611608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dwg0oYactmuAXhLn9IpJzPVOXuQcRpm1qrHW521QINw=;
        b=q2IFix3rXhZfQs8jPC5gztiXEipYu0UUzlv5MaoQt31A0Xa144DFGED+YXFqTICIg7
         Hf03mrTFSn7+MHor1IH6Q4+ivNykG9oeplwAkE78QRTbXrtu0eEH8QW1CXXaPO0c9Zi5
         O1kuJGK2WF7y8FfD0iC7OQ4gSPiz9Ny2ETULHrOIWigB+cw9qzx25/bgMv5BYswIaWSY
         TG3J//3+3gLKOv0GVcIhnf04oggwhy7F237c5IJHpzVYVJw4ojiGbkvcQbomWcZ3+BG7
         d6OEjeAMbvssjnQK8i6wXeyGGJbnxgY1Fxpd/p91CiXuVzF0JylgoX6s3vpSKOLqthUX
         KCIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuqWW/5Qw7rQx8F6zIe5+fHMfoz9DZrcY9a8VDsZg7T4wOz65dEshGLvHoHnQ+cIgvkad+bQ==@lfdr.de
X-Gm-Message-State: AOJu0YyzppxFCj3GZnXMGo3IGvjOMZmMtLpfLvTZAgSirYi4uzMUxmDY
	2uJ3Z+Ja56CXgOB/EtteKjWn91/VUgiIkUQUNtdQqPgxAdM38iWE
X-Google-Smtp-Source: AGHT+IHXskgDMJuubUQ8FZ+dJLLe2lOBI4851Hhl4VuXE2coHghjHs273I0uC7flHH9RNhf4+i5osw==
X-Received: by 2002:adf:979b:0:b0:371:8750:419e with SMTP id ffacd0b85a97d-37a4235a33dmr4890558f8f.47.1727006807364;
        Sun, 22 Sep 2024 05:06:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4dc9:0:b0:368:31b2:9e93 with SMTP id ffacd0b85a97d-379b7f59cc9ls1097891f8f.1.-pod-prod-02-eu;
 Sun, 22 Sep 2024 05:06:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLDJ0MIbDIynp5VnAuVEE7y88gtU9Ofr/AAtHbOAyaXK2sv9uFCkx24tx07u0ggHcyKAYdJnX57HA=@googlegroups.com
X-Received: by 2002:a05:6000:1b8a:b0:371:a8a3:f9a1 with SMTP id ffacd0b85a97d-37a42252ce9mr4216116f8f.11.1727006805503;
        Sun, 22 Sep 2024 05:06:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727006805; cv=none;
        d=google.com; s=arc-20240605;
        b=ZkYW4Nz7bdO8qDldo9UuUCiGE0W4dUDkBMAWPpWCUU6e5BHhSJPBlNQo7/K2oL30jc
         ZKp9a9cQ2m4nQvCy+PZu7axLYeGZOTBRsjiPnkv8/tKDvRtTYta/eXB65Uby4REl4Ac8
         O8I3QxTlW6YaW9FYSJiIC2LAd6S4TF0MAeX+d6eNYWjTFVqUlL5jNeeLYDSbcvi9TX7I
         h3rRwYF7sdQpkLe71MYtu4MxUd/OdQ2j123NloZ10ATOF/p4P+qlk4zsFwwTjZKpcgOL
         tWLXCgCIUiRwJE6sFlT7iLZgzezmNhzzp3oiK1/+tMuzRIDnHezG/gQd6Y34I9wi2OVh
         Yy1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PiZOe2lz0efuBE5xsl2if9Xg0X7UVZYSnN/VuYjkL3s=;
        fh=bccSYMXuuKARwL+gQGDfpodidGnPrNe84vpJWFPVqBA=;
        b=PcgTImrBMAg4t4AZhKu/nSZMeFXwHEyQHBWjz0mdtELZksfZCCo5Ijj/RSrmsroCCU
         fxuEIiJiM9ZaDqB029HIpvc1M9v011E0xFxtr2msics8yWXTyyqVNiki0bZUa5kGEjab
         /oyd6+tXSkoaGSGXAqUVj4COQVYkGThryRFh+34reeElwdcg25CNuYTeYCGo6/nxfMTi
         VZV7GLc6O8pgCW7xE1S5dIF9CweUdVSBcjfLl+7mYO5ylajfqeqD3AcZTwfQGs97bWAy
         UqQYCEus17yKCjn1lGlqo+EViwM62E24X+qUcV5C1khPfYg93OhM/ZZ6CSB9gPRJlE93
         LO6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XYKaLXGb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-378e7802392si395880f8f.4.2024.09.22.05.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2024 05:06:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-42cb1e623d1so32679535e9.0
        for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 05:06:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUiVJCU15gYQSHNB91AdNlCa1mUKy25HbGnst+v4nltXyy7q0JZce19FFdTa8Bu7bfbhc5RGEnESqU=@googlegroups.com
X-Received: by 2002:a05:600c:4f8f:b0:42c:a574:6360 with SMTP id
 5b1f17b1804b1-42e7adc0dc7mr60810165e9.29.1727006804828; Sun, 22 Sep 2024
 05:06:44 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZeiVRiO76h+RR+uKkWNNGGNsVt_yRGGod+fmC8O519T+g@mail.gmail.com>
 <20240921071005.909660-1-snovitoll@gmail.com>
In-Reply-To: <20240921071005.909660-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 Sep 2024 14:06:34 +0200
Message-ID: <CA+fCnZfXp3-NOq-LB13q8V6tv=H976AeNQXU8p-VGK-m9Qdh1g@mail.gmail.com>
Subject: Re: [PATCH v4] mm: x86: instrument __get/__put_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, glider@google.com
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	hpa@zytor.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, mingo@redhat.com, ryabinin.a.a@gmail.com, 
	tglx@linutronix.de, vincenzo.frascino@arm.com, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XYKaLXGb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
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

On Sat, Sep 21, 2024 at 9:09=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
> strncpy_from_kernel_nofault() where __put_kernel_nofault,
> __get_kernel_nofault macros are used.
>
> __get_kernel_nofault needs instrument_memcpy_before() which handles
> KASAN, KCSAN checks for src, dst address, whereas for __put_kernel_nofaul=
t
> macro, instrument_write() check should be enough as it's validated via
> kmsan_copy_to_user() in instrument_put_user().
>
> __get_user_size was appended with instrument_get_user() for KMSAN check i=
n
> commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
> put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.
>
> copy_from_to_kernel_nofault_oob() kunit test triggers 4 KASAN OOB
> bug reports as expected, one for each copy_from/to_kernel_nofault call.
>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> v3: changed kunit test from UAF to OOB case and git commit message.
> v4: updated a grammar in git commit message.
> ---
>  arch/x86/include/asm/uaccess.h |  4 ++++
>  mm/kasan/kasan_test.c          | 21 +++++++++++++++++++++
>  2 files changed, 25 insertions(+)
>
> diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uacces=
s.h
> index 3a7755c1a441..87fb59071e8c 100644
> --- a/arch/x86/include/asm/uaccess.h
> +++ b/arch/x86/include/asm/uaccess.h
> @@ -353,6 +353,7 @@ do {                                                 =
                       \
>         default:                                                        \
>                 (x) =3D __get_user_bad();                                =
 \
>         }                                                               \
> +       instrument_get_user(x);                                         \
>  } while (0)

instrument_get_user is KMSAN-related, so I don't think this change
belongs as a part of this patch.

Perhaps Alexander can comment on whether we need to add
instrument_get_user here for KMSAN.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfXp3-NOq-LB13q8V6tv%3DH976AeNQXU8p-VGK-m9Qdh1g%40mail.gm=
ail.com.
