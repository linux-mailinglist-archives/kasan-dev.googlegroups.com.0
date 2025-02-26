Return-Path: <kasan-dev+bncBDW2JDUY5AORBOXE7S6QMGQEQB3EVVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 94273A4647D
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 16:24:43 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4393ed818ccsf50220295e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 07:24:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740583483; cv=pass;
        d=google.com; s=arc-20240605;
        b=L0aOE4HgCtqcl3WRyt1tG/qxGe/zwij6Cp6n4ex2Ajbs61yTXIrAJCf06RS5hmqoUT
         XoMXyaIyEwFHJ7iDZHn/KKwxDrEECVLcaoSe8j7ubZwk0zqAy5K/MUkPAfQI+cAjYh4D
         AB54QdKCXhJ47FIhGMU70d3pqcOly/cyPNrEUf8DfO6WSJf1Wu8iEUmM8swsS6xPnIbj
         m0YokCM6d+EO0dt1eynhPL2FAdnBLsYCriuWkXQL5igiqxc/wewRkEGOaUKuW9lMngx+
         1wEl/uMF5UxXpLy02KtWtyHGGWkSss+W+TG1Gjc2nCCa1HlbM4h7MwCsEI7WUJ5Z0FOv
         ENaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FMqyMO5RBMU1eTzVAlMDQMtS8xu6QrcXR8BZx29ZXxc=;
        fh=2d43jWm9Q4bPEMMTqjtuOuIrUGeKhL4v/n7Dp90BLrU=;
        b=JcsrIc9T43WKZQ5GaqeUPfJVo9pWvRzwH2IKV36sw0ywhcDw+koNW6MJdJNe6qtBnC
         ZrBPnWYwjCPi6VagRHH3gBjvtIWlqCnL4bgtnpYiB9HCY2dwkgpL7Uiy6cBb9YzcXmWf
         bSzWQpNgYtRVoPzU7Ei3DRH/ZzqzW5oquzUfaDrzhwV1Grf3linrth73eSGaFaZZjfyH
         CqC59/lDdtxyeWLuVXNlw2oMkukHu1mDn9K9ZqXQJqIrrtB/XEbZR0KsoK7+Kj4wSjia
         DWU6jH0gOsOxMBLydhnd77A6ojaryvHEhQDvyvjlk3zvJGGtBtTTR/yD0ils9jH0gxGF
         6Ajg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l5O10sJK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740583483; x=1741188283; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FMqyMO5RBMU1eTzVAlMDQMtS8xu6QrcXR8BZx29ZXxc=;
        b=d9quKB41mNuGev+MpVQDWHsV13f3Noah2UFYZd/EzjGFHcldiTzQTw/04hFgG5AgDi
         TeeGkuKxCXWcK+CIBZCQ0ff0GWUeougvSnjWfBNCFce58ai7pLVFdIXrIZDokq9K4qAA
         yMaOb0OGPtn6B9g8b0vsgQPVBM+/bcEISbnP6aLTZ1LC6DbwhTAPKpy3Rznd21xVcQDk
         SjGifv7JIdV2JlEGDSxXFd6nXxKUJ3JWbX+BGfafaJYUx1Np8VUFJdIWo+nsKBSTvoeE
         /Slk5RJBI5RJEGW6+WCY8yVJKvHbhQH6N1b9GRm69YUzT2sYUv4wu3Ec2D48ACDFhZWg
         IRgQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740583483; x=1741188283; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FMqyMO5RBMU1eTzVAlMDQMtS8xu6QrcXR8BZx29ZXxc=;
        b=O4jgcFfORvnxuQ3+XXVvlRvx8bVivar1mG4wkHrY7LAzrr9TeOH5hwZCb6FvuoBXc7
         T4ruZLCFLzBPeFOxmbTTAhY5AwLYV0twFeUx22bO94+p5kODVTsfXCz5FjQVg7TqZFvn
         FI+L44p1rlUJJYS4Le8OoDoHLrIw4CArcj11iBafdjoIs6zekrugoWLLpLbwLRQ8ucO0
         KmumaR6NaCUOuORx79xKvjW3sTVT6jGke+oJCPXoeJarf9vCrFEKE3KTVEmrjvuUKGaD
         5FGk4I/ExtCU/vdoQ/0ANBKL9+KBiYOikTtnLYit55tgGWLWqZoAsjcF7XiXD4ueNNQZ
         IHCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740583483; x=1741188283;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FMqyMO5RBMU1eTzVAlMDQMtS8xu6QrcXR8BZx29ZXxc=;
        b=v8Z5wYshJuSxr9cXv02L1jPxB8iU+HWB103dy+D135uvbo0SqRQHRiHZA8smyQAeKE
         /FYx9Hk5u95B+MYFDjG/VJh6A19vvYqGJ8k3xl70Y433R87Z8VPjYh3mJvAhGaGlALgI
         uuCCt5NZgwtLIj/FucanjVwoTGro4AyUF+If4BoEOAerAoojy5/t3ZHh15lJfEnFUYgo
         NYbS4JJMFFYWtlr+SA8SB9jWU9d3lVHXHn4V2SzAIT71lZRv3kdEUAVPLmZF8+YSpS5x
         aLNii9T1ZXLMyPK/KB598F18xyHaqZRmP1OT1R+xWTnSaTc3JqVo4lh0R5KXIZ3tJuYG
         0ORA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV09ewzcUHOlvjbEcGiBYixNcmSQXhfqTwVaEUX0vVUl7BWnb9ffm1IwUHBqa1oXDcuLHM0fA==@lfdr.de
X-Gm-Message-State: AOJu0YxdquOfdvSw/mM5F/LynIaPHr4zmH5zuhb7ppOFPZE6TlyOEt8W
	DPRehy5eAgHZ+fve5wEbeBwofwJJxp8ZF71AGorFmS5iBXy2quze
X-Google-Smtp-Source: AGHT+IFJHuAj13whryEevG7Zf4LOQsZyXh78g1zEErV01c0JMlTLvqaP1YN3MPkKG3Dy2C7ggAoFGw==
X-Received: by 2002:a05:600c:3492:b0:439:8ada:e3b0 with SMTP id 5b1f17b1804b1-43ab901d6a7mr31623805e9.19.1740583482502;
        Wed, 26 Feb 2025 07:24:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGsf7g/2D5FZMFGbb3ve6mT7pj/G8lpT3eOegeTnIgirw==
Received: by 2002:a05:600c:55ca:b0:439:92e5:41c6 with SMTP id
 5b1f17b1804b1-43ab976ec61ls4281755e9.1.-pod-prod-07-eu; Wed, 26 Feb 2025
 07:24:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnccyBRwMmM3CaTaj9CgPdn71/CipxD/h2P5bc77IoQOcg7gxWKevNh8ErK7Gs5w4BpS73IZWhCzE=@googlegroups.com
X-Received: by 2002:a05:600c:3588:b0:439:6304:e28a with SMTP id 5b1f17b1804b1-43ab8f6fe56mr36247115e9.0.1740583480111;
        Wed, 26 Feb 2025 07:24:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740583480; cv=none;
        d=google.com; s=arc-20240605;
        b=YN6QHeO7rrUbbN6lDnJjhYnxptjgrK7mGm41XYxI171SK6FBSM0R8LCsy0jNSKlb+V
         gvqXTjo3nzDva0B+zCsgT/Cxm4BBF/q2njoKc8nSQ7K7epiZzbh03JDm44V2KUG9oTZ8
         Pf+CzlKFaELsq2L7x79+BA20WHABSA1LylH2x8Rw9hsp4uBk/1yzFpCHX9ZzP8oioiqi
         jdvY3Teg01IkvkVQ21MqQHLmh6HuHXVTKPhRmZlRJr6Vov5yb64t8zYqj8KvPWLrpWn+
         XZXiCShB6wZAGaCkwVTT3ziKMvwpX/4BK5KPPIR2D6o7YZ4HZPqKGHFlCzneBK71ZQRU
         TLkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hsuCvPIYOZxMSn5nKFFEtm5mHOuqFxBxK/9CbbLtirI=;
        fh=hiSf1pkgH8wcaMH539sQtqUO8zPwKtGUnzLWEc2DfYE=;
        b=P+88NMdXxOM130CKzmQE9vH0g2ds+s/leilpt1FV4Zr5tIYUSj7zl81YwunEjxQeKY
         HowyrjRTSLgy7MLpeIxzdFiy8b4y9Cx24f8fqx2aoQvboyxHMFdLeZD1zolDmgMFjoXJ
         dXvxP6GSG1zVHy6qHlrmamL5W4NK3egBNMeK3GaO5AzrZ3y3sk7lxnJtR36rTkNPx+Nm
         sgS9CkGOHAiV0vWwN5Y2JKM93prACoTVOLjo/a8NbGE5Baj+mEgWN4JdAccsxFjsXoof
         yqM3rER7/fTKzcsq+whSS0RU0soE/H372D0ULq6COLUtA39AuccVptqm/BHRn4PYe5gF
         2J/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=l5O10sJK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab2c4e833si3056745e9.0.2025.02.26.07.24.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2025 07:24:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-4399d14334aso61126415e9.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2025 07:24:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW59CQFie4XOlcNy2cN9gT49ID237ESmGIU5ljds/FkdnLKIA1VTbcSn5K+JE0pErVbcLokMYQ2pZ4=@googlegroups.com
X-Gm-Gg: ASbGncsg6aFSQMayW7mniPeYPb5J8oFSdimg9pxGTTaC6NUaX6tH6gw5czuOIaJBoHf
	KuA5XTd4fj8FPA6C0msDTXpOXWBmspTrNXx9TeBQI1QH5b175rRvc3vx+bE0LSS64szrkF8QHtP
	vcn1tz1U24qg==
X-Received: by 2002:a05:600c:3548:b0:439:8a44:1e68 with SMTP id
 5b1f17b1804b1-43ab9046de3mr32060425e9.28.1740583479193; Wed, 26 Feb 2025
 07:24:39 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
 <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
 <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com> <ffr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6@n4kdu7nxoaw4>
In-Reply-To: <ffr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6@n4kdu7nxoaw4>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 26 Feb 2025 16:24:28 +0100
X-Gm-Features: AQ5f1Jpqwg1oQbqitjHoWgohREHEbfWOkzeGk2nGzOh9RmhEEI44EKvWgfDP0bM
Message-ID: <CA+fCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Florian Mayer <fmayer@google.com>, 
	Vitaly Buka <vitalybuka@google.com>
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
 header.i=@gmail.com header.s=20230601 header.b=l5O10sJK;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
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

On Wed, Feb 26, 2025 at 12:53=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> After adding
>         kasan_params +=3D hwasan-instrument-with-calls=3D0
> to Makefile.kasan just under
>         kasan_params +=3D hwasan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)
> inline works properly in x86. I looked into assembly and before there wer=
e just
> calls to __hwasan_load/store. After adding the the
> hwasan-instrument-with-calls=3D0 I can see no calls and the KASAN offset =
is now
> inlined, plus all functions that were previously instrumented now have th=
e
> kasan_check_range inlined in them.
>
> My LLVM investigation lead me to
>         bool shouldInstrumentWithCalls(const Triple &TargetTriple) {
>           return optOr(ClInstrumentWithCalls, TargetTriple.getArch() =3D=
=3D Triple::x86_64);
>         }
> which I assume defaults to "1" on x86? So even with inline mode it doesn'=
t care
> and still does an outline version.

Ah, indeed. Weird discrepancy between x86 and arm.

Florian, Vitaly, do you recall why this was implemented like this?

To account for this, let's then set hwasan-instrument-with-calls=3D0
when CONFIG_KASAN_INLINE is enabled. And also please add a comment
explaining why this is done.

[...]

> >What do you mean by "The alignment doesn't fit the shadow memory size"?
>
> Maybe that's the wrong way to put it. I meant that KASAN_SHADOW_END and
> KASAN_SHADOW_END aren't aligned to the size of shadow memory.

I see. And the negative side-effect of this would be that we'll need
extra page table entries to describe the shadow region?

[...]

> I think this was a false alarm, sorry. I asked Kirill about turning
> pgtable_l5_enabled() into a runtime_const value but it turns out it's alr=
eady
> patched by alternative code during boot. I just saw a bunch more stuff th=
ere
> because I was looking at the assembly output and the code isn't patched t=
here
> yet.

Great!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw%40mail.gmail.com.
