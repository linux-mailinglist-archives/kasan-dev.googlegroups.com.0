Return-Path: <kasan-dev+bncBDW2JDUY5AORBPWZ6HCQMGQEA7IQVQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 271BAB47570
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:17:53 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-336e2f372c1sf14788111fa.3
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:17:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179072; cv=pass;
        d=google.com; s=arc-20240605;
        b=jaKUNzLOvzLtWUpkEzsdUxdSx7XHaDz86dQkWEaigptl1r+8UqExy/cAUMHlh5h80v
         PFQMT9bGKmJKHbZcU4wq+liy5Jxs4UU95xihxIh4e4/JW/2KN6+iHRGoRQNHJXq2f074
         5qvqcQ8yvFMqwxaNXQof5RXEpcUKY9Si6RL0DOhg6IH8gtElqC5MKADkFlFLoAGU2ueM
         T6Dpftct15EDwpiMUcdK+fIwXgWqaFU6hyUS60tEr0pSr6v8J2QsiOM8AAfNcIsSSU/s
         aLZHum3RiO9i2SCgpI6RmetteffoJmxThJyfyuEF8H8EY5gH5kNrtDbWoiS1fXmRVsJc
         qblQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3XiBC3YnITjDEMymV+sH2MSwXrS5XAKoG7T+fRynC3I=;
        fh=oOeqPM/4WALVdWpiilX2TqhWQmNy2TLeYLSJSNl1kuE=;
        b=Jl9X+S8nvfINh7yRPyy0jLPm/KiPzi4NJ85l176f6kJ37bpWbTpBjfpOZL0Hm8yFum
         0ZLoBlte7c8D+LpOSrjkqGsl01MFaf8hABfXmrPf86Z5ek7LBDmntED49VeUQko+bFMY
         Q2M3zy/rwjv/hHoRrpCYPWGcNd6U3Njfbr1JL1/OmY2I1YoemdyXDwr1r9BSZvpxXO96
         3dffIfWyU0W+wHMrYZ1BkFGjhHQX56WbsbL5LgwsWKF1TC/OfMqwhyxMAU5/8c82scSs
         68yr1BxgLg6iuhIX/S6AqhqEphM2f8qdMCqIHaWarzCuMXaKRlPivyO4PpW4FBLy7bpA
         mWlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hT6ugBLt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179072; x=1757783872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3XiBC3YnITjDEMymV+sH2MSwXrS5XAKoG7T+fRynC3I=;
        b=V/lyLtsSPcejqvUg62eYP+yenUmsG+SfkqTDyJ2fQ6zvP/IIVVBxu0z1miOsPAz89K
         6Dl4uR8IuU6loDd7AtLqZiMh41mcDx88VJgLoZPm7EGJVdiYTDHm3DYDPBNdDXCGS30z
         qgivywJCZhR5ImMytXwkne1zHhZn9McZZKVFpPuIHuxjO7V+c5aBo175dhYkP1mfFM87
         kg+PNe1SAB2z9ZNQyPm+NNMK85c8qIvFgS1NS58mb5QsT5v+KKQB43CjvQZKmhpqJnip
         ETt56lHuzTjC94l6KWiwy+JGFU9JyRULP45issdQmW2VpBqVC92AJZC91xvXZ4ABNUCR
         sUWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179072; x=1757783872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3XiBC3YnITjDEMymV+sH2MSwXrS5XAKoG7T+fRynC3I=;
        b=ApQsda+4YBI5J0JMwaCiWHgmQFDtnM9LQEqAEXT2l22tWyn9jywbr78dLxBsFPbf6S
         nggkw1za9LFr2q10YfU62lTiBu/TSQ3pE4Yum+sR7Be1gnS+KzeHCOgs7GPkkcL22rg7
         T0wdgfhaGxan8nR8QT3kfUc5tHCyw7Y2rXChZCPDP08IeLWybHV8THUCfkaxjVPDQJXB
         BtyMNCuwfj4MWHDpwni87OGblYYp0FQFeRj3MfR7m0BmVIos5qOWpvUTAd2pV82xFzU4
         QFcTpYs9vIXqSpcXOkwYjiFwojzdDJ4RxAofH2kUtFz9CehSUc1DXWBnVEDGD8b3M1Jn
         s9Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179072; x=1757783872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3XiBC3YnITjDEMymV+sH2MSwXrS5XAKoG7T+fRynC3I=;
        b=eEzgsxmsb4CTH8Y2bf1qicWJ5sJ4b9IccdzbtIbo/aLyCvRBnqyBvnM56bxlBHuCYO
         1/kLtQRfo6y7t2v57SxKqojttdJbD0QLdpCZZ/gZDPeSfdzVxXcSnVN95sBEzonXEC1j
         0Na1rhiIGXf4cUaWvZ2v1DIsHw1ru9Eb7/wQfC2iNzimA5+QFWw4vX/9MV6RldUwInRj
         OWEj0DyGRYjjwW/78ibRzZHfaxhUJwhuPfJrh6alHwPDzyWZGgdo5YNfVeAX43xFpMGo
         llQfwFPTKPtPOZBnZL7WW/8RV2/dcEkzrbqwYdhAv5UcaiAOxXhJ5XkH/bH7vGMKeHsm
         uIvA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8gZVvvIhZjOQEAF3Gfrsl/oFxGf4UGOaZcrQfML+AdWGJQl0nQrkVsslxmjYNLnL87TAHZQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw5DL8/V8lGjUosa6nRnJW1kNBj4XpF53KtzJ8r9Jc6OVegjDIU
	X5bQ4UAZBeJDjAvLA3Nqrx8s98gQjymQhRgzPwcqJUNZRLBBhX/tcdTB
X-Google-Smtp-Source: AGHT+IFICeR9T74g8VILVPwSH5ovbuHt/g2pnCmq/lWl9FssYMdGJENqFpNPlLDCEsIm/ZWcasdRiQ==
X-Received: by 2002:a05:651c:2341:20b0:32c:bf84:eb05 with SMTP id 38308e7fff4ca-33b57c44997mr6469411fa.33.1757179071914;
        Sat, 06 Sep 2025 10:17:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdkrUISLVP+whe+MuUlKlVLrmSJX+zs/1AgA75x5TYOFg==
Received: by 2002:a05:651c:4112:10b0:337:f217:a78b with SMTP id
 38308e7fff4ca-338d416b61als3831441fa.2.-pod-prod-07-eu; Sat, 06 Sep 2025
 10:17:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUg193Jxb7RiTXSF4T9Z4/VctdFiOAKM7D70ODxY5pg6Ai4iVifR1l2VVwIV+7BTCQWBXa/+AYFzfE=@googlegroups.com
X-Received: by 2002:a05:6512:1289:b0:560:98e4:c986 with SMTP id 2adb3069b0e04-5625ee79705mr728160e87.11.1757179068729;
        Sat, 06 Sep 2025 10:17:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179068; cv=none;
        d=google.com; s=arc-20240605;
        b=TfhYYNa5gOjf1UuWRilcU2GTgAM8PX+r3ZkR7HKKev1Ild7k3MfjDb9XXa1+Ol6Cx2
         iP1kBDxgTr7lrocr9J0MyeuX8iJbe1g6hc2AswP0SmzoWnwDm+SmhUhv60yEJ3r9JGxV
         xncNA0px9ToMwNdCcE0VAnIS3XFnMkHdVCeS55FGqprTssJXGQ2grkbMYiUq/1jUU+4i
         CL72V+ZKoBSOyHmOv+7KfJJ0K2t2T2Lc7Pwj7KpEurMqZFLAEYBZ9/vWY9Sy2XkNZ0dQ
         2ToYuBsJNmVTkyjYzyZyid/1Vd+oNl9/42wVeK/I0pf1GCT99NS1/cihp8L1zYeQpqex
         Cn7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KLznC9wbj6fsrEsXcR7N+oZqquNx2F+cSjxXWY46pjI=;
        fh=LssOqnJSwKECHg7JYnjH0WuwrrBhNOlHTi3c+MjWlxs=;
        b=FMHmHUr7gM/QoEqj9reVRHD32gyqdlIs4+Ju+KYVFYyuHgy5dTEcXHUcyW6FhB00J6
         RHxT11CHm63LoVXu1W5/Oe4sqLEQty2Hwn2YY150zHrpnABz+x7W8KzwF5QX3UREraAw
         8DfxIqVE46WOSV+G8mAZYbVDznHt1Ei9LzPjd8qR8psgiZEv1ZPHeP7SlbSmdQv/EZ+/
         Q/hJV85neO9DLBHhodmRQC4/Xk6PRTivpeS/Jtmyx4phhiKuPjCAuCqLUGSxIiq0ag8/
         Iu7+rQaxbV3uvqQ2ySk0LAvBXijJ1+GruLWofcaCDvhEFJEWRpUxlHvhp/q33LbeaWiT
         DIXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hT6ugBLt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-56369a99766si9826e87.7.2025.09.06.10.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:17:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-45de2f5fe86so644045e9.3
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:17:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCULHX4063jtAX4ji65h23RPfv8MatTlVnEuDBmBxVkbfpqwWdh2yQElGxp5CwSSwTsqV4rFXibxsIk=@googlegroups.com
X-Gm-Gg: ASbGncuGOmGj00r7AJXi2Cl7Lec7csCQd8k7amp/iy1xlXr8HqQ7cGOE4gPP3qshJbv
	4k/z/Dt868metiEOkOQRQ5TkvYYylHFUwm9xQWeqLS/jtvqbXMr6wmRkInyXB3Fv6CelhkXCwuF
	tFiGWgpbGINEUZQlsKu8bOLB7P9Ujjw3AiwVTunyP1yzPHZzbz+ptIcuQLnZw582culp+95eAlW
	M0Ajtwg
X-Received: by 2002:a05:600c:3b1a:b0:45b:9291:320d with SMTP id
 5b1f17b1804b1-45ddded3454mr23011575e9.31.1757179067563; Sat, 06 Sep 2025
 10:17:47 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <98d2c875da80331a51a5c61e8a67ca43fc57cbd3.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <98d2c875da80331a51a5c61e8a67ca43fc57cbd3.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:17:36 +0200
X-Gm-Features: AS18NWBlGrTUf2BbYo1ooSpg8yIusv-EYuyVF2j8Xf3UqWFYOvg4hL7GWGKDqp4
Message-ID: <CA+fCnZeUvsvGy02k4zQwkGUkL7KbuLzah5XC7kp1m5uwp4bPVg@mail.gmail.com>
Subject: Re: [PATCH v5 03/19] kasan: Fix inline mode for x86 tag-based mode
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hT6ugBLt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330
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

On Mon, Aug 25, 2025 at 10:26=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
> inline or outline mode in tag-based KASAN. If zeroed, it means the
> instrumentation implementation will be pasted into each relevant
> location along with KASAN related constants during compilation. If set
> to one all function instrumentation will be done with function calls
> instead.
>
> The default hwasan-instrument-with-calls value for the x86 architecture
> in the compiler is "1", which is not true for other architectures.
> Because of this, enabling inline mode in software tag-based KASAN
> doesn't work on x86 as the kernel script doesn't zero out the parameter
> and always sets up the outline mode.
>
> Explicitly zero out hwasan-instrument-with-calls when enabling inline
> mode in tag-based KASAN.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v3:
> - Add this patch to the series.
>
>  scripts/Makefile.kasan | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 693dbbebebba..2c7be96727ac 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -76,8 +76,11 @@ CFLAGS_KASAN :=3D -fsanitize=3Dkernel-hwaddress
>  RUSTFLAGS_KASAN :=3D -Zsanitizer=3Dkernel-hwaddress \
>                    -Zsanitizer-recover=3Dkernel-hwaddress
>
> +# LLVM sets hwasan-instrument-with-calls to 1 on x86 by default. Set it =
to 0
> +# when inline mode is enabled.
>  ifdef CONFIG_KASAN_INLINE
>         kasan_params +=3D hwasan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)
> +       kasan_params +=3D hwasan-instrument-with-calls=3D0
>  else
>         kasan_params +=3D hwasan-instrument-with-calls=3D1
>  endif
> --
> 2.50.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeUvsvGy02k4zQwkGUkL7KbuLzah5XC7kp1m5uwp4bPVg%40mail.gmail.com.
