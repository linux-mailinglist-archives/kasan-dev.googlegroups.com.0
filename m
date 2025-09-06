Return-Path: <kasan-dev+bncBDW2JDUY5AORBM626HCQMGQEYM3D6SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 07745B4758E
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:19:49 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-3381cbfc1fbsf7110301fa.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:19:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179188; cv=pass;
        d=google.com; s=arc-20240605;
        b=QKmyuC7a2jRb+O7V7GOm0cZL1ax/gEqwzDyWGdK0WJYcS+sd40lNQrkfOXDxi3q9E5
         tVj8rkMhVWYwTNMG5re62KxqYO0gaK6pipExXQ2h8cM06+JMORuLEGJRwsV7Bf2ImFMi
         INoEezk9ciT8xsYnt98Exd801uiUDulQkRk3l74QYWf8ct2mAG516LzOOTYAo/VyBimL
         bGobtqvWiH3dXCdZK5DDe8nGk37/2n+LazvCbaW4jYI9UthuNvRkUw++FUook+vBL8Le
         agFyMEZXpU2nHXQGOMJ2fwPZ/cstSl6rSoejo5lR0y3QCG9d0+tgfHlVsJNOWq1SuNXZ
         SSPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=QI7QfMOK4qtBo8c7BG5lMYeFo3HibePnWxit8ebMZAQ=;
        fh=1MNRaM9F00OSqJz++b7bkYSi81gmRqFleZpIb3VnnxQ=;
        b=bl+/p6PNThC19wNtdFLjhi5xRw0UXsRfj4wHtkXnjSd3N9KyzCroGQfES4Rgz1uTna
         t7fdRinV7wni25WPWWtFAmYmboxATe3gXsViUG1+V9Lw6oKjh9f+9nBzQsVLFfn+gabn
         jhgQYWQ4IS71nNQw7LCaCrXelj60515dGpeygrjCd/4SCIJJx6A0mbCjmhNaBXiTCF+c
         A/59vchHRAVSOaFlV/uX6Ago5AEW+8x7hbFoKpkA6xm/GXFwsTAWWa3jVtJGXyiHemcB
         pvAcUQ94xCQVf+MO03qc9FVXfo5I2WpgWKUm6oNciJgc1Yq1VEJqfbdsvYjv8vfUXoIm
         XJVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kTVAHwuR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179188; x=1757783988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QI7QfMOK4qtBo8c7BG5lMYeFo3HibePnWxit8ebMZAQ=;
        b=DeRqTar3qmlOQMjSHw7/VEhQfAa8PLjwC0pYqH7s87RSyFG5xm96j24cmThXmQNcpp
         ZfhOivAAZtl/mLT1DROcSktogP/zG/W+2IrFTqew1Cerq0O8RO+Y6lQLXV0RQ4FN8kzO
         6wtkZ2HGmrk7gP8Ha4DJTwZwrOWcXszV+GNDFQqCYr1UD2mToGtx7TkWl7+pD6uX1Kea
         I5DP4+j+anvDjIrZSn6Qk12pc+oGNBijYpnZMftG4LN2N8hq9hyToX8GFPz6zzV+bjfz
         88eDi9BAhuKfS9CWoz1Os3YJVs7jwAqH6927Wbz6ifgnM0q+nUdmilyrNlmoTEM2n1lr
         fqBg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179188; x=1757783988; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QI7QfMOK4qtBo8c7BG5lMYeFo3HibePnWxit8ebMZAQ=;
        b=UDMfhrdq22fSyPxsmGXPtPMfZphYo2DJWKuIK2pOdhJfSQSAHPTU0XhaHlRgkO/4sh
         b1Op+uP0w5LiQ4OMpzo2yUASes4GtykPK1VKXe/Iue1uFeqGm4FPtuGwCDaKz1DxsauU
         FxQM/rf6a6SNQ+lT9ZodAbHQGFiBJJhGEg0rRlE1sJKuDiAvEH+KtQDQtgypQtoASAqg
         YWtEDkEpj6BBByhmYPqv7rY1DqKNN91rqq4xaXl/Kfnl+lIqOg17eh+7z7xbBidfwxBz
         P3Qfke5ki1nMfFrvySxy4+mIWc5dvWf9/iyMvz51oPJZJn/gt6SBe2cc1avLGOgOnnhU
         OHfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179188; x=1757783988;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QI7QfMOK4qtBo8c7BG5lMYeFo3HibePnWxit8ebMZAQ=;
        b=B9T6yTcnSelCpCITj0npucxSIMKQWsYxIX28mSJoF4ljXErTY1ZWEuA+5aCWw5Y4Dn
         EvBx/9HOASm+mIuF6j1OsFZdWJj+URmguubBE1jj6g5QD76lfqz8d4APVWfdBNdys2BT
         ylQMwdIPveCjlOBXEOMZ2w+YvtWUe3wDZrKCf670do5wWtj9bfVOaLPJFnGOL7uJ1um5
         JYsnoy8HjRCjPoWiIMUFiCgmOVvz5QWSexIXktuhX9XPAHd9sZVoaRoCU8Jqrr0dpRFF
         hqDD6mrVY/+CUy2vAJ8UuUdSq7mm76xnAyQq7WdzfWhfqo4WrgnQN6FVjjNvaxDDFTTC
         zVtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXY/U/dDc0aARhERup5I+YbkjE1PUZ/eS/F0K6P5rpsXskgamr8/wJejDk55PyD90s00zA3cw==@lfdr.de
X-Gm-Message-State: AOJu0YxDHGnAU+l9TiZNUtBS7V9WhO0q5TlClgdbDJ6Afrmnnp9A5N5T
	G7FJgn4tTEg4IzMOGekFgG7sZhuFRuHYAAwvToOHBBR9EHYYluGloDcq
X-Google-Smtp-Source: AGHT+IHRFYnTEMh+9L6XYO5o9SPKNWFg0gUcP6U9cXntzX5z92x9kTYo+aYrw+IBobiZon8iBYDwyA==
X-Received: by 2002:a05:6512:3b0b:b0:55f:4e8a:19ad with SMTP id 2adb3069b0e04-56260a6233fmr655983e87.13.1757179188098;
        Sat, 06 Sep 2025 10:19:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcMdVDBQDXq1oP02Sxqk9V7pb0mujzD1nWP0TzUcRmwiw==
Received: by 2002:a05:6512:290c:b0:55f:400d:484d with SMTP id
 2adb3069b0e04-5615badee3fls534004e87.2.-pod-prod-03-eu; Sat, 06 Sep 2025
 10:19:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUiYZBc2c+AIIz9jTwcZuezFm4umfrzGJKW+tQlrGH12krsl+wlDqu9DZo4LfR69sVb72Podkuf/Zs=@googlegroups.com
X-Received: by 2002:a05:651c:23c8:20b0:337:ec9a:a557 with SMTP id 38308e7fff4ca-33b42e68b16mr5616941fa.0.1757179185311;
        Sat, 06 Sep 2025 10:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179185; cv=none;
        d=google.com; s=arc-20240605;
        b=iO+Bu84EUphJfBKtZiNxVrB9fucVjJBR/OGLJg/ngTkSou7BRBw6BtF1yW+8togzM/
         MeuLYhYpXkYUm97wHh5DgMQAAuxjOh1yhJi83h+e7BWHF+uNQmsM1WXNEDa2g5SdPk9f
         jR2L0pbI50ubFDK7xktwafYQLGRBqtcIYjBqd3495iEro2MstDE7q+Ai7e+6ZK56CWvx
         ly6mB4ExmPQKqMEzkrQUODgovjy9QJkjM0YJDZ9D9iRabMdrhIgX+YwcPTIgH4xfzof4
         0Qg7gp6nRWZizwIkFq1seccShEPT9o1aBlS3roavLjcNwoJtpD0Yf/vINr5NlsdXoI4U
         1BNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eJMKKvsr9aBhw2LBExeW27+96C2S4i1wtwzuhhQgIDI=;
        fh=5Lke0jskHPBFziqNnEVV/ggHeSiuRfVarawUMVAac0E=;
        b=HX9qMonufZIGjO/nPMLR1Yp3tqXxFVTZwjJtCXUov1jyGtrbipNCVBwQvw4Fw/0QbE
         goex2yzxBfLau0u4mhiacn0gDRQ/rC3sHrDp9sxK+u/iMCYtPlq1hwFAAAB55v8MCNJ0
         EANrjNo6xRM/qu+ZyS0N/pMIVBkDxdPWCTSLyfcvsQ0DhWTaM+jR2y88fNj22NqmTL3A
         zu+9vsXB6t3bKVtckDCSbfo0zMD6mjF+LWWjlfDHSurQ3TN8E4+ptU7IvPLvMBUqOb0I
         9xPd64XM93u84406lCK6rOCcI8kWNUFpHPc/eI0yT0jCINdyczu5N56jLyHXNh8ipPqZ
         odFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kTVAHwuR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f49f1a57si2563831fa.0.2025.09.06.10.19.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:19:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3e5190bca95so702374f8f.0
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:19:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV7Gg0E0pLxxhLIjjl3PjKuhNSmp6+1NbP3MRxTLC5K52fGj4iUY7Xn2qyxM9p+pK2nJoC9I/Mfou0=@googlegroups.com
X-Gm-Gg: ASbGncvHH6BJaUXxjarii+i3+XcUF/HuZk7CMZgZlnXDcRd3p0Owlx+WjDU4t04Aa03
	8XUb7HEHoVElp+9whqq50nQJuss5Eg9i31HNKivZ8E07fIDhyaHpSpswKibnS0ocCGO0Sr4qliA
	2RomdGR220RSp/iaaM8vSfh+90AZTIvlleYnoKJz+nNJBzwPOIR9khYoZxKaTreEnJ/6Z8NfnNs
	APjcTxH
X-Received: by 2002:a05:6000:2c0b:b0:3e0:37f3:7778 with SMTP id
 ffacd0b85a97d-3e64317d070mr1984874f8f.26.1757179184312; Sat, 06 Sep 2025
 10:19:44 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <3db48135aec987c99e8e6601249d4a4c023703c4.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <3db48135aec987c99e8e6601249d4a4c023703c4.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:19:33 +0200
X-Gm-Features: AS18NWARCvbmNO2W6P1AIa0UmJPeNw-mXWqtKJ3IgauS5o9YHYHKl3h4kKJN_64
Message-ID: <CA+fCnZd2824w610t86xQk+ykfv3EyAOvhb_OuXjru5e+jE4HTw@mail.gmail.com>
Subject: Re: [PATCH v5 19/19] x86: Make software tag-based kasan available
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
 header.i=@gmail.com header.s=20230601 header.b=kTVAHwuR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Mon, Aug 25, 2025 at 10:32=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
> ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
> (TBI) that allows the software tag-based mode on arm64 platform.
>
> Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
> of memory map to one shadow byte and 8 in generic mode.
>
> Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
> CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
> support is available.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Add x86 specific kasan_mem_to_shadow().
> - Revert x86 to the older unsigned KASAN_SHADOW_OFFSET. Do the same to
>   KASAN_SHADOW_START/END.
> - Modify scripts/gdb/linux/kasan.py to keep x86 using unsigned offset.
> - Disable inline and stack support when software tags are enabled on
>   x86.
>
> Changelog v3:
> - Remove runtime_const from previous patch and merge the rest here.
> - Move scale shift definition back to header file.
> - Add new kasan offset for software tag based mode.
> - Fix patch message typo 32 -> 16, and 16 -> 8.
> - Update lib/Kconfig.kasan with x86 now having software tag-based
>   support.
>
> Changelog v2:
> - Remove KASAN dense code.
>
>  Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
>  arch/x86/Kconfig                     | 4 +++-
>  arch/x86/boot/compressed/misc.h      | 1 +
>  arch/x86/include/asm/kasan.h         | 1 +
>  arch/x86/kernel/setup.c              | 2 ++
>  lib/Kconfig.kasan                    | 3 ++-
>  scripts/gdb/linux/kasan.py           | 4 ++--
>  7 files changed, 15 insertions(+), 6 deletions(-)
>
> diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x8=
6/x86_64/mm.rst
> index a6cf05d51bd8..ccbdbb4cda36 100644
> --- a/Documentation/arch/x86/x86_64/mm.rst
> +++ b/Documentation/arch/x86/x86_64/mm.rst
> @@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
>     ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unus=
ed hole
>     ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual =
memory map (vmemmap_base)
>     ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unus=
ed hole
> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory
> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory (generic mode)
> +   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________
>                                                                |
>                                                                | Identica=
l layout to the 56-bit one from here on:
> @@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
>     ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unus=
ed hole
>     ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual =
memory map (vmemmap_base)
>     ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unus=
ed hole
> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN sh=
adow memory
> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN sh=
adow memory (generic mode)
> +   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________
>                                                                |
>                                                                | Identica=
l layout to the 47-bit one from here on:
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index b8df57ac0f28..f44fec1190b6 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -69,6 +69,7 @@ config X86
>         select ARCH_CLOCKSOURCE_INIT
>         select ARCH_CONFIGURES_CPU_MITIGATIONS
>         select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
> +       select ARCH_DISABLE_KASAN_INLINE        if X86_64 && KASAN_SW_TAG=
S

Do you think it would make sense to drop the parts of the series that
add int3 handling, since the inline instrumentation does not work yet
anyway?

>         select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE &=
& MIGRATION
>         select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
>         select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
> @@ -199,6 +200,7 @@ config X86
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN                  if X86_64
>         select HAVE_ARCH_KASAN_VMALLOC          if X86_64
> +       select HAVE_ARCH_KASAN_SW_TAGS          if ADDRESS_MASKING
>         select HAVE_ARCH_KFENCE
>         select HAVE_ARCH_KMSAN                  if X86_64
>         select HAVE_ARCH_KGDB
> @@ -403,7 +405,7 @@ config AUDIT_ARCH
>
>  config KASAN_SHADOW_OFFSET
>         hex
> -       depends on KASAN

Line accidentally removed?

> +       default 0xeffffc0000000000 if KASAN_SW_TAGS
>         default 0xdffffc0000000000
>
>  config HAVE_INTEL_TXT
> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/m=
isc.h
> index db1048621ea2..ded92b439ada 100644
> --- a/arch/x86/boot/compressed/misc.h
> +++ b/arch/x86/boot/compressed/misc.h
> @@ -13,6 +13,7 @@
>  #undef CONFIG_PARAVIRT_SPINLOCKS
>  #undef CONFIG_KASAN
>  #undef CONFIG_KASAN_GENERIC
> +#undef CONFIG_KASAN_SW_TAGS
>
>  #define __NO_FORTIFY
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index f3e34a9754d2..385f4e9daab3 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -7,6 +7,7 @@
>  #include <linux/types.h>
>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>  #ifdef CONFIG_KASAN_SW_TAGS
> +#define KASAN_SHADOW_SCALE_SHIFT 4
>
>  /*
>   * LLVM ABI for reporting tag mismatches in inline KASAN mode.
> diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
> index 1b2edd07a3e1..5b819f84f6db 100644
> --- a/arch/x86/kernel/setup.c
> +++ b/arch/x86/kernel/setup.c
> @@ -1207,6 +1207,8 @@ void __init setup_arch(char **cmdline_p)
>
>         kasan_init();
>
> +       kasan_init_sw_tags();
> +
>         /*
>          * Sync back kernel address range.
>          *
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index f82889a830fa..9ddbc6aeb5d5 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -100,7 +100,8 @@ config KASAN_SW_TAGS
>
>           Requires GCC 11+ or Clang.
>
> -         Supported only on arm64 CPUs and relies on Top Byte Ignore.
> +         Supported on arm64 CPUs that support Top Byte Ignore and on x86=
 CPUs
> +         that support Linear Address Masking.
>
>           Consumes about 1/16th of available memory at kernel start and
>           add an overhead of ~20% for dynamic allocations.
> diff --git a/scripts/gdb/linux/kasan.py b/scripts/gdb/linux/kasan.py
> index fca39968d308..4b86202b155f 100644
> --- a/scripts/gdb/linux/kasan.py
> +++ b/scripts/gdb/linux/kasan.py
> @@ -7,7 +7,7 @@
>  #
>
>  import gdb
> -from linux import constants, mm
> +from linux import constants, utils, mm
>  from ctypes import c_int64 as s64
>
>  def help():
> @@ -40,7 +40,7 @@ class KasanMemToShadow(gdb.Command):
>          else:
>              help()
>      def kasan_mem_to_shadow(self, addr):
> -        if constants.CONFIG_KASAN_SW_TAGS:
> +        if constants.CONFIG_KASAN_SW_TAGS and not utils.is_target_arch('=
x86'):

This change seems to belong to the patch that changes how the shadow
memory address is calculated.


>              addr =3D s64(addr)
>          return (addr >> self.p_ops.KASAN_SHADOW_SCALE_SHIFT) + self.p_op=
s.KASAN_SHADOW_OFFSET
>
> --
> 2.50.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd2824w610t86xQk%2Bykfv3EyAOvhb_OuXjru5e%2BjE4HTw%40mail.gmail.com.
