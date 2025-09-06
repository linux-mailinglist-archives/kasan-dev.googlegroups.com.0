Return-Path: <kasan-dev+bncBDW2JDUY5AORBGG26HCQMGQEEH3HG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 18826B47584
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:19:22 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55f6f4dea68sf2495303e87.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:19:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179161; cv=pass;
        d=google.com; s=arc-20240605;
        b=JchhJlA0uHOIN0X3Ijq5ZMJXMnCygAot7Y4ItxmZHDugKJ5hQE28ffym2ZlvkC4j+Y
         qScK+T0jhMocRKlEzCd/maFVoJxP17zLLRPoEpjHnUg8fTFElxQNEDVDyTMbMwmcCRik
         MmP3NTldJ9i8l4avhY+lEwClu4NA03g8YEjfwFFnlIggVIBujCKeBtyQfLV/1j1QF38H
         I1Tk2r1SnGMEO/MI1g8o7rrPZBgcG+Rm1bko3QVE/+YTpsm3YsG9saZh/kHWURxTzZUm
         jpfdbGVJfobYNGEjWlzQbcyV1TZbiKPYjrUsOA0eDv7ZGIbVmlUk0C8F1Ye1W2rpJoBM
         hfrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=MGc/ixa04mku5XvXHwk8oIqBSqZnHVqoW9wBdp3t4ZU=;
        fh=AwhgQ5/VXlOR/YyAENYzDE34YDuKDY5h6XGUXSuKZiA=;
        b=Pj2lt4LnkQXD5s82FjSmpKAoF1XbRJK0yFoYI3xL3WbSdoVXUEWHjNicJWA5T8+Brz
         Iz4K1IuTQxrFuHOUZ1hFGJlRnjExzJLoN5yBPK7MzR+w3dmuERrsysSeQPOf8jyI/7ju
         rhAxwuG+g8Apvo7P8tieZt4CoqtYAyep8YMnSM5SRqMWBdHg7nYv3jl0B+75kVBaU4V3
         EREh9Uj77c6vkGcULHmSwJI4UuK0kePgA2CWzcTd+ELFMzXNlyhT76aj3WXiGVlm7L75
         dEkA3D83QN1dAnpGjXddk/oyMEpnQMXCUWDDKwKAXY8glbRIp84s4NhCJ4J37MfW4kUc
         BAzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bau5iR8v;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179161; x=1757783961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MGc/ixa04mku5XvXHwk8oIqBSqZnHVqoW9wBdp3t4ZU=;
        b=vNX1vS03wqK21MddhkRtyLgkYYfjGRqaYXUkO9ah/75qtkApIhb8It0D7mhoZRd+B6
         3FCgDF99MWmtvFY5+EQ8Jvb8T8SUCOlx/XaGzVpopZquT/3MuWS61CPiozjIf1l190Em
         +iVND9US996TY35MgT2oYB7zk5GWcpfWm3zBUYxpG2pHWgePKeGL7eQJFZZBPxcKhWCy
         MB4kdogLTtA9HKQCFz0RLmntp9KRd16geAzk4pUfQW5YidohKGCHbQoauHPj1yafUFvC
         NzxcQJxDHNtLQwABF+FMeubwmqNRymWA8SakJPGisVHmfNd6U11gb4qLj2NA+4iSt8iT
         /L8g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179161; x=1757783961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MGc/ixa04mku5XvXHwk8oIqBSqZnHVqoW9wBdp3t4ZU=;
        b=E0Rlv90W2pW2+oh9o566MboTz75GHULit5+kt+8LBdnI+kqDuBBm+JlrU6D9hQsTSO
         yMmUmMeVl4/9QPIYKht4MYGMeFmQZdlsvelp8Jb9fxJgST5FVVrkpgnkdrPuMOQQRR8i
         JoqG2m8/eFmXtUPgN3N69AHk2bxfF9vUmF35gTNrqu60Tb32SlSnvk7kJL7t0hzvvj4Z
         3bciI0/F+UdOe9istA09xkvirNdJkhFy/om62oG+lxesM5huwmZLM7GA3wPfFT79qntR
         3nsVnJnBqXBWTi8B9UwFN1yc9uIGh3N4TMG57W49MT/uWsMJPgkNMjjUIKEl+FIJoYM7
         EeBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179161; x=1757783961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=MGc/ixa04mku5XvXHwk8oIqBSqZnHVqoW9wBdp3t4ZU=;
        b=ftfuw7B8pOZD1TgqrOGLI98PuWPnPer+ZPDmALvhZR6+Pzwo1JbyU88w8qvU3GjoDL
         NAmvgd8Jn1ysnAKlzwDflSF0ySwlGDfQfpLhtuvjqW6PxdLRhAsEzF9ii4ruCjME4ejA
         /uyHVgRRDqKDhn3A1+gBidzWbpOTf/4dpdXMtszfLFJEoAyF4c+AdB1SMC2tY0Q72uOn
         NZH+Kqxjd7LBDH7cCjB4MMU2BCwaxYTrpVt2X04i/4zJUAVacdSuUbSPjXDZobacRGQF
         tYWG39O0m5lhxThA820iPgiir9M2ehHBl1m8QuNy1EZQrAOtlv+bCs/JBxDbrDHzg6JQ
         ufuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0TeMPCTFEZ7ZzeIO6Y+eUzYsj+0jVFKI9pIMrjm2V7T/UiQj2GSS6G7TE8DBO45esT2+QPw==@lfdr.de
X-Gm-Message-State: AOJu0Yx3MVb0jHIch7aSBfs/T5Aao+rfYMyABOegj945aNFyb/k3iKV0
	DTJT2D/u/St80n3JVgMuJQKFDbEKe0SqoZFlP13zht4VbEcK0defoBeV
X-Google-Smtp-Source: AGHT+IF6rSM8/uXmQtNSdCbqpFtcRKdX0pn753zv7D0e8ojkr5+Nhbf5M7+T/2buNSSmHFiePWy3pQ==
X-Received: by 2002:a05:6512:b8a:b0:55f:43ab:b220 with SMTP id 2adb3069b0e04-562619d7f5dmr684661e87.34.1757179160984;
        Sat, 06 Sep 2025 10:19:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdQLiyoFWAyn4ivx4md2HWVyW3KmVNKsiMCYGUwYdgYCw==
Received: by 2002:a05:6512:3ae:b0:55f:8255:d96a with SMTP id
 2adb3069b0e04-5615babf325ls574276e87.1.-pod-prod-02-eu; Sat, 06 Sep 2025
 10:19:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUi+jxGOSyJd+dkria0KhXrBfbhU6wyOf/oatlykC7zIQ0UmHdcI0gbiSW2N8FwcTbhXyeTijV+TIg=@googlegroups.com
X-Received: by 2002:a05:6512:15a9:b0:55f:4e8a:199c with SMTP id 2adb3069b0e04-5625ffc8808mr757757e87.20.1757179158075;
        Sat, 06 Sep 2025 10:19:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179158; cv=none;
        d=google.com; s=arc-20240605;
        b=dicWeK6ZTETknLRqr5Iu0WTNkfbTFAS+7T3KHfo6Gqz5G8gVq/yYrsvohp2Q3VPwS4
         SoEMHC8OK/D5278EYsUgCHog8CQ3/5GUnYeRmnxF9U2XtsdgphCh749cHtQB9hkHfWhT
         lab9oTlKhXxUwi+8Cn9RBcs9ZkCPhosCFRa6nHsK2OVw3NcH45zhFy0BucHdF5bEITe4
         PuiiXtyW+aybXGSGMWgOn5P4i2qMfU4+8n7n3caUhy6KADbch5ujx7Co7hmaRM23Fa75
         UG1f4Hb39in4iOXUtbTweE1dFU1aNpF2MOM+UK1wcTTIGhfX+v6EWGI846iHvIBeJQ9R
         Bxxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BGQShZZAoC8IOCDe971xjsR3B/73MD2B3WQtZ33juWA=;
        fh=3KZGbWov2h3QilK2b6wa9pr784A/VeCKqytRYoLOMgg=;
        b=GpS68RGAWGzZfyegtWJwcM/8byQHfB5UwQLkQ+Q/pvvH1iAUywZUqi+0BsspxLzrFS
         M/sCiDLkT6ebk+otdHiRxT+XSGLrMtI53VnN9yKtv/TM1HuuWC3rC+iGfsRRqArhCaqi
         NAij/toP7haBuMmMT0geif09ZjODp+8Wok0haLXicI8PyQCEqtDyTrzmPni5ob4db3vr
         +EmSmATkIQPDSFVdimyjCAhJb96vjTcQh0IZ8AxJGjyACOC8+KO3ewpiKTI8EAD9pR6J
         mIB2DgQAnnwmDvHxDYKZ/j3qX3gfWpu98onO61m9dwi/GU5x601QD2Q+iWBPB/QIlMwq
         2DNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bau5iR8v;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608ac88793si196819e87.5.2025.09.06.10.19.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:19:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-3db9641b725so3166080f8f.2
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:19:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVlqWXKahlj3BQgz9Fw4Vi6GHDgOeGPZr+vYYmhtERbx4ABUljGMJnj3FquZ7cU96oXIM9JEjmB5TM=@googlegroups.com
X-Gm-Gg: ASbGnct5AoHvjB6ZbdB2F7MnOol3chO1DcyJehmaQPTKmJcfQsGacXXrKOiHUaCHxz7
	g4E696WloWvTtfzd55zHCX7h+C9tUbmxDEC1KM1vjUBdqhcE0gzi+NZQEQvwBmrO52f26f2NSJ3
	M7i0mDF3TVvpAKUEh/hFE/DXee1v02JemlQU2YK7sX01EXpXv/nERQhk/5UWhU5ccxVtM7VPWwa
	Z1JoMRC
X-Received: by 2002:a05:6000:2312:b0:3d3:494b:4e5d with SMTP id
 ffacd0b85a97d-3e629f1faf0mr1903280f8f.0.1757179157138; Sat, 06 Sep 2025
 10:19:17 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:19:06 +0200
X-Gm-Features: AS18NWDxFT4623FCGfz8GntFkBjzjskpR65nPPTaISyQJutWsmUOYJwFObV25h0
Message-ID: <CA+fCnZf1YeWzf38XjkXPjTH3dqSCeZ2_XaK0AGUeG05UuXPAbw@mail.gmail.com>
Subject: Re: [PATCH v5 15/19] kasan: x86: Apply multishot to the inline report handler
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
 header.i=@gmail.com header.s=20230601 header.b=Bau5iR8v;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
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

On Mon, Aug 25, 2025 at 10:30=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> KASAN by default reports only one tag mismatch and based on other
> command line parameters either keeps going or panics. The multishot
> mechanism - enabled either through a command line parameter or by inline
> enable/disable function calls - lifts that restriction and allows an
> infinite number of tag mismatch reports to be shown.
>
> Inline KASAN uses the INT3 instruction to pass metadata to the report
> handling function. Currently the "recover" field in that metadata is
> broken in the compiler layer and causes every inline tag mismatch to
> panic the kernel.
>
> Check the multishot state in the KASAN hook called inside the INT3
> handling function.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Add this patch to the series.
>
>  arch/x86/mm/kasan_inline.c | 3 +++
>  include/linux/kasan.h      | 3 +++
>  mm/kasan/report.c          | 8 +++++++-
>  3 files changed, 13 insertions(+), 1 deletion(-)
>
> diff --git a/arch/x86/mm/kasan_inline.c b/arch/x86/mm/kasan_inline.c
> index 9f85dfd1c38b..f837caf32e6c 100644
> --- a/arch/x86/mm/kasan_inline.c
> +++ b/arch/x86/mm/kasan_inline.c
> @@ -17,6 +17,9 @@ bool kasan_inline_handler(struct pt_regs *regs)
>         if (!kasan_report((void *)addr, size, write, pc))
>                 return false;
>
> +       if (kasan_multi_shot_enabled())
> +               return true;

It's odd this this is required on x86 but not on arm64, see my comment
on the patch that adds kasan_inline_handler().



> +
>         kasan_inline_recover(recover, "Oops - KASAN", regs, metadata, die=
);
>
>         return true;
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 8691ad870f3b..7a2527794549 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -663,7 +663,10 @@ void kasan_non_canonical_hook(unsigned long addr);
>  static inline void kasan_non_canonical_hook(unsigned long addr) { }
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> +bool kasan_multi_shot_enabled(void);
> +
>  #ifdef CONFIG_KASAN_SW_TAGS
> +
>  /*
>   * The instrumentation allows to control whether we can proceed after
>   * a crash was detected. This is done by passing the -recover flag to
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 50d487a0687a..9e830639e1b2 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -121,6 +121,12 @@ static void report_suppress_stop(void)
>  #endif
>  }
>
> +bool kasan_multi_shot_enabled(void)
> +{
> +       return test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
> +}
> +EXPORT_SYMBOL(kasan_multi_shot_enabled);
> +
>  /*
>   * Used to avoid reporting more than one KASAN bug unless kasan_multi_sh=
ot
>   * is enabled. Note that KASAN tests effectively enable kasan_multi_shot
> @@ -128,7 +134,7 @@ static void report_suppress_stop(void)
>   */
>  static bool report_enabled(void)
>  {
> -       if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
> +       if (kasan_multi_shot_enabled())
>                 return true;
>         return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
>  }
> --
> 2.50.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf1YeWzf38XjkXPjTH3dqSCeZ2_XaK0AGUeG05UuXPAbw%40mail.gmail.com.
