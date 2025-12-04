Return-Path: <kasan-dev+bncBDW2JDUY5AORBHXTY3EQMGQEP65R74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 762D0CA48FA
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:41:04 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-47910af0c8bsf13101115e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 08:41:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764866464; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tb/D2J16i23FOSSVrYYofNNibybRLxamoVba/1Ze4d27Ln4P0YVrefKsFXyVNm/1e8
         wXD7GJXnsINMPcw6tMVokCZz3w8LWajtR4lQ8pSJ7GvAD3jrTgjLpMIduI6MIGqazYC7
         DPLgjlB0Lpl7MU8lntR9ZmFWPFeNoNyCegr850qkF7fWM/tOTJX2QndPpK8EvEEzrAZo
         mRWaNQiiDSfNkrPAA/R669glfCFsmmIf8Vsr8Ll1YmT3coLbyIoF8nuwC5Kv5cqPvYCB
         jECL3hDOIfUSEltUNAEbUSNRQP+B0DGRS8yJUwfYmgn49Ds1j8Fc3FL1GkSviuo8TcZ4
         hxjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=AGzgIS5R5Si6OZtooMRPzUZUkzBKXQ23ykteRIm869Y=;
        fh=udcq7555eioCAW+KGK0uRQlf/WThO4dkTvrs3rwtuJs=;
        b=Rk1/ehrH8j//r7TS4FEgajPTgO6LZbZup/cbeHjLqWt1chW1g5LFQ900Hu62/5CuFZ
         bK+6BsVWdL8YFndAso+thnRmTgCHmF/sE6pfW5b9cMnlL2A0a0oLAVkTWXlv4LcuI28j
         AlZvfzkNwtiS1LIRaDse3Px2jwrfQfPrHJmMgM0q1g6mOCfXM2Vla0vZ1xM4Wjy9PIv2
         QfOEowDvNnMQzN+KAwtswsmQkGMWR5FS2xy7i4vrpBQoepRoiZVjRdpDk5K297HJc0jn
         MjQn1l4BK+XS+icS6mzIOD1tcYkB0ZJAL2XRIrHlgzawtROQGbliQ30PwqKyFOlFFYv9
         VblA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=J8hzG9tV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764866464; x=1765471264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AGzgIS5R5Si6OZtooMRPzUZUkzBKXQ23ykteRIm869Y=;
        b=CAXTGzZdBdn+zczDjYlvOOT1YwASIYTCAQ6p5sxpRnHQhq5ZWhzoxXgjG1DqpRWsrk
         P6kHf8KVtZ/AjonnMFw3MY1Cc+sHz+jcQ/uVO7gb1Q3YOfWY92NhFWB3QqcXS6ewXH6D
         tcIEAYKgAdo86rmkyH4IgQbTORUGg8Z/fRc5StfgDFRav6JNjUkcX2ez9sgagAgdlki1
         RPq2zba8aETsx4rwPgJY1SaaH3MFFHludun1RdacqVodh0UlEtR63r8pzdJxhAkU4D5Q
         sEFNf45Jao0KqOnkxl+7ZhOenZ6QhFv8UcCeJBwBO7NhBBPcTP2qDoZvkRxRg5uT5ish
         pwJA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764866464; x=1765471264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AGzgIS5R5Si6OZtooMRPzUZUkzBKXQ23ykteRIm869Y=;
        b=AHxp9hMYIrzm/k+zSPdztOAWwYBGGRTfNZ+lqh5G2vk7nLt+sYFbo1usiNDkRWyMhj
         KfpIZRwPB765DEx8mAIv3CxgJwm8SNBW/rK4n7BUcPU2Z9qi/DAs1bRfE89EL9D98Y9I
         ozzD3G7if3xdv3A9agf5dZYX7TEnPKWeZAnMo+X0i7sp7LdFQUJBiFde/uT9WAVa6gsI
         nELtcIkUm3Qra36gjwI7lS9t6To4U0sXZkLP5PjHJw0JXe6E5aKUC5BU+ik0kbLCHiE5
         mt1Hs00yE+430rc5SxUBSU97kag+YZ3Ams4Hl+J5faOwMHB6fVHPod7mX7yBGAlgqvlW
         tD9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764866464; x=1765471264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AGzgIS5R5Si6OZtooMRPzUZUkzBKXQ23ykteRIm869Y=;
        b=Xofgtu7lken0A272+eUO2QOV9X4PVh4R6C5twFRPFkomgTzQ/PVB3eKndMVCDniodd
         vlMNEm9wDws2b1yNaPcj7gEPrXpsy/sDvGqsetKvkCwi6ds36Q8mb4MsX090VqtciinZ
         aPA+nMGU2rck5RNxETq8i534PRAnFn4Vf4Mib3PxDjrBXMsRJ8cWMxOSrP2WF8XZ/AZP
         oJznOuxGE8VRbPwMh4it+EwwVE6bdEeUmqFRMz+BOgGsn9rtZ0LBIYRSIZqfkvNoxXgf
         rJt3sEW0+GcWNz7cKaTXvfN9rR+aLHaFLbDA0mpkM9TQLs8wKfsvGFBzwt20oZdcZTgm
         PBSA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdywUyWNwNt6j9/TOBdQUYVc9ZzqH+Bss/MyZgS4mcjrVXAb0tZ5HYd2s2wuSuTBRJkMtalQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyhhh0cZwE/PcupBTUfW9wemJikpnsTVs5ZnUB4Gkxa/NhdgStt
	KUxaPJ/r24PXwws1Mbuf14dwPC/9lRnECeISuyfNV1OnJOBiHq6PrvBc
X-Google-Smtp-Source: AGHT+IEivSjkliRAKqP+8So7b/SnJLXRaeaIYm9//Jalnog0F6AtCcEHfXy9Z+3OaG6/02fLd36kbg==
X-Received: by 2002:a05:600c:1c1a:b0:477:9574:d641 with SMTP id 5b1f17b1804b1-4792f380be3mr36777685e9.22.1764866463716;
        Thu, 04 Dec 2025 08:41:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YUpgnX3pPKPpAQd50ylmxm4gYnsTxkzmZD7FSAofDaTA=="
Received: by 2002:a05:600c:a11:b0:477:a1a3:e379 with SMTP id
 5b1f17b1804b1-4792fccd713ls10651935e9.1.-pod-prod-09-eu; Thu, 04 Dec 2025
 08:41:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWRL1X4gPrNYZqLUo7mxK/iBCrLYYj1UdhCIh/XpteYN9sNR0oIby1G6baCxkfh9I/imQVfeEz2XDg=@googlegroups.com
X-Received: by 2002:a05:600c:4f54:b0:465:a51d:d4 with SMTP id 5b1f17b1804b1-4792f275cd2mr32797645e9.6.1764866460877;
        Thu, 04 Dec 2025 08:41:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764866460; cv=none;
        d=google.com; s=arc-20240605;
        b=c14PnDENdhMpWaPRVZ6w4/0FpWjCwD9lmvQMXnAJFagy6RjQGgaVb0oIUMaQXfoHnF
         d0N8gcnTUNofOLLANGums+wPNDIlyglEIY/xD0341vNgy186xMtWlvEcSH0roGQyHtSq
         qyUk7/YdTL7+Triwx3ayyE4AyP5d8DrYr9SxfRT9oruECr+ZMItpicpquzLvXIoqcxmb
         hG9BqG9GUNnK7ie7ef4Gcp+kGn7NaBdhVS/aLoEXRMkEvV6L69waawyQFAYrbV3hPqsM
         lKSo9v9tBFXW7IEtHVjwd91zvoyHvZvBVQvviz8KLNSFzbADVbjvrpTJOR3RW3DfZ0jh
         hv1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vXS4+o2Fq+EVRwWvGJTitCnGquHusQLvUPzYznKmUto=;
        fh=sy2OD1Js9qu5cZzKXYh5Rl/r8Ft/mZ2Vgjoa6i9+FIA=;
        b=Dbjqq6ET6F6k0LdCp/vvk1zs1gxHn2sZVEjCfBeAy563fC8rbWLTCAbMIzV/C4EIkh
         t1MrR+paoFFLtvKZNET23AX7r1v7q4ggbFxIQCTn/qMPOJaEwzx2M+6QZQ9g3QOX20VU
         oG3ulqEg+xIwLOjuwZ6lOYBR48RAMPREyf15gZuiGeSYPH62F5+B1MHFuYUZHXxSilc2
         DxzSNEzZRtWekVZmQArEDC1oifCdckEe3Q/6wS8UqsVZF+hF0j9SkdOQ4zx4Y1Odpx76
         GLwZ1mafmd0dfuI7SE9b5X8eCHPHiYs/bX/okB5uzzzbvVADe9WYwqabYgk9XJC7g1Pe
         sMlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=J8hzG9tV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792b123da4si641525e9.2.2025.12.04.08.41.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 08:41:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-42e2e77f519so917261f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 08:41:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVd6iTPqYNgSUL0nsYJfsrOp8MR1GP+YHDwoVgdcrFo082HnbpyNz+j180yBnykmlcxd4RUiPHw2VA=@googlegroups.com
X-Gm-Gg: ASbGnctH+4xJwywAYyohqJEpQzu8SwsYBwWfO/EFUInD6d6djFxYbD5qiayJ+KKZ4WL
	mu360EsD4G8ld8hcc36NGZJsx0OIRPjCUFr4aZeOMSEaQ9aX/FQvovp8kJAzTNI4ZY4xc266M4c
	XS/1oGYyGDCmT8LU4J957WjK3J68Z2UzmXfZyc04zXLdlYUK3tfg9ZVCvnbVY6nkVNegG6vIsIH
	CiAR1VuQUtT3oVIpblkMCFS7ctuIctDzfn4Xr7uUD8o0RhD9gUu72Ip2Hlb1vneHDuKl5aOSQLo
	qH7S0t2cgjwhTxUPg6AaFEXun0Zi
X-Received: by 2002:a05:6000:4212:b0:42b:3dfb:645f with SMTP id
 ffacd0b85a97d-42f79858038mr3500253f8f.47.1764866459724; Thu, 04 Dec 2025
 08:40:59 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com> <20251128033320.1349620-13-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-13-bhe@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 17:40:48 +0100
X-Gm-Features: AWmQ_bmxfZbuU8zhqgeyaLqAy9mjVXVUUmOMRc0g7rdfnIXPuRMuopEGEYYo_ps
Message-ID: <CA+fCnZfw5V4HqHepJUbH5cFSEj1G4yvJMb=1Tjd_7WDBP7uUfQ@mail.gmail.com>
Subject: Re: [PATCH v4 12/12] mm/kasan: make kasan=on|off take effect for all
 three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=J8hzG9tV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434
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

On Fri, Nov 28, 2025 at 4:35=E2=80=AFAM 'Baoquan He' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Now everything is ready, set kasan=3Doff can disable kasan for all
> three modes.
>
> Signed-off-by: Baoquan He <bhe@redhat.com>
> ---
>  include/linux/kasan-enabled.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.=
h
> index b05ec6329fbe..b33c92cc6bd8 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -4,6 +4,7 @@
>
>  #include <linux/static_key.h>
>
> +#ifdef CONFIG_KASAN
>  extern bool kasan_arg_disabled;
>
>  /*
> @@ -12,7 +13,6 @@ extern bool kasan_arg_disabled;
>   */
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>
> -#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)

So do we still need CONFIG_ARCH_DEFER_KASAN? If not, it needs to be removed=
.

But if we only allow kasan=3Doff for x86/arm64 after all (see my comment
to the cover letter), I believe we need to keep it.


>  /*
>   * Runtime control for shadow memory initialization or HW_TAGS mode.
>   * Uses static key for architectures that need deferred KASAN or HW_TAGS=
.
> @@ -30,7 +30,7 @@ static inline void kasan_enable(void)
>  /* For architectures that can enable KASAN early, use compile-time check=
. */
>  static __always_inline bool kasan_enabled(void)
>  {
> -       return IS_ENABLED(CONFIG_KASAN);
> +       return false;
>  }
>
>  static inline void kasan_enable(void) {}
> --
> 2.41.0
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev=
/20251128033320.1349620-13-bhe%40redhat.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfw5V4HqHepJUbH5cFSEj1G4yvJMb%3D1Tjd_7WDBP7uUfQ%40mail.gmail.com.
