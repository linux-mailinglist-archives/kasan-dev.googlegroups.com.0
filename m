Return-Path: <kasan-dev+bncBDW2JDUY5AORBKOLUHFQMGQEII5RHQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B3672D2256D
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 04:57:30 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b6b64b843sf348797e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 19:57:30 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768449450; cv=pass;
        d=google.com; s=arc-20240605;
        b=l0e6HCYn4lvbCTyJjbeTkw4dXAkEOofdCb+zqmWx5RHIq4meTIFJYyv2dBfHYFJc2T
         7XyKkiALTTWwZaNFxuEkKEhW4cCpcskyY8Y61qwUn+rrz3j5Nv2yLcqbVFV1mlIC52ir
         R4+y5itEkB5i/AEWO2oW0FtghAoSgTfJ3fQMLbGeTWhQB/2wa6h/u3s5NgODUCOWErcF
         ulJRZ8Ls3AHpkkEnpElqiw3a51u1lTbxgG4CnBDGsgD86HGDTeNnonhEb8ROfW77V42O
         OxrGz+zxteiBTdGkv2nrXFwst5BmKJZdTism5QTmiwzsm1bg7HLtRW+KSJNHqeTROrYV
         sbFA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=GERRapItMtNakOsDLPAjHtH+mFJ0hzS+thgmjB3Wn2o=;
        fh=/FN4FsHKyV883DAnEU8jCtEFo1WF2UbNHyam3mPm3CE=;
        b=WMwDb4hf/YeheFOXQp6MTSUXY0afCk9Zx73REcCIyQdLyVHwG15DlSD/eS1aTngG+6
         GTEEn13vTU79tDvQg0+LJr9gb7VbRY7UlnLoCpdX+XpkRH9htGrj/vzli937Tn9jl7lo
         okxs4gnYqF91AM3DUl4L/FEKkhR1/NkQVI8EHBDRA6HfEpmEuYNeU0TukKXREZ3dN7+U
         ID4YGILiXtu0rrCAI0DHjzXi4Tffllg96L7ZSSjFkFnyFSB5qb8bSxOd7hcYELNAjjfP
         bPO3Cry7ku3cR/fMh2pAkjPFsFMJTEMUOIm6Y5LBTv76Lot5Ex7TiieqN7nk5iudLl6V
         vKBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VbudfZlF;
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768449450; x=1769054250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GERRapItMtNakOsDLPAjHtH+mFJ0hzS+thgmjB3Wn2o=;
        b=idD3q2rvhRv89FzdhAVzTQ2zWQljnZgMOvnN1UyI9jdM8Lg6PZOWFheA4T9U3iw3V8
         081qPt+zkhMH0t8W6O18xILdEQhEFaJqr3f2v5lxwzyKtP/0/STYwPDXQFJTwXh/iRhF
         wyLuvOdlR2wLLHQoO/4Sa+Qn8LYooItOO8FM4LhoJ2JQr8UFcYWq13ycRC75SvpjU5Dy
         bKVQcBK6ZIOTfDvItqCvqfeZd59iopyu9VaSi+YMtv0T6VQLBcMfijur6Af34buD03GJ
         +yp0YU6r1tAG5KJy/+4Lm261u/s0sEjiTTwMmVpANtqDNgJonTFNXmJzWOR/6++XLsQC
         OVyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768449450; x=1769054250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GERRapItMtNakOsDLPAjHtH+mFJ0hzS+thgmjB3Wn2o=;
        b=ZPzapFuVY4DgNwEveTr00vIkUUWnR+xfJuyP3MnzeaaX3y+uUrRkjpe8VyU9WS+NTN
         TIDak68twRYwymBT3TtuOdrXmi1YIlrS1o2myIQIbVOQjYQyDqSZOqq2teuYX08Knovp
         5KCC6aebVuIwstFARKZDvce3RduMpuea2QSPtQGhOntc+xXPwuQqsHz41kWg2rOwAzyk
         8RBkh3CXwmJBdtvXcKXqkESy17GKzhyxzv9DUQajw0SmUBMEozVCwRhgdYbMbGTRqJOf
         AlCBcmvqyfO1UdsSnoM9gRX4XqJpD7O3S9DRtheGIB34HW6PXI2TsuDujuWWZ0Kt1p8/
         jQpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768449450; x=1769054250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GERRapItMtNakOsDLPAjHtH+mFJ0hzS+thgmjB3Wn2o=;
        b=ObxHv1BsqL8ErkxI/3nK7rkRTZ8ISkmINeGaaCY92x3aZXD3TNzgwvII7W6tbWxwws
         cHjUcnftiQf2ZlhUyU4sB7F2lJpvigpDYTwezFwyUW1/M3bDG0EQCc6h0Z/nBG3ghUL+
         CaO6/pWERfEgwrtL/x5mdU3lzE5bTAMKu5LZP+kfvVC/RKOTmWJ2su149ErENY1/BeQs
         QYbKnr3M8U6T04D3r+DbkfQdez69cP/BT9qPXaNi8K0PEj0wRGEwv+mhZn4iAdBCjGte
         BhveUIoYG+DFVVCeTBy9KG77wgoiIV8fHI0DXQaS6BDfRuexzKHYkw9hzGxP28kcfHqx
         bXPA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUm09OkjoQSxXmWtxryljP2cODNCQYR9af4SXmTYFWM36/zhISqV/c49PgwolOwUV6KmwG8Xw==@lfdr.de
X-Gm-Message-State: AOJu0YyfYqxarup2ijhBCfCrume84n4TqmFZPpCQaui8yPX6kfCExx/L
	8My1DHsmpbjwgAKWeGZlt9qfMATMbFooutkVkLfptPHop+sZw+jbkzMc
X-Received: by 2002:a05:6512:32c9:b0:598:f1b5:ab9c with SMTP id 2adb3069b0e04-59ba0f8125amr1758923e87.31.1768449449780;
        Wed, 14 Jan 2026 19:57:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ha/DnLSY8Hhs+KrYjk3jCVQhmvJzMx02fgUMEg6p1uwA=="
Received: by 2002:a05:6512:31c3:b0:59b:6d6d:c with SMTP id 2adb3069b0e04-59ba6b4b2edls202144e87.2.-pod-prod-09-eu;
 Wed, 14 Jan 2026 19:57:27 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXxr9Kt6KPyqyWw9bNSzC/7Q92JT2YimmZ6Yzy/kTAgOUetEnPq4hzhcIwwBVG8YX3CCyTWrGFldYg=@googlegroups.com
X-Received: by 2002:a05:651c:2126:b0:382:f8be:991c with SMTP id 38308e7fff4ca-383607472dcmr14404651fa.20.1768449446943;
        Wed, 14 Jan 2026 19:57:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768449446; cv=pass;
        d=google.com; s=arc-20240605;
        b=UN4qwnVp15KVgTNOxTSve7/Gal/eCp3NE0Q9UsDznKJkYlrAQynXaQLz0U4+PgkRLX
         GDdcy9Frol/7T2Ui/cxS7dp5j3bGxlJ5IEY806V1tBR7lqducD5PYwZmegbACQwaYbyF
         kvIm36AIsNc02coCbFJ9ilYUrmkqVFe4iSlvrnPHChbd6MK+MC/1SUhY3oj8gcn+PhV2
         1yOghKe35j5+UVwFkqedz6K9t3dce7fJ0ibygk9SW9f6igEIpZAefacx9fvZURYGJn4T
         iNRkjl/JKehRyFQo0abehKs1Q8I2Z3T50525ZIteczUfYsOLA0JVCuFSJh8s4VnMysFV
         gIxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dF8ykdDUqJ0kZqPReApJ7+RcoAo4qkCvnJ+8HSR43WM=;
        fh=gw9FpogSc2/9KAf91CoD0Z8Iu6z/ickw+EnY1NIZTCs=;
        b=IzxO8Xezuj//hdAuoYLEMLVzMGtz7DQiLYpKK/JdBfskDuWCLWC4RFYgCW2bmGuCL5
         oEwmUvBeqCvTB5sUypipiQRS8klBQiGORy2Z914fR2ay+VE1uRI1i738MksKJa3/gC69
         jgQFEK5Ksupy0HE0yno2zO7bbKuY8zmqz+agWmwlCOFnslRh2YZMFYnhR9DxkYUo6njB
         HeKXy6rO5TG1KuFWjxFndiL5Cct7eCZ/+CRezD6z2gm1QTp+3yOU7AvI66W/wJlmoQKn
         i/65GH0w1MgVGgjs11BAx9evQBJ6Fe8vAj+HFmRU1jIXqbCqsCDxCArp+RgHky4uM7Q1
         neag==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VbudfZlF;
       arc=pass (i=1);
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3830647c24csi4732561fa.4.2026.01.14.19.57.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jan 2026 19:57:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-4779aa4f928so4903045e9.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Jan 2026 19:57:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768449446; cv=none;
        d=google.com; s=arc-20240605;
        b=At7xVmhlBzScBimYZFJ9rVA6cnFQzylDWguOS9HnSP8gBmYxhRbjvhV50bBBKgf15Y
         hf6aKLDMpxdYNji8sZhY1D43GEzgePEO4yw97JzKhvTscAH5rhaTuldWSjJpm+Xb+cTh
         MJhdETmTZzsw3pTW5W4P+VhTmhxWizwVQphCflsZ+xzt1ZvQX7NzFQTRNc+nV98ohc30
         7iCv5zlBzfE7OcTgFJv89g1ZEmnHqVmnP7GW1RMd6oSpsRk1PphFJ+fIMJxdzXycZa6C
         QHrWKGXSYXrko+As1FPLkWCuYBmyjdrll5lhdQT+QxLg6drebAH0FzQljVf2CL/Fv4YX
         3snQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dF8ykdDUqJ0kZqPReApJ7+RcoAo4qkCvnJ+8HSR43WM=;
        fh=gw9FpogSc2/9KAf91CoD0Z8Iu6z/ickw+EnY1NIZTCs=;
        b=bKArQX6SfplVIA5Z5LpMC63dSK0G/n186XOMRNj3U9WScKCyxiWiTEWd35ES6KrSHA
         OsRGKpPSCFCI9R2n6vcLtfHPeJIUJktG/RsylPWaPjL8cAtskTFfNMAFxHLeN74WHPvG
         r6kFxKOo0+HP095x5bStMIORvaw7epUm4pYsjs4Ke+vLh9yaMpORRYHpS/PXug+gu07K
         1l+RwDgGtlEgWr+NXHVmD0GixQgOEbZ0ywacRCwYYvyAMU5rZ6PCbjbfKpuR94P9HdT5
         l+SBkYV32HepqTy/4sBJCRoYpZ/NefWPthYfZm25+fjXE1XiH2PHKCaKZFSWHQrfnsse
         XN6w==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCVBC6yk+RZw8NqDldAYWqacz9Eu9/VKRFtn11qGyv8p83MYMJ3tcg0YNkLKcMi5moPsKZHZtFYvr4U=@googlegroups.com
X-Gm-Gg: AY/fxX5tKj8ZaY3dJbDXLhU1adeQeyyfCNzM5VISU3jW7yWMJZFh7Uj9UClK+w8JhKD
	UxIz0eLaKFwIXsGabCaheJ20+scrfv+kcruI4Xld8xIQvND2xs5/ARastk0j1UzfM/SAVdTEQHY
	GoVOoDgIMeca5a2HKg5zjgPkUTFx0DT6xMLUcX2UVVoSDoY7l95gXqt4NWQHfj0a21kjob7Y9y5
	2RojcmQ9m13pzYaYoY24H0dg1lNjC8kX5L9gCzr1ac4IVPwB7K2wjnqQXYygOT+FTLp1jF0qTDS
	NgDTtZeWnpC1YtRiSwykfJM0WGXG8Q==
X-Received: by 2002:a05:6000:1448:b0:430:f742:fbb8 with SMTP id
 ffacd0b85a97d-4342c50132emr5549030f8f.21.1768449446128; Wed, 14 Jan 2026
 19:57:26 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me> <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me>
 <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com> <aWfDiNl9-9bVrc7U@wieczorr-mobl1.localdomain>
In-Reply-To: <aWfDiNl9-9bVrc7U@wieczorr-mobl1.localdomain>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 15 Jan 2026 04:57:15 +0100
X-Gm-Features: AZwV_QhDwJPvCo2WidVMEEygaFIr8dW0DNnDeWkqySsg7Bs1utl1YydiVNaZwUw
Message-ID: <CA+fCnZd4rJvKzdMPmpYmNSto_dbJ_v6fdNYv-13_vC2+bu-4bg@mail.gmail.com>
Subject: Re: [PATCH v8 13/14] x86/kasan: Logical bit shift for kasan_mem_to_shadow
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VbudfZlF;       arc=pass
 (i=1);       spf=pass (google.com: domain of andreyknvl@gmail.com designates
 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Jan 14, 2026 at 5:52=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> I'm a fan of trying to keep as much arch code in the arch directories.
>
> How about before putting a call here instead like:
>
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>                 if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0U=
LL)) ||
>                     addr > (unsigned long)kasan_mem_to_shadow((void *)(~0=
ULL)))
>                         return;
>         }
>
>         arch_kasan_non_canonical_hook()
> There would be the generic non-arch part above (and anything shared that =
might
> make sense here in the future) and all the arch related code would be hid=
den in
> the per-arch helper.
>
> So then we could move the part below:
>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_ARM64))=
 {
>                 if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0x=
FFULL << 56)) ||
>                     addr > (unsigned long)kasan_mem_to_shadow((void *)(~0=
ULL)))
>                         return;
>         }
> to /arch/arm64.
>
> For x86 we'd need to duplicate the generic part into
> arch_kasan_non_canonical_hook() call in /arch/x86. That seems quiet tidy =
to me,
> granted the duplication isn't great but it would keep the non-arch part a=
s
> shared as possible. What do you think?

Sounds good to me too, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd4rJvKzdMPmpYmNSto_dbJ_v6fdNYv-13_vC2%2Bbu-4bg%40mail.gmail.com.
