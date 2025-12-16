Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKPEQTFAMGQE7G4STDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 46BE7CC1F01
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 11:19:23 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-657490e060dsf5479444eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 02:19:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765880362; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gq+8BfS9ObOXG9EHXXPmYctS3bfdF2u1KbsCGg8+4TS/+fT6oqaGHImPfHje333NKZ
         Tt9gifb1vHtLKkJiNJHc0Pr/htfQkudZ9EJGpUAeWoGh7a/bx7tb6udN+sasAfy7RUmE
         mFczJq2i0UW4cTQnHPHaWTTKNKGlfFhMkzYK3qm551nucC0BbOMGIWHbp41gjva+mLlK
         zc7/1kosPFBuqLlukVkTLYcyaCy8fNsJie+3TUtSvtALXHPd1RxCT6KlhLhC7cr7yrU0
         N30spY79p1H1RSoK5BWPkx4L4RIHWpgRv1zD/4DRyE/P6qatcioh66tJMLXIQ41DYGNR
         k+Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bVMGtmw0seLuZEVzjO4neeFeqTnZ3xodF46yFepXAr4=;
        fh=VI6Eh8OLqVTxHL5NRHaUU9lIwc5Dua4YXSIFIZes9yw=;
        b=jOAUTEJ5/qb18X0JcHSxCSaHol1MXU56kciebtPkhC1up50L+zJHw/EuN6YWvvZayC
         MuqOr42+u9u12wpUMZgVk4Fzcfofqotq2iLAuXPa3gJFWY2InkAOf1uksElmUERBgEhg
         HGLjk90+5Ybw8g0aAG8VLpWPXCVTJlLNudS6qlxtPWP7v2l9/BPNFONSMOOgZeFMf8lR
         KM7afRuVyILqJeNUpytKP+z2jQHPfkfyybS+1TRfNISf5jd+Z5irzOELkjLoPM70EmNc
         cz2m+J8W8CJmWSYgAO+QSM2IVjk+NquovNXbCDBwduJQDKErUOEB7+Yea9qo/pIygVml
         C3Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oxUFM3BI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765880362; x=1766485162; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bVMGtmw0seLuZEVzjO4neeFeqTnZ3xodF46yFepXAr4=;
        b=eWDRbX80GD8tm3XzJ0d4h8cckCrvW6aPcEHScijlRk3wj9J1sVjCyKsnR9PE/RB881
         TbuaqPbujh6z6JaZyZUor0Zl/ifyQg7ivuE3bVLEkorcke97HG7O8imUea86Gs4NP4rL
         KYgpuNth/s0wUFsPJyna/mbNPVW1LFXwsCc7iDEqP7UuZmaGmpuqqtHPEX3juHQR1MzA
         KXbNgsMQJ71KLF626s7/0JlBHVwmUJ1Teh10CtvVSuQ+fr/xXDebGK/2kpOWAss+PjC+
         J6YeLLHd6y68uktlTOxiPJEflbIlV0UdeSkmSd/v3oNDnBMrT1hAW16FJmdHHbqLYM/C
         7SGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765880362; x=1766485162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bVMGtmw0seLuZEVzjO4neeFeqTnZ3xodF46yFepXAr4=;
        b=I/yzJrcI+fJGJEamHIHXUevJOQs4gl3K0xLBPjC/+tj3CaRSq48o+8x2BYTJ1nzVQ1
         fFyZcfKml5UJuYSXTpqg3QlfCgfW22AKBD9u4Dla9ysAKVlt8YU5ApKO3/xi7XR5o3Y7
         FuyAVqY7TMzhffPssvyiItH1VwQzF+05UiytRLpZ0i9r46Qd1q4pcY8cgDBt6d1w+O7c
         bNNAhaXv21Np1LNevCkADlkyetDDXAudb+otecbMrQGCfql59fdfePd7Bi2me1NX0TnL
         x6PwgiYPKXkf+FVPfoxiOD/iAsGOsfZ7u9I7vCEBkW+BF/YNxhzGsNWf7JkqftSQEMna
         y0+w==
X-Forwarded-Encrypted: i=2; AJvYcCVk+eIjQrtrCJg8GEm0EjfgtMLcaq/ddDhQ4ETUbfbbCKkJmMJHM7+n04NJq8O+dMppFvNuBg==@lfdr.de
X-Gm-Message-State: AOJu0YymR7OgbFV+RrP4azO4zDKT4z7hYbX06uh98jR8xgVQg68PA5nm
	lLYCwP2xNrIwVFzQQ1B/Q03PZDayaYQ4sldMDbtmLZ5itKHcVqg+nKhW
X-Google-Smtp-Source: AGHT+IE/cPY8ixVhdOcfjsRQt+2g3hIXid0qwfA1WSNZIS1KDjTsrPB+mvTS+w9HzKOZgO3XQtoiAA==
X-Received: by 2002:a05:6820:4b16:b0:659:9a49:9055 with SMTP id 006d021491bc7-65b4518708dmr5871235eaf.32.1765880361850;
        Tue, 16 Dec 2025 02:19:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ9n+tP9fwMsL401Lj6B4vOOcKLUGraXbO8ukByyPy1Rg=="
Received: by 2002:a4a:d344:0:b0:656:dc35:485c with SMTP id 006d021491bc7-65b43960337ls2466955eaf.1.-pod-prod-09-us;
 Tue, 16 Dec 2025 02:19:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUciBRFWuOCorNx9OQnyaxwfF8XE9hhd7LtBDXPRShC2yvDxv9tahyL/gw4xsQ+UPn6vRlBNuDrHlY=@googlegroups.com
X-Received: by 2002:a05:6808:bd6:b0:453:77d6:1784 with SMTP id 5614622812f47-455ac93508bmr6243770b6e.33.1765880360841;
        Tue, 16 Dec 2025 02:19:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765880360; cv=none;
        d=google.com; s=arc-20240605;
        b=QJFAa/lelPFV+plqfg0QJ5kE+NwSwYH/VfOGt27eQ3VeKqc7O5fjQrJNNjkvXyg1up
         3lFB/2d2vcAyK2EpsuQYmd/5Jp/ngEsNagDUgts2N4b9xpyAJd/MKqfhqABHZlDvXw+F
         T3MVtPKF+G2JEnDtcXWBlIerGW1rZvvk6Ut3iL/tH4UQvlMYAY2948NsfJTmiYh07Cfy
         Fy88F5KyoT3xl3T46ktK1Pu/0heLda9vBCwUSAEACZedn1xqaHNDHTfhfhIlojgL+Ugu
         DS0F9xK/VpQm0PMjfMAh29mAWUWiWF2+bxnESRrA7/IUvOQ58bH4lfFvxsUsAuoougVn
         6Syg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OypqLsil5xBkKa5aVXNNZdJt/nIt7Du6XmfYVCVljvI=;
        fh=U3zFnaJkQpLk7yiXNHikq3isu9D6zBngxniFckFx6oY=;
        b=JJ0q2ydOO/ft+MD7/Fo3MADVjG4yR91ue8mM9tKMkOf+0f1mDVTANeWjto1pU2JjvP
         QtZCYGUQpkK8/H2++G53fioxhYX43/oAzdNO2QBp4W4j3AO1grZHvIYUdlvQmb9FRB9M
         rlFUAMGcukBkaFKBuRfUp5Pbj/20VcgjJI1v9f+WpElpnX4hHR1G8PfLZaHxqovCc4LW
         CNjoMSY8c9zajEkHiIj9hs0hrJhDU0MjZb5wG0CXV8sASztj9ualgnby09bpmJCweFDZ
         n3FSSTM0kiKIL2R2yNifInD125ZVKdMyOsGylwtM7mWWHI05p12d8e6bI4W2ZSufjNpU
         D+1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oxUFM3BI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3f614e34af8si308493fac.8.2025.12.16.02.19.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 02:19:20 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-7aa2170adf9so3524346b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 02:19:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWs36fm8iTjDdOvMgShTITeAE8xV/g31F16LjEVUUj8DzEkqZYL70Yp6JlVEsQag+N7diAAkiBReus=@googlegroups.com
X-Gm-Gg: AY/fxX6eCYT+eIsi8OmJn71UMY7ilfpzwtdBE38OyDoHCLzb1DS5ORWIhJnG63VQkOM
	KJO/hwcNI8yvEW185m7KsHpZBtujcjy21ecQHLjvQwaXWPLtT/NZBRLMtzYXckB+jtszF8qnXuG
	nB4rnEa6Kw82p1BpErRGTatJ9hrfXzpv3AK4vZw6Hp0Y+k9wImsfOcVCWedmbNr7KVhrHctJBz/
	8g+qvan8oBSOO46ILxaNv+JrMO86t3mI7vIUNKl3ONw2t11XlvxsIgwr6wHzSi0V5ousVAhr0lP
	GIzDg85AhMjtlfSjime3GeLWnw==
X-Received: by 2002:a05:7022:61a5:b0:11b:9386:a389 with SMTP id
 a92af1059eb24-11f34c71006mr8757169c88.44.1765880359439; Tue, 16 Dec 2025
 02:19:19 -0800 (PST)
MIME-Version: 1.0
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
In-Reply-To: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Dec 2025 11:18:43 +0100
X-Gm-Features: AQt7F2r-TNi3C2dkEfzWWdFLAvdsJ9j2DX6plsYqvw6Qsd-tzVkmo5-aWx03RSw
Message-ID: <CANpmjNPTdnReD1rmdyGPvpOqp0N6yc=XMfmdnNdgVrptGTTaVQ@mail.gmail.com>
Subject: Re: [PATCH v3 0/3] Noinstr fixes for K[CA]SAN with GCOV
To: Brendan Jackman <jackmanb@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=oxUFM3BI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::436 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 16 Dec 2025 at 11:16, Brendan Jackman <jackmanb@google.com> wrote:
>
> As discussed in [2], the GCOV+*SAN issue is attacked from two angles:
> both adding __always_inline to the instrumentation helpers AND disabling
> GCOV for noinstr.c. Only one or the other of these things is needed to
> make the build error go away, but they both make sense in their own
> right and both may serve to prevent other similar errors from cropping
> up in future.
>
> Note I have not annotated !CONFIG_* stubs, only !__SANITIZE_*__ ones.
> That's because for global settings (i.e. kconfig) it remains a bug to
> call these stubs from the wrong context and we'd probably like to detect
> that bug even if it could be eliminated from the current build.
>
> Concretely, the above is talking about KMSAN, i.e. stuff like
> instrument_copy_from_user().
>
> Other than that, I think everything in include/linux/instrumented.h is
> covered now.
>
> Signed-off-by: Brendan Jackman <jackmanb@google.com>
> ---
> Details:
>
>  - =E2=9D=AF=E2=9D=AF  clang --version
>    Debian clang version 19.1.7 (3+build5)
>    Target: x86_64-pc-linux-gnu
>    Thread model: posix
>    InstalledDir: /usr/lib/llvm-19/bin
>
>  - Kernel config:
>
>    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657174f0=
537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
>
> Note I also get this error:
>
> vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !ENDBR=
: machine_kexec_prepare+0x810
>
> That one's a total mystery to me. I guess it's better to "fix" the SEV
> one independently rather than waiting until I know how to fix them both.
>
> Note I also mentioned other similar errors in [0]. Those errors don't
> exist in Linus' master and I didn't note down where I saw them. Either
> they have since been fixed, or I observed them in Google's internal
> codebase where they were instroduced downstream.
>
> Changes in v3:
> - Also fix __kcsan_{dis,en}able_current()
> - Link to v2: https://lore.kernel.org/r/20251215-gcov-inline-noinstr-v2-0=
-6f100b94fa99@google.com

Acked-by: Marco Elver <elver@google.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNPTdnReD1rmdyGPvpOqp0N6yc%3DXMfmdnNdgVrptGTTaVQ%40mail.gmail.com.
