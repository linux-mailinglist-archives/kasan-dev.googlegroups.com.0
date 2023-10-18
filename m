Return-Path: <kasan-dev+bncBDYJPJO25UGBBJEUYCUQMGQEYG3GLSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 01A857CE2F5
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 18:39:02 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2c51a7df557sf40057521fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 09:39:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697647141; cv=pass;
        d=google.com; s=arc-20160816;
        b=OWjqV1cR/KjbrFjz0n852plHTcqDv0A7RLNkXzqEJkycE6cV7lWXhyNa7yuW/T47WN
         nfu+LLoCc3aQZc2F6J25X0WUiAv44lpRPHSRVN9LgdgYIMLUYtz+op614p00GLcgKDUy
         Ci/FRyQdx0mzRB/RS5pH33pjaiYdhVksz/guwbnSFl0mqgVQxh53TK85HEWcwmitKUtd
         WmF88gC9zcBn5VmzIkusB9PRgKm7tl/LvKl7k4+x+1OxG7K8Tb/75sEiSK2yGEGrn+OG
         dTix+6TPHn8mBRD3JWweD3HbhzZKiOmdUyuFXg0ME3UR/edJGAQBIj+X9+KAsgTECWwV
         mKqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rSR8uH9kfOpzxQo/rjAYQD32J+i67QXKmvVyDHfMb/Y=;
        fh=BJwVMxMZvPsjUa/j28oSfHZeQm3S4VBnQwgd+fRYQU4=;
        b=ENTxUq6777wDB8exk9rMpGRn/aFHF3t6VwxyPIuxSoEYzR4Z54L1qAhz36FG9Y0A2g
         8SsXyCW5E8C1qxNvtr1bwMITCAMM4BzOZVuyKii0agbxuNXUUd3dSdiq9vE+c/ieBBNg
         s6RrexDcOOZF3LqevxSVsxa2momjOHCZNDGjPlOH02P3ppm3HilZ0mRHdywVY8WVkNnp
         IkuimcIgm5PO5rghLTu9ArOpP0QGk052wUGWp40N+qjcrsjpoQPlGTuw5LqWMteu+NU9
         SFDjxit2iBNhznUh0yOBK/xRNCXAPKGD8WVt9L3xdWEfKl8Ym6rQnJNhVflMU0V8h2fi
         qxOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WwD4Zay4;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697647141; x=1698251941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rSR8uH9kfOpzxQo/rjAYQD32J+i67QXKmvVyDHfMb/Y=;
        b=PPZzQjOFHPfntlI8m/ZQDjElV8SDpfkYP2Tajcte/N4ffBzCkpNQ56PwUVMaONwQ3y
         /afM0H/CdYFm0oc0JNrdK880Z7+jzmOw3gfwa+tvC/jz2culYiYDuEjlJolJvcxbfSDZ
         KVzV8pYIWTxG0WqsMgiWmYP3s/Nd+JKgeKpC2rJJ0WxL6+leE++gkdczO3OE6AEqR+XM
         MrF/IQ/wT26csXCoDRXK+vRJqFTudN2fBWO0EaoiCsyhZkHA32dWqCGCvzYwiGQoZu2h
         H7JPUn2YdYOi9Izp+rKrEU+lf1P9spcWNWKOV49Fm1ZKM6h1M0bPra1bFllJfIPO6XEk
         yxjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697647141; x=1698251941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rSR8uH9kfOpzxQo/rjAYQD32J+i67QXKmvVyDHfMb/Y=;
        b=ksMt2pKtv1F3JfNJlr5DNKHy1syAASdxJ9cIyqQcu8+W4XePx/OvMwu7DSkYCy6c4M
         KuMP7o8SZ3cLdHSggU+/qQAJxemW6flls4rEwBJ2smSnLh7UIL5H+jrm13D4EL4rHSds
         T2CcPAESuFxCQo58fG3F1U6O3z2TQ9UwFW9mqcRaIAtyAqJFJ2z7JLHzojEOUJVq1YD3
         iiHm7gM7/aFvMEw1cPaQmHd/ML+2jMpa0W3cHoxYOgktHPfDPTf+veyjNkS/as5TMh4A
         Pd+g63BBCjJ3zYloiOeEubsANFnDlm3pWu+Aph6K5MDpDvXZ69g31gAgPZFj3NIBQ86K
         leiA==
X-Gm-Message-State: AOJu0YyZbjWas/p3AWPXivgcwyWIlDFAt4NcpFaAZhwjlmOcyMIceI2F
	D1YUkxUOqi38enclVwhUayk=
X-Google-Smtp-Source: AGHT+IFuHjMIyMI4FzeTqMy5O1nzQfHseincSqP9qQb/6BHC6GlkbaOKjQe5J7ZFL7nPk1d8gU7gJw==
X-Received: by 2002:a2e:b5da:0:b0:2c5:25f3:8e1c with SMTP id g26-20020a2eb5da000000b002c525f38e1cmr3905310ljn.21.1697647140794;
        Wed, 18 Oct 2023 09:39:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7d01:0:b0:2c5:12ac:1bb2 with SMTP id y1-20020a2e7d01000000b002c512ac1bb2ls876861ljc.1.-pod-prod-02-eu;
 Wed, 18 Oct 2023 09:38:59 -0700 (PDT)
X-Received: by 2002:ac2:4183:0:b0:502:cc8d:f206 with SMTP id z3-20020ac24183000000b00502cc8df206mr4290285lfh.23.1697647138980;
        Wed, 18 Oct 2023 09:38:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697647138; cv=none;
        d=google.com; s=arc-20160816;
        b=ME+5nHfNBBE7pzh7FBrjQkYFAV9KwiCXbzbuVM0wGA+dINq2RIJg9qn1miRF3OROxq
         RMcjVZblnucJnNdnM5XF+WBZMzXDRAU/rAjdktFV2G1p1YpbaNTrg9drdxDZwFy5FR6s
         SRgOF4OBRYxLh7f59ER4XVC4bdVBLYei8nvl+cyCZ88M2FODdDTTVhBY8PPOnyRQQ7A6
         0iWPQayDgRBeoErHUmfzYxOeGPyNK5aRbK9W0jDfMLMO3DlRYxzPdQCANy8L9xu5fE2Q
         DZ/KMmR/MwctXrofvZ1h2kitNbO0arxQffgcw/45iJfD3wknTo7SYeucwHIkDE0TosiW
         /wZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z9SF8JJcd8ct9ipQtfiI/7at0EuX7KbDRsL4NAWMQ7k=;
        fh=BJwVMxMZvPsjUa/j28oSfHZeQm3S4VBnQwgd+fRYQU4=;
        b=LjjV5BWeFYl19r8lf06m4OdHSA5Xcfbw47w2wk1tYqDX57YYtQbAP2KeRFj+wcP5Nl
         tNj3IkoeArA3yo2glf/ADCf4t0khAvN7PUssQIoMpO0erwMIew7PsoIHtHuoINCYk6HD
         Fp5dz5FhptlmzElW3jMB40NCFcrB8YjsJ5aXgRbGMYBqG8oQvUpR/Bn4QfirqadoPLOE
         9vYxr7ab4EGrCApdyawd1yjIYDAxAc0MVkJcii1ahL0OuiewIrfiq8ZGCv96agLdvSYb
         exhtZA9pRRa1G3e5lkQuXKBoTfENg8YZhj+em+IwFg0ClRp0aG/qyVnSal5PAHiNkm/m
         N2wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WwD4Zay4;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id g21-20020a0565123b9500b0050446001e0bsi167520lfv.3.2023.10.18.09.38.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Oct 2023 09:38:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-31f71b25a99so6199769f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Oct 2023 09:38:58 -0700 (PDT)
X-Received: by 2002:a5d:4ec5:0:b0:32d:8cd1:52e4 with SMTP id
 s5-20020a5d4ec5000000b0032d8cd152e4mr4431912wrv.6.1697647138401; Wed, 18 Oct
 2023 09:38:58 -0700 (PDT)
MIME-Version: 1.0
References: <20231018153147.167393-1-hamza.mahfooz@amd.com> <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com>
In-Reply-To: <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Oct 2023 09:38:43 -0700
Message-ID: <CAKwvOdkB8EDpbHjkL=u-5_ri6c+y6EMDx2sET+EEANXoSeDDSQ@mail.gmail.com>
Subject: Re: [PATCH] lib: Kconfig: disable dynamic sanitizers for test builds
To: Marco Elver <elver@google.com>
Cc: Hamza Mahfooz <hamza.mahfooz@amd.com>, linux-kernel@vger.kernel.org, 
	Rodrigo Siqueira <rodrigo.siqueira@amd.com>, Harry Wentland <harry.wentland@amd.com>, 
	Alex Deucher <alexander.deucher@amd.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Nathan Chancellor <nathan@kernel.org>, Tom Rix <trix@redhat.com>, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WwD4Zay4;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Wed, Oct 18, 2023 at 9:22=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> That being said, we're aware of KASAN having had more issues and there
> are some suboptions that have been disabled because of that (like
> KASAN_STACK). I'm not sure if Clang's KASAN instrumentation has had
> some recent improvements (we did investigate it, but I can't recall
> what the outcome was [1]) - maybe try a more recent compiler? However,
> KCSAN and KMSAN shouldn't have any issues (if KMSAN is enabled,
> FRAME_WARN is 0). And having build tests with them enabled isn't
> useless at all: we're making sure that these tools (even though only
> for debugging), still work. We _want_ them to work during random build
> testing!
>
> Please share the concrete problem you're having, because this change
> will make things worse for everyone in the long run.
>
> [1] https://github.com/llvm/llvm-project/issues/38157

Some recent issues I discovered in clang that exacerbate stack usage
in general, which is then amplified by KASAN:
1. https://github.com/llvm/llvm-project/issues/68746
2. https://github.com/llvm/llvm-project/issues/68747
Those are next up on my to fix list after what I'm working on now.  I
suspect that those aren't the last issues now that I've found a thread
to pull on.

--=20
Thanks,
~Nick Desaulniers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKwvOdkB8EDpbHjkL%3Du-5_ri6c%2By6EMDx2sET%2BEEANXoSeDDSQ%40mail.=
gmail.com.
