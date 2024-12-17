Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRXNQS5QMGQEDN3ZMRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 64CB59F4613
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 09:31:04 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3a81754abb7sf95490155ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 00:31:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734424263; cv=pass;
        d=google.com; s=arc-20240605;
        b=kCzoBJlj6MnOjddX2KtXO2JpXV1y3fVQaw7SnSd+a+nneVZp2EmCNWGgs8Ip/aONmg
         SnW8J6hcGfcChqDWZ7Tjwxn5cFU1tlWh/l1uixk3Kmh7mN+vaA0gCDO3KCCV5bGqBDAz
         csaHoyujwyAe3VEKoZfLheRkutLUOHqjAfDfQ26x+86Mpl5ff5gCeFGIu4OaFelBn8TB
         ii6mXEasT3yapIQCpoSwRIzhrL1WikpvNE8dZo3TlQJQnvLppMHD2HF4DaUQYwuVgNCo
         sWYD4Q7c8B4mKeayh+0wswt2u6rsfyFMGWTX7upMY3QMG+CoiEtJUcgOZJfR1QASosKG
         Zebw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xdj5+Ga4gktosu/ltQf5ZTAfXYaRmJBOtDJkJBx3vQo=;
        fh=hiKR/lnDtCklF1CMxNkryXbqJrthu2FquF6ILNk1bSw=;
        b=JYWi70i6Z2J+IJDM1BsoYrWcV4rl3j96j9aS8uGIYmhId9mWZFv8/zF5hfPoRwo5WB
         pfvHJIz2RfvcdjA33Sq4K8yqZWQAR9a4QafoRqr0M1fUTF9PtSWszqDdYRTB1g7OISez
         SzW2g15CT2KuevEiwNaLriNuKowZabn1yc3o/i8qgKmE/X4RLo7D9grTlHxXfPeh5BLj
         P2BDe/kDPxT1zXSeYRNmLbwnuL5ubsYUtTTPsuNwV0rTQQT61qFcQszxmL3ckQWxTHKb
         kBMlqn1Yd5wm+AxZd8uye9VdU+BDHwlsZYXMvKhG+R5UsmxDdVrXF/0uo/fdGUgLLARe
         Rgvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MYucUwTk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734424263; x=1735029063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xdj5+Ga4gktosu/ltQf5ZTAfXYaRmJBOtDJkJBx3vQo=;
        b=IdtEhO821/JsGTGPiQUzv98f4c45J0s9f7KW1vWgeoOMeGUUa5LqYiSeTITUQsQ9/F
         UhLfFmFqBqyLDV2KHK0+NSWHiLa6zWeIXO8OBQkW+PV1ULo6DYd3/CpF4ArIoQ5Y031a
         fZG0OjUPOAfPPdVdgMnkO5/VUHQTuA0tvLR+RonnITD3KjrSWdTb8u1OQk9vkBUG303X
         mEIQ8OQ62d99gCEGpSRwn3Xq7IUpni1M0IuGCTcW+x6KPmCIwKbcZQ44L766BP3gGzAe
         L6GtOahwNpOQeNJ3mQDJHlVr4cM3brYcPc6DMO0QC0ia9uo1D4BW6zXFp1qwBE907yPr
         qADw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734424263; x=1735029063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xdj5+Ga4gktosu/ltQf5ZTAfXYaRmJBOtDJkJBx3vQo=;
        b=baJ+MnmgpAHcI3scPlnJfUZ33XLnyKBCsYM2B2SfF2yEMuLFeO+1qMURfBHVdjfTQc
         1P67VqlnZWDtth7kMt1tx4xO1BQcJGUJnstf3KtvmB3oug4YbK1VXEgwVTt3biNZFOdo
         FYR5rDXSxR7cTnbbpWVDYC4PjWWy3F/c31NEJCTR9Tc7j08i6Pb06lBy277VwiRQJWlW
         1UHTV24cZ5eiHZ51H2OVySwSCVrLWw8YhPb+7G7yv5f4jcHAOyhWlf5s/6i606OardeK
         ltkZLJsfWOM/rB4YwHCK/MmbUbOXBj+Hb2EbV+MHm05IwEAQhBDbEWeT60yzdwbeqgow
         s5+g==
X-Forwarded-Encrypted: i=2; AJvYcCVtOdZCbpXi/Hp+VTkw3fjB4SkvDtkewWRMf99Vi44W6StlsgsOS0itUedPaBmeMqVkoeG8qw==@lfdr.de
X-Gm-Message-State: AOJu0Yz9EFUETej+CKwIcENKRwmnlXJQhQJEfWsuFfIJ0G4t9R+6ak0c
	WiPWG2xOAzrIcNr7pBWZjbLrvua/JhPQ8RGrjwbq69Pl/iRWbMbK
X-Google-Smtp-Source: AGHT+IGmYWTvJebw4QUd3o7QrPyr57RkrxnIb61XxxFqldyH74BRgLilbskjjDJ8KISQ9XDCxBf6Dg==
X-Received: by 2002:a05:6e02:1887:b0:3a7:c5c8:aa53 with SMTP id e9e14a558f8ab-3afeed83f61mr139991515ab.13.1734424262904;
        Tue, 17 Dec 2024 00:31:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ccca:0:b0:3a0:cc84:9864 with SMTP id e9e14a558f8ab-3b0484fc7cbls27961495ab.0.-pod-prod-05-us;
 Tue, 17 Dec 2024 00:31:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWXyILDdO6GOV5LUpyt1pq3yRDaUICVnbW+zc41iSYULntdx0nwvcMYi9eP/spDMSyCNVEVVFj+mcQ=@googlegroups.com
X-Received: by 2002:a05:6e02:1b0b:b0:3a4:eca2:95f1 with SMTP id e9e14a558f8ab-3afedc1a2b7mr183165365ab.6.1734424261929;
        Tue, 17 Dec 2024 00:31:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734424261; cv=none;
        d=google.com; s=arc-20240605;
        b=YsyVkfgNuO8JvSOA8rGBScupbjNGtC7Z9Q5NyadX2nG61rjcTVEa5aalp0FXPjWwh3
         DMZjeCFgNrbxrGh4SAzHr/TfivR3Fde8a4FM7dfkUk0ny/fRMeij9pGTHZzpnt5PKLI3
         6HkTCdp3e6/+GrCiz5AxJx8LvdV0DigNTVdynTnRLymlk1cKFKsyv0p5OWdRXdI2xK4T
         yyAoOdNoraayQNHb8VIqt2aiK9T4BQenrwW9YQTieViISIp7wzfG3XjWR86Hm5k/uIkH
         FdaCCcrysEIQwlqjvQTUztfyZ5+OPf1pWN1sgH2it93t7Vy69ZmeSVmiWI1X63K7EpDA
         9I8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=saEqunEX3TYOKQAwnsF0CjMAlS0gmeVDyn1k5hQP5xQ=;
        fh=5TSwIhM7LfSrSus2ZCRXFqL9tUMRH7hsQi4cc2xW5Ks=;
        b=QX1cBPdGx+27GEqW93duCPZB1BzpXRhO6ws1Mag7bDLnfIE9ihUgQKJRlULR5dre0C
         4Ad88op2ItLpAXBPoyYUSZ3BwnKotX3iE9TpPVL8cMmkAKwG5DW3SUsJdPGnWdunPI1U
         zbJZ6rZ29SGznF1mM3QoeMOFnL0fN04CYTrf/qlErcuqaEauG/tGLj4vtdoeLr5PNyCg
         Y2RQ5k9Q0VQFdT78HJ4ok2LMFnZjLaxJIonlU87v4rU//JRyg0xAvkK7HgCSgBQRaEEU
         eIUfUt1ZHC6kwuTGvDttWvvwK9iOFfsWqxZXmIWsbkAWRoupWYf/biszVpYsuutPXAwD
         uIuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MYucUwTk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4e5e25f075fsi298162173.5.2024.12.17.00.31.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Dec 2024 00:31:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-7fbbe0fb0b8so3313892a12.0
        for <kasan-dev@googlegroups.com>; Tue, 17 Dec 2024 00:31:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUsp6mEFYuPhz6vCXSzE4X4L0bkXnOCuk4Lgi9iRHTRd7jxm0vHdumBSFuCm0QQtQkPjGO1KAIrSq4=@googlegroups.com
X-Gm-Gg: ASbGncshvoP8c6EjoHtEZoxyaV92g/HPgjc1QE5dzKX6hcz11+fIwDTubyX9zPQ+Gzu
	aql1GYC+80kcYnVb0cfVOQmqzjb1fcbgLVOZynfWepzuFfojt4PbgDqi1W3r41eHnUIHoCQ==
X-Received: by 2002:a17:90b:6cc:b0:2ee:a76a:830 with SMTP id
 98e67ed59e1d1-2f290d9876bmr24674940a91.24.1734424260980; Tue, 17 Dec 2024
 00:31:00 -0800 (PST)
MIME-Version: 1.0
References: <20241217071814.2261620-1-arnd@kernel.org>
In-Reply-To: <20241217071814.2261620-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Dec 2024 09:30:24 +0100
Message-ID: <CANpmjNOjY-XaJqGzQW7=EDWPuEfOSyGCSLUKLj++WAKRS2EmAQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: mark in_softirq_really() as __always_inline
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MYucUwTk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::535 as
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

On Tue, 17 Dec 2024 at 08:18, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> If gcc decides not to inline in_softirq_really(), objtool warns about
> a function call with UACCESS enabled:
>
> kernel/kcov.o: warning: objtool: __sanitizer_cov_trace_pc+0x1e: call to in_softirq_really() with UACCESS enabled
> kernel/kcov.o: warning: objtool: check_kcov_mode+0x11: call to in_softirq_really() with UACCESS enabled
>
> Mark this as __always_inline to avoid the problem.
>
> Fixes: 7d4df2dad312 ("kcov: properly check for softirq context")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

__always_inline is the usual approach for code that can be
instrumented - but I thought we explicitly never instrument
kernel/kcov.c with anything. So I'm rather puzzled why gcc would not
inline this function. In any case "inline" guarantees nothing, so:

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  kernel/kcov.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 28a6be6e64fd..187ba1b80bda 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -166,7 +166,7 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
>   * Unlike in_serving_softirq(), this function returns false when called during
>   * a hardirq or an NMI that happened in the softirq context.
>   */
> -static inline bool in_softirq_really(void)
> +static __always_inline bool in_softirq_really(void)
>  {
>         return in_serving_softirq() && !in_hardirq() && !in_nmi();
>  }
> --
> 2.39.5
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOjY-XaJqGzQW7%3DEDWPuEfOSyGCSLUKLj%2B%2BWAKRS2EmAQ%40mail.gmail.com.
