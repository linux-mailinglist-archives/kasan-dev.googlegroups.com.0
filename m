Return-Path: <kasan-dev+bncBAABBWVC5DBQMGQE4SLCODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id DD032B09F06
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 11:18:20 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3df4022687esf23380835ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 02:18:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752830299; cv=pass;
        d=google.com; s=arc-20240605;
        b=MdKbmet26XlxTVFQjTTfII2aZ0c35J2F3I1293KLCH8PYtL2LFHXEVKn/iFhbigW3N
         gTRpNzloK4REvpxQr+76UAOcezdrVmGZ0cRpKJ5H5UEIuPccro33alDvM0LUjXUju8T7
         P/f8NS2FbAO34Ow7mc2PT9RzpTJQow4vu209XGkhcNjoJu6EwgmNAeTCeVTuk/nNDfUV
         QeEoFXbZ/9U4YaH8Bdi8cNNyuJSCk4lp9BkGPxfRPnx2lcKHZNFP+YnED2h/wXywseyw
         s5AnFkuJnY0Bvw0GiyEvUMg1BjeVsrdR0MYjwJ0iOCkNQTyfIRJ6ct8jGhyPPqnd4TL+
         fqIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xpTpxVBk5xs7hpjPZ71MJDUZXeW2rVQ2dy5w1vhxE4Y=;
        fh=U1jFk6sxBKV7YF1ECA1G+9Luw3Q1wQ9IeLjmezdsH3Y=;
        b=lRKEXdDUAjzDXBNfTj63mdcnqfGDP0jves+KIHZe5vIBOJ6HJoRZ85p/vVyGYpCbSR
         BfaR1bLv99lQVnRdmcQIKAlak9viSgTuQhP+fV9ta4qr1TQt/Vbt926BKWVg5aWBMqCQ
         bBOPRWY98NU4ow+vrKqoXrsGwo245aj6cScfSeqpm5mW5jCBg3iK5Z9PZxBM3jbWYRg0
         HoV2oD9AJOh/vX4OZ3mcv1muZra3lOoJEusFCt0dgaDw2bCtw0nWeNICKpBu073yguWV
         e/8c59n7aznlLSIHGwOlBt/yHpAaZOSmwpRT4c80668YQD1t1ph4A5uTN+vvjE+M8Dkd
         nwWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=upUCLIdr;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752830299; x=1753435099; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xpTpxVBk5xs7hpjPZ71MJDUZXeW2rVQ2dy5w1vhxE4Y=;
        b=ng/C43aZrYh5kjxtyQd1u8Fxer+sXJSiJeDqApAR/q9+m6ZQ4kRGc6XFLDouoggbdm
         XUsq8gtE/t+BMgJIwQRCgyZtqVqhie3RRXv0WKRrEU6BVoqfEpenPT+bu150v2pFm6B7
         8U/LLvwWVY+rezFKRU33K0Jkncb12OgK2jytfnOnnq3zPJM0SOu7NlmMwVk5fbwSfja+
         pzeZxImvOR+sD13qx0ziB8idxQ+CW7p2rJdlEf47c2eSZhuu7TKi049nB8wTu8qp7JSk
         V1TCUMulad1qD8/rOA1ygTtKOR4ghU0oI+HKu0o7RDNqufwq+akr+YdRRD28Zv/akoh0
         uqeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752830299; x=1753435099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xpTpxVBk5xs7hpjPZ71MJDUZXeW2rVQ2dy5w1vhxE4Y=;
        b=MQnXB4+POpjf8SsYu8wPPUDtaChQpf+39FSth9hBztXZsFKOCSakvo6XK0ayUtWGQt
         br/i9l8BjebacV2zG8Y53ZW2x2qYVOIXr8K8a4W60/FXuMT+kMlLTUh4tHy1b0HNsuU5
         EoXgxxPOoOX63ymSR+X2HYVmNGjkovy8af+CRcURp5dk60KpFux36rd/xvfHOqnj33Ys
         dOWy8/xCaznOw41A2azY01PjMWSZ+b8y0hLvlhWvmCJVmHPl7mTBWEDSSZiuo93x91BX
         HXPzRCvvwySm5bLs3cRwWmMx71SpHvlsFka3HSzs0fiC3WrQVN4pf83NrxdU022TpSbn
         CPKQ==
X-Forwarded-Encrypted: i=2; AJvYcCU7Wo3kVckRbjSqRnS9H8GR2CYcLqzT/uVT9ke+GCUTaAVbdquUPaM5ccfOA5yUHr534UJMrw==@lfdr.de
X-Gm-Message-State: AOJu0YwvY94klxsxElgWq8lp9NdbraiQW5klaute3x0pv6t27nF2MJcU
	Vyo1A7a1gENFFVia0k0dFuFr8yu3RUbeVQ8Rj4o9hzk3/u09mkAWlVPC
X-Google-Smtp-Source: AGHT+IEWmFuzLhduwtO9LGQLRsqysiUh+cY9jj9iLjGnS/gmiM/pD2hgYIGMsIvDQSpQmx1XQ4n+Hg==
X-Received: by 2002:a05:6e02:164d:b0:3e2:84aa:f473 with SMTP id e9e14a558f8ab-3e28bd601a8mr48110465ab.1.1752830298869;
        Fri, 18 Jul 2025 02:18:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcoq5JrZNsxrRMItxNhpo8tnVXbDgn/pndxmxtfJp49ew==
Received: by 2002:a05:6e02:350b:b0:3e2:9ab4:3eef with SMTP id
 e9e14a558f8ab-3e29ab442c3ls1016735ab.0.-pod-prod-00-us-canary; Fri, 18 Jul
 2025 02:18:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjtE/34do7rQxNTkglX4d9TMsU8miPC0kujCWz32qR7vxMzbsSptzQvF1naLSh7vZcdgqpX97OnRk=@googlegroups.com
X-Received: by 2002:a05:6602:298a:b0:87c:ad2:cf4c with SMTP id ca18e2360f4ac-87c0bc34a39mr300939339f.3.1752830296916;
        Fri, 18 Jul 2025 02:18:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752830296; cv=none;
        d=google.com; s=arc-20240605;
        b=hGx7uczC0FEuMZ158VrQsEuVAWdgKIyKRiRB8sMYAJFAr3MCou55nJ3UoBElmQKSoc
         VEKDT8mePTudKhjIZk42oqHQybth0hbX/e1+UrzkzTAD9GD1V0sOuU/IL6xKiyNModig
         GhYSmUyMObTcSSWdqsodh9op8DT0foY3XhNE6lflvmbOrjDs179hYuiP6oiEQ0A4oL/s
         +/2Rs5QR843eCTSdyvh1HKKW/grlTqsxLlll75T1KfrSwWRAgAgLe2XJmkKLOyPizer7
         NBMTZVZ6oEhEyTNOGtCK6zfzAsNf8fRBw/MYQW0qTBkDxUcmKf1kfYC10DfaQvg+f3TS
         Qnmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=04XZ3n49dipBeBmJztAm4W/QiiUkoj0gNbWiC3AXtvE=;
        fh=TC+vtTC+9DgJlbEWiD5WXyfV3/6RP9KmB9w8FEZevn4=;
        b=UnZfrYR4OnxAAtoZPpdm8mx2P7wi0WMyI2vSqR7d/wn8uFcNphfaF47HTf8INpNZQ3
         eY9Qr2j5kvXaNfk5XMfUh+ipJlmwIk5omppSdRoaY1gHjUs1ruZcpv7i9qRPvwLTEQmS
         SBesl/YaX4wMYr0AiFYM0SD/5ZoxHKkhQAzafflVyHPw0nkMOmYohuNyMi7ZJxfLvfTn
         XEPebgvMNVfqIRMqdc5nbywIxlUT1fEI9CbrERvtwwBwsRgsq+14MhX8DC7lJv79+UxY
         8zw96idVCYoYEfSGhJO2onjKz881DIc1B7HKNA+oYQDfIf5x7+jbcRGzc68yZTn+NdxT
         XwPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=upUCLIdr;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5084c91b927si60485173.7.2025.07.18.02.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jul 2025 02:18:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3D51F44D2C
	for <kasan-dev@googlegroups.com>; Fri, 18 Jul 2025 09:18:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 20228C4CEF5
	for <kasan-dev@googlegroups.com>; Fri, 18 Jul 2025 09:18:16 +0000 (UTC)
Received: by mail-ed1-f44.google.com with SMTP id 4fb4d7f45d1cf-60c6fea6742so3879263a12.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Jul 2025 02:18:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWk9O8dzMeLy3TMgoEGxBF1Y1CEbUGUeT7HYx+KFZf9FF46fbwMAgT1BegqsiCkdR4ds3ejT504h2E=@googlegroups.com
X-Received: by 2002:a05:6402:26d5:b0:60c:6a48:8047 with SMTP id
 4fb4d7f45d1cf-612d456bb15mr803449a12.11.1752830294637; Fri, 18 Jul 2025
 02:18:14 -0700 (PDT)
MIME-Version: 1.0
References: <20250717231756.make.423-kees@kernel.org> <20250717232519.2984886-9-kees@kernel.org>
In-Reply-To: <20250717232519.2984886-9-kees@kernel.org>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Jul 2025 17:18:03 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4RyZQTak5AgYj6TaXHyEefgw+wmXs9Gi8jUJWrUV5HQw@mail.gmail.com>
X-Gm-Features: Ac12FXyrA9A9-rpLV3MB79YH2kXhj6f2Fk9F6HAlk-0emUPTHthuyPP3lR9zQXg
Message-ID: <CAAhV-H4RyZQTak5AgYj6TaXHyEefgw+wmXs9Gi8jUJWrUV5HQw@mail.gmail.com>
Subject: Re: [PATCH v3 09/13] mips: Handle KCOV __init vs inline mismatch
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, Christoph Hellwig <hch@lst.de>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, x86@kernel.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=upUCLIdr;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Reviewed-by: Huacai Chen <chenhuacai@loongson.cn>

On Fri, Jul 18, 2025 at 7:26=E2=80=AFAM Kees Cook <kees@kernel.org> wrote:
>
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we
> have to handle differences in how GCC's inline optimizations get
> resolved. For mips this requires adding the __init annotation on
> init_mips_clocksource().
>
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
> Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
> Cc: <linux-mips@vger.kernel.org>
> ---
>  arch/mips/include/asm/time.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/mips/include/asm/time.h b/arch/mips/include/asm/time.h
> index e855a3611d92..5e7193b759f3 100644
> --- a/arch/mips/include/asm/time.h
> +++ b/arch/mips/include/asm/time.h
> @@ -55,7 +55,7 @@ static inline int mips_clockevent_init(void)
>   */
>  extern int init_r4k_clocksource(void);
>
> -static inline int init_mips_clocksource(void)
> +static inline __init int init_mips_clocksource(void)
>  {
>  #ifdef CONFIG_CSRC_R4K
>         return init_r4k_clocksource();
> --
> 2.34.1
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAhV-H4RyZQTak5AgYj6TaXHyEefgw%2BwmXs9Gi8jUJWrUV5HQw%40mail.gmail.com.
