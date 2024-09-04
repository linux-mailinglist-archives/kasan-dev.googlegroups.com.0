Return-Path: <kasan-dev+bncBD5L3BOATYFRBYU74G3AMGQE3RV2DJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D27C96BBCC
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 14:17:40 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-42bbad819d0sf49022385e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 05:17:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725452260; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uli3GqKK9cMEQrfl8Hz7qqWXc3jwqvGPQwjGuPuGVqV86onblkzfG0cE6le7iqcv44
         vmUbJBEf8nCzwgKp9G7TN8EszngvGNeG95YkB4uxjSCdF68DahwcnCI6qubZ+0tN2P7U
         whFnKBpeVWdN+gJR7R6i169jj4RVkqr2JKbhXKVIWlVM/dGKkxR8lysXZT9feHl0JQYF
         RKx4U6Odz8ESIZ7alqu+Gicb+ZSLFztDLah+p85iXgbz4UsQChchCvPVY/wRjwjo4G+c
         xWcqYPQ09XaWipB/C9hE+Z23BQ++1+mgnz9YrGbusUMyXPzXo9RXRkNT6r5AlE7fVO53
         91SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=liXV+n2h5hbumkDA/XsY3zTX2oYSywY33CRX5UDHccM=;
        fh=QAHOG1hFo6AOczjnava/vlG6jU9/A0o7LThXLgYv6oQ=;
        b=KTd/vgXKszsbQBHgdxRQmQZrxPgr82t6JNF0bkklBSxsdjty2Yfwtyqht30oupyB7D
         6Z4Brqs+aBjPziKtMbCm29/9UJFhN3jeQwPNWxXAiWNTIHbvNUWQYUNIP3q59Rls5GhF
         cCuErs4H+F9fCe2OMxDLyUVS73LCb4OoTPp6SV9BGR/SMhrGByLDDqJQQ+CN2hYO5Sgx
         Q22ca1NmFTPX5x+WIco7TlRBOezt+H2Dr9yWGd50Zg9bnrTGdhNKiDEqIAbL+L2iH+N/
         WxuoYECEv08OPkejRU0XinJ1uMmLp/K8bkBAedZHjjpw3+UN2EE4N/q+fq4y8DVMD5Mv
         fXWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=FQ3FOs68;
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=apatel@ventanamicro.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725452260; x=1726057060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=liXV+n2h5hbumkDA/XsY3zTX2oYSywY33CRX5UDHccM=;
        b=eW63Tg4j+fAi4CisFMUKsoVrjd9x0ByQik18RG4q1NotS3HF1xJZ1GkqL+yWoCodSS
         cIrXh/jWCBd/DbZVbmjSo2Is+29k7WTJXFvywaP/UsZUXkHSPrrlHIEUBa/xoTdcBlLl
         9lIdJRRhIc46RlMaDfBuNGH0ejrWtmZLZiXeybCSx78S0fWRUT/1Zoh3k9o8V1bxzdP+
         sZmOacPJFDDfPn9pOP271dKRetAoDD8SNpF0sKV9URpRFqN4bQvivjfBjz/vK+JbmDZd
         pTc6dFwmcluch4NkWKfwSYn2pvLE11tbWAUYYb8u5rotg7bNt7xdPJdqVCi3PWncxsPB
         dzwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725452260; x=1726057060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=liXV+n2h5hbumkDA/XsY3zTX2oYSywY33CRX5UDHccM=;
        b=FMPqUY5tBEbdlJ4eDepZb7TS8rWNlGUfiawb1xxW01GgJuapnCjvjLcQAbl9CWGSLz
         ZNHtY39Y12r5ptQyV8B/hFaobmo2uVO3wvLwvAsEvfUvkJKwOmCKkIiEX8wUSgBKNiC1
         r4fkxkzG1j4YAUJ8I9wfrod606gXcNql1qz77yMNfNevTUSqIzAPsbgWS1j0NnMJN3mJ
         OQNShbROQ8WiRILXwDPZ+rxUMVRYtmRskUliyEbVwR+TmF20hlC97WjHi8s++xPiLTgM
         nvc7yWHXi21EzBiDZFBbWlaip+WAj/ez5QzhTi38eT44tLbnPp/+yU+4d1FFNBo+FHme
         R8bw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbkrPDxZydZGwJChk41NyHaEBULPByu4wm5C+gyvpbDfIRjws9EN/AhPeQrWEcpX6xEaafdQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzdp9jmm4p33snLCO2RfnFP3O2LWgqBhgV5kL9H1S8sJxaDVK5m
	3PCQttsi1ie/gG9V5SdeuQ8Ag7ho71Cf6OA47SROOy+QQFP9wAva
X-Google-Smtp-Source: AGHT+IGhim2FjdKUurd9rMKAvvwDK3tW09E3sFcybGsukFgSCKM5pvEQNujxx+8F0tY/zeY5sDYJQA==
X-Received: by 2002:a05:600c:3b0c:b0:429:d43e:dbb9 with SMTP id 5b1f17b1804b1-42bbb436ddamr120172805e9.23.1725452258942;
        Wed, 04 Sep 2024 05:17:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4506:b0:428:7aa:dab5 with SMTP id
 5b1f17b1804b1-42bb283e022ls21717465e9.0.-pod-prod-07-eu; Wed, 04 Sep 2024
 05:17:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzneT2t+GC1fNn/2CbdFeoYsaeLwuX630F7L9/tG68Y0TbwJMOIUWqLlsC1Cfwv1hIxYuhB9X0nQY=@googlegroups.com
X-Received: by 2002:adf:e94a:0:b0:374:c90c:226 with SMTP id ffacd0b85a97d-374c90c0298mr7969988f8f.9.1725452256870;
        Wed, 04 Sep 2024 05:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725452256; cv=none;
        d=google.com; s=arc-20160816;
        b=Oq8C8QAFQX8owlZDSryfNQD3+mRaV6QKdrmwl7KlaTlRoFst0tKytltWdhyF3IjSMG
         hlem3dLUi7rfvOQ/rL+jhc2l0i5ytypYMxLyZFjuLVnQ47LLDbtcOArjBBhjtOP0IdFx
         lMLt6AwUuosKHkiVJYpsBfK77BoPnH0oP6Jr2ir+CmYZU5yboSRlBtQkhSUEGI98csAi
         Mnk4381QMXAajac8xJxKs1DrwfumQNYZJs5UmAobAvMYwKvi9m7gaVwawANsVOtE0o/j
         kqDSa1nbFPHAxCRWVCCDE+gg7QOaG3o3elipjNvFvt5PD5dJMJewnUUQh1L7xKKnXk8N
         /kzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jlAAsB7SoUZZgOYwhXzTNmhBITwqQOW3TbtLYgYnb60=;
        fh=98FWJidbgjTjyJc6MTsDRys6Zumbco6UEbdi60oGTjQ=;
        b=CCRA94nfMo/8CeULmfOD1hKY76PA3wwf8DCEve5k+6+6RqouT9UyYs1DeO1LiSKUu2
         OELDJ5Wb8ByLg7ZQAog3TRT5uNZqxo0H1UegxL7PLsWeV+Ky7LP6EnNv0ZrA7p2W3qIl
         mmpLdRC/W1FrV8Vz3xWWk1B8d/vQC1R4XpFLWXJ+X74QNt+mQeHsBsEJPYPF0/3SVfbk
         qoWM/t6+meGhxORqMHEenaOSLfRcrkxlr8zMpCUJExcr/yoVvpHRX1eZGg3lcYA+/3Vv
         Xw+tVp5O7WW209GhvxKEhu6rJ9OF0GGzOGLIDZ/penttIDDe3+65n+PxqfxWdiX7OqHy
         bMlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=FQ3FOs68;
       spf=pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=apatel@ventanamicro.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-374d26c0159si94307f8f.3.2024.09.04.05.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 05:17:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id 2adb3069b0e04-5333b2fbedaso11409104e87.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 05:17:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/1JHKIGg8x0YMzRIpfXnexzYpzNT1k228TfEcfGA+tACFjLYeY8284z+e8MBVD/8xUiLzUWQ/6N4=@googlegroups.com
X-Received: by 2002:a05:6512:2211:b0:534:3cdc:dbef with SMTP id
 2adb3069b0e04-53546b8d6d5mr11049948e87.43.1725452254963; Wed, 04 Sep 2024
 05:17:34 -0700 (PDT)
MIME-Version: 1.0
References: <20240829010151.2813377-1-samuel.holland@sifive.com> <20240829010151.2813377-10-samuel.holland@sifive.com>
In-Reply-To: <20240829010151.2813377-10-samuel.holland@sifive.com>
From: Anup Patel <apatel@ventanamicro.com>
Date: Wed, 4 Sep 2024 17:47:24 +0530
Message-ID: <CAK9=C2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g@mail.gmail.com>
Subject: Re: [PATCH v4 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions
 for guests
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: apatel@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=FQ3FOs68;       spf=pass
 (google.com: domain of apatel@ventanamicro.com designates 2a00:1450:4864:20::136
 as permitted sender) smtp.mailfrom=apatel@ventanamicro.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> The interface for controlling pointer masking in VS-mode is henvcfg.PMM,
> which is part of the Ssnpm extension, even though pointer masking in
> HS-mode is provided by the Smnpm extension. As a result, emulating Smnpm
> in the guest requires (only) Ssnpm on the host.
>
> Since the guest configures Smnpm through the SBI Firmware Features
> interface, the extension can be disabled by failing the SBI call. Ssnpm
> cannot be disabled without intercepting writes to the senvcfg CSR.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> (no changes since v2)
>
> Changes in v2:
>  - New patch for v2
>
>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
>  arch/riscv/kvm/vcpu_onereg.c      | 3 +++
>  2 files changed, 5 insertions(+)
>
> diff --git a/arch/riscv/include/uapi/asm/kvm.h b/arch/riscv/include/uapi/=
asm/kvm.h
> index e97db3296456..4f24201376b1 100644
> --- a/arch/riscv/include/uapi/asm/kvm.h
> +++ b/arch/riscv/include/uapi/asm/kvm.h
> @@ -175,6 +175,8 @@ enum KVM_RISCV_ISA_EXT_ID {
>         KVM_RISCV_ISA_EXT_ZCF,
>         KVM_RISCV_ISA_EXT_ZCMOP,
>         KVM_RISCV_ISA_EXT_ZAWRS,
> +       KVM_RISCV_ISA_EXT_SMNPM,
> +       KVM_RISCV_ISA_EXT_SSNPM,
>         KVM_RISCV_ISA_EXT_MAX,
>  };
>
> diff --git a/arch/riscv/kvm/vcpu_onereg.c b/arch/riscv/kvm/vcpu_onereg.c
> index b319c4c13c54..6f833ec2344a 100644
> --- a/arch/riscv/kvm/vcpu_onereg.c
> +++ b/arch/riscv/kvm/vcpu_onereg.c
> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =3D {
>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
>         /* Multi letter extensions (alphabetically sorted) */
> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,

Why not use KVM_ISA_EXT_ARR() macro here ?

>         KVM_ISA_EXT_ARR(SMSTATEEN),
>         KVM_ISA_EXT_ARR(SSAIA),
>         KVM_ISA_EXT_ARR(SSCOFPMF),
> +       KVM_ISA_EXT_ARR(SSNPM),
>         KVM_ISA_EXT_ARR(SSTC),
>         KVM_ISA_EXT_ARR(SVINVAL),
>         KVM_ISA_EXT_ARR(SVNAPOT),
> @@ -129,6 +131,7 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(unsign=
ed long ext)
>         case KVM_RISCV_ISA_EXT_M:
>         /* There is not architectural config bit to disable sscofpmf comp=
letely */
>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
> +       case KVM_RISCV_ISA_EXT_SSNPM:

Why not add KVM_RISCV_ISA_EXT_SMNPM here ?

Disabling Smnpm from KVM user space is very different from
disabling Smnpm from Guest using SBI FWFT extension.

The KVM user space should always add Smnpm in the
Guest ISA string whenever the Host ISA string has it.

The Guest must explicitly use SBI FWFT to enable
Smnpm only after it sees Smnpm in ISA string.

>         case KVM_RISCV_ISA_EXT_SSTC:
>         case KVM_RISCV_ISA_EXT_SVINVAL:
>         case KVM_RISCV_ISA_EXT_SVNAPOT:
> --
> 2.45.1
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

Regards,
Anup

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK9%3DC2WjraWjuQCeU2Y4Jhr-gKkOcP42Sza7wVp0FgeGaD923g%40mail.gmai=
l.com.
