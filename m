Return-Path: <kasan-dev+bncBDFJHU6GRMBBBX662S4AMGQEHOJZNLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DC2299A5530
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Oct 2024 18:27:12 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6cbd3754f4fsf63560026d6.2
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Oct 2024 09:27:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729441631; cv=pass;
        d=google.com; s=arc-20240605;
        b=FwVYvQoVglL3+21OSu6V+MOwP1f8OF7Ks12kGUvB75rFntpGNDoWwV1IcvUF/05Qg9
         wKQjFh80GvYijVLJRyI5R0rvey309OFyW0B/CTen4aT5UXQ+rE17G7Do/OVNuDnUkBb6
         /144H0t3JYWOSor3+v+a3jZhFoHpchaS0kiDPKxdj0NVaNIoqyEUPTnm9eyeypapsxjV
         iVnuA75bP27NnJL/RlQAAzOMpAsksc6itA8p/zcCTWGqhUWbrZeCX/vy/5PZqHdyBA0k
         ZQr+JnuiNBWv5gtC0uNTVwSGUB9GPl+RwykwFocL04G9KqFP054gUUHYlRYFxZcALVZ2
         0chg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=uBEmuBs9oCdKaWkNcvP697NwnUxXRC6+TpZZBY3BF9g=;
        fh=h0Ib5/91NaaTxx6t2tCWa0IcZmXvXA5FBlcx+cAXW4E=;
        b=S7fuwLNWwIfJWctUsnhoQ+jVIdHti76VtW5Q3QPQes+/xvdw0Y/TsqYJTnIllkL2xW
         T/kF7OCq+baW1B7QMTqhTJw4sGYspCX1FsJ7oNjf5MED94eX8MdUgfXw92BcUZ0iIMGg
         I8kWmDk2UcAjk8e96z0qfGz7KA6yRTLxqsjWYGIZy+SngGbNvIMvKxaU2nhIafB/cgI8
         zd8hQWEZ7Oj623mYjdRxPEhbRIn9X0+to1vkuokEYY90AncGXkqHbljUELwjr1QvcUKF
         11Kx3QVkGIBtKMtVqe1FcXQlv3wQf1AttFMRNwRiegJmiVKmfg0N6wS64C4FW2EKMsju
         TEgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=Hmb9Iakv;
       spf=neutral (google.com: 2607:f8b0:4864:20::12b is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729441631; x=1730046431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uBEmuBs9oCdKaWkNcvP697NwnUxXRC6+TpZZBY3BF9g=;
        b=io2YWgAJ2PjKq0DRecgIKMBlil6kwxwidzzh9BypOcd7kY0Ue2VAyoxwJJVvldv3Dc
         euGb0UYDZ2NgfCzDZpzZ1T65f0l4lRKiVjIanyVnGM4Oo1j1CLhhkKvFklZLAhZDfIxE
         XA0pfVp3DglH4Jo90j4PU6wHceFLEg7bRkDPiWpfX3JnfBdJYohqHaWFisVrPfpowOkc
         j4cXU/yRk/ihZ/ubalhAWXsVFOLDaNfEh7Ex1nhk/R9K2ur4+G9H1UGsvGZ5mC5v6y8p
         9oDzF77g3ZsN6xvj2HXgrDgVGaMJB6IYyEkcWaXuAr6q9n3qGQAnVQR7b05V+BVkwRnz
         HgMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729441631; x=1730046431;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uBEmuBs9oCdKaWkNcvP697NwnUxXRC6+TpZZBY3BF9g=;
        b=QBCe7hX81hE6bNyI6jaLh9cTkndJFuH3K8nkgQtpE5AOCUgVkrmyf8RpHIks+9MfMw
         WpFOu+Yo0v0/Uj1uP71WauNYU4skI2XCjOtZ54yDqSJJTnEVRj5NPOadyCEEJ7sqXiaR
         QdGZLxnUDqbecoG5xMA6H1rHmfGo0fw9TYBqqoE6YdF+TbIqDPC4wBWaekHwId0WEJi2
         2JyXBWZ7RLaWXdtIOyGZgVFl6X7k2cN9jTqlLi7IP+kwTn5XOPXA0UTG+ZJ+mg2I21qM
         xbXwdyTNfVvRAisQgXuhQCFuK2Xq6JdQ52wt6s9W9Tk/PXHD5ectZMjLggrLAxoyIErC
         1chg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVRT//HSBaNlfPBdLdEaC08BnX0pjQTwcMWqyHZWw7i+Uzjwt04rtEzEGri5yLPum8U64IDlg==@lfdr.de
X-Gm-Message-State: AOJu0YyxMcbNQa9FZNTnsEsIjChL1xB8+YVgp3UpoK29TNvg6gj4irjh
	f3s5Fx+nXNbOxizAusJazeFlj67kRmcx0ED9aMTlWDW8s1jr/jJz
X-Google-Smtp-Source: AGHT+IHLam7bozMQCHg/3M/0m8h1THmYB+ROrPWBMgFDwKH+rJaCrYnUnp0h5dfBDasKRWtWmI4/Jg==
X-Received: by 2002:a05:6214:3107:b0:6cc:2855:5df8 with SMTP id 6a1803df08f44-6cde14b8327mr107864466d6.4.1729441631314;
        Sun, 20 Oct 2024 09:27:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:260d:b0:6b5:268:d754 with SMTP id
 6a1803df08f44-6cc373802a1ls39368176d6.2.-pod-prod-03-us; Sun, 20 Oct 2024
 09:27:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+evYih1MY5O0ChZS3VGouSq4qlbCfy58BCsYtKVf2fCfM6jzyWWnUlYvkmPcKEbPZd1MBOKF/QLU=@googlegroups.com
X-Received: by 2002:a05:620a:178b:b0:7a9:a1b5:26f5 with SMTP id af79cd13be357-7b157b6eb31mr1079411185a.26.1729441630563;
        Sun, 20 Oct 2024 09:27:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729441630; cv=none;
        d=google.com; s=arc-20240605;
        b=SYJ6XHFy0nnDUq0/YEF9j5mF4MFLNU+Tvt6OzXRwJD+qhe/7RV+JDN1+2nrTsbepXw
         6h3fqMnOkCK65jfRWKwUAojRJAMqJB5j4TqNOEaOMRzq3ozNZ0pYj8P/JagZRrD24yMA
         Aktt5C0A+/wFUXDoXW94L7bVWhQjLiehZ/P3DUgWMeudEqq0FK2zNgsZmqEGbMrrL2oL
         fmDPJI7hCxpNG8ItheHYJSvNx+XUW64TMrc1gZuOvvU/gmz0RYIEXp6fYdP+ptI420Kk
         1Ms+2dSdL9pBbuHxFW5nhHukSNuUs/yR+nKposdnaIFrxgpPS7FvJcPgd+6199FiHHLE
         0tFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vlJnZ2dnH0yKZQoVb1MYW1Cw6i1APoJ7tUtFkvOa8R4=;
        fh=GZzaxldLzLbqoTxRT9FSczZgSmRu7ZZr9hkmMxiR3ck=;
        b=Aarfe/vYgH8JewVfKzFHczMANNH29E5WjilgfqcHZddwHSX4+JnQKGPNvZlxg/SbiF
         bWfdDTL2a1RVICeoNA5oD+MZlDD/4+zdbogh/q3xCsPVwRQYIavUO9XGAaNbs77LjOAM
         AyoaGnDeHk9qHpmN4Uxc5k2De/6xVlmhknxL+MlOUage3GZPgudbffhCjdMuGju12sUR
         /UCH3kyXLI/nY+OE6/giNKVXoOXzav8FJjXi9PCI09hT9Uj8E0lPDizymEedwrKgUN46
         H86k4bgBMIc+JKDZb0IQ43kbQLOA911Z0dgS92z7i5PwBkxpBEZIu9k7FBmfRMi4q8j+
         b75g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=Hmb9Iakv;
       spf=neutral (google.com: 2607:f8b0:4864:20::12b is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b165935590si4893885a.0.2024.10.20.09.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 20 Oct 2024 09:27:10 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::12b is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id e9e14a558f8ab-3a3a309154aso13024825ab.2
        for <kasan-dev@googlegroups.com>; Sun, 20 Oct 2024 09:27:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSo7SxamOWFr2ewVvvd4IzboC2d1HrKRK9zWRZTOt9zuwyymXJHQt7Df3rOtdvFwIWIkZNNEyY8fI=@googlegroups.com
X-Received: by 2002:a92:cd83:0:b0:3a3:96c4:29bc with SMTP id
 e9e14a558f8ab-3a3f406fe98mr81302935ab.11.1729441629798; Sun, 20 Oct 2024
 09:27:09 -0700 (PDT)
MIME-Version: 1.0
References: <20241016202814.4061541-1-samuel.holland@sifive.com> <20241016202814.4061541-10-samuel.holland@sifive.com>
In-Reply-To: <20241016202814.4061541-10-samuel.holland@sifive.com>
From: Anup Patel <anup@brainfault.org>
Date: Sun, 20 Oct 2024 21:56:58 +0530
Message-ID: <CAAhSdy3FTjVUDBJtbsFwj6+DWjrQh3nWwvsm_1edDUO9SkXB2A@mail.gmail.com>
Subject: Re: [PATCH v5 09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions
 for guests
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Atish Patra <atishp@atishpatra.org>, 
	linux-kselftest@vger.kernel.org, Rob Herring <robh+dt@kernel.org>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>, Shuah Khan <shuah@kernel.org>, 
	devicetree@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Jonathan Corbet <corbet@lwn.net>, kvm-riscv@lists.infradead.org, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	Evgenii Stepanov <eugenis@google.com>, Charlie Jenkins <charlie@rivosinc.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601
 header.b=Hmb9Iakv;       spf=neutral (google.com: 2607:f8b0:4864:20::12b is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 17, 2024 at 1:58=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> The interface for controlling pointer masking in VS-mode is henvcfg.PMM,
> which is part of the Ssnpm extension, even though pointer masking in
> HS-mode is provided by the Smnpm extension. As a result, emulating Smnpm
> in the guest requires (only) Ssnpm on the host.
>
> The guest configures Smnpm through the SBI Firmware Features extension,
> which KVM does not yet implement, so currently the ISA extension has no
> visible effect on the guest, and thus it cannot be disabled. Ssnpm is
> configured using the senvcfg CSR within the guest, so that extension
> cannot be hidden from the guest without intercepting writes to the CSR.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>

LGTM.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>
> Changes in v5:
>  - Do not allow Smnpm to be disabled, as suggested by Anup
>
> Changes in v2:
>  - New patch for v2
>
>  arch/riscv/include/uapi/asm/kvm.h | 2 ++
>  arch/riscv/kvm/vcpu_onereg.c      | 4 ++++
>  2 files changed, 6 insertions(+)
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
> index b319c4c13c54..5b68490ad9b7 100644
> --- a/arch/riscv/kvm/vcpu_onereg.c
> +++ b/arch/riscv/kvm/vcpu_onereg.c
> @@ -34,9 +34,11 @@ static const unsigned long kvm_isa_ext_arr[] =3D {
>         [KVM_RISCV_ISA_EXT_M] =3D RISCV_ISA_EXT_m,
>         [KVM_RISCV_ISA_EXT_V] =3D RISCV_ISA_EXT_v,
>         /* Multi letter extensions (alphabetically sorted) */
> +       [KVM_RISCV_ISA_EXT_SMNPM] =3D RISCV_ISA_EXT_SSNPM,
>         KVM_ISA_EXT_ARR(SMSTATEEN),
>         KVM_ISA_EXT_ARR(SSAIA),
>         KVM_ISA_EXT_ARR(SSCOFPMF),
> +       KVM_ISA_EXT_ARR(SSNPM),
>         KVM_ISA_EXT_ARR(SSTC),
>         KVM_ISA_EXT_ARR(SVINVAL),
>         KVM_ISA_EXT_ARR(SVNAPOT),
> @@ -127,8 +129,10 @@ static bool kvm_riscv_vcpu_isa_disable_allowed(unsig=
ned long ext)
>         case KVM_RISCV_ISA_EXT_C:
>         case KVM_RISCV_ISA_EXT_I:
>         case KVM_RISCV_ISA_EXT_M:
> +       case KVM_RISCV_ISA_EXT_SMNPM:
>         /* There is not architectural config bit to disable sscofpmf comp=
letely */
>         case KVM_RISCV_ISA_EXT_SSCOFPMF:
> +       case KVM_RISCV_ISA_EXT_SSNPM:
>         case KVM_RISCV_ISA_EXT_SSTC:
>         case KVM_RISCV_ISA_EXT_SVINVAL:
>         case KVM_RISCV_ISA_EXT_SVNAPOT:
> --
> 2.45.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhSdy3FTjVUDBJtbsFwj6%2BDWjrQh3nWwvsm_1edDUO9SkXB2A%40mail.gmai=
l.com.
