Return-Path: <kasan-dev+bncBDFJHU6GRMBBBB5C4G3AMGQEDNBZTMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E9F9696BBF6
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 14:22:32 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-39d505a087asf8072535ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 05:22:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725452551; cv=pass;
        d=google.com; s=arc-20240605;
        b=J8IIbix+wb/JRcXJisOZGinOFNQN0MGjlt0QtAfx1Ysa7HyrPgreK4ZMSeR/O7J5fi
         Al+juFFW/Bs2qt4/h/ko7yoKvSu6fOj3nSKEsvfEkN5+5wwMIy8y4EayH0JFx+keSez/
         Tlrv8RW2DcFJF6/6bFxaD4oCFZc30OJ8O8wcTMQHeVjZuRv2egWH5EpgJ1LayTsp411A
         KhmvN5mnE9CbwlVOeElclr8Pk3kxgdEhRkvd6qxHfHUUbnCVfO3hkN0tYu2iLZow0spj
         vlhyA67uVNUBYITuwvdUDCW/3NLjdrSMviWOQzZgFmbZRmo4mAkRrPRO6xsa+cwRg6yb
         iSyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=/G38W6QrV5JM9ysCFlNTsTQ7/PHyXr6RtK1vdinqTsQ=;
        fh=T0fzebUQZ8Y2Y+6Rjjl4rKKMh5Nq6IY9iH7AvDy8/c4=;
        b=dm+SU+Xzpj49geX8YWMT2V8N/kiURm84G/rqInJpRtjWwvcMLMl7LGZZQ0hv/uQ3F7
         lfouc39D2JaYWRwxDzmVwt9uQMQt0+ZHHWaIOJKS4M+RN5yg3m2t9jBQ3zMy2pY15xIJ
         Hq0Htcf4CYvDyMx+EKny/+6ypBALmZQAXbssVU5RIN656zLNZPDkl+2HuPNRpXWMcDEu
         gZClV5nMet2GvddMm9TFKSdIPH2IDMc8lv9Cmdjl31wlicgmy0HFlwEcAUzhyL3JKXUX
         lmft85Vb2+Z1cF5qzLZ3+AuNIGDrX6+HEa2ob8fDeZHMMADmS8wYs6cXneO9JEVgluAt
         iZOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=GA2nDUz8;
       spf=neutral (google.com: 2607:f8b0:4864:20::d32 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725452551; x=1726057351; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/G38W6QrV5JM9ysCFlNTsTQ7/PHyXr6RtK1vdinqTsQ=;
        b=dTN9alO59il99PZPPWJ9imhWH4S2VOWF6YL6+0630da9J1du9io+ha5YdA2LkK1A2v
         um2yX145oXAXbGZZkXnDWLOttndjSNlGu58xW9g57Znpu0clVDwcXOynd9C9cZjc3CFR
         pYT/HimrEUrrJcnDIN/b+wDb3V9uvnbKVJZFRfoVCxWtGd2EsKkZYx/rRCDFCuTI//iK
         mh2UI1r9iJhBaCnADbnPrX1LRR/oSrg7uI7KV+8Zu2qaNHnIk7x1a8ScahA4BSGfhT6r
         YANCOdGo2lc6trvoUVua0198ifA0LuyPB/AOiWfCyBRHRZEIOAEv0ZYhC55Cyo5nWsr2
         lQ6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725452551; x=1726057351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/G38W6QrV5JM9ysCFlNTsTQ7/PHyXr6RtK1vdinqTsQ=;
        b=Pq3HbSI1geIWSs260yPS50rLJF7QEq5im5WlG6Q4XYb5AZf8wUTD2v3fIwZSR1seZs
         NhUMZtK/bvPUMW60Xj6L+llKEKU1nD7CDbp+FX9DzUIN+dxPx9yGMZlMIW+9V8VsLSNX
         /pLK/egDo8VcooLeyXxdZM7U6afKhNXZG4PP9nd3nBss3WwSf4tw18qCInKMIE9ZMu4v
         z55+85dlY0R6wgmqJDNs4hzZm6u1n45uCCEXa9g/yzPGzweJW8KPSHE8BdVXJSnOzmpG
         urJxgwu+xhKo6AJ/WjlkhrA1FTX1t4hQtUlzyDNjU81bV8q9C3Ck2S+0cEZ0fbYcVAGb
         em0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVde8Nfaj/zjiJmshfvTtOF/M37eXgP4nF3FefHbEqWzC6+jvitYkFFpBreLSImVmXf8A/a4w==@lfdr.de
X-Gm-Message-State: AOJu0Yw9WBVFipEf0y5CxgzUr4ghWvSwsdNmNBFdpyu5sjwDyqEHPKh4
	TCI8tgW5H6c0JRiK9xYXVAC8kradS4e5RUyZkmerAP4xGMIzNu6j
X-Google-Smtp-Source: AGHT+IGliA0TnTVKyXLyPcqGtpYgori6OXuZQ+SHQY7RBHnpLizk+E68//Ihy5xosZKPIKCqOeKVQA==
X-Received: by 2002:a05:6e02:1a0e:b0:375:acd3:31b3 with SMTP id e9e14a558f8ab-39f7978eb8fmr13213195ab.5.1725452551452;
        Wed, 04 Sep 2024 05:22:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c14f:0:b0:39f:57ce:7264 with SMTP id e9e14a558f8ab-39f57ce74b9ls12980675ab.0.-pod-prod-00-us;
 Wed, 04 Sep 2024 05:22:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoSLWscZKlNU+RAn7qBAZKRh4Y8xUyKbHXkbV5mKKAWbg+U70JY7ighQogbmhIlRZIncPHFHeCkA0=@googlegroups.com
X-Received: by 2002:a05:6e02:13a4:b0:39b:35d8:dc37 with SMTP id e9e14a558f8ab-39f797b951emr15636695ab.13.1725452550656;
        Wed, 04 Sep 2024 05:22:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725452550; cv=none;
        d=google.com; s=arc-20240605;
        b=HY29Hhv2nwM84wKq31XXeCIdUPmhKHknIJ/DRVkVF4kdjVlPE4lLaYv/5PGUgEuIlH
         Z1NkvrzPZFTghvFGDKkUkrCNJoqEorI8MYYlrET1bfh4oAO/9Y9mzwoT4bShs8w+v45J
         71qHNL8IjnLxiGC1m3fu1q+8hS3iElNkGsQwykAyjZn4ZybhuiQAOy57L9dUMaC8cOt9
         k6cZDZMCXPqygyE/6CyEeoVOfZDCdcVGVQxJQJLWPNilHhCyIw6jZC0y05XL791nRz7m
         OZr1hXeNdOXlgvU2UnYqRFELylRh+EkM/dRqk5Cv/TyH/hE6YHIIS7GLMfxUgJx1si/q
         0Qog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Ju9Hq+FgR4Nn2GcAcehqW18ZWQc9xC6Fkglr1yE5YOM=;
        fh=ESTmNvo6cyfbwe8FOIQs3U68wNDJ7BIGBe1w2fe5cQY=;
        b=K13VrTgHdLyUD+QDiVWSRhqWZnh4gwMnMhoPmN19aH4Kpitq92SdLrhzlTwjbAGmT5
         IRMuRdgmOBGrRlmG9tYE6grKbb+g/EucIMSn/JU3eQHu0qmA08VlOXJCVyIyH7O3X6k4
         Tn2jfZI6swHEDLWW8wEl4S6B6+plOQRJjyjVYFGoIsIfzd16Qe8omue80kXeF80qaEil
         9R8XbqW/GtlqVCRR98R9+wbwrjyhc7K36ACRD92NKzimm2G8U3GVufdq9icGvYYIoE0L
         NLyL5GzrFdV6rnrDUSgTvjcx2+chUyWsf8DNatCoABIgnhwQQBaXz8UKRo+P4umi5gl9
         h0FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601 header.b=GA2nDUz8;
       spf=neutral (google.com: 2607:f8b0:4864:20::d32 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-39f4938c4e0si4071415ab.4.2024.09.04.05.22.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 05:22:30 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::d32 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id ca18e2360f4ac-82a32294b27so22241139f.0
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 05:22:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVT9q/LpoQO31mMuNA/brS/LPUOp1uS56+8SkXWQ6WlIEhtkpJG6cxSSH1WdKYxTMEk8KP8EVyfY/Q=@googlegroups.com
X-Received: by 2002:a05:6e02:1c46:b0:39d:4dab:a533 with SMTP id
 e9e14a558f8ab-39f74f88f94mr14510545ab.0.1725452549998; Wed, 04 Sep 2024
 05:22:29 -0700 (PDT)
MIME-Version: 1.0
References: <20240829010151.2813377-1-samuel.holland@sifive.com> <20240829010151.2813377-11-samuel.holland@sifive.com>
In-Reply-To: <20240829010151.2813377-11-samuel.holland@sifive.com>
From: Anup Patel <anup@brainfault.org>
Date: Wed, 4 Sep 2024 17:52:19 +0530
Message-ID: <CAAhSdy0P6Jxdr1+zQLuisMpMapHWHXkSkzEEBG+wWXbbzf7ASw@mail.gmail.com>
Subject: Re: [PATCH v4 10/10] KVM: riscv: selftests: Add Smnpm and Ssnpm to
 get-reg-list test
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Atish Patra <atishp@atishpatra.org>, Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20230601.gappssmtp.com header.s=20230601
 header.b=GA2nDUz8;       spf=neutral (google.com: 2607:f8b0:4864:20::d32 is
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

On Thu, Aug 29, 2024 at 6:32=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> Add testing for the pointer masking extensions exposed to KVM guests.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>

LGTM.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

> ---
>
> (no changes since v2)
>
> Changes in v2:
>  - New patch for v2
>
>  tools/testing/selftests/kvm/riscv/get-reg-list.c | 8 ++++++++
>  1 file changed, 8 insertions(+)
>
> diff --git a/tools/testing/selftests/kvm/riscv/get-reg-list.c b/tools/tes=
ting/selftests/kvm/riscv/get-reg-list.c
> index 8e34f7fa44e9..54ab484d0000 100644
> --- a/tools/testing/selftests/kvm/riscv/get-reg-list.c
> +++ b/tools/testing/selftests/kvm/riscv/get-reg-list.c
> @@ -41,9 +41,11 @@ bool filter_reg(__u64 reg)
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_I:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_M:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_V:
> +       case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SMNPM:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SMSTATEEN:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SSAIA:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SSCOFPMF:
> +       case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SSNPM:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SSTC:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SVINVAL:
>         case KVM_REG_RISCV_ISA_EXT | KVM_REG_RISCV_ISA_SINGLE | KVM_RISCV=
_ISA_EXT_SVNAPOT:
> @@ -414,9 +416,11 @@ static const char *isa_ext_single_id_to_str(__u64 re=
g_off)
>                 KVM_ISA_EXT_ARR(I),
>                 KVM_ISA_EXT_ARR(M),
>                 KVM_ISA_EXT_ARR(V),
> +               KVM_ISA_EXT_ARR(SMNPM),
>                 KVM_ISA_EXT_ARR(SMSTATEEN),
>                 KVM_ISA_EXT_ARR(SSAIA),
>                 KVM_ISA_EXT_ARR(SSCOFPMF),
> +               KVM_ISA_EXT_ARR(SSNPM),
>                 KVM_ISA_EXT_ARR(SSTC),
>                 KVM_ISA_EXT_ARR(SVINVAL),
>                 KVM_ISA_EXT_ARR(SVNAPOT),
> @@ -946,8 +950,10 @@ KVM_ISA_EXT_SUBLIST_CONFIG(aia, AIA);
>  KVM_ISA_EXT_SUBLIST_CONFIG(fp_f, FP_F);
>  KVM_ISA_EXT_SUBLIST_CONFIG(fp_d, FP_D);
>  KVM_ISA_EXT_SIMPLE_CONFIG(h, H);
> +KVM_ISA_EXT_SIMPLE_CONFIG(smnpm, SMNPM);
>  KVM_ISA_EXT_SUBLIST_CONFIG(smstateen, SMSTATEEN);
>  KVM_ISA_EXT_SIMPLE_CONFIG(sscofpmf, SSCOFPMF);
> +KVM_ISA_EXT_SIMPLE_CONFIG(ssnpm, SSNPM);
>  KVM_ISA_EXT_SIMPLE_CONFIG(sstc, SSTC);
>  KVM_ISA_EXT_SIMPLE_CONFIG(svinval, SVINVAL);
>  KVM_ISA_EXT_SIMPLE_CONFIG(svnapot, SVNAPOT);
> @@ -1009,8 +1015,10 @@ struct vcpu_reg_list *vcpu_configs[] =3D {
>         &config_fp_f,
>         &config_fp_d,
>         &config_h,
> +       &config_smnpm,
>         &config_smstateen,
>         &config_sscofpmf,
> +       &config_ssnpm,
>         &config_sstc,
>         &config_svinval,
>         &config_svnapot,
> --
> 2.45.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhSdy0P6Jxdr1%2BzQLuisMpMapHWHXkSkzEEBG%2BwWXbbzf7ASw%40mail.gm=
ail.com.
