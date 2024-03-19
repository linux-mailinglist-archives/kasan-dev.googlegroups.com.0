Return-Path: <kasan-dev+bncBC76RJVVRQPRBD6M5CXQMGQE7626KNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id E654388084D
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 00:56:01 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1deed404fd7sf255095ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 16:56:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710892560; cv=pass;
        d=google.com; s=arc-20160816;
        b=vw2V9HcVejK3quk7YkCUKXWsAf2bSS2iju83v+NNIFUxY5LAVLqaxNZCmgGjelmgDQ
         4JomzJDx8DP+dQVWzoT8XDoCUxuz6WSsywTVsUiihWqFxbW3mS0OewdlKnlhIPKtj/dc
         DEMXFEtM49ZdxWJ+F6lFOLMYsy45AIWKwW25uWgfypamV7hRQ8V1gNbD3T4cBHindMYl
         xtJXw+RSnp8U/7VoCdIx/Zy2oV0V49YzBIkRYveOeq4MfyF+bx3IcVa6jIRDhlbVSRj7
         6y/BkysElUQtyN0oYLT6TYEcerzSGLA3GIZR+Vi4UuqbOlPFzIYyvE1pjljnX0F6c347
         M0ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=6xoprplfq/9vEnE+CPhnekxP1kqYup1meotB8BCHkng=;
        fh=EmGDvLGUmuF5a2kKc+CqOdtU7yN5BI8dBIPTuzJtZY4=;
        b=SxO3WRGV1Ibg8YoK8NFadjsBIPtgc+R+wpU83W6etTZ0j7KCREBrRat/l+M6G6J3SN
         srlXTHfz+ME8flgxQVdjiA9kigVT5RduTkb1zdSp0OSwFAWRl4hEoFEhXLcLgQNVpn3I
         +JxkhS6RWTZ1Lo6puuyuRr4+yHTG3koUQ0FhOBSnDyWhVTrVmwfLsB3hWYjUQxWzGmYY
         PSjIarDWlPFjaX/DvZVIVl0F6eOGX+q4nHj9zMVoUQCqCycgP5s9O4w5mhk3pJ7GflHm
         m8SPK9YhuaClt7VOhqL6iBsjZZN+7SbG+zhZBjmBsGGvWKz/ZatAA7P76vPifoKZ9Q1m
         LWpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=lQfkOzvW;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710892560; x=1711497360; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6xoprplfq/9vEnE+CPhnekxP1kqYup1meotB8BCHkng=;
        b=ZJ/aUjFKbqqrLSv/9v58PAh21RfayO3b5LNicyw6jsG9SQ66Oj1TyEZ1E0a7jxfw48
         kD79lxWm0X2dUZslmlpzSvYUEZ9bXjE24lN7mYJxXHDP5YeG0MKrw7grtyv88lgt0ftu
         57rOSEQqg/o75Y/KeAwjq2E91TohiBpf/x8YHclClj1RtfbAk/7Po+RixpxSyjuK9LqN
         a3l6TrVKjJFDgWhXz2kttSC5zDaMm9Yjxk6k+ubE8/PvLLhekyQfT8outAiIT09HM04/
         zzhfG/P/3FW53u4m2keynHD+2I9aohV1nu5/JNUrkuTC7jYeqDQcdBsAqamKIOAzMNjc
         GKPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710892560; x=1711497360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6xoprplfq/9vEnE+CPhnekxP1kqYup1meotB8BCHkng=;
        b=N3U4RzlQ2cyvBcUstVKSxoS4DDc9JjX9th8BS427oQbMcosEPl9C2btl1+ySWde6Qg
         dHq3IXXy39grGSWfChcxagx5Z2790h5ta1Mh9AIhbw/8aK/dEVafrYWE9LvHLtFKOAWz
         FgRvPkNXTCFtKMS2thHNl8/F4Qd1CtTSZku1YnSmbjZ+rtO9Y3kWfz9BmCpz/IOIu7HI
         kdJErpenFcfTddXPrHIjaVnzBbl5UzfP2+SCDiDbPjGhe5OES00f0UY4jYUGAqA/qXxo
         JpevkV5RITUN5cyTOynjCDtr+gGbRJGyyEMC+asH/XHDrmxI5AEW39Jm8bLVKm8Yi2XC
         MZVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUI0zmDeem8Xz3xSFvLiZWZV2NeurNj/Df5CzAzkhYAfwxv9eLbiXN1GIQhfzAiABctmtAc6VU8C5od6zY/0I7/CpIFFGmpmQ==
X-Gm-Message-State: AOJu0YxCbkleiG2onqmqESKiIV3drqJBu+Jx+Mfbj1XGlA//5lVrcFHj
	Hk6MAfus/SJCmzbeplEH2B4Xh+dxqrPNdhU+eRQmlz7rJX83RPaI
X-Google-Smtp-Source: AGHT+IFoNuxEG5NhR+/8rC44dlt5Ox1kR/7TpTPSerbtEqgtmaeHQZHtCu0qPdqmZZ6Fe277WLijWQ==
X-Received: by 2002:a17:902:ecc8:b0:1de:ff9f:e760 with SMTP id a8-20020a170902ecc800b001deff9fe760mr130461plh.0.1710892560125;
        Tue, 19 Mar 2024 16:56:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9216:0:b0:5a4:5c82:a148 with SMTP id f22-20020a4a9216000000b005a45c82a148ls5768444ooh.0.-pod-prod-01-us;
 Tue, 19 Mar 2024 16:55:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDB3CDBBpdmVjwl4Ai4xsYueKB3tKCzv9J4LlBpC1PyDiIU9ABSfXYZ5MsNMTHQ+Ms6CSMrwHbx53DeWmg2WJDsqSk+po1qwOpzA==
X-Received: by 2002:a05:6808:e:b0:3c3:8ef0:88ba with SMTP id u14-20020a056808000e00b003c38ef088bamr5079116oic.31.1710892559314;
        Tue, 19 Mar 2024 16:55:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710892559; cv=none;
        d=google.com; s=arc-20160816;
        b=LaMddNAKxYtdj+Sese6iLZbSO7/8scg0YOSiAjw1LORVD20AwEmkB1TzpicSBdvVTa
         XaPR3M1GvQYjlkxTUeQq/TPi0e8xpzfx8ApexkfL5VhT38r9DyqVRzueaShYo+HzBV7t
         OL3sa3ycirhM0iIg9r0RnKLrkAQdm1HFiIEy5jUcG8NHCsVgKRhATR9xTVuBv+cnXsP2
         vW8zWYtsY01IkOs76zLbfCSF2bf+g0KGzawj1onoDn/Kw6O8tTDFui/NsG4DVzF511ty
         sfaJZKdGdsPRQSoTTgkyYL1GgenqlgQBiveZVSeSyg2dIoOahyaIswwRPIoMh2pKSLJY
         wvDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=frQ+kwCuCCJ3eDZ6Belhj/LKRwCvmbaO9rNQmp6RZGY=;
        fh=66w71kGk7v3OVRZjvjUk1lTaO2lKLtBUYrGZcBaNhC4=;
        b=tZyp/jie1o66wYKzlODYxWx4SNuGQjk+PW1UkT24s8y/4PKOPoQQI/jSFoSA8QcJZj
         /l0p0C/G0glVDe6HZ/BSNqmHck7O0k+wAGOpYJcW3ddh+SoPpkmnHfUZXTuEwot8If03
         zwxP5u2j9qLyz6hOiC26ybDmKkuTA8Khjn1yrrEhPGxDg+ZWGZkrQyD0bwUeq5n7XzHQ
         swO+DWJeN+tQVXOcVZw0duof2Z141QZFOpaOh5gaccVpyg3+wQ3lF9XXpVbPqvFp7nXF
         +2zfzgK16KrihJ4dRnaXdK1ktVQZbPbJQ1PPMyox0fUkjVodYWXiRKMcS4x3US52qrEh
         6+Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=lQfkOzvW;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id bw8-20020a056a02048800b005e430f2514esi671552pgb.0.2024.03.19.16.55.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 16:55:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-60a104601dcso64647757b3.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 16:55:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX56iIKlUPWtQm6gSkdLgosWmwPmVea8DFrq/d+xAu//+PqkSI/EIvknwQ2yi7/6yQ0Af0bjCMrFgQphCidhQK3f8JoAnQ6MW9Ymg==
X-Received: by 2002:a25:2fc2:0:b0:dd0:e439:cec6 with SMTP id
 v185-20020a252fc2000000b00dd0e439cec6mr14153797ybv.18.1710892558409; Tue, 19
 Mar 2024 16:55:58 -0700 (PDT)
MIME-Version: 1.0
References: <20240319215915.832127-1-samuel.holland@sifive.com> <20240319215915.832127-6-samuel.holland@sifive.com>
In-Reply-To: <20240319215915.832127-6-samuel.holland@sifive.com>
From: Deepak Gupta <debug@rivosinc.com>
Date: Tue, 19 Mar 2024 16:55:47 -0700
Message-ID: <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
To: samuel.holland@sifive.com
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>, 
	linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	Andrew Jones <ajones@ventanamicro.com>, Guo Ren <guoren@kernel.org>, 
	Heiko Stuebner <heiko@sntech.de>, Paul Walmsley <paul.walmsley@sifive.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: debug@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=lQfkOzvW;       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

On Tue, Mar 19, 2024 at 2:59=E2=80=AFPM Samuel Holland via lists.riscv.org
<samuel.holland=3Dsifive.com@lists.riscv.org> wrote:
>
> Some envcfg bits need to be controlled on a per-thread basis, such as
> the pointer masking mode. However, the envcfg CSR value cannot simply be
> stored in struct thread_struct, because some hardware may implement a
> different subset of envcfg CSR bits is across CPUs. As a result, we need
> to combine the per-CPU and per-thread bits whenever we switch threads.
>

Why not do something like this

diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
index b3400517b0a9..01ba87954da2 100644
--- a/arch/riscv/include/asm/csr.h
+++ b/arch/riscv/include/asm/csr.h
@@ -202,6 +202,8 @@
 #define ENVCFG_CBIE_FLUSH              _AC(0x1, UL)
 #define ENVCFG_CBIE_INV                        _AC(0x3, UL)
 #define ENVCFG_FIOM                    _AC(0x1, UL)
+/* by default all threads should be able to zero cache */
+#define ENVCFG_BASE                    ENVCFG_CBZE

 /* Smstateen bits */
 #define SMSTATEEN0_AIA_IMSIC_SHIFT     58
diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
index 4f21d970a129..2420123444c4 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -152,6 +152,7 @@ void start_thread(struct pt_regs *regs, unsigned long p=
c,
        else
                regs->status |=3D SR_UXL_64;
 #endif
+       current->thread_info.envcfg =3D ENVCFG_BASE;
 }

And instead of context switching in `_switch_to`,
In `entry.S` pick up `envcfg` from `thread_info` and write it into CSR.

This construction avoids
- declaring per cpu riscv_cpu_envcfg
- syncing up
- collection of *envcfg bits.


> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
>  arch/riscv/include/asm/cpufeature.h |  2 ++
>  arch/riscv/include/asm/processor.h  |  1 +
>  arch/riscv/include/asm/switch_to.h  | 12 ++++++++++++
>  arch/riscv/kernel/cpufeature.c      |  4 +++-
>  4 files changed, 18 insertions(+), 1 deletion(-)
>
> diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm=
/cpufeature.h
> index 0bd11862b760..b1ad8d0b4599 100644
> --- a/arch/riscv/include/asm/cpufeature.h
> +++ b/arch/riscv/include/asm/cpufeature.h
> @@ -33,6 +33,8 @@ DECLARE_PER_CPU(long, misaligned_access_speed);
>  /* Per-cpu ISA extensions. */
>  extern struct riscv_isainfo hart_isa[NR_CPUS];
>
> +DECLARE_PER_CPU(unsigned long, riscv_cpu_envcfg);
> +
>  void riscv_user_isa_enable(void);
>
>  #ifdef CONFIG_RISCV_MISALIGNED
> diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/=
processor.h
> index a8509cc31ab2..06b87402a4d8 100644
> --- a/arch/riscv/include/asm/processor.h
> +++ b/arch/riscv/include/asm/processor.h
> @@ -118,6 +118,7 @@ struct thread_struct {
>         unsigned long s[12];    /* s[0]: frame pointer */
>         struct __riscv_d_ext_state fstate;
>         unsigned long bad_cause;
> +       unsigned long envcfg;
>         u32 riscv_v_flags;
>         u32 vstate_ctrl;
>         struct __riscv_v_ext_state vstate;
> diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/=
switch_to.h
> index 7efdb0584d47..256a354a5c4a 100644
> --- a/arch/riscv/include/asm/switch_to.h
> +++ b/arch/riscv/include/asm/switch_to.h
> @@ -69,6 +69,17 @@ static __always_inline bool has_fpu(void) { return fal=
se; }
>  #define __switch_to_fpu(__prev, __next) do { } while (0)
>  #endif
>
> +static inline void sync_envcfg(struct task_struct *task)
> +{
> +       csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | task->thr=
ead.envcfg);
> +}
> +
> +static inline void __switch_to_envcfg(struct task_struct *next)
> +{
> +       if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV_IS=
A_EXT_XLINUXENVCFG))

I've seen `riscv_cpu_has_extension_unlikely` generating branchy code
even if ALTERNATIVES was turned on.
Can you check disasm on your end as well.  IMHO, `entry.S` is a better
place to pick up *envcfg.

> +               sync_envcfg(next);
> +}
> +
>  extern struct task_struct *__switch_to(struct task_struct *,
>                                        struct task_struct *);
>
> @@ -80,6 +91,7 @@ do {                                                  \
>                 __switch_to_fpu(__prev, __next);        \
>         if (has_vector())                                       \
>                 __switch_to_vector(__prev, __next);     \
> +       __switch_to_envcfg(__next);                     \
>         ((last) =3D __switch_to(__prev, __next));         \
>  } while (0)
>
> diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeatur=
e.c
> index d1846aab1f78..32aaaf41f8a8 100644
> --- a/arch/riscv/kernel/cpufeature.c
> +++ b/arch/riscv/kernel/cpufeature.c
> @@ -44,6 +44,8 @@ static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __r=
ead_mostly;
>  /* Per-cpu ISA extensions. */
>  struct riscv_isainfo hart_isa[NR_CPUS];
>
> +DEFINE_PER_CPU(unsigned long, riscv_cpu_envcfg);
> +
>  /* Performance information */
>  DEFINE_PER_CPU(long, misaligned_access_speed);
>
> @@ -978,7 +980,7 @@ arch_initcall(check_unaligned_access_all_cpus);
>  void riscv_user_isa_enable(void)
>  {
>         if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV_IS=
A_EXT_ZICBOZ))
> -               csr_set(CSR_ENVCFG, ENVCFG_CBZE);
> +               this_cpu_or(riscv_cpu_envcfg, ENVCFG_CBZE);
>  }
>
>  #ifdef CONFIG_RISCV_ALTERNATIVE
> --
> 2.43.1
>
>
>
> -=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-
> Links: You receive all messages sent to this group.
> View/Reply Online (#659): https://lists.riscv.org/g/tech-j-ext/message/65=
9
> Mute This Topic: https://lists.riscv.org/mt/105033914/7300952
> Group Owner: tech-j-ext+owner@lists.riscv.org
> Unsubscribe: https://lists.riscv.org/g/tech-j-ext/unsub [debug@rivosinc.c=
om]
> -=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-=3D-
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKC1njSg9-hJo6hibcM9a-%3DFUmMWyR39QUYqQ1uwiWhpBZQb9A%40mail.gmai=
l.com.
