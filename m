Return-Path: <kasan-dev+bncBDHJX64K2UNBBHOCYG4AMGQEHVLZXSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 834659A175D
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 02:58:06 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-45f067f9e96sf7862821cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 17:58:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729126685; cv=pass;
        d=google.com; s=arc-20240605;
        b=emvRqo8H8pcpbGQmuJ5vp9nLQFVFYmbXHxLbBcUex8dCcoPIIiGRXZhBljAXchEVIv
         4x7p+XYlk7LEOeJKhtMbuxUp7c6fg0HhvJGrqzjfa22SjiHgJXFEmkv5bvaKjG83/z7Y
         FIr1kPastK4EqxidhQij6k80eoLnRf4sz2X6VKmonhx8mJgNqNChnunxUXXH2k9fez4p
         IfKpuJcsfsG241Ds1R3kzatCZOINVb6ibwbqvLJ37+7mUNKgIAbKf6TfpQPNbPF+TMOx
         qyAti7RiSY/3+Ox67Go7yzMfB+4NM7Gxd+VwoOJVduix5m3f17Vo9gD/pblps6doNZ7K
         h6GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JZcA7XNmK+Yv6YdbwvMI39fFT94IIpKRRXFEp7d2D68=;
        fh=d1QpxKqZoiiNiUuXzkPe2ShXrc+VsmJSIH7lEFnmkOI=;
        b=a6sWqqhE5gOTXb4utqVmDa4kHE5zwhZvHHMxaeEwevaKPGK4dO3811xJmMuBps7JIZ
         Z+xojMlmsMoVNyOybZJtnG7lHs9z2ntPW7NhB8jT8pXxgpqCCU8ga+8V9FyEfpcZpZT3
         ob3ADDRT7WRTjsIUuItCvDFlRqRTyMebA+7GXNdBZCjBlBdF/V4AHn3dxzKtsLmwlqiD
         XK5njDBrwhqV6PhXpjQlZWLbTUyPrA8Q5jEWq8NJFhgfDozcycPQSmcKPSAK6WL2ZXBu
         G+iNXpDeuYODSqMsLElmcvKE2/D7XxWTYHAR7XIo0BLkEbfF5yKALo0zY5RoU+ZMh7Fb
         9Rdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=i7Da7Ccu;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729126685; x=1729731485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JZcA7XNmK+Yv6YdbwvMI39fFT94IIpKRRXFEp7d2D68=;
        b=xhFTAS+cO++SdGg8oZmnkXLRbb2QMqfgZ4TTMGj8K1rY3Y2ZWwwrzphxCP6Xc0FRGg
         FhuaPitij/wcLnJcLORUkNw94KRLMhg00UwqpZjJFm/wZYsrOPdOinXnvSgbRpXcVaEr
         N4zNv/3LsxdHxoEyTItuJwKqaxNUpSE6S+nrDQq4g8Bve9hm7fsRblBMI+TPmDfrXISu
         l1wmRirnpAjUwtnTFZ78YM0DXCezL9QE5rzEltDHFH8U0diFQB0VsVh+NCPSUv3n2uKo
         9t3Q4egATHYZLRbKZ6geIEo3Y70mdCM2YJdmvt5oOwUFe3sZhRfw/2g0PPisoEKiwkyZ
         hQEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729126685; x=1729731485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JZcA7XNmK+Yv6YdbwvMI39fFT94IIpKRRXFEp7d2D68=;
        b=hWd4sDIg4n1PiE5kp3vqCC76PwiLO2f72tiI8x20gRMCX4wXyIIzSs6LglbEbdSpQ/
         ZggrycJjhTKabcubxFhr9IwLjUlnmp+2rruyxvIUesV4mL/UIYgkhGhNiaSX9+172gUN
         U5cEScnjj/U2Hy+FUBcn5TLXzENJ4M6AEBSr/WF8QcSmcWGdA3NKATSfK4n9K7saOQkU
         hoIEnQg7BonvLrgghj/kVU+xDBKEWrbU3n6kY+CL8+NJP9Jo1Wnvt2widK6MYzcvxKqr
         2bIdc58Dr6VjvHCO4ufq2lSxTaqNdzEcfGYUMVMXOvIi+Pv7cbM+W2gyG8NKV1YlC4sB
         OG9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3wJrD0EMd0rHOzh6lhHuQOwMlMwsO45cXz0natesmpZBA+uyZlPQnE6rMfJUtkMSsChHl6A==@lfdr.de
X-Gm-Message-State: AOJu0YxDBSnXCfPiJp2vaXVB4HSpe/8JAesSxBZ6459vyfgNjyY5fQtU
	L8LxKkFOjq4Tz1PkWGn2ElGcpiw4JdB81V1fuYS9FtOGi15yZkC9
X-Google-Smtp-Source: AGHT+IGTHyMGpfC+zavg7IP1hOg9dSVVc0FQxnsm9GuPZigy+kmSQ7K8trWTRqT+9aKzLauGod7lRA==
X-Received: by 2002:a05:622a:a18:b0:460:87e7:7cd9 with SMTP id d75a77b69052e-46087e78ddemr78536821cf.24.1729126685354;
        Wed, 16 Oct 2024 17:58:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2d3:b0:458:403a:4ea4 with SMTP id
 d75a77b69052e-4609b6e5e18ls1600221cf.2.-pod-prod-02-us; Wed, 16 Oct 2024
 17:58:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCRZeywRoKL6DY/T6kU8teF31Wxy+31+savjQcwMCUNhcbk6xEwE7cdoaMPQleSc1E/h6Gpke3MgQ=@googlegroups.com
X-Received: by 2002:a05:620a:4690:b0:7a9:be54:4b00 with SMTP id af79cd13be357-7b11a37932emr2979626485a.35.1729126684434;
        Wed, 16 Oct 2024 17:58:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729126684; cv=none;
        d=google.com; s=arc-20240605;
        b=JEVBq2311yNWDS4HCTt69kCBpB2plKi4RNskWzMaBhCh1BOMLtqR2aTxyhvMbClZ+L
         CSPX0CK1HAC8h48VqNraMc1gqiCN3c7xpORCYM2ISogkecha5eGGvqtASwW0osD488C1
         iwZOvdWphOt/6yrHQBroKAZE+lNr5cSa5GmXW56enJOCl2WjSB/lE3HAXBL8eYNtk6JX
         eX64a7vzL5tOOyJFcpXMmXYnlZ14ZQWFf66gWJ39fF5ol1AI7eQkVn6gX4bywwwi6YHo
         op7BXQ5iIB0MZLimcowi1cwSM4dtsLS6S4VYqibujj5jTQmJBrR9nIYTAkEsE8+V7W+G
         +3/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+xzsoLjsBfwusEklaj61R5Uo3anocunfPETWtAtlm4w=;
        fh=8O4xjbvQ9wd+LvZx5ehEEF1gKJStXe3FpysAM91K85U=;
        b=CJ0Zlu+8PbaD+bMjocvCoRWl1bMoBSI+RuEQnzZRoQMMArrEk1vddxgC8CqyAoTZfB
         kR18D8JIx+zL+OsEFw5spm+XNTMWcL6In3tQN5DX4yDqAmRqoyvo/n93WBIpLcJ8Jca4
         6RsV0W4NQkwcer8VZYc7/veN6JJMVM7feOTtGWmNZblQl7JJVHSpmN1EXjn+g+kMjIPj
         2MT9pYsajSStK9A9odsndwqGcgk7HKVkMHD+DIdfpvhWKtOs7A+XHhOX3MHOHoLeLCnL
         I+aUBG6LZL1gFE6tyvyWF86fMYMTHRM1K+yqCEUx9R/mugn1I/trLWZUmqnIwLMqQRvJ
         qkqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=i7Da7Ccu;
       spf=pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b137139570si19751885a.6.2024.10.16.17.58.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 17:58:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of charlie@rivosinc.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-71e585ef0b3so301992b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 17:58:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVue+N0er9sDurW7t77HFvDBTpLOyXckUD9st9+XBbiBpKt2L3QEZCeZDEgGnc9XuzBJ73HCxUvsqY=@googlegroups.com
X-Received: by 2002:a05:6a00:10c9:b0:71e:5f2c:c019 with SMTP id d2e1a72fcca58-71e5f2ccbadmr19417242b3a.9.1729126683343;
        Wed, 16 Oct 2024 17:58:03 -0700 (PDT)
Received: from ghost ([50.145.13.30])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e7737178bsm3678688b3a.36.2024.10.16.17.58.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 17:58:02 -0700 (PDT)
Date: Wed, 16 Oct 2024 17:58:00 -0700
From: Charlie Jenkins <charlie@rivosinc.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
	devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v4 06/10] riscv: Allow ptrace control of the tagged
 address ABI
Message-ID: <ZxBhGJ0-hir0gFor@ghost>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
 <20240829010151.2813377-7-samuel.holland@sifive.com>
 <ZuOoqTfKs/7G075O@ghost>
 <2e25597c-6278-4bc6-a0c2-3826841c2ac0@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2e25597c-6278-4bc6-a0c2-3826841c2ac0@sifive.com>
X-Original-Sender: charlie@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=i7Da7Ccu;       spf=pass (google.com: domain of charlie@rivosinc.com
 designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=charlie@rivosinc.com;
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

On Wed, Oct 16, 2024 at 12:50:32PM -0500, Samuel Holland wrote:
> Hi Charlie,
> 
> On 2024-09-12 9:51 PM, Charlie Jenkins wrote:
> > On Wed, Aug 28, 2024 at 06:01:28PM -0700, Samuel Holland wrote:
> >> This allows a tracer to control the ABI of the tracee, as on arm64.
> >>
> >> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> >> ---
> > 
> > Since this code is identical to the arm64 port, could it be extracted
> > out into the generic ptrace.c and ifdef on either CONFIG_RISCV_ISA_SUPM
> > or CONFIG_ARM64_TAGGED_ADDR_ABI by adding some generic flag like
> > CONFIG_HAVE_ARCH_TAGGED_ADDR_ABI?
> 
> Yes, it could be factored out, though I don't know if it is worth the overhead
> for these two trivial functions. I don't see any other code like this outside of
> arch/.

In my ideal world there is just a generic header somewhere so the only
"overhead" is creating the generic header. But I will defer to you on
whether it is worthwhile.

- Charlie

> 
> Regards,
> Samuel
> 
> >>
> >> (no changes since v1)
> >>
> >>  arch/riscv/kernel/ptrace.c | 42 ++++++++++++++++++++++++++++++++++++++
> >>  include/uapi/linux/elf.h   |  1 +
> >>  2 files changed, 43 insertions(+)
> >>
> >> diff --git a/arch/riscv/kernel/ptrace.c b/arch/riscv/kernel/ptrace.c
> >> index 92731ff8c79a..ea67e9fb7a58 100644
> >> --- a/arch/riscv/kernel/ptrace.c
> >> +++ b/arch/riscv/kernel/ptrace.c
> >> @@ -28,6 +28,9 @@ enum riscv_regset {
> >>  #ifdef CONFIG_RISCV_ISA_V
> >>  	REGSET_V,
> >>  #endif
> >> +#ifdef CONFIG_RISCV_ISA_SUPM
> >> +	REGSET_TAGGED_ADDR_CTRL,
> >> +#endif
> >>  };
> >>  
> >>  static int riscv_gpr_get(struct task_struct *target,
> >> @@ -152,6 +155,35 @@ static int riscv_vr_set(struct task_struct *target,
> >>  }
> >>  #endif
> >>  
> >> +#ifdef CONFIG_RISCV_ISA_SUPM
> >> +static int tagged_addr_ctrl_get(struct task_struct *target,
> >> +				const struct user_regset *regset,
> >> +				struct membuf to)
> >> +{
> >> +	long ctrl = get_tagged_addr_ctrl(target);
> >> +
> >> +	if (IS_ERR_VALUE(ctrl))
> >> +		return ctrl;
> >> +
> >> +	return membuf_write(&to, &ctrl, sizeof(ctrl));
> >> +}
> >> +
> >> +static int tagged_addr_ctrl_set(struct task_struct *target,
> >> +				const struct user_regset *regset,
> >> +				unsigned int pos, unsigned int count,
> >> +				const void *kbuf, const void __user *ubuf)
> >> +{
> >> +	int ret;
> >> +	long ctrl;
> >> +
> >> +	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl, 0, -1);
> >> +	if (ret)
> >> +		return ret;
> >> +
> >> +	return set_tagged_addr_ctrl(target, ctrl);
> >> +}
> >> +#endif
> >> +
> >>  static const struct user_regset riscv_user_regset[] = {
> >>  	[REGSET_X] = {
> >>  		.core_note_type = NT_PRSTATUS,
> >> @@ -182,6 +214,16 @@ static const struct user_regset riscv_user_regset[] = {
> >>  		.set = riscv_vr_set,
> >>  	},
> >>  #endif
> >> +#ifdef CONFIG_RISCV_ISA_SUPM
> >> +	[REGSET_TAGGED_ADDR_CTRL] = {
> >> +		.core_note_type = NT_RISCV_TAGGED_ADDR_CTRL,
> >> +		.n = 1,
> >> +		.size = sizeof(long),
> >> +		.align = sizeof(long),
> >> +		.regset_get = tagged_addr_ctrl_get,
> >> +		.set = tagged_addr_ctrl_set,
> >> +	},
> >> +#endif
> >>  };
> >>  
> >>  static const struct user_regset_view riscv_user_native_view = {
> >> diff --git a/include/uapi/linux/elf.h b/include/uapi/linux/elf.h
> >> index b54b313bcf07..9a32532d7264 100644
> >> --- a/include/uapi/linux/elf.h
> >> +++ b/include/uapi/linux/elf.h
> >> @@ -448,6 +448,7 @@ typedef struct elf64_shdr {
> >>  #define NT_MIPS_MSA	0x802		/* MIPS SIMD registers */
> >>  #define NT_RISCV_CSR	0x900		/* RISC-V Control and Status Registers */
> >>  #define NT_RISCV_VECTOR	0x901		/* RISC-V vector registers */
> >> +#define NT_RISCV_TAGGED_ADDR_CTRL 0x902	/* RISC-V tagged address control (prctl()) */
> >>  #define NT_LOONGARCH_CPUCFG	0xa00	/* LoongArch CPU config registers */
> >>  #define NT_LOONGARCH_CSR	0xa01	/* LoongArch control and status registers */
> >>  #define NT_LOONGARCH_LSX	0xa02	/* LoongArch Loongson SIMD Extension registers */
> >> -- 
> >> 2.45.1
> >>
> >>
> >> _______________________________________________
> >> linux-riscv mailing list
> >> linux-riscv@lists.infradead.org
> >> http://lists.infradead.org/mailman/listinfo/linux-riscv
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZxBhGJ0-hir0gFor%40ghost.
