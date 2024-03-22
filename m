Return-Path: <kasan-dev+bncBCOJLJOJ7AARBUPZ6SXQMGQELU57YAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 33ABE8867F0
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 09:09:55 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-513dd43a245sf419170e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 01:09:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711094994; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y+B8ZPMteYFTizyvb7erhFpxR8Cj/sO7uJ/azb8mZutB63CFHjfghm07Nq1rRpn9TB
         0umvstj8DyfzRbhgc9It43tgmJXrMrTWXNHKOUHqahNz+RAYqlijcloJel7j7oy5uASI
         x5zlbQYCHKAc6bj1p7pm9PQoA2UYPhB9JGuXfPSosCtwFtn33KNkyYJmL6guefOR5Z95
         JMeGgxYf9qNmYMDTGLJ8N+NqL3DBgEiF5tsonNusUBc69RlRhSojRYR5bmpBYIXv48DV
         izY3MlrBLoQL8+/lVYtI/sxkKFZc0+lrWrmWPJz4+TRMPOPmX6ubPuVO+f1nHh8B2Kl5
         0SYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3CYZLa8ysWAS+O2+yZu67qsA6ibxgrQ+8D4plqUk2mI=;
        fh=LhfJvm7gWUkLHfm1yDlPSkuDTEjtqRb9ZAMz7KnAY8E=;
        b=eAvBJE0DZTZNOgdYsjUn2Zr9l9tOfj/SEfQ0bp2NwhdceVzPHdBl3Me4PK+HP9lCbE
         D3ZT/mHcDZNqFsi5apo7osKshRDXOGKeW5hBde+lf2MZnAWZ0kMz63PNShtTAJbnyjr0
         rB/kOO5omog3v0ZI6qy9GAjiqNfdm3OpaulYwuCpiiN8vjSvnVMTOzHjlw0Xz7aEwRU1
         y7vWBQbk0280dz8TukU2YJneFLOtnZ3N59fyc6Vcxy7y0eTN7ctqUf4mWRLmLsEALoW3
         6xOTTDKoPL2yse7wPtV/DpBGUE5nvEnnk7+3+o1dajMaxzp3Btx21wbb/NfzFSyBBPiu
         MecA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=QmM447QZ;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711094994; x=1711699794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3CYZLa8ysWAS+O2+yZu67qsA6ibxgrQ+8D4plqUk2mI=;
        b=XWuy3ZTVpJqyUVbIpRE/LKyXzj1wQi4a4m+DRRS2MVNBPYFuiNvDiYkgK8HhRRmxqA
         kipRDaADaNSWU/qpMTDYMyIecImS7HbSLJ2qjafcqo1hwbysiacBG3L/9b1A36lkBugT
         ILQIkYxIqsN2IesSk+veOmRqJTT4zrDHsNuhGsZEIiMlrTtNhLhvqt6pnNiUwb20EXBq
         R51T10eYPTQRVEuEZPaSFoR+WHY4be4BFySeh67qp/gwXq8owFZSj2dBiSNm+/GkSEHq
         DfMDajI7hl0wjkpYn2H5Kg1roDdC0S9cPeWY7nD0l2EKyxlJK84rh2mOmlrEwar87Mhy
         cnWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711094994; x=1711699794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3CYZLa8ysWAS+O2+yZu67qsA6ibxgrQ+8D4plqUk2mI=;
        b=vCHtEKJtHuH/i51XXiWdR8qLrQL2YMjQ9jgElKemDylEO6DdwOGrrULupKXfTfm+MP
         vll4vWrPd/8QsqpUeSK3clrNWsw6IXAGdtqAurnDhoLM4hokkmeeiQqjfD/CXKeIUdJm
         3+W7vAnXE2Uuy0l+C+xf8LpetapgprqjlvS3Fn+Oo6vxvLSsk7ZKTyIsg1JHy4Bls6DI
         SiJKFZCfyUE1Q5EZklEGUMBu172j33GmdRe59iln7i7czKJsF1WRP4tN35xLOYyxzw59
         oYAOEO1svnX5gQhGrq6FDjuBevKE9TW6y3oIL2OaOsg1gcBj8vqK58ct6hAhYoPbyN+c
         0b5g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXJG4bp4AjQ8L3UX1sXgNM++huXZ2jgq1FUVv7x+VlAn/tWwle4724RLmilPWa53Hmy20Rd8Gn5UaeTqhVl3XcNoedKx7lKng==
X-Gm-Message-State: AOJu0Yzmeq2kfMlbvBDAPjKRBU01wFMizGXOl4TWZUC9gYWW52pFZY43
	g/VqfAbb7IRt/nnam9avJFsSmPVAmRz19pyTkbUnVfTCy+YoWlOU
X-Google-Smtp-Source: AGHT+IFJ/yP12zRSfa6FxNG60q7z0m0zFPEG1hpuPcB02xOR4awSsL42Wkbd4Ziw78vfKOp1BzEGQA==
X-Received: by 2002:a19:6406:0:b0:513:6982:d940 with SMTP id y6-20020a196406000000b005136982d940mr991149lfb.1.1711094993482;
        Fri, 22 Mar 2024 01:09:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d17:b0:513:1813:feb9 with SMTP id
 d23-20020a0565123d1700b005131813feb9ls714317lfv.0.-pod-prod-09-eu; Fri, 22
 Mar 2024 01:09:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdQyhr/hx+zXuvHEVC5PoNxIivjcAbzxorVyEW2ej4QRvomv2jOwXUmVOmIyIzo8ZFjLgNZG+K8o3iOyVmYk3Ia8tvKYgLLOSFGQ==
X-Received: by 2002:a2e:8888:0:b0:2d5:b33c:1f64 with SMTP id k8-20020a2e8888000000b002d5b33c1f64mr1080246lji.38.1711094991363;
        Fri, 22 Mar 2024 01:09:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711094991; cv=none;
        d=google.com; s=arc-20160816;
        b=vXYQih31gWjazVQaaQoipC8Ki4zY7QiBGsbzjh1C+tD83uXTikWw5g0uQ3AnIgVAav
         eeHilpvOQEqAhE1EN4Xkzn+IF441ugNkHm7utgq2O9XapBoMYrCO5OZn0K5cAsKBMpMC
         n/rNZwoO8tl9CIfiduXZklixcdPOu67VlrQGUSIQzS11WxH86Ml1NDxNuX/ukFtn1PiF
         oVPcRwoZSm8x/ibFzfcfDTw+oQ4L41NKvvFStWAZfJMFAcLsAbmFIGIh45FLbFujoevW
         ziefRFXAJAzxqbJNSJtimI6i5kfbrhkf7u7N6lezI0Y5KcypPXFmTC4V5s1pmFMM3Oet
         kGhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GE5LhZmpwjg/Vlr/58M0lzDTSb9NjpNMdXrf3nX1bH4=;
        fh=kBeD5P5a6nCzAnhedrbNslYt5Ncysg4t1P2N13MmH2Q=;
        b=fWM7nntRVoJdprM++yJwIlEoCQpidNBxTckdboFsYCav9lIw1u8ijW8k+WV3G5S8fs
         JyC5ilLZ6O3RPOw8dk7rLejz24GiSmeRHP07v0pD2Kb3OIpyDH603zOk6JviY7nmYo5f
         LLQtC9SRLJNPhD4tFk/lHa+5K5azJ4TCo4HHai5XhNeZyOj9d8s+hL3FEQ2FBP5F7VFN
         1VVUYxoaRkkGMKdi24vU8x1UL4KBXvh9iiA/I+ZlCQzg5V0CYO8T2LlHMfzXYrUr8U+Y
         dZw3dQMJ8zhtk2cj9JPaYaKsJbApkdpElrWtHNjt1Oo8xWEO+3TNoVJaJezvTJFZ93KI
         88AQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=QmM447QZ;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id f6-20020a7bcd06000000b004147c0e826bsi30113wmj.0.2024.03.22.01.09.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Mar 2024 01:09:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id 5b1f17b1804b1-4147cec437dso1232025e9.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Mar 2024 01:09:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6xQiAhhDfv/nTK0KK+2jlaOBh0f/0apfu+yk5x96KxNhaL3dOvNNstoIhw2WvUNFxJqH678ByRNj+5FeSZH3U3Yluv96VDz7cgA==
X-Received: by 2002:a05:600c:1c26:b0:414:a89:3443 with SMTP id j38-20020a05600c1c2600b004140a893443mr902935wms.25.1711094990861;
        Fri, 22 Mar 2024 01:09:50 -0700 (PDT)
Received: from localhost (2001-1ae9-1c2-4c00-20f-c6b4-1e57-7965.ip6.tmcz.cz. [2001:1ae9:1c2:4c00:20f:c6b4:1e57:7965])
        by smtp.gmail.com with ESMTPSA id s16-20020a05600c45d000b00413f4cb62e1sm2291207wmo.23.2024.03.22.01.09.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Mar 2024 01:09:50 -0700 (PDT)
Date: Fri, 22 Mar 2024 09:09:49 +0100
From: Andrew Jones <ajones@ventanamicro.com>
To: Deepak Gupta <debug@rivosinc.com>
Cc: Samuel Holland <samuel.holland@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, devicetree@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, 
	Rob Herring <robh+dt@kernel.org>, Guo Ren <guoren@kernel.org>, Heiko Stuebner <heiko@sntech.de>, 
	Paul Walmsley <paul.walmsley@sifive.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
Message-ID: <20240322-3c32873c4021477383a15f7d@orel>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
 <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
X-Original-Sender: ajones@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=QmM447QZ;       spf=pass
 (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
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

On Tue, Mar 19, 2024 at 09:39:52PM -0700, Deepak Gupta wrote:
...
> I am not sure of the practicality of this heterogeneity for Zicboz and
> for that matter any of the upcoming
> features that'll be enabled via senvcfg (control flow integrity,
> pointer masking, etc).
> 
> As an example if cache zeroing instructions are used by app binary, I
> expect it to be used in following
> manner
> 
>  - Explicitly inserting cbo.zero by application developer
>  - Some compiler flag which ensures that structures larger than cache
> line gets zeroed by cbo.zero
> 
> In either of the cases, the developer is not expecting to target it to
> a specific hart on SoC and instead expect it to work.
> There might be libraries (installed via sudo apt get) with cache zero
> support in them which may run in different address spaces.
> Should the library be aware of the CPU on which it's running. Now
> whoever is running these binaries should be aware which CPUs
> they get assigned to in order to avoid faults?
> 
> That seems excessive, doesn't it?
>

It might be safe to assume extensions like Zicboz will be on all harts if
any, but I wouldn't expect all extensions in the future to be present on
all available harts. For example, some Arm big.LITTLE boards only have
virt extensions on big CPUs. When a VMM wants to launch a guest it must
be aware of which CPUs it will use for the VCPU threads. For riscv, we
have the which-cpus variant of the hwprobe syscall to try and make this
type of thing easier to manage, but I agree it will still be a pain for
software since it will need to make that query and then set its affinity,
which is something it hasn't needed to do before.

Thanks,
drew

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240322-3c32873c4021477383a15f7d%40orel.
