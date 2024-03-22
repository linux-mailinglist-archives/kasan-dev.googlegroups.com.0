Return-Path: <kasan-dev+bncBCOJLJOJ7AARBNXU6SXQMGQE4USTX5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D8748867B3
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 08:58:48 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-33ed234bcb1sf1358921f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 00:58:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711094328; cv=pass;
        d=google.com; s=arc-20160816;
        b=uCA57ia+fx4RvhTGxyaqRV6ifaLfPrUNL3X3CJmDj0Ht13AZgmQYui3RvDN6gjWD9O
         oP5DnnCsVA4h7y8HuEazGEM+2u/GlSRNCHqqgHxWAc3iDzEglG2PIdjyeK3VZHOax3kL
         Bh1Oh5wd55ZhyAUqeSVY7q6eqItfhFYETUC/As40W9nmNEBQ7UYljLfq+8zvFijJ3wIa
         OrguuJeHCAyjpXzY6xVhlQQf4R7eZ33X4vIstpbGLQmI5Kf8EBOqPfuJLzOfVrEMseIT
         npgBYOr4yu8b1BltqvXMZCzPufKN8p0uuyBfIhi0NcZ3ONrHk0U/w99eWUR4j77Id4UT
         8LIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UNWOJTMRQXjy85B+J0B+JbxM1ck1m0VcnAMGqKjI9Dc=;
        fh=eYaqELbN4MT0Zy6qwLPFiNIxSFQNhcHLEeyCgo5fxGs=;
        b=VA/n6ua7pulCt+M8Ys9s24akaTp2xGmHLJHSEPbpRdJgDTEv4uZCUiMo3fpKPOrXF/
         JeEQIpeC2COZ09xYb6L/1C6sBSZ9RTdbhd4nP4nVt5Bae2k+BwqZfrnVGWb7HFIatb7R
         g+b7zZW70gxMMxqV/BEYSDrDc4IT1ehC6/lxy5iqntDHq7vdIwGPkHhc7tAJeE7lSyWb
         KWp2VV2R8zsDCVe6MfEitnf8qQ9HGZtbp8QBV4F7CaoQ+8PSbZhwshVVBs669g9BNRAQ
         Er8BvBYi5LhZJSLJwpWW/bB9iLKzaraCN2UCrl7AqDdmkrG4JYxCL1hapk2VOyvn3Yg1
         FIcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=dVYNBA6Q;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711094328; x=1711699128; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UNWOJTMRQXjy85B+J0B+JbxM1ck1m0VcnAMGqKjI9Dc=;
        b=GOQu4jh86gWlbsK5tP5HX2pRwpwjxPpiVnG5Itj5oIH+WO36Ua7+qHTOUmk/U+/9Ck
         GALM6Mts2vqOqcTzxtXfN4f5dnnIqjJsqAlAHP7zyywR4P8SjF0hzZgYe+Z2z5q7SabH
         dL01Fn/PMcDlJqK7v5YXc4LARkjLgTPHw2bv9wTmDtQ4O7Dm4cEs+uvvPJYF3Lhxa+Fa
         1AvqIHrBPAPzuIKRC0hff6QeTiK0i1DFZYJe4MxxyO/7umJN/6/rKzK+l94pytOtccZF
         kV9Joh5LB8rRdkmU9Kgu3BU9ijn7bSW16Okw09NtCuE9w+ozwqlTIhLhaRckFKPD4ZGw
         ggDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711094328; x=1711699128;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UNWOJTMRQXjy85B+J0B+JbxM1ck1m0VcnAMGqKjI9Dc=;
        b=BZi1rym7LlikSTOfqHWoKx4z45M/2WS8A/ZDeIMOvYLksUto+3OFX3GHjSkpNPUbGX
         UbXNA036BeYQSD2TVHlXcWQI+LpgLvIKiOgCCqEFElR/48U4CHhEgeak1cX59e05KKKl
         rnJQNGPK2xjQOAoy6bdjswdHrcbZXOsoOSB+A/2NfwQV55h6tD5n//mn08ll1kXPc6xF
         0KkQG7Yq2xFlwhU+N8ChyzFsTfOg1pllYZ00OPqowQmSMh6Xgg1WQnn8Rj3inkyvxWf3
         s1Wm9Dh91bKCCC3xGBViFfIIsMTqCp/RCq0APk71YpLzMx+ezr2FGVyZAgeHAgqCOCbA
         pfKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsTe95MAO4loL4bJYu8Xps+9fRwyUzgecrD8p7ftoVEiJFe2XrKz0Za9A/90tCgCLSSg611rWWhpGrBCUyCve9pz3ojIEnkA==
X-Gm-Message-State: AOJu0Yw2jVIIfwR1qZfOzewex9yrZJBUm4OD8Eu4/jv6w1e99hHHOwN/
	kU6SKUojZxCFeYGi7JOLqODGt63qDUBX1UgpfahVaXAiUj7CJCYz
X-Google-Smtp-Source: AGHT+IH4AT8hLcxapEX6G3DceIa6lZjmTkuQIZIMy17ArAroZE3fdA3CdNjLgcC8tCNmJuSdFk3vGg==
X-Received: by 2002:adf:e40c:0:b0:33e:bfd2:24cc with SMTP id g12-20020adfe40c000000b0033ebfd224ccmr1057800wrm.31.1711094326991;
        Fri, 22 Mar 2024 00:58:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5120:b0:414:1eb:a97d with SMTP id
 o32-20020a05600c512000b0041401eba97dls1049032wms.0.-pod-prod-00-eu-canary;
 Fri, 22 Mar 2024 00:58:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPmwHRlHSiSW/bnJOr6RWOt8kdE66yvxcrI7xY+NZv2vWj1DaON/jLeWjBR4maBbhJkjHmIieHwYGszxt2knjahd4QlDxiG5dDRw==
X-Received: by 2002:a5d:658f:0:b0:33e:c595:fec9 with SMTP id q15-20020a5d658f000000b0033ec595fec9mr1064644wru.8.1711094325115;
        Fri, 22 Mar 2024 00:58:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711094325; cv=none;
        d=google.com; s=arc-20160816;
        b=rX8uzcKzbMVwkov8fz0O6E0vhi3lbmkQ2im4c8k4kkLrLWq4KwFXsRVpbYJDEcyFt7
         ee6KUbpDTySAmV3TDsATWubPDL9eNvqWdv0VSjsUZSl3oj8TqiTdx+hU4NXbSylYrmmb
         D+JKuh6LWj945rczkB+1YUpzUgt8vDaSwUJbHj+ImAcUmeEmCMxnmXyiUjJo1o/h5/An
         dphndHd0YJyWhmMpP6fxJnzxqnrCgSoIjJD3VTgLJYaELi7YVoPciZR/Lw6vc7z3IX0S
         deeIqvQUNdEn6KW25kJyOjCvJRgH+2Z2vvywkdypK7XN1LOh4QLOHFvXjn19mlDtuysh
         IikQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Qq2UvdnGF+i0lv3cQE2vwfxzP0IBqc7zAeM21eyo6SQ=;
        fh=CPrzOEDppnzZ/UHPCSbYcyakj1EnUeYmmjDL9qoT1hA=;
        b=pYE6FEls7R7OZ+vnNiapK/zq/76mIgtIbDU1vOVJeBEam8+KwJ9MqyBjJLdR0AIjoc
         sBus3URnC0HmD1XbiHypANnFNbLtRMRTKUEzTQBbRz5+PAVLlPNo2+Kg5iyEj2DhtgvA
         E3YGsVqbeFXcjmLkVVmuux1q8C89JtTcNcMv8EhISbZjzwHY5ws/at5q4k1bJdoFTCLm
         kQSWYu6MmiBQsVKtWJ9M7BksFZlgVpE3R8D4nhsvjMRuD6IFxZ/KNTYK9pvmIIQtv+RW
         adnzgKCMCeZjFihSMpqqu2DTrVs/bmLY7lAmia7Ml819mJnFXsHN5KkhOz1Jfmic1cvu
         Ffdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ventanamicro.com header.s=google header.b=dVYNBA6Q;
       spf=pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=ajones@ventanamicro.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id bh5-20020a05600c3d0500b00414024b3027si77875wmb.0.2024.03.22.00.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Mar 2024 00:58:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-4147e283c4cso41475e9.1
        for <kasan-dev@googlegroups.com>; Fri, 22 Mar 2024 00:58:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXvndvkLLDHWHgdNNDgGkOusUGowRR2mF8a+AUa61hxmhA2uPI9O1diEKN3+/gR1JeiQGBOKoYN9WDaHDYUWyvTyMLEQItxpmsdRA==
X-Received: by 2002:a05:600c:3b17:b0:414:b66:51f3 with SMTP id m23-20020a05600c3b1700b004140b6651f3mr1050755wms.14.1711094324659;
        Fri, 22 Mar 2024 00:58:44 -0700 (PDT)
Received: from localhost (2001-1ae9-1c2-4c00-20f-c6b4-1e57-7965.ip6.tmcz.cz. [2001:1ae9:1c2:4c00:20f:c6b4:1e57:7965])
        by smtp.gmail.com with ESMTPSA id n18-20020a05600c501200b004146bdce3fesm8016711wmr.4.2024.03.22.00.58.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Mar 2024 00:58:44 -0700 (PDT)
Date: Fri, 22 Mar 2024 08:58:43 +0100
From: Andrew Jones <ajones@ventanamicro.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Deepak Gupta <debug@rivosinc.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, devicetree@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org, 
	Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, 
	Rob Herring <robh+dt@kernel.org>, Guo Ren <guoren@kernel.org>, Heiko Stuebner <heiko@sntech.de>, 
	Paul Walmsley <paul.walmsley@sifive.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
Message-ID: <20240322-168f191eeb8479b2ea169a5e@orel>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
X-Original-Sender: ajones@ventanamicro.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ventanamicro.com header.s=google header.b=dVYNBA6Q;       spf=pass
 (google.com: domain of ajones@ventanamicro.com designates 2a00:1450:4864:20::32c
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

On Tue, Mar 19, 2024 at 09:20:59PM -0500, Samuel Holland wrote:
...
> This is really a separate concern than when we write envcfg. The per-CPU
> variable is only necessary to support hardware where a subset of harts support
> Zicboz. Since the riscv_cpu_has_extension_[un]likely() helpers were added
> specifically for Zicboz, I assume this is an important use case, and dropping
> support for this hardware would be a regression. After all, hwprobe() allows
> userspace to see that Zicboz is implemented at a per-CPU level. Maybe Andrew can
> weigh in on that.
>

Hi Samuel,

I've approached Zicboz the same way I would approach all extensions, which
is to be per-hart. I'm not currently aware of a platform that is / will be
composed of harts where some have Zicboz and others don't, but there's
nothing stopping a platform like that from being built. I realize this
adds complexity that we may not want to manage in Linux without an actual
use case requiring it. I wouldn't be opposed to keeping things simple for
now, only bringing in complexity when needed (for this extension or for a
future extension with envcfg bits), but we should ensure we make it clear
that we're making those simplifications now based on assumptions, and we
may need to change things later.

Thanks,
drew

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240322-168f191eeb8479b2ea169a5e%40orel.
