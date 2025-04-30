Return-Path: <kasan-dev+bncBDCPL7WX3MKBBU6YZHAAMGQEOI7DXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B042AA53AF
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 20:30:45 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-47b36edcdb1sf5752811cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 11:30:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746037844; cv=pass;
        d=google.com; s=arc-20240605;
        b=fJ3MYNFHg7tPAXOzeCUe01rOv1M1pAY6O051+nVZS3tCJcv3wJxRLSyJJBbNxYniXl
         8LSk6RpNyfanS2f1EVfpomlucga9pBcy+J/2sRsV7u4biFHIgfxUejDfIXUxxesJJzXJ
         9DZdCm9YWtk2lgmvKrZYFODvMYTxyni52EI+kQGUvYlp8aOL4WBanUuLMilo/7VBIA9A
         yDT+VNjBchj/7yEsjiXLMEd8bJuhxnQ/JyR3uq4JmWPxwD+gldEIeCmOF/Mk7Peb/7El
         j/SS2TJ7NnEGLOjNGt0sPvqXsQNOg6cmZw+sB7TiE89E77uDvno/om8VPpTCZ2a3+xs5
         P5Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=T8V1Z0RBR9Tv2W8wZykdTHuSPRAOMgo1ppzjHkZstdA=;
        fh=sTnbtlsVg8KunFL68o5uASmSeff+fzjZQGjBapIF7t4=;
        b=DqLwrhyGoVxUNwvYPZuT9SUbQJKlSfKtlIQoekQ6Xu+wNjVnYwaguiCl2dcppvlIvM
         2L8EvrDB+Eux+1h82DmPglLnDNG4FS3AIvf8gdOwK6p600eJnwdZpw6biZRu66kbGHcz
         kAhQBYc2mmjxUbg769zIWW1TIqcCYl+Cka/HBd0xbdWLHvpheyeQHl0y2v74i4aAHaCz
         2l7mEcOb0Syf5WhPhfN6QeCO37n2rqdnTjuLMSD9TLRuEkAomK0LTCRyiJq7s9/DzQTw
         1AcINKt/Cxk6lTOT2Y4YJyg+aIRY/UQcVwAycb6LafJsyOoy9sIp3tYzonX4cbJ3foWQ
         OfDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qop5rON8;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746037844; x=1746642644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=T8V1Z0RBR9Tv2W8wZykdTHuSPRAOMgo1ppzjHkZstdA=;
        b=fa8DVIG2/RFebeiWH/a2z3wmqota50xAaCwg0zxH1NH8/2myHb+gqU0Lc5JtkajnjP
         Gz0tFJqOL1BD/5A8upgLfqwHDfZw5Dgz1Jdt5sqnJ2jUHhOVI6FJa3o079s0uFQdOA2o
         8Xfj9fMLyaT4bkCb+B/bmZ5kgEHOrXSSC5ndAW4DaPVrSb9ZB2XQnetVjks/4QAZG2KU
         gid/r76crTGEWGPkWk8wYU3GEusjcUy66HWH0o4+EMiFX3lhBx/hVEoW/K3tWC5d0Uj8
         rKnANwrN2QAwVuoHaykZjejiOuf+yScJuKeFTEQz/gaFl+wU9/O/M+xw3P/2zsQY8Wwc
         hrgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746037844; x=1746642644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=T8V1Z0RBR9Tv2W8wZykdTHuSPRAOMgo1ppzjHkZstdA=;
        b=BJrTtuDJWb64JjgnS7twKjIdbzrFw8bzySXteCts8R/biDf+xHzhZG0hKmDpunnREY
         j6cFoOULmJXC9xXbx2e2oza+o3dWPS1dPwWRVDBUIBSR7xXkIG4YWBeQJGKHyrksuJIm
         KaksLOUP2Z+lX+883hTrtkk+CsUmqGxolBGwvmD9ld23+5S7LBc4HeC8QqzXBim6nGDe
         suMOKpB2XggNM1J7GbXQ0QLny7e1rmtock3V8HqP+Mki2SeCrDlpHpmFou+W57lVTquA
         YTGBIa9TAAjTSyuQ3aitOcRm0DZQDQ5IYg/1LZtaUMtBNSqu1uZ/CKyGvYNoDr+mJ7eZ
         Qc2w==
X-Forwarded-Encrypted: i=2; AJvYcCWtTLF4tShF5V5lgM9HkmcJbpWfNuF9CZYhRCJVKpdwI7XEgRkmLCbrWeNdRJ9xCEjcdAe+YA==@lfdr.de
X-Gm-Message-State: AOJu0YyPxE2uANvZDlAR0ngUmQr1bUIVB3k2+G6e52B9sBz6wZx0pZAW
	X3AoMow67SrlfA+3BUzLRo9Ctcy7jdtxskBJoeFgmRKUzqp7rNho
X-Google-Smtp-Source: AGHT+IHfns1uVHTbUP7B9zMvoGtD07e3izxAPR2FMVxLxhb2+It3V9ZKxB4e9JSYBqNB+2YvhkM8YQ==
X-Received: by 2002:a05:622a:418c:b0:476:b461:249b with SMTP id d75a77b69052e-48ae7a1feaemr4511401cf.12.1746037844110;
        Wed, 30 Apr 2025 11:30:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBElLFTdd55OC7S5x0ot2uhQf6XaRsYQp+Qy29kSoajvWw==
Received: by 2002:a05:622a:4787:b0:476:aff3:74bc with SMTP id
 d75a77b69052e-48ad89a0e50ls1616851cf.1.-pod-prod-04-us; Wed, 30 Apr 2025
 11:30:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtjgwiPtF02HUe9l4wGz84nE2kNy65LxCMfBV/YD37lPUJB7elLJRg2U6GmE6Nhc9Cicp7B/SfkXY=@googlegroups.com
X-Received: by 2002:a05:622a:1e19:b0:476:7e72:3538 with SMTP id d75a77b69052e-48ae95a4310mr4277431cf.50.1746037842148;
        Wed, 30 Apr 2025 11:30:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746037842; cv=none;
        d=google.com; s=arc-20240605;
        b=YgMbe4TP9z7+KEXIJ+pel1h1oIpz7e/X18yNTKUm4oeTv0Zjaiu3P7g2rKEVk9rsGt
         x4iAN5fpaBWfvwql/UYcwjOjuv8CvTDQF/sae6DgYZU3ZD4ZOsoGV9VazBmOK5Ica1vO
         HQ0ebI4FwIjhn/DYL3EGzozUkORU2Kolvrpx2Fz5rQug1jhK4nHGJVub6qVRQm4DJtUc
         vis7+tifAFDVTe6gVI+yya8Djorj2ou32SqPC3q0Qu/O6ByQZAZL8fBBC1Kz33bCokNK
         FpeFxj7o4kdWa2pgMcMlYCZZqUJKQnTvCMK8aG5w9+SqxrUYEf7ge317GE1ffue4hhuE
         AcaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fl7g83EJcOWH5FHBku4zjmzjCnfMb9T61oBNbl3E4mA=;
        fh=vuqwRWwINia5VpWpj2ioyjJd1TDgkKVqERd2373s0NM=;
        b=cz6gbivHunv1jsz6DXOEfNGKKIlvBI16OqYlgtQFOraA3G0vekI6I3Nz1pQQ71Qq7Q
         870PR8qtkhARwWYmPRyXBMa/5eYVeDA2zZ4oslKpU4gEoUNWxfzlNaddeCOaUEYgW8xs
         xrNv8meDnmt5jO2ngeNRQftJCC+qx/GS4g5VenORaAV9otc4wIYIAxXEkdy8QRkeBslM
         E/HYP/MRR0j/LdS9ok4xtplAWudg96nUwMfPrIpJuhvbvVtddyMmTTO2kcmDiBpDfKF3
         B9kyau9HqVlGkfPUTESC72Ku3o7Zi+dIHkZA8rF27BisqLoDmwkM8IdekE9g1bWzHX9N
         Ct5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=qop5rON8;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4fe6aa8a5si965446d6.2.2025.04.30.11.30.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Apr 2025 11:30:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 18FE74A14B;
	Wed, 30 Apr 2025 18:30:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2F53DC4CEE7;
	Wed, 30 Apr 2025 18:30:41 +0000 (UTC)
Date: Wed, 30 Apr 2025 11:30:38 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mostafa Saleh <smostafa@google.com>
Cc: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	will@kernel.org, maz@kernel.org, oliver.upton@linux.dev,
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com,
	x86@kernel.org, hpa@zytor.com, elver@google.com,
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org, yuzenghui@huawei.com,
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org,
	nathan@kernel.org, nicolas.schier@linux.dev
Subject: Re: [PATCH v2 3/4] KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
Message-ID: <202504301130.3AACEB0@keescook>
References: <20250430162713.1997569-1-smostafa@google.com>
 <20250430162713.1997569-4-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250430162713.1997569-4-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=qop5rON8;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Wed, Apr 30, 2025 at 04:27:10PM +0000, Mostafa Saleh wrote:
> Add a new Kconfig CONFIG_UBSAN_KVM_EL2 for KVM which enables
> UBSAN for EL2 code (in protected/nvhe/hvhe) modes.
> This will re-use the same checks enabled for the kernel for
> the hypervisor. The only difference is that for EL2 it always
> emits a "brk" instead of implementing hooks as the hypervisor
> can't print reports.
> 
> The KVM code will re-use the same code for the kernel
> "report_ubsan_failure()" so #ifdefs are changed to also have this
> code for CONFIG_UBSAN_KVM_EL2
> 
> Signed-off-by: Mostafa Saleh <smostafa@google.com>

Thanks for the rename, this looks good!

Reviewed-by: Kees Cook <kees@kernel.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504301130.3AACEB0%40keescook.
