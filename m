Return-Path: <kasan-dev+bncBDCPL7WX3MKBBOOYZHAAMGQEVOJHGDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E7EB3AA53AB
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 20:30:19 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d9099f9056sf2754885ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 11:30:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746037818; cv=pass;
        d=google.com; s=arc-20240605;
        b=HwTq/CS7UJJtnho5+7hFRFrV3XkCRbfZX+9Rt2Gi5zNcseNTU3kWqutE5G156Kgjn5
         LpNuRO8z7sAY08YlA0qN5+GAa4QbVJYcCL8pr9CdbwgvfxqnIiGib0U3rELlrkih9Yo2
         Sp1PSFfF76Y6Ruhp11eemJkJfc6G1FPOWIVhgTQxL2m//Q9bIxh5g0N8HOYoeZBRcpk5
         kWVHYMpc2kwV6rUVB9ZwWqU79VDgzTBt+MYlDpE6k9r3/J6zX1EH/X3pTL7purZOmjjb
         1FgnwZeYeHiAA0Fk5zP49gWC9OpqQgv+n9vW4lsO4HI9w2OgcFzcipof0ZGO5vXgIvHn
         1AIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MdiIrB1KzIHk78YKRX7KssbW9adUzbDJAbJ6WMFSAIA=;
        fh=iqtgspzb648FUkACbebh6jyzLwg1gxbUgFwWkj5svj8=;
        b=lKgj0C7fHUgAmVlCahQxC5cxV2GuF3jyT1q3sNYXwwbhiLFDilDgj3vP9d0GdHDQxX
         iIDNXFFzu+MpbAuluMnKTL81Beu3SAqQRjKHBbBe0UPsy0xbvoY/R/HWWeDli8sVVQFV
         qI+SRE/IEZr4us0vjNH/GQ3BWqU4tPn1vNCjZxy48fNHu3H6t7bwepA4CDJKSTf8f/OL
         rPq8N9RlTxuYKimXi+p0dLwIG9g68VDRBYIqj9QGTUaMsY00PXcWQoW/DytilBI9BMs6
         uYFWgZUwwpOKgX7Cx2lka41Q+IwnuGmM9RS+DwCVFTO8DSmebKCvn9pYtJm3V9WwNbsI
         ZyLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JkjsRPYl;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746037818; x=1746642618; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MdiIrB1KzIHk78YKRX7KssbW9adUzbDJAbJ6WMFSAIA=;
        b=nlaDXESKacWwn0MrUw6i7Yd1kG4jjjmiE24veIu46bRwDCv6wGirApZ+ougxSGUU16
         nO9JwtWY4EForyyB5Yclf8QsfSO9wlGnSX7DTO1ps/eiPXKJc/0jnpRrGKn78wsOe+70
         +Lzl2Mhj+gePaqyzW8fsA5sNTgxx26cvQxg3t6a8H5GNAvH5fUJtoAykRmsTRjyKvYJN
         nHnVDYLMMz9vr160qSUEsNmKFmMvvZAk9z9Ilcd47+VDWbk1hLAyncRTPd50MbGKCSH9
         yLkJDqYRtdXHy+wVuCSabeRV2dH05oTBXD53kAh2CCfsUqqwpTsu1mz4pXRWtT7uvt8e
         falg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746037818; x=1746642618;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MdiIrB1KzIHk78YKRX7KssbW9adUzbDJAbJ6WMFSAIA=;
        b=YLCBNMOwUTcurnGeFDF2MjdXUY4pcBrpxg41yUE++rVMTc6VhNH4MmyqjzzNJJ3T4L
         YoW/CrmoP1S0VYJhaagKv+1HjXcZyU88YvIUMUhZuEO5NS9N2y1r0oPF/V1sZYX9jl62
         mkMFtXAoPXCnyxyIcxkrAr7G+4q5tkQ6cemi6rU43CGJoCNbGnvM/8jO7xl48mC/nkCP
         P52rgG7ywHygDpMmhMJaEqi1KKaAvql17ojQiPMfNmyzNG0JzvKZmaHpsuD3yqBchsuJ
         2lxlgmYaWP8ahxDHwzRpZ0D9nO50X90/phBqTGklDW+FuAt/Yz4nnhU3VPT8eLpKRFIX
         ilVw==
X-Forwarded-Encrypted: i=2; AJvYcCVIQNvsdLvDEAYaVzxhLSA8dDgN+7CfAvpXtCl6fwJkhhdGfsUtLe7FwsLQM9GcJIQBn15oTQ==@lfdr.de
X-Gm-Message-State: AOJu0YwTgReItqi9tPyG4MDZfvnP2aWwRsxXS1YYwiQHdcCLtlVGUSMq
	B+CDchypphdOywr+K9gxedW5yU2RA5kCyIgiouO6VLETWQ2XRr7V
X-Google-Smtp-Source: AGHT+IGysxT0oWLR8oWRnMmOS24s59F99EBviPh/NJUUcjg5s+/WkG18tLshKWkROo2wkCWes/7FZQ==
X-Received: by 2002:a05:6e02:1a43:b0:3d4:6ef6:7c70 with SMTP id e9e14a558f8ab-3d96772b24fmr53335305ab.21.1746037817909;
        Wed, 30 Apr 2025 11:30:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFSdj78DBgf6fJ5RVLry0LxS+SY6ignARBQiIclaSrBEg==
Received: by 2002:a92:cdab:0:b0:3d8:a9b5:762c with SMTP id e9e14a558f8ab-3d96e7ff06bls2227465ab.1.-pod-prod-02-us;
 Wed, 30 Apr 2025 11:30:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUoQVDs31Wov98X3QUsJSIqYX9bsxwvWEk521cyaP96Ph3Vz769AKCghAR4rpiE1WLB0CJ+GVS8tR8=@googlegroups.com
X-Received: by 2002:a05:6602:4a0d:b0:85c:c7f9:9a1c with SMTP id ca18e2360f4ac-86495f17c23mr564650639f.13.1746037816957;
        Wed, 30 Apr 2025 11:30:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746037816; cv=none;
        d=google.com; s=arc-20240605;
        b=FqECC9qmhzbx84HvDeFQXtsA9NiY8zY8sgvAbpm3G6/wi5BqdvqNasfF259KynJLuS
         a9y1Nc+xmW9FR+8n/9Wbk3Fl2n+T4rPtZsxzCRAVgthelKnLQRVfWW/VqWSsGrIVgnJ5
         3ylE7Iizje2827rbb0SXjaOVkW5brbqj/fodPzkcx4pH6zi620NK1NXIvyV3i5Pi0puR
         rCKPz9OQgJuOTGAMtsG3Nx58O4qmhzQBjvoxL8KDnlw+ddqovem0BzKmZRuCl2o7sKdv
         Kq9WxPTFX4iVjIpKazLVu4h7F1S8ZqgsNPIHckjx3cN2sa03caVTPmXQ5uV+wzihw7yW
         kThA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hEsXF9Ci0pOXKtOKAJPjgn2loXpllrh4pvEkKsXbuQ0=;
        fh=vuqwRWwINia5VpWpj2ioyjJd1TDgkKVqERd2373s0NM=;
        b=UKfNyTZ1xPMjX+wAeqCvfZSOywcVMDXwTmNJo2W2uMfanSn0Ew+Cd/mFeqWZuHisMX
         7TbQfFfcK2UlljVecGmZjt3DwtVtVPqB9j7zJvL8t3WNDKkSr9rk8S3SNpsgoAcVZdQP
         xa0vZSo6lnDGmg0DgRCyRyKsJAzQPKoZLFFHY6VJdZu6lXi45ltmrn4dJFg/qDIdnQLd
         kpt+Qs6/iCF0RuMHYlNF10wuzWvMefnho7s6gHoPDlpdw/KZjBbJbDMN4AgRotBbRWC7
         XUzQadVQB42rOV9U61fzM0a25FCBPgxHUoUimowPOaDUDRYCKhV2UuTAIO27J+7GAgre
         2IhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JkjsRPYl;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8648bff8147si19568539f.2.2025.04.30.11.30.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Apr 2025 11:30:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D4E904A747;
	Wed, 30 Apr 2025 18:30:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E9B0BC4CEE7;
	Wed, 30 Apr 2025 18:30:15 +0000 (UTC)
Date: Wed, 30 Apr 2025 11:30:12 -0700
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
Subject: Re: [PATCH v2 1/4] arm64: Introduce esr_is_ubsan_brk()
Message-ID: <202504301130.184F0BC@keescook>
References: <20250430162713.1997569-1-smostafa@google.com>
 <20250430162713.1997569-2-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250430162713.1997569-2-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JkjsRPYl;       spf=pass
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

On Wed, Apr 30, 2025 at 04:27:08PM +0000, Mostafa Saleh wrote:
> Soon, KVM is going to use this logic for hypervisor panics,
> so add it in a wrapper that can be used by the hypervisor exit
> handler to decode hyp panics.
> 
> Signed-off-by: Mostafa Saleh <smostafa@google.com>

Mechanical change; looks good.

Reviewed-by: Kees Cook <kees@kernel.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504301130.184F0BC%40keescook.
