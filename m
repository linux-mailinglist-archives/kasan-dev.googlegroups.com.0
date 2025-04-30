Return-Path: <kasan-dev+bncBDCPL7WX3MKBB5WYZHAAMGQE27QMGLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id EDDE9AA53B2
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 20:31:19 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-47b36edcdb1sf5763801cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 11:31:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746037879; cv=pass;
        d=google.com; s=arc-20240605;
        b=UD1gyqw6WFeEiOqp6ATU34ksVp9zyAh0ImKyX4UfodgbjjTby+EBV1JVHUYdKZjhik
         OcwH/b6xjcXPIlsQShbFnr4nxY5R26YeNYm94M0dA81jE34fZihAzWAOtFG3tNQiT501
         kQl9DjLNJf5O+YlND3OwzGgSfLgF2kFsBkl0emUPQlVBernzr7pQNdohiD7iJGxGCzcY
         ZVeQ9814mAQB/LlSCxq1dXXFTxA+IcdIU+kvCAEUdyxZh4vWgVBbBi5n2ntMRKhhm2lH
         /JAJcUg8B0vyWrVktmU5V9pA7CwBRf9kF6skyLzsnwGcTutSz1yp/ZRBZbBm5hFY2Yc+
         qvFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=OYu2rVLvveKq0zpjHG2lwC2bQY6UXg+j4pmE8KHgPGM=;
        fh=M+tZcjVPwA05kfRuFvaPCr/QN18buCJ5DTo0n4hwbMc=;
        b=EZc2Y8byJwC56fJc1FWPmfnzgiajWrQ7usGn7Od8AZ2uc+aBz/PtFqLZAPlKl243O1
         L8XUERBQ/Oa7D8CJ5KpJcI/9EZY2FQZJRlPReWfI1EfSHFa8lc9ILBXBj2p07p9LaoRV
         iN08kpkeUzlPtyiq9S+/qHWZwSfvglHoy5T5pJUAzoCYMcuX6qb5ZtAvgrAYqM2Fa3IA
         dH1IyySB3uUWV4+LZ/L0NJpkqLGrESKT/CqoTFwwHJSFq1lt40ToVGxZ9RH/Qdr4S0Kn
         d4nO8eVjU4DW53B0OVu9TGyr+1uzgsXQICMcXwTxHQ+mBA/0b4evs4pwgpFkPxMdSyVo
         ut9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T4k78qbE;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746037879; x=1746642679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OYu2rVLvveKq0zpjHG2lwC2bQY6UXg+j4pmE8KHgPGM=;
        b=gldOfJa7cY9PaiE/nJ+i4zbe9JoUk0b8YA+ijtlsZ7HrQ9dy5B8wH5gx8lRuQf83k6
         /nFqs5s3uzBUGMJXt8O2K9vkGEwwKrpDVS3iBQDrSb0tqQltbEcJEScoRmiTdHhHOPAb
         XirWh8QRzdg0PR/mlL4tYDva2ueJsN1unkucLh99JqBHN9oJBxjxNacX2AmnrgV3uuFz
         EJwB23z2YyM7R6mz6dOvbfGRTejwYjfKt2oJdV1amdo3jUnng20s6c9DNH/lIp2ZOzzC
         KtdGp9aNWVLQSqQ3YpbqkujrFIfmSLsbpP+dXLFcf6msjYawZ0R1NEYdMiqVhIq1DuxP
         o+zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746037879; x=1746642679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OYu2rVLvveKq0zpjHG2lwC2bQY6UXg+j4pmE8KHgPGM=;
        b=ayjtxteNU1pY3YwLq3lP+b7fk9Xo0lplieW8Hs3ST5Cdcjpup9Da4gL9meY2Xhlfdl
         hU3q3wcpMqjNjkTP59EaRM36zjMR7sFau6aaIq/MKN24UZAWjnkRkQRm/4ojwK2ixz0Z
         T7g8sml9lx2Tsbi8uOvkweX+g72gfqEWGlILrlOjOWUL7rk1B5qafgeVXWe/hGPs1FhQ
         X4AzDueX2qUUtQ+iiOrbUKT86wkXkwCzCs8ZkJvk+jfLoIg8/l9vCGrUEl2TCxZffkNK
         BMtl5/xx76SoPSXphFMdjwAkcoCD4HmWsIq8tRC6uJlHHw+ZBDTB2dEFCHw0GTbp5+sD
         IHng==
X-Forwarded-Encrypted: i=2; AJvYcCVyW5X+TZt3+n0IKfIw/ic484CZn0gdppRnVKa+qyiTJxqe6TLIiZO23/eRmcMqNkpyscJ3KQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyvi+pMEglatY7ziUWkTukINXfVJk93yERhBZYEdQ8GLgRQlqEf
	iQT4VsoStYo394kaohI2bVpS5ygDsBRtYzY9XfMtsouYtLNvQL8O
X-Google-Smtp-Source: AGHT+IEnxDGfKMrguWWdY7xrBt8iKz+GNMbm2PfD3RunLls594/VyuimSVY2jpTOPOUMPxnEBRmmpA==
X-Received: by 2002:a05:622a:1b07:b0:477:64dd:5765 with SMTP id d75a77b69052e-48ae94acfd0mr4676951cf.44.1746037878732;
        Wed, 30 Apr 2025 11:31:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHtfdpi6auYFBM8PzinidbAwq21OD8+CQJlSblkGBtd0A==
Received: by 2002:ac8:45c5:0:b0:47a:e5d0:12f with SMTP id d75a77b69052e-48ad89c7f8els1750571cf.2.-pod-prod-04-us;
 Wed, 30 Apr 2025 11:31:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUI+PabYiKcUzDwWvzIltPCix/9+QBuWU3l17u4RBOJWeHP03oj/6YRc8EV+/ml96SBHFduBM0CoOk=@googlegroups.com
X-Received: by 2002:a05:622a:5a06:b0:477:e07:4c5d with SMTP id d75a77b69052e-48ae7b1cad1mr4889411cf.19.1746037877907;
        Wed, 30 Apr 2025 11:31:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746037877; cv=none;
        d=google.com; s=arc-20240605;
        b=Z3HyJ1E1lBuothfuVKWFNMino5oJ0CiRu6JBN92/pnFsGDRbCHn01TkB7Wo/iCX+n2
         e1FG48hmNwIA7Hm6RUgcYeON5Uf/x3OOU5rYqL1lo8DM2d8dKJOdbY8R/8gTMhLUvjxw
         kMghOV4iEMwkThT6Z83REBQc4cvVmgAcIa79uPEThzyDBJMCPYRc2kC5Vb2A7VVtXfm+
         aDndLnunXS7BRYktv/Fmx0ZJWlexSCttYNgFDp/oKfHMA9+vNbtKPTNgczmo+u780X65
         QNDVCECOpne4bmUyfcE4NqGJZ98DDueTV/QuhOQXOS1NL1YIQZ0WTJE2VWOa/OwkVnSb
         AQ6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ECWK0nN3GpkTgqSmGsP1qzkrOrQDOh0oY5fSTP+e/mo=;
        fh=vuqwRWwINia5VpWpj2ioyjJd1TDgkKVqERd2373s0NM=;
        b=P9A4x3l8FPmtIlzFe+px0+GrlJQnpGrX1xzZc/epV+pQsuhK7TrPYCAmjReiII1JSL
         6punebcWMXCRflHbvFv0HQjkozauarpss02W9gZXEfaNS+lF7gOriSCKrVHHkRUkIuCD
         PXHMVDBeYncmGOTx49y2YJjZab5iqiRFMvY0bsuIacdXnJ0+Q6pXfuEip40cK82R93Uz
         MaD/SCtVrNJFDvOub3A91nyiNKTLTS46GjF3qZpb6xgEEaAF80FKqwjj3QfYbDBX6qhI
         yAOi6g/rgZQ2UVniPm8iQNzmgK6byewkuBtmZWF8THJ4MBDYe+A0HWepmkB0WFmXW+4/
         fpNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T4k78qbE;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47eb02be0c4si5122841cf.4.2025.04.30.11.31.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Apr 2025 11:31:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 23436444C1;
	Wed, 30 Apr 2025 18:31:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 36EA1C4CEE7;
	Wed, 30 Apr 2025 18:31:15 +0000 (UTC)
Date: Wed, 30 Apr 2025 11:31:12 -0700
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
Subject: Re: [PATCH v2 4/4] KVM: arm64: Handle UBSAN faults
Message-ID: <202504301131.E58BEF14@keescook>
References: <20250430162713.1997569-1-smostafa@google.com>
 <20250430162713.1997569-5-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250430162713.1997569-5-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=T4k78qbE;       spf=pass
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

On Wed, Apr 30, 2025 at 04:27:11PM +0000, Mostafa Saleh wrote:
> As now UBSAN can be enabled, handle brk64 exits from UBSAN.
> Re-use the decoding code from the kernel, and panic with
> UBSAN message.
> 
> Signed-off-by: Mostafa Saleh <smostafa@google.com>

Looks correct to me.

Reviewed-by: Kees Cook <kees@kernel.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504301131.E58BEF14%40keescook.
