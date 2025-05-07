Return-Path: <kasan-dev+bncBD56ZXUYQUBRBZOJ53AAMGQE7SKJU5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 997D3AAE8F0
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:22:31 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-22e3b03cd64sf1256795ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:22:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746642150; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rb5dq9J4A9zrlU0NZIHFRBIwX2MbMmjVbNfRTpyHR0WeRo6sw3Ypvqhh9Lxjo97lAN
         up1E0BhlngVwqL6VLjhr52ycdQZEFySNF0uxIlJbqHBe5xDvCUZeHxf0haEamVba4MlU
         ccuW4kw3cOL8Xq8h+769edRgaEPohKFZXMHD5oLDUfVlHdp/53H3YwT2DuiEAsC/gBgm
         70CdENOTZ5yLWT6QiREJtrSr6YnvZVFVOE260iIF+icwttJRlLqbpnzYYZau1GFbV2vK
         aevGCFMWEpWrN95KGsuJLQZ/aE/N8TxC8tdU6w5rER7dgzrfj+XDr8GI5u8rJRgaBfaM
         SBsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=KrrdOlUnJwdGi3H21zjzSBKDjMYSb1xq7Y9+KIX+hao=;
        fh=xqfWQqFPlIpaynOYmv3lrgjRen/qHebeOJJhP5HsBQs=;
        b=Ok5s4s7ODJeRUJd4hHQwigfb4BF0ibAiWjpVQbEoL7zS5ScRG4M5WyX2OyyuMQg10y
         ymaJ5z2U69pHBzBxBZy/yTI2C8cCBfWB4IpNiSQU3ZZcrjlRzf4Rw2urA/FFdLKqQFkY
         V5htyRIhzORuI+O3J9nCm7lQBQRQo5dOERSHS9oSX/07wt4BIfxNQJBSUYQsM0qMZMtz
         ArBijZi2MUd/jNX9PVYFRFT8LY6rYTNTDF5FCgGK758Il7Ud9gljvEeGdA2Er6eG+JfS
         4odE7QKTYfaUlTArQGyf0hp8/cr2JXTzXhw8wPDy1rxZxlV5A82QLaHEZEY7YcWSDULF
         4fLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kArIe70s;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746642150; x=1747246950; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=KrrdOlUnJwdGi3H21zjzSBKDjMYSb1xq7Y9+KIX+hao=;
        b=xE/h7s54q7+E/c2VwG1S0wS1dGP8cWrZe/yya3qx1AEGEgAZ9940ssbdG4dg9KPlnv
         1AIFdks/iqa2sLDnS1y4fQeYlmmhL72q3rDaONnYEIcpqz2Z/JOGcE1vD+3qZYZtLXrk
         g7rqgJljiv5OYAnHQktRBG114ZuoZsi/42ao538VQ3FUTdHaWaRryDAKWcKqxIX0/slN
         HnVi0fIaj6ZmTcJakPK2EF2/ILyzurBkh9lBNCP9mX1nFWIXYFQ1hRfKE2CwoDA7H3cK
         0r2v0ZJ5kSnlv1/vFrZzW2D4UEw419uarGQ/+V30HZDoDYHK4ZzGj3mqx/dAWyj5H7Xh
         8gOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746642150; x=1747246950;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KrrdOlUnJwdGi3H21zjzSBKDjMYSb1xq7Y9+KIX+hao=;
        b=BjjRL7GARJMTSujDp0YNctRhrI5prHdfr4svzViJTSxeQXx6Q2KtX6nd81WgTGn9ap
         hXq48/3GU1kHRkkVn6Od59RSooxd/xpQSwdlNKHYtE+Kc7yhkX52JvBCGv33Mu97+emT
         1RA8HifdyW3eJkCtlbRiH/OzLWxMTjMzMgNUnsgDtkl/0PKpp+GaIuk0sqJ1iioNa4W+
         lzY3OjDQwe3I6mEcGt2IkzmKJ6QjRJH5Zk9YgALbyguQ4/2XYYjhOlx2zJrHzTA5bYdn
         /y9OJjHDU+UnGh0xHipu+V6JErlt76WTkK1v9rlczsWXZfsmdW15QDeefoatDFpXqzqf
         ZwJA==
X-Forwarded-Encrypted: i=2; AJvYcCUdHs2gSEVxpI9tKqfEpJsPsi3KTU8BFIw1URYR4UnbceI0dVnbkY46sdhjbK1QW8HQaitJeA==@lfdr.de
X-Gm-Message-State: AOJu0Ywxyc7fvIyC3AuVF2GcwJ/LUUN0d3MYFh/EvSQNnCiGzg1kmYQV
	9hCJe0AH4+qiNKda/grpfqcmxEHYVHrip0RC+pM1pIAzpy2TsdKp
X-Google-Smtp-Source: AGHT+IHU1TXNOxNEsOuOjA31bjn3HU+Img3QC3hyQCHFlnBzWdVAFTaUU2S90k1MuiMXksaSmWvJ3Q==
X-Received: by 2002:a17:902:daca:b0:223:58ff:c722 with SMTP id d9443c01a7336-22e5ea73cebmr66447925ad.28.1746642149905;
        Wed, 07 May 2025 11:22:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHNlAP5CDgMmDZqMgm+2Tocr+eQLAu4KZpWuaDJidSV6Q==
Received: by 2002:a17:90a:1507:b0:2ef:9dbc:38e5 with SMTP id
 98e67ed59e1d1-30ad8a563dals116871a91.0.-pod-prod-02-us; Wed, 07 May 2025
 11:22:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBHVUCASaXHiryItFN+qETaiqXUHvmoUPxEZYEh4QfROOSJBVTeSe2MO7HFYuMo0Fr1CoKhB9qm7k=@googlegroups.com
X-Received: by 2002:a17:90b:2249:b0:30a:fe:140f with SMTP id 98e67ed59e1d1-30aac21f358mr6576171a91.28.1746642148407;
        Wed, 07 May 2025 11:22:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746642148; cv=none;
        d=google.com; s=arc-20240605;
        b=lpNYftxEVPKKttGm2TDFymFg9wUSKEwox3JcACC/qaJ+I+tIxawXE9MD8ijbZGvpDf
         JA80WAzdsrLrh/bMBKeSSGNEECBKo7riPuAmKaJ0gvRg1dxaPGZavf/8gVC5ku78mPGq
         2EQhrxMeOl4RJ0ljbXxKawpJIhEGLS+UMuSR4/9GAE62ENd+nnKgDIhArJOdBnGs2eYe
         Tk8uNg5t9Lk+hE+0OXOsBH/pxTUFT8uL7a75QpFHX/g6XYp7jub3d3Td/B6FBwiH4jtU
         KN+ZatQ4FWcCtU5jr6PIR/MARMahZopT9eQatx4rjFRHzFfmFk5fXv53rVYFGAyRuikA
         hajg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YMcr7kQ9TGaTP6WhqfZiDNaymUksVxM7RBsyZue/exk=;
        fh=uWegRM3R61sqvGjK2EyAFeCl7Yo0t2kNXyohQFnhiL0=;
        b=Ar7vzZTaxBcwQrpvov1lqIlAvASjTv4Fw/Dr3WmJ+zYzZ/JvDsOCls0ML9gXI7tMQV
         lpaK28SLxGRx3tSgyVMW/8PlSoyjc2xKEMKu/7/jyFe/Mk2KWz+0xF1Jk2oM5RDgqmIi
         cEHEOLpk8Js7/v8Z2jTUojcchDCe363CkwmsUV1CqwwA6aYG8S8PHYO1aNG8tGTJqt3c
         L5yyVDZcK3+NZturrgezRrs17HF316N6RgPaOM2G6TXfPAaQt9wEi+/9AUzz9QiKHSIJ
         FuYHdeUPgf0+g+zJXVoQ+j8hMCWiycHSeCvnsDbNL+CxVmzrVbhcSYG94xIz32o9ly9t
         Iwhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kArIe70s;
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30ad483f220si33558a91.1.2025.05.07.11.22.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:22:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 865D6629DA;
	Wed,  7 May 2025 18:22:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0BDE8C4CEE2;
	Wed,  7 May 2025 18:22:24 +0000 (UTC)
Date: Wed, 7 May 2025 12:22:22 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, kernel test robot <lkp@intel.com>,
	Jens Axboe <axboe@kernel.dk>, Christoph Hellwig <hch@lst.de>,
	Sagi Grimberg <sagi@grimberg.me>, linux-nvme@lists.infradead.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	x86@kernel.org, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH 1/8] nvme-pci: Make nvme_pci_npages_prp() __always_inline
Message-ID: <aBuk3nBDOv_6wFCT@kbusch-mbp.dhcp.thefacebook.com>
References: <20250507180852.work.231-kees@kernel.org>
 <20250507181615.1947159-1-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250507181615.1947159-1-kees@kernel.org>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kArIe70s;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Wed, May 07, 2025 at 11:16:07AM -0700, Kees Cook wrote:
> Force it to be __always_inline to make sure it is always available for
> use with BUILD_BUG_ON().

Reviewed-by: Keith Busch <kbusch@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aBuk3nBDOv_6wFCT%40kbusch-mbp.dhcp.thefacebook.com.
