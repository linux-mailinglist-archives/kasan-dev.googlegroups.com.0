Return-Path: <kasan-dev+bncBDL5ZOFA3MARBKGMVCXAMGQENOYK3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 63169851679
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 15:07:38 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-6e0919e07f4sf3068783b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 06:07:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707746857; cv=pass;
        d=google.com; s=arc-20160816;
        b=ux4IBkBsNYkBpMqptVkv2PZykgePXNoUguz5rX+Z1LQY984w9FphL19tMG7kHwf+/+
         Z2da0B/I8Jo15Qz6ZlkulJZhbFJgvVozJ+RPYqgFv7hby5RgG67GnLX2ddCQw3bqWPg9
         kYJQU5LDVAt+tmHZFbrwwNRHderxaTkubqwodYyKeFst1UTdbPt5C6HaGVax9Evm/dV8
         poqVK02vNAhf+sgrYdB/f60x4L9froB8oXV95CdU6Akmzgg5mAQwT2ZgYtqCSlWPVJxu
         BNZZP1HFn0/9Aq2fTxoccrXa47uO5akkdstLSffZIFrtThIjcx420TIW+ZKNjO33toTc
         /XWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=z+vnBIb9UPN2SNNQdKDnKJxi247avKY1Abu5KAt6HxU=;
        fh=aQrfaKunhZ4xrJEz2jFQgAoeEPSOeJY3AS4PC88qRy4=;
        b=FqRmX/akVi2B2bMVMpXzHuUe1Y8zG+Wh4KBzqFWio8d2zYs16epmVUw9hJk3DAFxUT
         yCvmddvb89/XvObybJG4c4wc4MR++jbnWyTYYCaU6Yae5RB0ETcZlz20/dLUlmmBWl29
         IN4jPSlOnQREba4lnBr2dT9MZVZ72UoJTAsZ7+4xZ5nGQneBWqIxIfpcsF8XstClcdfN
         kfRDSPVkXwezvtjqRe8RZTsTqxhrDK7em4xfwwvj9iOaRbFt29RipdQ5wUz6HmfAN0BZ
         HWEON8koF+hhtzd3hTC0i8fHgBK0qB8xWYTVz71ZfevwNif8SAaXBzst8SMFdLThbz2r
         GHFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VBIv1suT;
       spf=pass (google.com: domain of matttbe@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707746857; x=1708351657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z+vnBIb9UPN2SNNQdKDnKJxi247avKY1Abu5KAt6HxU=;
        b=dQDEbY0fMkO9VF6kK3RwBarUigqa3ZLSQYj+gm5xckGzYSF5rGhqRE3Q1OuOWLX3v+
         z6p/aqHjrhQstJSyxV/rgsM1XwdSHw0bBUw21xRtbx1ut/SRa/5OQF7yHEyqhUFK0pW0
         cgO6mlOkdoicj719/QjS2JSHbUjEdKsPDL5+Ox+kqjERm3ALt+f9f0JzmwuMMONoMS50
         BvWyN1T6+GTlJnAjMtWvXiYbWeLRxUNgxp7S/IUZLbgx2iS4eJfXTfWmeo43ITJgL0kC
         EDKiRZR/69gzhpgI7I1IGXDkye66BfbmKRIf5ZZXQXrNObBPF4RUgprXT127FN0U7pGZ
         uhKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707746857; x=1708351657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z+vnBIb9UPN2SNNQdKDnKJxi247avKY1Abu5KAt6HxU=;
        b=BbS5ANIM3rEAjgu8jUk56FCfSz1J0BwaOR13K6f4oicAaepb8bpm9AXn+gSEwxShQR
         EujEoQlq3ZpEjUnL2gk1W4VEIkJuOkyHf/m7RHjj2WINox7h1BujHpiECdTCXbIMQ18p
         d6I+w4lY+9NXybxl1hvm4Gmgr4VunXourKykjMrRJejTxbrlfyeF47IzFEtfUlwy+MHl
         nyBe6wTouGmQqN0k4wNYNBGLTMcRzbHPdE27a7S700V8ivVy6ef+1AH25ZEDGVyywg8S
         Da3jusbErXx3RDQgrV3buwBy7/j85xiCBNW8P2pJuYxMqFFRctCOEoE3V/jwZZNsTrQP
         xZ3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfFf8TZREW3ETDbhdao1y2bt/Lo1pW6f1m+2Ypsf5U9ekLG+JxyUoe4L5y8ORmdlx4/Bt45iSSjMv9pxoJ2d/0CxElMABtGQ==
X-Gm-Message-State: AOJu0YxZ5wtLMRDd0YcAKc9L9cXs+9nbW1CDF5wkt94HHv7IxYDDRDeI
	WXbbVCS/y9Mb9cxM7zHwwyySBnzUeMiJw5JS+xsDE+XnKJAX17yK
X-Google-Smtp-Source: AGHT+IGPKwKpuZpn3tO1ZsNdVKpDWXDCZg0HCf8svUtx+hDy/oeB2r/ZIBoU3qi3KAvQqk636rLamg==
X-Received: by 2002:a05:6a00:be7:b0:6e0:8618:d06f with SMTP id x39-20020a056a000be700b006e08618d06fmr7961478pfu.15.1707746856926;
        Mon, 12 Feb 2024 06:07:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d91:b0:6e0:e588:64d6 with SMTP id
 z17-20020a056a001d9100b006e0e58864d6ls308354pfw.2.-pod-prod-08-us; Mon, 12
 Feb 2024 06:07:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX+eubw7gDxAhQLb6RtK5/lWIM6x9skjQlWSxlZ4UjE5yuuj8OMkfe42kOXWzLIRy/pIHB1LTY8pn7Jrvf8c7M0HcBdnpjxtjbCXw==
X-Received: by 2002:a05:6a00:450f:b0:6e0:548c:97e5 with SMTP id cw15-20020a056a00450f00b006e0548c97e5mr8194762pfb.2.1707746855603;
        Mon, 12 Feb 2024 06:07:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707746855; cv=none;
        d=google.com; s=arc-20160816;
        b=sDtspk2+lT6N53vIsvXsnTG7UxpEm/vJbQRd+ql8LW/ZYM4F3+5Dg/6aMuh/ZrBelg
         ooz0/PJfJDUFcl4m+SEoCADmWomcBlR0TPC7VHk2G8ToAIxtk+YqDgwxyzEMVGi1b9B6
         t9u8IIFVXgiNQeVdiqbz56l6AiXTHvF9uWz70I5w/CtwKw08RWsW7jzZDQ8JIFPPP5hi
         ydvYdV7oCaQZcEWPOQiBbMqwF/aus2ZZwjAOlN+YZtQgeVSEfAjNgx76F8joEqU+2Vuk
         8Qn6zbCVeKvrZbK9WZ4AfaWogap4mDDwNzn0oZ0c8vxrGEP1zx9FoJGFBlcGZm9O8zjP
         Fi+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=wQZzxnB8q0V2Sg/50mGuBeVOfVry+bx6wLapHA4lhuw=;
        fh=LmE81iqzJ4reeYTLIbeRiFYoIHLbsWx9ysJjQgny/eM=;
        b=QRr6+sQ1UQzEV5/G88emBfcPMQVPM1YUeQmHGfbgKX/wKjiktYIjbqFe+RCRZPTO12
         3Mu2JF3EDsxwRLQd7yRAI4MJ0XSby9JrobGJxQ2dswkUmn4I+jSB7Rkq1nKv8fPx+G1A
         PNmoIdB9sD+v1ikoynp+Wsd1Dh4ko+85FN01Acz8f9J682GITM3aajXMherPDWIW1CV8
         doeekGW4UdsacW32DnEUYAmfzTwbnDbp2ZicbQW/2f9KJ7MDdqCYnfyDt6bE/DHWb/1W
         c2eYQbaB6hd5IUYh0pSwZqW2v3A4TAjn5LrRvY5wjjmuj7AoTwur2azLkwsmLZSzZ3xR
         6I+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VBIv1suT;
       spf=pass (google.com: domain of matttbe@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCWDLDIW2jdt8zAyIR9tY4vdn0Px+SySkXGDSPilhcZQD6YSWPzV/+MqlhPg6Q1WZatu67q5OxAua32U3fBn2rItkxIm+2ahtkj2JA==
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id p6-20020a625b06000000b006e06c8a8c7esi1059671pfb.1.2024.02.12.06.07.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 06:07:35 -0800 (PST)
Received-SPF: pass (google.com: domain of matttbe@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id EDF9E60FBC;
	Mon, 12 Feb 2024 14:07:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 99E59C433F1;
	Mon, 12 Feb 2024 14:07:32 +0000 (UTC)
Message-ID: <0ffbfd54-57d2-474e-8dad-7f1469f4da21@kernel.org>
Date: Mon, 12 Feb 2024 15:07:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] hardening: Enable KFENCE in the hardening config
Content-Language: en-GB, fr-BE
To: Marco Elver <elver@google.com>, Kees Cook <keescook@chromium.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 kasan-dev@googlegroups.com, Jakub Kicinski <kuba@kernel.org>
References: <20240212130116.997627-1-elver@google.com>
From: Matthieu Baerts <matttbe@kernel.org>
Autocrypt: addr=matttbe@kernel.org; keydata=
 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
 lzVbFe7fduHbABmYz9cefQpO7wDE/Q==
Organization: NGI0 Core
In-Reply-To: <20240212130116.997627-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: matttbe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VBIv1suT;       spf=pass
 (google.com: domain of matttbe@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=matttbe@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Marco,

On 12/02/2024 14:01, Marco Elver wrote:
> KFENCE is not a security mitigation mechanism (due to sampling), but has
> the performance characteristics of unintrusive hardening techniques.
> When used at scale, however, it improves overall security by allowing
> kernel developers to detect heap memory-safety bugs cheaply.

Thank you for having sent this patch!

Cheers,
Matt
-- 
Sponsored by the NGI0 Core fund.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ffbfd54-57d2-474e-8dad-7f1469f4da21%40kernel.org.
