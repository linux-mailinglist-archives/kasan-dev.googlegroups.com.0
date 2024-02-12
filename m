Return-Path: <kasan-dev+bncBCF5XGNWYQBRBTWXVGXAMGQENGTRGZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id C77A1851D8D
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 20:04:48 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1d9b1f2b778sf97485ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 11:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707764687; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZrREYhfIDNRX02rEGrdN9uZyRCeZCKRGAEoH8vTj6bTt5Nov0AL6thWZMemRKfbNHz
         r8E0A1A8gtDLGKeREwk3yi0LEjHDH7wwrVv9RqaYO5K8t288zvbQV6fv9ZNGHXZyzS0I
         ntJkS3r/rvIwNtVFu1Zf+XPCrFCXuZT4C0zd7PGcZFBXN8SD6T5XtjCPrVl6jgJIMb4i
         VYtM79youSgSZ6mV5377E08BiDWPRPt4hkZl+aAG0rczubBTpGNS97s4/fJGXZpX6AxR
         jqCyXK+oNQsR3He3FDkQ72GDVBC5rTnRR4p0YuCj/rRDoiHoEeurJ46o3r+VjPE1ZXEs
         xilw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XSOabdfJCc/ZbdLvrbxu6zl1D3YlPc4WYjwubELbxzY=;
        fh=CMdwfRKYaQTNOrRx3DnbyJJXX14FT/u+uQT6J8e18uc=;
        b=XEj0usZR7fGgFNrfPDAqW37uoIWZaH9rIETzHIHLiIe+rLnyUgteMVLS8yF1Wuztef
         8kIsFruhQle26WHCOpQXhCTMDH92hog122w/kf6hOxe1hoCPVawHIpyBmz+5RLrF8rub
         rfBfeV9e7CbIaD10IgSeaD9uLe6wF1RzvjPVywSf2sjwoXnpyWB3pgXVG6/fPEBMMhY2
         upeUHja1DisipYGhrDt1PVWm5dZ+m0a0SRZccIHktMb5wKRdRDMg3rMXRaF6NNIfDuLa
         t+veWXmGCKg0etqfinjL3ylhBPb/o6ucZVllpIlV5TtYXacUO3SE6qAsZ2pKPnGYtdgY
         I5OA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Y6e6N0mU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707764687; x=1708369487; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XSOabdfJCc/ZbdLvrbxu6zl1D3YlPc4WYjwubELbxzY=;
        b=m4zZDWm8+IQ4i53MmkP9299YgsN38+dwBmVlNPVXpsUql5/M9HVWchV9KO+XKa1VZA
         JpW8TW4zyhblkLfmJPgdUxeosvjJM78BeUoH9d01IGzISiQRz5LRoxHrK4ls8SEpZmPJ
         KH8qh5niSzuiyusUdiEbhB9hn249gdUlD5s+KDci2oBkKab0GaPqL6Uvz6oe8wqHG701
         yzLkt1a1gyN4LYyzXONM9H+HpeldB8swhlGHsb8UkvnxKZIAO4c4I9ErnZNqfWRLuPYM
         uFR8vtkCXHhTknTkrTpFAaKLfll8kdnp+Uv5UCrX3aqw7MCzBnVmp9xIE2F1BuKHK7uY
         csXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707764687; x=1708369487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XSOabdfJCc/ZbdLvrbxu6zl1D3YlPc4WYjwubELbxzY=;
        b=Nz3xEHnLloFInAt7r/v/hWOsX4CsprQDfQzPfUK6zrOCS/NNIKmlEXO9oQVwnbFL6t
         RnVvQIA5nZwdMoPnNGB3yHNogP8hVjv2+o8gxsOZgu5MOutK0WohzdxIoYvi+oHhs98X
         HPA79rZDV2fb3apIfxCS40OmtKvDFHgXJf/t/vACTois3YYU6ciA57o6cRfUIzT34P0L
         /4MJhTPJEOj0e8QVLH0gzqBwU+aBeX0VFCHcybcaj2QUxHZX0uzspqS9wqmLLNLrInQX
         N3JT3G332aVpUrHZr6PgcoY7wmKW5n8NSK1ygBEx9SrHqQJwlz9pVhzwCk3Op9V2eZhw
         2f2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy4wi6nk82Uljf9MWsaP4AdeQS0b6gGYT0NabET/SVvia18LpFo
	YzpWFx9+sXGZ5izGbFoxo9l0mKT2CiEGk9VBXhfl+1ryNNdZzdRN
X-Google-Smtp-Source: AGHT+IEWuA1zUJ5eI5IdWrnbKrmdXXeAHXxDc8KkTZ3WdwE47CRWKSZfXzZ1kaKWSaB9fjNit/41zQ==
X-Received: by 2002:a17:902:eb90:b0:1d9:df98:f35e with SMTP id q16-20020a170902eb9000b001d9df98f35emr340085plg.3.1707764687097;
        Mon, 12 Feb 2024 11:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:558c:0:b0:59a:a4a:21db with SMTP id e134-20020a4a558c000000b0059a0a4a21dbls423213oob.1.-pod-prod-06-us;
 Mon, 12 Feb 2024 11:04:46 -0800 (PST)
X-Received: by 2002:a9d:6502:0:b0:6e1:128a:6250 with SMTP id i2-20020a9d6502000000b006e1128a6250mr6198391otl.5.1707764686253;
        Mon, 12 Feb 2024 11:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707764686; cv=none;
        d=google.com; s=arc-20160816;
        b=ls/+CRHb4A6vG4MiaotV5k/BKLAtT6kCSPnw3RTmla15I8xAXRAchv+oAXXnyt3D2g
         4n7t9OP7UAH9YP2VSuqillLQ+d1NjMm+tDytaL57oY86n0ZK0D2KqZVBomiFJ7EaPEOs
         ovIMxmlL3FPj5LxPXfv7tOkVycRWwfhlHgRUw0R5A4bnOtoT/W81vJ79ytoTDY6ErNBW
         X1y2FemkymDvajSY/0rky1ZixXuNGL7UQHnELuX4UDDUa29X2bR5yothkTFVHju1eDx3
         Iv8w0OI8R+36mnX0zb0DLgy/JW6JwCurDrgBjoQ22BbSWMlconcTGYW9aJ9q9pYcPnc/
         oHpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=D9Gd6e25cxmqAh8U9n9pGGxOPN3zPyZPlpWz7dOHdE4=;
        fh=CMdwfRKYaQTNOrRx3DnbyJJXX14FT/u+uQT6J8e18uc=;
        b=p0TyZYQsMqKwPIjUCRkq8wQQglWRFG+G/d+7+IYur70vZsbgbGf6usyP74DXVCaNUN
         0eyd6KFtfxXe/MF9qWQQqPq+pH+opr5WdIX9u5xUX8DYf8WbAafEMTjDtlvGeXI3efte
         BKwr3WovHzSirSIyMW4DxkzjD7Vo47tnv4Wd+FzS56C1q8n37VcsFDXxRjcAFOa1KxiW
         eEayiFfYTbSvZmHuMXLewmPh+jqeE5jjEznV1Y9hSUBNTYSTRjlQ1q24aJPWpr2CWuVj
         FR2fNgpF+xy5FrW9rOo3dy+vPJYR24ckMqmqfZ3AfOy1QgG/lou781CwrkexR4s4OS+G
         IrxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Y6e6N0mU;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCV14Km+11jDN0zDkGCTjNQiI88O2RukNwwaPZdzgosl8+3EaYiOVzgTtuq1bBGv9D+K7ajEvYjip4YW+KXHQ2+O3Z2WBTd+4w894w==
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id a26-20020a9d471a000000b006e2dc907d04si100068otf.2.2024.02.12.11.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 11:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d2e1a72fcca58-6d9f94b9186so2970609b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 11:04:46 -0800 (PST)
X-Received: by 2002:a05:6a21:3483:b0:19e:3654:7d18 with SMTP id yo3-20020a056a21348300b0019e36547d18mr9708752pzb.10.1707764685511;
        Mon, 12 Feb 2024 11:04:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVO36wXJ8WF/oPUZEEFHM50EauKzF40TtKrdPyNMlGVlpDVNdEQVzaf+BHz8hXP5ZhzX9QvzEGON/bIfoHGREsez1nnyFc5iQkIVKhJHIgDw361aU1icXsRc7ySM5b+39YHXjyHYGxgtBAZ6WkkJ1PBc15aXHr0HvH3BGX+dzpUVCLKhRQE5qSFYdn6nrz2Jy+nZRRrlLOsdDVNIb70suywLv4VsjK3a4+tF51PlwNvdLep5NC4bRlMBct0WDJM2oCmAlteto0wc19cB8l17q+zgDJIiaI=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id t29-20020a62d15d000000b006e0a55790easm5079811pfl.216.2024.02.12.11.04.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 11:04:45 -0800 (PST)
Date: Mon, 12 Feb 2024 11:04:44 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	Matthieu Baerts <matttbe@kernel.org>,
	Jakub Kicinski <kuba@kernel.org>
Subject: Re: [PATCH] hardening: Enable KFENCE in the hardening config
Message-ID: <202402121104.4A87C47C87@keescook>
References: <20240212130116.997627-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212130116.997627-1-elver@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Y6e6N0mU;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 02:01:09PM +0100, Marco Elver wrote:
> KFENCE is not a security mitigation mechanism (due to sampling), but has
> the performance characteristics of unintrusive hardening techniques.
> When used at scale, however, it improves overall security by allowing
> kernel developers to detect heap memory-safety bugs cheaply.
> 
> Link: https://lkml.kernel.org/r/79B9A832-B3DE-4229-9D87-748B2CFB7D12@kernel.org
> Cc: Matthieu Baerts <matttbe@kernel.org>
> Cc: Jakub Kicinski <kuba@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>

Thanks! Applied to my for-next/hardening tree.

https://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git/commit/?h=for-next/hardening&id=1f82cb2f3859540120e990a79abfee8151ea6b93

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121104.4A87C47C87%40keescook.
