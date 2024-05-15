Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VQSGZAMGQEQWBV42Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EEAE8C60DB
	for <lists+kasan-dev@lfdr.de>; Wed, 15 May 2024 08:38:56 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-6f4739ba7dcsf2889452b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 23:38:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715755134; cv=pass;
        d=google.com; s=arc-20160816;
        b=MWlBwCLgbicosWTcD/yTTRIY+UoYJSqf78oDqGpsIJleZNNmaSlVcehLTbDocqLQjc
         NrDB+Rkg8OMIVSzpjqDwfn2RDsZO+boK1AKAEwccR+j2/YkhY0srQSX/EU+KSU9KXO5G
         +Uw3VCeIiU4qOmEcYa5h/O9ahcR8sOp99nENuvgXrfmlWScPQOKjcYMg2krWW/ffWbW2
         hLXQG3E3kzGlydaiqwCqDns4tbn8eJ5yQg7WoVPPHk2qOjWGMMbWo2G0eWwXio60g2ET
         9GTmqaJdb1pkyK/qLTB6ZxNp9Wg7NzUSq8xjd+Q2HiyeINETiAH70S3VzJCINSsCGgcF
         uX4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GEhL+PsG2QfsIYGFjX3mIqDpa0YnYypzs4gs2CGluPE=;
        fh=kO8bj+Rdo5DTRxKvp2HbD2rFTGlwoJ2SHRvChYFgqkQ=;
        b=gnBupjFyY4VadOwACupAb0V65/lpZS4KRUFDfrtWdjtSbv5Q6QYrMNEkVJBE6ysoF9
         CpHAdvtUCt13vT+0HraucgyOq7eORoiCv7yj9H/32SDE3wd5Xfpw4tBc+8EMEvQhn0Gj
         OUdHK693bcwvq/yOQBr0MryV0+sdIdmM4s/29Qid+0iiNVUyPRax6hEhnT9y5DNIuY8I
         106sgsRlDaX+wKzMCe0y/wjnIFNcuXS77/wX6dfnNNo9mwG+jPygmHM+6N4YoSyxTJV2
         WGKG4YGcFpT0ZdOKDmWSKWapBOxIzaF7ZNBs3/Host8bRDC3jTBEZkN8Zh1eecXD85Xh
         KI/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h0l+RrVN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715755134; x=1716359934; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GEhL+PsG2QfsIYGFjX3mIqDpa0YnYypzs4gs2CGluPE=;
        b=e7D01YkPZRo7XwzCgBUg9IYnJdCUrbyRRu/p8nVku+7pEQ1JvvgEZFIGZ0liIe734p
         qoKBZ0jMLpUHHNx++yYP3u4ePWvDp+YvoQaGZn2mquHPiZjh7pnG3+VJy0+RYSCW51K4
         y7D2PJsRxA4l2rjgUTln0xaANBYGmMEP7R/yV8RrEJ46Y7I/+1uwvJpvM49jpeQaWatT
         Z86GRcpSF+EMngUZsqWjs7t+f+2KBLZhgIkYmcoNa70CmbrHE8lFWjxTnUiHGrDshgIH
         6XolH1cDtSLxwENnilpdSr8tPH8TH3hK7U2Nkgx+LLcnbZtAOSu7DR6ZHsBEi4f8uDQ4
         6syg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715755134; x=1716359934;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GEhL+PsG2QfsIYGFjX3mIqDpa0YnYypzs4gs2CGluPE=;
        b=i6hLHGobauS2+Rqvn8wc+3mqfXdahtycbH/0/4Kl/CB3X1mtPtLU0POeV0XuiAS/K0
         QuK6Z5kwU64Gp6JX/D6S8cKiBZ13h/V8o6++e0wCKmWHQfWlPi0GGvrtKrencNd0DilN
         RfdUvvWs54IjvIuPeU0MdQCRvlSt4WwgWM5+9JLjn8AOyOXm8C2VP1MTANilhU2Jr0CM
         YlkbFOyIv2uLTnGOyUxQrpfMJ5v2SwrDl6L8OueRL9x7mslU4ceCzorkMBvcs3yxXH+A
         fnWK7PaO6y1KMA76d2g0euFe+TYxDPKJ8susy9NoSzMFW5BOAPM+CHRepf5j/bi/QfSb
         JMZQ==
X-Forwarded-Encrypted: i=2; AJvYcCXMTgbk2t7p2aIqTkBpriY/1MmErP00O3dZ83zIEP8mXYWlCCMlRU5SUX5WoLKGVjeciZfMWw4jWJS6MEcAnKVbfX39CeSECw==
X-Gm-Message-State: AOJu0Yx6RFa2hwXrD0UO/NRifAa6LIa8l/3VT8PVclbVvxOC2LlkSYg7
	y7Vv6iyg0UyE219nRD0r1i/V6jJDXnWuqhM3rBUbNbxIhUjBf2ef
X-Google-Smtp-Source: AGHT+IFP/vU1Wj0vlAAN3e3HsY70BNdWA6tvb20yy6e8yY85mphPqEw7ONmvvmqnAB8d7OOq5FRtNw==
X-Received: by 2002:a05:6a00:230a:b0:6ec:fd67:a27e with SMTP id d2e1a72fcca58-6f4e0299dfemr17105805b3a.1.1715755134331;
        Tue, 14 May 2024 23:38:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:301e:b0:6f4:78b1:6b79 with SMTP id
 d2e1a72fcca58-6f4cae1657cls4536642b3a.0.-pod-prod-04-us; Tue, 14 May 2024
 23:38:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiJ24IEoRWw5Zo80XvrJRxKbJPMYPnJ5GLFFap+jGN5QQqUYYjtKMtHVXs3/jLnMATbSxLkuh4ZlcdXfZxL0pLHbFzXOdQrixygQ==
X-Received: by 2002:a05:6a20:729b:b0:1ad:9adf:febf with SMTP id adf61e73a8af0-1afde120efcmr16286590637.31.1715755132925;
        Tue, 14 May 2024 23:38:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715755132; cv=none;
        d=google.com; s=arc-20160816;
        b=vEh7KxFgYW9lqbwLEUBJUX2TV7tL7HKAceaF6d26uIAJoRC+KwXdzKpEvBcjtSbNx/
         zIuhkATDjc7UeOEVRPlSS/kbZP4xmx7566V+lb7lK/eatSeAELD4YR2sU2sPjAzgsLjY
         OwAQaRQPxXQCSOW1kOC9V3oo0N16eRBGMSbq0CnKZTuCw5/MTMvqX7xg7RDVFRvRS+Od
         yW+DC9Qup00HiICST7ZdAB/8xvaMlzHS7kdHJXdIvvXQEumIl2E2jzIW8r8oFDO7VtYd
         4zMQ9iTYB5+07OpCmRT0rRqNg8B3nDAaMvRB7TCSC+UcA1JTmPFTYxEPDG+iRQtwyBQD
         rGsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vVNSHkVmQ2QEQ7lf4BbvPSzpubRsxHLfx4PuD65Mr2w=;
        fh=qY/10ywRi/2oAbucAcM5rp8oK3dsCZh/wwZLTChKII4=;
        b=Q0/uris7CfdZpBdRYCORcrwiiyOsYfx8rHGDh1MDQkaTJG5yzw0dd8xONqb6XXciZJ
         vpS0qXc+eaY3nyLVHXeRLDTnda6cTqz3BPo7pSIKexJPHbvaENFtWz3O+rpMmV/ycdeW
         V0gMP0sCBnbQX67kgJD76p6qU5n55pYydZV1mATd7JJ0au95YsLhx7JhBw2Ml6TiDup+
         2w5GbDfjTL2CSw29hjl5UfsCYJpNs/K8Jg/+X/X800g11DYCNdzDldyr8wNPulFsSqmr
         VOpy/hPA/WPGNrinfcldrsEouR026XvSY2I010EDbHNPBkjq5z7F2mJaUnhocRRRnBU+
         +Rfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h0l+RrVN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-6f4d2a97184si793893b3a.2.2024.05.14.23.38.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 May 2024 23:38:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-4affeacaff9so1669944e0c.3
        for <kasan-dev@googlegroups.com>; Tue, 14 May 2024 23:38:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/fqrci6ZKwEFNA0WQlYIAo1IzgqQpdroH7dK0JJGju5LE+055p9EImwvllidmgg0uMjsE5IU6LJrYxBQvzFlnzZAB6ejNrVxbKw==
X-Received: by 2002:a05:6122:4698:b0:4df:315a:adab with SMTP id
 71dfb90a1353d-4df882c2956mr13577261e0c.5.1715755131816; Tue, 14 May 2024
 23:38:51 -0700 (PDT)
MIME-Version: 1.0
References: <20240514233747.work.441-kees@kernel.org>
In-Reply-To: <20240514233747.work.441-kees@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 May 2024 08:38:15 +0200
Message-ID: <CANpmjNMmNvW41j8RfqZr8asW5BeRXLFkmW_MTO_DX=xEtQNgFg@mail.gmail.com>
Subject: Re: [PATCH] ubsan: Restore dependency on ARCH_HAS_UBSAN
To: Kees Cook <keescook@chromium.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=h0l+RrVN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 15 May 2024 at 01:38, Kees Cook <keescook@chromium.org> wrote:
>
> While removing CONFIG_UBSAN_SANITIZE_ALL, ARCH_HAS_UBSAN wasn't correctly
> depended on. Restore this, as we do not want to attempt UBSAN builds
> unless it's actually been tested on a given architecture.
>
> Reported-by: Masahiro Yamada <masahiroy@kernel.org>
> Closes: https://lore.kernel.org/all/20240514095427.541201-1-masahiroy@kernel.org
> Fixes: 918327e9b7ff ("ubsan: Remove CONFIG_UBSAN_SANITIZE_ALL")
> Signed-off-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> ---
>  lib/Kconfig.ubsan | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> index e81e1ac4a919..bdda600f8dfb 100644
> --- a/lib/Kconfig.ubsan
> +++ b/lib/Kconfig.ubsan
> @@ -4,6 +4,7 @@ config ARCH_HAS_UBSAN
>
>  menuconfig UBSAN
>         bool "Undefined behaviour sanity checker"
> +       depends on ARCH_HAS_UBSAN
>         help
>           This option enables the Undefined Behaviour sanity checker.
>           Compile-time instrumentation is used to detect various undefined
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMmNvW41j8RfqZr8asW5BeRXLFkmW_MTO_DX%3DxEtQNgFg%40mail.gmail.com.
