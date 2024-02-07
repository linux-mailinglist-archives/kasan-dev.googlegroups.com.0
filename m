Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBCUSR6XAMGQEX7HQEUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id E2CB484D0FD
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 19:16:43 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5605cbef331sf931a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 10:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707329803; cv=pass;
        d=google.com; s=arc-20160816;
        b=hqLf/Gdv0hEdHsjSdong0754s0nCYJxw8EFlDYu1IVJDqGVtlohKZtayeWzAoNy7c0
         rfc3YBtEApS5An9adK7yey2vLF2DkR4T24dytXMad+j/o5ncKMzlcjhAHw6WFJAGbMC+
         dikXeyLZwHZ9HYmZ6v3vVpQidJiYN8TUXxibz7pVTOocC7HnP9ka2cbr8rSM+Eo3a/JO
         oBIy7nb7byW3gOzOqSc7Kv6nfT2s6D7sF5w0k5zmvPDwa8nhKGPtO5aZaotoeQO+SOhR
         MKT2ws4ReG2Dhe3F5ozq+oUsmZs0HnHeXOLRgLA/mEBivCj+3+APxu6fF3LLXJZlq0gz
         WiKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kf/m5wQaPPISOG/CoDeOYfezCSSYixpkNjpY0s+o+Xc=;
        fh=mWAk0Cw9j8//lWONbPmcn2kYSFy51JbHL6OZ9mAbqYU=;
        b=cOTHYtjlT0VsdW9UBeIOHXGwbqV0BBuUWS54tbfo4ZFJLFabdQ2HWFndX48cydvbdx
         P8HARRJLM2cuw1Y7k9Gc56RPSG9+Y004IZ9QVLsiwb1OYrEGJNL5klP28vZF2hQsgx9H
         LfOhA+WeYjXNdRoKCYIswymZ0gUgI0s4k1r58jstu+71MmR9bug0lnShDV/oqB82zHhg
         mM+RsotHcpNW9oyoFq/p9QRdvJCfuHC5zRUJPIhrXbk1B2iHYzIZgdHiVYew36Suj6Uv
         OKitU7jG/LriXIUlRmoKudLegeotz/E0VG4R7fm4GH8eDFTeyH98HGAJnt+8u9mrcwd4
         HBwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=UPBO+P9m;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707329803; x=1707934603; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kf/m5wQaPPISOG/CoDeOYfezCSSYixpkNjpY0s+o+Xc=;
        b=hpdKC29eA6GkGlsQfFn+lT35WhYOuIT3TM9hFlpe+zxfoZkE6cm716dKdmXFHZti/d
         eKdpSiQEft9+JqoJJFAQAagIQDNPTwQRk8X1SSeiTpl0MVxMFc9UOdFCtyJvCAS9TRXX
         4h/kY3cI7Zg8xKap4mpNavfM7niIc3JJmZUfcmjiMTB501RKFK9s2uytWuWlGsdY8KD2
         UfzMpQv+L3aawdxzX+TLKI0H36+flwxuF92dtiAwSFpaTo1SoP2sTrp0g143LYZ/tQaV
         zroWpgMlnIHE50DPjI40xiyxLHmvOq4aPnw9c8Igsn7smuqL2OP6DHstqIylFH7HEmGe
         5OhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707329803; x=1707934603;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kf/m5wQaPPISOG/CoDeOYfezCSSYixpkNjpY0s+o+Xc=;
        b=IcK8TFZYpVMjgM6GSw9DQALqI3Rmk8zm0FY847hL1c9Bpd2jXDbPFeiJGQqstSGFOO
         ajbgeaTE2wrzNYiW3gxU8TCHIqFieDW9//I7F1rFT2Z0NhsSI8K65AcC6FuFRFJGjUux
         ToJxPI4IL2fN790khVfer+ofVDLICylSzcVxUrQknawH9dEMmH2D7CuJE5INOaqM/Eu4
         6T28PqFV7+E0ojZcFUKXVpIIRXgiGPfbeCub+w1hKP28Ohwzq3VXaimIQKeShA4JLYyW
         06Ek5EAGAhmN5iZy6+8WIhRwUOwVaI7w5LhDm6fg+D/SLY2OwIH+PwlsP60OGqgODcPa
         aqaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyrNJqyUFwzNq0JJMF7sUSKUydb76Bm+i2IcV/9Ft+vUy84oUKw
	iPdosTzyacaHMRZhLuc9KYs/bchhSv+JFk9iip2tXMHILbQ7lEvm
X-Google-Smtp-Source: AGHT+IHSEmLfvbcHE5uRz3mXuEq4sOxuUn70Z3HRk+H9+owEITYuDcYANrVbn63elxsq6+bGsKr8SQ==
X-Received: by 2002:a50:f694:0:b0:560:e397:6e79 with SMTP id d20-20020a50f694000000b00560e3976e79mr167375edn.2.1707329802446;
        Wed, 07 Feb 2024 10:16:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d93:b0:511:694c:ab91 with SMTP id
 k19-20020a0565123d9300b00511694cab91ls310852lfv.0.-pod-prod-08-eu; Wed, 07
 Feb 2024 10:16:40 -0800 (PST)
X-Received: by 2002:a05:6512:ad4:b0:511:62f6:8395 with SMTP id n20-20020a0565120ad400b0051162f68395mr3854425lfu.46.1707329800147;
        Wed, 07 Feb 2024 10:16:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707329800; cv=none;
        d=google.com; s=arc-20160816;
        b=uarX05Txx3XIQJvApZ/guIGNkMLw+UkccAiqcRtxOpHcpyxgVUBhTWc2rqwCgwxbwx
         0Rq+H4SGW5wzWFubkvem+tnZv9AVr4cN9TqfMjl1GgXKk6zomYRWEhkxgW2eoja5OK73
         OqhjRIs/KqUbSzPgLBdUz4+OmxRdyPFzUx9Fb4QbXIJFzdbn4JmMj3za39KyMf+0CkUT
         1bbzQN4hgrLiloVE67MsSs8ixl4ZBGnZVXdPwS+0k6/G6gRnxNaG3JI5EWdv/jqd/PsR
         JiomgBJUb/F+Qcw1VOreyXRYZbaI8J/h7YKOEpAlAephonqn2p56hdwhJa85ea6bbzDG
         M3Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cF/Z75FRESL/9093tIkb8FBZyiCbHtfUBM3PklHfN0A=;
        fh=mWAk0Cw9j8//lWONbPmcn2kYSFy51JbHL6OZ9mAbqYU=;
        b=v7Ad0QC4OLF2zF6otdZMQYUS17LxoIm5hXAW4xRqqv05ysw6K335zADRIHIcI4OVSE
         2XsBSWXlV6w5o2jaxfad8NV+VlKDpEtPVJlhOvymEdu+e1t3i7/KJr2Twa2eDVtBHL8C
         Aaz6743w7XqQFv2ANZCS9IOs/TQ+5uAbYmAS5sRy6hgii7rkR81HR7SWR9iODRZvp2VN
         nBK+QXPYzoTPJy/peCJ6qVtPvZ4Ak2Mm0LRqNVFFISo0SFIkJ/6OvOipH2qZp0g09IPD
         wrSSSOVHSvT/QDmVmsgJarvl/wFTNR6qiUwzXuZPX53+kxlOJfgPfK4hgIRqJZjvskhO
         Nb1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=UPBO+P9m;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
X-Forwarded-Encrypted: i=1; AJvYcCWzA758ZaCv/LB+jJwD+giMKElW6u8NR2D4WAHZC3vtFaeGjfYcPexDpQCdVgeXwTOvy5YgILeF2eWkHXO/1phHp4LzV9WDC2D0uw==
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id dx13-20020a0565122c0d00b005116bbbbd07si9409lfb.12.2024.02.07.10.16.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 10:16:40 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 4BA3540E01F7;
	Wed,  7 Feb 2024 18:16:39 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id XwEu8As-sH61; Wed,  7 Feb 2024 18:16:37 +0000 (UTC)
Received: from zn.tnic (pd953021b.dip0.t-ipconnect.de [217.83.2.27])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id A5E8D40E0192;
	Wed,  7 Feb 2024 18:16:26 +0000 (UTC)
Date: Wed, 7 Feb 2024 19:16:19 +0100
From: Borislav Petkov <bp@alien8.de>
To: Marco Elver <elver@google.com>
Cc: Matthieu Baerts <matttbe@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Netdev <netdev@vger.kernel.org>, Jakub Kicinski <kuba@kernel.org>,
	linux-hardening@vger.kernel.org, Kees Cook <keescook@chromium.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: KFENCE: included in x86 defconfig?
Message-ID: <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=UPBO+P9m;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Wed, Feb 07, 2024 at 07:05:31PM +0100, Marco Elver wrote:
> I think this would belong into some "hardening" config - while KFENCE
> is not a mitigation (due to sampling) it has the performance
> characteristics of unintrusive hardening techniques, so I think it
> would be a good fit. I think that'd be
> "kernel/configs/hardening.config".

Instead of doing a special config for all the parties out there, why
don't parties simply automate their testing efforts by merging config
snippets into the default configs using

scripts/kconfig/merge_config.sh

before they run their specialized tests?

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240207181619.GDZcPI87_Bq0Z3ozUn%40fat_crate.local.
