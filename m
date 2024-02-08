Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBLHGSKXAMGQE2QRJYEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA51284DECF
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 11:55:41 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-a3571b434bfsf27199766b.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Feb 2024 02:55:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707389741; cv=pass;
        d=google.com; s=arc-20160816;
        b=TPEbKMmex+rZAyiEnUQVhuxji2jqgfYVrpXr6itpgnQ9N7c3fZAV3Y/bPm6FxCmTWt
         GqVR2dz/c3tRjo0o6x3Gwr3/0+IjFYgWyDVsZpGXsjQqtvRrA+f7BKLKd/VMaKb3h1R3
         oRL9bPgnjEWo9t+xBubo0i4RBOx2h4qx00uwKzssYWiCFqP00uaeKyTK3ioOnGo5xmAs
         LJQw9wljU6s7k6OxKEOLzSdJfLQxKtIe/CR3Se4KxXGwx9S4jskxs5u2eFHW4ST6Sz34
         hBVdgk0ghE5m4wcXWhQTPdn1VSCg2PkaET3NlHCmREaCe9e8tSyDcWJz3zQV+f0oNsg5
         3OaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vqNSKN/yew108nEdxKC5eiEOldJPjZWX/8RcePUNB9k=;
        fh=odm+mx4lfWTKarGx4W3mcm8OvlzL4hrRaqtT+S7fij8=;
        b=k2gGmkoWQF6pCtDr7ifMXvvMeTKO5EfXKSu48cDDwtmjGDRXOlEsJMgpGe57qdFCF+
         wwPO/NCwcX/UvDcG4L8KvdD3xNGQlHQB4cLLNJaTlQeph6yaRaGjdp3xQnMidM+WO3VG
         UUKakA+Rr+ujrjd99xSkA/GxyhodMNoEtcbLolEPMMroF+w7wEsfFkWo/BbT0UzqpHAH
         dA25LWDpV3wwozyduYC+2iQt51B2WUFVxaMruit8KUQtb6vqTYH5I9g1InA1XnF+DRzi
         Ro6olGw/bINVSknbbXZnI56l1NYBVJ2HM5fDQEer6CEeJYqRKDk5R3Q/4YP7nhc1bmTt
         qPig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=ghGKhaLf;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707389741; x=1707994541; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vqNSKN/yew108nEdxKC5eiEOldJPjZWX/8RcePUNB9k=;
        b=A+JEXz+YIIKxEDCW+TZ4kV5ezRdqVJbGrmTPmuEe/jtIgHynjCuHjTgdNDpvPwIOoT
         nKNRe32QjWoPeU429JhtVsTX5tF34+jY2CV+SZc1IC/AzUmrZ+WxY8MxYufpCpFvpmtP
         NbLGeBR2LuRLqrVPTkxwbmxL7I66fAmPbz1dVnNMeVo+iO+uIIohE7bP998j6oIV09r2
         f2ftFzBU/SsiAJrFfY3df+RQYBbFtAd2mqtj7VGWiUntXzQJFOIqoBG89z51kVS4DhIg
         DkM63FVOrD7+dBzUc6tc9Jt8AgCfDwiBVHRKMG815DxHyOiht7Yd5lToPmEs7bTUSFg1
         R0Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707389741; x=1707994541;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vqNSKN/yew108nEdxKC5eiEOldJPjZWX/8RcePUNB9k=;
        b=M9yh9m0KJbFFcv6cRVZfvOj7BnBccvGp+xoa27TbE6JhTwrzTiCx5E1gCuce8QBROM
         7+GQfvf+iCk90a2YSg9K6N1mloBB5h4t9XwAVZZZdmWHSct2oe2xSmsQDBAjeza1tzjz
         eq3iV2Gh5FBW6AZzBsmsPGbcqC7n8XucXuaqO78CmJOc5Geqn7vXLT/iAg1aM1Dlosqq
         5xXYGPrOTeh9ShYryLGj9pAJQfScKtqmR7nkdy4E7HAruL/u4M72zBBdxFqt8dbTtUSq
         rKrNeJr9fJh8hUJsOURt1fEBg0UsVfrYR6KPqz3t+jNHNDxS3zQH+VXoFziM3pf3rfd9
         Gt/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdiPtVTB88pO49tnliN0lA/hIAWQdHh1ffXxBrrbNqGar+JCqaLAABarZjMxxbMAjx8VIWtFJXBLRRYfl++w6IvUtgqNUX+g==
X-Gm-Message-State: AOJu0Yxk96SZndVB5OwBfHFFCRDmQpDy1plI8A883Ppb1iEgzishKanR
	7yxrqB37zGBb8Jn5nyWQtYnz/WYDOgnTjLb7htvLqPH3I/hlNRCm
X-Google-Smtp-Source: AGHT+IGKhAPmVbk/SQPBFE+trlHntvbjRYZMKnVvrOi5m9s8x/ck7TaVlafMGJNCGkWn2j6+RWbAXw==
X-Received: by 2002:a50:d6c6:0:b0:560:26f2:f8a7 with SMTP id l6-20020a50d6c6000000b0056026f2f8a7mr6463442edj.0.1707389740618;
        Thu, 08 Feb 2024 02:55:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:401e:b0:560:bb98:b04b with SMTP id
 d30-20020a056402401e00b00560bb98b04bls771245eda.2.-pod-prod-06-eu; Thu, 08
 Feb 2024 02:55:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU88AQBnekHsbAc6Bks/ENXdbuZrQErLq9DrkvdqYALeSuTqtuHXC5Jj8nwerXmqMtlXuFIV1Lqwqi6AGYONiANSW6/H9Mjn6SGgA==
X-Received: by 2002:a05:6402:1651:b0:560:81c3:cadf with SMTP id s17-20020a056402165100b0056081c3cadfmr5807988edx.38.1707389738623;
        Thu, 08 Feb 2024 02:55:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707389738; cv=none;
        d=google.com; s=arc-20160816;
        b=yu71nKZFaTqnIEwDfUr9R995VjEcsPD7hOkcXHhyjXOKxyQsaCzKrM0PBopB0suWm7
         t5WcD8MaInBJUOg1hNIFFKEFrIpeNh9VzZsbGyM44qPv2faRmgQTvhpr/Onr3G1Dqnt+
         LQOaGzGF/52Gk/xvwWsEtvrGU/8pw+ZPGQ0AFEjmWh63cDS1xtnTwayjmhipbKvPHOfy
         H0iX8wtlHRXqdoOhQ6yiS/ENWoE8061UXwF/IxK9l3WnNby+/yhO+JhXRYEhYYtTyviL
         wRuRzUbb7SeskIdScswZp4z5gkGU6iwWvVL5KAeQj6zJb4JWKrKRUvZkpvR9vd0b8IAo
         7k8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4dqcHEtm0V+r2N9kdvvX85ax2ZPQFWE0+wTfUSVpdEE=;
        fh=C1FS0mbjfUkMPa8pI0QRYa/iMmuMEnitBMUIHMUX/cE=;
        b=kVfwCWMvmQcEzsmFmOUVTYAAyMoGQqd3LCKaGno5biy5/SQ9O7vMP4MHySShOKOKfP
         Qj8IY7PoAsvd0z3Npf0hG81SKfnh1ZxEVhwv7c9eHHgaYxmlyibYoBOdT56aAZ0Iufsh
         H8JfJbrDXjWhApBHR/+JdgYDU9A81MQhwtk2rYqlM8fJ56aoPPKdYFvIzEJFqc+lEH5m
         NOUCUmSJ8r7WEkzZgkGvLqjlpGooqCsuOReaxGLyqYCj5/5RgyVmT1rQz2FbtQx2fHR+
         zYakjU4Kiry1qWeUGehWndmkxSKbT+k3BxB0YazQJSLArzuotyw+wl+1AsXbdTe19ulz
         HeeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=ghGKhaLf;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
X-Forwarded-Encrypted: i=1; AJvYcCWwlmt1e3x43niyGVFdTB0rZG5KBehdFW0z1xjPcitqwUcXAydseAFN1KFpAamV11OnV9+jIMuOYRmr6UWX9bl+o+9QgBTeRUpe+Q==
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id y6-20020a056402270600b0055f361dd78csi36183edd.4.2024.02.08.02.55.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Feb 2024 02:55:38 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 568B740E0196;
	Thu,  8 Feb 2024 10:55:37 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id w9Aw71IIhNTF; Thu,  8 Feb 2024 10:55:35 +0000 (UTC)
Received: from zn.tnic (pd953021b.dip0.t-ipconnect.de [217.83.2.27])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 912BC40E0192;
	Thu,  8 Feb 2024 10:55:22 +0000 (UTC)
Date: Thu, 8 Feb 2024 11:55:17 +0100
From: Borislav Petkov <bp@alien8.de>
To: Marco Elver <elver@google.com>
Cc: Jakub Kicinski <kuba@kernel.org>, Matthieu Baerts <matttbe@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Netdev <netdev@vger.kernel.org>, linux-hardening@vger.kernel.org,
	Kees Cook <keescook@chromium.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: KFENCE: included in x86 defconfig?
Message-ID: <20240208105517.GAZcSzFTgsIdH574r4@fat_crate.local>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
 <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
 <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local>
 <20240207153327.22b5c848@kernel.org>
 <CANpmjNOgimQMV8Os-3qcTcZkDe4i1Mu9SEFfTfsoZxCchqke5A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOgimQMV8Os-3qcTcZkDe4i1Mu9SEFfTfsoZxCchqke5A@mail.gmail.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=ghGKhaLf;       spf=pass
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

On Thu, Feb 08, 2024 at 08:47:37AM +0100, Marco Elver wrote:
> That's a good question, and I don't have the answer to that - maybe we
> need to ask Linus then.

Right, before that, lemme put my user hat on.

> We could argue that to improve memory safety of the Linux kernel more
> rapidly, enablement of KFENCE by default (on the "big" architectures
> like x86) might actually be a net benefit at ~zero performance
> overhead and the cost of 2 MiB of RAM (default config).

What about its benefit?

I haven't seen a bug fix saying "found by KFENCE" or so but that doesn't
mean a whole lot.

The more important question is would I, as a user, have a way of
reporting such issues, would those issues be taken seriously and so on.

We have a whole manual about it:

Documentation/admin-guide/reporting-issues.rst

maybe the kfence splat would have a pointer to that? Perhaps...

Personally, I don't mind running it if it really is a ~zero overhead
KASAN replacement. Maybe as a preliminary step we should enable it on
devs machines who know how to report such things.

/me goes and enables it in a guest...

[    0.074294] kfence: initialized - using 2097152 bytes for 255 objects at 0xffff88807d600000-0xffff88807d800000

Guest looks ok to me, no reports.

What now? :-)

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240208105517.GAZcSzFTgsIdH574r4%40fat_crate.local.
