Return-Path: <kasan-dev+bncBDCPL7WX3MKBB3NN3O7QMGQELSSV7QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id C51E4A831D1
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 22:22:07 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2ff798e8c93sf52964a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 13:22:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744230126; cv=pass;
        d=google.com; s=arc-20240605;
        b=MeVrdzw3RepByxsDziGVvDY8MRalrb0+pTR3bJxGQuiubu597385FJYHhS+3O501SN
         L7DgwrPO5eBEpF2LnbRGshboQp+EqKuE+XbDGVNlcmzQGPf79zJaWhcFBdomDiC0odEl
         feKj1jK6NMQEmd5o/lY8dn/A6OzUYZPFTOkMFmvu2dx9ynJ97HF0VnCYU3m1eMNOLZEA
         Am5Wv1vkyyGq7oy4cT6i5oJM/HWMHj7tB8G6Ezfdft3NpaZ0sUut0vbfBKEcNTNyXS0K
         QOdvdJ3Q6WZk9dfhQ1sta/rKOC3GJT9sRkDvMNrILmRVb59wPLgH3YlOJIz4taXP18Re
         Bulg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=gj222e/A5kYkAVUTXggQMhCK1RDM4dVGXNESKi/fkrk=;
        fh=LHt5rU+O4hPD8PkI6e5DGgvEmF2UNwgWTeO2+kq/stY=;
        b=Aiuna1v+1lN2xPze6Moffm8CfjcvLaMmrEhHvwZL8zI1BnSxMWRVXM64r7meGwh1Bq
         Xn9NQVcLm7IEMXjj8ikvvKNPQ3YY1e5TU1p1U2DQeqafZqSnVuMpN0W1QarCRZe98Z0t
         SWleOVxG0hMMj2WDUJtuvr6bYxc3JoNwiK3N15f+UFGsqlDnDjwaEdXQhOnw7AQ4NFwF
         96zgsdIsWtFhvEcZIjdVwROfiNAv0uq6gO1qAWOmngZGEHRhSrUVzNMAJ6aapcI9tndS
         Z2AdydLWKh/nQyEeSCaPQ0sXg2O6mfhwiD6rnkV4REQjaFL1WCPF7iX9HTkQlt1tD/vo
         Kiwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="nFWm9V9/";
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744230126; x=1744834926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=gj222e/A5kYkAVUTXggQMhCK1RDM4dVGXNESKi/fkrk=;
        b=rHoRUgsjp0RY9vNAMK4fDTmDVP52I/OJVgVYEqEwT5qf8h+gvVS6QJaf9SczCYFQNd
         8oEZvy4Bkz5gXwICNi0K3n1obsT4WDuoVw4+7I4cCxvlmJ8AA8P/2uwqDlcaC45tbIFX
         rufApN3j1JaXeHezjn6RBupRyVJE4gvrVVchzneKO0beGvemRNNZmKOtXamUDmYlnzRo
         7eHkTJCigVLy1ReAyDhDlQvW4cEBpvwgFtarWOvk2k3r4RIptoHFFVdpsq2gu+DliMkP
         zh0KNcYYaXckIPe1BGmW8nHgZQOByqHjiH7Fw2qcnhpy8AOwKAO1PHLEjrWxWgK3+IwE
         7Thg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744230126; x=1744834926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gj222e/A5kYkAVUTXggQMhCK1RDM4dVGXNESKi/fkrk=;
        b=Tj/jd2a3Ea99KaFBtDEsRZ2kR187KteoUngSBOUYsQ9ijAEO1Gt5i3h2VNagVZAzRd
         SyBsd1xbk5K7T2SJ8YqE4MTrZFDRIXsYUB5W6ta9mhlXaCjbiRVMK7xQq9hC/LI1L0EA
         83K5G3cUl7q04hVIZQBRye32GHZBmfgoXSCfjjq2XTDqCYvA9jwEFS3MOzyXBHJUPtKn
         v81gmrbA3pETeXHjQ4QwvAP0PuPuWyMRF4ahznnaKDTjKXbrNuY22NzPHwygbf3gXZ76
         KA6e1QQDG4B31Q3gUdOmKOnJlE2vzCKnPUJCS76YDGIKkEKJOgSf7mwPNscZauMKdG/6
         BHvw==
X-Forwarded-Encrypted: i=2; AJvYcCUe0+jviyKzal9mQyOZt8a2ARHf1XgsV45g66IVZsb7YEqv5cmfzK6Hhf6u4pQosb+RAZUwSg==@lfdr.de
X-Gm-Message-State: AOJu0YwL9qmEGXsQxJU2+KhngzXG4MqFNzjlIAvY8OIxBLUWEgCAS6HH
	he9zJxs5DjaUSEE3Jb4EDEDt8iUvqLeTPP/zGDsEFbsCbmEeif+/
X-Google-Smtp-Source: AGHT+IGeVdhcV4Wbbr41+P+T0PM1G06mfZKa16CPJYFMnD7SIDJPgdWAd/6azqXOXXhs9tyj6EtSSw==
X-Received: by 2002:a17:90b:5147:b0:2ee:aed2:c15c with SMTP id 98e67ed59e1d1-3072ba0e83amr377786a91.28.1744230126018;
        Wed, 09 Apr 2025 13:22:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIA0wLrL1D3Kz84kHvdzJk0eL0qR2zMqkuV5MrHEnFRJQ==
Received: by 2002:a17:90a:e652:b0:301:1dae:af6 with SMTP id
 98e67ed59e1d1-306ec14aff7ls154364a91.2.-pod-prod-02-us; Wed, 09 Apr 2025
 13:22:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1lvQ5fxrSRzCDyj7IiDc2mIGobnHBQk67lcW1h1YD8/2TVZG1DxGH7SDtdTEGqKlEcQ7LOOqC2Sg=@googlegroups.com
X-Received: by 2002:a17:90b:5445:b0:2fe:99cf:f566 with SMTP id 98e67ed59e1d1-30718b6ef8bmr455017a91.13.1744230124794;
        Wed, 09 Apr 2025 13:22:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744230124; cv=none;
        d=google.com; s=arc-20240605;
        b=V0f7sV5HXHEijnw40aNRORY2J0cVf9uIeA7AMjewi+YC9UDbMQLtEvr/+mdjymDQws
         rvFPV+A5o8GksQd0qbyXMH6bTJaFyQ1n5xid+6Gft2v1+qrxtFn2W0wEkJNfE8uu2Dzc
         uhNBLywIUdH9DJVGTMD1+kv6MSPe5zkeBwMy2w4X4atrEWl/LAhcT1zlGBvv393e2BoS
         XbxzHc8/s0ZjIKwe1OZ+EFUYpeCQmxRxor5135uT3tpqKBnfA/GXo5tfkJudE5clxx30
         J38Ns0PRb6+FCb+BJoIsBktCCCdNI01HEuXl2fHfnZ0qi0wLpsismw64M9Ttvcq+Fs55
         yAYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pmYPDfwbTvY1BF2wIERIcWSlzgBMSydsWhi8u4EcY4M=;
        fh=GGSsy7+1XFV2osQAgZOdt+BHIQkY4zrIeIzu+f1I/AU=;
        b=GnKxNTqyDKIaafwAVRzcjcHAKoh0VJ7vuadAaMc//w2c5HLOSSPqeZ2H7oVvzvL1zI
         QWChtPmWluzeKtn3qR//pr61MTaYgtyEXRzYSbn/rcMkh9l44O36iqm5dD6/H6O0IpL1
         l2oVv/fJAA8xZke6/3TuviRC0mXUG2QjLNUc9HTET2ZdUBm2iAtpEx69naSy2MiHh6Ra
         5YgpFwE6ePqFS6XoCdXoIm9Z9LwFy/EWXCRqZcEJ3vi1VtT1cpmigo7LCoPkWUWcS8al
         F5f0OEIovcBMiqOzxOTEQ4qhDFZxGn93wV21Yp87wXm1w9pwfLo43Or4nH/Ew3k+EvWy
         3C6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="nFWm9V9/";
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-306dd2f383asi145091a91.0.2025.04.09.13.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Apr 2025 13:22:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CE8D661127;
	Wed,  9 Apr 2025 20:21:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4306FC4CEE2;
	Wed,  9 Apr 2025 20:22:03 +0000 (UTC)
Date: Wed, 9 Apr 2025 13:21:58 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com, Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH] gcc-plugins: Remove SANCOV plugin
Message-ID: <202504091321.2B7E95FE@keescook>
References: <20250409160251.work.914-kees@kernel.org>
 <32bb421a-1a9e-40eb-9318-d8ca1a0f407f@app.fastmail.com>
 <202504090919.6DE21CFA7A@keescook>
 <6f7e3436-8ae8-473d-be64-c962366ca5c8@app.fastmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6f7e3436-8ae8-473d-be64-c962366ca5c8@app.fastmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="nFWm9V9/";       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
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

On Wed, Apr 09, 2025 at 09:28:22PM +0200, Arnd Bergmann wrote:
> On Wed, Apr 9, 2025, at 18:19, Kees Cook wrote:
> > On Wed, Apr 09, 2025 at 06:16:58PM +0200, Arnd Bergmann wrote:
> >> On Wed, Apr 9, 2025, at 18:02, Kees Cook wrote:
> >> 
> >> >  config KCOV
> >> >  	bool "Code coverage for fuzzing"
> >> >  	depends on ARCH_HAS_KCOV
> >> > -	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
> >> > +	depends on CC_HAS_SANCOV_TRACE_PC
> >> 
> >> So this dependency would also disappear. I think either way is fine.
> >> 
> >> The rest of the patch is again identical to my version.
> >
> > Ah! How about you keep the patch as part of your gcc-8.1 clean up, then?
> > That seems more clear, etc.
> 
> Sure, I can probably keep that all in a branch of the asm-generic
> tree, or alternatively send it through the kbuild tree.
> 
> Shall I include the patch to remove the structleak plugin as well?

No, structleak needs to stay for now.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504091321.2B7E95FE%40keescook.
