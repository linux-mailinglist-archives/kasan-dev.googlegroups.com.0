Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBCUJROYAMGQEWGY4IWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A679388C292
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 13:50:20 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-515af96a73bsf1277574e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 05:50:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711457420; cv=pass;
        d=google.com; s=arc-20160816;
        b=mxmfVqHUySts6wFKFFmpjqmk/z4LEDNJUV7AW55etvknzZTemBsLDycpgVoB2KqCH1
         kHpxgiyczwzGQfMoVCQAWg4/jGM7hwItLBJdzsN+U/lm9cy3/DAI6OrpuZ0hIdiYlA6t
         CylNEmCBweUhr1FxjC3AjfdVwybz7kC6CacNd1fr6Nd8Gtu77YX9TtqTB5xAirxGxHGF
         oQ6dL+ScwBFf6/cyZxl7cEPy8IuODe4tlBnV6yhIcPx0+KwqVNSYSBcN867BqRHpUBW5
         bpko5iC+lJyrzQZwbxlXXQxDDBKB8ITQcqVXe7IjM31T13bRkf6Wdql/dCNJJwSQxIDP
         uQDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4ih7e0EotX/2NflTb8mKp1mkmZnzbVFejdWtmi6nJTA=;
        fh=mwp/QSQTolkoPkOR5IXVxGqAmv8+rFKM1Y+1nktPMik=;
        b=A8/kE5Knc39eD4jCVIQe4DH38NjHt5QbkSVX3JrwoMpSYMxU4greEJsQDddyNQwNaA
         FnSjjAEMaRYUGohjFg0KO9MrhmZA5KOMq8PpVvgBBrXbMhDhCDbZUOfv0KeRL1O+cRz+
         dD7DpTDW1R5x6lRsqj7/ClCgiRAHtlopW+a17NentgesuDcvbcdh9d9G5IF6kYh/AMCl
         tCtzDsCcHjiBeWrCAK/krasdIl5jGDDuIo+8su1OIkkAoaxbZI8M+vU2Ry8FCj7ZPhks
         VhgVSJ8uJsfvSDnLz1Rk52JSTgVLZNDujn4eO0Lxb2KzlG+gB+1Mx3KvYverPQdVnL7R
         58DA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=Qr888QUD;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711457420; x=1712062220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4ih7e0EotX/2NflTb8mKp1mkmZnzbVFejdWtmi6nJTA=;
        b=QFgwikf1oXpypyFOpqUL/otzw7YLms1p3AGjBOt6phZ7o95Q+ImM4YrMQWUeu+s6ka
         F6r1zzrMkeEhPTC4YqzU0Ke9VGKKH0Jg4nRx+JBuf0/EU2RJ3q1GFWiwUD56Nc5W6Ncg
         tdan+qbbFrGIOoFm0r864R5W2UBpdGqREuZdmZmFvnmNp1FyEwYk2aFe7m0dnNcNvMaj
         MDJrra154ENYfjTXxd87oeTOaFyo/EIgAsyQ5wXC+clxfhThpM3y9iwg3GD5iURfxld4
         iX8FEgEUAYDUyMXMo3KwZfSerpL2TvBe8bG7QuwRxIPnOeCU02vEGtF/LXr+P+zgIEiQ
         BIsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711457420; x=1712062220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4ih7e0EotX/2NflTb8mKp1mkmZnzbVFejdWtmi6nJTA=;
        b=BVcrdDFELE7kqIyazNf1BFv894E0PMMArsdJnWNj9yXHBPMEcPwHESrXAx2CJWSdWZ
         xOJUJYhrrbnwJSzPCSzx33K0XbpiaJOWYeSfd1AQp1Tw+YVDDrffpGndWgAFNEEn2M+k
         jc1vRrQIQHcgGaZlZ51es0zGRRHarGtdSigjHAtZ4TmbjcziTY6iWtOe3D+IhYX+cY73
         3OezZ6L3Qg7BcdSdE12MqoWK21IvoPcXPeYp0YjpUHL+fEZ6LwqR+oDbyhzLzBoI71ex
         maJrlaL/6EBNX9SEY+6Z/iDp2onYcAc3a5jTHhcXOgLMISalLUH2UYDnQgyxw/5pzFv/
         b1Ww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURTpQBwgcz5eNyCfVuXyljK0viLKnh6OMqfcCyyNuVhwhUQgr1cAmhAk3bBiD1I0ljXSfbzMgqd4jqX0TeUFMZ6fTCFOj7QA==
X-Gm-Message-State: AOJu0Yz7r+5SxRt6sZpncKsy2tjfkz7UheTCc1SOfMYsI4E5TzgU08YA
	mxCtVhwmVDVqZ849r2LlsWsbhLur2f7emdFFrKXllnC52hDeokoZ
X-Google-Smtp-Source: AGHT+IHOkwiIfAOcyUDDOB88fwQTstAf881FaBBUD/PwCq6IrMFIqjZ0LxwGWwJ6DGZfv0jcVKpwkQ==
X-Received: by 2002:a05:6512:47c:b0:513:edf4:6f20 with SMTP id x28-20020a056512047c00b00513edf46f20mr6343942lfd.54.1711457418884;
        Tue, 26 Mar 2024 05:50:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4c81:0:b0:513:c2e6:28da with SMTP id d1-20020ac24c81000000b00513c2e628dals205688lfl.0.-pod-prod-06-eu;
 Tue, 26 Mar 2024 05:50:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5721G5u8pkjQlRaP+9r571XaJVz0Q6W7NhOtieSGkn4QtIP6t20uLC3kkJXIqMaYWPLK0vD1Zm6iPQMKhU1kdgHnNfqUh5IimCw==
X-Received: by 2002:a05:6512:10d3:b0:515:b5f3:e1dc with SMTP id k19-20020a05651210d300b00515b5f3e1dcmr1808969lfg.36.1711457416564;
        Tue, 26 Mar 2024 05:50:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711457416; cv=none;
        d=google.com; s=arc-20160816;
        b=aUmdY7lFN9iHp1WAkoLUZocjGD0XdViWuLQl4xuhQVmXD0wIWNrZFN7KU33lTdEdHw
         1kCrDGYjvdtPi8AHDNu0YMyWJ95Td4DhOE1dqWoXzDk+a/HlspCpF+HNAf5PaQR+ATd/
         x26/rugG59mXE5X8X6UzNHKzCyMILqmrSfeHrUf3aRXIa1zlcMlFV4/7vQvjofPySBzb
         tXn37ilJ3621XSM/ah72vu6GbDYeem//xqUaY2sqFWe3qKS0IWS/vyi4Z2Zi+L6lbaOU
         515H9OcIudDwes1KjygDp8qRTuYrY7fMqHuas9LvvdW6EXn0C9WnrOh+7CrpKStNT9hZ
         wcBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=06BKn4JRYDCymbCW3aUPHk5b/bEgAy9YHyinGcr1ris=;
        fh=vi1pxMxIwV62mpYIkNphiTEqTgghikcvRxyFIr05sMk=;
        b=SrpeL1N4ll+DZuxPndXrCeI7B9pgp4k3Dzapv+nwjcgI3PogtWu3vsZu9kf1jfRkSV
         3+4O+YKRcUJjnrkd/LIqaHmdbshHcKsy7lDYVw8YFYXpC86xhcZcP3tYBEf+s1SLcp1H
         5p1GNAqqJHye9Tnrdro6VLaOyxnWc1+pvrTSvT5y7+KtKgQGTze6phXOQlVyLyT01Tal
         iZq2x4kvNPlQzTnZRrffrEMARQW5JJaT6srrv73DUSxEbxIatY8AXN5rkam7XPfVNkq/
         Q63QHNqCAJZI0FuRJRlyUp0GD+WiaY+8iu1ITmuUqus84eutD5+D5RcEVVP6VbXltysS
         4O3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=Qr888QUD;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id e4-20020a05600c4e4400b004132f97fa43si118532wmq.0.2024.03.26.05.50.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Mar 2024 05:50:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id B7CAD40E016C;
	Tue, 26 Mar 2024 12:50:15 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id v-owZCfkRxVJ; Tue, 26 Mar 2024 12:50:12 +0000 (UTC)
Received: from zn.tnic (p5de8ecf7.dip0.t-ipconnect.de [93.232.236.247])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 77FE240E00B2;
	Tue, 26 Mar 2024 12:50:02 +0000 (UTC)
Date: Tue, 26 Mar 2024 13:49:56 +0100
From: Borislav Petkov <bp@alien8.de>
To: Paul Menzel <pmenzel@molgen.mpg.de>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: Unpatched return thunk in use. This should not happen!
Message-ID: <20240326124956.GFZgLEdFNDZSnQSuWx@fat_crate.local>
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=Qr888QUD;       spf=pass
 (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Tue, Mar 26, 2024 at 01:40:57PM +0100, Paul Menzel wrote:
> On a Dell XPS 13 9360/0596KF, BIOS 2.21.0 06/02/2022, Linux 6.9-rc1+ built
> with
> 
>      CONFIG_KCSAN=y

Are you saying that with KCSAN=n, it doesn't happen?

From the splat lt looks like it complains when loading that cryptd
module. But that thing looks like a normal module to me so it should
be fine actually.

Hmm.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240326124956.GFZgLEdFNDZSnQSuWx%40fat_crate.local.
