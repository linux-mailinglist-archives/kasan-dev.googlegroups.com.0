Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBJPF23XAKGQEOQJIRDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 04AF51045E5
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 22:39:50 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id c11sf641126edv.23
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 13:39:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574285989; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvGPZLEnzFEa7kUSMGjWfC8bCpIT3ISPLOwozkA60Z7xvDDYTqtTm+kqfjTjwkx05h
         XDdIANcXGIPSiw6NodQz2TpjXOHzvwPFxcdbsrzzSew8rr/I6FwSLzEly584pYAqdG3E
         1w1i5BM8GY8esA+kpDJYcWKYdHT17wljYJk+AIlpLOGZUjjoL1DIzPlvxae24pRxnZfu
         ODYEqVH424We8HQ2JHomp9ez0hpc/bXUsj7vrw9qk/HDD8SuSxBQfVTwj5wcJYlE23b5
         +i69mDVZ4UX6ovnE+gUeUYHnlHHcbWjjhmRnu15y5ZVmBehZltzpnLkygu+/dR1DE0FI
         Pziw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=rkhxNT7gRc1IucMzmx5R1+YbwocGK6d4rKFEm9vraNM=;
        b=o/dJve/T6+PKyPBkw4vID6LnuMn7DxikDHMPk/asKXT6Rwtj2h3TpO3Im3lTiE56yO
         jGMpflrPf82mGVOmQ0crs2qNkG6xwpX0R0E9PAnNvYxXXY7zqrr0y/yvimhOusC61rEV
         LtcrzhWKoRvVjwcCQuFOFWqXI3CR6VXGAxneli+YJoKhBZuVmHDodOovaEPHBUFh2jqS
         S7jzWiafpCiMfpk+/LGoHnsHQG1PpZi8jnuehR3ET2dBzIraEnEzMOdLlAU6KfPOwgM7
         gNDm8kAqssnALRrwXtqP+PKSWBM/ignK8iQNek9NHttODDInXafLU7tIdEUNIlNO+OM4
         A/pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=eQZ1qfsY;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rkhxNT7gRc1IucMzmx5R1+YbwocGK6d4rKFEm9vraNM=;
        b=axpgTzYtfGE6Yr1hA2grsBuD1l8hqIDIkDhyN7br3H1wMabUurTNIH7rjicgZB6/e0
         1jjAEGnlBYx+4SUAlqr/aAetQolScGb2xA03m1f+xa1mD51dv0NyczPnB8MNtkH6sOtM
         9fBSBd5eriUF2IrqjDKXK+KbrHQ+Nwo+bjc5BQgHrAYvplwGSEdiwBASW8VFxyX0f7uW
         FLMT7TQXiG+ghYGTmzIg4Pgx/hPVxLyP5nxWD/aj/Zu+BsYvjPg4aJGZ6h3XLF/hvPUa
         ecVVZGqlHyvxEcc3rCRCOCVAjqEZorgF7YwifjSCVPbhxQK3w2TV9HusbhayTgH8yTNR
         a+4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rkhxNT7gRc1IucMzmx5R1+YbwocGK6d4rKFEm9vraNM=;
        b=YeFZpL35pj8xz3NFHKUHanIdTOAm9kGDUHGPtOuxzllCTlqjOwYiiYKdKM7UM5cHlX
         +DrmkqEX1HmOOFnrlhrFoHkwXrSFB7odva8Dr6FoVAbcBV3LLrRXVpQQkEJU/E5Bg2lp
         IwMajF+cF8JUk7NUBRCNQJtr2w9bhPTQ1JOwcXs86R1XM5wrqFDNoC/B0X6D3SrgWqEx
         6Y8QaoJ97Gq42OCu1QkFskt0QnkPIuiiJNYDgCet1t2ETcOi9CXXPr+yLX08PqxNA4Co
         HUquNqKdsQX897s9WIUUzbMhfgZchxNO/Qx/F+zToxaScPG/mtNpxGZ4AquuIe7GgfSw
         Cm9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWP2tIiP1YIHQxqhZ2M12W0X465qjbvjHsVGcpLMg/UxBWvbJdI
	Sod400nVbsNPZR95FRcB7mk=
X-Google-Smtp-Source: APXvYqxr7rfu74bgxxvz+9pkWnAXcDI5cHpjitl47VoiaAm0xkTViov2sePdmN4lY4BvxBVWUwYBkQ==
X-Received: by 2002:a17:906:5959:: with SMTP id g25mr7984578ejr.248.1574285989734;
        Wed, 20 Nov 2019 13:39:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2493:: with SMTP id e19ls1864547ejb.4.gmail; Wed, 20
 Nov 2019 13:39:49 -0800 (PST)
X-Received: by 2002:a17:906:2e52:: with SMTP id r18mr8332419eji.178.1574285989290;
        Wed, 20 Nov 2019 13:39:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574285989; cv=none;
        d=google.com; s=arc-20160816;
        b=rV4RyhRIUKITb7sKYUEw95uPMA1dCrU6zQUS/osWLZ6SBIi2PiOVCTCZlG+uTQNQWl
         3hX2ngo+b2vJoCmnctJ1v0hmYFNuxG1JYXpclVIJXSlvnbrH9wbZQlGBWUYJCRyZVz93
         ekWoWL5LtgOLydx4wA0x9O7wu3pfimYcoiwd4MZpnp5ica8+vOWEqs6nGut5DJ91KTca
         ZnrPkCUwnbmsDVml/UcTORxiR78j/n6iweIEXFbGutu4do9wwlpayhA4LMir9xMPv/sb
         GYmVmUwlbnTe5AyHhLo+4PU2m39o5RqhudHCRjMEx0V3DSsZNmXL8MYQ/Y/s1uYCE7EU
         v5WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=unydtxWRxd2NXuJKHq//1qdDSsPdWBzWdKiJb7+o+yo=;
        b=M/4rY6rRRtdfEl5l7Dkhrao4C5s63Il4arY5vCP2zV0ZQV5yreOfj1M0884667YuJd
         Ffd3WmgcqB7B7/v/xfJSaWs0E/CCAgzG2D9BuVwZbPEb5DSd7d0378qHK6+JAd9lAwsx
         Aa95GpFLFAefKbyjUo1cuDiL4YrJOdJPDttMlHugXEcnwIGcB7i4I2XSzDk2RKEJy6cM
         40xlp5IwBjkAfN/Oi3XcIBvqgZ4Bs2q1XYWi1fw2BoOaooN3bU0WiIxT8hDnHEafI3tZ
         qLiIshp/EPXi9NnkGqX8yMtOc6eeCO3wAJ2lc/Oe8AA9oxREdWzfvTriBUYFZg4IhADH
         KQMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=eQZ1qfsY;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id l26si25951ejr.0.2019.11.20.13.39.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 13:39:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F0D8C00A5DC709D5356F6BE.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:8c00:a5dc:709d:5356:f6be])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 869311EC0CDA;
	Wed, 20 Nov 2019 22:39:48 +0100 (CET)
Date: Wed, 20 Nov 2019 22:39:36 +0100
From: Borislav Petkov <bp@alien8.de>
To: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>
Subject: Re: [PATCH v4 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120213936.GM2634@zn.tnic>
References: <20191120170208.211997-1-jannh@google.com>
 <20191120170208.211997-2-jannh@google.com>
 <20191120202516.GD32572@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120202516.GD32572@linux.intel.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=eQZ1qfsY;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
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

On Wed, Nov 20, 2019 at 12:25:16PM -0800, Sean Christopherson wrote:
> I get that adding a print just for the straddle case is probably overkill,

Yes, frankly I am not too crazy about adding all that code just for the
straddle case.

Also, the straddle case is kinda clear - it is always the

  0x7ffffffffXX.. + size - 1

address and we could simply dump that address instead of dumping a
range. So we can simplify this to:

	("general protection fault, non-canonical address 0x%lx: 0000 [#1] SMP\n", addr + size - 1)

It all depends on how the access is done by the hardware but we can't
always be absolutely sure which of the non-canonical bytes was accessed
first. Depends also on the access width and yadda yadda... But I don't
think we can know for sure always without the hw telling us, thus the
"possibly" formulation.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120213936.GM2634%40zn.tnic.
