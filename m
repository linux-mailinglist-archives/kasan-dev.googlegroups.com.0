Return-Path: <kasan-dev+bncBAABBKN3ZHFQMGQEYH4NBHQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id sF9UHqtdcmnbjAAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBKN3ZHFQMGQEYH4NBHQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 18:26:03 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id DFB9B6B399
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 18:26:02 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-4358fe2e7e1sf885463f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:26:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769102762; cv=pass;
        d=google.com; s=arc-20240605;
        b=NjtM+jp30+4JUxcy28t4O7pN6Kst/LY/t+htb8pWte1+URe4uFxaxZv64fWW4zZ1YQ
         8aSABeGTqC/O7Xkepiac0rS1VeqEmuXpO1Kk+hgPpJkSk3sWyv+qwdG8nR9oi+1OoOJb
         a9Nlh5dNIovjlHBqehMsTixOakbEPh1Hr4hsoDt2AENA7v79Ed/Bw3R3IqqXD8IE3FaL
         N5OWvIqX8LGn2RHAyLoQX/xt+ygaWTGqPKvMRcFEwJit/Ox4HVhFfhpSN1F9YKcGiB2j
         wluIliI1XCFB50vWKeBM1wVwO1LPvs+TUSf/hTfc9KkKIF0ahzL9sQ05TrE3JFIh94Um
         yZGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=c9eVyEaU9fDvDeQNXN10CVJWqbcjObipoZz7dLMsnMI=;
        fh=kV8Kai/9mjnPhBqmLDQQbaekKsefi3q9r6kNbHOpUHg=;
        b=fmhxMIq9SthHrSZK/om8Gm7S7kpAaZjrRinyFpZ35Hmco9Yb/TSsovdMJDM9S5ZU8+
         ivxGERt5W9DNZzEvaCgAEx4TRYz5dpVEvB0KKzLhGucNQ+RIMKx3NFjSvukUkcRfLLot
         bd7MIbRXcVBCh5d8hdP3uS/ta+SH+RZ1dr6/EG49jtnnXm20s/PG8cBPEE+3/JAoThAw
         1b5lv+p5vYMjiOJoXOuO1VJAeWUiADKKlzo67JUmqzTR2m07e+Rp7FpNB52QZq1ai4kz
         8kPK3r2hReIfi0yE3sJXd5Byku0HwrMOiVjYhdmeVWEDtUaK35lQT4Qm/RfEiq5hFQWj
         uMnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=c07CYpp9;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769102762; x=1769707562; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=c9eVyEaU9fDvDeQNXN10CVJWqbcjObipoZz7dLMsnMI=;
        b=xMJlKgbRLRmS/zRJikrFOAx6CYMEYzm3eQIkKhEWVhj2LpoATCfT7RnjpAB4NqyzbZ
         EH8oQLVaiIvAcP10sthfBGjwMk/4PooQA59vcN4VfaP4a/pogolhF2iWUWb6DYJK5Iuo
         NYNhX6FY/6cte4JPWdOmKnYP025xprgDfgkDgue2mcFqKApfNzV3NAXhDlHweqkwMoaf
         fTPtgPp/My9AkQEaMU4EfFfWsXm7dacVJuKLipNBsZui2FZrdDEqc6+TBlI/he3UzhSR
         rDzub89uNJ7Dh3VKilCiZvkkqovDQSq2/mp6IifkgPa9K+Pc8Rse04y/ZwKgrVXp3tlF
         r5Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769102762; x=1769707562;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=c9eVyEaU9fDvDeQNXN10CVJWqbcjObipoZz7dLMsnMI=;
        b=gLmyii+AtsQmE9X9zJmXTRqoc8GRl7cxO4xLuLb67rgChJrg2CSHQ+Ry6wkVzw40X9
         6cZZ4GESbdi+LQQi6W5/8G/MHi2sVYFn3G4AT4MMmpPcxi4gThGMBLcd8Dvue0Xe+Mzd
         shbFbv2jKkgarqHDewlxEQWADmLQOlhIOLdf6eTXeBT+qnkDTz3pnjvn14nBGyXVuTCJ
         Y6Uij7sdM/C/6CNp7VLnAciVn86WHFTtF3iAgSgwCVvadDP6ZQ0Augy+/WLf77ZX2uLA
         2TBi+xghk+mkXMwdp4cmaA1HRkC1fAaYvmmsKiMOj/hhlyI9cE6YL+uPguAQbm/rZwdY
         opWQ==
X-Forwarded-Encrypted: i=2; AJvYcCXlVz6R0MMpwLkh+omZjyBFjTwATvbCsEnDds0CxYxHxN+Ea3IkmvPj2bAcM/6RW7P6T+HLVQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxl9Wp7pANRI18e8TINP3w41YZxeQx9rH2DCc9+lMY8dZeXbIGV
	a3tAtcWCUGm2HPRgtt6/JGwu6D1vW6dFErEfLxLGN2kHsLQTEhKZuHTi
X-Received: by 2002:a05:6000:2211:b0:435:ae10:cf92 with SMTP id ffacd0b85a97d-435b158965fmr440947f8f.8.1769102762014;
        Thu, 22 Jan 2026 09:26:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HvbtTyimcaTMGY84Vu2uJXfzV//RQPJ6yeNLhooigpag=="
Received: by 2002:a5d:5f54:0:b0:435:96ad:525 with SMTP id ffacd0b85a97d-435a6400b4els773897f8f.0.-pod-prod-09-eu;
 Thu, 22 Jan 2026 09:26:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWsvzogCrDhR5uy2QkgEZ0Eg9umhG6Y2kIbQBa10vGuk104oPlgh1oxZSyDIMKHGXA+QsHMy7GkRh4=@googlegroups.com
X-Received: by 2002:a05:6000:184a:b0:430:f742:fbb8 with SMTP id ffacd0b85a97d-435b15954b1mr484531f8f.21.1769102760308;
        Thu, 22 Jan 2026 09:26:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769102760; cv=none;
        d=google.com; s=arc-20240605;
        b=eBAOADsA/fEqkotA+BgQdj5yX2RxKLeTyXlt6BuPoiDe5WaS2ZD69L3wVfynsaCy2i
         bfOwuYvNY+IIlUfRfljlpNZcAZcI+ZGnvG5bpW9Uk3UPPndM8sdRQ1vKnER8z+cfI/0Y
         RkmHFq+QtISpwAZViJrzaSQEnj+eBfW6xXxYxW/RJJilk3If2OVXKvROIdmBbmcP5+5h
         B2gLSBbRrvJldoWW+ymBIyvOdHhuACU5jG290XtE/bZNuF1gO4i5P3Dej/J0dKNv7vnZ
         ZXJWh3jwIRnxkiqIUF+edlhNLAPOtMyJSeTZYZpQffDVKWKeJSMWFcYCJ6C6ZoWY+0gG
         tMOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=nyjwh9Rs5YqQ4WtOoe0Vcb06dokpFc8gAXu8v/qQW98=;
        fh=c8BEqmqpvakpD36jSETMj05wfv9pYd5DeazKNlAzweM=;
        b=Fswm6P5h5h2TeBp7b1LbeE+7z1P4Umq2iCTld1KM2s6LygT80v+HpeqRijTHuWW6ce
         mrQAexcnW9x6GksN29U7r2dskUSRMR+Yi9hAQ6AQuiZhaoxczvQYyUFntQwPLEZltKIl
         NpcSFgN48vG6RfW/fXQ7esPdGEYrBtwwW4dY7Z10gnxVsrIKenmFdhECtZh5pS9pWd/t
         AoSXM1H1RgY92l8zwqNXnQEPCQxaN2ZP2KkM6hfj82Oi8pLKU9bMqkA9KARmkJwf9Wm1
         2etGuuXwxugpVVcWb1nmtb+VT18eVE5KyERQ70YAimapmC7S32ZiqrkK0uw/eftBFM4e
         xBhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=c07CYpp9;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435b1c69cafsi1128f8f.6.2026.01.22.09.26.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 09:26:00 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Thu, 22 Jan 2026 17:25:48 +0000
To: Andrew Morton <akpm@linux-foundation.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Borislav Petkov <bp@alien8.de>, corbet@lwn.net, morbo@google.com, rppt@kernel.org, lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com, vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org, catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org, jackmanb@google.com, samuel.holland@sifive.com, glider@google.com, osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org, Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com, thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com, axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com, bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com, urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com, andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org, vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com, samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com, surenb@google.com, anshuman.khandual@arm.com,
	smostafa@google.com, yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com, kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org, ardb@kernel.org, justinstitt@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <aXJcoHSRLY7tzIpU@wieczorr-mobl1.localdomain>
In-Reply-To: <20260113093400.412cb4c5596ff3336ac803fb@linux-foundation.org>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org> <20260113114705.GJaWYwubl3yCqa1POx@fat_crate.local> <20260113093400.412cb4c5596ff3336ac803fb@linux-foundation.org>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 460f3c13defaa3d7589248b966d5fcef4b3ce730
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=c07CYpp9;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBAABBKN3ZHFQMGQEYH4NBHQ];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_CC(0.00)[alien8.de,lwn.net,google.com,kernel.org,oracle.com,gmail.com,redhat.com,arm.com,intel.com,sifive.com,fb.com,siemens.com,amd.com,debian.org,linutronix.de,infradead.org,zytor.com,suse.com,suse.cz,linux.intel.com,vger.kernel.org,kvack.org,googlegroups.com,lists.linux.dev,lists.infradead.org];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	NEURAL_HAM(-0.00)[-0.987];
	RCPT_COUNT_GT_50(0.00)[65];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-wr1-x439.google.com:helo,mail-wr1-x439.google.com:rdns]
X-Rspamd-Queue-Id: DFB9B6B399
X-Rspamd-Action: no action

On 2026-01-13 at 09:34:00 -0800, Andrew Morton wrote:
>On Tue, 13 Jan 2026 12:47:05 +0100 Borislav Petkov <bp@alien8.de> wrote:
>
>> On Mon, Jan 12, 2026 at 10:29:57AM -0800, Andrew Morton wrote:
>> > The review process seems to be proceeding OK so I'll add this to
>> > mm.git's mm-new branch, which is not included in linux-next.  I'll aim
>> > to hold it there for a week while people check the patches over and
>> > send out their acks (please).  Then I hope I can move it into mm.git's
>> > mm-unstable branch where it will receive linux-next exposure.
>>=20
>> Yah, you can drop this one and take the next revision after all comments=
 have
>> been addressed.
>
>Cool, I removed the series.

I sent v9 with (I hope) all comments addressed:
https://lore.kernel.org/all/cover.1768845098.git.m.wieczorretman@pm.me/

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
XJcoHSRLY7tzIpU%40wieczorr-mobl1.localdomain.
