Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBIO5THFQMGQEZ2R43XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B89CD1A1AF
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 17:11:15 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-47d5c7a2f5dsf70939115e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 08:11:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768320675; cv=pass;
        d=google.com; s=arc-20240605;
        b=kRXeT0MgLqbjFcO3Dcnh8BC0YjcFgcL5Halv8v8tAlX5BIuMhKC37Spc3i0iGrGOvM
         8wSktvu/tRljc/6ngY4VplAGHJqwz0F0VrUWoZ8W2eSP9wnJAupa3ABFP2GX9VV2adiz
         h9bKhmUqKMzCcpTv9NYm/X2ma3dswv75w3etmKLkK4OQ+aanqgcumXyYMBp95maywIFN
         cBocYOBKjSxTruP9IUbWGngdI+gVHbbiJ5+fKaMQSlVBBPgPaGAnlT1iTImFtrpy/1/N
         WXN/meoHMtBWwaHkYYml9pal3Jox4VS/DW2H7sr/58yWRG30bYg0A2MEIniUfHO83KnW
         z9uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2MQ8fQtysJ2bQfrMgxrCT2Qc8mRVyYr/ExbckASiKf4=;
        fh=vdHWeX797/M1osEaspMZ6GJesMSTxZQ6UkUTyIoWPCI=;
        b=aU2MOanIIKjzhOF9oDOEhz8eEPU6TYLYHjERq0NpgSKaV5gkXoH8a/ohPvR8QYO9m2
         IvM1DF6BVWtmElKT0ez0JydYQi+YSQQKKzGSP/a7Lxqm2mE36BeDHoYwsiux6bhPMFMR
         sGzuvk82NGKc+2OlnianK7fYmO4mfUDToKM/cwjVA+sOzXXDLQSa1aBeVdNwoz2myRHM
         Izz8gGCH6UGcomyZPTTs5KXR78MUKZROvaZnoMt0jniT5ltMfmTN0oIqSl41xcdLIqJs
         EUS5pcprNb4lUKZnyxi8QkInaXbKty9rfxelIRkiXAH7/5zcp6UiF9VKFSzwDwty/6GS
         RMyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=LE51GYz2;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768320675; x=1768925475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2MQ8fQtysJ2bQfrMgxrCT2Qc8mRVyYr/ExbckASiKf4=;
        b=HtceAmJHeFqHSpDbt0O4mFMlFpoe8AkZkSWAwvx7V3vPyuwL3FfgOwjaATypOtXb7S
         bUmZdA6Qx/H2tnmn3KqIWuJA/2ZRHFIpHt/bG3riYntW6OTUXmKut+cXjA05XeGlsH0M
         EH4B3yYo21cbDlaqQzEPiLYi1M5twNra2+vQ2LrtryrZTGz2veoA2nyLmTL/0rbaKDHn
         /NZLLw3j5ZgYQ3V/u7fNfwLny8YguFDl5chNJkcG4Li9UJux7dh/P0v62xJn4IBHTtg2
         RQ8Klt6ICJlIjb/W1PMSrwXDcR7QQQ5vVXPXWVqZ9dXNE6xnaPVoJIV5er8HstMXEv1t
         diLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768320675; x=1768925475;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2MQ8fQtysJ2bQfrMgxrCT2Qc8mRVyYr/ExbckASiKf4=;
        b=EAd1bdjlEGwXfdwbFVo/hZO6S7sz5C36TY4/LfHMkFyyC8KocscCiWpPmCKe7AA+p/
         eTpnC/bvd5bK8df/KH/hNXCvx+Jrhqc/UfV8LWEp/6M2kOCLVLUyPsFUxsVjEIq6b62J
         UD6xOilZsatUafcq5zZEIsxOF+4csr2i3zUvZOkgLJDl9XY0NMwwBl5BdA35nI81vZwa
         Xw+j0KcJH1KS4zHN0uA1/UjJ1ooqGcIWp845Qfi06/BQ2fYK+QIDFcauYByaK3eRd8uS
         0tlMJQlIIQQ9jEPDYJMEmomvwg1Bmk563SDi+qBpRStuL6n3nDUMi+kqvCFTlmp4m9g/
         Dscg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWP2R2C2sml2sP22SoWPogurmhAFpLiotUDl6GgLNgy13Zh48lrpB3iqdX7Pp0h/pxGjLlh1g==@lfdr.de
X-Gm-Message-State: AOJu0YyGqntyEm9FHuz1Z6l1En+Uz2l+WaKkdvTtjszJgGsSFOlFOKlY
	HJU2YJTLoI0BnR9CQNyop4GMWyKDwhR+C25RLnGTju5ukIVVxIw24+Nk
X-Google-Smtp-Source: AGHT+IFWtBqFISMDyLXUvfO2sEtwjUn449cC5/tzXEBDOm3AulvrPY/G7Jn0vg9Vf1KF1X1DtoGXlg==
X-Received: by 2002:a05:600c:4694:b0:46e:3d41:6001 with SMTP id 5b1f17b1804b1-47d84b3db20mr212026605e9.34.1768320674333;
        Tue, 13 Jan 2026 08:11:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FX2tndvOp4bZ1mtcqm4A5eDvxbQ8T5UbT6891HQif++Q=="
Received: by 2002:a05:6000:22c7:b0:432:84f4:e9dc with SMTP id
 ffacd0b85a97d-432bc921e0dls4613280f8f.1.-pod-prod-09-eu; Tue, 13 Jan 2026
 08:11:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU4R5MvpCLzyHDPPNpXHuC+7qVCXwX6CssteL4bImOVxUgL1fbuepSJl9l6hoCBy3fL/24I4w+BqSo=@googlegroups.com
X-Received: by 2002:a05:6000:40c9:b0:431:48f:f79e with SMTP id ffacd0b85a97d-432c3775b58mr27473702f8f.25.1768320672019;
        Tue, 13 Jan 2026 08:11:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768320672; cv=none;
        d=google.com; s=arc-20240605;
        b=lTNzoecJsHp2hDFlwVZ1GLcxPvHxd0R29Mp0/UyzkBL15Q6gWENcE6781TpJKsFqKD
         raws7m5MtHuprCSDWIv28d/w0P1FJaQWRGNzcUE70/pRI3Q56rs5be2wCcTCmkjQQ4iQ
         lxtlD1YPHvZGfGVx0pcvpcJ7uGpi4LIK102JN9HCtVrYT+k02kmJ1TuK04CIACxQV8JX
         /05mA2aO8h/QwChEub3mTr857WDW2UFsyZ8/4lqx+oaV5VWFoXshyo13a/kHQ31NGGbh
         9CY5YRZh6dNi9Xxx1HnsqWsPMIt+9/mTU0sYqDgcRFIjv4xxck+DFo+LzA7Ki2NZ3yhl
         8KkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5I3NLHg1N9Vs+cPMd8JSUsoS7ZWc7H5v0Q1JxudllUs=;
        fh=uNrXn1fp/rD3r8l45eii5VO6lFn8NZM8tPn9l5l6iCA=;
        b=EfWAB+XXW7Zc4qCneRUfjarKYps1Dlr24Me1iXYKDuQk0fW+lQ1bIlmjBd4OK6bsAJ
         7LvpSAZ7XOJfLS1RkDVl9XFYFZRY+NP8FSaVmVKMP8QhxE1da5z5G1daziGVaxqWBIZM
         GbIICTNo42vV+hQh/cDUHOe8e0d/71C7OCUqVBCGWfP2Iy7DycHsGjQPZCXaeK8uFOQC
         L/cq5edPtt07iHeIqKsEC6hadKQ0d22hrZtaANLmBsAFfVR5fUjCyqWo1+D3hsQrgD/B
         PAhJotwb4+Tp1je5B6RnH34i3Kr12p1OtpXJyeo1eWiBKjsmY/YqAqP8J48lk8UeCYvD
         cj8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=LE51GYz2;
       spf=pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [65.109.113.108])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432cad77c3dsi308981f8f.1.2026.01.13.08.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 08:11:12 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 65.109.113.108 as permitted sender) client-ip=65.109.113.108;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id EA9DE40E0252;
	Tue, 13 Jan 2026 16:11:10 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id AbHLtSQcmX6m; Tue, 13 Jan 2026 16:11:07 +0000 (UTC)
Received: from zn.tnic (pd953023b.dip0.t-ipconnect.de [217.83.2.59])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with UTF8SMTPSA id 592E140E0028;
	Tue, 13 Jan 2026 16:10:48 +0000 (UTC)
Date: Tue, 13 Jan 2026 17:10:47 +0100
From: Borislav Petkov <bp@alien8.de>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andy Lutomirski <luto@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v8 14/14] x86/kasan: Make software tag-based kasan
 available
Message-ID: <20260113161047.GNaWZuh21aoxqtTNXS@fat_crate.local>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <5b46822936bf9bf7e5cf5d1b57f936345c45a140.1768233085.git.m.wieczorretman@pm.me>
 <20260113114539.GIaWYwY9q4QuC-J66e@fat_crate.local>
 <aWZlpjwMXgdtZGMQ@wieczorr-mobl1.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aWZlpjwMXgdtZGMQ@wieczorr-mobl1.localdomain>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=LE51GYz2;       spf=pass
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

On Tue, Jan 13, 2026 at 04:00:47PM +0000, Maciej Wieczor-Retman wrote:
> The two added lines are two alternative ranges based on which mode is chosen
> during compile time. Is there some neater way to note this down here?

Explain it with words. Perhaps put a footnote or so. Say that those are
alternative ranges so that it is perfectly clear to readers.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113161047.GNaWZuh21aoxqtTNXS%40fat_crate.local.
