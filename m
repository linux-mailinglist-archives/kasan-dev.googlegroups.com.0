Return-Path: <kasan-dev+bncBDCPL7WX3MKBBQMSQDAAMGQEVJEINUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 23BA6A90C8B
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 21:47:15 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2c238fbc14fsf7530982fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 12:47:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744832834; cv=pass;
        d=google.com; s=arc-20240605;
        b=HrHLqI0LO5srIVLZl3BYV+71ZSCT2UkBn/Sh+90ucCTPatvoYisaqK5SlTdUZyYxja
         p36svN822Xtv7MgdAwTckFCCLfMI5201x5Iq8MPkiX3pX/TPRV6oYMzNE17YNOkgUIRu
         m8A4HCs7MGuxzbnEM/yMKy8UefR6EP7mB3UjSOCyVpHCxgm/8z49yal022bzfYqaZhBE
         hgYXye6TCJqYr68IG8gPxz4ogSi2a+BzbUw6OX0HGIDSRIZ6QpNCUxP96vKHK/9k82Eg
         FqgzG6WgolCX1wX1aq6Ke+5cTLETd1wGrT2+WJ0BVzUrrjmB+MJmEMlPq8pcIqXWXEkn
         DdLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SotomS4OvFH55JfYUQWZ2ahfs4V3tvhNkC7LGgWbhwQ=;
        fh=SKPyeHS9teooDHnhR/SgxEH3WKDok1iJH1IhDYzm2NQ=;
        b=a8DDSTCtYLlbTmAS7nqnE69czo0o8VaIvtOxFHucGxfCS1SppO9CB1JPpmepKTQhGh
         Pf01fwHTGT4l8SbZM7Yvn7NXhJwF7H4m0eYl2kJ9lUXF7QQNN5Qm62vWA4Jis8z6Kf1S
         CgDUmdI/x4lruEoMFOFbBr258FoVA3pjs7Aw1Ktg/UeDprJn4oKeP9pFxRXVeB6dFEuR
         DisYMXmN7mN1cntnxS8Ujvgrm9MLDBIpUIveEtPKRIzSyPvlB8MIn9OkCXq3nzWFVL1w
         OgBo3wXlMbbEjyTZGQ4dDITW5tkYfjjiJ75JIGDIm2PLswoGDSGiEymmuTA8xPdfm/1w
         QzfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oLpXnQw5;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744832834; x=1745437634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=SotomS4OvFH55JfYUQWZ2ahfs4V3tvhNkC7LGgWbhwQ=;
        b=gOhj3RoGAmP6Fvt7/zznrDZCqCIU3pKJId89yt3uo4zYfOR+AburfTcrUjyQOmQKE1
         +1llQW7/hj4a6RpRL7qa13CtDtqVz7ONb77VLvXPOP6vhNwTccQKV7Fn1YwCSHRW9+jr
         0xEUk/uNselm7G1T0fWBLt4aopqMfsP2u4RfmdWW7K24ibyXrLyEBcp33xJHqpgm5hrs
         /HyrTITBXNyWc0BjBw9y3pdBAnSpuk3KMD+Fg0jwQPgHrFyS5wOWwBRSRDH2VMHdJz/c
         hA7z2/Y3PSre/4BY1+rABHf1aezagcZHSxK1S+Xko0iAkZtiK+WjJNVgR3wTmSFa3aQe
         nFIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744832834; x=1745437634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SotomS4OvFH55JfYUQWZ2ahfs4V3tvhNkC7LGgWbhwQ=;
        b=QaAzfC0eDfmZBlADkifAKf3lhxuJyUgC0G4pEAlz0uVBd+t4blSe3uUsUFlKRl2N9g
         He78+lqIFB6pNNvBuJXiU6Se/6X7JSAMljjZnh5oI3FxwSq5z4HQ0OIGG4so2/3QTii7
         EhJEgqeS8BwvJBe2G08Lcuq4X+wqQ2ncYJ7+Xdlu0R7R/4QZUMDDVZfbh24sMJe98tW0
         P/4VhMnMy+r5FN7Dn5NscpNl1Uaig00gj9JLY5zdWksW/Vvf8ihDLXgMs/huVdBS97oZ
         cQVL3LPvIOy1NtFH1pf8+Uiq3vj/ZMyKlKWEKRW8DKTDJ8aMQMVYgR0OjJCdp2pm9HuW
         8FBg==
X-Forwarded-Encrypted: i=2; AJvYcCWJxhh+8wqFwGBGbwVhV3YMuRJOZWt4Aw4red97ZqdGULENIEgxEnVvln5/56yocCV8gJjGLw==@lfdr.de
X-Gm-Message-State: AOJu0Yweh7lyE08kdf1JuqG/xhvD4pNQ6N8OK5GfGOBMqrFlf5gt5P2+
	B4Byhabwl/qlFtndfb/k+2NNvkgpOHQDsG5GL4JYuZYtAPefd53w
X-Google-Smtp-Source: AGHT+IGTgidNUHSBvrmt16XDy6FTTMgUEpQHdV5CAR0zXTjRZRZQEn9kHzs7P0Jj2XQs5uMp7hW81Q==
X-Received: by 2002:a05:6871:6006:b0:2c2:2d0f:40a3 with SMTP id 586e51a60fabf-2d4d2d3b490mr2246507fac.31.1744832833616;
        Wed, 16 Apr 2025 12:47:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIB27lOizhpljbOkWQlN/ftOQ3+50aZWL9khVM4e5BHbg==
Received: by 2002:a05:6871:3a20:b0:29f:f56e:68fa with SMTP id
 586e51a60fabf-2d4ec0d004als133094fac.2.-pod-prod-09-us; Wed, 16 Apr 2025
 12:47:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKSS14PhbHKSTWfU57XvOCPqculvt5/jDskw9AXxKxawQ54jyClZPvygR1LJPry6/RpUOQ5NH+T70=@googlegroups.com
X-Received: by 2002:a05:6808:1706:b0:3fe:af0c:6eaf with SMTP id 5614622812f47-400b01c36b9mr2053150b6e.1.1744832832751;
        Wed, 16 Apr 2025 12:47:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744832832; cv=none;
        d=google.com; s=arc-20240605;
        b=V9dzra3dXiuxE8N2u0yVKHMRxM1Rh+hgqL5D1G4OA8dJVPCMvGFMlALG7Q7D0/JuDy
         owTLlygHb9RpWQRfWp1kZP2LO7W18MxEitEoSHkEqMCHKxnjbzlOY/ar/aECph/qGBz5
         reTfvovXO7ahkSSIeK4ySN5Jx3JNwbXBzKbnvSa+L2XL2KHnNDEUF9Bz+s9IKQWMhJyN
         Ym7Ab6XbUQTHxoSzw8HzJelCBdWRAaMzOiXxD/9nJFsgfWHFYoFkHtfetPNYXdmSE0uQ
         X6+w2Z9abx1Kq4VRFxcXvy/AptdD06JC9SBB0Bbo2Eon1/a7gikJwaFdv8JwEaoLWI3m
         GbSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=H2iUCs5cFH/1eRLoXilHgWHuOuB3Ys6PpPjSztItutY=;
        fh=vuqwRWwINia5VpWpj2ioyjJd1TDgkKVqERd2373s0NM=;
        b=DXBb/oTCMs54hXs62dn3RyhPsGtjyyg5Nl6DsWLXd56UCZTje6be3dQFB5aJ7jN8MN
         Eo3ySfNH53ke6BNtByjOB6Fx3GzavwSdNDKKO3sLL8kFqRm+pig43Nex8OXlRAdWA+X6
         si15tRkB2ztr8q8uKBAQdkCkwM9k85BOwxcFpnYScT0FLSamVM6j+lIMmp8l/cRGs6t5
         MZO33svLZqiHH9f/e2iJXjjKrS+Mbnq941RbY/peJBezLca21OUgmLG4CUfvT1pLujt2
         APuru/eDlF5TUTPSpa9zUZHgvspFX5nfC9/nVNEFSM91kKJxVO08QUyrojWTHj0n6sXv
         xLjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oLpXnQw5;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-40076265383si279574b6e.1.2025.04.16.12.47.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Apr 2025 12:47:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id AFE7D6156A;
	Wed, 16 Apr 2025 19:46:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 67B57C4CEE2;
	Wed, 16 Apr 2025 19:47:11 +0000 (UTC)
Date: Wed, 16 Apr 2025 12:47:08 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mostafa Saleh <smostafa@google.com>
Cc: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	will@kernel.org, maz@kernel.org, oliver.upton@linux.dev,
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com,
	x86@kernel.org, hpa@zytor.com, elver@google.com,
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org, yuzenghui@huawei.com,
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org,
	nathan@kernel.org, nicolas.schier@linux.dev
Subject: Re: [PATCH 2/4] ubsan: Remove regs from report_ubsan_failure()
Message-ID: <202504161246.AB73A176C@keescook>
References: <20250416180440.231949-1-smostafa@google.com>
 <20250416180440.231949-3-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250416180440.231949-3-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oLpXnQw5;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Wed, Apr 16, 2025 at 06:04:32PM +0000, Mostafa Saleh wrote:
> report_ubsan_failure() doesn't use argument regs, and soon it will
> be called from the hypervisor context were regs are not available.
> So, remove the unused argument.
> 
> Signed-off-by: Mostafa Saleh <smostafa@google.com>

Funny. I wonder why I put that argument in there? If we ever need it
again, we can just make it conditional (and let the hypervisor pass
NULL).

Acked-by: Kees Cook <kees@kernel.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504161246.AB73A176C%40keescook.
