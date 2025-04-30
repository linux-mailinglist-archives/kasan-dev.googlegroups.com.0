Return-Path: <kasan-dev+bncBDCPL7WX3MKBBPGZZHAAMGQEYMGN4PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AF26AA53B9
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 20:32:53 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e6df20900f5sf226231276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 11:32:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746037949; cv=pass;
        d=google.com; s=arc-20240605;
        b=MaGH74IzBOUuutkwkZO5ddaXSF0b4dGqlUQbL6aDXwDm3iJIN3fl40p70LxP7Gkgww
         XUpGX63AMVMutFAXLIom93NudStZRQw7+etEey4rgCV7lhzRws1L2zFmqVXaQkbul+be
         GAiKGuh5DgLekhBRUAlTeSnKYSwAN4InY3S2EUL2iiH7B4qkJmR0oUYnJDLTV6c/BRGo
         Q79Ou8m5bmcBQgXe7Ncz9FriM3nPh/QpBJe7ziQybb4oy91EXPMdNsMAcM/5e+2Gu1BE
         nle0pleYnGoagzr9malug5+rbEGD7+PxeQ56FGqVGloNglFVvzVTCdmXfsGUvgkb6RjS
         83aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=XK6GSruJCNcL0QSfkm3UtP/kMazE4c0GH8BINoi60p4=;
        fh=XN/l/1wtHftfpJKHUTZbeOTddBaJyT2rteLK/SEFl1w=;
        b=ebYx9Vu+kwz27aMQZ6iKniTkv3VwBjco0mE+00u9PIqsVRoZCea3Vx1UQAK3SCLO7q
         /mZxlI1vK3g3B+wc2HS2KU1zv4bOaZGfIbkRq/ZS1/vDd7XfoUasDtpRIU57qHUWrEC1
         LDtsbeKYJm2d0S2YMMNpAdHEvR7PLxahLgZUPMiddaQUAxN3Yzog3dnTBRdG6X+F0i9l
         47YQ9ui5LOE3BTzwponGRgTn/ens6nmdJHFij74UxyuT2xIwcuDuCdt9FgZacw/qoQYp
         ctb0vPzCr9ukSkzbYjqXcHdTO6oBKBw/CGDUqWL1HWXWbA8TE7Eb/Y0MSPdEeYITj2Kz
         p5PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="IB2X2j/T";
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746037949; x=1746642749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=XK6GSruJCNcL0QSfkm3UtP/kMazE4c0GH8BINoi60p4=;
        b=eZLu2her9j35OSjcDXnXLjM8e9AJum+tn/uwfto2xQgv0edudo86cuvlaGN94lAoLT
         59mV05MwBLHvxlcpe0vgaykGHW8eIREH7VR8VDtLcXgoo3U4T7UoliENSRAHIDyGnd3U
         MaFU1Em3zRvHHq5k274Bm6LVizJ/7NppizwEsIevxiW+1kfdbWtFR+P3FuuhZoGpGpdf
         SNXdRbGRNR5Zo1zB2wQGaDGu/9jAYRg/FlUBXtKF0VsTsRyQx8DzP59pz0dAC9WHD5lS
         SMPn6HaDF2WXYDAxDKnEBHDJrPOxKwfOKcL17PTN6k5rBbWzXu5xHo1YM5X1SW0y2ycO
         ykUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746037949; x=1746642749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XK6GSruJCNcL0QSfkm3UtP/kMazE4c0GH8BINoi60p4=;
        b=tka725kni/3V4ovj9NSns56MaFt9DtusCNF9YrXuNcHVnqeJQ3GmQ0Rck+czBUMzjy
         zn1c+J9ximDRCJskicYLwuW1pQPPd8hwT3IxAX5EUk71RQPzKjEHA0gckaUM5n2JmHzZ
         87Mtf5QKppBrGxkLxbdKgPanANUnkp88I9IcISfLo5djtvdnhDOniRIbTNGe2FWZ6F6a
         5KqQYWjSCnnrmFbqs4t5OmY/1AEAMy25PxC5ot39gA+Hey2Wn9Mx6FhkFupYv1eLCPSR
         EJy9/DmPTCjsbsyeVxsu6DpJBUJ728p1LGWuuX62vCAKIwzut8WjedirVVEVEn0h1oj1
         qK5w==
X-Forwarded-Encrypted: i=2; AJvYcCVdW6DN7I9XGHhsoSEuWJ1n6D5h1uxOD+jTtpGLW7plyuRp9rRKptVlP4S8+YpEfFXv0mwnOw==@lfdr.de
X-Gm-Message-State: AOJu0YyG0Vb7EKJJw0G4atTIyXixuTumhuWBuo8bBcJDsFi7eaJdFIyK
	atMcPLH1tti3NM/pksG64w1xqL6pFTVi3EprYkA20KGvap1jV54F
X-Google-Smtp-Source: AGHT+IGEAhOIr+RXbG4b3AYRfd0I3HZ3xofsQo5Ch18WqSsje2SXAgXNOflspuUl0q49hNqJ6yP+ZQ==
X-Received: by 2002:a05:6902:228c:b0:e58:a25c:2787 with SMTP id 3f1490d57ef6-e73ebfd39ecmr6148055276.38.1746037949142;
        Wed, 30 Apr 2025 11:32:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEX3PfotKFtODLpTDH1nsejXsghCtGXv3DAHtnTsyKWzQ==
Received: by 2002:a25:d689:0:b0:e72:87fa:2588 with SMTP id 3f1490d57ef6-e74dce8d8cbls206974276.2.-pod-prod-08-us;
 Wed, 30 Apr 2025 11:32:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsavYnrsfB6AfLk6IJ1ZEVrye8HVhgo//lvliGM7WR0kzKqqPUmcuoqnJzcoggS39T4jjmxJYGoMk=@googlegroups.com
X-Received: by 2002:a05:6902:1542:b0:e6d:fc1f:3c9a with SMTP id 3f1490d57ef6-e73eade0d08mr5834344276.20.1746037948163;
        Wed, 30 Apr 2025 11:32:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746037948; cv=none;
        d=google.com; s=arc-20240605;
        b=RzsxCnH1Nt2gr6sF2LKgBgFEZwtWmyU+mto+w7LJvuF/KWhxJGiiHdnUo7PNPMZ73N
         OOI2dqs53cY+oZLXcnI/nhOtUDKXVCCw+rnhQYIu7z9iDpW2NYLIEdz7uVshwgfgk80a
         BNURdLe7u/JhxK+WwH6cpjWwNV+33e/GAc/UbtO6zMil9r3zAJBv4B58Yx/PIwQp8CTy
         FM5MI8OpwZnk9yMDzFiZEdAzWdjT2iPdRsi3aIwUTaa1vvEuH2WhSnLfL3lCRxv04XD+
         JvMTvVEse+P+LCzxcfkrBh4nUSgYXelKjVqHB/Ag4+b27M2DCp1qVFQSxN9dMLqRS56o
         sYrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oq+eCJc0gw3GIz/xcLSjgk7dmNoEtZGEP0Cyk65cVQM=;
        fh=vuqwRWwINia5VpWpj2ioyjJd1TDgkKVqERd2373s0NM=;
        b=i7ajHgeEQ+XWd9zxLzdYUtmZe8o1z0skqnkvZSS9fezxCuqKIkZ20gcLEPyqRHERXS
         XfosPVqors0v6yWgB3ME848Pxrgd1KCZCuOEMowvE8dhT3qRC13liASPG2IoRTNyzu0p
         z2H+2oj+Zs/Gp6wcQKFCTGbv/eg3rTThgx6cuYsrLF3XBlOohn/LPaeRSIq8p5RFK73Q
         KbcGov9xRoCSDdTYWN20giSbbr6mica+M+eqQwFRxdevwEyridfBzbSwtuy0pRZO8sR5
         BOLnkqgtI9rQBQn1e+CFtm4moZzErrGT3KkgoyRKJZz8pADVsXk50sQWhVL6CjEesHtP
         4/uA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="IB2X2j/T";
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e7414850904si85841276.3.2025.04.30.11.32.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Apr 2025 11:32:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id E7CE1A4B6ED;
	Wed, 30 Apr 2025 18:26:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5A331C4CEE7;
	Wed, 30 Apr 2025 18:32:26 +0000 (UTC)
Date: Wed, 30 Apr 2025 11:32:23 -0700
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
Subject: Re: [PATCH v2 0/4] KVM: arm64: UBSAN at EL2
Message-ID: <202504301131.3C1CBCA8@keescook>
References: <20250430162713.1997569-1-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250430162713.1997569-1-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="IB2X2j/T";       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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

On Wed, Apr 30, 2025 at 04:27:07PM +0000, Mostafa Saleh wrote:
> Many of the sanitizers the kernel supports are disabled when running
> in EL2 with nvhe/hvhe/proctected modes, some of those are easier
> (and makes more sense) to integrate than others.
> Last year, kCFI support was added in [1]
> 
> This patchset adds support for UBSAN in EL2.

This touches both UBSAN and arm64 -- I'm happy to land this via the
hardening tree, but I expect the arm64 folks would rather take it via
their tree. What would people like to have happen?

-Kees

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504301131.3C1CBCA8%40keescook.
