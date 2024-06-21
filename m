Return-Path: <kasan-dev+bncBC5ZR244WYFRBYNT22ZQMGQE7W6GSFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 90FAD91294C
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 17:18:58 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-3d217d63eafsf1914802b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 08:18:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718983137; cv=pass;
        d=google.com; s=arc-20160816;
        b=WLMJMGcO4v+YUU5OtOwvrxHEjsaPGiIZKlz1KkTgbCNV7jfOxbOqeXYeV5UrgN2blD
         pxcm0UZar/suQyeZdtn2kPXAs9yWNbpZVucEhjb7c4e187kZEpHrU+4eRq3knKdumjeH
         KEN+seSNDpwPcMyJjgd6G4a0nvYhWFlaxmpE24vfT8Zk42kin1sX5FzRQs0Wo3AjhmlD
         rH+wPCDFtAYNdTgAFqHtKohWGB003gVL/Blwz7igZkVlNnLJXLFF41/VYTrjlnGAHF4U
         k1Ft4pZP3rWcCBwc1QwRPDxT3cW/l15ilrZJx/MtvWcDh1JQMWP3ZV6iNK+AOsODGUqR
         4qZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2K5cVFiutuI4jJZJWn28WbqoycaqUXMtDKUcLDjoLfI=;
        fh=dlhMWK2jWtayIM2tVc9q5UCLQ+er2VjZ2pJ3uh8mUvQ=;
        b=vEIOQ+At3749P3a0wUwtF+GqrcFtaro8NStBmCsKhLERRBP9nGNPFgWHLE2d9FQ6D4
         8UOTQFyIlbA7QOF0c6tASYQtVUMzb6vQP/1ZR+21RK5l2I+P9wxgTEPXp6c0VhOKx/s3
         HwNnHz+VkH1faahUmIESkDpeNTRakEyE/x4QhGjegRt4SzoKtkhtWuk3bSIiFne27Iw3
         /i1RvxUrg9nb+ku53flDR2j13w6ATv019mhWZiJcHEk8mEeAgfmCbbxDz53/Fpd42rZF
         hpTw7GWyGghmE+rEeNARTSvRXh99dks8hqxPr5fh+8ikvZMHZ1gDGAX72VwJmVxLctde
         4jTg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=X7FpdOPg;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718983137; x=1719587937; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2K5cVFiutuI4jJZJWn28WbqoycaqUXMtDKUcLDjoLfI=;
        b=eTZpgejwNI16mQ7f09OspWkm153j3WsPPUx0P0AUf5QTDd5PUQYQ5WbxiXS9wE1QGq
         ajw7fi304yH+U82snzIqnFT8O1kjyTVLapUXpLjMyM312SKjSCOgXvS0Rg0aO22XNkJn
         lhgI/vr7dr1qwEnfaoPG15qohiQNfeWVGPWNHb6SI5OQnJjk5BdP+mMg0vKN2xG4CaTI
         WPsPQ/Ap3MUBaPOE48IBnPnHPqwxVNAHFkDANxs6WzctcufyZKfhoM3vdOye7DyCpNo7
         MpWXLI5mo3FGHM8rx9EuvPEZhE/n3UarKNinm0kEtZ4YIiklPm0T08/n0arlGUgQVCW/
         CZsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718983137; x=1719587937;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2K5cVFiutuI4jJZJWn28WbqoycaqUXMtDKUcLDjoLfI=;
        b=QVFqLuDgONmgPz1MTIWbOwjFGJLOLcvZNL/nCYMm/1yVDbdNx2FA32564nSIsboauy
         LibiFvGD3YjBOxPNaPbim7fTmuU1fweKnIgdgfde+25HnPNhYU6OQyqFobzPaZsZK/NO
         pDh9B+IoufwB6Vew/G30JWrecZrhZQ8F4ov6dQksu+moIhCbZvayfvD1/2WDGT2VKs76
         Ly8dQPZ3Pmr5Wqrwm84jJ2aUWztY1JpUMvP7kNPurOrgAqoRrj2TpLwXOlAn6RNXufNM
         py4dAORJ8c49Vzv+P6ynAVg99Mvrs3NuQbYnTO4HfhcOVuBAxQVShvHJEBNsmNTouJVi
         4iHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW7UBztHncq030UHHq2617zmXeaXDf1WX60nVny0LirHGt+kaqrA83XaqyKDweiCDIybCekaj3YIjWTKqrH3rh62MYqbPIqqQ==
X-Gm-Message-State: AOJu0Yyune4XMO+ukwEWDuoToaLWW3TiKU6QA5GN9LZ93e/rA4G2/FJn
	bLgPKnx7dzlY8X8V6ocFTMgu6/YTdlCLbIGEN9MBvYR4qSHEQZ1R
X-Google-Smtp-Source: AGHT+IGI41yiJsWiMfJxeOVl6mD+uN0N2c1qRWzMp4V667RuJJssKPq3kd4kpTx3XwN7s3cKpBrEdg==
X-Received: by 2002:a05:6808:10d5:b0:3d1:d214:2492 with SMTP id 5614622812f47-3d53c38ffa3mr37028b6e.29.1718983137322;
        Fri, 21 Jun 2024 08:18:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3815:0:b0:5ae:1f6c:8988 with SMTP id 006d021491bc7-5c1bff18468ls601668eaf.1.-pod-prod-00-us;
 Fri, 21 Jun 2024 08:18:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqOW1TwsJXhcwTjsgFPZteOf0eKhYyXxlrhn/3R8qPLju3ijC/qFDbMYmbvGZC35ASfh2GntmcMpF+/IbsTZSp4y8fnSmOuPkQhg==
X-Received: by 2002:a05:6808:114b:b0:3d2:2fb5:b477 with SMTP id 5614622812f47-3d53c2d9e3amr51166b6e.9.1718983136315;
        Fri, 21 Jun 2024 08:18:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718983136; cv=none;
        d=google.com; s=arc-20160816;
        b=z+NU+HQChH+4djTn6vQ7hKlekt+0ZLazqlh9G1EtWfJbncjetGDZwktvosFNrF/9y3
         xal0YYusDgfgyojnTSxkH9gxy484MI413IN5DZwtMVSkUkT5AA5JAxAa3zVrq4wO7iXp
         sPZ8coJH/n/dpMQLJVX5PbsR780SAoPeflMxwHubU2MDze8mYdwhRvdAZ6ajlg1AA7xc
         GPPzWTL5lh+1o1MDs2Nmo0fJEVisXoDKGoShi70ckobWJJeVJk9zax8dmOwWROxs6Pj3
         cHXiiLenqjVwdaxkgcGPjXtcgoSncgsJa3SyCPYZdVEcQiE7wqo3hA9eftmVw56Xkucx
         R/uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=arQzK9E9OaIOaSSqIFBXrlImAbl/ph0pOfVVfAoLxck=;
        fh=xfgZUnrvJBC27HjvXMR9Z+JWAiEWBhuAMX5C5NwzagQ=;
        b=ojm3GRYkXIY2puVNKPb/uHecKTlDaF3phcG29lKjM5eQ4tvHcRg2Taoj6zme9zD0U7
         SC2NsWfKW9eComLhXEzYGHI9HBupabwEWfAFvY9FEbrKqfW7OQdnfh9fQDb+gqASbJbs
         E1dO17X+DiFvarq/EFcTpIFekttdxQqf+aiFnww6qlutO7x5nup9jEOjK+vW9mx0WGWM
         qFvjiUD6u8fodGrho42dShpvWPxF4gymdk2KHMT+PYaBIdUeAEB0/AzGtebfZW5zNYfL
         DgUUpmKmtRP/ur0cjE1lOgKrpE2z6P0mU3Mj8HmrN3sC/xkw2pJtIsxDREdtC/vwx97Z
         ny/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=X7FpdOPg;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5345107dbsi84172b6e.2.2024.06.21.08.18.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Jun 2024 08:18:56 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: cftrBpgzQ3O1Ikbc1iavSg==
X-CSE-MsgGUID: xOfaZ8BRTJiGtFoYrKB1Ag==
X-IronPort-AV: E=McAfee;i="6700,10204,11110"; a="27438685"
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="27438685"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 08:18:55 -0700
X-CSE-ConnectionGUID: WVCIpfUyT4m7SHbE2X3ZAQ==
X-CSE-MsgGUID: OTtIiSzuRYiQWFLu8lkqxg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="65866970"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa002.fm.intel.com with ESMTP; 21 Jun 2024 08:18:53 -0700
Received: by black.fi.intel.com (Postfix, from userid 1000)
	id 130921D6; Fri, 21 Jun 2024 18:18:51 +0300 (EEST)
Date: Fri, 21 Jun 2024 18:18:51 +0300
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, x86@kernel.org, Dave Hansen <dave.hansen@linux.intel.com>
Subject: Re: KMSAN stability
Message-ID: <wlcfa6mheu2235sulno74tfjfxdcoy7syjqucqt44rfqcmtdzu@helxlktdfjcy>
References: <dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq@3udi3sbubg7a>
 <CAG_fn=WvsGFFdJKr0hf_pqe4k5d5H_J+E4ZyrYCkAWKkDasEkQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=WvsGFFdJKr0hf_pqe4k5d5H_J+E4ZyrYCkAWKkDasEkQ@mail.gmail.com>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=X7FpdOPg;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Jun 20, 2024 at 04:12:28PM +0200, Alexander Potapenko wrote:
> 
> Hi Kirill,
> 
> KMSAN has limited support for non-default configs due to a lack of
> extensive testing beyond the syzbot config.

Thanks for the patchset that addressing reported issues.

There's one more problematic option I've found: CONFIG_DEBUG_PREEMPT.

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/wlcfa6mheu2235sulno74tfjfxdcoy7syjqucqt44rfqcmtdzu%40helxlktdfjcy.
