Return-Path: <kasan-dev+bncBDUNBGN3R4KRBB4YTDAAMGQEN77OM2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 41320A94E72
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 11:12:51 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5e5c1bb6a23sf4406090a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 02:12:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745226761; cv=pass;
        d=google.com; s=arc-20240605;
        b=g+oM86IN5cGVCzZBWeMGB9hsvgfCo7IPuQZAPd8T4huGElmlNTbsz1XnI8kFkSinmC
         Gsay6IPgsknu8bAjXpkPaHV2wpICBvp61R/JbPBk/HIsUtQkUNB/Zx2rMihm9Ok9tORn
         g+orJs8ND0BK+vKAK/MTzm81n4V6g4rzbuWeOsZvx9h5DoSo9v+TaDVeU8Zx+AP6fPyA
         yc3nzORtBSeh04yOS1qeP3vNeJUqITOiqh8gRGeqvifkwVngd8kmYGJcxjWcJSDNgdDF
         QQJZfAcy+2ZGfbIw/Pq9qdEcI+IziswejySFMxwq6Qz2Sjs+Z6LrOhtsJ02LK6Zknsim
         iPjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=TaUKNtp06GH1mhLH1AL7FYbc8M7xyLGsuOcIxOTvVTg=;
        fh=kFe4z1CTZuRr7FnZl/097CfVbKp1kpbQE2M5A9yDGL4=;
        b=IxipFn1OIoNGIeNHHXmKPg/FgaXUGcl+djQvqFqUCHtSR7EdxGhS50GG3+cxqxsd9E
         mc57Y3HNScadSlcqDgJ6Ms14phwZheWMfqhAvgP7Rofy7YiUoXRi6twtuwvD4bZroHfn
         3mFhbaEawgciCL9y41Z6DmQE6HqAX+g+9PlT3skOjPhuuNDlPK9DxmqAOQC7HoUH93jb
         ES7QIkcdHDIMnI+c6WecXgyUe9Y5OTmjNU6oYAcfhxoxt01gjoRxAYB6ZPqagUTZGu11
         w9NFvQyEP8IFfe38YBZVg8sVX8b4yWutkndLJUYLTTmU+4MICFaCiDyXoFJATDLn6Q3N
         Rxnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745226761; x=1745831561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TaUKNtp06GH1mhLH1AL7FYbc8M7xyLGsuOcIxOTvVTg=;
        b=mmkBShYQgNFvzdR0i1YWyArMEYbKOw9SUMKSDyQoWIyO7PqRG8DBnagqS4Iw47ZgW1
         Eqbt+2K1XZvV+652AhPD+DD1bHGd4T+J1D4C9thT5LvV4izYK21ZHcOn3O0Ab/ZepVw4
         /QOZJi+EMoV/iX9at5fHSPLsdLiZCMQunr4WQao0OrQR57EY6wauE9Cwf1W6YG/4FBud
         OCy9FcwtnvLqbubt1YAYMGkR2YvqRSGkhwsBipABwhFok/mHeE8QU9t3jS/9NlB35FLJ
         tgmZ1kbYuqOmgAs/nk2nS5HzgSEeq1D49r/sdzx/4fBkA5K7mRE25XAk2F/5JJxY805q
         Ny8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745226761; x=1745831561;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=TaUKNtp06GH1mhLH1AL7FYbc8M7xyLGsuOcIxOTvVTg=;
        b=rZm0Xof/g3/b35ATA0+FRZIqx0q9ADG8nqK4M8RZdsIwMFTcgpswwSvS/xFLbF77G0
         LCQulKVC/wYNu9X3qgg4c20+SAWxaKVbDWVRuj4XSpu4t20QUTbcGY6jss+kTjEgqTDc
         87svRigxxMMTa+Vm+VB0VixWUjwg8eZ2jsoZIYy2REY/e589bPO4AgLBcjq+1t5Ueoj2
         FOaf/QN6QzIGcYTQsSvq9W/HJypKk69c+8VlFOPBq1dCX2/kMiEZNr6feZJQk5gwGI/q
         nuzsIqsxh7pvpQj3TnXXZksockeaiz7rkglhPwMP6Gt290fjt1Pj+tMe9PFARq4HK0n9
         LbJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsF/YPLpI1BPUIl3sds9YzOakEojoQT0yGxXw/mBtxkgaLnkp+vGCr5CVxRZYrs9UAhyZK2Q==@lfdr.de
X-Gm-Message-State: AOJu0YzqXtORUIL00YUxXrVFpgvA9YjFDAlISCZ1OLICEA3mvEoM0Inv
	uZZEmmOmfgqnoIVHTh3nbJbY/CL6QEChV/GuIHmLUs/Un2e0ARLQ
X-Google-Smtp-Source: AGHT+IF6zgyYBQBG0L4xjWYM2ktXDCsuRURwyD4jU7UkFEpchB6JMQ25+C+/r4+fqm2/j6pGiJU25g==
X-Received: by 2002:a05:6402:210a:b0:5f4:ca30:acab with SMTP id 4fb4d7f45d1cf-5f627d4688dmr9974420a12.9.1745226760185;
        Mon, 21 Apr 2025 02:12:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL/Y8ukRogj0CEoTBRIn6jw3faK2h7ylgqbHICe7ajNgA==
Received: by 2002:a05:6402:35c2:b0:5e4:9718:9ea4 with SMTP id
 4fb4d7f45d1cf-5f6b02f121els177435a12.2.-pod-prod-00-eu; Mon, 21 Apr 2025
 02:12:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVy5xMnOoO6Nng+W6FbaYTVAOGJAq5ZGIhGSd5Il0xdU+XCzmAIpyL/Cmt4mjUPLIaXQCaFln31J2o=@googlegroups.com
X-Received: by 2002:a17:907:6e8e:b0:aca:d276:fa5 with SMTP id a640c23a62f3a-acb74e53288mr924911066b.0.1745226756992;
        Mon, 21 Apr 2025 02:12:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745226756; cv=none;
        d=google.com; s=arc-20240605;
        b=U1wQKhSMW4zVPNLxxI/wvIvuWI1BhXQ/ZPmlhGxeD4fwONFPAXlttqtPu33oC2KieP
         pOAxsimkpUvUPvJwNZWl3aYkkOIDYROOusEdc7Jc+JS9VeKBY+YT55wRpuhyP/ktLvpw
         YdjhBkUpXTV/oVat8mA57piIJALWwARpgGpmkOHSMS9lr3/NB7ddDgKDOt1Mc4l6EFQA
         iGbpYKpS8nX1eFFPlPlI9OtkFuOajHcgWvdtUyDgOIyNoYrlkx34GH6GK1VRlVk1Ilfz
         DiNxj33m1kAaAc36kdX0NEzvwpxSjFOTMaYVDCrlWmmzcV44hyNcBcnuy3KnKY/bv0Eb
         5ZtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ZwnMT9iyHKRFWugR+0k3kpgyohlUA1bPJnpPrt50Yco=;
        fh=GVqYepxEFTP/sP/yG3gY3pXURdbDjo5PppVB5S4sZYQ=;
        b=E7FdJi7UzYl5YMsy8lzOf+5qVp3Bkf+adhUqJgRFm7PC1Ubaoi9A5EBXzFQZjvl3do
         xNRhc9/43tSM2SxhOM8Gjrp7O2fwX4l55TOBsoNMQgJDMAnYbbpKdf9FwRpKF6VOtIaL
         m5UOpJu7J/fENLsL6fXjbiKcpjjxmnLj10zxL5zC3DDcjk/frrOTZyjmEh8DoCRgSSKN
         VvyT90ce5D9EFM6c8V4VtdPnPO7Tf/LcU1zVcRAJntM0SeC7fGh/R33TLsxEoLA70qjW
         xeuUW6rDpJP4OV2jRL5itEnVar2ifkJ2RhTto+BZNyh0WjZBwyNecZv3T+4jccCOdooN
         i6qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-acb6ec59725si14988666b.2.2025.04.21.02.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Apr 2025 02:12:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id A997967373; Mon, 21 Apr 2025 11:12:33 +0200 (CEST)
Date: Mon, 21 Apr 2025 11:12:33 +0200
From: Christoph Hellwig <hch@lst.de>
To: Kees Cook <kees@kernel.org>
Cc: Christoph Hellwig <hch@lst.de>, Masahiro Yamada <masahiroy@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-sparse@vger.kernel.org,
	luc.vanoostenryck@gmail.com
Subject: Re: [PATCH] kbuild: Switch from -Wvla to -Wvla-larger-than=0
Message-ID: <20250421091233.GA21118@lst.de>
References: <20250418213235.work.532-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250418213235.work.532-kees@kernel.org>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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

Looks good:

Reviewed-by: Christoph Hellwig <hch@lst.de>

Note that sparse currently also can't cope with VLAs including the
prototype syntax, which also needs addressing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250421091233.GA21118%40lst.de.
