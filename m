Return-Path: <kasan-dev+bncBDVIHK4E4ILBBM73ZTWAKGQE4LFUW6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7424CC3358
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 13:51:16 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id x13sf3973055ljj.18
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2019 04:51:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569930676; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7EKMSpmTL8qyf+Gsv8lP3eHNLNUJW5dGhCzQM6RzIFd3MPbI6eRfMgyl4I/K/cfNh
         2URsXXpAZpDGKesn6pKWocECsSaywDN4h/8e7KoEK65lrGEKO/zKP0MLWL70w65s1c7o
         lLXHPlCsK9z4XHwNugBQPcqBmztZYI5oBPJV1xMBUaV3KpWRToCK/HOBSNINJfvaOzTh
         R0/c0z3ND+mbCGNv8gm4AtXAEkJQYamEcYyfzqb+0dVODLZsmsO0vAe4xYUV7O6ZK4kz
         2po/HiLErn4YSA9NTK/ocWKRmGj2fBEpQhHpfacsS9zwXkqeG8B6eCKxkwTzWNPQ66Ho
         5QBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=JLJS2S8eN8fTai6JttzBdd9/aa2NzKVBfNXVfQuwQt4=;
        b=sVcZSIcOdCoDtNi3BbdOkaN7BQxzqRs1OHHuYtfOgsr1Wmw+vkEM67pxxVlI7RtSm1
         YnFruvV0GXp5bvgQ34ZWdpXyA0UFwPyBKuWJ1IKMoSIIdOzWPi3oF7e9zEN/OJ8wjQbP
         LI6iz9J1lVJS1pAeAoHnplRAECrm1u1P+iW/AnMGAQ4vJzwhKXH+N4oOKRCUBDIBu2hU
         YbdjP9VxoA+s8H1T87dWqmR5boeqlJgVs+J/v4nxvsKSuwB2eB8+MHjFR9aa45LYa/FL
         lH50XCi0fPNVu54/aQK2zTA0SQaRIyAmmfAamkWWaHE38OUggzY2NCknthdHTopRyE7J
         h+oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=AKJTyjYW;
       spf=neutral (google.com: 2a00:1450:4864:20::544 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JLJS2S8eN8fTai6JttzBdd9/aa2NzKVBfNXVfQuwQt4=;
        b=Lq2nFIEI+/KBkf4Z1opWRZ4i8UK+LHZOes5XQ2v0Unp3ZKwY+VEBmskhDk0GHycs3G
         xiCnQYQKPAn+BkcytV/rsfFkB5F4U404k+HTHiDAev6VHHzeSOfxk8TlDjpbJ1Qm1h57
         Btsxz1Hi6r5SY49hjhtjxzfrk6JHEtDqMYam+PCpn6giYI712epMq6chMgWDu054J2m5
         783GfaItYa9Iq7zoR7CLNZTp0OemyT0q8tq6CDHNuQDWFsAyhBksUWo72BwJdS3wF7HQ
         +Zi/EHG8yBw1TdWaZEJCNKC0rKxfPgE1L6N/r5SHDHRrwfBCqVQPSIHUEyMhtcnvKWvz
         wjqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JLJS2S8eN8fTai6JttzBdd9/aa2NzKVBfNXVfQuwQt4=;
        b=CP3T9pXPSTjQQbBUXpsJLkFrQzJQWlh+LOcpaIZTeU0gMe2v7KBKBPpaljE1xLIMj0
         9Wa3Ex6zFx19todMDAuInOIw7Ux2nbhU9Zg4krdmQ631UhitEVAtqLQqk0rx41ZDx6T7
         5b/TPI3bq6tWbQvCsjQWFWGKFUBr+A7oBAmKy+7DRAK2GJwOJnf6hlMa0W2ZZ9nh7fFE
         td3rNLIe8FRpPfV6WEfhxzyiXqAyewQARM2661+AYVVv9gC9RSNUqQ9/1Nq0rcyU0DEv
         wgZXZImhT7Byn5GTCLboEf1rXaJpWG0aa3GWOjClKRqe4tVllsiad2aHm+salQQn4Aih
         4zww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWA2YQ2Hx7ft6/oAcmcqG/8YeRfSvy4h84MhlwIOeJAUQEyt/nd
	Mx/qqt0q/gwr9z08/9BL9M4=
X-Google-Smtp-Source: APXvYqxqBrmuIHhS6m0e+fpv9aToyFUlOQL06Tj0ePgsx3ev++k3bGXBz4+HU3WCIQITKT8CcH90qA==
X-Received: by 2002:ac2:5ec1:: with SMTP id d1mr480974lfq.83.1569930676057;
        Tue, 01 Oct 2019 04:51:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1043:: with SMTP id x3ls1973312ljm.14.gmail; Tue,
 01 Oct 2019 04:51:15 -0700 (PDT)
X-Received: by 2002:a2e:9692:: with SMTP id q18mr15598710lji.73.1569930675418;
        Tue, 01 Oct 2019 04:51:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569930675; cv=none;
        d=google.com; s=arc-20160816;
        b=ysnWjEdt6UlvidzheowsfMphhTtcjNoNgfDTceIJnWqcTKvoRlrJH+9AgPlJRFowTN
         Z+AN5aaZ0CN/h+zx3gA4TgZUwXTwRCuTuh0PUuOwl/lQPLg8tgfQUL6hw1jI77Y+x44V
         wqUPr7IJQbCxeeFjrHQnO4kXkox7dh5VYjHxz9lAx47tWqqi63E9hJUwNg0yzOg7hjLB
         bTORrTqWX+8uFpciXpgRO+uKFcuOkaytnTuTQOt7e5IfjpUfMp+U6Vn4/0WoMDUFHjmC
         mc9WgqBWICwTz60tt0X9yuXcXO53unmBdQZJuzxN8JcpmlZ5PAmxNtLneyiw8iB42DxG
         BHDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WwRvxBteqT86BHeeOqI/ZRhly3cYrwnuA1zRjDpe2Bw=;
        b=hi5WCAEBRFcFuWV1ombRy9ZiWbeeXvTsVzXD8g9KKtD5Gx12DWwch9TAyBdEHwsCB4
         d7tSZHIGQIu+9bDtssQc6CRnWPdlVQnX1V4eSd7GZ8CUI5XQ0hrc5iFrH2baO175Z2SG
         HGBCkhYvPA89dmsGGnMGqWLaDlvTTXj1I+ZmkZQYF65Eo0ZZss1XmY1kaVBT2NWheIbJ
         OMJhVfno8E7Lg2Ul86TJ9AiN+0jd8VRslsnNrLQ4otUQXy5d31dz6NnnbBqQ3dpyzJGn
         qVV49WRCnQaM7cctUbsKZJxsMcdYgwAkGCLRRVxE0aqV7RBNUtklm0JG0+jrUv9ymjLY
         /2uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b=AKJTyjYW;
       spf=neutral (google.com: 2a00:1450:4864:20::544 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id c8si1101878lfm.4.2019.10.01.04.51.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2019 04:51:15 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::544 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id f20so11587292edv.8
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2019 04:51:15 -0700 (PDT)
X-Received: by 2002:a17:907:40bc:: with SMTP id nu20mr23547119ejb.309.1569930674891;
        Tue, 01 Oct 2019 04:51:14 -0700 (PDT)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id z24sm1818728ejr.83.2019.10.01.04.51.14
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Oct 2019 04:51:14 -0700 (PDT)
Received: by box.localdomain (Postfix, from userid 1000)
	id A87D7102FB8; Tue,  1 Oct 2019 14:51:14 +0300 (+03)
Date: Tue, 1 Oct 2019 14:51:14 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Qian Cai <cai@lca.pw>, Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: [PATCH v2 2/3] mm, page_owner: decouple freeing stack trace from
 debug_pagealloc
Message-ID: <20191001115114.gnala74q3ydreuii@box>
References: <eccee04f-a56e-6f6f-01c6-e94d94bba4c5@suse.cz>
 <731C4866-DF28-4C96-8EEE-5F22359501FE@lca.pw>
 <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <218f6fa7-a91e-4630-12ea-52abb6762d55@suse.cz>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b=AKJTyjYW;       spf=neutral (google.com: 2a00:1450:4864:20::544 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Tue, Oct 01, 2019 at 10:07:44AM +0200, Vlastimil Babka wrote:
> On 10/1/19 1:49 AM, Qian Cai wrote:
> >=20
> >=20
> >> On Sep 30, 2019, at 5:43 PM, Vlastimil Babka <vbabka@suse.cz> wrote:
> >>
> >> Well, my use case is shipping production kernels with CONFIG_PAGE_OWNE=
R
> >> and CONFIG_DEBUG_PAGEALLOC enabled, and instructing users to boot-time
> >> enable only for troubleshooting a crash or memory leak, without a need
> >> to install a debug kernel. Things like static keys and page_ext
> >> allocations makes this possible without CPU and memory overhead when n=
ot
> >> boot-time enabled. I don't know too much about KASAN internals, but I
> >> assume it's not possible to use it that way on production kernels yet?
> >=20
> > In that case, why can=E2=80=99t users just simply enable page_owner=3Do=
n and
> > debug_pagealloc=3Don for troubleshooting? The later makes the kernel
> > slower, but I am not sure if it is worth optimization by adding a new
> > parameter. There have already been quite a few MM-related kernel
> > parameters that could tidy up a bit in the future.
>=20
> They can do that and it was intention, yes. The extra parameter was
> requested by Kirill, so I'll defer the answer to him :)

DEBUG_PAGEALLOC is much more intrusive debug option. Not all architectures
support it in an efficient way. Some require hibernation.

I don't see a reason to tie these two option together.

--=20
 Kirill A. Shutemov

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191001115114.gnala74q3ydreuii%40box.
