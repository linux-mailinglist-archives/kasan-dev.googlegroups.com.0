Return-Path: <kasan-dev+bncBDV6LP4FXIHRBFNK3L2AKGQEDBD2OCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D719C1A9225
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 07:01:10 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id b1sf2825507ilq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 22:01:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586926869; cv=pass;
        d=google.com; s=arc-20160816;
        b=PqslCzG130VuQMtoIGMvrMC6cmnMWXQ5Aq8DcClEkAa3fHO1utTWkYq0sgbtHVsU2O
         D4En6VS+djMLKNpIfjXMyCf38PGf29s9EIKaYFv1qQ3xT8AG9P3iiUfNwrV0WjDMm2Gj
         BT69oZ7A7KeugbH+LCeAfb1xJDRPgt38y85xlWMDV9BllmcD8a87e/ounE8rhTEVZ6P9
         nT7+OxR9/l8zE0DDuJ8vLOXY53AiPMCuKgfUVc216b6rGzz8O/GoV/16ZO+g5ZlqQB8J
         qJ3cUmjwlbjZTuw2/VxGCFbJwL3icI2vz2Bl5mfYtMAFfonDnrLGRIrd7vVOyKaKoAz3
         /hng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=byr5SewLoz2LApoo0UUqF53WH1Z23s8uMo2M4ckIYfA=;
        b=LV/CNCuW/DCcFZT7RaFdY4AnBHtEbMvK/dt1ZSqwpXg3IJ1UQq2z7a2u+TKpjP6PEw
         qy9jIFFxl/kxGlJlzvP4vvq67IbERP7BRSEHm3IiFS/nGbOF2l4b4nJv2xsC6Ze96h4J
         KqlAWK/9HDOngnQ8kG15PRlST44OgDADBKe3iX7bpWGsvpP2ctC8/3OB4td59cnVknr/
         OEYVXZWeW0upX6cnV2pBpghxtcB5R9AiSvyN6Cd8XGmfgt6igqkMN0kUNdQ4Zoub15nQ
         u/clXGAs2nBf6iD0WkIEcVpVRFKgJ6Sk9Kwudx+XeW6ahvhJs066IMwrPTKcX1dwQPDs
         8Q1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20150623.gappssmtp.com header.s=20150623 header.b=Tcxzc6xC;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=byr5SewLoz2LApoo0UUqF53WH1Z23s8uMo2M4ckIYfA=;
        b=dGCw06Ry85PNOCpEVqQvp8JErOr7CCbRqwCLep+1IhHKNdhV39ms7TKEJKUnV2JPvb
         dAJTdSIUtxYWmTK7Toq3CxrQ0WiJxJQHmpq4rYYJQc90DcLM+g2vGv4iKzaD5Imjd1KH
         5qCk+VgvhVkj03dqLgwco4Ww13gSNIE5Y2HzG/GZeKvZP592mfOiwO+GHaRZERn+xfsP
         IZi4/zhNXr2aL0Sb/zhKDQtrI1LIBnXZvvIlCJoZS8+K5ZGRkP6Cs09YY22DyomZ/6j7
         mzwrLS8YzDuYZN1U++MbR6XTqhE8UoH/YAng7rjxzOWj9hgd5NMc6GwxXEi4sKkYb9c0
         S6RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=byr5SewLoz2LApoo0UUqF53WH1Z23s8uMo2M4ckIYfA=;
        b=rQpMLvaICtiXai19OGC/dGEiApx450mssMssw7KM2kOck5jPgz8F4GHsUy/X9ImZBP
         L3gTZdpd5awn46dfUQ3bgYYR8rcmLyqMMiXuzi6Jl2j4zWjhdTdvXaz88u4rUH+r1uA7
         LAUAwShnFMrmDF+8u63H1P8p57IhLuuxTZTOcIoxoNoMKiGoyR3BqjHnaPnIZtjFk93Z
         YQDJ8ybn8227DLAQW0L8QL3zyEPiHJTZN68ADMwlSLXuxscAkiWeSKaRfHhaGyzxKrgs
         L0Cdtw4ePc7IdsyoPMkzOIb+8MvzI1SpyL1xncwCRlTw+NmrvzZIoC0TomVajbmJSOPl
         ptIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pua9k4OwHRwpUQV3G5FPtHNxOGN8HZLCjC4ckmf0V94HgrJUo/Ew
	+PZszjolXj5AFBMEhvMWCrA=
X-Google-Smtp-Source: APiQypLN76Iq/uW0knPXuN4ZHwiZ4V+XL5rK1OzZq9im+aWb70+TcgD94EdZ1t86j28Y4kVjMyCsqw==
X-Received: by 2002:a5d:9b0d:: with SMTP id y13mr24717761ion.117.1586926869429;
        Tue, 14 Apr 2020 22:01:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:4919:: with SMTP id w25ls2849230ila.10.gmail; Tue, 14
 Apr 2020 22:01:09 -0700 (PDT)
X-Received: by 2002:a05:6e02:672:: with SMTP id l18mr3890034ilt.237.1586926869116;
        Tue, 14 Apr 2020 22:01:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586926869; cv=none;
        d=google.com; s=arc-20160816;
        b=pnS2PksYAdJ+iuAbFVw4A4+RR7faOzszA8M0kl6oYdTyq8WBHM4uX5XwbJ1UxrdTGH
         UKEsNugMcKZX814g+iynXaBYrQHBBNLkdACeHT3ToSZNQK376BXseMm+sH+S290Q6vS9
         CnryXhRWL7iJ3Cm2wjxdt8QfMgTxhNJ4k04LjCbDSUqu0TK2SScuyyE+cYOgw4lQmI3U
         UzaTdMDxsL8l48YZQnRFl9NU0uKYehcxbPIXxil+ocPeQwpJLapupcMRJmBrZZs46n9b
         nZSdh03Wv8vcHFP/n+GibXzmjMhOXQOcfa93Vra7egq/Od048kXZf1UoomvW274ViJ3A
         8RJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ef3HLI/XX5ogd42JRuoGnEbb/Ln3ZxgvuLj5jaeUWkI=;
        b=QEv+m+yh/zQqGOCRkRJzOXBKJ9MjzXHgrvipC5D217V/mB+UXJ8oU/KwYcfWT+eJN0
         sJUW3IdkA8GWLs+W3bVhn4Qnr+NWT8WDLTPQfjPKWwuQUSd/RwEEYZqaWrvg5ewyGjva
         szdxYPT33vKdmLmr/TzZW7r9VsI3ZgPTjg46lOFj37ihjdxfRxBZ3NebzOBLcTIRqV4g
         kqZz2AYO1mwRhxauCEOozSTbAEmpMT/wndG+ye7dugjfT3FrCVSnnuJTT11+ZcBg/Stj
         WHtbF/KcNsPWZBGKOx3+7m94el5te22hjyH3EA5XhbxGth3txoAaz+fCoGqpiBm0eBz/
         VhwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20150623.gappssmtp.com header.s=20150623 header.b=Tcxzc6xC;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id g17si638358ioe.0.2020.04.14.22.01.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Apr 2020 22:01:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id v38so1099171qvf.6
        for <kasan-dev@googlegroups.com>; Tue, 14 Apr 2020 22:01:08 -0700 (PDT)
X-Received: by 2002:a0c:e88d:: with SMTP id b13mr3243342qvo.245.1586926868219;
        Tue, 14 Apr 2020 22:01:08 -0700 (PDT)
Received: from localhost ([2620:10d:c091:480::e623])
        by smtp.gmail.com with ESMTPSA id 10sm6168833qtp.4.2020.04.14.22.01.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Apr 2020 22:01:07 -0700 (PDT)
Date: Wed, 15 Apr 2020 01:01:06 -0400
From: Johannes Weiner <hannes@cmpxchg.org>
To: Waiman Long <longman@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Joe Perches <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
	David Rientjes <rientjes@google.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	x86@kernel.org, linux-crypto@vger.kernel.org,
	linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
	devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org,
	linux-cifs@vger.kernel.org, samba-technical@lists.samba.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH 1/2] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200415050106.GA154671@cmpxchg.org>
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-2-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200413211550.8307-2-longman@redhat.com>
X-Original-Sender: hannes@cmpxchg.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cmpxchg-org.20150623.gappssmtp.com header.s=20150623
 header.b=Tcxzc6xC;       spf=pass (google.com: domain of hannes@cmpxchg.org
 designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
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

On Mon, Apr 13, 2020 at 05:15:49PM -0400, Waiman Long wrote:
> As said by Linus:
> 
>   A symmetric naming is only helpful if it implies symmetries in use.
>   Otherwise it's actively misleading.

As the btrfs example proves - people can be tempted by this false
symmetry to pair kzalloc with kzfree, which isn't what we wanted.

>   In "kzalloc()", the z is meaningful and an important part of what the
>   caller wants.
> 
>   In "kzfree()", the z is actively detrimental, because maybe in the
>   future we really _might_ want to use that "memfill(0xdeadbeef)" or
>   something. The "zero" part of the interface isn't even _relevant_.
> 
> The main reason that kzfree() exists is to clear sensitive information
> that should not be leaked to other future users of the same memory
> objects.
> 
> Rename kzfree() to kfree_sensitive() to follow the example of the
> recently added kvfree_sensitive() and make the intention of the API
> more explicit. In addition, memzero_explicit() is used to clear the
> memory to make sure that it won't get optimized away by the compiler.
> 
> The renaming is done by using the command sequence:
> 
>   git grep -w --name-only kzfree |\
>   xargs sed -i 's/\bkzfree\b/kfree_sensitive/'
> 
> followed by some editing of the kfree_sensitive() kerneldoc and the
> use of memzero_explicit() instead of memset().
> 
> Suggested-by: Joe Perches <joe@perches.com>
> Signed-off-by: Waiman Long <longman@redhat.com>

Looks good to me. Thanks for fixing this very old mistake.

Acked-by: Johannes Weiner <hannes@cmpxchg.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415050106.GA154671%40cmpxchg.org.
