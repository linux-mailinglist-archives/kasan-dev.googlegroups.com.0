Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBE6PZ2KAMGQEPPKJFBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 72AE95371D4
	for <lists+kasan-dev@lfdr.de>; Sun, 29 May 2022 19:04:20 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id q12-20020a056402040c00b0042a84f9939dsf6534795edv.7
        for <lists+kasan-dev@lfdr.de>; Sun, 29 May 2022 10:04:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653843860; cv=pass;
        d=google.com; s=arc-20160816;
        b=DEPRtq+GmHKAWhu3M0amitcKVs4LtT0rymC7HMovjjbvspixYHSMLZTrdin49ZbMrb
         5On1JqkjfvWGKpzRkSobTYgb2FPzu5pJHowwc8pF0MQ5ez6AEvfV1vsuoh0y5X02O1tz
         +SD//pHjoLOPzEMz+D31gDmgEltSBlaRVMN9o6Qv2QAs6acb15w8zufMzBiUcZyD0JvV
         IFDJaI0oud1J0CFnVtNISRB1ABZb39J0FnRQHY0ZvYsiOxLN6FDAj4UuwIEsKK857QgN
         I2skN4nrm/e9yW81GGdDOq8cUITIy82oJ2weVUfKoPO4W2ipIMgQAXBZuuo2EGLe4Dxp
         wzIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=Ylg5hq4jj830qupGgfWhMN7iwK42niawoDGF9x4pOhs=;
        b=0eFAuvOtwALamQ4UfkClRUXBHNHiHzdU/Y9RRuC1E31srvKWuDk6UxDUitwO7O3xAi
         SUq4L0WCuVLuTwmV60aNFRZeEzig+Z+sgViqcVgtBxAz0u2tcyEXSWE/8KWGXAchZgZ/
         CQh2jS3yQlbbGBLqgpaktkCwsz+GAh4N/7Q7gwJKjT0XbOx/jZdkrHVom66WqjgilSdy
         aEdwgWJUagb9fh5nVnd8A01zXDnCBNxtydpVNSLIsej8YC8FF+HeV1rc7opDwhY8u3vc
         ALGsRJOz/md98feVX+efto8ey/WSOCbXWo++qvEJyOcUyAkZaoeEUvI9+ocD6KSsCMZh
         cJbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=vwrRH2a8;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ylg5hq4jj830qupGgfWhMN7iwK42niawoDGF9x4pOhs=;
        b=tI4HEPNKY+dYJ6OD4riyBB1LMKicmpPmRB+AWsi9XvJwG/i5omDr+VvhOAv3diEnAm
         kix4Kedf0QwdK6no+dNT0G7NliMOpYUVHeyYUDrjhLvyLBltPAjq7L35LPvTrDPv8l+2
         cZ6cHTnnv9LrhCl+Ce6hZ8o1dEGo4yych11b/4BQE8oilY2PYu6IBBL1gW50xqdoDyoc
         xFEW9YuygBoTDcxbIf70NZpO/vfv851AHrKtg5oTehnpUyNxyfODC2si3yiHmtD4lHi/
         F2Ew6hb0/Qeq2l9U9nNfb9hB37RW35cgDGTk7b8qFKNoa6hUhDew/19c4sHhbQjyz7Kk
         w4Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ylg5hq4jj830qupGgfWhMN7iwK42niawoDGF9x4pOhs=;
        b=WwY/v1aq+rgeLysWqGRonhxcOvmiPFt1+In8n/s00qkbtrdeXMmQnPD3Acznsexp6u
         ItPIMjtpH0EgWy3UoKJlzcVCV53W9kQRNwpk3K5M4eW3rakODRWkEUYh/Fw83xESR+g+
         gT0plFw0tcsgsx6vHs3MgWbCefSebW+1goKLlkyxBcFOyQCVtftuWPoavQv5vW0TASYr
         J59Vb2Fl8i7eyRUUvP5G6hFh7nTN1CPSVVJuMo818JhjE7s3tQcIyWvn7aKrXCMs/sHI
         G/zDI/rm4SUe8IpHMFEIaEA0ev69WN3AdSsm+EMSR+zsyGM/P1/ZuPZMJyOxM8ki5h6B
         CMzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BND5qwhcfM7nKNzd75rzk/j+A2Mwfst848zKB6LVAt2HMSkfs
	eLAnqUM/sccxoEZ/yTmXTL8=
X-Google-Smtp-Source: ABdhPJyRAnlj4Eo0OvzH3/2ZjLL3L44VfLoL/xMiK7PTG2CKRdPiFNexDBbW6wfbi/ahUIsDPt5XGA==
X-Received: by 2002:a05:6402:a41:b0:42b:e6ed:4170 with SMTP id bt1-20020a0564020a4100b0042be6ed4170mr14402120edb.344.1653843859852;
        Sun, 29 May 2022 10:04:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5205:b0:42a:c2bb:3d7f with SMTP id
 s5-20020a056402520500b0042ac2bb3d7fls4240392edd.1.gmail; Sun, 29 May 2022
 10:04:18 -0700 (PDT)
X-Received: by 2002:a05:6402:2155:b0:42c:297b:76b8 with SMTP id bq21-20020a056402215500b0042c297b76b8mr13595451edb.190.1653843858611;
        Sun, 29 May 2022 10:04:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653843858; cv=none;
        d=google.com; s=arc-20160816;
        b=IFpyzkEhqoKSf3+tzb3ETtwzALxd2a40wy7t/K+pGAHx4twAsOhbeX9rK9JTEDZ1ye
         0su0LXiE8V+1X8ayp+XfHzUl789TspZGugq2TA/Hx4JkgTLU4XdlQGFusBtBkWovEhtB
         Ye9OHt4dOsFuMtkcc2aa5RLa3WY/pKhtFivrMl7hlo6J+Btk3QlMukJQFLaZhsizuIRt
         C1JXei9S+M+yfLxUEnFulC0TaQk1fXQC5iDyEwM+X9ADMEFnqd/zzs347Zu/e1d96t+y
         aGhxj/ITyVp7qnM50OQKqglAqbQjaz7bfKG+vzCJHhux78eExHYAatYfyMxj93M6O4uZ
         hqfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=BLA4aQRvfntqLMm99a+1xZPVRcOluvd10rffKGFrc10=;
        b=SNZSbf6wUgOUAftkzsFLgB2XSgqSRrveaJidxbZ8zVMO6BivkKG0Lp9fU4uopdj76e
         sJYrJWLzUr8UMidy1pgoWJJbs+ziZWqIa0g0g0j8AT4GxMGVMzmFFuYOJ7YCUXu5lrfq
         GK1wVg0aksAUv2puKC56FnWW0jRjC/yxemufE/kRovsEmfLs2/+9mv9dCMkjGE9zb6ng
         gUULfBbQjyXDYvwZP/+PUdpe07blArlXav7ZSf6ThP9XGJatSvYen47cR93MOgPWldJL
         g+8xHU8+uJPT0+Iu0rcR6oVqvuJG1LzXDjdkyyx3D9sAYP4di3dqTi+hxup/Y/IvR5of
         tHGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=vwrRH2a8;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id ej25-20020a056402369900b0042dd1db7093si19320edb.5.2022.05.29.10.04.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 29 May 2022 10:04:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nvMKn-007myT-UG;
	Sun, 29 May 2022 19:04:10 +0200
Message-ID: <1a4e51a4d2ed51e7ae1ff55bd4da6a47fad7c0bf.camel@sipsolutions.net>
Subject: Re: [PATCH v2 2/2] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Dmitry Vyukov <dvyukov@google.com>,
 Brendan Higgins <brendanhiggins@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org,
 LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
 linux-mm@kvack.org
Date: Sun, 29 May 2022 19:04:08 +0200
In-Reply-To: <20220527185600.1236769-2-davidgow@google.com>
References: <20220527185600.1236769-1-davidgow@google.com>
	 <20220527185600.1236769-2-davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=vwrRH2a8;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2022-05-27 at 11:56 -0700, David Gow wrote:
> 
> The UML-specific KASAN initializer uses mmap to map the roughly 2.25TB

You say 2.25TB here, and
 
> +config KASAN_SHADOW_OFFSET
> +	hex
> +	depends on KASAN
> +	default 0x100000000000
> +	help
> +	  This is the offset at which the ~2.25TB of shadow memory is

here too, of course.

But I notice that I get ~16TB address space use when running,

> +/* used in kasan_mem_to_shadow to divide by 8 */
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +
> +#ifdef CONFIG_X86_64
> +#define KASAN_HOST_USER_SPACE_END_ADDR 0x00007fffffffffffUL
> +/* KASAN_SHADOW_SIZE is the size of total address space divided by 8 */
> +#define KASAN_SHADOW_SIZE ((KASAN_HOST_USER_SPACE_END_ADDR + 1) >> \
> +			KASAN_SHADOW_SCALE_SHIFT)

because this ends up being 0x100000000000, i.e. 16 TiB.

Is that intentional? Was something missed? Maybe
KASAN_HOST_USER_SPACE_END_ADDR was too big?

It doesn't really matter, but I guess then the documentation should be
updated.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1a4e51a4d2ed51e7ae1ff55bd4da6a47fad7c0bf.camel%40sipsolutions.net.
