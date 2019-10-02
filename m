Return-Path: <kasan-dev+bncBDK7LR5URMGRB3U52LWAKGQE6C2Z5MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 70EE0C8790
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 13:50:06 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id y12sf4754087ljc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 04:50:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570017006; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q9OupeI0QBqX7MubXXvthxxRWNX5qAq7Owd0lw5q+5iLX42LdYgL6P757RaD/zk8pa
         NvaaJ/Fgh11kAfi+gRWf+Pm1yjszcRThLLyHw94+xJSjHgG6gNAu+XfYU/C1SL9bRK3e
         U/L/BQDa46js8XqaudwZr4aALql0b9q51kCFpp15wx7uvdf4sincOWQ0bN9K8Kcq2BBw
         ++rFVoM518xRvdBr5nBokW8KQk8L2Vx6o23H0nimeSA72f5DKFUtkuJ8buVIPqpqTob6
         zKCEr7yabxEhoVZexeXU5aDS8S0gvxa0AwmUAKgDoy5JMvFGIKHyQvvC37wWIqMAIwUI
         b0Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=uxyzCZPUhJa/4mhTzk4rDanMu0L513cwd/4cuQJKyRY=;
        b=BcmUlg79s4WJAgd5gtVGlY/ovuNlB3XQL9/QgfDKf4d8KodZSnhgUjL0m+JALzaI6d
         qvXRHEItwhTKintyVQPUPnXAmubrdXdZ4Wg6tZ+DddFfo43JworSu7aYD2jFnzxt5XXW
         0g5d9wWHbGnLJ9StQS+Whn14s1ncljH7s1rsqsW5kJ9RjSqX7acsSCsmPxkgmUL6KxTL
         sax0yiinF90ERxF7Marj8GQmkK9InNX7ASLKO8dfO+TYlkua3Bd+Ls19pOsGBoRDwuWD
         fJ/B+eVolm2/FPCswC9S/0KRGHn10A1Q3gXsk+cMmk/EeRBRY1qFA6b7R8v/xF+wC1RN
         wdYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NKTwvoIx;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uxyzCZPUhJa/4mhTzk4rDanMu0L513cwd/4cuQJKyRY=;
        b=TXp8zsXnbMFyF0gnjbmujjPf4qis2oJmfw8MWWmVt9R6s9FJwGLAXc5ac8eMjZN9/j
         GYCDXVUKIFURjdiZWpxuk1LaUhDKKsosbmnSm2uK3o4gJzI1S9Q1Kjt/zGmWT1QZNM+s
         YFFCBcftU7FKdf7GaFOhCGJ3dKi+G7v1siGrS/KCUJ1gB23xbhBIBTXEq37gdDuvQ3lX
         gROS9jigwqAHWhS18Fg20swHUoy2Vjwp1sE14XkRFDDogA+GxPAqh8a/hqy5bb40miz8
         IkV/uYxIF0OlEqj9rIi5qimgijVC9rWJky9BlOVnRBDkjDn5cNWqz8ymG4gYdTY9VSmz
         +yzg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uxyzCZPUhJa/4mhTzk4rDanMu0L513cwd/4cuQJKyRY=;
        b=NwcZxDQ6kRDz71AvgyajErSLbFNOatPJ0FDsFv1/nckTxJTRUCXDByzDQoQxzQOjB6
         Ty8ioGI6WdniBeckRJOA45UDld6wfj/z+BmTCkZ4WNtg6RH7aFu2ZQBFJp1bxH+JdfLg
         CJDMdtpBktEunWYlGBrMRSCYsAkSw2uzxJBdyw/2mhlKoqLGFpp1g0M1wKDbGyaNcNKh
         QQ44oj09TQ62TA6MdJ1rAVgrNqebbdkr0/G5oEANQ2MZsDpk9Dc4wf48HM2KCn00MMID
         v34svu3jeFLOWCly1x7NF7KA/VUAWM9/qLyLbdeM4E6vMApbVgxpoiAWgmMS6j2oX+ot
         Rl+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uxyzCZPUhJa/4mhTzk4rDanMu0L513cwd/4cuQJKyRY=;
        b=Ytczv3JdYWSfMTx2RhFQSQCFMbLxwJJIs5uQ7yRY2jRClrZhepEBEMAfsYf3tGAIbt
         gSDdn+R86Xq3Kn7GkA1jIzSl499yAg5WhFTrSj5XhD7oeurC39oCiXWP54stdkUIWRff
         BjC/JWNGAJD2QB7oPP4pujF2BePgaVLTKppKEFnSv7l1M0jpe7YThHUAE9TxPTF/40l6
         24us90PUSm7OVMTv5VN4VtxSrMmnzmnbWx90koMkJBvOUbFei4kOlA46zkx3gvUW4ix4
         kyNK6HhSDL63ByqKonmANLwfJcd776ga7UHZoVBrWVfUeAZdfDQybDc+dmUAYSuCvbKO
         V5MA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVWRLnkviVt0KrLH6Bp0FskIjOcL4DuWJ4V2g6MFo/BK5/p0Je/
	r+2xYfdrsxipk03cU+yS1Z4=
X-Google-Smtp-Source: APXvYqzWFAlpD08N8jfKGKO/uhjPQJXab6iZEspsZmYh6eVeAL9gYDw8c13Fs4z9iy5qXC3+O+lCig==
X-Received: by 2002:a2e:5d17:: with SMTP id r23mr2188153ljb.229.1570017006070;
        Wed, 02 Oct 2019 04:50:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3101:: with SMTP id x1ls268402ljx.1.gmail; Wed, 02 Oct
 2019 04:50:05 -0700 (PDT)
X-Received: by 2002:a2e:9a83:: with SMTP id p3mr2266535lji.136.1570017005584;
        Wed, 02 Oct 2019 04:50:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570017005; cv=none;
        d=google.com; s=arc-20160816;
        b=MUxjjNaMq+HirqvmL5tYjl0voT09APb3EbfIkbBIFxOjb+KIvhZsAb6rOYh3y9TaRP
         3UBkzH16OdBK2JHmtP2l5XdrIk4e+WmVg/E1R+GEoAzKHHsPfxYZ1gKm93YhhUiKKg4G
         VfluT+nDTzEFTYu59G0U4BikyGcBJyUNhGJ17UMqedulopUytDsMrFxd0Q3xAiifMqKe
         WA3Eg2gMYFMFX+TLfFZEAP6LKI+uKEY7j+ANVhG1RNZWyYOpLy/1G/8pnN/g62fudgJm
         NKDCLDcsVQxeXT4LYTqJY4I70bhg/7XnW/xodzgP5fEYhgleA9hs/Ij9Si+vZrpI3jww
         /MrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=ERYCwhz2Jv8a2PVju4gxqh772VeR3/dOesngu7HPYnA=;
        b=ClbEQ9kPEfr7DkLofUpEA7hI27GD73PnNymmMhNJydDmRpoqUnmilfxS4rCNfZvmIY
         HPRs7diuJkyudTFgE/Pa9OV8rXUCdUWwjPnLvGd8U/ly4rwlZg0AmX+c45n0qSK/tYYV
         bXuxeIM54kpSa1er85QEGAsICLtjqHh5fJjbxl8Oh9g7b7WJpmQGSjZzS7aE3sYeZirh
         xUYaYUf5LJYQpySxzhDSwqIJ48IpjLdq2owZma1Pp4nuGKir0rfvnbMBg8fkL06Lq7sS
         9/V0n00f1O4Ar/uGp4QQYKzVpOxIDcG282HSH8W7gh1kSJh4wG31Vc6aXgqFGzzNL10I
         1rqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NKTwvoIx;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id u24si989836lfg.2.2019.10.02.04.50.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2019 04:50:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id r22so12530230lfm.1
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 04:50:05 -0700 (PDT)
X-Received: by 2002:a19:8c14:: with SMTP id o20mr2075568lfd.158.1570017005189;
        Wed, 02 Oct 2019 04:50:05 -0700 (PDT)
Received: from pc636 ([37.139.158.167])
        by smtp.gmail.com with ESMTPSA id x76sm6142064ljb.81.2019.10.02.04.50.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Oct 2019 04:50:04 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 2 Oct 2019 13:49:52 +0200
To: Daniel Axtens <dja@axtens.net>
Cc: Uladzislau Rezki <urezki@gmail.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com,
	glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
	mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr,
	linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
Message-ID: <20191002114952.GA30483@pc636>
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net>
 <20191001101707.GA21929@pc636>
 <87zhik2b5x.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87zhik2b5x.fsf@dja-thinkpad.axtens.net>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=NKTwvoIx;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Oct 02, 2019 at 11:23:06AM +1000, Daniel Axtens wrote:
> Hi,
> 
> >>  	/*
> >>  	 * Find a place in the tree where VA potentially will be
> >>  	 * inserted, unless it is merged with its sibling/siblings.
> >> @@ -741,6 +752,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
> >>  		if (sibling->va_end == va->va_start) {
> >>  			sibling->va_end = va->va_end;
> >>  
> >> +			kasan_release_vmalloc(orig_start, orig_end,
> >> +					      sibling->va_start,
> >> +					      sibling->va_end);
> >> +
> > The same.
> 
> The call to kasan_release_vmalloc() is a static inline no-op if
> CONFIG_KASAN_VMALLOC is not defined, which I thought was the preferred
> way to do things rather than sprinkling the code with ifdefs?
> 
I agree that is totally correct.

> The complier should be smart enough to eliminate all the
> orig_state/orig_end stuff at compile time because it can see that it's
> not used, so there's no cost in the binary.
> 
It should. I was more thinking about if those two variables can be
considered as unused, resulting in compile warning like "set but not used".
But that is theory and in case of having any warning the test robot will
notify anyway about that.

So, i am totally fine with that if compiler does not complain. If so,
please ignore my comments :)

--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191002114952.GA30483%40pc636.
