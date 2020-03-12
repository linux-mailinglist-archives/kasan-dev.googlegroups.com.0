Return-Path: <kasan-dev+bncBDGPTM5BQUDRBOMFU7ZQKGQEBLWEVCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 95B9B182801
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Mar 2020 06:03:54 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id v14sf3107442qkj.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 22:03:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583989433; cv=pass;
        d=google.com; s=arc-20160816;
        b=J3p7hW2yHAVgn2Ii/DKSdO595XNSBdizy7M0o9TswuJmoo0w+2I7nTm7EiCdAxx/vb
         KtSQu9b3/8rl8LNX8HJBLQ37KH7jKDdvo6wQnxej1nhWTWeZTUacd0GUWN+z3B34PMiA
         X1CzmWWitaVF8wSHYNYISKXjHN3jXHguTP4OUSoHEh4xvrM3lYHpVb8p5+PnJAEoNbqo
         h7YTOtAlqItEGcqLZE71hpg0cKBvuz3HeHd9qhHIdZn6vAxak3Qbc+TzmrNvYJ9QUl15
         Bkr1OIIDEKe/CY46dEMoZQE0bkhWRhaBDO3FFZMcmTpXjsModAFwf6DuKpFiGFhSZb3M
         u8zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=prNWXd1TNcx/x8vJsEuMtmUJdZ6pe3tW288Sgk6WnAY=;
        b=shTMXXTUpiQOjcM0uoh8brClf81brFYFuQ4FsUX581cD5kUSV5TE9fOtAEQmu8iU/C
         5alnhvJMjW+o3qEnW+cgtYrENWbLW7B3sh+RQDN+EQ3KpH4A91OjblJvML9oZxN21evJ
         04d3t547akUDnNurxlmCcPh1d4BsVnjEqC9YK7I/QQtohz0TN8F0V6FRxlnaAey9BQRL
         REgmGuvXIWwKEuI58YPB4RD0bMHq9ZdViSnrKXFbKvteEn32mC30NovP/QH9yWIPaRze
         fEnXDPBGwl91AvCY8MbkrO33IkiSf4iNjodH+gfv6h0mcPI5HeoG55SV3LQPq46hB8M2
         1eiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=WXCgrUwv;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=prNWXd1TNcx/x8vJsEuMtmUJdZ6pe3tW288Sgk6WnAY=;
        b=TY3BvSCFPZBxeqWQ3AFJ0u8eRlSjN9XQxGLTvKM8e5UqMqApz1be0ynSronV/ycq9i
         1837Q2CK8XTLJQOLeWd5NedTiFQ7aszqnNhuButYq0ClKyrSWOYNlyxael2/hLGEonH3
         /WfBm7EXo0IQQLYzvGKdF25aiXzp3Xwun6jBQ82AxiFatzKpPLjyVpKnUBZSut88camL
         8rGPyIr5zZjLKfO7lB3ih1z6l5gIQdKQeiNx69KdM1o13X4gMYHTVDSFVwoqrjGnf7F+
         0Y8Q5gbxLwOhP0Afy13588GBefEKSaFh4H9MEUxEbwwzUtQzZQ5nMqrpD1AjZSdrGLMH
         ZrXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=prNWXd1TNcx/x8vJsEuMtmUJdZ6pe3tW288Sgk6WnAY=;
        b=Jh9894JJUmrIfDoH/nBPyq7ZAvWYnoKWr9zyNqH2cqHO6O3pzZZQV4Xe/JlFZZXMlk
         45jTz1T7lAU3O8BCnP3tO+OP4/lTXw/L7M/WkRKAAWIYgCfReYdXgKVfi9F65tu0TnJG
         8GdhvYXZvbnB1Oavtfv4GnKpIPcS/1ttFesBJCEUHR7bSzWM3RQhs98G+1S6AEcWSNBB
         dSJAPnlfU6dQB869r4yxhEOz5ixc+crTAUU1AMAmKLmv3X6wFBP+zL2btM91dIqsH+Q8
         /cEuif3XZ+g1SK5PzYxRLwXXWYidZpo+ggoxp3zowt/jiPCDBli7ese8IGYleVgLdDpu
         J+bQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1Sn4aPAswyn6hzLkoe/6LSnU/HyMIxdWXfiib+GrXc1YRcnSix
	mG4eho2emy+NGPWVXGuI9K4=
X-Google-Smtp-Source: ADFU+vsLYTzlCXPDBOa48aMe9TKhSwHwB0zp45OWOJuAais5Mt+JwylneE5lP7zSplHoBF/qYYkVpg==
X-Received: by 2002:ac8:44bb:: with SMTP id a27mr5653108qto.160.1583989433495;
        Wed, 11 Mar 2020 22:03:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:104f:: with SMTP id l15ls10510qvr.11.gmail; Wed, 11
 Mar 2020 22:03:53 -0700 (PDT)
X-Received: by 2002:a05:6214:186f:: with SMTP id eh15mr5564943qvb.249.1583989433156;
        Wed, 11 Mar 2020 22:03:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583989433; cv=none;
        d=google.com; s=arc-20160816;
        b=XFeIHJfeWDZVwh2EPqhs9hslonFe2fu6Dr7rjQgkTz7edJe4UtnGFm82W0N/N4EFb8
         GDVhFRDslHX7YWZV6d29omB8oWXD1pvQZ88hRXOxEnPQNT7uayVHRyo4fL1wOHJD5E1M
         kPGYEQhlUQMrVDML366VXDikWz6oZnjt3HqcE5lpGSfrdB58HnXTxIp4gA+sh876YVXc
         Hzz38RQx8yCiHCm0SXKE3pzRZ9Zo1H1XABqUsK3VCn7gH9Ws+2Cq6MZMETwNn4HzbiAs
         TQkjc+uEnP4xoY23oN8ksiDHsxk+ALq54DnEtzpOzuClx1BR3WuBwqlQe0wPJ1WlJ9AC
         /LrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=EiH9wliZJ7SlCOgjGr1o9krpwAx0Yhk57Jmk6JMcvtA=;
        b=GtWQTdqDA+LWhitU/QFd0RI9zrpeWKdrh0MzgHqu32FJK1PUtFjQoEyP1Hc0ih7Ifi
         uap1gENt9O79i0gs9zj8mGWE8Fzt793qSgOili1vcz2fsAWzXtqEg6vTWlEDW/KOxkF4
         p3NbTBc4JZdBkOVkZjWJFfPNFcdNyci4ydyoKjZ1oYCgQeslXpj3fM7H73p2QdAtQNXE
         GFthN5msZQAO8Oq8o0sDMLoQqsCHKPGvTgGvhHTByVSfaT6Po1/hyjld0h27YQP8Leiv
         Zck2mlJdotmhRvKe6WmxXBXbGlK73QKHgAM6mHc/G+qj+7rYNihg5rlzrqEZi6LcaWjM
         jPeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=WXCgrUwv;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id n138si169488qkn.5.2020.03.11.22.03.52
        for <kasan-dev@googlegroups.com>;
        Wed, 11 Mar 2020 22:03:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 478dd462c20f46619b06cde0ca3267d9-20200312
X-UUID: 478dd462c20f46619b06cde0ca3267d9-20200312
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1488432028; Thu, 12 Mar 2020 13:03:47 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 12 Mar 2020 13:02:47 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 12 Mar 2020 13:02:55 +0800
Message-ID: <1583989425.17522.29.camel@mtksdccf07>
Subject: Re: [PATCH -next] kasan: fix -Wstringop-overflow warning
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai
	<cai@lca.pw>, Stephen Rothwell <sfr@canb.auug.org.au>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Thu, 12 Mar 2020 13:03:45 +0800
In-Reply-To: <20200311163800.a264d4ec8f26cca7bb5046fb@linux-foundation.org>
References: <20200311134244.13016-1-walter-zh.wu@mediatek.com>
	 <20200311163800.a264d4ec8f26cca7bb5046fb@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=WXCgrUwv;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Wed, 2020-03-11 at 16:38 -0700, Andrew Morton wrote:
> On Wed, 11 Mar 2020 21:42:44 +0800 Walter Wu <walter-zh.wu@mediatek.com> wrote:
> 
> > Compiling with gcc-9.2.1 points out below warnings.
> > 
> > In function 'memmove',
> >     inlined from 'kmalloc_memmove_invalid_size' at lib/test_kasan.c:301:2:
> > include/linux/string.h:441:9: warning: '__builtin_memmove' specified
> > bound 18446744073709551614 exceeds maximum object size
> > 9223372036854775807 [-Wstringop-overflow=]
> > 
> > Why generate this warnings?
> > Because our test function deliberately pass a negative number in memmove(),
> > so we need to make it "volatile" so that compiler doesn't see it.
> > 
> > ...
> >
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -289,6 +289,7 @@ static noinline void __init kmalloc_memmove_invalid_size(void)
> >  {
> >  	char *ptr;
> >  	size_t size = 64;
> > +	volatile size_t invalid_size = -2;
> >  
> >  	pr_info("invalid size in memmove\n");
> >  	ptr = kmalloc(size, GFP_KERNEL);
> > @@ -298,7 +299,7 @@ static noinline void __init kmalloc_memmove_invalid_size(void)
> >  	}
> >  
> >  	memset((char *)ptr, 0, 64);
> > -	memmove((char *)ptr, (char *)ptr + 4, -2);
> > +	memmove((char *)ptr, (char *)ptr + 4, invalid_size);
> >  	kfree(ptr);
> >  }
> 
> Huh.  Why does this trick suppress the warning?
> 
We read below the document, so we try to verify whether it is work for
another checking. After we changed the code, It is ok.

https://gcc.gnu.org/onlinedocs/gcc-9.2.0/gcc/Warning-Options.html#Warning-Options
"They do not occur for variables or elements declared volatile. Because
these warnings depend on optimization, the exact variables or elements
for which there are warnings depends on the precise optimization options
and version of GCC used."

> Do we have any guarantee that this it will contiue to work in future
> gcc's?
> 
Sorry, I am not compiler expert, so I can't guarantee gcc will not
modify the rule, but at least it is work before gcc-9.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1583989425.17522.29.camel%40mtksdccf07.
