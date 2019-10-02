Return-Path: <kasan-dev+bncBCXLBLOA7IGBBPU32HWAKGQE32HIBXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9732AC4822
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 09:11:58 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id y27sf3340103lfg.21
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 00:11:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570000318; cv=pass;
        d=google.com; s=arc-20160816;
        b=ozDJyFbSBgFzQc77Y2JneNC+K2k3manTaxSVT3k83tqo5DaB7DdHUD8S4fe5Ud+cxe
         StvnBoN4kxF8O+JR5iXzzZzCuPIQXT0DQf6tXlH6fGePmHAZ17qUA0zV3Vip9UhySLmJ
         ACoizWOc7vld2dOITb8gR5074yIW+KKppVhRXrHmWeIYHUgHaNa40aTheQw2N00J7NC1
         Lrp2sqTxAjrfya/L67jsq/qXRK13JxbgG/HmnD3lIFm7ensxJma2TqDGWL6Umf6FhjBO
         rbxxZ0DIC7mkaOTNakAH4l9neGc+1gGEZEulFnKzvjFqWzvGl5bi9WN3HDVFUvrJPBeC
         DeeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:user-agent:in-reply-to:references
         :subject:cc:to:from:message-id:date:sender:dkim-signature;
        bh=skyqhYPOyyzZ3+Z3FTqzP7HWZXrrobsxi/T7LiF4jBk=;
        b=iE5Duqg/KkhTdlcGBCkh8Ur0jGUc16z6PuywVcctqEeP+Iu1gByqYIB5srSmozugcB
         YsW3DN3i/XwhqsprlZ3WoKBVSxz50etXUuhTsFfU7Hcvp/aitYzJ/3tbP9JfmZWdSW1o
         6hnjw8CHqJ0JQiQBbKTqOIjQB5cE9fBJo1IhclHDWboFZHT8JNs7MQUo8hAUIvT49L8c
         H7frpbVFML33Ro/zDOz2QB5Z54fnx1/FEdOSpNi4BvbigQBCve6galuhxZ9cYN6UshQ7
         reFdPuaXI3x/1X6oGvAJJFch+LZhfQfdRQ7R2YHQ2mPQTxuzow0ZXIRMe2hDMDnw0PcO
         3dPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:from:to:cc:subject:references:in-reply-to
         :user-agent:mime-version:content-disposition
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=skyqhYPOyyzZ3+Z3FTqzP7HWZXrrobsxi/T7LiF4jBk=;
        b=TOgqE9NAKiduz6EubZNhUN54j9vIBgL9logGgM+XzNETRGrydkJOjcoaJ5+/XtqI15
         nvekM7cdJsjw5Z4cYQxRGcRr5Udvoosidx6QGVtbZHDVaClo06NfHez0OGpVOTJZwzEP
         yiOie5oe8GBVRqIR9/RDO4fDj4CZJSgiapcrcEse6cyWNNTvOEPUx5cdAk1O1GWY3W5Q
         F8vj4uc5HwM2GWtl8Ns39zhGQoW+8fXWPSccJHZPchn8rKP/4VwNJwGsbC9340+tW767
         B5EaVWFUN2nE/XXE8el5NFKJ0czMbRlKAyJyPs7wAQcDLPGTPolRsFglt133s6ZUyjnv
         j+dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:message-id:from:to:cc:subject
         :references:in-reply-to:user-agent:mime-version:content-disposition
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=skyqhYPOyyzZ3+Z3FTqzP7HWZXrrobsxi/T7LiF4jBk=;
        b=eVddR0mHCmsCwLcYUgIKl9Gsx3VLdzMf1+Rmg8LRUo7GUWHdP3OoadhZOIE0bxlaTy
         CFlUrpNxXnysxFYTonJe5quJW7NeeuPCpWJ84MTRsH1JY3m38dDGPM1kizuDJm3+AwTt
         1uO0s96spk9IA1x5dOIc/Auzpilp/UCP+jmRkdVRJPEq0Gb37+kj36PQ6ig8pDP0TFqF
         G/3uO8+ZEwejk6Tvh+0hLqygt4gbXXd23EjRV6FnuCtJ32WPPUvYujD4cK5gP+/cH73B
         mgKvqKgJEOveNxMV6Vx/bFP2SyyrE2UGisNV1KmOqbLuDNzCB6co8X5nNDG3SBQvm6ui
         bVug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWD59U9hpCIFLw8Lx14J9y5t3On32NCaPf+Atpy454+cLF1QL6Z
	+gXELWA+vt30hR/ekGdgENE=
X-Google-Smtp-Source: APXvYqwqQBOyBdc/W4Vhk/RY5Xg9FHeR2ZPoAfOGMVVRaS2LGfSKARoCRFZneUMHmkPC9/xDOI14Fg==
X-Received: by 2002:a19:7605:: with SMTP id c5mr1312883lff.114.1570000318131;
        Wed, 02 Oct 2019 00:11:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:f613:: with SMTP id x19ls124959lfe.16.gmail; Wed, 02 Oct
 2019 00:11:57 -0700 (PDT)
X-Received: by 2002:ac2:4853:: with SMTP id 19mr1212153lfy.69.1570000317599;
        Wed, 02 Oct 2019 00:11:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570000317; cv=none;
        d=google.com; s=arc-20160816;
        b=ONbgS+BTz/BciEWyaajujt6KuPep9oyt3TWLuQA7eXYH/cffcMmQuch4Fu7D/GfrT0
         y1vNZYmFghhVVQfuUDNPouGqS42k8ly4SW9kKTl9qLOIylYf7TQYuCKxJpJL/CqxMnHe
         fY8UApfBkCImfKpCQDkSiRpcQ5KejLZFQ/oSD1WHJowpWTV7yxsrniVy5n05HXYs33fB
         oR6eL4tdZIhceVbh6VrVJYoa1ZS9b+9d4XJJYRobHvRZBZuXUqIdbxkXIh7qY2G+VpSt
         YBPPeqzpU6gipIXK+wR/xdmnlvYyQSSE2BKSoIqhzYcRqn/7cPv5EutSYQwC+iP150q0
         fDUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version
         :user-agent:in-reply-to:references:subject:cc:to:from:message-id
         :date;
        bh=q9rTd0qOWH06W/SCA1xRriaNYvKE/pXFcO/Enm/G2CI=;
        b=Iwsg5HjSN3iq0/VIwIOQ1kHt/VEGdi/WYJsWeNO6jABZDZGo4fcy9T3InjMqVyNUZc
         qVpXbW3gqrMu8X8wxtItiul/WlF+j4tUL74drVjE2jbdn/VNdN4x0EsRoLx4NAfb7kBX
         nYVhRReGi/q+/FsFqoZ81hbnwpUAQAc2l+CgVHz3lM7jvluzw6VexP2RyoUlnF6Ug+EX
         fx65emL0jjG3YBWa022Pg0P+8H2eoQZHF7cZ66zTXDYpOfk3Qskr+tbLqIefFwaGR2ym
         Db/pAQlD31VsKvA/FEPW/XBzKCDz9h1ivdUIA2vFbUAwz+sqp8hYEQdKiflPpSRB4pot
         HzEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id c8si1292703lfm.4.2019.10.02.00.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Oct 2019 00:11:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 46jnPl5wHGz9v0tb;
	Wed,  2 Oct 2019 09:11:55 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id e2yIw6Fj-kKw; Wed,  2 Oct 2019 09:11:55 +0200 (CEST)
Received: from vm-hermes.si.c-s.fr (vm-hermes.si.c-s.fr [192.168.25.253])
	by pegase1.c-s.fr (Postfix) with ESMTP id 46jnPl56CTz9v0tZ;
	Wed,  2 Oct 2019 09:11:55 +0200 (CEST)
Received: by vm-hermes.si.c-s.fr (Postfix, from userid 33)
	id 348AA64F; Wed,  2 Oct 2019 09:13:04 +0200 (CEST)
Received: from 37.173.255.220 ([37.173.255.220]) by messagerie.si.c-s.fr
 (Horde Framework) with HTTP; Wed, 02 Oct 2019 09:13:04 +0200
Date: Wed, 02 Oct 2019 09:13:04 +0200
Message-ID: <20191002091304.Horde.44CFpqD3KN1HHZOT0U8wSQ7@messagerie.si.c-s.fr>
From: Christophe Leroy <christophe.leroy@c-s.fr>
To: Daniel Axtens <dja@axtens.net>
Cc: gor@linux.ibm.com, linuxppc-dev@lists.ozlabs.org, dvyukov@google.com,
 mark.rutland@arm.com, linux-kernel@vger.kernel.org, luto@kernel.org,
 glider@google.com, aryabinin@virtuozzo.com, x86@kernel.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, Uladzislau Rezki
 <urezki@gmail.com>
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real
 shadow memory
References: <20191001065834.8880-1-dja@axtens.net>
 <20191001065834.8880-2-dja@axtens.net> <20191001101707.GA21929@pc636>
 <87zhik2b5x.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <87zhik2b5x.fsf@dja-thinkpad.axtens.net>
User-Agent: Internet Messaging Program (IMP) H5 (6.2.3)
Content-Type: text/plain; charset="UTF-8"; format=flowed; DelSp=Yes
MIME-Version: 1.0
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
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

Daniel Axtens <dja@axtens.net> a =C3=A9crit=C2=A0:

> Hi,
>
>>>  	/*
>>>  	 * Find a place in the tree where VA potentially will be
>>>  	 * inserted, unless it is merged with its sibling/siblings.
>>> @@ -741,6 +752,10 @@ merge_or_add_vmap_area(struct vmap_area *va,
>>>  		if (sibling->va_end =3D=3D va->va_start) {
>>>  			sibling->va_end =3D va->va_end;
>>>
>>> +			kasan_release_vmalloc(orig_start, orig_end,
>>> +					      sibling->va_start,
>>> +					      sibling->va_end);
>>> +
>> The same.
>
> The call to kasan_release_vmalloc() is a static inline no-op if
> CONFIG_KASAN_VMALLOC is not defined, which I thought was the preferred
> way to do things rather than sprinkling the code with ifdefs?
>
> The complier should be smart enough to eliminate all the
> orig_state/orig_end stuff at compile time because it can see that it's
> not used, so there's no cost in the binary.
>


Daniel,

You are entirely right in your way to do i, that's fully in line with =20
Linux kernel codying style =20
https://www.kernel.org/doc/html/latest/process/coding-style.html#conditiona=
l-compilation

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191002091304.Horde.44CFpqD3KN1HHZOT0U8wSQ7%40messagerie.si.c-s.=
fr.
