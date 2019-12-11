Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBI6EYTXQKGQEGBSPRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id AD1EF11B998
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 18:06:43 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id f15sf10759151wrr.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 09:06:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576084003; cv=pass;
        d=google.com; s=arc-20160816;
        b=poj4KC6y8/xaAMyaOZpcwofWIj1DPuvJjCJ6f0PVq1HOdxOC5cRifgeBK9RtMp7Ubf
         h3a+hsXsr7kYZPH9b2Ncv1t8CibcZDBJGy6G8tO3tRXPzgmdxUcl1cfPMvGQ0BNFGnbh
         PBLFi176sOfgQqHOF/n7NBoW2e1DEKQlCdroUfu1wbip3v0qF7ZH/iU+Z3mM59L83qzE
         cl3Er9wDPMATESlF19MsMF24E54w8C1tE53V3MxLVUH1VCUtWSabZkITv2RArYeLzBE8
         P/U7JllMPLh0qsPmDtjQDzuhBZk+k/V2xkPrk2n0TdwIgwf114QdwcTPNeyEVOP0r7t/
         P9Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=oVmnIlEKMmHhzcdGdALweR2svZ8C7iJnmbhAzgJyF5s=;
        b=UBJQcUND0MpicgNjpjbfSLUUNZz8IfgPFDX3TsCnZl375L33SFwfQHqgLJsNSA7fYh
         u/m04PxUE5Pj8AsSwPLi+uqPpi9mld+tBiLKg3gssfoqPLGuj9asThc/Q/GnnJ0Lu6VD
         wjUcS4NI215gmT0ZDKG0VAlsFHnzmOtEez76x1XeSE2bAs3Pmg7fjt6lwLflJtA8iTho
         od925GaysLQs7IS4INE7xNloJ7n6nFtGPN76uHbZaVICVgn42EcoDPKlQYqcHT0Fe7Dm
         bRvCqRQvw8H1Oaa4+hCw8OUkk9hqePcl51P6PpXI4i/OmL52m66/biax99g5/OLbQQO6
         j61g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=reW1jpsj;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oVmnIlEKMmHhzcdGdALweR2svZ8C7iJnmbhAzgJyF5s=;
        b=KhSk7r9YDLUOTVzXJPESDD8oBxuezBFZf/3u6eY8UtlbagHvlJzXGI4dYYq6f6e3ga
         B1h9YS5x6zR7x9ncn+QJN6aEo/tIX2s+edM0GhFH07vi/XRXE71ElmluZoDcLaDIZu+3
         4WI//Qd08rUtf3XL1SHMfMAihDVsyISeLwAEJ0oq8DIVRXOGvBRX2eKShGrP9ddtnk8i
         ToutQeUND6ffVepBfAnPK+MFuAIRl2HlzaFe/9i7Cez+wy8/WA6cC/sewCJoBSkeqXWx
         uXDHXseNOuIJpD0PbIIUbmzGJH55+6nX0/qQIpW8Jkk8VEsR0oinkMfSrnUQ+BJ2LNaW
         d1pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oVmnIlEKMmHhzcdGdALweR2svZ8C7iJnmbhAzgJyF5s=;
        b=RZAHt1K+a+AS0T/tiNRPRkmuctEkdqP4QFGbntnRks286TTg7oOyoqSXUbQxo5ylg3
         mq5AnOoAKtNEYtPCW/qNA2KRzK0/8EDu9PBdxmETzYK1T7YvTrfBtwL0P9+pZH7Gb9OU
         5oU7Oc+S4ZGhN4UKAQ8QF3EsIW6d6EVSYv6QSPZ4rIKmoFMLc82sYnSrJT1tB+OMkREA
         x/6MlvcuaT91iYVZHJmjszlAr6w6dZRhhvyomtJJJZtfx0qWdeJsk1D9ei0hMUPT9t/4
         nFZawpk8/4Eri61v+PVi5bCqm6HmdQHML0ZknVLxRXdCQ9nYtH88T9K35TjYILytVlfJ
         fcag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXmgAnfy11kqAe3Xc9kvRVeKVNTZK2yfqU5Tz0VCKUjfZ2CEoV9
	lbHXxD4QRpR+hDxBWlOgh/8=
X-Google-Smtp-Source: APXvYqx/M/vbkbCtYeNSggc4unC/9FbEfdypXHYwqU+qNDWr03BetYGhA36efwFwbl1ykOMRqfpGhQ==
X-Received: by 2002:a1c:f316:: with SMTP id q22mr911840wmq.103.1576084003347;
        Wed, 11 Dec 2019 09:06:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7409:: with SMTP id p9ls1683009wmc.4.gmail; Wed, 11 Dec
 2019 09:06:42 -0800 (PST)
X-Received: by 2002:a1c:a5c2:: with SMTP id o185mr901070wme.175.1576084002869;
        Wed, 11 Dec 2019 09:06:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576084002; cv=none;
        d=google.com; s=arc-20160816;
        b=oLUIlDHbZs+i2tb738lzCgMXQHQG3KSx9DO8m/MgbtmL5zMu6XA+G3YIh0pk6tmW22
         d7BrjkK75KJfXOTEWjgSP7axdkHHm9iqg5NINAmnkez/xWlbdA6CwF+++CbA7XcAmtmw
         vTjTboyOBxJF/H6YxWGd/2J8uizW5on3jg3saFAero6L4N88ZUWBMWcvnOt53IQxqdNA
         dklTgCfxhHzPJyoImGi6TP4cIoAwQCx9ESx+/ing96ZEgWmss9VosS1a9IXmlhb4O/DV
         L5uxbsM55po6F0tVYcv+JQ7Zx0vararvxybKfAiFFstXRrb0kx80+6F+snokjfbgjJi5
         z0HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EJEZLGG0R25FiEGZ36o3yiaHw5c4zLdXmBC4Wq4ADFM=;
        b=0WHNwxsWWOF2M3yyUwGaZS5DKUrZ3INz3P+43tjGbW3I5sAenPv7BdlKwhmIHRIPS+
         bmrUyHcOYvkIz9qCmdA5ZBXni6Uc4Kt9Vq6Ln+sUf0IPMjz1BC35u3w9teQg91Cy3UsA
         adPTZeNTr41A82xncBkRieJo4/xtnbW/j8tf7FeiSllPkO63lurtZGOwBsHELA3vXybE
         DBCVg7vgs5jwbOTenWNrr1iAIZIpsdQojJVSTiMm0Ng/lf4zqh0FUP+H1/t6Tl06OTpH
         GQ55SZcIicB6If07uxCNorle0xDefhAbp3dJYcon+eOSbQII9NjfTCyEOOHDNk0lmrBP
         S9Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=reW1jpsj;
       spf=pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [5.9.137.197])
        by gmr-mx.google.com with ESMTPS id y185si69539wmg.0.2019.12.11.09.06.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Dec 2019 09:06:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted sender) client-ip=5.9.137.197;
Received: from zn.tnic (p200300EC2F094900329C23FFFEA6A903.dip0.t-ipconnect.de [IPv6:2003:ec:2f09:4900:329c:23ff:fea6:a903])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 022811EC0CEB;
	Wed, 11 Dec 2019 18:06:40 +0100 (CET)
Date: Wed, 11 Dec 2019 18:06:32 +0100
From: Borislav Petkov <bp@alien8.de>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v6 2/4] x86/traps: Print address on #GP
Message-ID: <20191211170632.GD14821@zn.tnic>
References: <20191209143120.60100-1-jannh@google.com>
 <20191209143120.60100-2-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191209143120.60100-2-jannh@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Spam: Yes
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=reW1jpsj;       spf=pass
 (google.com: domain of bp@alien8.de designates 5.9.137.197 as permitted
 sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=alien8.de
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

On Mon, Dec 09, 2019 at 03:31:18PM +0100, Jann Horn wrote:
>     I have already sent a patch to syzkaller that relaxes their parsing of GPF
>     messages (https://github.com/google/syzkaller/commit/432c7650) such that
>     changes like the one in this patch don't break it.
>     That patch has already made its way into syzbot's syzkaller instances
>     according to <https://syzkaller.appspot.com/upstream>.

Ok, cool.

I still think we should do the oops number marking, though, as it has
more benefits than just syzkaller scanning for it. The first oops has always
been of crucial importance so having the number in there:

[    2.542218] [1] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP
	 	^

would make eyeballing oopses even easier. Basically the same reason why
you're doing this enhancement. :)

So let me know if you don't have time to do it or you don't care about
it etc, and I'll have a look. Independent of those patches, of course -
those look good so far.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191211170632.GD14821%40zn.tnic.
