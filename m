Return-Path: <kasan-dev+bncBDY3NC743AGBBR5KUT3QKGQEAYAYAKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 23B481FBE78
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 20:54:01 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id k16sf14966343pgg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 11:54:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592333640; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ct+JaA9lT+2lwjwRCFASbQK9nLHvzevikjnXdczp9mlZrQt/a0wYmpai8HSZxHsvd8
         jRV1k5vukHMTft5CtFsrCSLGVJVn99IE+b6tH1yoKw+NntKr2jmNEN6S7Hto6e4SXGIV
         FHCPJ146jZbYLnY34q4TjTusvDHsIX3G/Katfgb8uGm7KZF2tesxp0FZIWfEsxGXJK9N
         5FtCPXyGC+JAou4ZZy93g8P8lA4uWvhlJNibaIMsr4tOfS+xzCBJlLfHIbdaruBg556T
         xFKYbPQ65zSkN4aPxTImRZ1OP+L+rFy5b1iZN96nyzoRQmOYIo6hLQrKi3GvioALI+7p
         eSjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=HoJXyI9PYWfft2ZX0SjrE269+IS8RckYsXtc2Z25ddU=;
        b=hExntfJs3GX2RMLjwzUk0tmvW+jK4bSPhSVvTmEzITftAKCA6RWjYtwApCFdRRuFzy
         8iavq9zPRzfjpIne4Oq5ZW+42H8EJFJ8sVvNDD9xIw/ly+IGdPyyFGbn0brKn5xcYHA4
         2YbleeAfRW01p/TZlFMez1NqIXAGNTaWISdXGhMfMaA4EMFIqu6iMACYX4coVIRxZfOk
         sdTdAJFKC7LSwmS5x1HDvE3MEhSwWpW4cLix/ipUEPgONOzGwy44Ck69dbrjjFX9mZNa
         gTuUno+2MjXfiYWas4ALwwzneCA9rHycepllbH0RhOea/VnS1e6lja/BeeiFkIIn69Y+
         tkBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.204 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HoJXyI9PYWfft2ZX0SjrE269+IS8RckYsXtc2Z25ddU=;
        b=CrGR9nt51wTQP0t5QCTeowoQRnspb8SjNcbHvM708t9MFN5TQV5zQQJczBlda21K/q
         9uK4hRB4VZ+4X42gASFZ4EUE5DoU4hg5N6pgIYJrc1QV0hZBy+1MET8IiLxD/EpIz9zy
         lNKjmS4d9pSzzfjOT98KERSwsorXQhJru8Q0Y246Vv6daT7nFarMJv4rl0zlpKPBIn5t
         J2hLr7TyrF/HsWQwR9Y6CpOzEW2lIT4w7epU0LatijaEJzAePqEx9l7kOMGW03jMCAvi
         qszRS+B/GAk3meOxY8x7ZYht8spbo3XWiXCaPxobUvidWx9ydRr3EyeAxe5jSmWB/2In
         basg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HoJXyI9PYWfft2ZX0SjrE269+IS8RckYsXtc2Z25ddU=;
        b=VFqB4zamoMDhzISxEWMKOx2liVQzfZXUXh3+93QfWcgYAsrMG8i2sORrgVknWOJbiz
         CHruGME61VdfjkgboKDGTlOZ4T24lNKZFIJfuuKg0wH0SYtgbu236qbJPn2dw9rgrT4k
         8qUTFZ1Dzt2a99b7afTRE9IaNWKo4XCXTy7BaDn+H/zNwEQs9Wld7fPk4ZeyBq5tdaNW
         Ai1VCcUWb18vAzvAobH2q3MnNOZ+rS6IpCla7FmeBc422Hxt4MZiz5oSHP9bONnP3KZs
         2rWOTaSMcve8I6OlJzwVmrrEKEQSm8BvAS9VSVPQTlRSJjpjWpcQOeOzmYoHlTapDw28
         fvXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/AHCPuS1bo7P1t0DT6IH7u2moxmahn2k5hUTV0tc6UM0DbjZ1
	x5WC5UsjCxyqKTs+MNLsfk8=
X-Google-Smtp-Source: ABdhPJxgi0dpHng0Jqc7Ecu3h1d1FgMG2LykJsRQfBvek+Vq9icGeP8t57HSACFyQgkZ4+W2roxGkA==
X-Received: by 2002:a17:90a:250b:: with SMTP id j11mr4566716pje.194.1592333639807;
        Tue, 16 Jun 2020 11:53:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e28d:: with SMTP id d13ls242149pjz.3.gmail; Tue, 16
 Jun 2020 11:53:59 -0700 (PDT)
X-Received: by 2002:a17:90a:9d8b:: with SMTP id k11mr4509129pjp.10.1592333639233;
        Tue, 16 Jun 2020 11:53:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592333639; cv=none;
        d=google.com; s=arc-20160816;
        b=ifkEGJN/I+EPz6M9Zi12p5rmKewCA8pCpUt5qqKELRI8004c7lWsFJ6zo5vFgQlahj
         F9lFYE6g6Acc3k/DqC8vqJsqVaCMO4PMFvrpy7E1V2lT5gjT3ozLUCJEZRGMZgziMqi2
         qDgWF9rAzJxFAd0Dorhp5j3zw6oE0R5PdBpOo4XkrXckcRJDC4FAaLkCSoIpp8HvklBH
         mpUSqYSSOJGHCVfv6JeoC1uRKzV6T0t804yszNuXWCqKU2KIG7/WazKU6Z7yo3EjneVf
         Y+F5FBDTthQW53DLXgPqQyOIHMdMDH1o6FUXq+f9YNdoBfYQPRw22CKXYrUMgzbQwhnX
         Ku9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=gUCYLrg3WYifyrKyhHwoSpquLHjmg6Wambj9qBiH15o=;
        b=TMOkMoX/dIzBdUEKWquHTepjPtmoS1FOMuTqxUu05LNjkfTkAIn44zcblmw1yXF7VN
         PKQnDpTB0/G27CvAerqagNCW5Y0efhLjYtfP2+yWSLAbT15eON8rTE8YEa5Qt0S6nSO7
         DM/+3iyffnvJ+lca9Qmc+Mm6OLkyQSmKEfaiuxVy7FU71OUEuyilY6HHGR6IyvZLIliz
         8ryXxW5G+5T2an5OcKLzcYus9NFK+r9cc+7yLxqU/1jmYKsgz9Xr3ta2pOzFgUievdYK
         5BbvJtmdN+iKX8eLmi8t24NusuLOzzkLnOqonMZyPKrJN+NqOTik7DpyV7tkZOiofSHD
         bMXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.204 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0204.hostedemail.com. [216.40.44.204])
        by gmr-mx.google.com with ESMTPS id t72si1248839pfc.5.2020.06.16.11.53.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Jun 2020 11:53:59 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.204 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.204;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay01.hostedemail.com (Postfix) with ESMTP id 1290410050792;
	Tue, 16 Jun 2020 18:53:58 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 50,0,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:599:800:965:966:967:968:973:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1541:1593:1594:1711:1730:1747:1777:1792:2194:2196:2198:2199:2200:2201:2393:2525:2560:2563:2682:2685:2693:2740:2828:2859:2933:2937:2939:2942:2945:2947:2951:2954:3022:3138:3139:3140:3141:3142:3352:3622:3743:3865:3866:3867:3868:3871:3872:3874:3934:3936:3938:3941:3944:3947:3950:3953:3956:3959:4321:4385:4390:4395:5007:6248:6691:6742:6743:7807:7808:7875:7903:9025:9108:10004:10400:10848:11026:11658:11914:12043:12048:12050:12295:12296:12297:12438:12555:12740:12760:12895:13069:13311:13357:13439:13845:14096:14097:14181:14659:14721:14777:21080:21433:21451:21627:21811:21990:30054:30070:30091,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:1,LUA_SUMMARY:none
X-HE-Tag: cent55_291055a26e01
X-Filterd-Recvd-Size: 3364
Received: from XPS-9350.home (unknown [47.151.136.130])
	(Authenticated sender: joe@perches.com)
	by omf13.hostedemail.com (Postfix) with ESMTPA;
	Tue, 16 Jun 2020 18:53:51 +0000 (UTC)
Message-ID: <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to
 kfree_sensitive()
From: Joe Perches <joe@perches.com>
To: Waiman Long <longman@redhat.com>, Andrew Morton
 <akpm@linux-foundation.org>,  David Howells <dhowells@redhat.com>, Jarkko
 Sakkinen <jarkko.sakkinen@linux.intel.com>, James Morris
 <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, Linus Torvalds
 <torvalds@linux-foundation.org>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>
Cc: Michal Hocko <mhocko@suse.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Dan Carpenter <dan.carpenter@oracle.com>, David Sterba <dsterba@suse.cz>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
 keyrings@vger.kernel.org,  linux-kernel@vger.kernel.org,
 linux-crypto@vger.kernel.org,  linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, 
 linux-amlogic@lists.infradead.org, linux-mediatek@lists.infradead.org, 
 linuxppc-dev@lists.ozlabs.org, virtualization@lists.linux-foundation.org, 
 netdev@vger.kernel.org, linux-ppp@vger.kernel.org,
 wireguard@lists.zx2c4.com,  linux-wireless@vger.kernel.org,
 devel@driverdev.osuosl.org,  linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org,  linux-btrfs@vger.kernel.org,
 linux-cifs@vger.kernel.org,  linux-fscrypt@vger.kernel.org,
 ecryptfs@vger.kernel.org,  kasan-dev@googlegroups.com,
 linux-bluetooth@vger.kernel.org,  linux-wpan@vger.kernel.org,
 linux-sctp@vger.kernel.org,  linux-nfs@vger.kernel.org,
 tipc-discussion@lists.sourceforge.net, 
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
Date: Tue, 16 Jun 2020 11:53:50 -0700
In-Reply-To: <20200616015718.7812-1-longman@redhat.com>
References: <20200616015718.7812-1-longman@redhat.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.2-0ubuntu1
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.204 is neither permitted nor denied by best guess
 record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
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

On Mon, 2020-06-15 at 21:57 -0400, Waiman Long wrote:
>  v4:
>   - Break out the memzero_explicit() change as suggested by Dan Carpenter
>     so that it can be backported to stable.
>   - Drop the "crypto: Remove unnecessary memzero_explicit()" patch for
>     now as there can be a bit more discussion on what is best. It will be
>     introduced as a separate patch later on after this one is merged.

To this larger audience and last week without reply:
https://lore.kernel.org/lkml/573b3fbd5927c643920e1364230c296b23e7584d.camel@perches.com/

Are there _any_ fastpath uses of kfree or vfree?

Many patches have been posted recently to fix mispairings
of specific types of alloc and free functions.

To eliminate these mispairings at a runtime cost of four
comparisons, should the kfree/vfree/kvfree/kfree_const
functions be consolidated into a single kfree?

Something like the below:

   void kfree(const void *addr)
   {
   	if (is_kernel_rodata((unsigned long)addr))
   		return;

   	if (is_vmalloc_addr(addr))
   		_vfree(addr);
   	else
   		_kfree(addr);
   }

   #define kvfree		kfree
   #define vfree		kfree
   #define kfree_const	kfree


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel%40perches.com.
