Return-Path: <kasan-dev+bncBDY3NC743AGBBV7CY36AKGQEQDEQLVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id AB02C29628D
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 18:20:40 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id o135sf2262265ybc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 09:20:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603383639; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bba+65RSvqW+oYwt4G0/r4q0zfmQZAU/PAS5SUuYVMGq2cmRzUhZ4IFJ5PV2A96N+Z
         I22Wv47Ghc4tlrcDsVvcRLzjGd52pPwfw/jDVzHmaLjtdhSxjAN+CtNvD2ie78TfQL13
         qEVrQeBMGPPHEGl8AMW5DJSgD/xu2Q5gpljvKM58MhS4wLqmfGuqpGBZvBw1xEC+Fktt
         bUWgr2lHSUEC/5OA9TTptFZ0WCovIR7Jx6nPTL7sSWdNUCjR5uyyTAks4XR5JzgWrYIz
         XZdk/g33O4mZUJI1JWRJLjuo/Bujiui4TBKX6/vBqOqV20/xupflZewjD82qFrz6Kmpy
         0CPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=fLNIswdqbhKk4V5bdQrZ2vkNpVpYLEs8kiT8Pof/YGA=;
        b=qVCQqKIC+hQ18SiV3xuCgh51bUKOSzfO9hAo98zC4Lhsxv+teuarmCqJrWg12dTyU1
         KsgMK5K+P2wH/ImwFlF+tYDs5XsHL7e2K0H12XwADWrQdO1SyEJMY/+z+9tBRbFKk6sT
         aCmaZU+aWgAxkLLyFR4hp/uq3cqGiiCwq9q/BgtHy+t9LsYM1PWdC6LfOyMSHBC+uRF2
         yGQxFzWFBaK/5h2dfuxgib64Eh9PVj86HpfPXe/WUZurT3EW7PAOHG9Pu/C+Z5FMobCq
         TgtOFfSCNWXAaRfrS/i6gQWCs8TX907igxUvdKqd+jPXvkrxDyPcBaokxiU3QRGvMovh
         JZaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.159 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fLNIswdqbhKk4V5bdQrZ2vkNpVpYLEs8kiT8Pof/YGA=;
        b=A43AnOiWbHrfLYqQmpImEVMymScxzpKtuqKSFbJreP7VE/xpCkDQF3pgp2NvndDxds
         lSwD7u0xLNimo+cY392PsZvDh6CIwZKM7p+O27n2E+mzle8xpztGy5/JRA4gxEVYzjuv
         xtsrTzGHAtG7VrfFsDCVIncT9fb29LnMiRhd6d++vgPgtRMuJ86QEcJrRItFmQovtw3U
         0ZW2u+DbGHvLWNhtp+njN1r/dPwI5vO9y1KTVnlYqWgbvkHQuHS6hGTjxBSILe4KZqqZ
         smin8wHPo5CUYgLLmgS99wt1UbIrsV9HgV1BfWn6wlis74Y7Kz0qCEyR7qXcl26laLx9
         rgBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fLNIswdqbhKk4V5bdQrZ2vkNpVpYLEs8kiT8Pof/YGA=;
        b=JSP85UktvJqfMETIEqQbVDnMZaD1JUYkZjwUymmPnqMlIq/swgGa/xXfelNf0z6+dP
         ZBhJg9LUN9ivBHjrdUOZUUcutQkOUF9kyCiWoTpNVwyf3nMLC9k23UuGTnsMMNPmQ4TM
         VrsZJDtdmT/mS34k5paVVKKZ4XGLcUvOwqJscUHCUzYclj79kN3D0y1peN5BumezBdLL
         fV/gLtIeaFXGAWrUtBysDnj4yePYIMGPp/8I2zz7SnMNEMebtv3dQEWEbptu8+ewPgnR
         Eg4sxZVDv21iwgu4ZlnrF7AjB0ot7LdPOFd4NsaGhdgTMJMio/CisumvvTasRFZaZaOF
         r+pA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ypSVf+Mhj04t/zh/k9JwdOOTTuJBB4W2WZj1ThPLIlzYZ90JI
	LTU6dgk5SAN9b9h7cWgZqIY=
X-Google-Smtp-Source: ABdhPJx3eKAkFZ73IQ09dB4E8p+fK9NZ07cCg4+UoToR3VxeRbN2Qs0H1J6+gNEdd4mBv6v6JZ1BOA==
X-Received: by 2002:a25:df06:: with SMTP id w6mr4295335ybg.485.1603383639605;
        Thu, 22 Oct 2020 09:20:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:4e3:: with SMTP id w3ls1086284ybs.2.gmail; Thu, 22
 Oct 2020 09:20:39 -0700 (PDT)
X-Received: by 2002:a25:7e07:: with SMTP id z7mr4644929ybc.193.1603383639133;
        Thu, 22 Oct 2020 09:20:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603383639; cv=none;
        d=google.com; s=arc-20160816;
        b=cwEYIHt8dGOl44pDiU8fgWYSOHde93Omtz1PEVmVR5NiWPQG1amtq8vrg11ZL9Lyzs
         WU/kZdqgrdFH04jo679MENtTSYmme+Bwq2ZlQJ5KJitYoCooaIIN6/pTn5RiY6BguEBt
         HOqOca9bHqJsMdhwGFUiIRsnPO1m4qF6ChHSuZioizQuoV6UrQUidZZEZ5fqPigSG8zK
         j9IKR7wTEwc7FkcGB2P6u7/Aa2sVMBii8nvyLR+6ZocPoVipyayPZ6hNq9Bqry0pgpD8
         QmMw4UfHWjsoW6nkEYOwuFq5H8JpoCL7apQllgei3OFP7Cc8j8QLbtO6f8fBagORW4Qn
         kwtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=9LwbpeWFRvKGRiafzZRDSWSY2qgNKaeXli8v8XDTX8s=;
        b=KA46WDuoIWyA8rdt/YlEwaW9lzvIpPgPUmAu56hvatVWzrgF082Glsfn+LmJJA3ZRw
         rafo1hcXKGO5OKQDGkj1pgzS0iUHLddjafczZdatmNykzBG601QvbWHaMn233K+3Jm9V
         0UkUWyXnKP7FjCIwowkAD8D6HB4CqCgP1r2IPeRS1wzN4/qSioUxHb/O4r/fiChN0BE5
         uDvlrhf+iQ9pkvV91CRQhDJv2xGzyI1dKgw8B/WvV7dTyYi/f8OzGE+UTFSilCKv9Jtb
         wpLE/ueEF22yKYjkA6RwnXGkLGMyET71nTLoG5TnEBbldADIVkABLy9KSIMjJdigezj1
         pHMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 216.40.44.159 is neither permitted nor denied by best guess record for domain of joe@perches.com) smtp.mailfrom=joe@perches.com
Received: from smtprelay.hostedemail.com (smtprelay0159.hostedemail.com. [216.40.44.159])
        by gmr-mx.google.com with ESMTPS id r8si188677ybl.1.2020.10.22.09.20.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Oct 2020 09:20:39 -0700 (PDT)
Received-SPF: neutral (google.com: 216.40.44.159 is neither permitted nor denied by best guess record for domain of joe@perches.com) client-ip=216.40.44.159;
Received: from filter.hostedemail.com (clb03-v110.bra.tucows.net [216.40.38.60])
	by smtprelay02.hostedemail.com (Postfix) with ESMTP id 5284912EE;
	Thu, 22 Oct 2020 16:20:38 +0000 (UTC)
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Spam-Summary: 10,1,0,,d41d8cd98f00b204,joe@perches.com,,RULES_HIT:41:355:379:599:800:967:968:973:988:989:1260:1277:1311:1313:1314:1345:1359:1437:1515:1516:1518:1534:1540:1593:1594:1711:1730:1747:1777:1792:2198:2199:2393:2525:2553:2561:2564:2682:2685:2828:2859:2933:2937:2939:2942:2945:2947:2951:2954:3022:3138:3139:3140:3141:3142:3352:3622:3865:3866:3867:3868:3870:3871:3934:3936:3938:3941:3944:3947:3950:3953:3956:3959:4321:5007:6248:6742:8985:9025:10004:10400:11232:11658:11914:12043:12219:12297:12438:12555:12663:12740:12760:12895:12986:13069:13255:13311:13357:13439:13845:14096:14097:14181:14659:14721:14777:21080:21324:21433:21451:21627:21788:21811:21889:30029:30054:30070:30074:30090:30091,0,RBL:none,CacheIP:none,Bayesian:0.5,0.5,0.5,Netcheck:none,DomainCache:0,MSF:not bulk,SPF:,MSBL:0,DNSBL:none,Custom_rules:0:0:0,LFtime:2,LUA_SUMMARY:none
X-HE-Tag: juice98_4f032d527252
X-Filterd-Recvd-Size: 2328
Received: from XPS-9350.home (unknown [47.151.133.149])
	(Authenticated sender: joe@perches.com)
	by omf17.hostedemail.com (Postfix) with ESMTPA;
	Thu, 22 Oct 2020 16:20:35 +0000 (UTC)
Message-ID: <133aa0c8c5e2cbc862df109200b982e89046dbc0.camel@perches.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias
 macro definition
From: Joe Perches <joe@perches.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Ard Biesheuvel
 <ardb@kernel.org>,  Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Marco
 Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Herbert Xu
 <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, Nick
 Desaulniers <ndesaulniers@google.com>, linux-kernel@vger.kernel.org,
 linux-efi@vger.kernel.org,  kasan-dev@googlegroups.com,
 linux-crypto@vger.kernel.org, linux-mm <linux-mm@kvack.org>
Date: Thu, 22 Oct 2020 09:20:34 -0700
In-Reply-To: <20201022073307.GP2628@hirez.programming.kicks-ass.net>
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
	 <20201022073307.GP2628@hirez.programming.kicks-ass.net>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.4-0ubuntu1
MIME-Version: 1.0
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 216.40.44.159 is neither permitted nor denied by best guess
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

On Thu, 2020-10-22 at 09:33 +0200, Peter Zijlstra wrote:
> On Wed, Oct 21, 2020 at 11:58:25AM -0700, Joe Perches wrote:
> > Like the __section macro, the __alias macro uses
> > macro # stringification to create quotes around
> > the section name used in the __attribute__.
> > 
> > Remove the stringification and add quotes or a
> > stringification to the uses instead.
> 
> There's a complete lack of rationale for this change.

I'll eventually post V2.
I'm waiting to see if there are more comments.

As I wrote in reply to Ard:

https://lore.kernel.org/lkml/1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com/

Using quotes in __section caused/causes differences
between clang and gcc.

https://lkml.org/lkml/2020/9/29/2187

Using common styles for details like this is good.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/133aa0c8c5e2cbc862df109200b982e89046dbc0.camel%40perches.com.
