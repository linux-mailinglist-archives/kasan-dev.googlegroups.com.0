Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBUHUQX2QKGQEDIUKVMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EFAB1B5A63
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 13:21:54 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id u137sf4950838pfc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 04:21:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587640913; cv=pass;
        d=google.com; s=arc-20160816;
        b=di1m+7xKwDUfgRLChyyf3SFAGe49+eJV1HqBk0YhePRKPtwInjfds7gmmi6SboN9ne
         GmLyOfUh40GiNDFIT1sVLOa86sSAKgixQvFLshHWVg+Hcdn7RA81I538SNq9wCt6zV+3
         mxzJSkv9wiAUZRKJZh2OqpChg6TNtKzFK76l/i3yMIqF26IoJSpl9iy3SPcpdvrG62ss
         I+CqygSobciOeeNo+6aE4zPgakclEKFqdZyTcO6PcnpY7Kyxp9GmgHBqXpBDqnMZzH/A
         wtgzjdXdKCx76Zctf3xehKn1gTPzmdttrqs5ffJlQ3RHUWKYSRLjpQGrkyIr8eYzkGVL
         FDRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=sMwAarC+zQCjMLHXO+OBEvShnJtV18GkFNiTD9pji/I=;
        b=MP2AHKhH+tp0YG09XB4iDXxID6abdbtaWr6IqNPNSgN2Sx7FdmrLQUJy5qo0Z79IQV
         b2qhzsDzkaIQ6N6IXEGkmNXT56UVg09T9WpmfbYUkeXVB/h52NnwCOJBLTaUtjMXNQza
         Z0tnjINyWP0DOPmWMsyt4aed+boU3xP1ysCyU0xexJAoaC0wNqwNUHMHNLN01Ufim6O5
         KU/AkeEADisJd1UP6aCs+10s5146b3plss0DPr/wS3mPupIbhHcXvSNSe8wxDwn1aWD5
         SBzdNPLXE2JF7yVHeSSXNR8AgXkEoqjmi+fw5+iZxPz7JXjWId8ZxkVK/Vl4b8/cE6t1
         uLVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=qpZpn418;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sMwAarC+zQCjMLHXO+OBEvShnJtV18GkFNiTD9pji/I=;
        b=FkU+uOAjBSEPP85Xg3qTxjZpSuffA5jl4bEw8UhA1dA3yAEelH85M/uR71anIiS7kO
         FNrSL1PJJPKhWkVZQqWQ94vx6DXmuTcBHq53L59uUaUk8zvKXaxSxNKBdl/utkccFSPS
         pYV9T8nRjrK3Gt5PS+TLDo6etuKmf9Fvaa1cKkyzFOIPmxeyJKY3e08mN9Lfytx4SDM5
         uxitbV+3DeQ5r7BbAvpjIBFldmb+/TzAMJS2EhbDTLrF6nIHmSmRBhCCm5ggkw4HT1sk
         BgmFwpuVGb234PA+Iu4ZEfQbdyDkXmuu2iKVxu6RI05zeepaXbkd4mcv5s9BSWF9Cmcg
         sKog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sMwAarC+zQCjMLHXO+OBEvShnJtV18GkFNiTD9pji/I=;
        b=PL/q/QFGFz9Os0C5pQXN4IRULyZr90f37p9189l+jOkXY5E/0Dt+QBHTrbmtsPeGDC
         OOYDBmfZDFdE+MndqnrYs2vX/szP3uiBadmXZnH/WpmdTPY8VNh2h/iPzU6aorn7D6eW
         T66r5oK4huxkEDMr8if50308JpixcZXPT1zpk+f0pJPOIaS9C8aUbwpa/01cBvUx/Pjv
         9Gu40BfMkpVK5S9d8DUFY9G/i0JDKrRJ6SHTy7jIIh04VcBdCruu/ftxOA1EXgNw2pSX
         04sL7ysPoEK56buRnJ5ILIHAA3xr4ezJIW22nlH0FNdeIqyiXseecS+ryn5g1f0BqSkN
         samw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYpUzKiDrEOGUaK71EADjyrjWYoxZF547hxRS4N9AGis5BH8KIc
	YjA7Gkl3liBmcqPnx+7d+88=
X-Google-Smtp-Source: APiQypJaCRpUrhqj6AMHVYaB5VIz8EYyPdzfYS+EY4bITyMzVxYLwz766xwT13IOpz6iRkGSvj2Uiw==
X-Received: by 2002:aa7:8b4e:: with SMTP id i14mr3112570pfd.98.1587640912773;
        Thu, 23 Apr 2020 04:21:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4383:: with SMTP id q125ls708128pga.7.gmail; Thu, 23 Apr
 2020 04:21:52 -0700 (PDT)
X-Received: by 2002:a63:f843:: with SMTP id v3mr3579100pgj.421.1587640912332;
        Thu, 23 Apr 2020 04:21:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587640912; cv=none;
        d=google.com; s=arc-20160816;
        b=rnyylfLUvok6D4Om19frVhD5MZNaBBr4QIPKZeVqfYqfcTPSMkMsXGcxKHyEo09Nf0
         vQ3w0Nazuysegw4qaE9xa7IO4rzk/8abCtrloaSVTuXLPin2vmtYGvJytZtwdp5fb/2r
         qI7HPxa9GaDoMEyt2bwJgty42n801t5yaMZTyRqT4gsusxIPIxDvCI5JvcjsM7UunQ2b
         7PNb3WRTwuL9PvX82U8NUkTKUam6TPcV2BI1jBQh4e/hZFJIVjrwJOmFBtCmhCnOJGX2
         LcwKdl1PNg+QsKzue3YdZjSpaD62+fZBXVEzeg+sEH02UHvja5IMgGvQZxht90oK1ZDn
         hoWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=lhSh3eeIrke7xfXKnLFNXKOf7zLgRTGB4zBEZI1sk9g=;
        b=qdw8hplu8BenuSDCdwtHOYWSDys5kZF9rULFBE1DqIn/KIWOCuQLsoGUyua6yc0QvC
         JI2toCbuVHvEMGx4aCaH9Lub5T+aF6iguOX4rf0lZlKfDDf4PefT78cS/3fPyn8z2nKd
         /oX/v8AdLqX6l5bVKJg3rEU1eVWSt7C+eCrQ/DhUDE8PE96zgnOy+8/rMSdypw1+hUub
         hKwcpKWlDVZPIpc2fASlDRgPsSq9+8hOhT+llaeIJODhX99S61oVcSYbPbtRFqN9mtac
         z8FaTEmYQhTInVXp9MU6zNpYedKhnvpVJJmTM0Am5x9No7RiPe0wwh9XQZTMH8GFDb3O
         Y6jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=qpZpn418;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id gn24si606715pjb.2.2020.04.23.04.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 04:21:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id g74so5878080qke.13
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 04:21:52 -0700 (PDT)
X-Received: by 2002:ae9:dfc5:: with SMTP id t188mr2741170qkf.384.1587640911889;
        Thu, 23 Apr 2020 04:21:51 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id n31sm1550523qtc.36.2020.04.23.04.21.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 04:21:51 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and pgprot_large_2_4k()"
Date: Thu, 23 Apr 2020 07:21:50 -0400
Message-Id: <DD433C5F-2A08-4730-B039-8E0C25911D10@lca.pw>
References: <72CCEEC2-FF21-437C-873C-4C31640B2913@alien8.de>
Cc: Christoph Hellwig <hch@lst.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>, x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <72CCEEC2-FF21-437C-873C-4C31640B2913@alien8.de>
To: Boris Petkov <bp@alien8.de>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=qpZpn418;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72c as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 23, 2020, at 7:06 AM, Boris Petkov <bp@alien8.de> wrote:
> 
> No need, I've rebased and testing. Stay tuned.

Cool. I can only advocate to take another closer look at this patchset (it looks like going to break PAE without the pgprotval_t fix), because bugs do cluster.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/DD433C5F-2A08-4730-B039-8E0C25911D10%40lca.pw.
