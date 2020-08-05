Return-Path: <kasan-dev+bncBCV5TUXXRUIBBY74VL4QKGQEWPJOKTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7035523CB61
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 16:12:52 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id s2sf32398176plr.22
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 07:12:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596636771; cv=pass;
        d=google.com; s=arc-20160816;
        b=TljuC+6OCXFjtW7wN3Wi78FOxKPGpaeB5qH64jZe9KFUgtGaOPu+rlmGiYXp/NuTO0
         mVErS+I9tEjCqRc5+oVhtc8YvBNzlyoCcPUXp69SULP92Wk+4iQVXt5v9C53qfDNj4S3
         DhTFdJR/WGxzwhnGatzd1Z1LVpTvdMESosFWK45rNrSUgGF8vObQFgWKJ4/NQpyYs8o9
         DRSrU+y3G4x2ypy7NU2738NjKF+FKh3YytaSQWls/Bpci8lIMHnMIax8nk43fRmlVF7M
         sKc+F7G31XIzbMpA7YHTGoUK67XR9oEjQNvlfbhtzLqkOPpNfhXeBQlWr7khE5bQ1Hd1
         ATvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fsneuyf3ozPxA4IlP9FUebJFzOT/xSXx8FP9ryg5pSA=;
        b=qAklQ2DS6/QSAjUgIuPTZSKcKAx6ZJ3w851FV+vRKRlW2Wog1C4K4WPg0rFWlMh0ez
         0OGy9sftvXVNZ1N1CrcfaWFLnbt3jS0cux0MM7WEbZniEtg/+FCUzTgEQUSZ/UCItjya
         IMXCFwQKGGcWqTkwjSz11Z9LaCNN+iOS5PMekpNKt40U6WAj66E9oHDLTkI6qixmp9Ov
         x3nWl6p6UGoRTCb9Oriw35G4IELmBFvksk0zI5z5RUktFKtfpk9gnBAWH09i+Oy7bSEz
         m65ENpMRrkquucbNcWTWB497Vu52VQc9MH5T5YohiKDXaYt8N9iEUUf96WfckxGmyvYs
         W7qw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=xZgN77rc;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fsneuyf3ozPxA4IlP9FUebJFzOT/xSXx8FP9ryg5pSA=;
        b=f+sF/V4ukaWqzTHeOFdiDIT1a/7jZDHXL86oN5qvh2ZMZLs8WhGW1ek8YjhGkOB/Gk
         /tn857QLeSkh0uejYkNIUomr4tswZ1+nxxgUylilIBjxSgh9/hJbgOrklveSvrvCSmnB
         CmmQI97rxV8yMgWTRm16JpcrNXCMSdKujglEp8DPRSxga3zVPpbZ5VSWAkVUnEAGK/Fp
         imvKxqQT9Ib/mp8q7CJ05Cp+9opvI9VOWpylr/ZC6PmjLFzDpDSLX4oUQUvsgKi36ChH
         xkg4NtzphYseo65yBgMVBqoDrAb0OpjTRrsgqhD64hfCXq6Wz25vP1s3LSWvbeziayDt
         36lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fsneuyf3ozPxA4IlP9FUebJFzOT/xSXx8FP9ryg5pSA=;
        b=t5SzfCGM9ZeojDCiiSu6XzNggPrU5WxbKnO/YaMFS/uteaMpHS98XthZBpDVNloos2
         W5x/Dn3J4yHuTK6CKc3UrEbc0w36deiDD4Iat+gnGCM7Ut7YGqLRXcJNrgHUsaFp/ByW
         lnvISWnqLQqj9PBkRfbZcIM2xpTdU47z6kAQAZ5+adRtHHgzMg3dZdkPfQcQ0edtq/Yp
         ixsd6UtVNtwUZ9N0gT6gArWD0sddj29e1ratDoP1RdQjCXmbNc5coNTxTUqLgf4Pj6O5
         pJ9nE1Qg4RM2MySw0U77BokjOgVw9Uze4mDODgKHX8brfcA4F9lQ1u7/S/opxhHuR1U9
         jUqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lWrJdV/Ur4rFueZjISi+xeSOW/ZnnNDvwlLvSvg2JVvMvi/qJ
	Hs4SU2y2aYLRclohk2d2aEI=
X-Google-Smtp-Source: ABdhPJzJFlzJFfyp2eVeDUdyu26mKZJBeOce9G/x/yoQtcfBvRa7PF9khCRw58rKC3SGWidG1rymsQ==
X-Received: by 2002:aa7:9569:: with SMTP id x9mr3607121pfq.16.1596636771104;
        Wed, 05 Aug 2020 07:12:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7593:: with SMTP id q141ls929201pfc.0.gmail; Wed, 05 Aug
 2020 07:12:50 -0700 (PDT)
X-Received: by 2002:a65:6089:: with SMTP id t9mr3236761pgu.236.1596636770670;
        Wed, 05 Aug 2020 07:12:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596636770; cv=none;
        d=google.com; s=arc-20160816;
        b=AWzuwldcjEKUAYdQItsc2hNujmnJr0uNl05+b9N6k/OxfKx5UDB67pmCdlout28eUS
         qej5ICPByRx0drbaXMivgJCQvgFQmFQMKL4JQTNkt4dQlxXyTEloqajKugdZw6wt4U1y
         INAJbw/KC8xtJd5ssa9buXlE+kYjm7JGxnf5kX/s3LB85h1gOK/ZuqIIV4GykeEQZ1JS
         9hpv/9qBRKv43BvyR1u6Zbl+nA1nqF1RNBUXBvXsm12AaVLMRP6pvHZsIEsuIay9kBhL
         LAi4zgldjuJLnYEB01dDWTZfBEzXRSu7eF1VjNioZIdrNSJ9oFPxsC+aIL+PF+OO67k9
         M6IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RIIneg+7/mEtbE19meMAOfaXXJsMYVcX3DCzixtwFp4=;
        b=wCdhBof2BH+4XEyPTYRNH8Cven88s/OUxB5xon+YJPJy6Y88reKyW6v+8LNx1afNq3
         4hbLzoBc4CBVUTOPL+prhc2mqzmsbOuIma/egPfVPTNXxrYznSHhE8KMardGMNVt0uwn
         6sGHC3r5/EGPpATgESoz5ssvud1mx21X+irjZRCj2xWMerq3tXWem9sYtnrJLtIlvf1C
         SWCashOVmDsgX/gyxKl4sYnwZhe5GqrxNmYFZc7V5DcczYcOec2ufuO6nmtLiQ5K0Dmg
         X68rqyKpo11Jtia7nFrFIm2ootqjEIKOqd3Zzqm0Baz2Y8NgPGFhJCgGFzJhvWyGiYtv
         bE2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=xZgN77rc;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id t75si99126pfc.3.2020.08.05.07.12.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Aug 2020 07:12:50 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k3K9p-0000Mo-TQ; Wed, 05 Aug 2020 14:12:42 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B13C7301E02;
	Wed,  5 Aug 2020 16:12:37 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A584823D7A30F; Wed,  5 Aug 2020 16:12:37 +0200 (CEST)
Date: Wed, 5 Aug 2020 16:12:37 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
Cc: bp@alien8.de, dave.hansen@linux.intel.com, fenghua.yu@intel.com,
	hpa@zytor.com, linux-kernel@vger.kernel.org, mingo@redhat.com,
	syzkaller-bugs@googlegroups.com, tglx@linutronix.de,
	tony.luck@intel.com, x86@kernel.org, yu-cheng.yu@intel.com,
	jgross@suse.com, sdeep@vmware.com,
	virtualization@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200805141237.GS2674@hirez.programming.kicks-ass.net>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
 <20200805135940.GA156343@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200805135940.GA156343@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=xZgN77rc;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Aug 05, 2020 at 03:59:40PM +0200, Marco Elver wrote:
> On Wed, Aug 05, 2020 at 03:42PM +0200, peterz@infradead.org wrote:

> > Shouldn't we __always_inline those? They're going to be really small.
> 
> I can send a v2, and you can choose. For reference, though:
> 
> 	ffffffff86271ee0 <arch_local_save_flags>:
> 	ffffffff86271ee0:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> 	ffffffff86271ee5:       48 83 3d 43 87 e4 01    cmpq   $0x0,0x1e48743(%rip)        # ffffffff880ba630 <pv_ops+0x120>
> 	ffffffff86271eec:       00
> 	ffffffff86271eed:       74 0d                   je     ffffffff86271efc <arch_local_save_flags+0x1c>
> 	ffffffff86271eef:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> 	ffffffff86271ef4:       ff 14 25 30 a6 0b 88    callq  *0xffffffff880ba630
> 	ffffffff86271efb:       c3                      retq
> 	ffffffff86271efc:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> 	ffffffff86271f01:       0f 0b                   ud2

> 	ffffffff86271a90 <arch_local_irq_restore>:
> 	ffffffff86271a90:       53                      push   %rbx
> 	ffffffff86271a91:       48 89 fb                mov    %rdi,%rbx
> 	ffffffff86271a94:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> 	ffffffff86271a99:       48 83 3d 97 8b e4 01    cmpq   $0x0,0x1e48b97(%rip)        # ffffffff880ba638 <pv_ops+0x128>
> 	ffffffff86271aa0:       00
> 	ffffffff86271aa1:       74 11                   je     ffffffff86271ab4 <arch_local_irq_restore+0x24>
> 	ffffffff86271aa3:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> 	ffffffff86271aa8:       48 89 df                mov    %rbx,%rdi
> 	ffffffff86271aab:       ff 14 25 38 a6 0b 88    callq  *0xffffffff880ba638
> 	ffffffff86271ab2:       5b                      pop    %rbx
> 	ffffffff86271ab3:       c3                      retq
> 	ffffffff86271ab4:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> 	ffffffff86271ab9:       0f 0b                   ud2


Blergh, that's abysmall. In part I suspect because you have
CONFIG_PARAVIRT_DEBUG, let me try and untangle that PV macro maze.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805141237.GS2674%40hirez.programming.kicks-ass.net.
