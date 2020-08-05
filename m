Return-Path: <kasan-dev+bncBCV5TUXXRUIBB276VL4QKGQELLDWC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D076623CB6A
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 16:17:15 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id b11sf4815136edy.17
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 07:17:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596637035; cv=pass;
        d=google.com; s=arc-20160816;
        b=YwMwXKiXKolvQsgMzvshqNBB02fyyhmvY5JQxyXkFCR2n7rZMgYBovR21FazIwhUhm
         rJWTLznl8aZvGxiaJigKpcUfmta/asfVghNQNGb6o5ntP12hLTwbKjrIfurBwV3PYcmY
         C0Iw8ccPBSXvOZ8MT5KUUPBcSyrm9T7GMAWnflOswBepXpAFJMJ88y5BFAeBvmU45gpm
         k8lTCj/Fj++QFH8DXw6s5saYMiZEq0ux0J/p6xdrDADfddXQOi96LLUM4r+IlW311QPq
         tEB9Lye16la/hBNpPN/aP7wzJVXJ7EAF8xNiRQoQSoHr4AB392keOkGBpwSGkzXDixtG
         MXzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=T0PQnlHQ5H9myeS9oGE7mgjwzSxu7rqkwqz756JJLTI=;
        b=zF/fFe8ZwhpbHTM37xOxxRGOappzsiHsK8JHJVvA8AXxzHcIwyyBPINh9XBnB56KqL
         XTwBlG1aNDfJdSOfmP7YEV1tAsy3Fv0wWxZbJcWOBzaCEsRiX48mgFY7RaHq2JV61BmQ
         VjnkCLbm8NalA76fuxFzcmK30Qgw/fS99lMCrYIEVEfS2RSu2fgyG9tlE/U6tODuurYe
         uTVyUSBmHBah5jRKab+5eobhUsSauNPS0K5Cr1B5L3y2sQZY7+i9qf/uqivjkl15C1Sa
         j2NoHazr8xrXYx/vfvjpESIivQEk9BjDVTN95DRHtqLu+/65Su/y+lc9hHwCfpW8uN6h
         ot3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=wWnLh0O7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=T0PQnlHQ5H9myeS9oGE7mgjwzSxu7rqkwqz756JJLTI=;
        b=gwwgvDUM4f4Ub1zYNBd93QgbLJSucknmOqMq7+KfdmrYPj33dOsflvnUlB6KAkYa5K
         x+GMnFkrlAwD5ByKlTs1sNePJasfTLkfu4Ar+p1VymwOTg8nC6NoQJYgo/4D0siN9b1/
         xhpJ1kwi7VreqXK970Lsz4rBPLhw17Xnomr9vyA0Ubo6BUV/GAxbu0eTsfcu+A/zLE3E
         1GzU6qtBicF3rZ6VG9i7MUaiHx0XKmSC/mNdi+AFd7tfUDFyi5Cl4/hPC7oeCWMHr8eA
         BNu0/Hwe/vLHA9m/6hrHk0nN9kPjnuhT73goJ4X/ww4+QWsNIpJ7TYKKTB85qWYAmzRa
         1T2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=T0PQnlHQ5H9myeS9oGE7mgjwzSxu7rqkwqz756JJLTI=;
        b=k1yfR7NgN8SkVv4zM/xgawoybNHiwgrZpGgnV3p7XgWHNNOsgKYNKNnLqZN2OMtrxX
         Nio40/dIpkrIUmfW3ifiRORW742AOQG92MYfjzWIuB26hel30XV2hcNf9McxAO9XvDQu
         rM+K1dr8rQBvZW8wASgcWn6mgjxT3IHigi/0hlbzcK68KcRTW84mxiLy+w9+dBL/pCW/
         vTWTmhsTxlHnj9spZidxeRj+dwl6pdafLGZJHrgxFDB8P2KMe6SahpxaDntXgxkLHD7u
         jHUshzC6S2aintjkbLNNa44NOup5TdlM0VQUlGJNsck2IyW9ZWFqIdnIL4VEOgdiQDOA
         FN+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZTYr+QF9NZGPluumENHu0f/ack3OBIuYGK0Cd/dpRc78iPn/Z
	e+qijBjGu4aNRyNPTCAKtFE=
X-Google-Smtp-Source: ABdhPJyFrB+3qHYiCmHhUr99kIbiWCQMQop0i0mg5z98Pc0zw3e0x31LimGhBUbppBcM17gwPQGGlg==
X-Received: by 2002:aa7:d8d8:: with SMTP id k24mr3185359eds.32.1596637035610;
        Wed, 05 Aug 2020 07:17:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:17ce:: with SMTP id s14ls2335830edy.1.gmail; Wed,
 05 Aug 2020 07:17:15 -0700 (PDT)
X-Received: by 2002:aa7:cd08:: with SMTP id b8mr3095447edw.228.1596637035058;
        Wed, 05 Aug 2020 07:17:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596637035; cv=none;
        d=google.com; s=arc-20160816;
        b=P7MuckIpBkk9fqQ+D8ZNpCqYNgWVaDaNxo2+Gr6BU+mcMc4JIoGXepMUTAoJW5JTbW
         fIpzVRbEv90oLlGI6Y2HylfdiSSqA/jGQgJz0tFc0BLvLHwIWJbh24YXUbx8knPH/hwi
         sCvf/oo+uMfiMTQX5AeF5uo4sQqNiKs0E9BsGtPB1G6O0+2/LSa7IB2wI3QR2Nj6GZhC
         ZFGhRT+eJlIWTAXIBG0uFz3pg9rOVFw0duIBOEy8lU21s5w9B7T6JNCyupd9JR876tq8
         aUK6ZEIAriL4DqNr2lj6ias/CUUYNZVBIn4Rqly+UH3Trn5HTEMQd/rB4NIE9VSi3t6e
         7RNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0+DiSUHCj5Hv8PjpoaXrRSduwxZW9oCImFLTKQ6/8Jw=;
        b=JAjppZVXhLS4VwTi2GOMWmt59BhfgWaeaQkfHQ517ugK/d+TRXLdDDCIz6H0Qvxrku
         XNp4WOVEAS6Clo+ExJcu3XDHhu4wHNwvn5yOCYRjYN9goQvFB25tGeY/LHdMqOVApIy2
         i0TMfuGOABKYWuc/6mLGz4yAz8QJ83jpdxFgf48tq4o5B6zhxx2PF4EhW13Dx2O2Pybv
         5APd0MhQoFEaatdNPlCE38r0Vlvt6Twdr16iWPJRGfYQDXy8dCkNHF+vHR2XPxiq9l2T
         N2pIMvH2SQetfMHitxFA9Uyiv9Db4lX7QE/soaDcgrEC6FH9pTGByyDiB9vqz1vuJ6a0
         +lrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=wWnLh0O7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 63si69059edj.3.2020.08.05.07.17.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Aug 2020 07:17:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k3KEB-0006vw-3r; Wed, 05 Aug 2020 14:17:11 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2FE9D301A66;
	Wed,  5 Aug 2020 16:17:10 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0A7E022B957D0; Wed,  5 Aug 2020 16:17:10 +0200 (CEST)
Date: Wed, 5 Aug 2020 16:17:09 +0200
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
Message-ID: <20200805141709.GD35926@hirez.programming.kicks-ass.net>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
 <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200805141237.GS2674@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=wWnLh0O7;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Aug 05, 2020 at 04:12:37PM +0200, peterz@infradead.org wrote:
> On Wed, Aug 05, 2020 at 03:59:40PM +0200, Marco Elver wrote:
> > On Wed, Aug 05, 2020 at 03:42PM +0200, peterz@infradead.org wrote:
> 
> > > Shouldn't we __always_inline those? They're going to be really small.
> > 
> > I can send a v2, and you can choose. For reference, though:
> > 
> > 	ffffffff86271ee0 <arch_local_save_flags>:
> > 	ffffffff86271ee0:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > 	ffffffff86271ee5:       48 83 3d 43 87 e4 01    cmpq   $0x0,0x1e48743(%rip)        # ffffffff880ba630 <pv_ops+0x120>
> > 	ffffffff86271eec:       00
> > 	ffffffff86271eed:       74 0d                   je     ffffffff86271efc <arch_local_save_flags+0x1c>
> > 	ffffffff86271eef:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > 	ffffffff86271ef4:       ff 14 25 30 a6 0b 88    callq  *0xffffffff880ba630
> > 	ffffffff86271efb:       c3                      retq
> > 	ffffffff86271efc:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > 	ffffffff86271f01:       0f 0b                   ud2
> 
> > 	ffffffff86271a90 <arch_local_irq_restore>:
> > 	ffffffff86271a90:       53                      push   %rbx
> > 	ffffffff86271a91:       48 89 fb                mov    %rdi,%rbx
> > 	ffffffff86271a94:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > 	ffffffff86271a99:       48 83 3d 97 8b e4 01    cmpq   $0x0,0x1e48b97(%rip)        # ffffffff880ba638 <pv_ops+0x128>
> > 	ffffffff86271aa0:       00
> > 	ffffffff86271aa1:       74 11                   je     ffffffff86271ab4 <arch_local_irq_restore+0x24>
> > 	ffffffff86271aa3:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > 	ffffffff86271aa8:       48 89 df                mov    %rbx,%rdi
> > 	ffffffff86271aab:       ff 14 25 38 a6 0b 88    callq  *0xffffffff880ba638
> > 	ffffffff86271ab2:       5b                      pop    %rbx
> > 	ffffffff86271ab3:       c3                      retq
> > 	ffffffff86271ab4:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > 	ffffffff86271ab9:       0f 0b                   ud2
> 
> 
> Blergh, that's abysmall. In part I suspect because you have
> CONFIG_PARAVIRT_DEBUG, let me try and untangle that PV macro maze.

Yeah, look here:

0000 0000000000462149 <arch_local_save_flags>:
0000   462149:  ff 14 25 00 00 00 00    callq  *0x0
0003                    46214c: R_X86_64_32S    pv_ops+0x120
0007   462150:  c3                      retq


That's exactly what I was expecting.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805141709.GD35926%40hirez.programming.kicks-ass.net.
