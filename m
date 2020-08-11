Return-Path: <kasan-dev+bncBCV5TUXXRUIBB7WFZH4QKGQEAIBWABA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D640A2418C7
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 11:21:02 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id r11sf1005114ljn.22
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 02:21:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597137662; cv=pass;
        d=google.com; s=arc-20160816;
        b=u0J0BPQ6ceZYGCucUFcYWEp4QALR34kq0jQGzyK2wUINXxedp/uRGG/aRmXPngslmS
         N1Adtv+k/SR1fVuMwoGSdKuIP5z3Uf8cNGv+1ArJbEGUpMnojBD0ADXm6tqkqAHN85To
         6ITz3jvPTKTQRUVNS3sSYg9k59xcsJcLe0PNrSBXDaM9g9igM0D+eyOSrY2W0JNvuTqH
         GB8O1358CZKbJ2x55IGhmPcjD6kVhiQzxtZKvNd0YtCHMOB02GNZXQa2+31vjaOZvEeK
         91osfv+IPXhNJQFxJSPBxoXSdUmRCIzaNYO0fJbI60+nHJel3XEOOvUErG+KBPt5UIZS
         7Xtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qeIXy081WNrr3fZybMKj8a/Eiq1Bdt/tSuxDUc28iko=;
        b=BVhyX/Ax3PVbXqkklvyR1WLf4zQ557wZIdlIzLjet/8oBuP+fOXhJjrU9lbXMvh6Wp
         QRJpmYDOQcnm9uSyHNk9SSW1aQ36wHDGmRkDvCexjLWcjmmZZWGGZ9+/Pdh/2LLddd3i
         L/zmVBUrwMkdZWTtRSudAheBv/hBXEQpj4ltjXU4D+m3+PckI2FMhjgPQe0t+ALopdBF
         QeRh5JfsTp4Bv9c7qhCY7pwBD9m5pOx6kbUgt8yDT3Ue8JfdYl38swQhNr5v1YKRl6ig
         ZDMe80Vlv3sMtcBuO0TMkipGOQbsQjY0Prm33lBRZ25MmnDFXnSFIrRsFKKa5J4dx8Yj
         HB5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uwpIB3Nt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qeIXy081WNrr3fZybMKj8a/Eiq1Bdt/tSuxDUc28iko=;
        b=r0+ic75Q/zL+s6DAaFZE1S14on4CoD8AyNiqJXtK18LeopszrGgjO/WaexL36kC0E9
         M/Xl4Ll629eYKvLdC9okbZoTX9DgKutcL6xXTX31tC4KNukgXAsZ9ad+gt7/asw1pCu4
         k2wydRVRwMI3C6E8/Xiy2ZL6Bm01Lz1mWW4biMJfMvx5wJX+y+zB1bF9+26crN3SZwa6
         1DRNWqoogNqXwpO/iZOsgmLyQfsYhW2VmmywuJYS47VX6VlUhXMaHMRogh6Holf1G69Z
         JcZHg0V1cDPmJTQxdygKSUmp43RKIFQiZaYM1ud4pm0wTQLa3fjHCS5sptnziw2odlju
         r2fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qeIXy081WNrr3fZybMKj8a/Eiq1Bdt/tSuxDUc28iko=;
        b=BstqWb4XTxXr5LLy+WFNB0KTeHo1TRuocCCqir29QuHu7G0HpBxp7p+cM/dl5OqEqx
         EtZZq0AeEzPyn9h4QI5OD1lGxCzjQeC9uhKETSe/lklEtchuxvCXFQII8gYupNLk3gt9
         zQ1D/ENkWyKEsVvCWG9rmVAiHDjCONxl45L57dG0KurE7DcP6LgDNTxzpcLj8Bj/kXXC
         DvPZmvPP5KUiV6IEcEc3JK9gzEvE/lhKB6WcqwQ5Jozp+oW948cfjQ8WWncRxkkb3F5l
         6wQ3J5gG0rmhQrqfdmbYSFqCZVHCoPtxwBcz/ITz5qNiM2+Gi1OUQrjQTTd+u/PZUS3J
         4zog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sFzyZAaYucurb7nBM2wd8/Dm8ch/2nuWXwv16rLzZGeRY7te7
	SIvhYD1nCdV+qqrxfxfEb4Y=
X-Google-Smtp-Source: ABdhPJxlPPqMAhNepSNZvhx6P/HO55WRukQheLZBsaIBITakvWniedTlCR2OG20miBTedX1wgYWtaA==
X-Received: by 2002:a2e:96c3:: with SMTP id d3mr2677035ljj.270.1597137662440;
        Tue, 11 Aug 2020 02:21:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:60e:: with SMTP id 14ls50536lfg.0.gmail; Tue, 11 Aug
 2020 02:21:01 -0700 (PDT)
X-Received: by 2002:ac2:561b:: with SMTP id v27mr2789805lfd.22.1597137661866;
        Tue, 11 Aug 2020 02:21:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597137661; cv=none;
        d=google.com; s=arc-20160816;
        b=jBrBCAuH2zp3Y+j9UGG6CTt8z0wegJmXR8wF+1S5ksn+460wNB/6oe9/SJL/vEXQ44
         g6Ly3IrVId0znQvzu8ku+ROAVFulIx5zJO+6Yr/NdCGuwpz7wbZf1+L4c6EBwvl3tN7N
         ijktr7ADsD4rzGDDxXWWf5cPC91xK6S38vvHeEUdYr5hDfsKxC0qcBBgtjXM0kcw29uX
         rF8YxF4lhZvx78ynq0uPw7DhXm4MhAqfGtjKlq8SJFYXBO6RTprhxmxJdBHpycGVQYBS
         Ng8X1rHIJLLL8TWHryjEBA7a+aSuylQVrvQ6Hvt1YmPiEU6j5xMJn9jm+XCZILRJ1cuV
         MhbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=hm4JdNf7SM0QMQOFD/GVqjWP012kTgNDcYqFU8vfr/U=;
        b=x5jRdBvg2OWpu6uqYUkdpC/beEe02vWYou+sLoH5T48haf5D9E7IlFCdogXAEAvBVo
         W09T7mPytIVWd5/JjlbvT/e+oxnPZQ0Ukk/5nfPM9t7G6NjcGyipvZqfu3wI4/FgNFnm
         kCKFj+7kT9vWjITMlZgfyXZ8I/f8PHELuGEzUmc8TpO6CbWlQGvvjYfhCk74fgnBAq5g
         Es2GTpcS+dWPw6AMt5gLihfN5wNGmseveVFh76n/pm5ovhzX1G2t/Hb+AaU/WO+XrJEI
         pqz+cTyDFId79X+iDU/f+OKz5EKUDZNB82bV6wgOJkR/MHxW/JmcV72+xw9AM38jWdn7
         BHkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=uwpIB3Nt;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id s3si983778lfc.2.2020.08.11.02.21.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Aug 2020 02:21:01 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k5QSn-0001tP-Lq; Tue, 11 Aug 2020 09:20:58 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 28822300DAE;
	Tue, 11 Aug 2020 11:20:54 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1982020BFC4E5; Tue, 11 Aug 2020 11:20:54 +0200 (CEST)
Date: Tue, 11 Aug 2020 11:20:54 +0200
From: peterz@infradead.org
To: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>
Cc: Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Wei Liu <wei.liu@kernel.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200811092054.GB2674@hirez.programming.kicks-ass.net>
References: <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
 <20200811081205.GV3982@worktop.programming.kicks-ass.net>
 <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=uwpIB3Nt;
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

On Tue, Aug 11, 2020 at 10:38:50AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> In case you don't want to do it I can send the patch for the Xen
> variants.

I might've opened a whole new can of worms here. I'm not sure we
can/want to fix the entire fallout this release :/

Let me ponder this a little, because the more I look at things, the more
problems I keep finding... bah bah bah.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200811092054.GB2674%40hirez.programming.kicks-ass.net.
