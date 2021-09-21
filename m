Return-Path: <kasan-dev+bncBCAIHYNQQ4IRB5WXVGFAMGQE6TLYULA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id E3B2C413E0B
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Sep 2021 01:34:15 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id c22-20020ac80096000000b0029f6809300esf5152609qtg.6
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 16:34:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632267254; cv=pass;
        d=google.com; s=arc-20160816;
        b=xiF6+Ke3Kem8OYV4pon+pl+YzUDPV2pvEa8Guqzug4nr/SfaOcgPAVKlea9jS7fCp2
         0LCDFWGeaO6FaXPZEt3C/C/o+45eVztTVpEkaOzyLsutz9NKP3gWxneVDoBJI0DLDjiR
         rsourHfBF4I0Ae4us5dnMIm1cblQfQe5sfBsvYAwpZN6umKQuZyZUZHTc2UhSljv58PU
         0WMrVi1VEXMVjWnAXnrSPkTAdIrbEVH6UftJlpzEBsEYIu0QXjeEMJklqSn0ArDP6+Qa
         hioe8kGlDkcxJ6ekL1ETRyJ4iK4YqUBG8JHAR5+q1B3nBoQM3NeZweVIpma8onpPs4KB
         f+DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Ra0Tb+vFbDVHPByxDdBapp08v0TpHhim/7iE5tTxlPY=;
        b=Gc/vkxPRtu39PUkZ4p2BerCVD2eGhvrMINrP1EsvANPFu4UpVhvZmM1IRHaAoOpt21
         Q0s2PGvaI1DMH7BzIrhnqI4VF1niCYQwgQx6SOUXsHwMsQOsCd+h171K8qwIff+T7VHa
         f9UO2LR0Xxci5pyaSPjMsUn4gH7749YVT8ZiYlSCBVwVV13yXm1DjPrqA40HsoErNCbE
         pzEjul8GqPZtrohbsQKY9wH0In0Y75dKOjrg+N/o5rNgc5qmUk/NU1BeY9szYt0DXS4b
         LAPz0sxO5JyOxsKLVX9mvmObqvcbFLeOW4PhE1CgkHUBe1Sa84utPpU6q7dwWVJeYqZw
         dt9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZvuPio6q;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Ra0Tb+vFbDVHPByxDdBapp08v0TpHhim/7iE5tTxlPY=;
        b=JNcEAlzgGudiMcKhGCO1GHrTX5u5xNjwPkEU60C9BQ/TVUXU6/e5q3u+D1beyDHofE
         ENHizEpPAr3cDEkI2rJdBD0TMTS1b+ZP0oCwLydDew7sCDYbd037IngoFR/DBLPe6Q1J
         FEbtzIKX/qGRSv0ZipBrXZrOvuL9iPvX3g/bp60qhgglgvfw4cevgDKyXBFXL3r8IZGx
         dPpPNJn6fzsdtsjv1JDArWuFz7uAQMP2SuOg+dfeeU2GD/3HK6tsc4JKxZ7xernexRH0
         6txgPCcxBIK1hCSf4AKkBdRSCNi3uA7lagnSr/X2wG3z6qftEk2xpADenPt13QyzEgSt
         P6zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ra0Tb+vFbDVHPByxDdBapp08v0TpHhim/7iE5tTxlPY=;
        b=zEXsQbkwCbuRKgKftR6/O0NVEfnzlpDfuPwb6gxH9lByydaPo7Me9R1K/u6J7wwrSB
         kvovnSNb3duOKhTHwh4fUUEH+hjkByU2myniTWQHwVAVljzhObeKLMqt7ePstAv04BN7
         BT8Tq5kVDR5A2u/BSpjrrNXR8SdS9TKSVn9cC2S7vn8cDuHczngTMPwXNVnYVSkJ77eS
         J1S+VP3ZEqupk0dt4T9QDOw3Xwig8dru2nNlICNDVjSy26SaKSfHoqZAmSpMKwTK7QUa
         PX/I4D3CG3PAT0h4Fpvv7nL3CeQAwPtqOQY56MzoRpGNADUsY3sW5esq+yph/BbVtd9C
         4rtw==
X-Gm-Message-State: AOAM53053AhWs5f3bTmiWhm5a3OfwoRZcZH/CjTgJ3Pa2bKMTl+8h6Bx
	DW/NtGot2Z+anHJ1vVH/E2o=
X-Google-Smtp-Source: ABdhPJx+F0d9WI+5qxzciq8iH9DGG5sCEa9rN1/aNswsUosF2+OSnnzAQc4ODk0OzhMzrLp8ep3pbA==
X-Received: by 2002:a25:d28a:: with SMTP id j132mr40029111ybg.224.1632267254682;
        Tue, 21 Sep 2021 16:34:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:566:: with SMTP id a6ls233842ybt.0.gmail; Tue, 21
 Sep 2021 16:34:14 -0700 (PDT)
X-Received: by 2002:a25:528b:: with SMTP id g133mr1676852ybb.128.1632267254221;
        Tue, 21 Sep 2021 16:34:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632267254; cv=none;
        d=google.com; s=arc-20160816;
        b=wIfVBITkGuBuYZXmyIAn6T5hvk1fDRvxWMQULPZH6sXA06sjx+JTE46IFkwhh45ewy
         WdgGztFZXtuWSoq7hLSf7xFdN5dyFg5hdvuDnJCe3ZqdhcvrgF7W5TQL1lc3yopvNpya
         3F5iSEIVaA8Xqm+YdkSY5S7MYlsE0BIiytG2L8KysFFkM7tF0JPHdCKLq2g7XiEJi9JL
         YT3nOi0GKcGSUcVdqIaB6CGjKq9AizTNJB3RpaVVgUm4Nl6mQc10JkQmK+pn7nTW/dUY
         4UgbzS/lgy/AGwLHjM3X69F0RTwGSzqBlQU0LgDPguBGKlo1M6azXHzJN1rxZOVkJNpV
         ruxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CLwXFb9bh237p3NLMPDDN3QcXe2KmKQWVOAqgszlTS8=;
        b=tGm3LhKEo9jmrm0JZTXGPsngm5jGqEfYwgLiask6sSGj4sEZGnkhYmfY6U4ZGeQ+pe
         IVhrqquE/FI0OvdTUCnv0UuE9nEHUNyW/6uiG1Z6Ys5klemX656u2nUJ/1k/a6wXUOwp
         LufeG/+GP0W3CMT5X/iXRBOFjfc+kz+Xq8hvE/ddZwzNEwpqvxoOOTh48KaNf0Tn5xc8
         4HIHbtodVKRhufF6G1dVQ6JHEQjGVD4GOklSNTHWAD4DEDwfS0O16TUqvIKdtUid7QMi
         legt/52xOLBEMrxurn+9ITYpPZ5dc3Ze4FC9SZk9iJ0V1aJXT60lhM4VpU6w3yJNZlPT
         F57w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZvuPio6q;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id k1si21622ybp.1.2021.09.21.16.34.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 16:34:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id k17so1043305pff.8
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 16:34:14 -0700 (PDT)
X-Received: by 2002:aa7:9282:0:b0:3e2:800a:b423 with SMTP id j2-20020aa79282000000b003e2800ab423mr32998153pfa.21.1632267253615;
        Tue, 21 Sep 2021 16:34:13 -0700 (PDT)
Received: from google.com (157.214.185.35.bc.googleusercontent.com. [35.185.214.157])
        by smtp.gmail.com with ESMTPSA id g3sm161923pjm.22.2021.09.21.16.34.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Sep 2021 16:34:12 -0700 (PDT)
Date: Tue, 21 Sep 2021 23:34:09 +0000
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>,
	syzbot <syzbot+d08efd12a2905a344291@syzkaller.appspotmail.com>,
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org,
	syzkaller-bugs@googlegroups.com, viro@zeniv.linux.org.uk,
	the arch/x86 maintainers <x86@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [syzbot] upstream test error: KFENCE: use-after-free in
 kvm_fastop_exception
Message-ID: <YUpr8Vu8xqCDwkE8@google.com>
References: <000000000000d6b66705cb2fffd4@google.com>
 <CACT4Y+ZByJ71QfYHTByWaeCqZFxYfp8W8oyrK0baNaSJMDzoUw@mail.gmail.com>
 <CANpmjNMq=2zjDYJgGvHcsjnPNOpR=nj-gQ43hk2mJga0ES+wzQ@mail.gmail.com>
 <CACT4Y+Y1c-kRk83M-qiFY40its+bP3=oOJwsbSrip5AB4vBnYA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Y1c-kRk83M-qiFY40its+bP3=oOJwsbSrip5AB4vBnYA@mail.gmail.com>
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZvuPio6q;       spf=pass
 (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42b as
 permitted sender) smtp.mailfrom=seanjc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
Reply-To: Sean Christopherson <seanjc@google.com>
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

On Fri, Sep 17, 2021, Dmitry Vyukov wrote:
> On Fri, 17 Sept 2021 at 13:04, Marco Elver <elver@google.com> wrote:
> > > So it looks like in both cases the top fault frame is just wrong. But
> > > I would assume it's extracted by arch-dependent code, so it's
> > > suspicious that it affects both x86 and arm64...
> > >
> > > Any ideas what's happening?
> >
> > My suspicion for the x86 case is that kvm_fastop_exception is related
> > to instruction emulation and the fault occurs in an emulated
> > instruction?
> 
> Why would the kernel emulate a plain MOV?
> 2a:   4c 8b 21                mov    (%rcx),%r12
> 
> And it would also mean a broken unwind because the emulated
> instruction is in __d_lookup, so it should be in the stack trace.

kvm_fastop_exception is a red herring.  It's indeed related to emulation, and
while MOV emulation is common in KVM, that emulation is for KVM guests not for
the host kernel where this splat occurs (ignoring the fact that the "host" is
itself a guest).

kvm_fastop_exception is out-of-line fixup, and certainly shouldn't be reachable
via d_lookup.  It's also two instruction, XOR+RET, neither of which are in the
code stream.

IIRC, the unwinder gets confused when given an IP that's in out-of-line code,
e.g. exception fixup like this.  If you really want to find out what code blew
up, you might be able to objdump -D the kernel and search for unique, matching
disassembly, e.g. find "jmpq   0xf86d288c" and go from there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUpr8Vu8xqCDwkE8%40google.com.
