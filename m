Return-Path: <kasan-dev+bncBDEZDPVRZMARB4G6RGDAMGQE2VTAX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 60C0F3A3467
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 22:00:49 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id z3-20020a92cb830000b02901bb45557893sf2068785ilo.18
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 13:00:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623355248; cv=pass;
        d=google.com; s=arc-20160816;
        b=n3y8mqUrNlHCHWSVwQNUA/QTprobwMVV/GUXT7qQJPOkv2QWwdWJSGeER5MkpWEaxN
         a3aSv5vW9HQI+Lzl8Q2LoKivubt6o/uc0mZr9luJsXW5+HeG2lIgag/tHs8q07EDHVRZ
         5XDzhoz4CRGnVcGDMKYL49ckHi45O/RpyKTHj1XVd24Lwdv576Sl5KgIg8dti8lLPRUL
         HKW3hpS/6F6QQwxwIeC8gcRAdlTPKLEMruq3SHhLKFtVQf4CZx4P883H5t7cNckj1Wq0
         RTVSerlN4Ia2CX0FrDQcmeDErvNBelc/FOXoU0cnLqEBLk8GNdPuRKoOsj+OnhEkJ7dZ
         mHnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TlLRyarHGbIOEW1ADKrieuUqbGAtzNSbgtC43GcwyK0=;
        b=IT4NQtNWna0Ve8jsBxpHrhrnRE2OFswHuPsLzqQcycaq/ZvOIHPYW9ZUXt6Dcwtd5L
         fLUejLgq1nnYPaAOFuxyfs9MK4yjpMBgCaCtriaqf1HQEVUZ7SDygMKRQKzKsoZO0o6C
         2juB/5GLAhtVuCT8Ah40v+x+Q1hOp7xgJ1wIo2WbBmMih9xMM/n2Ul+e95uMN8nNaOuW
         ZXNkaHIs3nrrapUiFhldOYbT01kaRpUpqXgee8/X+yA7ICNviXUS7E1VBtZpCHEWA2XZ
         Qz3XOCKRwgrHf/qeunP0STwT8H6znu22xwcZPfF7knu3Eb+yy6+yEGN0XfenE9kblv1N
         wtlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=it1PG+R5;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TlLRyarHGbIOEW1ADKrieuUqbGAtzNSbgtC43GcwyK0=;
        b=rQEBT1F1axrNVDtTKSyUaJUOsWA3Tp3yLqGLBvZQOoSBD4hOsPv2z5qrzTt7rNzZHv
         rVnkDNc0FsrtJaRM6HfpXX8x+kZQFog7qvBFPA/zTv49e1h+XxMUyKS3hizanJcGIHfv
         uenSLKWTgRekDb1XIh0JDk85ObuFxYvmqPeQ+dAdOmJefjQk8y0mzWQ9CUnnPgaKpO1H
         fIIRVjO0qpltZ95g6EsZXthUYGn0GVF3eMaAgycFUN/dZZ5Gbu1pOLLwg44MvDvkLC7a
         Xti7wQ8+FuF72PnNhPYCSvsJ0MDhHwT6s6/zJ7Z/7A83wslCcM6u3cIz9KyJU8UzO5as
         z3nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TlLRyarHGbIOEW1ADKrieuUqbGAtzNSbgtC43GcwyK0=;
        b=bGg08iQoXmQFBYMSJtNNiewMu1zEQozQH4afxQIqu+rJwCb/2i/fPr44yeRfoHev4h
         W1PbXbKwPfYrQJdFZP1U/2yVdzyRNPbf6xDG7/QixCawXVJRG1f79TDOu0irKX0KKgTu
         tIc0oHvHPLZ33TQNtttW6ZOwFzvmC4T+M211MzgQy7kVbcqa9okJUIm7lgPsTX3fgseE
         L7an+OT1dsFXZ+I6HDDBqFInc80vcenmhCsFYUQ6WrWOy9Ux2kXraocCNMmWbLOZFQT2
         lk5dGpLWKK0FYdBEOEwXAd5R5ZAIT6+mpy6j+Sc8YvDm4NcFWAu+Ff4Q99GQZBdg8U/g
         5P8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QpvpE6fXHssAithg7D8KqmPuTsH+r6S9RAYm8ByOxYstTA0mK
	CJlUkZ5KSwUZxxdUyCeo1HU=
X-Google-Smtp-Source: ABdhPJw0PAKFJhxQWtvZI2cHICgdrEPFSWhJBOEV5y/QuIpiC1X0rpGw3PfiVUfO3SGGUT3r7Jttjg==
X-Received: by 2002:a92:660f:: with SMTP id a15mr411474ilc.182.1623355248122;
        Thu, 10 Jun 2021 13:00:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:68a:: with SMTP id o10ls1927244ils.3.gmail; Thu, 10
 Jun 2021 13:00:47 -0700 (PDT)
X-Received: by 2002:a92:d4c6:: with SMTP id o6mr364744ilm.196.1623355247728;
        Thu, 10 Jun 2021 13:00:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623355247; cv=none;
        d=google.com; s=arc-20160816;
        b=JhCj/dxAC1bpMzmEm6V7h0bo5mdNqKhh9PLzVtwhN1Y1AkaJkz9Ybw7oe9kBAYVwA2
         Dq/Z4s26O1VNzEqdaI3wvFcIn3FTtuGJRMsd70BWpdNVHeSrCIflo63uZI8DGJL1ZPHI
         Qsex9O3l20hebMg5NyQhXHX0lXeTa5vsmRElM5kfgs6r/mx+XO+incAwbFKwRMCVHnAr
         CT3lHs1HBMMqZtlsxJxayBeHq3fKpNm2AcgzwjNZ0TXGxSIIrDzGkED9JmrIGCUzYngq
         SeZkTlyK9/D1LzE/LQvAKnPXgJ6aDdPxxB1p8yYJ5DyR+bHRc2u5gKGGM22tt5pn+KMY
         KuJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VcQcVK1muxZfeixLAT70inWCF+rrO79FtgsqXLLTmhw=;
        b=NZ+OfCgq0lsAXJTYsivTuws/zErELimvfIrB97F1GkNqOkZsVyZA+BZCMxGcCvoUwj
         uvC3z6q47zSo/xROkx2TwvOBrquF0jIjhNi4PeqwYP9ptTpl9gW35unZhvelnMrpDBJF
         stHv9+r/5RZt8+FXLbh+EDvsmAJOMAeSpSPpgPgC9ToyeSCny62G8aoNH4Zlu9zpZSe0
         RDlJuoJboTqwh2YpDH65EECf2faEzS8q11vmV7yGikHjtnozXsZ0UWIYCki9h7yMjN8n
         3T6RVMzgF7ES00vuhbSDPekB4Ase5ZC7LYlVQhsT+njLNrBgkzqLGe+bEyx0rlr5f5y4
         Hlhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=it1PG+R5;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x13si487843ilg.2.2021.06.10.13.00.47
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Jun 2021 13:00:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2DAEC613F1;
	Thu, 10 Jun 2021 20:00:46 +0000 (UTC)
Date: Thu, 10 Jun 2021 13:00:44 -0700
From: Eric Biggers <ebiggers@kernel.org>
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Kees Cook <keescook@chromium.org>, Yonghong Song <yhs@fb.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Kurt Manucredo <fuzzybritches0@gmail.com>,
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
	Andrii Nakryiko <andrii@kernel.org>,
	Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	"David S. Miller" <davem@davemloft.net>,
	Jesper Dangaard Brouer <hawk@kernel.org>,
	John Fastabend <john.fastabend@gmail.com>,
	Martin KaFai Lau <kafai@fb.com>, KP Singh <kpsingh@kernel.org>,
	Jakub Kicinski <kuba@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Network Development <netdev@vger.kernel.org>,
	Song Liu <songliubraving@fb.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, nathan@kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	Clang-Built-Linux ML <clang-built-linux@googlegroups.com>,
	linux-kernel-mentees@lists.linuxfoundation.org,
	Shuah Khan <skhan@linuxfoundation.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Kernel Hardening <kernel-hardening@lists.openwall.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v4] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
Message-ID: <YMJvbGEz0xu9JU9D@gmail.com>
References: <87609-531187-curtm@phaethon>
 <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com>
 <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
 <202106091119.84A88B6FE7@keescook>
 <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com>
 <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=it1PG+R5;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Jun 10, 2021 at 10:52:37AM -0700, Alexei Starovoitov wrote:
> On Thu, Jun 10, 2021 at 10:06 AM Kees Cook <keescook@chromium.org> wrote:
> >
> > > > I guess the main question: what should happen if a bpf program writer
> > > > does _not_ use compiler nor check_shl_overflow()?
> >
> > I think the BPF runtime needs to make such actions defined, instead of
> > doing a blind shift. It needs to check the size of the shift explicitly
> > when handling the shift instruction.
> 
> Such ideas were brought up in the past and rejected.
> We're not going to sacrifice performance to make behavior a bit more
> 'defined'. CPUs are doing it deterministically.

What CPUs do is not the whole story.  The compiler can assume that the shift
amount is less than the width and use that assumption in other places, resulting
in other things being miscompiled.

Couldn't you just AND the shift amounts with the width minus 1?  That would make
the shifts defined, and the compiler would optimize out the AND on any CPU that
interprets the shift amounts modulo the width anyway (e.g., x86).

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YMJvbGEz0xu9JU9D%40gmail.com.
