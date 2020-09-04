Return-Path: <kasan-dev+bncBC6LHPWNU4DBBYNOY35AKGQEOFQ2IKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 30EEB25CF0F
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Sep 2020 03:24:50 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id a5sf4691315ybh.3
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Sep 2020 18:24:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599182689; cv=pass;
        d=google.com; s=arc-20160816;
        b=KC7DYfH4NEqWGPagrXbzNnNb5LqUQo+XVryweoNW+2C7pE3bR0SWtvqx1BB6I11OjD
         Byh/CMkTwPrx0KtB8l03VqOGzLhUnmmjSAboD97rlkzcdJtEIR+aUoqJ5gGe/dgSP5Rl
         gWUeVL7SFMCyugPiEQe6CjtCY4sY7xdivcDI2tjalO9FnS8Fg6sOtjI7T7tfpWbn5Dke
         h2GSVG0+G153u3K2PzR+GVpidqXPoFPqa4Lz506SNGOCQ4UMiIE65gEB1piBwQVoKSaP
         blylCY1MZ7oEV0HT0U3mJFRF35atOjP3LAuCOVpGUIJmSehmn5MPpdx5SelTomf5V8nW
         eqYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=JmguXRXmdfrn3xePpNWFi2mZghWBXq1RWLYn3hZulHY=;
        b=PoM0iUX4Geg4K5GJ5u5V2OZ0svtUeLwWaljM/Ng3FnKrjPnK491Fma7Cgb5ozKvEgy
         8JV9CWDKZ+JCB4aMAvOTfIAPzprSUqjZdqkqqgW9wV7lCtIKnY2LXLiIrMZwEhjfo44Z
         GRQrYr8sjU6L23zK+LGMhwlPi76rore+XI8oOIgyRJaLEWxnh7NFAWPsis62gF8JNdaU
         N+TWM4m04BMrKSh2GbrTYcV71uEnRVxSpL2uzSoWCCpPaJuXj1TYeJXK11WtsP3eP0L/
         sCrTFRAhaC4zKMljSXCXTl8NPvz1A9xrFTjFTTQ1DZlLt06QmzjqX26LXPTicfGysVqF
         frXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="T/jIh1Jq";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JmguXRXmdfrn3xePpNWFi2mZghWBXq1RWLYn3hZulHY=;
        b=CvC/R2PiWI550r8mSfSHblvv7ugE2JU5bQ7y1Wl1d5GRXrRCJg6Ci0czem+7jn24+Z
         R6VIkfwRWgER04PdcnySAWvK0MBZaVup2kdUe+mhOKaDgmUNds0QNRwr1yXNq3O2FTFh
         iXOKsQxPQapE9nfocDK5cyfVzecQH4DoT11mWzbLwv8P8p2vzwBCR9E/hyGkdR5zuNEy
         WuGuXkDqdY8kvw+u3J2qLsVD1l4LbRESENoPcymncFL66S7LTDFpvrwuL/F4XImDGrCJ
         Zv2SXgefk4M6RMVJryjCGIHr8a9UIoVUO7XwGKqqi6gNvHvI44I35uF0eDUQxrxxd9wc
         DPHw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JmguXRXmdfrn3xePpNWFi2mZghWBXq1RWLYn3hZulHY=;
        b=FCgw9WSRzglu4cixH8Q3loM9O/1yDXyqMX9eZ19V8d377O7ErQ1wkDRu6MC4qerq/N
         0O2Pk3dRF41mxa9dP6kcEo/RyT2d41M5kj+KqEMAGe4E7iOs7wkBDG4J+G3GNwqwsacJ
         hWhlaby1yFYmdjw5l7OqsFXBn6imUyW6RZ8cxEg7KrbhSdKqg+9IvbT9AmxQ+QLFQvB3
         rinMMeH4EPRJ2PW+PQ/BgXg77zeXl2fxDMxoQmzVLWnKBtWwvDbHVwNh1EdYkXuvPUJB
         x4MxHymWcxwMrkvRZkCfEPipv5G5JnITEVw2ob8JlAoP2uF/nLuyJ85dA+xeWhpkfBEP
         DdFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JmguXRXmdfrn3xePpNWFi2mZghWBXq1RWLYn3hZulHY=;
        b=cyGjazeO+oio24IoOfZnlz/dNeU5SKjdoIIrAooKq7jv2M5nbFqbSUwvYBJE8EDQue
         DstgmM79XT1x8jN9ZPbEJMi7nShfrzuDRAK4z5h6A0BTJk0O+k76MZuZsJ7ZMzrPLwvP
         0IYZqG5KoMjbvac+4riGACnSLH2MJDYSM0oxOaUdKSYsaKV4R/WUZwJFoDebY+okkXdv
         +BG4MRBX4UZzUu9gFcb6JiuXgSNSXNNVFQVRuRjHQhtyCHAu5MI2HARAkYD1lEM9i/sY
         R7h+d+9Qb+IG2TekHwASBZUQjHAkGhlTc7mRBLrf2VgTTX73jWRFav3SSbfMDoTeoQEF
         IanA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uoOEjXEthvlVDiuwzJu2w9IvYTexOCqV2ZI0BPhacrF00n3S/
	BnwUcN3XtXHLKWvNPMYhoF4=
X-Google-Smtp-Source: ABdhPJyM3lTU9ifbpQlAlc5q42O8ojAhw5jcOmSC1VaXBRViRzA/Mj8u8IB2PmBpWbr3Pq+w7RfDww==
X-Received: by 2002:a25:aca3:: with SMTP id x35mr4881430ybi.248.1599182689181;
        Thu, 03 Sep 2020 18:24:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d4d3:: with SMTP id m202ls3630551ybf.6.gmail; Thu, 03
 Sep 2020 18:24:48 -0700 (PDT)
X-Received: by 2002:a25:83c4:: with SMTP id v4mr7274863ybm.109.1599182688736;
        Thu, 03 Sep 2020 18:24:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599182688; cv=none;
        d=google.com; s=arc-20160816;
        b=oBmhe0Kop0dXRHZ+shZSNdAftVpTZBjV7UHInmDWZZpThx8e7yYRUGvUV+mXFiMU/K
         WVh9Jj3hS1i5BtD/8OWBsclDwAu1VF9yafE5DXdJLigaYoPw9k4dY16WOKhgUDSGhvr8
         mbidgRfzxjH9aVqTOk83hMBYq/tDdzECqhMqwQmdLX++JBu32QfVanZGas7qRbDD1osU
         6G3ejGODmFHypWKMMtYAx3es1O5lD8aCu7F+Wwc4xOM0Iouwh0e1gSjskj8F5hA8xMC0
         aVluS2vmN76BeUPX0y7nsEhGb53/sBu1b78X2XftUtJ2wpSoFl7LsavALC5VB8leK+Km
         8hRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DCar6p+BerNTwBIOjSSDhhKMTYZUeaLOP7U1DRIXsek=;
        b=fxryBX2bKZaTYGcHtWkBqBf+MhK5k/rq4REbX+5xTGGx1IL6KeZpZghIKHaLxk1TH9
         a1Wbzfkd+x8/6Smb/kDGCK68YMHRMLfb77vqZP2vHULbPmHb3VM743d44jt7LKEzm3QE
         Rgluki30+3+J6DCzzcU1AoxbBxQ1Q6ZsCbAoXO4igZsxYsNsI3IOkUNdgW9W6ZwSUDGl
         zHPlDrjWoomV2dQlpTXFpxs2UGf7Eb5LxXdlQaWu63zE0laDSy8QBsu4+UHdrYeqoKBM
         2E+1JlQMGfN0dZ0PWJZHF8DAcwe2tqVjlJX3zM0NAyGpTyvHAR5zEFZhjaRKEfPS7K8n
         dWgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="T/jIh1Jq";
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id y18si400824ybk.3.2020.09.03.18.24.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Sep 2020 18:24:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id n18so3575360qtw.0
        for <kasan-dev@googlegroups.com>; Thu, 03 Sep 2020 18:24:48 -0700 (PDT)
X-Received: by 2002:ac8:1417:: with SMTP id k23mr2212424qtj.89.1599182688424;
        Thu, 03 Sep 2020 18:24:48 -0700 (PDT)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id b199sm3435069qkg.116.2020.09.03.18.24.47
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Sep 2020 18:24:47 -0700 (PDT)
Received: from compute3.internal (compute3.nyi.internal [10.202.2.43])
	by mailauth.nyi.internal (Postfix) with ESMTP id C9A6427C0054;
	Thu,  3 Sep 2020 21:24:46 -0400 (EDT)
Received: from mailfrontend1 ([10.202.2.162])
  by compute3.internal (MEProxy); Thu, 03 Sep 2020 21:24:46 -0400
X-ME-Sender: <xms:XZdRXx0khH3mFpusNE0FWTbI27XoZoNUf310TpnOgpjcfS3jE6N38Q>
    <xme:XZdRX4GKZ-LBJSbbXw52euf0aa15V2P4qJuSLChJdmcr1E-Ru0Uwr4pp0xC2NsYMb
    Pqp0jfIHeKXY98mzw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeduiedrudegvddggeeiucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepfffhvffukfhfgggtuggjsehttdertddttddvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuggftrfgrth
    htvghrnhepveeijedthfeijeefudehhedvveegudegteehgffgtddvuedtveegtedvvdef
    gedtnecuffhomhgrihhnpehkvghrnhgvlhdrohhrghenucfkphephedvrdduheehrdduud
    durdejudenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhm
    pegsohhquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtd
    eigedqudejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehf
    ihigmhgvrdhnrghmvg
X-ME-Proxy: <xmx:XZdRXx430vCqn4Z8PKiCIiUGxPkdWgOjTmf7XyvX9b9Vj_-xxoIosg>
    <xmx:XZdRX-3XkX-ReXSr4PEkKbssjCUWFWwL9FuhNO1K_PGtUidk3qpKYw>
    <xmx:XZdRX0Gi1yn70Cc4y4aDVjZHtIRCaaxzxTN9D8_AVIasa-5Pw8ynIQ>
    <xmx:XpdRX4Fyvw814QnuW6MVseWbKWf4oFuBHC9_QQ-aEhIJOHee-WIVuQb3nHg>
Received: from localhost (unknown [52.155.111.71])
	by mail.messagingengine.com (Postfix) with ESMTPA id 4B806328005A;
	Thu,  3 Sep 2020 21:24:45 -0400 (EDT)
Date: Fri, 4 Sep 2020 09:24:43 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, kernel-team@fb.com, mingo@kernel.org,
	andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	cai@lca.pw, Will Deacon <will@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Daniel Axtens <dja@axtens.net>,
	Michael Ellerman <mpe@ellerman.id.au>, linux-arch@vger.kernel.org
Subject: Re: [PATCH kcsan 18/19] bitops, kcsan: Partially revert
 instrumentation for non-atomic bitops
Message-ID: <20200904012443.GB7503@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
 <20200831181805.1833-18-paulmck@kernel.org>
 <20200902033006.GB49492@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
 <20200902061315.GA1167979@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200902061315.GA1167979@elver.google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="T/jIh1Jq";       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Sep 02, 2020 at 08:13:15AM +0200, Marco Elver wrote:
> On Wed, Sep 02, 2020 at 11:30AM +0800, Boqun Feng wrote:
> > Hi Paul and Marco,
> > 
> > The whole update patchset looks good to me, just one question out of
> > curiosity fo this one, please see below:
> > 
> > On Mon, Aug 31, 2020 at 11:18:04AM -0700, paulmck@kernel.org wrote:
> > > From: Marco Elver <elver@google.com>
> > > 
> > > Previous to the change to distinguish read-write accesses, when
> > > CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y is set, KCSAN would consider
> > > the non-atomic bitops as atomic. We want to partially revert to this
> > > behaviour, but with one important distinction: report racing
> > > modifications, since lost bits due to non-atomicity are certainly
> > > possible.
> > > 
> > > Given the operations here only modify a single bit, assuming
> > > non-atomicity of the writer is sufficient may be reasonable for certain
> > > usage (and follows the permissible nature of the "assume plain writes
> > > atomic" rule). In other words:
> > > 
> > > 	1. We want non-atomic read-modify-write races to be reported;
> > > 	   this is accomplished by kcsan_check_read(), where any
> > > 	   concurrent write (atomic or not) will generate a report.
> > > 
> > > 	2. We do not want to report races with marked readers, but -do-
> > > 	   want to report races with unmarked readers; this is
> > > 	   accomplished by the instrument_write() ("assume atomic
> > > 	   write" with Kconfig option set).
> > > 
> > 
> > Is there any code in kernel using the above assumption (i.e.
> > non-atomicity of the writer is sufficient)? IOW, have you observed
> > anything bad (e.g. an anoying false positive) after applying the
> > read_write changes but without this patch?
> 
> We were looking for an answer to:
> 
> 	https://lkml.kernel.org/r/20200810124516.GM17456@casper.infradead.org
> 
> Initially we thought using atomic bitops might be required, but after a
> longer offline discussion realized that simply marking the reader in
> this case, but retaining the non-atomic bitop is probably all that's
> needed.
> 
> The version of KCSAN that found the above was still using KCSAN from
> Linux 5.8, but we realized with the changed read-write instrumentation
> to bitops in this series, we'd regress and still report the race even if
> the reader was marked. To avoid this with the default KCSAN config, we
> determined that we need the patch here.
> 

Thanks for the background! Now I see the point of having this patch ;-)

FWIW, feel free to add for the whole series:

Reviewed-by: Boqun Feng <boqun.feng@gmail.com>

Regards,
Boqun

> The bitops are indeed a bit more special, because for both the atomic
> and non-atomic bitops we *can* reason about the generated code (since we
> control it, although not sure about the asm-generic ones), and that
> makes reasoning about accesses racing with non-atomic bitops more
> feasible. At least that's our rationale for deciding that reverting
> non-atomic bitops treatment to it's more relaxed version is ok.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200904012443.GB7503%40debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net.
