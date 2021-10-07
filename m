Return-Path: <kasan-dev+bncBCJZRXGY5YJBB47J7WFAMGQEBUSHBBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 04D9F425FDD
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 00:30:13 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id c8-20020a4ad208000000b002b6b6df6b7fsf116260oos.13
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 15:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633645811; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fzx6R+sIz2KHiWUuByqgjAe6PCpITX6siuYZjmzCXaP2A8qDdkXyznTawL5Hdyv3Gh
         BEv4DzbjHIlQkMd50EI4b7Up1NyeWCiBl7YYGuHdf+ejiI7UaMlQCnL/YH79PIsQtKnK
         mXfx9/I1J38AVopormo74jMaLF9BMQ5EWLHtXN07WtszCggmP+J94bZs+4f1CDWSLBWG
         W01vgbDDH1wY0he7WaTGkvgKWUYGiBqcsK9ZI63Vbx+kla7SzyadCGk7vZhO+4khiJzm
         sSYw0fs6P0gioGy7GVGSNi0+Idia322IySjEMw/4n6xx6Hqt/rPYYUEzyouSyfngva8s
         Sf7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=oREvqUMdAk+mKMmV3236QxzAIkV0GH7+6jk8FD+PbAE=;
        b=r5Q0LhW9h3tINos8ztNsOsko8ssRxZDdJC/GcjVpmUtwXTCv2BhHAEFka1kdeyId3Y
         BI0EmQSWwVryljJug7lZYkDUNyWrpPaZxHKJ50h07ZYjBYineJQNDl+wn9VrnizQBo2/
         rx3cOLNoNwTtV8feHm2CMdmzo6CBu5N1fEa4zbv5HYSmW6rCAmhP+yhONQcrdCorzUrn
         DgWSh4dspAY9GTtqOaIjD3rl7zQB0r6pUeFMdq/MV5w/ZlAgRXHH9VCYygqqHgzsUAcq
         pPhrSws7diqvAvgKN6S9yQaa9KVdeXnmOJ0K7jAYNW8MwAKNsk7TfWNMwHDq1vsocMez
         gHug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=myPIN3IY;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oREvqUMdAk+mKMmV3236QxzAIkV0GH7+6jk8FD+PbAE=;
        b=IdeSM8pYtGo/hvxF4DOHQEtiVsXAQd8p6rA2nHuDya+eO5x0t2M1zk/jGFtiDEl871
         GQYfKs8K0rSc/GAP1Nwu9qBZqbKbxoxyXpCJOE7LQwZ7kSVw3awps8qGo3GOo7MlIFda
         cGAm6fWWyEx506gMCXBWcIvtfZslh+CvaU1aJzNNJs5rRMy50njXTz0n/77mBQWqSTAh
         URUERLd0HElNyCjpoglAMvL4Inw3PjMP0nlcnC2/j8i17GsJyR7JaJ5ko1LNtQxpNiOD
         ky5BK61WOFlqJ1ejNpTnuJ7o22exWlXwkv5my8up2+xkrju6YNLM/mVFdD29JfhUp51L
         /bcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oREvqUMdAk+mKMmV3236QxzAIkV0GH7+6jk8FD+PbAE=;
        b=YQ9EKE7XBcxA1R10f4d3m6t/VOLeHxAIdsXWqaOQ5uI1BGEr871hnsCGLP4WnTc/Q5
         qXqnpzyoXvaBnoCVVHHs8bS04UPY5cLssIygHNZ8SHrx7tWzE0GSUOakDjIIn5vstq/N
         8htRsRrB0wZuTBqJiPTcnRLYmd9MnuRGseOHToyH2jeEcCq+8TsoSdA+RIMBbZ6UIU00
         R4YyhG4/lXA9nA0nrxl3YmcLto76XV3LFF0VlXhQsQd2MDePoEW2QxLSSIGTnU3sJ/f7
         78Ybaynt3iPqXY/8RmN0a+04DqBGyYoMU8LV24teKZ/rXBiHuuOxSAxaezOmHWAnHq3H
         aaQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532o8ajJoL7SS8uIdOCWEw3ZvYMMkObb304Iw5OpK5stoUQXdOHs
	d+L8CDb/O1BzEqhbTe8fL44=
X-Google-Smtp-Source: ABdhPJyh00lzX8pftQnqlO032HIEvhPZ0zoeBxfnfZkI+DJa2e+XQZ0WljwwkypX2k7DEwoayCiFbw==
X-Received: by 2002:a9d:6c46:: with SMTP id g6mr5927042otq.55.1633645811593;
        Thu, 07 Oct 2021 15:30:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:318b:: with SMTP id x133ls430006oix.1.gmail; Thu, 07 Oct
 2021 15:30:11 -0700 (PDT)
X-Received: by 2002:a05:6808:f12:: with SMTP id m18mr13520268oiw.104.1633645811177;
        Thu, 07 Oct 2021 15:30:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633645811; cv=none;
        d=google.com; s=arc-20160816;
        b=qliKwQK7/9z4bnSwIId0LsTd+oConGF4N/yNp1VYbmehS7BZAIm8m/cNcuLk7uE2I8
         JMdELnSmvLW1DNTuDuzN6aJS7TnZYG2IIgFcNM61OJhW4y164oaMcaS0Jz4SKc4Ybjt8
         ah+y5GCVV+qXgV9GyI46py1sW1xzwEF6vBIF2lLfKS8pGU8xHaWyUqL+ACiBSRpGBRIk
         x7Eky0W6H/o+SanmUfPO+FozXbs4gCzbl3hHY1u4WiXXHRc9Vku68/fVTWlygMFkbsdd
         YshY9QulXtyG4bg5kikZPaqeaD958RYKj+yHpsSLXgbcq/xbNEeeZzNs7XistyE63LPH
         DzRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hf0UJ7Y/P4o3kOB5X10/cD70FzT/6bg3SdE9vsLk/vM=;
        b=eZiand7gjE3D35I3ygK+zmkMcPLEq9eF4EIjjZF7YzZ8wi7WA2okPu+KqZ3g+paC53
         yOcNcV/KD01dXuPEvQlzmlvKYygtXa4pcSRtZlmpA5epuaCRC6Rrypt+cmnSi+7MuOEM
         rRqQokYL89zs75g1fVpdS8F5WeVEITYCUUsCiHsYIxG8ZqO6cu7F8GyWr+lzUVdUp0Ss
         gvGjZQTDKXXrHZTYFnyzA7cmJtZe9DqOT8M0iSoeoIIGHUet+TeCf0kpbKELY5VyL4EQ
         wX15j1g9MBDUxET2oK+IQ4Ca9Wn0bR9QpVN7Fu7MfcykiXzr+c20JYNw/0ldAm+R4gae
         Pn6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=myPIN3IY;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e12si72840otf.1.2021.10.07.15.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 15:30:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6CA77610E6;
	Thu,  7 Oct 2021 22:30:10 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 3D0A95C0870; Thu,  7 Oct 2021 15:30:10 -0700 (PDT)
Date: Thu, 7 Oct 2021 15:30:10 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Gary Guo <gary@garyguo.net>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
 <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211007224247.000073c5@garyguo.net>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=myPIN3IY;       spf=pass
 (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, Oct 07, 2021 at 10:42:47PM +0100, Gary Guo wrote:
> On Thu, 7 Oct 2021 11:50:29 -0700
> "Paul E. McKenney" <paulmck@kernel.org> wrote:
> 
> > I have updated https://paulmck.livejournal.com/64970.html accordingly
> > (and hopefully correctly), so thank you both!
> 
> The page writes:
> > ... and furthermore safe code can violate unsafe code's assumptions as
> > long as it is in the same module. For all I know, this last caveat
> > might also apply to unsafe code in other modules for kernels built
> > with link-time optimizations (LTO) enabled.
> 
> This is incorrect.
> 
> The statement "safe code can violate unsafe code's assumptions as long
> as it is in the same module" is true, but the "module" here means [Rust
> module](https://doc.rust-lang.org/reference/items/modules.html) not
> kernel module. Module is the encapsulation boundary in Rust, so code
> can access things defined in the same module without visibility checks.

Believe it or not, I actually understood that this had nothing to
do with a modprobe-style kernel module.  ;-)

For C/C++, I would have written "translation unit".  But my guess is that
"Rust module" would work better.

Thoughts?

> So take this file binding as an example,
> 
> 	struct File {
> 	    ptr: *mut bindings::file,
> 	}
> 
> 	impl File {
> 	    pub fn pos(&self) -> u64 {
> 	        unsafe { (*self.ptr).f_pos as u64 }
> 	    }
> 	}
> 
> The unsafe code assume ptr is valid. The default visibility is private,
> so code in other modules cannot modify ptr directly. But within the
> same module file.ptr can be accessed, so code within the same module
> can use an invalid ptr and invalidate assumption.
> 
> This is purely syntactical, and have nothing to do with code generation
> and LTO.
> 
> And this caveat could be easily be mitigated. In Rust-for-linux, these
> structs have type invariant comments, and we require a comment
> asserting that the invariant is upheld whenever these types are
> modified or created directly with struct expression.

And the definition of a module is constrained to be contained within a
given translation unit, correct?

But what prevents unsafe Rust code in one translation unit from violating
the assumptions of safe Rust code in another translation unit, Rust
modules notwithstanding?  Especially if that unsafe code contains a bug?

Finally, are you arguing that LTO cannot under any circumstances inflict a
bug in Rust unsafe code on Rust safe code in some other translation unit?
Or just that if there are no bugs in Rust code (either safe or unsafe),
that LTO cannot possibly introduce any?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211007223010.GN880162%40paulmck-ThinkPad-P17-Gen-1.
