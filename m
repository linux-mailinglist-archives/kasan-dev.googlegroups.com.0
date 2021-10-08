Return-Path: <kasan-dev+bncBCJZRXGY5YJBBIMFQKFQMGQEE54MDGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D146426FB3
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 19:40:51 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id w2-20020a170902d70200b0013ed4c6e6f3sf5311867ply.9
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Oct 2021 10:40:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633714850; cv=pass;
        d=google.com; s=arc-20160816;
        b=rkZO9gkB5U7JBLg7bqZnZdRtP2M4/F8oeFdHVSirmSPMHjbeMnQqFc/k8xguEMAyk0
         X8cFn8Lpdz/DYIukiPRha5kfQHZXU5uyVsFHECVQ/6DjcoDOCkZmbmuewYMM/3HLna/C
         B43p2ue+PgJYk8VecDqQLie23+imSrCw41tHurHhCGsk7E5OPRkzG0Y72UM+xT/WEGHx
         e2RY0dUOf5t3bIlHnGYwfqPUPZKh9m5gRngp/W//9Wylf9xj5vWF3Ga9rqVMzCf0PO1d
         O7p8rWjYLGJ6eof4PXVlAJC3qUkRm6EmC3ij+rRZ2iUJiymepAAOHrcHwe3DjY9W8Xr5
         WFcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=2ESJrpQ+Ce9ETx7lj6+Y8Uo1pPZ5DVEBPRDtdnRI0Vg=;
        b=CnqYQoB+zV80OK5LbZfdEEu5A9JBkElmeZtmVPJ9cEIyOCUK/gdi816M5TiekyPOge
         /F93DJzFQtrztrestLHojnryaW2RakLrd/aTCY2DLjCDhbfBqgm6id9EcQktDQ3ORbPL
         A6ffuN6PNQPfYDp6nceV6qfg16G2+kiO5A39G1YZM1mzYiJHQbbTstPHcjAhWlFXYAdD
         kk4oEvZUY2rSK3zHh9knDXYzW7CQ7qGwmvGsq+Nea1oSkQxgXqtnkAnlK9cZSo32PRr/
         JAfARGegMqZmP5GqkvVk55pCMIVf82v2dK0ttlalRc50hxBvB3VdW6vigtKL2cyxEZT1
         nY4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o566nqtW;
       spf=pass (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pk/0=O4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2ESJrpQ+Ce9ETx7lj6+Y8Uo1pPZ5DVEBPRDtdnRI0Vg=;
        b=NpmfOQBjZ0GcC7amtKDM7XRBdYRcILQym13DuiVs5+WaUXIcjwWjnqNSoK7XdQE6+v
         rS24a/LscaGk7653jtFbR++CPQ7illJaYZVsLYLvMXJvVpHqKkFlzt1/i6N0Dd5X0+oa
         688XBZPLP5RV7rhD37T2yDp0KnDPpFB09uccgqQKBE09jv3ugZBb6UPIEYdkAhQFuRMR
         5QiSaDNaxDGa9TkhtAgJdVa1vyyZ6ZWLK8fUXxVdydB6uHdrBHQaqhp3ORUZUTFG2YSk
         syBY9UQiWoGVbEu5Uq3oIJLjQ2rH/goZUfFgH/yRcgOqS25qJIyWT0iCCjW7cfk/vSdj
         E/QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2ESJrpQ+Ce9ETx7lj6+Y8Uo1pPZ5DVEBPRDtdnRI0Vg=;
        b=naV60+Ts7jSQlZxZ0IyQKtxEUzbVNYlNU6s8aD+D4PZgmau0B3FW4b3ULIHgPrDkv1
         kAU27S0TkpktFiS9MwgXYg/EuKWzIuupNw228dplJhjuNwnRBJoYzXZ+uIY1cRfK7YW1
         v2xi666bCR6SXF/VymkYza8sZu0wFPZwsWeyQXsbCea9iYWLm15LLT2ySEQOuEMVDaL2
         6P2B7uyK7haU9EczWDUjLquyQGLG7y+n5g9hFtXqsR6+gkdAxxrCSIEy/W7JXGacPB0r
         myU+rgPpicOICQ4FHHiTMx8TQmTxWv3A7YS0zzJ6Up0Z1VfZGdT+/42duUZ2Jp5jPO+u
         N0Fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sHGptO2VvdVvRnpQJxCm87BsyiN7cyTDg/wvXMwJqEGnwL+Lb
	3+2S19DDe2h03IH507LK2PA=
X-Google-Smtp-Source: ABdhPJxwGhwHA/qD1ZlelN74H//dgfJWfQORbq+4Gx7FmhErXbaZ8f82zvW0HwwsC7WDiZE+srwGug==
X-Received: by 2002:a62:1e43:0:b0:447:cb0b:4c6e with SMTP id e64-20020a621e43000000b00447cb0b4c6emr11307561pfe.1.1633714849827;
        Fri, 08 Oct 2021 10:40:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6401:: with SMTP id y1ls1575725pfb.10.gmail; Fri, 08 Oct
 2021 10:40:49 -0700 (PDT)
X-Received: by 2002:aa7:9111:0:b0:44c:c206:ad9a with SMTP id 17-20020aa79111000000b0044cc206ad9amr9900973pfh.72.1633714849101;
        Fri, 08 Oct 2021 10:40:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633714849; cv=none;
        d=google.com; s=arc-20160816;
        b=Vh2vpRcQLpd6uwxxUbU7nCGu9qsyG81rQYM46AOGflI1c0wFBigAHezHE1XhSDCSwy
         oxPT3P+4pcH2AtjIxfPTrL37l6t96YeJD3HQEP7S3rWLx/CKNeCLfax9u6S72F/oJky3
         sMj5+wU417Fw5XLm9eBjciJKm+1jQzvUa+Vn+rgIuphyGmwlJAQ8TdIBTdhXeLlXtfQH
         DzQIW5DLHmfnGm2FBiiy71TTw/cxeDJ0tQZPQwZSgzcv4C7Vb6NZs5C5lBfFT3+vFU5h
         byzOtB8dEojhzdycBnSXnNiPW9PeAGtuD0MfWjUTZ5APSLQh64AVRQ24TiUhBPK4CQ+a
         aYaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=EjTGfe7P8yuAcTqVPHAfh2QYlcOORDEzyq0Nl14Br9g=;
        b=addan4HF25pjt/Fdoh0x6g9gyuCPbI3YR4pjes/aUnkJNrvnCXvDC5DyCKTCgVme4n
         3surupt3pxaMFLDNlzBXspAzBOS5v2Qeg2lV9JoQdNickzIPYrKXO0tWEWxkgnxjTPon
         ax5Ni6nD9jKXG3u84EyMccN8V14ZPdEj/fMeE6g7OFIhEMGjUEPLFEADtntKj6YPv9+F
         43EfIWc/aiiZSWuAhsVfnVgksgbFrfykK3477ReSRBr2w3AP0B8HX57K3dxznR8mEuna
         lIJGtIfjRivyXPx6iRpoxvCknrbqL53s3AaVKGKXEABDEhyrYdDblvcrYroeb4j+Eaok
         WBfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o566nqtW;
       spf=pass (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pk/0=O4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c130si486pfc.3.2021.10.08.10.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 08 Oct 2021 10:40:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CCA6160FE8;
	Fri,  8 Oct 2021 17:40:48 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9E0FA5C0AD6; Fri,  8 Oct 2021 10:40:48 -0700 (PDT)
Date: Fri, 8 Oct 2021 10:40:48 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Gary Guo <gary@garyguo.net>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
 <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008005958.0000125d@garyguo.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211008005958.0000125d@garyguo.net>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=o566nqtW;       spf=pass
 (google.com: domain of srs0=pk/0=o4=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pk/0=O4=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, Oct 08, 2021 at 12:59:58AM +0100, Gary Guo wrote:
> On Thu, 7 Oct 2021 16:42:47 -0700
> "Paul E. McKenney" <paulmck@kernel.org> wrote:
> 
> > > I don't see why LTO is significant in the argument. Doing LTO or not
> > > wouldn't change the number of bugs. It could make a bug more or less
> > > visible, but buggy code remains buggy and bug-free code remains
> > > bug-free.
> > > 
> > > If I have expose a safe `invoke_ub` function in a translation unit
> > > that internally causes UB using unsafe code, and have another
> > > all-safe-code crate calling it, then the whole program has UB
> > > regardless LTO is enabled or not.  
> > 
> > Here is the problem we face.  The least buggy project I know of was a
> > single-threaded safety-critical project that was subjected to
> > stringent code-style constraints and heavy-duty formal verification.
> > There was also a testing phase at the end of the validation process,
> > but any failure detected by the test was considered to be a critical
> > bug not only against the software under test, but also against the
> > formal verification phase.
> > 
> > The results were impressive, coming in at about 0.04 bugs per thousand
> > lines of code (KLoC), that is, about one bug per 25,000 lines of code.
> > 
> > But that is still way more than zero bugs.  And I seriously doubt that
> > Rust will be anywhere near this level.
> > 
> > A more typical bug rate is about 1-3 bugs per KLoC.
> > 
> > Suppose Rust geometrically splits the difference between the better
> > end of typical experience (1 bug per KLoC) and that safety-critical
> > project (again, 0.04 bugs per KLoC), that is to say 0.2 bugs per KLoC.
> > (The arithmetic mean would give 0.52 bugs per KLoC, so I am being
> > Rust-optimistic here.)
> > 
> > In a project the size of the Linux kernel, that still works out to
> > some thousands of bugs.
> > 
> > So in the context of the Linux kernel, the propagation of bugs will
> > still be important, even if the entire kernel were to be converted to
> > Rust.
> 
> There is a distinction between what is considered safe in Rust and what
> is considered safe in safety-critical systems. Miguel's LPC talk
> (https://youtu.be/ORwYx5_zmZo?t=1749) summarizes this really well. A
> large Rust program would no doubt contain bugs, but it is quite
> possible that it's UB-free.

The only purpose of my above wall of text was to assert that, as you
said, "A large Rust program would no doubt contain bugs", so we are
good on that point.

Just in case there is lingering confusion, my purpose in providing an
example from the field of safety-critical systems was nothing more or
less than to derive an extreme lower bound for the expected bug rate in
production software.  Believe me, there is no way that I am advocating
use of Rust as it currently exists for use in safety-critical systems!
Not that this will necessarily prevent such use, mind you!  ;-)

OK, on to your point about UB-freedom.

From what I have seen, people prevent unsafe Rust code from introducing
UB by adding things, for example assertions and proofs of correctness.
Each and every one of those added things have a non-zero probability
of themselves containing bugs or mistakes.  Therefore, a Rust program
containing a sufficiently large quantity of unsafe code will with high
probability invoke UB.

Hopefully, a much lower UB-invocation probability than a similar quantity
of C code, but nevertheless, a decidedly non-zero probability.

So what am I missing here?

> I should probably say that doing LTO or not wouldn't make a UB-free
> program exhibit UB (assuming LLVM doesn't introduce any during LTO).

I defer to comex's reply to this.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211008174048.GS880162%40paulmck-ThinkPad-P17-Gen-1.
