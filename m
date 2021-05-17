Return-Path: <kasan-dev+bncBCJZRXGY5YJBBD7NRKCQMGQEK7CTNIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 4175D383C4D
	for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 20:31:46 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id g144-20020a6252960000b029023d959faca6sf4579001pfb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 17 May 2021 11:31:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621276303; cv=pass;
        d=google.com; s=arc-20160816;
        b=FWqG80XyhhSB70pQYeSI6pjZAT1CtfnYTgQoN7h2eGM6lzlEzBxEIdkXcq/r4gzBbq
         P0PbHzfA0kkSDsKS0O+LKKFCaEWgAsToB6gyCwLpYH4lDCWHbEFZzbrV1Mr1AtNz4VqV
         nJP1sgVzz6PAZwXID5PpQqgT7nBe/WW6d8Y37YK1SREg97P6Ss2u6q12ce1YmoCyhFd7
         yukFRdqtNM39xWu7YbLFgcUBFTtUgHPnOmuCRJo07Z3ju28f++qKEvb7/zJ0fP8wx6Ca
         fJ23hDAV6znW3fVUQOLyMuJLG5yRAM+ZiiVreco+LkKt+RjrVUW1XE6fcHLgiwnIL4lv
         SaaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=kN9rEYDLJAUMl07m18lCREIUEzny9nHb244dlyvdJ7I=;
        b=R2BqfyfRRNVdU91q9fzqJLL5nHL11Bq3HLGj9BejIFFVgkxLPXX5pgo+5NWJTu9WcT
         dK9hLDH1pwj15IJf3m7xl7iwsp1qbfgO+sGG1k8fulU/l+4Tt7r3GWiosp8i3ZTaYvC/
         NWdIy6DsPu7IIEmVd+k7GT5aociIX+8T2+2qZP8Z2gdJCfyGYabkOg4Agz8jLDaQNLos
         0jF+q2jfKjxULZ03a9pqGlhJyHIO3gW3V5fp7c8rlJlLl7NiYi1sLW6INxa3L00gqysj
         IA+70xJV0oDo8ORiT2mHtM+yR41PND5XkHlVC1yLryMnJmFksEl5gGIn2OA5NKWo0zWU
         pOIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="kuH/HHRw";
       spf=pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kN9rEYDLJAUMl07m18lCREIUEzny9nHb244dlyvdJ7I=;
        b=kaktDcisW0iIovEQqgbNwyIfi/+0j5Bkoiv22Erjh/2X9e8zTMuyT/uEHpPD9+d2rF
         nsnLLO9j3hL7YOuWxvzw9kfVLeTeggtjPmYh5Cl/+AvUSkIqiEWqiPl07LGNn3fNKptl
         KTwwcLqz8n/udJHNg4jXmjjEeC9oLoied615Wg3amjRDvjgxMr08Uj2U4iJGdHr8G4as
         MXu1xt6p3FbjrbpWgts8yCOioA0gjeDT61wHZQ/aI+UqfYY3ELTIC+S7Sq7GoiDFKYxn
         etiowpxcq2eUF81mzYZv44WyTBvElCMa9Qw2ZzJeKmOOWgkO9mxYE1aiMDFO76YwdZky
         fdgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kN9rEYDLJAUMl07m18lCREIUEzny9nHb244dlyvdJ7I=;
        b=VONoviQl6lhknlgINEeE1fjdOIE6YLqzma2CEex0WOoYBsH27iLguu293ZPxAceAwX
         wCW2STp4pxR8Q0inM5IXc8fmxrGk21vw9R7kQYXSAIV/seBaYugQLq0aqcybeqKI1ece
         54s9LlpXPDnWmibFO/bekH8dio1KXkUe4u3xtRQOR4DYRdGOtH76kpRPCYSYf+dqdlpK
         bodgd9/i2SYkKHCIci40juSBnpuN2VlmI1N9t9+XAUFMD+DKO7xjE8NqLpgmcpL7UCny
         aXX/OfPS1Zmfx1ZLu/QxoYMHIgBHaAkBzsJZNLIHrjdxzbQPScgq8q1GnWrAbQ87x/n0
         Thuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KeIIdowrbeKWFsACuJANPjpi5qgJz0plV/OhI9b2FFYWyDjaX
	nzceZOqVNVB+nxFSi3xv3bA=
X-Google-Smtp-Source: ABdhPJx3NmMLVw1ub0PyoyQeznfOn1VThmRBqvlWZKHbV/IPKjMrTzpZXYuIlg87zZkZ+M1XEyqnHA==
X-Received: by 2002:a17:90a:3041:: with SMTP id q1mr448988pjl.191.1621276303729;
        Mon, 17 May 2021 11:31:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:dc05:: with SMTP id i5ls131596pjv.1.canary-gmail;
 Mon, 17 May 2021 11:31:43 -0700 (PDT)
X-Received: by 2002:a17:90b:4c4f:: with SMTP id np15mr770132pjb.191.1621276303191;
        Mon, 17 May 2021 11:31:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621276303; cv=none;
        d=google.com; s=arc-20160816;
        b=YqMemyM4VbNbp1aWjFvCIfQhIfCJWE6TVkFododcZFdfrC3bZJjbNshJlejiZYARW4
         71GAi+JkBQHnaULU2hbKNd6OWi7ErjWs8aB369Ude9RfpBvTNK5wOXYyJj/sqP1LddpK
         1nBrcgGnXET4UNF9tGP/NupQByeW4izqmffDRghkzpNcBJr3AX69yAtp+ISHFKstin3T
         YDBXRVBoUnCTuXNgNxrhvyBT5dy6Y6L2Jh1t/tFr3uxxbUluGrsr5YKaTXA6ekn5/x5F
         pgnKuLFCGWv+QRfIerNgL9/wD58F5FdLkcd4g+IbP5UQL0qVVs7seilBvuOPXG1fssrE
         ZWKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DygGXmcskXZHU1KN9XpnDsbytIsPtSEh7zxw83qbKrQ=;
        b=plvIPH63O6PUZYlPnfV/NK1CHs4s3Dwp+hhVlvOdzC2YpzVBq4VE6IP/fnXCvOMlT3
         XnvQ3NTQkH5aRnCIs5QlWV2DWSRx6yXWlhU07Yq9cmb/2N3Z5aAv5PuabSpSWCjxIdxW
         31LuxtFRYUaFyVtjIbNkLVh7J8Tr2usT9Pv0TiJpbPSqCwhFdiHX6pBemNb3vi87OxlH
         uK8B4oEb6M3KqIZ7Y1Z7FuTchdPkb+NFAsgRWuAzmT4h0aWfekfCFECTOfuVtEVjXdQs
         k/F5wTsITTyJSdVT0ZYjMLHsSGH+oMAyY1NEnT+HLYw+tXMWazLENTrYb1dQOk4mdP3l
         pCTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="kuH/HHRw";
       spf=pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f1si1180371plt.3.2021.05.17.11.31.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 May 2021 11:31:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DE86960FD8;
	Mon, 17 May 2021 18:31:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A18F95C00C6; Mon, 17 May 2021 11:31:42 -0700 (PDT)
Date: Mon, 17 May 2021 11:31:42 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Manfred Spraul <manfred@colorfullife.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210517183142.GB2013824@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
 <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
 <9c9739ec-1273-5137-7b6d-00a27a22ffca@colorfullife.com>
 <20210514184455.GJ975577@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210514184455.GJ975577@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="kuH/HHRw";       spf=pass
 (google.com: domain of srs0=btmv=km=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=BtMV=KM=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 14, 2021 at 11:44:55AM -0700, Paul E. McKenney wrote:
> On Fri, May 14, 2021 at 07:41:02AM +0200, Manfred Spraul wrote:
> > On 5/13/21 9:02 PM, Paul E. McKenney wrote:
> > > On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
> > > > On 5/12/21 10:17 PM, Paul E. McKenney wrote:

[ . . . ]

> > > > > 	int foo;
> > > > > 	DEFINE_RWLOCK(foo_rwlock);
> > > > > 
> > > > > 	void update_foo(int newval)
> > > > > 	{
> > > > > 		write_lock(&foo_rwlock);
> > > > > 		foo = newval;
> > > > > 		do_something(newval);
> > > > > 		write_unlock(&foo_rwlock);
> > > > > 	}
> > > > > 
> > > > > 	int read_foo(void)
> > > > > 	{
> > > > > 		int ret;
> > > > > 
> > > > > 		read_lock(&foo_rwlock);
> > > > > 		do_something_else();
> > > > > 		ret = foo;
> > > > > 		read_unlock(&foo_rwlock);
> > > > > 		return ret;
> > > > > 	}
> > > > > 
> > > > > 	int read_foo_diagnostic(void)
> > > > > 	{
> > > > > 		return data_race(foo);
> > > > > 	}
> > > > The text didn't help, the example has helped:
> > > > 
> > > > It was not clear to me if I have to use data_race() both on the read and the
> > > > write side, or only on one side.
> > > > 
> > > > Based on this example: plain C may be paired with data_race(), there is no
> > > > need to mark both sides.
> > > Actually, you just demonstrated that this example is quite misleading.
> > > That data_race() works only because the read is for diagnostic
> > > purposes.  I am queuing a commit with your Reported-by that makes
> > > read_foo_diagnostic() just do a pr_info(), like this:
> > > 
> > > 	void read_foo_diagnostic(void)
> > > 	{
> > > 		pr_info("Current value of foo: %d\n", data_race(foo));
> > > 	}
> > > 
> > > So thank you for that!
> > 
> > I would not like this change at all.
> > Assume you chase a rare bug, and notice an odd pr_info() output.
> > It will take you really long until you figure out that a data_race() mislead
> > you.
> > Thus for a pr_info(), I would consider READ_ONCE() as the correct thing.
> 
> It depends, but I agree with a general preference for READ_ONCE() over
> data_race().
> 
> However, for some types of concurrency designs, using a READ_ONCE()
> can make it more difficult to enlist KCSAN's help.  For example, if this
> variable is read or written only while holding a particular lock, so that
> read_foo_diagnostic() is the only lockless read, then using READ_ONCE()
> adds a concurrent read.  In RCU, the updates would now need WRITE_ONCE(),
> which would cause KCSAN to fail to detect a buggy lockless WRITE_ONCE().
> If data_race() is used, then adding a buggy lockless WRITE_ONCE() will
> cause KCSAN to complain.
> 
> Of course, you would be quite correct to say that this must be balanced
> against the possibility of a messed-up pr_info() due to compiler mischief.
> Tradeoffs, tradeoffs!  ;-)
> 
> I should document this tradeoff, shouldn't I?

Except that Marco Elver reminds me that there are two other possibilities:

1.	data_race(READ_ONCE(foo)), which both suppresses compiler
	optimizations and causes KCSAN to ignore the access.

2.	"void __no_kcsan read_foo_diagnostic(void)" to cause KCSAN to
	ignore the entire function, and READ_ONCE() on the access.

So things might be the way you want anyway.  Does the patch below work
for you?

							Thanx, Paul


------------------------------------------------------------------------

diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/memory-model/Documentation/access-marking.txt
index fe4ad6d12d24..e3012f666e62 100644
--- a/tools/memory-model/Documentation/access-marking.txt
+++ b/tools/memory-model/Documentation/access-marking.txt
@@ -279,19 +279,34 @@ tells KCSAN that data races are expected, and should be silently
 ignored.  This data_race() also tells the human reading the code that
 read_foo_diagnostic() might sometimes return a bogus value.
 
-However, please note that your kernel must be built with
-CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n in order for KCSAN to
-detect a buggy lockless write.  If you need KCSAN to detect such a
-write even if that write did not change the value of foo, you also
-need CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n.  If you need KCSAN to
-detect such a write happening in an interrupt handler running on the
-same CPU doing the legitimate lock-protected write, you also need
-CONFIG_KCSAN_INTERRUPT_WATCHER=y.  With some or all of these Kconfig
-options set properly, KCSAN can be quite helpful, although it is not
-necessarily a full replacement for hardware watchpoints.  On the other
-hand, neither are hardware watchpoints a full replacement for KCSAN
-because it is not always easy to tell hardware watchpoint to conditionally
-trap on accesses.
+If it is necessary to suppress compiler optimization and also detect
+buggy lockless writes, read_foo_diagnostic() can be updated as follows:
+
+	void read_foo_diagnostic(void)
+	{
+		pr_info("Current value of foo: %d\n", data_race(READ_ONCE(foo)));
+	}
+
+Alternatively, given that KCSAN is to ignore all accesses in this function,
+this function can be marked __no_kcsan and the data_race() can be dropped:
+
+	void __no_kcsan read_foo_diagnostic(void)
+	{
+		pr_info("Current value of foo: %d\n", READ_ONCE(foo));
+	}
+
+However, in order for KCSAN to detect buggy lockless writes, your kernel
+must be built with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n.  If you
+need KCSAN to detect such a write even if that write did not change
+the value of foo, you also need CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n.
+If you need KCSAN to detect such a write happening in an interrupt handler
+running on the same CPU doing the legitimate lock-protected write, you
+also need CONFIG_KCSAN_INTERRUPT_WATCHER=y.  With some or all of these
+Kconfig options set properly, KCSAN can be quite helpful, although
+it is not necessarily a full replacement for hardware watchpoints.
+On the other hand, neither are hardware watchpoints a full replacement
+for KCSAN because it is not always easy to tell hardware watchpoint to
+conditionally trap on accesses.
 
 
 Lock-Protected Writes With Lockless Reads

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210517183142.GB2013824%40paulmck-ThinkPad-P17-Gen-1.
