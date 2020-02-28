Return-Path: <kasan-dev+bncBD6LRVPZ6YGRB2EZ4XZAKGQEQ25UQQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 073B2173E62
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 18:24:57 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id c5sf286007vsh.23
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 09:24:56 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jpw/zaE5IHszsE6/VE2B7qgixUv8hdFdkNgfRzYG8ro=;
        b=X+W7iZkgSv9Rlnqn8GefqNc+GBG2ntV9YsWbSwO7CtaFHRw6UI2Fp31ML54RMMpYMX
         Szo8U/xhk9q2QAiKnxL8Fq0sjO2JpAM5XxH19llSFWtofNopF9CdLq5szaYTrhNIXuaS
         S08lmpLTYwyHR99nfzm6kV0yDURg9Lb/bllI9aVobzCqx8/KSeXDEFaWyBXIsiGjEfG5
         VLRGwlIyWfk6VgOfxzti6sXF9Nw3UPM3YOTfCgmB8/eepf2X72d5lYZsodEMyNPQMzIn
         YOrnst1sObWraib4f3oMdnQxa6b91bchukfR/nXRK32cTnh6SGjS9R3PpwIsIFew/OrZ
         QBuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jpw/zaE5IHszsE6/VE2B7qgixUv8hdFdkNgfRzYG8ro=;
        b=ShNvVra0IBrnrnmHMSGm2WQWbTnZ2Ig9+YDIrPVz7Tw9bfg0DWttOx6Yv/7X4cuI3e
         5/uD7qlQ7ZI2m4CpYtCSTPwAP8GKyEp4WlEkdr2f6bwNng/4uz5j70wYv4js94Zbc+D+
         ujQPou1pNGDuGgdg8B2AD9WLD9x+SPFbmItvqVU/LScIG2gVB9VeLF1gdVd/Kt+aPqpI
         OZukqnImXImqhb9iHvOHYOtpCFq6lKAgHVw8g53tpWqoMhguAOGVoufGoYO0u5xvEUkm
         jBQSogoU3R3YGil24phaiAACTnGvZ/TbUrOe+uK6Rh/aH9BeRyT+3GTzvSLN4Q+LU8tH
         BsXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0KTxKRh1wG8gyJyJtVu/0HSrQ2+godRCzrXG+4NWAhTsPczyzH
	F6GRY3HNVWdlqBtyxa8XNsU=
X-Google-Smtp-Source: ADFU+vvYaKb4p9X0DtlN+zh2KT8msAsmwjp1DQtpvVeyPI3tKq6hIf2tKRpXLyFPyD9iJrq2F5uuPg==
X-Received: by 2002:a67:2701:: with SMTP id n1mr3131741vsn.103.1582910696080;
        Fri, 28 Feb 2020 09:24:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f94a:: with SMTP id u10ls452676vsq.1.gmail; Fri, 28 Feb
 2020 09:24:55 -0800 (PST)
X-Received: by 2002:a05:6102:2154:: with SMTP id h20mr3130317vsg.162.1582910695626;
        Fri, 28 Feb 2020 09:24:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582910695; cv=none;
        d=google.com; s=arc-20160816;
        b=pWU67/+i4JJRwHbR0Crk95im0dz51sz2saFRWCGh0Sg9ltN26tV1ZGhHCiG+3RI+yy
         wD0o++lb6CL0dI0L5ZSsiDVWNouVLM996ih8r5gnqjKquuaXIhWw76AXz4BYgFMW/38n
         RwahItQRfZ2z70h+rYRi5qcasmLhZxSEK6cq5jtv/Q4OzQD3GLbs58ylUFGGTTojmxoB
         DDiVcYiDEtzu4NVWfKMZzj1FQVyzQliZraBQ5Gh9Dv9Dth23inwWP514ErFZGxfUvQZ9
         jzfkoremsTBMDWTaUkWmbeXAkjM2LMqadujJSpe+L2gvKzphOO7Que5k9i7/NeQamOLL
         ZZrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:in-reply-to:subject:cc:to:from:date;
        bh=Jpw/zaE5IHszsE6/VE2B7qgixUv8hdFdkNgfRzYG8ro=;
        b=dAa441Zd3tvwDWFpvZ8X+UdM0BQwrHAJuKb9L22E9Iu0DtQGbrT0ZS7KSN/9DhqsE3
         Wm16kNUjTaRcz4aKTi0jrTzXt5Q9Hiu04pdaX6cfJat7QVdXOrXYcJIRLGlGcNaNPM8h
         t1XibmqJ4aaL2zOV/a+2iaD1efi+xmu9ydU9npw83qsor6X7+iQ53QlcqiSBpKgkg083
         og5l25LxlYF/UMGylYXPcBxUfklemcx/ioUPjym8okkIvAB0kyPcZ/5UgDaxt2ZWbRbY
         HRjsXtJ760u/gRDH5fl4fvvoZJYn4M6GoaU1qkHE+IFmgyExtnMoiPyTy4sf4d1xPipV
         1Q6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) smtp.mailfrom=stern+5e5a5726@rowland.harvard.edu
Received: from iolanthe.rowland.org (iolanthe.rowland.org. [192.131.102.54])
        by gmr-mx.google.com with SMTP id 9si51982vkq.2.2020.02.28.09.24.55
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Feb 2020 09:24:55 -0800 (PST)
Received-SPF: pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) client-ip=192.131.102.54;
Received: (qmail 4543 invoked by uid 2102); 28 Feb 2020 12:24:54 -0500
Received: from localhost (sendmail-bs@127.0.0.1)
  by localhost with SMTP; 28 Feb 2020 12:24:54 -0500
Date: Fri, 28 Feb 2020 12:24:54 -0500 (EST)
From: Alan Stern <stern@rowland.harvard.edu>
X-X-Sender: stern@iolanthe.rowland.org
To: Marco Elver <elver@google.com>
cc: paulmck@kernel.org,  <andreyknvl@google.com>,  <glider@google.com>, 
     <dvyukov@google.com>,  <kasan-dev@googlegroups.com>, 
     <linux-kernel@vger.kernel.org>,  <parri.andrea@gmail.com>, 
     <will@kernel.org>,  <peterz@infradead.org>,  <boqun.feng@gmail.com>, 
     <npiggin@gmail.com>,  <dhowells@redhat.com>,  <j.alglave@ucl.ac.uk>, 
     <luc.maranget@inria.fr>,  <akiyks@gmail.com>,  <dlustig@nvidia.com>, 
     <joel@joelfernandes.org>,  <linux-arch@vger.kernel.org>
Subject: Re: [PATCH] tools/memory-model/Documentation: Fix "conflict" definition
In-Reply-To: <20200228164621.87523-1-elver@google.com>
Message-ID: <Pine.LNX.4.44L0.2002281202230.1599-100000@iolanthe.rowland.org>
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII
X-Original-Sender: stern@rowland.harvard.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates
 192.131.102.54 as permitted sender) smtp.mailfrom=stern+5e5a5726@rowland.harvard.edu
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

On Fri, 28 Feb 2020, Marco Elver wrote:

> For language-level memory consistency models that are adaptations of
> data-race-free, the definition of "data race" can be summarized as
> "concurrent conflicting accesses, where at least one is non-sync/plain".
> 
> The definition of "conflict" should not include the type of access nor
> whether the accesses are concurrent or not, which this patch addresses
> for explanation.txt.

Why shouldn't it?  Can you provide any references to justify this 
assertion?

Also, note two things: (1) The existing text does not include
concurrency in the definition of "conflict".  (2) Your new text does
include the type of access in the definition (you say that at least one
of the accesses must be a write).

> The definition of "data race" remains unchanged, but the informal
> definition for "conflict" is restored to what can be found in the
> literature.

It does not remain unchanged.  You removed the portion that talks about
accesses executing on different CPUs or threads.  Without that
restriction, you raise the nonsensical possibility that a single thread
may by definition have a data race with itself (since modern CPUs use
multiple-instruction dispatch, in which several instructions can
execute at the same time).

> Signed-by: Marco Elver <elver@google.com>
> ---
>  tools/memory-model/Documentation/explanation.txt | 15 ++++++---------
>  1 file changed, 6 insertions(+), 9 deletions(-)
> 
> diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> index e91a2eb19592a..11cf89b5b85d9 100644
> --- a/tools/memory-model/Documentation/explanation.txt
> +++ b/tools/memory-model/Documentation/explanation.txt
> @@ -1986,18 +1986,15 @@ violates the compiler's assumptions, which would render the ultimate
>  outcome undefined.
>  
>  In technical terms, the compiler is allowed to assume that when the
> -program executes, there will not be any data races.  A "data race"
> -occurs when two conflicting memory accesses execute concurrently;
> -two memory accesses "conflict" if:
> +program executes, there will not be any data races. A "data race"

Unnecessary (and inconsistent with the rest of the document) whitespace 
change.

> +occurs if:
>  
> -	they access the same location,
> +	two concurrent memory accesses "conflict";
>  
> -	they occur on different CPUs (or in different threads on the
> -	same CPU),
> +	and at least one of the accesses is a plain access;
>  
> -	at least one of them is a plain access,
> -
> -	and at least one of them is a store.
> +	where two memory accesses "conflict" if they access the same
> +	memory location, and at least one performs a write;
>  
>  The LKMM tries to determine whether a program contains two conflicting
>  accesses which may execute concurrently; if it does then the LKMM says

To tell the truth, the only major change I can see here (apart from the
"differenct CPUs" restriction) is that you want to remove the "at least
one is plain" part from the definition of "conflict" and instead make
it a separate requirement for a data race.  That's fine with me in
principle, but there ought to be an easier way of doing it.

Furthermore, this section of explanation.txt goes on to use the words
"conflict" and "conflicting" in a way that your patch doesn't address.  
For example, shortly after this spot it says "Determining whether two
accesses conflict is easy"; you should change it to say "Determining
whether two accesses conflict and at least one of them is plain is
easy" -- but this looks pretty ungainly.  A better approach might be to
introduce a new term, define it to mean "conflicting accesses at least
one of which is plain", and then use it instead throughout.

Alternatively, you could simply leave the text as it stands and just
add a parenthetical disclaimer pointing out that in the CS literature,
the term "conflict" is used even when both accesses are marked, so the
usage here is somewhat non-standard.

Alan

