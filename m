Return-Path: <kasan-dev+bncBDBK55H2UQKRBMGIR7FAMGQEDIVRIMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id C0D8ACCB96B
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 12:23:30 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-64b40c8df90sf602162a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 03:23:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766057010; cv=pass;
        d=google.com; s=arc-20240605;
        b=DmQCOhmTh4K8pL+AkjjSwt8MTq2R4dpm8Hk/EG4IpvfKBoCI3RCj4eW7woMocWF3vH
         0zeSONC2JF5iEra71x8vJWwOJigBaQt1IRDipaGZ7f14bR5D9P4/I5/kmkczcSJMtwvO
         wzlOoruMsdhaPWBTBk7QxV+XgU+3qe5NLcjUnzgiE5ALyuOiq09XUkfe/tv7SJ7R0HzB
         bk3WQTrbRoEau1bil2P+D9myp2Rd4VojZIG4dl92YiHRc3GBu42LWhGOS1Akma0bM8TZ
         4oTg2nMPDY5FTXX17iE2wGcmmhToKfBlHg2QcHjkmQz9uSG3CCY1T2fdm3SSKcCUTVyG
         Btpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=uI77B3ZuRg9dp7E2PLxsCAbiMniXMDV6pyQLkmxv/7k=;
        fh=k+iQPfVLloz3NM3XNfJHAzYONz/TTTyfudmWIDbD80A=;
        b=XNc31JAQUSRQ0zv8PkOTWds4EG5Mrj44NSd59WQJuCVUfjOqO4SQavEu4gB9mc/V+k
         1H1FjOqvS7YxenZNRHahCwPdNWH3yeffFCjWVENzCwsmUoxwjZrbmFvO8psYVEYXfSNJ
         Deh2VBksyG1o2r+HDDYsT0kAWKJEnk4ACBl47sbSzayrRKdHsyH80HnhIHLkSWGAi1tb
         1k0DcESm3k5qjTC9RJmG32Mc18FtfywhiftuQLGye9tSBWNsApZDRB1BTYSvuBBtSK+f
         tbfpNIzt0BNN/rM2xXxzt9TdmZMe+rwU6lTpAIcYTXdkNE3ne11BnWN748gkGTekcrXE
         d7BQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=MMhSvlZ1;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766057010; x=1766661810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uI77B3ZuRg9dp7E2PLxsCAbiMniXMDV6pyQLkmxv/7k=;
        b=T3s9fAZlijC4/lGjNA3tEUNfGo+LDplL+ds4oLzExhpGPJ73B2gEr8iW+G9vMQfIhp
         +txCR7mxXyUUb2/8f7XaRY7RWDJhIk2NWfQKEDNzG4ct6dVHEJDxWopicziK8c3CiwHw
         51zXGtqv8vf/qx0/vq9oflVOyabNvLTiFv6QTTP70h+dovb1XMWxaCAqXDmFKR4dYyAS
         +iI30ujfLM1vGmN12UM45r44pz7lkVLAJdUKH8U8aMV+h76hgYG30+xyzZQ4B6k1FZTe
         L9vwkf/1StZ6kQRHBwZPetBqFzUxEwDkseQz9jqUqsOBm3n959iyL1cHtVwiwj5MHPv0
         2DbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766057010; x=1766661810;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uI77B3ZuRg9dp7E2PLxsCAbiMniXMDV6pyQLkmxv/7k=;
        b=ChiUTHKAGbxz4T0WXrNwrfK45D7H7gfWThgkPXWVFsbC27rf4n1P2qYAGdEPMRm2GA
         eON8UoP5AThbdHQ4vLm0jRfXmOa1km2LiCeAMBYKpjGa/JAiZlxs/UvfsWmyBrpp/69U
         P+VMhTLEZNtW/YmuCcOSWCVLAK3nXUxPPRzWKh6FAlTGyCtC/2peBfaT46EYL8H11IQo
         62DmOREidAD74SK0ra6gQ0pfRxnIu0vcB+RIIipJ7mVHrHPYMiDpAc5TIQjdccqR/qcA
         fQ5mTUtjoutwdpEkBsh1VpxoauS1jKnS8wFqDkjrfeT6IuevgLYWipkp/c4AyYudUoTR
         jtFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXN0QYqQcZL6dQ79NOw/RCsSQbvQKhVvC5eUixS1NbIQd7D2qUA37ZTqN3s9cVjXKK6dBgDUA==@lfdr.de
X-Gm-Message-State: AOJu0YwKEAPyvZ08pR3+Dkqo2AHwiuvmsUxI1eykrG0fovBWQj23eJ8m
	g8L9u97apGgsnOvHODZdS8fXEh0FicuFmDIZkMKuh0xSIqgTkYRVgN6I
X-Google-Smtp-Source: AGHT+IGCOqXL2fWT4TlBSFg2ioTaiL07UIchHUg7JxpMnPHmmSX71XObqvIeGpOjRHMlI1rSP365fQ==
X-Received: by 2002:a05:6402:5245:b0:64b:7dd2:6bc2 with SMTP id 4fb4d7f45d1cf-64b7dd270ddmr205314a12.7.1766057009612;
        Thu, 18 Dec 2025 03:23:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYV8soWkrX4zIf52hAuLoNWL4PHioa85nrfHnrOzMElAQ=="
Received: by 2002:a05:6402:4610:20b0:641:6555:a42d with SMTP id
 4fb4d7f45d1cf-6499a413c05ls6752277a12.1.-pod-prod-06-eu; Thu, 18 Dec 2025
 03:23:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVyEImsYkTy/Z3HKJEHV0tslAk6AGqhaXq6zW1vmQAetjy4EaZHZNE2PBNlbe2YKLx4haFFRszBz24=@googlegroups.com
X-Received: by 2002:a05:6402:40c2:b0:64b:4a33:5455 with SMTP id 4fb4d7f45d1cf-64b4a33584cmr3403900a12.16.1766057006781;
        Thu, 18 Dec 2025 03:23:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766057006; cv=none;
        d=google.com; s=arc-20240605;
        b=araktCC4agLuBbqXVVjW/7sS3NJGGEo9V1cviqTvoCIOpAT4zeGe/Lfnp96awXXbDN
         QYjAB0IBUmOw9te2AEpK99G4gOfZ8KSoRfERjD6xrLT41YkMuHZZ18+KBLnJHY5HwkK5
         Bhu/svo1TrvOZclD9pykeLe5/78ht91KcbOuehBfqgBKiLwjSf9YRPi0irYXEWec4ME9
         lT3InzLZn6wWQs4eafOkyRSBtGZb7vAIZa7bT8RQk9O+czYDCNvHoPxmTIabVlU13u/w
         vODOoSaB8rXbTf8NlABc35HBcHzML7Nn4UP9irL5JZ/o15xz7JCmK5Q6KR1cr8uvGYkz
         fpfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WWs/FMKLopR8GlxWJLTbeh62Yklb02RoamS4e6t082k=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=KUq/WmdSVfESRAyhRRzFLE894VgHpmdWviCw2Wv0dT1h5VakZqMgPAQUnitam4gXH9
         e4TLI+yO4GLZlDFCuqcox4cmn7VlwThGByO00Fw6szuH5I2hdHoflGPjXLvpOVRYi1E6
         JQXS1q2C9OA5apeUBf9nVS9ghuZ1d9bdB+sZSmYnfjJEZv8EZchhqYeBMussC5R3XnRq
         w6vUrKeEeyAPLMZ9qYmAGSOUC2Q8SstvTvuwL13NsqNayt2y6XYEJ0rXeDb6GkJvttaE
         WLtKRCJsJsB8477vzt/N6Af/WAkqlx/Cm46/NuZP8zluWjD2geQK8Dl4Yr1/AbCHVeOw
         6qdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=MMhSvlZ1;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b58834be5si33615a12.7.2025.12.18.03.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 03:23:26 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vWBEi-00000008e0m-01ZP;
	Thu, 18 Dec 2025 10:27:56 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id DCB0D300578; Thu, 18 Dec 2025 12:23:08 +0100 (CET)
Date: Thu, 18 Dec 2025 12:23:08 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context
 analysis
Message-ID: <20251218112308.GU3911114@noisy.programming.kicks-ass.net>
References: <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
 <aUE77hgJa58waFOy@elver.google.com>
 <aUGBff8Oko5O8EsP@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aUGBff8Oko5O8EsP@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=MMhSvlZ1;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Tue, Dec 16, 2025 at 04:57:49PM +0100, Marco Elver wrote:

> Below is the preview of the complete changes to make the lock guards
> work properly.

Right. Not pretty but it works.

I did spend a few hours yesterday trying out various thing that don't
work -- as I'm sure you did too -- but could not come up with something
saner.

So yeah, lets just do this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218112308.GU3911114%40noisy.programming.kicks-ass.net.
