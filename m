Return-Path: <kasan-dev+bncBDBK55H2UQKRBOMIS66QMGQEWTLOJII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B02B5A2BDE3
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 09:28:44 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5440ed55ba0sf1085511e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2025 00:28:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738916924; cv=pass;
        d=google.com; s=arc-20240605;
        b=B97BaS36gfS/61mUFUJUow85tkU1HWCQGqOFq5UqpHtS1fp2jIfshbd0fouqGA07NY
         p/XkyqbDetQTew7wfroqza9hsWQ3dUxW+XE6qmPdk2pUMBe+PCHTlzt/DTznGDEVKks6
         bm8/PmcAm/nkoVeXJUceAGRHzR+/EtwJO6sGqPdsxq3xPu74NqskArqg6GLKfWlGa2w7
         T6Y4Dt3/Sz8GUiH+cP3PhGPqR+t2FwN65gXj6+CUaTN6HvphhlccDzLwuBZ1nzGyekFH
         r0lVm+NF/8tm9nhHNKssa8Lx6xvhQllX+770CZSS6EteJVRBz/MuTdNMRtx2Rrsgu1DL
         O9XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=fEP4Elz3pzhq+VDCQ5cDp1PEUGjZX0424EcmGFBo+z4=;
        fh=VgLzz1kLhSW4Og1d4kMgoH28f8vwUrGFmzAd1HJVvFs=;
        b=ZEdaHTFKtS1Rdj3r7LYmY0uFDK380jHAPfgdqLCLvLSNPT8igE0ZLpPFfTh55WTp9+
         vVAXM8exTVI4+6OEqPRBHY20/3haw3rUeTSZE1qmiYA3J6JYtmcbD3tAUo5hRFhTBGob
         7W+WBwqW5KK1k6q2XQvws6oinZVXlVHVGn709aloYylXTDYI/D7/LAXDvbar6crkG6Fa
         XXQupcuXkUtItVl+f3RE5UQeN/p+ypE+fum4jHPwMeSAz09gwTezUMOvaovwA0aKu6ff
         zqRGjAV4gV5HNxgi6l9LUIvGGgjqo2+JJX8RKxUdXT4R4Cm4P0a0iFFFe2ZJFJohh+cf
         04vA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GWu+vxi0;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738916924; x=1739521724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fEP4Elz3pzhq+VDCQ5cDp1PEUGjZX0424EcmGFBo+z4=;
        b=xuHQgUdr/7STh7F3UtUdjTjqScVO+wgb9LVsrIhTEiwHOfdTS5Vy9iFalnLRfG4NOd
         DBbAUl1xdz/T6VI1Ms2QFLsjcRdhGTKNGOWIu2JhJjRqrOdO//qnmfVgX1DGhTl2prRm
         U9m2R2ydW+UW2UH9O2iIv6azzRcEdoF9CmLFMI2m9tcIHqOjS04QFY49h51SVfyguz3y
         VPZAdL5lJkQVRY7mUIHV4h9l7Cg3wNTuzT2Mh8CBK1T4iVzLhKVZ7dPfE0GXA1GUYHB5
         Iq9GgPn42jPa+/9BFaQT3DYTw9bJYZRkSQ4XoRGufA4dDaZQmaBuHYuq3MT8gbNcRSdV
         qPvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738916924; x=1739521724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fEP4Elz3pzhq+VDCQ5cDp1PEUGjZX0424EcmGFBo+z4=;
        b=cPCg6zE76PinQ/7Lmjvo6ztfxYbEgOgYDYMD/yE1k00Kn2r9Jg3UaVkDa5IMuvb2/4
         PCgZQITQsP97GeYv7IW/QCAZo7BPpeV88BOuNxAzJvEwzmcc1vl/HHiYz8KRk4mqjaWp
         nQXO/iTQckqv142/FU578nZESaxpgNaHzbSVn0EsG5seDM/1mlolOywVTzC4oSwYy+LG
         PbCdEEKuO0ov/yyaJwiT5WtOSTYwZn00SonK5AZBs2oMrkrYujhiMV53FbSnXVCwYBNa
         U95TAQama6BvzaipM3m61jaFJbH5xyVGBT934OI8/DlWUOU7UVzdVlC7g1xfZxhk9X0H
         H/9Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9aQFZ8rq9nbKw5BhFiN/EWlrQzCTdDiCthBvFNWtU6a98gJngdgWPekfAa6MQAPMMaOc0zQ==@lfdr.de
X-Gm-Message-State: AOJu0YzURXWxi06CTLyh7T3THmSCAA/HDqJuFseXTPhko+acYiFwIL4m
	M5r0NDSRjujF/dYlBQjSzmThaQuNeOt0BLW+QRtSv/WEWkXLmIRz
X-Google-Smtp-Source: AGHT+IHToOQZsPr7w0gng2Z7SRTj6F4y9EBYhneSRXTy1hMUcuMfuYibQVBYE5VtwcoWDVSaxSyu8A==
X-Received: by 2002:a05:6512:3585:b0:542:2972:4e1e with SMTP id 2adb3069b0e04-54414ab50a0mr498529e87.12.1738916922395;
        Fri, 07 Feb 2025 00:28:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:771e:0:b0:543:e3cc:197d with SMTP id 2adb3069b0e04-544142e3b5els122203e87.2.-pod-prod-05-eu;
 Fri, 07 Feb 2025 00:28:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX1xmDEs8vAdinOrSYPBWiBhzd+HIU9djv9vpwaXt7KWfTF9K+CZks+XelO8Lgm6YN8ZR1TiXk7psA=@googlegroups.com
X-Received: by 2002:a2e:a803:0:b0:2ff:e7c3:9e2e with SMTP id 38308e7fff4ca-307e57fe4d5mr7332441fa.17.1738916919287;
        Fri, 07 Feb 2025 00:28:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738916919; cv=none;
        d=google.com; s=arc-20240605;
        b=jIM4GOV+gwqgccm5lZ8taKAzpSbORnqo2WCQ2MfBUgXB0AA8lQM4GXBetwZJpm0Vuy
         rqcixg6mJeQuzXnAw5oELGx2PjL8SIxIXqYIp3Cl+ff6E0zOYN53AI/NAhuYJ0xeEcyX
         82pGyE/p2QQmQK9Rxp5piwWDlE8HjqrHR96/5ECd8mAp2Lx1I7bD2ebe/h6KYnRKnLWa
         nuHvDJTu8hxoZnxi0kmgFDFZsRmyXJ4X2TOQ6/i+K288oF/24ZUnLEyHtsWGZvG1xuA4
         ob3nvdv2svgP8m0r2Us4mVBbuG4KXQppGRcdCUEWvvHzmgo1hgIqy9jJ5meBOzgpTT1g
         HQ6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wzocH2UaJwexS/hhrxFs84p2uFTxUKaRksQr1v8H/HM=;
        fh=p9qVCSW3g/knQl1jy4WovKLdPkqy2lNlDCIoDQ06JPc=;
        b=SyketwIPx9U3+L93a+tQFfElUXtaVW0BiVZFHn+ef+mKHGOnpVyVJJe7h2L9BNnA9e
         78iZeepCuKOlztMvOW5OZM4iUFMbyE7P/6hycwmhPQ0/22MsY7HJVyLrkXCtd3WvDFyL
         W9a3Vd9ph3dm2YuMhk/KD/LForxLgykyevpaA7eekd88+VdGxLRHK570PWPvsiiRwaF2
         lOLgxyPg9eokpjZaLw+H6emmWF2aEsw9AypGB/qisMYMsSA30hANdZdcl+b/43jsYoci
         abMPS3eCeZLeby++ckuqszJkPL11++eTdQjslkFlML5rENpahNkTZ7+0qdyFiQLRCh5D
         P81g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=GWu+vxi0;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-307de1c38bbsi640831fa.3.2025.02.07.00.28.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Feb 2025 00:28:39 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tgJiz-00000007U1P-0j34;
	Fri, 07 Feb 2025 08:28:33 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 451BC300310; Fri,  7 Feb 2025 09:28:32 +0100 (CET)
Date: Fri, 7 Feb 2025 09:28:32 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org
Subject: Re: [PATCH RFC 02/24] compiler-capability-analysis: Rename
 __cond_lock() to __cond_acquire()
Message-ID: <20250207082832.GU7145@noisy.programming.kicks-ass.net>
References: <20250206181711.1902989-1-elver@google.com>
 <20250206181711.1902989-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250206181711.1902989-3-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=GWu+vxi0;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Feb 06, 2025 at 07:09:56PM +0100, Marco Elver wrote:
> Just like the pairing of attribute __acquires() with a matching
> function-like macro __acquire(), the attribute __cond_acquires() should
> have a matching function-like macro __cond_acquire().
> 
> To be consistent, rename __cond_lock() to __cond_acquire().

So I hate this __cond_lock() thing we have with a passion. I think it is
one of the very worst annotations possible since it makes a trainwreck
of the trylock code.

It is a major reason why mutex is not annotated with this nonsense.

Also, I think very dim of sparse in general -- I don't think I've ever
managed to get a useful warning from between all the noise it generates.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250207082832.GU7145%40noisy.programming.kicks-ass.net.
