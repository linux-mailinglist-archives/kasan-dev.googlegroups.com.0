Return-Path: <kasan-dev+bncBDBK55H2UQKRBI5V4O6QMGQEAHJUEZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9411CA4001E
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 20:57:25 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5452b8298cfsf1404856e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 11:57:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740167845; cv=pass;
        d=google.com; s=arc-20240605;
        b=MWu5net0wF/jB2hA58XhYfF72R5EouJnR/v/HApGdYHHADi11n88TxYYOCn5wcGc9E
         qPoeqtECvYWZIcUUsHsZQx5qHAa4x5cdmDJ3OBI14Ji488a8x+y1SfB50ZHK8I7SEHZp
         XTq724e4Lyigs4gZIuMj1oiOEtqWx1P9AA1rj/0VHIRb/tlHfNNDGJBBDJ+rRnm4Tsct
         tFnPO9q5ejOBqniikEox6YsYOXA6PgWPTkHVFnXFlWhxC+TdaDC5a2smAxqsN0O7+nsr
         Qf8N7q2Ar1mOyMfVYGZktSO+CTlrdFXSmrlwik5HMLom3YpyqplEZ/Jnd4nLM56EdPV9
         +sKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ex40+S/n8mrdCwHVZA2qp0wXW3ThW7IwtDs68bCp1E0=;
        fh=TaCKAvx+U+Qk+hahEpW+WWM/HAmV73k3EMDNO6jLd1Y=;
        b=PkjnEoNhlA3jxQrj8ThxK/vBWUm7cnJS3+A+uQa95JOa2ST/+yr0eYAglbAyG1iYI3
         atMRWC/kyMakjnqjo2lFt/nvOt8zbzzfXaxTSsLb6OlSW00Kr1OrtbDP6cubDjAIKUeD
         JCt7A2i6ge3Sl/vLXeZ7L+yZMsKjXwHyPZVRp2EIbbXePsSPJcGZWO4lrvg0TL3Dy751
         ma04o56AqfuBo0Hi6D4XYGlmT16AoGs5VFoVTkYKf4rA8Ksn06hxuiJpagMlEoClieLc
         cmZ91DhZoWJ9LIonlaa2spLaTV7Hy3nPCJx7ZW4qBEl5cZwiA7Anrbp20fYSRftG2pku
         xDVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=SWBFReg0;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740167845; x=1740772645; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ex40+S/n8mrdCwHVZA2qp0wXW3ThW7IwtDs68bCp1E0=;
        b=Zd/B/OKkMJeLh1Nqg0KkxvNwrqzTkJ69/X5omrBqtptVqmVNdQIZRMzVwWGPI5Gepa
         ZkddsnY6VADt55yF27QIGA/Abc5p4Igbh4hBi3/3zDQ7z4q+liIXGFlGX7zBQHCQb1IF
         ZtEbQdHThmqeFYmoBkvZ27LojPldvGpsjbVn3D+yXdztbbdLX+873BZ4TEKo1DMUM62r
         /6CUkKuAEMJIscxDgExa0rwbaOLAEFpxtB1+d7O5SAxW9oHu23Z9aldIqPjPaZrKow30
         PSF/bJOJExgdr9tZNm4FTObq3wU9cXnAEOKv9fd2CNdxudl0foW2K6DJsxZfhHl5QARR
         Vc+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740167845; x=1740772645;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ex40+S/n8mrdCwHVZA2qp0wXW3ThW7IwtDs68bCp1E0=;
        b=LHwT8O8I8WMl4PHHrb/5Zm9ihSPU6CfCugvFE83tOoVm2mkVb8zFGQj0wJyDNLgpfu
         gfMylX0+1/brHAcjixc1BpZCxoKmjg5PaZnR0YJz0dzOp9myk+fBr0+Fx2pyhiUrD0iC
         LZ3Wp56e8kN7ogzuyEWjx21dCjcIqc/oc/+x9rd5lngvxQ4UHwsp8qJ3jeuLr0DkqNS+
         lcomJWnSRk7sAWzfX1eRt0wDAyOjHa4jpJLG1a4sBD2YMk9sQfSOF0BDaxtehIDgMO6U
         KwzOk0wEHa1KybAulEqnD9ztVKoSloGLwUs3UMB7Vy4noNYnWTonwUmS4tnl4j/4dEXf
         +DHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOEduON/Uh1tPl487Yk/8ooZQH3MfsCq4BsVk0TcG4hbrE+No0YEim+JodYnyKB6tSVSaGtQ==@lfdr.de
X-Gm-Message-State: AOJu0YzwDEucF+qZDfI30dMz/OU9KvTWPL4aLMEjyEcmhmPidkPOe3Gc
	WLtJHnj54Y4jTCGRyz8DlS54mcAoXkJZjTwEhMFHs14lPAaPfFxL
X-Google-Smtp-Source: AGHT+IE1okPMYf96VL4IJriBeI4qDf2Wim5WzRZFCyA+8Nvt68UTw2OjwMltJ2HxZ756Yk6CJo0a5g==
X-Received: by 2002:a05:6512:280e:b0:545:6a2:e58 with SMTP id 2adb3069b0e04-548392685damr1980129e87.32.1740167844010;
        Fri, 21 Feb 2025 11:57:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFqlBeT5ZgeUzVCwWWWvcoc5efWE7jy4myLlfpCPFWHTw==
Received: by 2002:ac2:5f63:0:b0:546:1d78:82c7 with SMTP id 2adb3069b0e04-54838e9f43bls238175e87.1.-pod-prod-03-eu;
 Fri, 21 Feb 2025 11:57:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWDYUd6KWk+2yoh6Gv7v8kpUogfd29x+mWOWWimITSgiMli9EBiE8CHzT4kHxiVDsPAinpfVyLwGqA=@googlegroups.com
X-Received: by 2002:a05:6512:130b:b0:545:3dd:aa69 with SMTP id 2adb3069b0e04-548392685f4mr1763896e87.36.1740167840907;
        Fri, 21 Feb 2025 11:57:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740167840; cv=none;
        d=google.com; s=arc-20240605;
        b=IoIS0+XAS+3MjW54/STjOwvUybr3G7MKzGb9lgq/0QLNFLlmqmVkFd2zGKLW29Yd62
         85SCnj5ZCWN2dlVb6ZUGZTA8wUDmpFVB/m9CcrzOASH8iZ5OB8Rv/+eouIG3C5ttWv7X
         g9pIgZ4aOwX3PJZy8wh60ODxHJwsU8AoQnfCYC5tNUR2wQBahwcEOo3M/xQVHPkWccH4
         IYJYfckxAix3Voq66B4ImthEIDxj2anIJ2faDczjl+HhIPa8bZbtKuLJTqErBD2ZvFT0
         65aV+yz014MaA/WUYOZCGCOXf2XNnBhjFVxS5dEUcA7XIKNrXoBdTKxIgCJfzQfX8zU5
         6EnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hL9ZIhAp39JgGtPt+XHHRB4UdgOeBbU7cs9PT+4BMkc=;
        fh=p9qVCSW3g/knQl1jy4WovKLdPkqy2lNlDCIoDQ06JPc=;
        b=Fyxqh2iGWFZCQowiMrgwjyy08FYQ07ZVRlCIH7yb+Yp1SjfZvYC4P0TkWxqSRwIP41
         bFaMwflvipVLcZ1Rm3/BEL8Cg3S8S+BaY0RpNlZRh4L2JNLr8O8HoYKSXnlod+u+ZBV3
         Gt0GfdPDiq21Oo90R2s0G2IA87LcDV+x4ZVbPbqQw8GoYLce4PKtvlO18eYFIDW6W5Cm
         auG4DlOXpt8rHwvJx/iyHdOclPW4xy2i84LJYuFzHBluPZZXxD4tnuZehejh4QIkyhHv
         QLc/EexfOeHkEIEur+4g9u+2KMUwfuD1uWrOUpiDR5d3117Fykb56IZU8kteThcazo70
         F1TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=SWBFReg0;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54526ecd5b4si180246e87.6.2025.02.21.11.57.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Feb 2025 11:57:20 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tlZ96-0000000Ew9O-2QH2;
	Fri, 21 Feb 2025 19:57:12 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id C10D730066A; Fri, 21 Feb 2025 20:57:11 +0100 (CET)
Date: Fri, 21 Feb 2025 20:57:11 +0100
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
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
Message-ID: <20250221195711.GG7373@noisy.programming.kicks-ass.net>
References: <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop>
 <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
 <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
 <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
 <772d8ec7-e743-4ea8-8d62-6acd80bdbc20@paulmck-laptop>
 <Z7izasDAOC_Vtaeh@elver.google.com>
 <aa50d616-fdbb-4c68-86ff-82bb57aaa26a@paulmck-laptop>
 <20250221185220.GA7373@noisy.programming.kicks-ass.net>
 <CANpmjNOreC6EqOntBEOAVZJ5QuSnftoa0bc7mopeMt76Bzs1Ag@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOreC6EqOntBEOAVZJ5QuSnftoa0bc7mopeMt76Bzs1Ag@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=SWBFReg0;
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

On Fri, Feb 21, 2025 at 08:46:45PM +0100, Marco Elver wrote:

> Anything else you see as urgent? Re-entrant locks support a deal breaker?

Most actual locks are not recursive -- RCU being the big exception here.

As to this being deal breakers, I don't think so. We should just start
with the bits we can do and chip away at stuff. Raise the LLVM version
requirement every time new stuff gets added.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250221195711.GG7373%40noisy.programming.kicks-ass.net.
