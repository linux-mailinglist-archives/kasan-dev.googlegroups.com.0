Return-Path: <kasan-dev+bncBDBK55H2UQKRBJOLTLFAMGQEOHAQR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 82C1ACD2FB0
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 14:33:26 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-64b756e2fd1sf2396952a12.1
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 05:33:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766237606; cv=pass;
        d=google.com; s=arc-20240605;
        b=NqEpeId75t5MS40oeLCJ77w4II/j+qZkOQacfmZipAeYIBRsRn7FtdpFUgIdIj5JYr
         v2VQzvfWz6fZKpKyjEGwcIRiuSB/gSlFco4z5jOaZzeu0POUhWcW2FpHHWmbxELayypY
         g1jIe0zz5PkF56zlPhbhS450RdeRbJ5Tgge/YOirh/dcmZoGRQ2Jifo0b4Lhq3/2/vKg
         3bwFtV2nZAwaxsCxrBttiMspXdJep9/AJCABnbl7Ic+SFgo1zjpSnMpmAJD171My1eAm
         LmaPq6wdwh08r4ChDhG0jiopddW2GAFjH5ZXKlGUgTCCaG/MKRHYwPPIs8NLhvP8zXT9
         YsEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XgLkle7ybJcV5cPmi3ZFs0rpKqo0mY65NG4vCTQHsWs=;
        fh=nEDYn3aA2nOV/Gr0d5OHHNEwhmMKnYG5jw3EtsZqWEU=;
        b=Vk+pzJ6YwdgLQ3fp+kTWeKUNJHuBVklDv6x8B4boJHG//MWF5Ark7DTc2yD0f0FPRc
         lLTIhRwIHx0GqWvl9rP2a4XeQLVotuGhwYM8xobM0DH6ahQF0nVlxfo7SnY5p1A0Xbem
         GDXsiw9gBRJ+4CCwdFJIfVFDdyzaXP2VashIgYdO2cqrdjQ9Pt4dAJQdBl+mh4n1/pfV
         XzaBrGkJFhR/phWNmUO3pTX+dLsIFyooO7q38Df+DFaovXwO/p/yNhkTkDrih7rIHDv0
         45ft0WzaAP8kTsGG2VZyOInXJ2phfKEOVqeGArPaqZ7MIDB2QgaFMir2MAVY31IXr5oD
         MLDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=JRF85bcV;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766237606; x=1766842406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XgLkle7ybJcV5cPmi3ZFs0rpKqo0mY65NG4vCTQHsWs=;
        b=wxHeHYEw6/gxUYVtLeY0ZZFx+WwmCJ5NoNj/bRXH6/7lakj58C0v0o9FEsxMK5WlMS
         BWndqpysd6lDMksR+vK64/pIZHv3oJRUmPsh4No+za8CbP+3dJaXS/TdTrNuVYqrHsJu
         KL8+BltVwghsAISXCqLnw8jgcySc7uiSRcWHU0q2C2bM52lx0SB1AqRFY/PBRObJ0xko
         2MTSanOAk0/YTb8uYEQTA0AfK9vWkbTutCaJs+IMle1ATyOJ476dsf+xWOy6GlPUKqIW
         44dvclhDcVAHALUBMV4/1Wel9epSsZBK8Ju1pcVpTvNNj3yiWIn8mBRQunLNrx6CG17i
         GpFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766237606; x=1766842406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XgLkle7ybJcV5cPmi3ZFs0rpKqo0mY65NG4vCTQHsWs=;
        b=jc+TPquhs57gtIKzMqVktQ6wSrxDr4W3nVAs/VTYEsLyK4Ph64KJkN5Aex+DFcEG73
         iXLl9XJM5hHNXFCVClENL92KBZm9DJpl4CkA8rj06BJbhnteMzZskNS+ZFW7UwMgaq1S
         kaFv4mOtz5qNRiuOB9hlygL3hWlK3tdefgyvqZeQcVlB02+e1k6C9Xqa6xj3h6alXsYf
         6/QiGTJ7LHQr8hJ5ZlZD5JbIeO4R4DwzwlEI9EjL1WU6IfwnHEm3pykWdhBtQzYyJale
         F4ecFpommrlLdm+QrxMrk8ciP3LkvGD/pQLCvScn3nfE9wtJ5sNPyjYy8q8bmuq4vKfi
         mxmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWpbF6fH1nZV6cBkJaRztR0TUia0sMmXNX/LG6PimIPG5ampsgXoVcyZF4jmIegstXt5bvkDg==@lfdr.de
X-Gm-Message-State: AOJu0Ywmx+54dGH9V7XdmQ0AhKAPbzHkI10XXuGGtcrbd6yCqA9S28cr
	jYsKqWuiW0bUpsAaQjdLTjxdJ6FvRnuh+ry1mZ1TtrbtnGEYni6z0BnZ
X-Google-Smtp-Source: AGHT+IFPW5OwxwZbE72wuCM2rb2LmrUz2PEjaxPvW5eH59AZV+qmjqKG3lo7gboQzcacwYSVjSbbcg==
X-Received: by 2002:a05:6402:146c:b0:64c:fee2:1dc9 with SMTP id 4fb4d7f45d1cf-64cfee21fc2mr2624396a12.21.1766237605650;
        Sat, 20 Dec 2025 05:33:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWas2dkS6SQe8B17i0LRRcSTohXZirDkz/vK57emNx7niA=="
Received: by 2002:a05:6402:1850:b0:64b:aa13:8b3e with SMTP id
 4fb4d7f45d1cf-64baa138bb1ls1314207a12.1.-pod-prod-02-eu; Sat, 20 Dec 2025
 05:33:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVicEdXU0yq+e/dtUV52aYIEHKwq3t0GbMcHkDAwlrGXSwEvzNQOdqPcGQT1clv7F3w8kP4xCXAkn0=@googlegroups.com
X-Received: by 2002:a05:6402:5109:b0:649:597d:161d with SMTP id 4fb4d7f45d1cf-64b8eef5ca2mr5485142a12.33.1766237603196;
        Sat, 20 Dec 2025 05:33:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766237603; cv=none;
        d=google.com; s=arc-20240605;
        b=kSo6S1lAt1aDjTUZxGkaczQgGEBdqDSHnLhZanyUFQQmxuyrp23jkxnWKY9LzA8+OC
         mtuf7NFNCpSR3mVszrhxRGKxv8T44laAYYpGRlJla6dpX2XsiEnLR6CRpqh5lPWDMfKO
         iNfLMhP9jX1iBDuI5ydMHKlb1QocKBD2oGog5f2IRsODbNxa4MJ1rCoI9FldAV38ubJ3
         iTM+yTURApD7JOabh0TgVdE2w+4nwWaq0iaCmRxX//Tvvu9zBNbik4tuDypwnJTU5HjK
         C436NPkq+beOWJHlSHR6lFhtVGp0cCIj5EczFK+2NjHNJ4J9duCAEWpFm6xKxNhDRJ+G
         mSTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sd8MF34DcKU450XHBOHX76rfibz+4ayylz6CA0Z+S7s=;
        fh=EbbH+STL7PCWaQzVdueOIQE1caWYPkKOMnTwpral9eg=;
        b=bVjbdv1X6i6a3v1y7kqCSk2/yA6vM0jUsdB+rUmazbETwmEYkBsIdHJmikuaafLHnJ
         ZETVV5Q8bKr6lozMy/yF7HDdmsWNHwy0lyMoHfAb4ulCafRxoTwvQ8L4rPwxh4UiIVso
         WIjIhMrHX7kfXnxmGG6lScLpsAnhrkvzN2Ri1k49Kf/ajNF2dw84Q9XFOZ3RWjU1T5P1
         4fA9mvYpOSuLK2UAPhXBddxrnWF8ofzKCbAb4iK4K8exhsbebUkznKZMsQCubaa89mtQ
         9wdNHbpf+5KyDDAXJeZbzUcx3Ewj47KBkpOCm4XWvSKkjVs2oyRCQEqV7pr4NbK0+XPb
         ma3g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=JRF85bcV;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b90412a75si82607a12.0.2025.12.20.05.33.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 20 Dec 2025 05:33:23 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vWwDb-0000000CS0m-1fEQ;
	Sat, 20 Dec 2025 12:37:55 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0441C30057E; Sat, 20 Dec 2025 14:33:07 +0100 (CET)
Date: Sat, 20 Dec 2025 14:33:07 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Bart Van Assche <bvanassche@acm.org>, Boqun Feng <boqun.feng@gmail.com>,
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
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
Subject: Re: [PATCH v5 02/36] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
Message-ID: <20251220133307.GR3707891@noisy.programming.kicks-ass.net>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-3-elver@google.com>
 <97e832b7-04a9-49cb-973a-bf9870c21c2f@acm.org>
 <CANpmjNM=4baTiSWGOiSWLfQV2YqMt6qkdV__uj+QtD4zAY8Weg@mail.gmail.com>
 <2f0c27eb-eca5-4a7f-8035-71c6b0c84e30@acm.org>
 <aUWjfxQ1fIZdxd-C@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aUWjfxQ1fIZdxd-C@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=JRF85bcV;
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

On Fri, Dec 19, 2025 at 08:11:59PM +0100, Marco Elver wrote:

> > Many kernel developers are used to look up the definition of a data
> > structure either by using ctags, etags or a similar tool or by using
> > grep and a pattern like "${struct_name} {\$". Breaking the tools kernel
> > developer use today to look up data structure definitions might cause
> > considerable frustration and hence shouldn't be done lightly.

Its a simple matter of adding a regex to scripts/tags.sh :-) Also clangd
language server sees right through it as is. So all 'modern' stuff using
that will have no problems.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251220133307.GR3707891%40noisy.programming.kicks-ass.net.
