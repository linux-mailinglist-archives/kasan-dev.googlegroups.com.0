Return-Path: <kasan-dev+bncBDY3NC743AGBB462WHDAMGQEEQ7WX3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id D12D9B86EC1
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 22:37:08 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-7246d398cfbsf14460227b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 13:37:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758227827; cv=pass;
        d=google.com; s=arc-20240605;
        b=HkavKqY+4I07c2RgGirJJ5rzEI20sqPUn/fabPcA0TeaxmexQh8sIsjGGvK2OK0drP
         kNOhlWHcLsnMDrtSBwroPzrEwpCRPR3kZZtcYlAVvgPW7bN8/MImfhcXkMA2kDxgirDV
         PaHOFofp5dK53oMWgkViMd/qc20+7ASTwi1q4Kr1GxUNGjCgNaDwsDJg4Otjr0TZFCBC
         rX/ozRXeQYl0LO3nRkaXgr1H+QfsWMQPFvrs+UVjhJtfai5Y1w+uLCzxmb0hNJf5bXMt
         aULBkKcz5dLOjDtOKy4FQzl3pseKeaiyR+Lp5NRmMeN7w6Xr+/nFaWBhsPO/Z/AlihrV
         pENA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=tS3kvVAHjdlyjzzAYwG/7l9PFfKF61l9V2VrN/+fdCg=;
        fh=cqwnuuxtFWn29YcfK6p9RALcf2D/qV/FFeEeP9X7d8I=;
        b=S7gZla+FeXjWS2i5AnWtMcVNE479NLWHuEjQUtThK7UTNA0wPX5F6C95J+9Sl6s0Pr
         rXDJ7AZ60Dhf7ynCzjStPev8DJ0Bka1iEAT+s7kHNXfeGhLTrMlcfcv+4utIyly/YK5K
         OST9SD+lHjIEEOiXB1b9Sd1y5kh0lSKpO00g+MXar5tfX9T9vBbELIh4U+ifIi3RELsX
         OIaB9pWIg3REwBi+RPewXFM08SIP3wqUFGiFba3N1wDLa4hOaPMbznskd1mhrbdd6NM1
         qSy++mRTs5bfndVlymJqgFlfLEKkCoqR1WbSnjZlCcbzTG7euz6EkCVMfoGd3tnvz4Sq
         i+PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of joe@perches.com designates 216.40.44.15 as permitted sender) smtp.mailfrom=joe@perches.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758227827; x=1758832627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tS3kvVAHjdlyjzzAYwG/7l9PFfKF61l9V2VrN/+fdCg=;
        b=OjRjWG7vr+uIvv4ixVGzn5yCObI8DJQNf88ZzJiZv8FUcfGBzkWcq3wt+JeKnf0qfD
         OzNQuIWLohbBub0Hl23y8PBsfTY168qCFmTXj9iyXyzcsk+lu0bsBTIelJyBXpkazwq4
         65BjHChNulYd00eEAw0tFeRwDDZX7XiHapKuzUQmWoO+Ttc6toWNezjD8z/QGR+7JVab
         JDmrmsI6Ar77jdYyw15tvssp48dhQuCKhpN4lQEOsziPBnOORdQ2CsNbDkEIBEWwK0OA
         o/ZeYaiLabMdK7zgiQX+BjIYeLMmWNzxh6HFVg6S4Q1UHTMIkU9ksmkx92AncGv57t/7
         sOJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758227827; x=1758832627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tS3kvVAHjdlyjzzAYwG/7l9PFfKF61l9V2VrN/+fdCg=;
        b=QLXkltRCMP8/Tk+XOUuGM7GtQw4+tum/4Jvpy3LSRM0mABy/VozaSfxl89Ak7vPH8C
         TwAQx8FI/yj9rEQ0c0WhbPlvbEgOcd0RjJxcyQsksSXX9GN67PpLCbsxsB8oyIY92WRg
         vh1KnqmF/hv5g+opmCxqp8RwnUw40BAS9sqwm+HIQAJEh87xyWUE6SpHRMBLMZOTItim
         VtxzBEXGR11YY5JzWCja104VCaP7anoc4DT3BWSed1P84+fnvHpTycc3YDyKXvKS48D/
         /wJHU7Nnrkvgw619Rkt+PjdVSqABnmIsRe0zQyc8nrgP6hial3/7lLg2TX4xraHYWLAD
         swUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXN1+BzwYKkyh+dv4Sp3hlPL4TQ7TfPOVEZXu2sv3trT3XqGO7z1zuJNERg3zj6xlbBKk6h4Q==@lfdr.de
X-Gm-Message-State: AOJu0Yy5MwxeVtp/HWQBUEk0a//iTFF9JkA0WynfXxrPC+DF896OUxQr
	6qVCuIy3CSm7KnSTKV+AutgJD7WYWQsa71CIWZYMFt5Bx7Vndz77Yc8o
X-Google-Smtp-Source: AGHT+IHH3uSndpSrN4LcYAwt6ppPQIs5GJv3aQtFrURnvfgAG5zeNixOxf7cEqGV6gkERXrAgmT9qg==
X-Received: by 2002:a05:690c:6503:b0:737:91f6:3f7b with SMTP id 00721157ae682-73d3ef2beb6mr8517597b3.45.1758227827607;
        Thu, 18 Sep 2025 13:37:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd49EsHac24VKJv6oPqS8AplEhlkRnIqrB39PBjLj8cLzQ==
Received: by 2002:a05:690e:2489:b0:616:721d:7aa7 with SMTP id
 956f58d0204a3-633bdd5f1cfls363876d50.0.-pod-prod-09-us; Thu, 18 Sep 2025
 13:37:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVY53R3FXoAcWPRLbXR9+bMtho0wdWTT/hRj2U7cwh4dZAkNz9KD/BDD7e0Pu6faMJDecpyTCWkwPE=@googlegroups.com
X-Received: by 2002:a05:690c:3745:b0:734:55b6:edbf with SMTP id 00721157ae682-73d3daf700dmr6620457b3.40.1758227826146;
        Thu, 18 Sep 2025 13:37:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758227826; cv=none;
        d=google.com; s=arc-20240605;
        b=KzYoCWKEYkYusmTRD58ulOqueWr/srDIynW0xKQ/0w1x+uUy3ZPMj50kXyCdxY+PdG
         tFzlenCIwjR133ORPc2Ro7RQmDkRXdHh7SdJE3i1Vcn0Vwk2VvtVC14y5urk6A67XJu3
         K/nRsADb1TaxcdoJP61LXmArzHeBRzcRL61dx4PXKR5K3OuQN+8JmcbkCd6kSsFmDIHR
         HyJtAoVdtlsVV95VPFywaBP308EJqpRO4ezOuJptgThDaBTMXo7GEuOoluxaziEd8jVs
         xXemvmKC4UgKhh4dfpjpTAPrI+Y3cAnTpmjDBdn/bPorOL+b1bz7QBp0JmBxTPZMFdQV
         k8Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=v7xpfX6fEkkbnStkewG7QbtECvAPIycp6/D6Q3kleRs=;
        fh=nYlnhKUq83JolEGDeFd0oa1y6OOSPIITltcqxb2l/mQ=;
        b=Ivc6NcuMkZCExAF29uibBC1I958StWfzIP8oYFDJ1AvKHubHXUnZhNODgX3fyfgms9
         XmBGZ3qqP+kgi7lt7We0GVZ+ujsAq31xsXkWePNEknyd9m4Yt9XBTDvY7QB06A3vBnnV
         WyrOn55/7fHq7xOvO2SIB+T9NsfObczAfd1SP0Mh/8k2jTVMXvgYktGhXd7/bs/g1NJO
         wYmwjf+rTQyy6IVwQ7L7GBE6cvvZwBcZWG16kLP6DGrM4QYT1fbHyYINV6yFVPVrIO40
         gwUpplntWyASexZE7GwQITyrIrsO4A5mJ13WylT1hwfIfb8L+9ySHKJDf1WiL4AxA9Qh
         bH3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of joe@perches.com designates 216.40.44.15 as permitted sender) smtp.mailfrom=joe@perches.com
Received: from relay.hostedemail.com (smtprelay0015.hostedemail.com. [216.40.44.15])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-739718b2e32si1179907b3.3.2025.09.18.13.37.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Sep 2025 13:37:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of joe@perches.com designates 216.40.44.15 as permitted sender) client-ip=216.40.44.15;
Received: from omf03.hostedemail.com (a10.router.float.18 [10.200.18.1])
	by unirelay07.hostedemail.com (Postfix) with ESMTP id 8E6D31604ED;
	Thu, 18 Sep 2025 20:37:01 +0000 (UTC)
Received: from [HIDDEN] (Authenticated sender: joe@perches.com) by omf03.hostedemail.com (Postfix) with ESMTPA id 9D9BE6000D;
	Thu, 18 Sep 2025 20:36:44 +0000 (UTC)
Message-ID: <13389786a2a121c21a6f4940b4acf09fad53a3d9.camel@perches.com>
Subject: Re: [PATCH v3 05/35] checkpatch: Warn about capability_unsafe()
 without comment
From: Joe Perches <joe@perches.com>
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will
 Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck	
 <luc.vanoostenryck@gmail.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
 Alexander Potapenko	 <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Bart Van Assche	 <bvanassche@acm.org>, Bill Wendling <morbo@google.com>,
 Christoph Hellwig	 <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric
 Dumazet	 <edumazet@google.com>, Frederic Weisbecker <frederic@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ian Rogers	 <irogers@google.com>, Jann Horn
 <jannh@google.com>, Joel Fernandes	 <joelagnelf@nvidia.com>, Jonathan
 Corbet <corbet@lwn.net>, Josh Triplett	 <josh@joshtriplett.org>, Justin
 Stitt <justinstitt@google.com>, Kees Cook	 <kees@kernel.org>, Kentaro
 Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn	 <lukas.bulwahn@gmail.com>,
 Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers
 <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, Nathan
 Chancellor	 <nathan@kernel.org>, Neeraj Upadhyay
 <neeraj.upadhyay@kernel.org>, Nick Desaulniers
 <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa	 <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner
 <tglx@linutronix.de>,  Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki
 <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Date: Thu, 18 Sep 2025 13:36:43 -0700
In-Reply-To: <20250918140451.1289454-6-elver@google.com>
References: <20250918140451.1289454-1-elver@google.com>
	 <20250918140451.1289454-6-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-Rspamd-Server: rspamout04
X-Rspamd-Queue-Id: 9D9BE6000D
X-Stat-Signature: py53mcfac346e64tk9rcf8ugswnwrn9n
X-Spam-Status: No, score=1.38
X-Session-Marker: 6A6F6540706572636865732E636F6D
X-Session-ID: U2FsdGVkX1+Psz6mclmN7I07c5jPtb/CcemQyIEeoMA=
X-HE-Tag: 1758227804-881299
X-HE-Meta: U2FsdGVkX1+3ZResTrAAf9g9L6dJTCgmeXzyM4kYyOanBXCbxLPKLUzexU279fp4Uk1s32nIlGL7ALFntG4iQsakleJTeVRQim4oreS1teDe2c1v+Yr3chddZziKPoDc++AISXJQPhyq2w3G+YXN9VlSwrMnsmWf2JBDP+6EKscCwfkdUqEPS2c1jIOhGC9JFL5oLKZVp7yaxDYTVOVvcxJD81BMXbf5A4qGtQvLNkMWZnMoJtyHKmlojlv7i6K2T4g5I4c9AZ5UYsKsHO+RYQ2ZU++uSS7Q3j7El4OW8jbzA/Y7Pj1Sh8vbE9tWV5T5
X-Original-Sender: joe@perches.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of joe@perches.com designates 216.40.44.15 as permitted
 sender) smtp.mailfrom=joe@perches.com
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

On Thu, 2025-09-18 at 15:59 +0200, Marco Elver wrote:
> Warn about applications of capability_unsafe() without a comment, to
> encourage documenting the reasoning behind why it was deemed safe.
[]
> diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
[]
> @@ -6717,6 +6717,14 @@ sub process {
>  			}
>  		}
>  
> +# check for capability_unsafe without a comment.
> +		if ($line =~ /\bcapability_unsafe\b/) {
> +			if (!ctx_has_comment($first_line, $linenr)) {
> +				WARN("CAPABILITY_UNSAFE",
> +				     "capability_unsafe without comment\n" . $herecurr);

while most of these are using the same multi-line style
I'd prefer combining and reducing indentation

		if ($line =~ /\bcapability_unsafe\b/ &&
		    !ctx_has_comment($first_line, $linenr)) {
			WARN(etc...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/13389786a2a121c21a6f4940b4acf09fad53a3d9.camel%40perches.com.
