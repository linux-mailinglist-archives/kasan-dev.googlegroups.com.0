Return-Path: <kasan-dev+bncBD3JNNMDTMEBBF7R33FQMGQEWORRESQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oE3GAJq4d2nKkQEAu9opvQ
	(envelope-from <kasan-dev+bncBD3JNNMDTMEBBF7R33FQMGQEWORRESQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 19:55:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 919058C3D0
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 19:55:21 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-8946e21ad8csf56095376d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 10:55:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769453720; cv=pass;
        d=google.com; s=arc-20240605;
        b=AxH5DXN6z1vMoldAcuXWSP9nu3bxgC8WAL6X3R3C5zF/2FcaDwyP2ax6JwnbT7EulQ
         6/YZ5WlmmUfgjlArtuJZUaEs218OSq1npu/N9JjfjToW18DqIoRW3yg7eHV80M1bP/pK
         zhh14aqf4r/2iqNBnU12q2aBzIBu8ck239FbgupxD+2R2xEXHwKvS7dl0TB42P85JUNf
         wsfZbAJaUI/ToFhIY5jDsaGCH0hdQN3e8YzBLX2Y0lz4TqY4EK2TC49+ZlvTZev40Jwe
         zrvxt0Asg9kl1WhiDrhOgmqVCMyeNTkwGi/Sqmmt416//z8B5AUr2HxWY0f0XYWQmQ6H
         RebQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=HxXWQ78ouCdog9Ft5EB1KVPYIqAHHXzPxfOsoNT7lGA=;
        fh=eiKcJuxL+TFuxWqSmASkiCoOfhvmkEXLfg7RgjoRdos=;
        b=GWrQZj/weJOZZdh1Zd/4SAaj1d/Trwb7wdAJL0gCLbYR73NN59XjrcmYq6kbVJfDKI
         9Xo/RhYhhmOC8FxfK/NGb1VtdwVBQqiSfP9bAxIzSX0SavTrOU5yIUG8yiRJVphUksCB
         unZBTw/yWBS8SS4y1i30D1vxa6u/LXNVKUfgDGN0ZZy/MDFPMz34ELIBzQB+U/ikfeGQ
         YDdRdZ1cuNFCB8kWG/f2/4rOMu7arvmjieEoDB5VBTRdm4+OydnMH74CVr+FuiB+yx/x
         ks+snZASFRyUEiYDgqgR+y6sgbCafRBfyLsKprSmYGMfs3XtdenH/4YwB/O8CF8qZB2y
         ejEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=4b+R0ix5;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769453720; x=1770058520; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HxXWQ78ouCdog9Ft5EB1KVPYIqAHHXzPxfOsoNT7lGA=;
        b=xop24HhNKDe70VYvqRp/JRGQaH7G3SjoYPNJuzzjd/mMizAjitlhWxwrOeihZvpOlh
         c56/aRskkgq5KlTtUGMcglXwejhXba986Js8FstMF2wmT3KV5+1dplQ5Q3J3iiK8GQKx
         J241tA4aUVZ0AuReg381W5TqxgPc/31GqO2PKTkLYqh16lGVx1x9SrtveTNlLqWh7oef
         hI3ib5at5pt6K8xyZtb//XFI/vB9CVlkELi3g2ERWTdA6m0q4F8rPVgjSzVPQZa0SoTa
         9VWZwovHuwiiGE7JP54OprDQU+27oiKEqkYvdWJY0wKENk5Nr/UAcfz8/ajEE76mRUqB
         dfmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769453720; x=1770058520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=HxXWQ78ouCdog9Ft5EB1KVPYIqAHHXzPxfOsoNT7lGA=;
        b=XqHgjhKFYRuUaCefbr6keMc/qPx/Wsu2sLrhtYNPj4MAZszcv8ckNqHUiQ5VosvrMj
         ga4nlaIhukv73BwWrdE/9/leO2zObSzmFEXjGKzXOLZlCjvaLtE+WPpdoXjTnltjBn9b
         1YoWT9nGdzRGI2IqXO1Yj1mwOfqudpHeoFhA2Q0oxnFzpMQ5P4de9sBU0nGmf7ipriOf
         nB1prNyxWlbEilYvS0To9n/ovwAqsZ+zrAyzypbWfY7Mp67tDFKGbjLRq/AAjbwF42SR
         uTplbrQR0gzo2+nU7I6xd+rrcvlz3pGFKmG1w/oFnAcGDoKPuFjvti1jYKGRoyCqod8H
         nqxQ==
X-Forwarded-Encrypted: i=2; AJvYcCWoBbTOFwEGT9/u4S88vQDvZ/oEiXUIMnz7h7AKaxunRgRzje9Ud9a3Si6Q1cNrKxely0IhKw==@lfdr.de
X-Gm-Message-State: AOJu0Yz89ol52NtJVNWrsy++VglmUYTScrUJ2o3krmOguVOph4L76lvw
	85QMaVGYIEaOX4Bn0B95blI+pBlGRq0QRa25k/mB+8eGzpQoXDdtuv8a
X-Received: by 2002:a05:6214:2624:b0:890:e2d:a9d6 with SMTP id 6a1803df08f44-894b07babc5mr70786666d6.68.1769453720134;
        Mon, 26 Jan 2026 10:55:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FDjwdM8T1aTSrMAf81mymRKsMxj3yO2Pe8pyEKDsMiuA=="
Received: by 2002:ac8:7e8e:0:b0:4eb:7676:b2f with SMTP id d75a77b69052e-502eb8bda71ls79463881cf.2.-pod-prod-08-us;
 Mon, 26 Jan 2026 10:55:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU2oet6NCL3BNI94e8Fn85n+QQ7J4j0m3WU7p9X359dgZBX25MpzJew5648Haa1ctiOg7uYKQED518=@googlegroups.com
X-Received: by 2002:ac8:590e:0:b0:4ff:b2a0:2b2e with SMTP id d75a77b69052e-50314c74419mr72680171cf.46.1769453718916;
        Mon, 26 Jan 2026 10:55:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769453718; cv=none;
        d=google.com; s=arc-20240605;
        b=GCDmfSdT/8l95qGLSqdHYTl+TOpcsKr4G9GacZ3xVfqeeSKOdz5unYmwmHznT1Mv9Z
         ad2PBy3oWONsJz0CvoQP6aoWSaF5qiiu3jD76v/aiqfU+ONXI7fK75wmUkevIhp5KkMi
         b1v9G6tGa6R8N3IxucaERML17q6OrrT+XVNKhgZE64NkbD1ePGmR3e193otJzRjlfvbu
         +qz3Mc1TlbWu44lEp7j5OiEqcyCVjgE9FO6/vyrvjkwsTX2m/dybhMbp7wEb8AgAm0lN
         r5YtFYfk1UqBnO5YTirOD//4LzuyonXoaj9guLNN3Q3fG4pfZMzviE4Uk+9BbzaM1LbW
         s9rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=lrmRnMiS7e8oDqS8sJHadbKNaRE4y8/9HerN9jURAnw=;
        fh=gxy4knLMkqk26VcUfaeRtWia6+1L36ooxTX+CrbnkHg=;
        b=gsnUaWI6Z5nCJ3pU8+yAKDgi4s25oWYqvA+f6ELHcj7kgZ40mP++EfJv7v2J1G3iQ0
         MXX3UykDsFXQX9+Ux93awwZxun3rpxFf4vAa2CUyZEKYPyz7FSZDzIVQItP0FBrz29y1
         uq3w3VZVulfnNLVG4NTVOmJmAfacR45nBOaLH1aHTo8ILB8yioOiyeVOaE4c8n9IfUYU
         qKWXQtxbnYcICV8XEm0BXYXycqHxKfgaKn4mppdgARIQJtebrt0ULAWL1NthjlKVes/p
         LYXyq+c5+M0bu/2gpQmLEzAbOJAEY+6E3xBlUSd6vaolBP1GKdUPQ3fv8GZFTVA8DvS/
         1Wew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=4b+R0ix5;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c6e38361d1si36709285a.6.2026.01.26.10.55.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 10:55:18 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4f0Hm56kBhzlgyGr;
	Mon, 26 Jan 2026 18:55:17 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id vhOvcRL97NLm; Mon, 26 Jan 2026 18:55:09 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4f0Hlj4MJNzlh1T6;
	Mon, 26 Jan 2026 18:54:57 +0000 (UTC)
Message-ID: <8c1bbab4-4615-4518-b773-a006d1402b8b@acm.org>
Date: Mon, 26 Jan 2026 10:54:56 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 15/36] srcu: Support Clang's context analysis
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>,
 Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>,
 "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-16-elver@google.com>
 <dd65bb7b-0dac-437a-a370-38efeb4737ba@acm.org>
 <aXez9fSxdfu5-Boo@elver.google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <aXez9fSxdfu5-Boo@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=4b+R0ix5;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBD3JNNMDTMEBBF7R33FQMGQEWORRESQ];
	FROM_HAS_DN(0.00)[];
	RECEIVED_HELO_LOCALHOST(0.00)[];
	FREEMAIL_CC(0.00)[infradead.org,gmail.com,kernel.org,davemloft.net,chrisli.org,google.com,arndb.de,lst.de,linuxfoundation.org,gondor.apana.org.au,nvidia.com,intel.com,lwn.net,joshtriplett.org,nttdata.co.jp,arm.com,efficios.com,goodmis.org,i-love.sakura.ne.jp,linutronix.de,suug.ch,redhat.com,googlegroups.com,vger.kernel.org,kvack.org,lists.linux.dev];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_GT_50(0.00)[50];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	HAS_REPLYTO(0.00)[bvanassche@acm.org];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 919058C3D0
X-Rspamd-Action: no action

On 1/26/26 10:35 AM, Marco Elver wrote:
> That being said, I don't think it's wrong to write e.g.:
> 
> 	spin_lock(&updater_lock);
> 	__acquire_shared(ssp);
> 	...
> 	// writes happen through rcu_assign_pointer()
> 	// reads can happen through srcu_dereference_check()
> 	...
> 	__release_shared(ssp);
> 	spin_unlock(&updater_lock);
> 
> , given holding the updater lock implies reader access.
> 
> And given the analysis is opt-in (CONTEXT_ANALYSIS := y), I think
> it's a manageable problem.

I'd like to make context-analysis mandatory for the entire kernel tree.

> If you have a different idea how we can solve this, please let us know.
> 
> One final note, usage of srcu_dereference_check() is rare enough:
> 
> 	arch/x86/kvm/hyperv.c:	irq_rt = srcu_dereference_check(kvm->irq_routing, &kvm->irq_srcu,
> 	arch/x86/kvm/x86.c:	kvm_free_msr_filter(srcu_dereference_check(kvm->arch.msr_filter, &kvm->srcu, 1));
> 	arch/x86/kvm/x86.c:	kfree(srcu_dereference_check(kvm->arch.pmu_event_filter, &kvm->srcu, 1));
> 	drivers/gpio/gpiolib.c:	label = srcu_dereference_check(desc->label, &desc->gdev->desc_srcu,
> 	drivers/hv/mshv_irq.c:	girq_tbl = srcu_dereference_check(partition->pt_girq_tbl,
> 	drivers/hwtracing/stm/core.c:	link = srcu_dereference_check(src->link, &stm_source_srcu, 1);
> 	drivers/infiniband/hw/hfi1/user_sdma.c:	pq = srcu_dereference_check(fd->pq, &fd->pq_srcu,
> 	fs/quota/dquot.c:			struct dquot *dquot = srcu_dereference_check(
> 	fs/quota/dquot.c:				struct dquot *dquot = srcu_dereference_check(
> 	fs/quota/dquot.c:		put[cnt] = srcu_dereference_check(dquots[cnt], &dquot_srcu,
> 	fs/quota/dquot.c:		transfer_from[cnt] = srcu_dereference_check(dquots[cnt],
> 	include/linux/kvm_host.h:	return srcu_dereference_check(kvm->memslots[as_id], &kvm->srcu,
> 	virt/kvm/irqchip.c:	irq_rt = srcu_dereference_check(kvm->irq_routing, &kvm->irq_srcu,
> 
> , that I think it's easy enough to annotate these places with the above
> suggestions in case you're trying out global enablement.

Has it ever been considered to add support in the clang compiler for a
variant of __must_hold() that expresses that one of two capabilities
must be held by the caller? I think that would remove the need to
annotate SRCU update-side code with __acquire_shared(ssp) and
__release_shared(ssp).

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8c1bbab4-4615-4518-b773-a006d1402b8b%40acm.org.
