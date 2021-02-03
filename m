Return-Path: <kasan-dev+bncBD62HEF5UYIBBHGD5OAAMGQE7BI5TQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id CE2F430E15A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 18:47:08 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id g24sf436723ljj.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 09:47:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612374428; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPtmCGp/QWHZWhF8I+z+VO6DUOXUP/vHEtJ/q9Ru3feM80IKwySDNRR8twQylRDWzd
         HBtbCN1266OJi7Qp9ABRIELQloypGajw/fWkldlfoeYRLxkDN/Q8OwU9d8051lk2kxBf
         jRflwzlIuhQN1BQGVMS7Q5XQLjnyGLTAgRDeuIBWV3eq/2axjXOHlkfWrvigbNxphxqp
         IOiXYxS5y3zSwvZwbvhF8LxtIgCiXmdtRHna39NmUYrmUidCOuLMgpTDxGHWmkhivHn4
         1B4GgHQzmxAS4s3KV0+1cU3WbhRbtrhxuLLbtFT/gXFvLv2rbdlBkx7vWC1wOC/O5yXi
         +PQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HiCU5GkhoIPxJZAXz3N8L+HEYsnNDn52EVD3Yh7s5DA=;
        b=fHSYpG5juKpxz7p4TCDiFi5w1HYsQlxkvFtKvFq64kDP4B951+ieQA1/63JpRJRWJ4
         0ksUtKQnUVb6f36nfKEDQRbel39DOV5F6w7sTpC7qtvWxjySsp2X5B5aCtmreGideY6v
         l3rHJB4TyShAJ2Mrp7Z2RV9r5LFRecuBG4VEXdmmNqwfo+FnfYKqTl5iT7AR1CPuEq5s
         FAyP4xhAWFP7hWYqTuSWgV3/JOakX1kZmdH7LH8OW5farOqUAE54aH1i5ZPqowJdeHpU
         GJb98UjlxZl2XBdEXxXpxWkpj5cclFUni8NN2BHd/G/NoEu9plOLTWyKJfmazqz7i1sI
         F1+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=rAHCkrSC;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HiCU5GkhoIPxJZAXz3N8L+HEYsnNDn52EVD3Yh7s5DA=;
        b=Gz7iVAzPByp3rHte/dUqee78krUwWw0v7dSv/d5Wod6cPB5Zig++pLYNAvaS76yUxm
         jXWrdB0sRk862JhkdayxfUH6nYJnIlGbbS6SIMDBPhsjspVwvlpqHdiv8dFu6eWAJTV/
         YqSF+8A4osBpG8VUX5d6fzNiMVwdqYyNObtLbLmpjDUdAzQUZhBRoYqOzRiddAUvAeOQ
         Zy2cOntjhby8yFS8O1UqIsTJ0XZKNctQCP/nsYyh1DHYGEhtp7xjYEoiE1IVz2GZK4/3
         o6M/QgtZS2N/G+2UypCfXE55FwtVSZIIZWrJX+nJdA8q1tkQ+ocBlAE2V/2adrTY1pU2
         eYxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HiCU5GkhoIPxJZAXz3N8L+HEYsnNDn52EVD3Yh7s5DA=;
        b=GwWqFX8AzwHzFCmoLJtnHMZGPWIR2YtQbyDfRJxXq3Z9eDYI0pVSVb9bu8uSwzPxHd
         cWNzc7Nq1wZCcVFhxVAq+1F7tafqAi5lkSCKSz68ZN3wJ6Fnfr8aciymYAevrkgLotgu
         er7Ucy3jvUyvn/03YQPaxuc9JNTg4GdBLuVjZtXrVM2N7pWM5rIUBljNjJ/bNHBW1vfD
         aUlMt+W91Qk1to5CNonwXRxBZHoiXr2FM6WAvCWkTiZFhL6SExs/bXn6YfH15ezzR4Ar
         bS8tQEv/fcGV2PYzIeg6HW6DSAqCDZoO1tndtrjejuHET9Gh8/IHFVK3RCcehcMI5+qL
         NgFw==
X-Gm-Message-State: AOAM532xZemeXhqu11XKZmshznsqgC04gJPWOq7uBpzM8Sqkqohvi8Mn
	3jn0vbS+UaEDkHtlTQ6LhU4=
X-Google-Smtp-Source: ABdhPJzM67xQtbXwvhJTzYwWb1OEKfBcst+L5psSlN1lqgAN6DBpN+2b6IdkVC9j7iVlmguVEmuJgg==
X-Received: by 2002:a05:651c:1044:: with SMTP id x4mr2308375ljm.239.1612374428363;
        Wed, 03 Feb 2021 09:47:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls859612lff.1.gmail; Wed, 03
 Feb 2021 09:47:07 -0800 (PST)
X-Received: by 2002:a19:a409:: with SMTP id q9mr239571lfc.60.1612374427286;
        Wed, 03 Feb 2021 09:47:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612374427; cv=none;
        d=google.com; s=arc-20160816;
        b=BtoD6sLYPygsHIERyuJXvkgvVx7JP5KpMgKMu37Opd+SNn+4e1yHNDP6Hfl9lJvMV3
         4oWFF+WeKrP4yzgzKdnxizuiuI+TGyIeKShWxJ+9mS/fRO9Z4yWxXHOLURPhXuhWwNGR
         rD172DWBYIBaXq7mI+92tW4C7K8GHfTh7XHz0O3xw+RvcYU2XckrVBj3ZlGOWwxzRMJk
         +DS0KPkvo/1aIWfaJPJibMDLmf1kT5tttMLP64pVy3KI9yORBNItqEHuA1rJZUsfjYoH
         qgn4kdYXCNkYNMwM2GSZ+fXpeEkv3zCIWwf58f4AWQAlMo5yBmVTKY89qZ6DtTI3Fqj7
         LW/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0Sd7lpuzzYzAe84omnrWYz0GYPR/9/jZDwcpOZKoCos=;
        b=FrRifL6bo8IicLzRWZX9y+NLagTL6BY6kWlyRkVKkXS5y1PPKV/dvEMBBgJFEPDOET
         ppK3+vJvqRqFYSrO1RDUWnwcVgJO2y6Zvc2djM5c4FUxKyy/dIgxPNwZEBvghkzwQVjw
         Zq7gJgxu92yUn0hpPcNIDEU0bGfKnBqLezvDOy97xufvWuR//TwuA9QLtqfw2egQ6r/i
         o0eZipAgzJzlUOjKyIGo4ZJ909kT2Ves0C/PnHnDvhoQjGpisc8X3wlhzyta5f39SlW/
         OdxqYlhLvvVloXS6ck4e0uV4F5rRRawE4b1BZFNWteL5PbCyN8CwqarqsFlUN03T94ZM
         bnGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google header.b=rAHCkrSC;
       spf=pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::232 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
Received: from mail-lj1-x232.google.com (mail-lj1-x232.google.com. [2a00:1450:4864:20::232])
        by gmr-mx.google.com with ESMTPS id c6si147015ljk.2.2021.02.03.09.47.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 09:47:07 -0800 (PST)
Received-SPF: pass (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::232 as permitted sender) client-ip=2a00:1450:4864:20::232;
Received: by mail-lj1-x232.google.com with SMTP id a25so92051ljn.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 09:47:07 -0800 (PST)
X-Received: by 2002:a2e:9cc8:: with SMTP id g8mr2376414ljj.479.1612374426835;
 Wed, 03 Feb 2021 09:47:06 -0800 (PST)
MIME-Version: 1.0
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com> <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
In-Reply-To: <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
From: "'Ivan Babrou' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Feb 2021 09:46:55 -0800
Message-ID: <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
Subject: Re: BUG: KASAN: stack-out-of-bounds in unwind_next_frame+0x1df5/0x2650
To: Peter Zijlstra <peterz@infradead.org>
Cc: kernel-team <kernel-team@cloudflare.com>, Ignat Korchagin <ignat@cloudflare.com>, 
	Hailong liu <liu.hailong6@zte.com.cn>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Josh Poimboeuf <jpoimboe@redhat.com>, Miroslav Benes <mbenes@suse.cz>, 
	Julien Thierry <jthierry@redhat.com>, Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>, 
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>, dm-devel@redhat.com, 
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>, Alexei Starovoitov <ast@kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>, 
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>, John Fastabend <john.fastabend@gmail.com>, 
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>, 
	"Joel Fernandes (Google)" <joel@joelfernandes.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Linux Kernel Network Developers <netdev@vger.kernel.org>, bpf@vger.kernel.org, 
	Alexey Kardashevskiy <aik@ozlabs.ru>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ivan@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google header.b=rAHCkrSC;       spf=pass
 (google.com: domain of ivan@cloudflare.com designates 2a00:1450:4864:20::232
 as permitted sender) smtp.mailfrom=ivan@cloudflare.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com
X-Original-From: Ivan Babrou <ivan@cloudflare.com>
Reply-To: Ivan Babrou <ivan@cloudflare.com>
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

> Can you pretty please not line-wrap console output? It's unreadable.

GMail doesn't make it easy, I'll send a link to a pastebin next time.
Let me know if you'd like me to regenerate the decoded stack.

> > edfd9b7838ba5e47f19ad8466d0565aba5c59bf0 is the first bad commit
> > commit edfd9b7838ba5e47f19ad8466d0565aba5c59bf0
>
> Not sure what tree you're on, but that's not the upstream commit.

I mentioned that it's a rebased core-static_call-2020-10-12 tag and
added a link to the upstream hash right below.

> > Author: Steven Rostedt (VMware) <rostedt@goodmis.org>
> > Date:   Tue Aug 18 15:57:52 2020 +0200
> >
> >     tracepoint: Optimize using static_call()
> >
>
> There's a known issue with that patch, can you try:
>
>   http://lkml.kernel.org/r/20210202220121.435051654@goodmis.org

I've tried it on top of core-static_call-2020-10-12 tag rebased on top
of v5.9 (to make it reproducible), and the patch did not help. Do I
need to apply the whole series or something else?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82%2BjBLZ6KD3Ba6zdQ%40mail.gmail.com.
