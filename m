Return-Path: <kasan-dev+bncBDGIV3UHVAGBBFXT5WEQMGQEUTP7VWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED3AD406E29
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 17:28:22 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id y6-20020a05651c154600b001c30dac7e87sf1075746ljp.8
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 08:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631287702; cv=pass;
        d=google.com; s=arc-20160816;
        b=a9WvfXQy5c59soopOc/j9wHk74nfReZa6DUiKovULF1LL9t1Wk1FQAFpmB9Lmym4mb
         awtiIMhcMxXABn3601Tf1Nh7z1HY/dNiXe9TZByD3TRzzprv7p7oNwpyG6TwkmMpDLtO
         eA2V/avBxh9c+KP5A7dgPvIS6OzSQQbuDBmchVaoKWUFJiB87Y7nwwfDk+FMaXUTkZbw
         hEgQhIE/RI/IYdiYFjzKm0wgv+MQf5WgI1VlSuYRw0fnuatgnTXwn6VtNv7SbiUp55YZ
         Ee+y1N64tJlYSxZrsUwntXHgiVek5ezqUBG4Ycz7pNo6SMV8xJA2KdzY/HdF6+Qyt7kE
         lLgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8rmQF684wFyn5cTGwB+AqZ1jNISHDahJhMCdko9CGLs=;
        b=ZqWvpDLaqhuF3AEymMMPf0S/Qk6bsQGO8upyti/K2IVIFiz1ctji8RSh1WQV4qsfXh
         yL1d54s7ZZS9ManSt2khfzLySMq0mrKcBG5QjVL6Ld97ixjoo3ghNhP84iKL/yOwDUxG
         2K6s9g6/OGdJAefOueXfm/Ejv4AHdxPSQ/90bCi9wLyae5tyqMeRLiyCcJoDULaQM/ql
         F1zyRG9xtoHOl3kjm4BwnVU1BrODmN85PcpH/cJXbfPPzcebyK1ZsEp9uoNTc1PsxjJt
         n36MAQxMg6Ro8aW7iLWPEH8U7k9mFmygUuago60lvqwwCnNaoBEUnvLrVZaRPz0tifCJ
         mAdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ol31PPlD;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8rmQF684wFyn5cTGwB+AqZ1jNISHDahJhMCdko9CGLs=;
        b=SWV21+k+uhWaIYzdF/Tmt969gHu97Eotdyo4jt4XvEYIP655+l5E+Y/iwcQDcaaO1K
         Sdf0LS47XXUYjjzmMhRRiyUQRuv2clXBxDAS1Xalv4D+O37G6mK4wza1w0878J3yUfYb
         CM6XAGUos9vaG2AuoELM/CHMEpn32nK2ETFpkUa9V/Mhw4/k+fgGK9tJE+PcGPZxM36h
         dCPPMKRoOVn93mmGATwjnw4vcyRfUOyA/1S1itkzhmwm3XiT/oJ4r28rRlT5jeekzM8P
         xN54a7WYPIT+4eusF8KaHdYdhe1CBlLr4iQE744dTJ9hiqXZdvDCCuY1JlSd8m88hSaJ
         22AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8rmQF684wFyn5cTGwB+AqZ1jNISHDahJhMCdko9CGLs=;
        b=q3QqgZgv9at/ZIfmGrTYjN7cRQtvNurOHSlURFe4Wz43Oxgh9Sa1iGOHiqYIYMF+CJ
         wW8x0iaE2R4ymcSHkLUtcC7q0CTITGXn4pOrJteQiMxGJbi/0g71iDSR8FFJykPSgIMt
         hYR54pa8VqgcOmi6tW2o2MOGREd8EhnRy2wqFIsZHWi+fHK+PK88quMvkkDshByLiNWZ
         QRSDU0LgNSu2CrAyssUL5uzWrT5FvBob2PKrrcGTPDq8ZTrJCBOvOugCCtDbfEOpLaT7
         hSj7lyB/kumCvpMxxRdsPlNoVdbI/s6wyjBUdEoblBtxhBhkMcAMMwhmcCbf3S48MYsi
         bR7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xecDd62pPYAmdpdDJAWX7byzuT7x0CFbzXbG1y+YpmtpwWHKx
	LaJvP0dJC7utQYsky86VO+E=
X-Google-Smtp-Source: ABdhPJxnEyBYtIaHKcr8NkyuNQQ7tB27T5grwgpa/z4l27/e0UzNJprosmKyf0BFRxdMjgPjk56/Zw==
X-Received: by 2002:ac2:4bc1:: with SMTP id o1mr3517019lfq.275.1631287702499;
        Fri, 10 Sep 2021 08:28:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls439894lfi.2.gmail; Fri, 10 Sep
 2021 08:28:21 -0700 (PDT)
X-Received: by 2002:a05:6512:3996:: with SMTP id j22mr4172950lfu.341.1631287701483;
        Fri, 10 Sep 2021 08:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631287701; cv=none;
        d=google.com; s=arc-20160816;
        b=XdWvyM+mMqy0Iwd/8Jx7s8VaIQGEy2vf8+Mha8NlRCmjO34/6eBIwenjHb/5+X2vd6
         XvI3GvaTxZET+N0G2BDLTuNpAivVsoPnCF/qL/6a9hnl0wsQ66/6GvCioOPKYBXNIlZB
         dQsKT5o9qbuZhwXgf0tGHW+K9yHMna47xBws3VhyC6bUNtTM2GuK4X0YfmDE02HkHAzo
         z8jfw7V+syTVaGgIn0vA2YbP5WOu86tU8Iro31OhdiMG4HQCAulTnOfLWqcLAXkH+hEE
         +Y3LOEF+gJlg6ZSR0cs9YAaV8gyMKDcEoDiNR0N9VZKbiefuvBfpEEZgKbS1nwDzA5p3
         EptQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=EI3QVBpMpmvzHjzxfllWn6UuMbjPLIo79cBtSieAgwY=;
        b=c/nmoFWp7QXHlIyj9rwd0ufJE6zh4L2g+QQ2V9fLQ9eKoztQl7TbM6SVTxk5X1K9t6
         DhGsisZdVsdvFELn4FFdZpSokyoJwR5w7dhSk9r+LzPG5ZCzAf1vhNSJjO9FtrYvuKx2
         dhVbAjbaLGLb57Vb7yQVMu5gWRlCqtq3DU/8YPUofMtZhM+E6XMnaNhTsM219eePWEcn
         PqMZwXuW3aEpTHfj7wjpw7gM8UiBOrj9LB8UJfxEwImkG0f9TqAnupw6HpVXxgIsqDXF
         bz5IZQ0aIODjMaHadYZEVNdRfzq9C6J9/Q5IEGufqB/5Sb2BMR/rB8Zk912jTfrfSkjI
         Xjhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=ol31PPlD;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id h13si431759ljj.7.2021.09.10.08.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Sep 2021 08:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 10 Sep 2021 17:28:19 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Vinayak Menon <vinmenon@codeaurora.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Aleksandr Nogikh <nogikh@google.com>,
	Taras Madan <tarasmadan@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
Message-ID: <20210910152819.ir5b2yijkqly3o6l@linutronix.de>
References: <20210907141307.1437816-1-elver@google.com>
 <69f98dbd-e754-c34a-72cf-a62c858bcd2f@linuxfoundation.org>
 <1b1569ac-1144-4f9c-6938-b9d79c6743de@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1b1569ac-1144-4f9c-6938-b9d79c6743de@suse.cz>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=ol31PPlD;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2021-09-10 12:50:51 [+0200], Vlastimil Babka wrote:
> > Thank you. Tested all the 6 patches in this series on Linux 5.14. This problem
> > exists in 5.13 and needs to be marked for both 5.14 and 5.13 stable releases.
> 
> I think if this problem manifests only with CONFIG_PROVE_RAW_LOCK_NESTING
> then it shouldn't be backported to stable. CONFIG_PROVE_RAW_LOCK_NESTING is
> an experimental/development option to earlier discover what will collide
> with RT lock semantics, without needing the full RT tree.
> Thus, good to fix going forward, but not necessary to stable backport.

  Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
for the series. Thank you.

As for the backport I agree here with Vlastimil.

I pulled it into my RT tree for some testing and it looked good. I had
to
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -3030,7 +3030,7 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
        head->func = func;
        head->next = NULL;
        local_irq_save(flags);
-       kasan_record_aux_stack(head);
+       kasan_record_aux_stack_noalloc(head);
        rdp = this_cpu_ptr(&rcu_data);
 
        /* Add the callback to our list. */

We could move kasan_record_aux_stack() before that local_irq_save() but
then call_rcu() can be called preempt-disabled section so we would have
the same problem.

The second warning came from kasan_quarantine_remove_cache(). At the end
per_cpu_remove_cache() -> qlist_free_all() will free memory with
disabled interrupts (due to that smp-function call).
Moving it to kworker would solve the problem. I don't mind keeping that
smp_function call assuming that it is all debug-code and it increases
overall latency anyway. But then could we maybe move all those objects
to a single list which freed after on_each_cpu()?

Otherwise I haven't seen any new warnings showing up with KASAN enabled.

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910152819.ir5b2yijkqly3o6l%40linutronix.de.
