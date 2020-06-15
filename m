Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBVUYT33QKGQEI5UJHMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 44E4E1F9B20
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 16:57:28 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id o6sf5753835oom.12
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 07:57:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592233047; cv=pass;
        d=google.com; s=arc-20160816;
        b=fwCHULCqBcZcfgRzxPg/Q/prYKKzf5Q9hIKISuG9TGh2KroURcnHEqPUFH9PUPTJ5e
         34s+JuZwaIkmRy5fqUVrAwz9u9Vjzr65//0/0rvE5QhD5+3ggNL7CANuR/8K5r/EkiUR
         vlnxhVIZ2fLhGev4cXliPEtbBoP6n5zq+7wXTOFXivwM7FEcyt7NYkYP/omy6Nv+e9IV
         CK7Iy0XUZMd+tydCYdItFMGn8VgeFU99oaHWKIR7P1LDqj+OprR3uSWmR9MdgZrHO1Xf
         rPIzDBw+rvClu+146g9PRX4e4OyfSHkb8CLZ37ZRGa8U9jqdtPKN3UiVY/m8d+HLh6Su
         F9iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9VaxOyoto12/D0ehFlUMjHz7PXqVkngPUEsXDlY0HkI=;
        b=O7LFDpmWjvTVWzRCa1aUEpLdTlI4FYh3oqgssob4he897SrwkXIWENPCe9jMQp8Lgl
         qCC6j1nOVZJ75ewh8FuVcC0yC4FQ69LoeDrM21PyItyc8s1DlzfbE+cl6W3dSSOQTvOx
         aDVLkEm0KKNGNpRlybN3wmQbYbydrbnMBERGNY0yt4xUetaoSropiDquELC7N0iMbIMf
         ervaY+TBG2L5zl4ZPXSmdhs9YLnD0A7SIxg2k2YUzKm7qulhYLwI3FXBk0u9nBuGXdWp
         Pjtj9HXlscii+2pMJu9DIGcas9BYKdp39oy90THaHwCt1EcLWcDBnuuOebbQiNhH+ELw
         2vug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="n5s0/8gx";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9VaxOyoto12/D0ehFlUMjHz7PXqVkngPUEsXDlY0HkI=;
        b=OgYKdjn9VlcRo06FYx9Ou/1DWCl5gqzKRWjIBDnlxp3/cCDMOVO4AeE8KFj1mivQrK
         MKMWlOrBvdfgGoMfqZX9Sy5967y8bAmhzWJe1UviyRwME+XHMwCpE0fS0i7KJ4JbPxK4
         rkugbKUIka/RTnSi87tBR/cOMtEGSwI2iF+5sBpZakqFLYgELLtWtKaMygfjcAnQNpZV
         85RAuzyHwS60DWtvT+4JomfCjIStCEwruvw/jFbJbXa/hOqoljf6pGs1LrTUWqLqlwCS
         iPe5PgvwHCOvhtqF9YUyFHqZy3Ja/ANT2FfFgltFh4I93h6Db39IS2U7cH5pXiad+8sf
         MXaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9VaxOyoto12/D0ehFlUMjHz7PXqVkngPUEsXDlY0HkI=;
        b=qJcL1W1HAb77iZVFtL1p543tnKcMHlk/MZkoT3VLK8YFoIv+kqq1J9AjLlVID8pEuF
         Bsw9tKpzyX/QNPCbQ4OZDt+BzMPFKDe25R0c4g/vzXJFGGh112SWFEY9MOQqykn/FihO
         n1PauqeFH3hgeeS8HghqLV6h74aegRsqQtNhO2WYU4v1Z6TEecfpVSPWDfHoBo9uDU+D
         kdofSMHIxTh1CCSbjIHaMV28uSTZlfk5yRHkCaPECGQA6K8DKfA6S4RKPLvqynHQMcy3
         LhFaX4N/BWJcouLMXf0Drbju+J5Ni4jg0y7Q0b7IAwT7ADZ8W4bD5edgcnS2MILc1zFv
         9s5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309mdnr0X+dukuzXajEsCa563nI5LKttmZBi8wKXd3fOh5QGERI
	WRqEIKCPw0N6MCgrQNqjPc4=
X-Google-Smtp-Source: ABdhPJxGs0OJZ0R4A5EKgYg1HOJatC9/awP7I2XyGXV7bZa8MTIdjl2iHPKW/f9LxpEzbb1B2x0t0Q==
X-Received: by 2002:a05:6830:2004:: with SMTP id e4mr21956440otp.85.1592233046873;
        Mon, 15 Jun 2020 07:57:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:494b:: with SMTP id w72ls2511358oia.4.gmail; Mon, 15 Jun
 2020 07:57:26 -0700 (PDT)
X-Received: by 2002:a05:6808:34f:: with SMTP id j15mr9407793oie.121.1592233046542;
        Mon, 15 Jun 2020 07:57:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592233046; cv=none;
        d=google.com; s=arc-20160816;
        b=HXyRgjFuvmrmMuJxNCBx8LTUB+NgvQjjTFxljrvXQfjiRKgSDM/jVTpW8q/2rVKkSq
         frkhAZtaEhylfTnvz6JbHcD/YsX+UghorwAugU2gXj0t+/ehPlOUGwm4q2ztzSrqudRj
         oH18iqqXb3WNXy8Mg/FYUSwg0sEbu6AwM7jfxSzCsphVxWYmpJ/axA0Qd1Xqr5xagz7z
         LMC/yL329hhTmJnJx1Rk9ctmO7MnhHL2W6pS+5NOtsUjrnV3JkBti+PFiU+/Xs733fcJ
         aixcMtvEmoTlQU3w0x6okebK03qPRVYdUoirTR7RN50e7YDmX2Mos2ytWI3He/L4CAa0
         bIsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=08f0E4d1bwVGcK92LZLgsimdGdtdg5Nb5qVsheDv8nM=;
        b=DmETyaXqXhDeyt++8ZHmJx9QHyWOVKrKNaqt8EpBTwWvJra6MjkTnkf67KfsROoth+
         ULxJPoqTM4SHLuxe48kldJavlOdCE9odi3p+HqjtiEtCFUUp2txRDU0iaJ3mKsEXjelf
         xH35ohQpSft07k7+6d6EgUsCftdvabAm5dyCPLinUPXp18+VKI0ZNj1ofGhKSEIaEzRr
         PdnxU3RwlyzK8L3p3coM9kFJNjhgY/D6XL7O5zkPCnVo+1CBmJ+uwcBavBSv7YFxe3mU
         ua9dhSNXOxZ2IcRSzufOQpwBrfhHsjX1yqCb8/gycgq1uYbJAC2aeq7OVwAi535iqgoz
         ka3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="n5s0/8gx";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id k69si856902oih.3.2020.06.15.07.57.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 07:57:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id f18so16019472qkh.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 07:57:26 -0700 (PDT)
X-Received: by 2002:a37:4656:: with SMTP id t83mr15544636qka.126.1592233045781;
        Mon, 15 Jun 2020 07:57:25 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id e53sm12573062qtk.50.2020.06.15.07.57.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 07:57:25 -0700 (PDT)
Date: Mon, 15 Jun 2020 10:57:18 -0400
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	the arch/x86 maintainers <x86@kernel.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 0/8] x86/entry: KCSAN/KASAN/UBSAN vs noinstr
Message-ID: <20200615145718.GA1091@lca.pw>
References: <20200604102241.466509982@infradead.org>
 <CANpmjNPEXdGV-ZRYrVieJJsA01QATH+1vUixirocwKGDMsuEWQ@mail.gmail.com>
 <CANpmjNP2ayM6Oehw08yFM4+5xTjXWcCT7P3u7FL=cCMxFJNkXw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP2ayM6Oehw08yFM4+5xTjXWcCT7P3u7FL=cCMxFJNkXw@mail.gmail.com>
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b="n5s0/8gx";       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Mon, Jun 15, 2020 at 12:07:34PM +0200, 'Marco Elver' via kasan-dev wrote:
> On Thu, 4 Jun 2020 at 13:01, Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 4 Jun 2020 at 12:25, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > Hai,
> > >
> > > Here's the remaining few patches to make KCSAN/KASAN and UBSAN work with noinstr.
> >
> > Thanks for assembling the series!
> >
> > For where it's missing (1,2,3 and last one):
> >
> > Acked-by: Marco Elver <elver@google.com>
> 
> Where was this series supposed to go? I can't find it on any tree yet.
> 
> How urgent is this? Boot-test seems fine without this, but likely
> doesn't hit the corner cases. Syzbot will likely find them, and if we
> noticeably end up breaking various sanitizers without this, I'd
> consider this urgent.

Today's linux-next had a lot of those with this .config,

https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config

Wondering if this patchset will cure them all?

vmlinux.o: warning: objtool: exc_invalid_op()+0x337: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_double_fault()+0x217: call to __asan_report_store4_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_int3()+0x376: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: sync_regs()+0xcd: call to __asan_report_store_n_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: fixup_bad_iret()+0x13a: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_debug()+0x280: call to __asan_report_load4_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: default_do_nmi()+0x233: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_nmi()+0x67: call to __kasan_check_read() leaves .noinstr.text section
vmlinux.o: warning: objtool: poke_int3_handler()+0x3d1: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: mce_check_crashing_cpu()+0x60: call to __kasan_check_read() leaves .noinstr.text section
vmlinux.o: warning: objtool: mce_setup()+0x1c: call to memset() leaves .noinstr.text section
vmlinux.o: warning: objtool: do_machine_check()+0xd3: call to mce_rdmsrl() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_machine_check()+0x2a1: call to __asan_report_store4_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_page_fault()+0xc4e: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: lockdep_hardirqs_on()+0x3a9: call to __asan_report_store8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: lockdep_hardirqs_off()+0x24a: call to __asan_report_store8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: match_held_lock()+0x4df: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: lock_is_held_type()+0x230: call to __asan_report_store4_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: debug_lockdep_rcu_enabled()+0xcd: call to __asan_report_load4_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_enter()+0x1c: call to __kasan_check_write() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x20: call to __kasan_check_write() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_eqs_exit.constprop.72()+0x24d: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_eqs_enter.constprop.73()+0x250: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_exit()+0x1f2: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_irq_exit()+0xd1: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_enter()+0x184: call to __asan_report_load8_noabort() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_irq_enter()+0xd1: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
vmlinux.o: warning: objtool: __rcu_is_watching()+0x20: call to __kasan_check_read() leaves .noinstr.text section
vmlinux.o: warning: objtool: debug_locks_off()+0x19: call to __kasan_check_write() leaves .noinstr.text section

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615145718.GA1091%40lca.pw.
